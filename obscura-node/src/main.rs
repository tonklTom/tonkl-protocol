// Tonkl Protocol - Node
//
// Local testnet node with persistent state, mempool, proof verification,
// and JSON-RPC.
//
// Usage:
//   tonkl-node run                                    # Start solo node (auto blocks every 5s)
//   tonkl-node run --vk-dir ./vks                     # With proof verification
//   tonkl-node run --port 9200                        # Custom port
//   tonkl-node run --data-dir ./db                    # Custom data directory
//   tonkl-node run --no-auto-blocks                   # Manual block production only
//   tonkl-node run --node-id node-1 \
//       --validators node-0,node-1,node-2             # Multi-validator round-robin
//   tonkl-node run --block-interval 3                 # Faster blocks (3s)
//   tonkl-node status                                 # Query running node status

use clap::{Parser, Subcommand};
use obscura_node::mempool::Mempool;
use obscura_node::block::BlockBuilder;
use obscura_node::consensus::{ConsensusConfig, ValidatorId, ValidatorSet, run_block_producer};
use obscura_node::rpc::{start_rpc_server, NodeState};
use obscura_node::state::{ChainMeta, EncryptedNoteStore, NoteTree, NullifierSet};
use obscura_node::verifier::ProofVerifier;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "tonkl-node")]
#[command(about = "Tonkl Protocol local testnet node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the node
    Run {
        /// RPC listen port
        #[arg(long, default_value = "9100")]
        port: u16,

        /// Bind address
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,

        /// Data directory for persistent state
        #[arg(long, default_value = "./tonkl-data")]
        data_dir: String,

        /// Maximum mempool size
        #[arg(long, default_value = "10000")]
        mempool_size: usize,

        /// Directory containing verification keys (enables proof verification).
        /// Expected layout: vk_dir/{transfer,merge,split,mint}/vk
        /// If omitted, proof verification is disabled (testnet mode).
        #[arg(long)]
        vk_dir: Option<PathBuf>,

        /// Path to the bb (Barretenberg) binary
        #[arg(long, default_value = "bb")]
        bb_path: String,

        /// This node's validator ID for consensus (default: "node-0")
        #[arg(long, default_value = "node-0")]
        node_id: String,

        /// Comma-separated list of all validator IDs (default: solo mode)
        /// Example: --validators node-0,node-1,node-2
        #[arg(long, value_delimiter = ',')]
        validators: Option<Vec<String>>,

        /// Block production interval in seconds (default: 5)
        #[arg(long, default_value = "5")]
        block_interval: u64,

        /// Disable automatic block production (manual produce_block RPC only)
        #[arg(long)]
        no_auto_blocks: bool,
    },

    /// Query node status (connects to a running node)
    Status {
        /// Node RPC URL
        #[arg(long, default_value = "http://127.0.0.1:9100")]
        url: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            port,
            bind,
            data_dir,
            mempool_size,
            vk_dir,
            bb_path,
            node_id,
            validators,
            block_interval,
            no_auto_blocks,
        } => {
            info!("Tonkl Node v0.2.0 -- Phase B2: Proof Verification");
            info!("Data directory: {}", data_dir);

            // Open sled database
            let db = sled::open(&data_dir)?;
            info!("Database opened at {}", data_dir);

            // Initialize state
            let note_tree = NoteTree::open(&db)?;
            let nullifier_set = NullifierSet::open(&db)?;
            let encrypted_notes = EncryptedNoteStore::open(&db)?;
            let mempool = Mempool::new(mempool_size);
            let chain_meta = ChainMeta::open(&db)?;

            // Resume block builder from persisted state (survives restarts)
            let block_count = chain_meta.block_count()?;
            let last_hash = chain_meta.last_block_hash()?;
            let block_builder = if block_count > 0 {
                info!("Resuming from block #{} (last hash: 0x{}…)",
                      block_count - 1, hex::encode(&last_hash[..4]));
                BlockBuilder::from_state(block_count, last_hash)
            } else {
                BlockBuilder::new()
            };

            // Initialize proof verifier
            let verifier = match vk_dir {
                Some(dir) => {
                    info!("Loading verification keys from {}", dir.display());
                    let v = ProofVerifier::from_vk_dir(&dir, &bb_path)
                        .map_err(|e| format!("Failed to load VKs: {}", e))?;
                    info!("Proof verification ENABLED ({} VKs loaded)", v.loaded_vk_count());
                    v
                }
                None => {
                    warn!("No --vk-dir specified: proof verification DISABLED (testnet mode)");
                    ProofVerifier::disabled()
                }
            };

            info!(
                "State loaded: {} leaves, {} nullifiers",
                note_tree.leaf_count(),
                nullifier_set.count()
            );

            let state = Arc::new(RwLock::new(NodeState {
                note_tree,
                nullifier_set,
                encrypted_notes,
                mempool,
                block_builder,
                blocks: Vec::new(),
                verifier,
                tx_index: std::collections::HashMap::new(),
                chain_meta,
            }));

            // ── Consensus / block production ──
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

            if !no_auto_blocks {
                let consensus_config = match validators {
                    Some(ref ids) if ids.len() > 1 => {
                        info!("Multi-validator consensus: {} validators", ids.len());
                        ConsensusConfig::multi_node(&node_id, ids.clone(), block_interval)
                    }
                    _ => {
                        info!("Solo consensus mode (this node produces all blocks)");
                        let mut cfg = ConsensusConfig::solo_testnet();
                        cfg.node_id = ValidatorId(node_id.clone());
                        cfg.validator_set = ValidatorSet::solo(&node_id);
                        cfg.block_interval = std::time::Duration::from_secs(block_interval);
                        cfg
                    }
                };

                let state_clone = state.clone();
                tokio::spawn(async move {
                    run_block_producer(state_clone, consensus_config, cancel_rx).await;
                });
            } else {
                info!("Auto block production DISABLED (use produce_block RPC)");
            }

            let addr = format!("{}:{}", bind, port);
            info!("Starting JSON-RPC server on {}", addr);

            start_rpc_server(state, &addr).await?;

            // Signal block producer to stop (if RPC server exits)
            let _ = cancel_tx.send(true);
        }

        Commands::Status { url } => {
            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "get_status",
                "params": [],
                "id": 1
            });

            match client.post(&url).json(&body).send().await {
                Ok(resp) => {
                    let result: serde_json::Value = resp.json().await?;
                    if let Some(status) = result.get("result") {
                        println!("Tonkl Node Status");
                        println!("  Block height:    {}", status["block_height"]);
                        println!("  Merkle root:     {}", status["merkle_root"]);
                        println!("  Leaves:          {}", status["leaf_count"]);
                        println!("  Nullifiers:      {}", status["nullifier_count"]);
                        println!("  Mempool:         {}", status["mempool_size"]);
                    } else if let Some(error) = result.get("error") {
                        eprintln!("RPC error: {}", error);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect to {}: {}", url, e);
                    eprintln!("Is the node running?");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
