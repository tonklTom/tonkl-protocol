// Tonkl Protocol - Node
//
// Multi-node testnet with P2P networking, consensus, and proof verification.
//
// Usage:
//   tonkl-node run                                    # Start solo node (auto blocks every 5s)
//   tonkl-node run --vk-dir ./vks                     # With proof verification
//   tonkl-node run --port 9200                        # Custom RPC port
//   tonkl-node run --data-dir ./db                    # Custom data directory
//   tonkl-node run --no-auto-blocks                   # Manual block production only
//   tonkl-node run --node-id node-1 \
//       --validators node-0,node-1,node-2             # Multi-validator round-robin
//   tonkl-node run --block-interval 3                 # Faster blocks (3s)
//   tonkl-node run --p2p-port 9300 \
//       --bootstrap /ip4/127.0.0.1/tcp/9300           # P2P networking
//   tonkl-node run --sync-from http://127.0.0.1:9100  # Sync from existing peer
//   tonkl-node status                                 # Query running node status

use clap::{Parser, Subcommand};
use obscura_node::block::{Block, BlockBuilder, Transaction};
use obscura_node::consensus::{ConsensusConfig, ValidatorId, ValidatorSet};
use obscura_node::mempool::Mempool;
use obscura_node::node;
use obscura_node::p2p::{self, NetworkCommand, NetworkEvent, P2pConfig};
use obscura_node::rpc::{start_rpc_server, NodeState};
use obscura_node::state::{ChainMeta, EncryptedNoteStore, NoteTree, NullifierSet};
use obscura_node::verifier::ProofVerifier;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "tonkl-node")]
#[command(about = "Tonkl Protocol testnet node with P2P networking")]
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

        /// Bind address for RPC
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

        // ── P2P options ────────────────────────────────────────
        /// P2P listen port (0 = disabled)
        #[arg(long, default_value = "0")]
        p2p_port: u16,

        /// Bootstrap peer addresses (multiaddr format).
        /// Example: --bootstrap /ip4/127.0.0.1/tcp/9300
        #[arg(long = "bootstrap", value_delimiter = ',')]
        bootstrap_peers: Option<Vec<String>>,

        // ── Sync options ─────────────────────────────────────────
        /// Sync blocks from a running peer's RPC URL on startup.
        /// Example: --sync-from http://127.0.0.1:9100
        #[arg(long)]
        sync_from: Option<String>,
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
            p2p_port,
            bootstrap_peers,
            sync_from,
        } => {
            info!("Tonkl Node v0.2.0 -- Phase B3: P2P Multi-Node Testnet");
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

            // Resume block builder from persisted state
            let block_count = chain_meta.block_count()?;
            let last_hash = chain_meta.last_block_hash()?;
            let block_builder = if block_count > 0 {
                info!(
                    "Resuming from block #{} (last hash: 0x{}…)",
                    block_count - 1,
                    hex::encode(&last_hash[..4])
                );
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
                    info!(
                        "Proof verification ENABLED ({} VKs loaded)",
                        v.loaded_vk_count()
                    );
                    v
                }
                None => {
                    warn!("╔══════════════════════════════════════════════════════════╗");
                    warn!("║  PROOF VERIFICATION DISABLED — no --vk-dir specified    ║");
                    warn!("║  Any transaction will be accepted without ZK proof.     ║");
                    warn!("║  This is acceptable for local development only.         ║");
                    warn!("║  For testnet/production: pass --vk-dir <path>           ║");
                    warn!("╚══════════════════════════════════════════════════════════╝");
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

            // ── Chain sync (fetch blocks from a running peer) ──
            if let Some(ref peer_url) = sync_from {
                info!("Syncing chain from peer: {}", peer_url);
                match node::sync_from_peer(&state, peer_url).await {
                    Ok(count) => {
                        if count > 0 {
                            info!("Synced {} blocks from peer", count);
                        }
                    }
                    Err(e) => {
                        warn!("Chain sync failed: {} — starting with local state", e);
                    }
                }
            }

            // ── Cancellation ──
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

            // ── P2P setup ──
            let p2p_enabled = p2p_port > 0;

            // Channels for local tx/block broadcast to P2P
            let (local_tx_tx, local_tx_rx) = mpsc::channel::<Transaction>(256);
            let (local_block_tx, local_block_rx) = mpsc::channel::<Block>(256);

            if p2p_enabled {
                let bootstrap: Vec<libp2p::Multiaddr> = bootstrap_peers
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();

                let p2p_config = P2pConfig {
                    listen_port: p2p_port,
                    bootstrap_peers: bootstrap.clone(),
                    node_id: node_id.clone(),
                };

                let (swarm, local_peer_id) = p2p::build_swarm(&p2p_config)?;
                info!("P2P enabled: peer ID = {}", local_peer_id);
                info!(
                    "P2P port: {}, bootstrap peers: {}",
                    p2p_port,
                    bootstrap.len()
                );

                // Channels between P2P and node event handler
                let (net_cmd_tx, net_cmd_rx) = mpsc::channel::<NetworkCommand>(256);
                let (net_event_tx, net_event_rx) = mpsc::channel::<NetworkEvent>(256);

                // Spawn P2P event loop
                tokio::spawn(async move {
                    p2p::run_p2p(swarm, p2p_config, net_cmd_rx, net_event_tx).await;
                });

                // Spawn node event handler (bridges P2P ↔ state)
                let state_for_events = state.clone();
                tokio::spawn(async move {
                    node::run_event_handler(
                        state_for_events,
                        net_event_rx,
                        net_cmd_tx,
                        local_tx_rx,
                        local_block_rx,
                    )
                    .await;
                });
            } else {
                info!("P2P disabled (use --p2p-port to enable)");
            }

            // ── Consensus / block production ──
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

                let state_for_consensus = state.clone();
                let block_broadcast = if p2p_enabled {
                    Some(local_block_tx)
                } else {
                    None
                };

                tokio::spawn(async move {
                    run_block_producer_with_broadcast(
                        state_for_consensus,
                        consensus_config,
                        cancel_rx,
                        block_broadcast,
                    )
                    .await;
                });
            } else {
                info!("Auto block production DISABLED (use produce_block RPC)");
            }

            // ── RPC server ──
            let addr = format!("{}:{}", bind, port);
            info!("Starting JSON-RPC server on {}", addr);

            // Pass tx broadcast channel to RPC so submitted txs reach P2P
            let tx_broadcast = if p2p_enabled {
                Some(local_tx_tx)
            } else {
                None
            };

            start_rpc_server(state, &addr, tx_broadcast).await?;

            // Signal block producer to stop
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

// ─────────────────────────────────────────────────────────────────────
// Block producer with P2P broadcast
// ─────────────────────────────────────────────────────────────────────

/// Block producer that also broadcasts blocks to the P2P network.
///
/// Same logic as consensus::run_block_producer, but sends produced
/// blocks to the P2P layer for gossip to peers.
async fn run_block_producer_with_broadcast(
    state: Arc<RwLock<NodeState>>,
    config: ConsensusConfig,
    cancel: tokio::sync::watch::Receiver<bool>,
    block_tx: Option<mpsc::Sender<Block>>,
) {
    info!(
        "Block producer started: node={}, validators={}, interval={}s, p2p_broadcast={}",
        config.node_id,
        config.validator_set.len(),
        config.block_interval.as_secs(),
        block_tx.is_some(),
    );

    let mut interval = tokio::time::interval(config.block_interval);
    interval.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if *cancel.borrow() {
                    info!("Block producer shutting down");
                    return;
                }

                // Check if we're the leader
                let next_block = {
                    let s = state.read().await;
                    s.block_builder.next_block_number()
                };

                let leader = config.validator_set.leader_for_block(next_block);
                if leader != &config.node_id {
                    tracing::debug!(
                        "Not leader for block #{} (leader is {}), skipping",
                        next_block, leader
                    );
                    continue;
                }

                // Produce the block
                let mut s = state.write().await;
                let txs = s.mempool.drain_for_block(config.max_txs_per_block);

                if txs.is_empty() && !config.produce_empty_blocks {
                    tracing::debug!("No pending transactions, skipping block #{}", next_block);
                    continue;
                }

                // Apply transactions to state
                for tx in &txs {
                    for cm in &tx.new_commitments {
                        if let Err(e) = s.note_tree.insert(*cm) {
                            warn!("Failed to insert commitment: {}", e);
                            continue;
                        }
                    }
                    if !tx.nullifiers.is_empty() {
                        if let Err(e) = s.nullifier_set.insert_batch(&tx.nullifiers) {
                            warn!("Failed to insert nullifiers: {}", e);
                            continue;
                        }
                    }
                }

                let root = match s.note_tree.root() {
                    Ok(r) => obscura_node::state::field_to_hex(r),
                    Err(e) => {
                        warn!("Failed to get state root: {}", e);
                        continue;
                    }
                };

                let all_nullifiers: Vec<_> = txs
                    .iter()
                    .flat_map(|tx| tx.nullifiers.clone())
                    .collect();

                let block = s.block_builder.build_block(txs, root);
                let header = block.header.clone();

                // Index confirmed transactions
                for tx in &block.transactions {
                    let tx_hash_hex = format!("0x{}", hex::encode(tx.tx_hash));
                    s.tx_index.insert(
                        tx_hash_hex,
                        obscura_node::rpc::ConfirmedTx {
                            block_number: header.block_number,
                            tx_type: tx.tx_type,
                        },
                    );
                }

                info!(
                    "Block #{} produced by {} ({} txs, root: {})",
                    header.block_number, config.node_id, header.tx_count, header.state_root
                );

                // Persist chain metadata
                let next = s.block_builder.next_block_number();
                let last_hash = s.block_builder.last_block_hash();
                if let Err(e) = s.chain_meta.update(next, last_hash) {
                    warn!("Failed to persist chain metadata: {}", e);
                }

                // Broadcast to P2P peers (clone before storing)
                if let Some(ref btx) = block_tx {
                    let _ = btx.send(block.clone()).await;
                }

                s.blocks.push(block);

                if !all_nullifiers.is_empty() {
                    s.mempool.purge_confirmed_nullifiers(&all_nullifiers);
                }
            }
        }
    }
}
