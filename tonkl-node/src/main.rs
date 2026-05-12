// Tonkl Protocol - Node
//
// Multi-node testnet with P2P networking, consensus, and proof verification.
//
// Usage:
//   tonkl-node run --allow-unverified-local \
//       --allow-unauthenticated-rpc-local             # Local-only dev node without VKs/auth
//   tonkl-node run                                    # Start solo node (requires VKs)
//   tonkl-node run --vk-dir ./vks                     # With proof verification
//   tonkl-node run --port 9200                        # Custom RPC port
//   tonkl-node run --data-dir ./db                    # Custom data directory
//   tonkl-node run --no-auto-blocks                   # Manual block production only
//   tonkl-node run --node-id node-1 \
//       --validators node-0,node-1,node-2             # Multi-validator round-robin
//   tonkl-node run --block-interval 3                 # Faster blocks (3s)
//   tonkl-node run --p2p-port 9300 \
//       --bootstrap /ip4/127.0.0.1/tcp/9300/p2p/<id>  # Strict P2P networking
//   tonkl-node run --p2p-port 9300 --allow-mdns-local # Local-only P2P discovery
//   tonkl-node run --sync-from http://127.0.0.1:9100  # Sync from existing peer
//   tonkl-node status                                 # Query running node status

use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, PeerId};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tonkl_node::block::{Block, BlockBuilder, Transaction};
use tonkl_node::consensus::{ConsensusConfig, ValidatorId, ValidatorSet};
use tonkl_node::mempool::Mempool;
use tonkl_node::node;
use tonkl_node::p2p::{self, NetworkCommand, NetworkEvent, P2pConfig};
use tonkl_node::rpc::{start_rpc_server, MintPolicy, NodeState};
use tonkl_node::state::{ChainMeta, EncryptedNoteStore, NoteTree, NullifierSet};
use tonkl_node::verifier::ProofVerifier;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

fn is_loopback_bind(bind: &str) -> bool {
    let bind = bind.trim();
    if bind.eq_ignore_ascii_case("localhost") {
        return true;
    }
    bind.parse::<std::net::IpAddr>()
        .map(|addr| addr.is_loopback())
        .unwrap_or(false)
}

fn is_beta_or_production_env(tonkl_env: Option<&str>) -> bool {
    tonkl_env
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            value == "production" || value == "prod" || value == "beta"
        })
        .unwrap_or(false)
}

fn parse_p2p_bind_addr(bind: &str, port: u16) -> Result<Multiaddr, String> {
    let ip = if bind.trim().eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        bind.trim()
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid P2P bind address '{}': {}", bind, e))?
    };

    let multiaddr = match ip {
        IpAddr::V4(addr) => format!("/ip4/{}/tcp/{}", addr, port),
        IpAddr::V6(addr) => format!("/ip6/{}/tcp/{}", addr, port),
    };
    multiaddr
        .parse()
        .map_err(|e| format!("invalid P2P listen multiaddr '{}': {}", multiaddr, e))
}

fn parse_bootstrap_peers(raw_peers: Option<Vec<String>>) -> Result<Vec<Multiaddr>, String> {
    raw_peers
        .unwrap_or_default()
        .into_iter()
        .map(|peer| {
            peer.parse::<Multiaddr>()
                .map_err(|e| format!("invalid bootstrap peer '{}': {}", peer, e))
        })
        .collect()
}

fn parse_trusted_peers(raw_peers: Option<Vec<String>>) -> Result<HashSet<PeerId>, String> {
    let mut trusted = HashSet::new();
    for peer in raw_peers.unwrap_or_default() {
        let peer_id = peer
            .parse::<PeerId>()
            .map_err(|e| format!("invalid trusted peer ID '{}': {}", peer, e))?;
        trusted.insert(peer_id);
    }
    Ok(trusted)
}

fn validate_p2p_config(
    p2p_enabled: bool,
    allow_mdns_local: bool,
    p2p_bind: &str,
    bootstrap_peers: &[Multiaddr],
    trusted_peers: &HashSet<PeerId>,
    tonkl_env: Option<&str>,
) -> Result<(), String> {
    if !p2p_enabled {
        return Ok(());
    }

    if allow_mdns_local {
        if is_beta_or_production_env(tonkl_env) {
            return Err(
                "mDNS peer discovery is not allowed when TONKL_ENV is beta/production".to_string(),
            );
        }
        if !is_loopback_bind(p2p_bind) {
            return Err(format!(
                "mDNS peer discovery requires loopback P2P bind, got {}",
                p2p_bind
            ));
        }
        return Ok(());
    }

    if bootstrap_peers
        .iter()
        .any(|addr| p2p::peer_id_from_multiaddr(addr).is_none())
    {
        return Err(
            "strict P2P mode requires every bootstrap multiaddr to include /p2p/<peer-id>; use --allow-mdns-local only for local development"
                .to_string(),
        );
    }

    let mut allowed_peers = trusted_peers.clone();
    for addr in bootstrap_peers {
        if let Some(peer_id) = p2p::peer_id_from_multiaddr(addr) {
            allowed_peers.insert(peer_id);
        }
    }

    if allowed_peers.is_empty() {
        return Err(
            "strict P2P mode requires --trusted-peer or bootstrap multiaddrs containing /p2p/<peer-id>; use --allow-mdns-local only for local development"
                .to_string(),
        );
    }

    Ok(())
}

fn validate_unverified_mode_allowed(
    allow_unverified_local: bool,
    bind: &str,
    p2p_port: u16,
    sync_from: Option<&str>,
    tonkl_env: Option<&str>,
) -> Result<(), String> {
    if !allow_unverified_local {
        return Err(
            "proof verification requires --vk-dir; use --allow-unverified-local only for isolated local development"
                .to_string(),
        );
    }

    if is_beta_or_production_env(tonkl_env) {
        return Err(
            "unverified local mode is not allowed when TONKL_ENV is beta/production".to_string(),
        );
    }

    if !is_loopback_bind(bind) {
        return Err(format!(
            "unverified local mode requires loopback bind, got {}",
            bind
        ));
    }

    if p2p_port > 0 {
        return Err("unverified local mode cannot enable P2P".to_string());
    }

    if sync_from.is_some() {
        return Err("unverified local mode cannot sync blocks from a peer".to_string());
    }

    Ok(())
}

fn env_value_present(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn validate_rpc_auth_allowed(
    allow_unauthenticated_rpc_local: bool,
    bind: &str,
    p2p_port: u16,
    sync_from: Option<&str>,
    tonkl_env: Option<&str>,
    rpc_secret_configured: bool,
) -> Result<(), String> {
    if allow_unauthenticated_rpc_local {
        if is_beta_or_production_env(tonkl_env) {
            return Err(
                "unauthenticated RPC local mode is not allowed when TONKL_ENV is beta/production"
                    .to_string(),
            );
        }

        if !is_loopback_bind(bind) {
            return Err(format!(
                "unauthenticated RPC local mode requires loopback bind, got {}",
                bind
            ));
        }

        if p2p_port > 0 {
            return Err("unauthenticated RPC local mode cannot enable P2P".to_string());
        }

        if sync_from.is_some() {
            return Err(
                "unauthenticated RPC local mode cannot sync blocks from a peer".to_string(),
            );
        }
    }

    if rpc_secret_configured || allow_unauthenticated_rpc_local {
        return Ok(());
    }

    Err(
        "TONKL_RPC_SECRET is required for write RPC methods; use --allow-unauthenticated-rpc-local only for isolated local development"
            .to_string(),
    )
}

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
        /// If omitted, startup fails unless --allow-unverified-local is set.
        #[arg(long)]
        vk_dir: Option<PathBuf>,

        /// Allow no-VK mode for isolated loopback development only.
        /// Rejected with P2P, sync, non-loopback bind, or beta/production env.
        #[arg(long)]
        allow_unverified_local: bool,

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

        /// Allow write RPCs without TONKL_RPC_SECRET for isolated loopback development only.
        /// Rejected with P2P, sync, non-loopback bind, or beta/production env.
        #[arg(long)]
        allow_unauthenticated_rpc_local: bool,

        /// Allow metadata-heavy read RPCs without TONKL_RPC_SECRET.
        /// Intended for explicit public explorer deployments or isolated local dev.
        #[arg(long)]
        allow_public_rpc_metadata: bool,

        // ── P2P options ────────────────────────────────────────
        /// P2P listen port (0 = disabled)
        #[arg(long, default_value = "0")]
        p2p_port: u16,

        /// P2P bind address
        #[arg(long, default_value = "127.0.0.1")]
        p2p_bind: String,

        /// Bootstrap peer addresses (multiaddr format).
        /// Strict mode requires /p2p/<peer-id> in each address.
        #[arg(long = "bootstrap", value_delimiter = ',')]
        bootstrap_peers: Option<Vec<String>>,

        /// Trusted P2P peer IDs accepted for gossip in strict mode.
        #[arg(long = "trusted-peer", value_delimiter = ',')]
        trusted_peers: Option<Vec<String>>,

        /// Enable mDNS discovery for isolated loopback development only.
        #[arg(long)]
        allow_mdns_local: bool,

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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
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
            allow_unverified_local,
            bb_path,
            node_id,
            validators,
            block_interval,
            no_auto_blocks,
            allow_unauthenticated_rpc_local,
            allow_public_rpc_metadata,
            p2p_port,
            p2p_bind,
            bootstrap_peers,
            trusted_peers,
            allow_mdns_local,
            sync_from,
        } => {
            info!("Tonkl Node v0.2.0 -- Phase B3: P2P Multi-Node Testnet");
            info!("Data directory: {}", data_dir);

            let tonkl_env = std::env::var("TONKL_ENV").ok();
            validate_rpc_auth_allowed(
                allow_unauthenticated_rpc_local,
                &bind,
                p2p_port,
                sync_from.as_deref(),
                tonkl_env.as_deref(),
                env_value_present("TONKL_RPC_SECRET"),
            )
            .map_err(|e| format!("Unsafe RPC authentication configuration: {}", e))?;

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
                    validate_unverified_mode_allowed(
                        allow_unverified_local,
                        &bind,
                        p2p_port,
                        sync_from.as_deref(),
                        tonkl_env.as_deref(),
                    )
                    .map_err(|e| format!("Unsafe verifier configuration: {}", e))?;
                    warn!("╔══════════════════════════════════════════════════════════╗");
                    warn!("║  PROOF VERIFICATION DISABLED - local dev override set   ║");
                    warn!("║  Any transaction will be accepted without ZK proof.     ║");
                    warn!("║  This is restricted to loopback, no P2P, and no sync.   ║");
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
                mint_policy: MintPolicy::from_env(),
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
                let bootstrap = parse_bootstrap_peers(bootstrap_peers)
                    .map_err(|e| format!("Unsafe P2P configuration: {}", e))?;
                let trusted_peers = parse_trusted_peers(trusted_peers)
                    .map_err(|e| format!("Unsafe P2P configuration: {}", e))?;
                validate_p2p_config(
                    p2p_enabled,
                    allow_mdns_local,
                    &p2p_bind,
                    &bootstrap,
                    &trusted_peers,
                    tonkl_env.as_deref(),
                )
                .map_err(|e| format!("Unsafe P2P configuration: {}", e))?;
                let listen_addr = parse_p2p_bind_addr(&p2p_bind, p2p_port)
                    .map_err(|e| format!("Unsafe P2P configuration: {}", e))?;

                let p2p_config = P2pConfig {
                    listen_addr,
                    bootstrap_peers: bootstrap.clone(),
                    trusted_peers,
                    allow_mdns_discovery: allow_mdns_local,
                    node_id: node_id.clone(),
                };

                let (swarm, local_peer_id) = p2p::build_swarm(&p2p_config)?;
                info!("P2P enabled: peer ID = {}", local_peer_id);
                info!(
                    "P2P listen: {}, bootstrap peers: {}, mDNS local: {}",
                    p2p_config.listen_addr,
                    bootstrap.len(),
                    allow_mdns_local
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
            let tx_broadcast = if p2p_enabled { Some(local_tx_tx) } else { None };

            let allow_public_metadata_reads =
                allow_public_rpc_metadata || allow_unauthenticated_rpc_local;
            start_rpc_server(
                state,
                &addr,
                tx_broadcast,
                allow_unauthenticated_rpc_local,
                allow_public_metadata_reads,
            )
            .await?;

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
                    Ok(r) => tonkl_node::state::field_to_hex(r),
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
                        tonkl_node::rpc::ConfirmedTx {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_bind_detection_is_strict() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("localhost"));
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("192.168.1.20"));
    }

    #[test]
    fn unverified_mode_requires_explicit_flag() {
        let result = validate_unverified_mode_allowed(false, "127.0.0.1", 0, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn unverified_mode_allows_isolated_loopback_dev() {
        let result = validate_unverified_mode_allowed(true, "127.0.0.1", 0, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn unverified_mode_rejects_public_bind() {
        let result = validate_unverified_mode_allowed(true, "0.0.0.0", 0, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn unverified_mode_rejects_p2p_and_sync() {
        assert!(validate_unverified_mode_allowed(true, "127.0.0.1", 9300, None, None).is_err());
        assert!(validate_unverified_mode_allowed(
            true,
            "127.0.0.1",
            0,
            Some("http://127.0.0.1:9100"),
            None,
        )
        .is_err());
    }

    #[test]
    fn unverified_mode_rejects_beta_or_production_env() {
        assert!(
            validate_unverified_mode_allowed(true, "127.0.0.1", 0, None, Some("beta"),).is_err()
        );
        assert!(
            validate_unverified_mode_allowed(true, "127.0.0.1", 0, None, Some("production"),)
                .is_err()
        );
    }

    #[test]
    fn rpc_auth_allows_configured_secret() {
        let result = validate_rpc_auth_allowed(
            false,
            "0.0.0.0",
            9300,
            Some("http://127.0.0.1:9100"),
            Some("beta"),
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rpc_auth_requires_secret_by_default() {
        let result = validate_rpc_auth_allowed(false, "127.0.0.1", 0, None, None, false);
        assert!(result.is_err());
    }

    #[test]
    fn rpc_auth_allows_explicit_isolated_loopback_dev() {
        let result = validate_rpc_auth_allowed(true, "127.0.0.1", 0, None, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn rpc_auth_rejects_unsafe_local_override() {
        assert!(validate_rpc_auth_allowed(true, "0.0.0.0", 0, None, None, false).is_err());
        assert!(validate_rpc_auth_allowed(true, "127.0.0.1", 9300, None, None, false).is_err());
        assert!(validate_rpc_auth_allowed(
            true,
            "127.0.0.1",
            0,
            Some("http://127.0.0.1:9100"),
            None,
            false,
        )
        .is_err());
        assert!(
            validate_rpc_auth_allowed(true, "127.0.0.1", 0, None, Some("beta"), false).is_err()
        );
    }

    #[test]
    fn rpc_auth_secret_does_not_bypass_local_override_guard() {
        assert!(validate_rpc_auth_allowed(true, "0.0.0.0", 0, None, None, true).is_err());
        assert!(validate_rpc_auth_allowed(true, "127.0.0.1", 9300, None, None, true).is_err());
        assert!(validate_rpc_auth_allowed(true, "127.0.0.1", 0, None, Some("beta"), true).is_err());
    }

    fn test_peer_id() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    #[test]
    fn p2p_strict_mode_requires_trusted_identity() {
        let result = validate_p2p_config(false, false, "127.0.0.1", &[], &HashSet::new(), None);
        assert!(result.is_ok());

        let result = validate_p2p_config(true, false, "127.0.0.1", &[], &HashSet::new(), None);
        assert!(result.is_err());
    }

    #[test]
    fn p2p_strict_mode_accepts_peer_id_bootstrap() {
        let peer_id = test_peer_id();
        let bootstrap: Multiaddr = format!("/ip4/127.0.0.1/tcp/9300/p2p/{}", peer_id)
            .parse()
            .unwrap();

        let result =
            validate_p2p_config(true, false, "0.0.0.0", &[bootstrap], &HashSet::new(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn p2p_strict_mode_rejects_unbound_bootstrap() {
        let bootstrap: Multiaddr = "/ip4/127.0.0.1/tcp/9300".parse().unwrap();
        let result = validate_p2p_config(
            true,
            false,
            "127.0.0.1",
            &[bootstrap],
            &HashSet::new(),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn p2p_mdns_mode_is_local_only() {
        let result = validate_p2p_config(true, true, "127.0.0.1", &[], &HashSet::new(), None);
        assert!(result.is_ok());

        let result = validate_p2p_config(true, true, "0.0.0.0", &[], &HashSet::new(), None);
        assert!(result.is_err());

        let result =
            validate_p2p_config(true, true, "127.0.0.1", &[], &HashSet::new(), Some("beta"));
        assert!(result.is_err());
    }
}
