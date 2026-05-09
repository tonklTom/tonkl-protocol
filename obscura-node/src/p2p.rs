// Tonkl Protocol - P2P Networking Layer
//
// Provides peer-to-peer communication for the multi-node testnet using libp2p.
//
// Protocols:
//   - Gossipsub: transaction and block propagation to all peers
//   - mDNS: automatic local peer discovery (for testnet convenience)
//   - Identify: peer metadata exchange
//
// Chain sync uses the existing JSON-RPC interface (get_block method),
// not the P2P layer, which keeps the implementation simple.
//
// Architecture:
//   The P2P layer communicates with the node core via tokio channels:
//     - NetworkCommand (node → P2P): broadcast tx/block, dial peer
//     - NetworkEvent (P2P → node): received tx/block, peer connected/disconnected
//
// Topics:
//   - "tonkl/txs/1"    — new transactions
//   - "tonkl/blocks/1"  — new blocks

use crate::block::{Block, Transaction};

use futures::StreamExt;
use libp2p::{
    gossipsub, identify, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────
// Gossip message types
// ─────────────────────────────────────────────────────────────────────

/// Messages propagated over gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// A new transaction to add to the mempool.
    NewTransaction(Transaction),
    /// A new block produced by the current leader.
    NewBlock(Block),
}

// ─────────────────────────────────────────────────────────────────────
// Network behaviour (composed libp2p protocols)
// ─────────────────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
pub struct TonklBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
}

// ─────────────────────────────────────────────────────────────────────
// Commands from node → P2P layer
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a transaction to peers.
    BroadcastTransaction(Transaction),
    /// Broadcast a newly produced block to peers.
    BroadcastBlock(Block),
    /// Dial a specific peer address.
    DialPeer(Multiaddr),
}

// ─────────────────────────────────────────────────────────────────────
// Events from P2P layer → node
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum NetworkEvent {
    /// A transaction was received from a peer.
    TransactionReceived(Transaction),
    /// A block was received from a peer.
    BlockReceived(Block),
    /// A peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
}

// ─────────────────────────────────────────────────────────────────────
// P2P configuration
// ─────────────────────────────────────────────────────────────────────

/// Configuration for the P2P network layer.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Port to listen on for P2P connections.
    pub listen_port: u16,
    /// Bootstrap peer addresses to connect to on startup.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Node ID string (used in identify protocol).
    pub node_id: String,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_port: 9200,
            bootstrap_peers: Vec::new(),
            node_id: "tonkl-node".to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Gossipsub topic names
// ─────────────────────────────────────────────────────────────────────

const TX_TOPIC: &str = "tonkl/txs/1";
const BLOCK_TOPIC: &str = "tonkl/blocks/1";

// ─────────────────────────────────────────────────────────────────────
// Build the swarm
// ─────────────────────────────────────────────────────────────────────

/// Create and configure the libp2p Swarm.
///
/// Returns the swarm and the local PeerId.
pub fn build_swarm(
    config: &P2pConfig,
) -> Result<(Swarm<TonklBehaviour>, PeerId), Box<dyn std::error::Error>> {
    // Gossipsub config
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(10 * 1024 * 1024) // 10 MB — blocks can be large
        .build()
        .map_err(|e| format!("gossipsub config error: {}", e))?;

    let message_id_fn = |message: &gossipsub::Message| {
        // Use BLAKE3 of the data as message ID for deduplication
        let hash = blake3::hash(&message.data);
        gossipsub::MessageId::from(hash.as_bytes().to_vec())
    };

    let swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|keypair| {
            let peer_id = keypair.public().to_peer_id();

            // Gossipsub
            let gossipsub = gossipsub::Behaviour::new_with_message_authenticity(
                gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                gossipsub_config.clone(),
                message_id_fn,
            )
            .map_err(|e| format!("gossipsub error: {}", e))?;

            // mDNS for local discovery
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                peer_id,
            )?;

            // Identify protocol
            let identify = identify::Behaviour::new(identify::Config::new(
                format!("/tonkl/{}", env!("CARGO_PKG_VERSION")),
                keypair.public(),
            ));

            Ok(TonklBehaviour {
                gossipsub,
                mdns,
                identify,
            })
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(Duration::from_secs(300))
        })
        .build();

    let local_peer_id = *swarm.local_peer_id();

    Ok((swarm, local_peer_id))
}

// ─────────────────────────────────────────────────────────────────────
// P2P event loop
// ─────────────────────────────────────────────────────────────────────

/// Run the P2P networking event loop.
///
/// This function:
///   1. Listens on the configured port
///   2. Subscribes to gossipsub topics (transactions, blocks)
///   3. Connects to bootstrap peers
///   4. Forwards received messages to the node via `event_tx`
///   5. Handles commands from the node via `cmd_rx`
pub async fn run_p2p(
    mut swarm: Swarm<TonklBehaviour>,
    config: P2pConfig,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
) {
    // Subscribe to gossipsub topics
    let tx_topic = gossipsub::IdentTopic::new(TX_TOPIC);
    let block_topic = gossipsub::IdentTopic::new(BLOCK_TOPIC);

    if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic) {
        error!("Failed to subscribe to tx topic: {}", e);
    }
    if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&block_topic) {
        error!("Failed to subscribe to block topic: {}", e);
    }

    // Listen on TCP
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port)
        .parse()
        .expect("valid multiaddr");

    if let Err(e) = swarm.listen_on(listen_addr.clone()) {
        error!("Failed to listen on {}: {}", listen_addr, e);
        return;
    }
    info!("P2P listening on /ip4/0.0.0.0/tcp/{}", config.listen_port);

    // Connect to bootstrap peers
    for addr in &config.bootstrap_peers {
        info!("Dialing bootstrap peer: {}", addr);
        if let Err(e) = swarm.dial(addr.clone()) {
            warn!("Failed to dial {}: {}", addr, e);
        }
    }

    // Track connected peers
    let mut connected_peers: HashSet<PeerId> = HashSet::new();

    // Main event loop
    loop {
        tokio::select! {
            // Handle incoming P2P events
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(TonklBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. }
                    )) => {
                        handle_gossip_message(&message, &event_tx).await;
                    }

                    SwarmEvent::Behaviour(TonklBehaviourEvent::Mdns(
                        mdns::Event::Discovered(peers)
                    )) => {
                        for (peer_id, addr) in peers {
                            debug!("mDNS discovered peer: {} at {}", peer_id, addr);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            if let Err(e) = swarm.dial(addr) {
                                debug!("Failed to dial mDNS peer: {}", e);
                            }
                        }
                    }

                    SwarmEvent::Behaviour(TonklBehaviourEvent::Mdns(
                        mdns::Event::Expired(peers)
                    )) => {
                        for (peer_id, _addr) in peers {
                            debug!("mDNS peer expired: {}", peer_id);
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }

                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        if connected_peers.insert(peer_id) {
                            info!("Peer connected: {} (total: {})", peer_id, connected_peers.len());
                            let _ = event_tx.send(NetworkEvent::PeerConnected(peer_id)).await;
                        }
                    }

                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        if connected_peers.remove(&peer_id) {
                            info!("Peer disconnected: {} (total: {})", peer_id, connected_peers.len());
                            let _ = event_tx.send(NetworkEvent::PeerDisconnected(peer_id)).await;
                        }
                    }

                    SwarmEvent::NewListenAddr { address, .. } => {
                        let peer_id = swarm.local_peer_id();
                        info!("P2P listening on {} (peer ID: {})", address, peer_id);
                    }

                    _ => {}
                }
            }

            // Handle commands from the node
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NetworkCommand::BroadcastTransaction(tx)) => {
                        match serde_json::to_vec(&GossipMessage::NewTransaction(tx)) {
                            Ok(data) => {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                                    tx_topic.clone(),
                                    data,
                                ) {
                                    debug!("Failed to publish tx: {}", e);
                                }
                            }
                            Err(e) => warn!("Failed to serialize tx: {}", e),
                        }
                    }

                    Some(NetworkCommand::BroadcastBlock(block)) => {
                        let block_num = block.header.block_number;
                        match serde_json::to_vec(&GossipMessage::NewBlock(block)) {
                            Ok(data) => {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                                    block_topic.clone(),
                                    data,
                                ) {
                                    debug!("Failed to publish block #{}: {}", block_num, e);
                                }
                            }
                            Err(e) => warn!("Failed to serialize block: {}", e),
                        }
                    }

                    Some(NetworkCommand::DialPeer(addr)) => {
                        info!("Dialing peer: {}", addr);
                        if let Err(e) = swarm.dial(addr.clone()) {
                            warn!("Failed to dial {}: {}", addr, e);
                        }
                    }

                    None => {
                        info!("P2P command channel closed, shutting down");
                        return;
                    }
                }
            }
        }
    }
}

/// Handle an incoming gossipsub message.
async fn handle_gossip_message(
    message: &gossipsub::Message,
    event_tx: &mpsc::Sender<NetworkEvent>,
) {
    match serde_json::from_slice::<GossipMessage>(&message.data) {
        Ok(GossipMessage::NewTransaction(tx)) => {
            let tx_hash = format!("0x{}", hex::encode(&tx.tx_hash[..4]));
            debug!("Received transaction {} from gossip", tx_hash);
            let _ = event_tx.send(NetworkEvent::TransactionReceived(tx)).await;
        }
        Ok(GossipMessage::NewBlock(block)) => {
            info!(
                "Received block #{} from gossip ({} txs)",
                block.header.block_number, block.header.tx_count
            );
            let _ = event_tx.send(NetworkEvent::BlockReceived(block)).await;
        }
        Err(e) => {
            warn!("Failed to deserialize gossip message: {}", e);
        }
    }
}
