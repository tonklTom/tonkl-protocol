// Tonkl Protocol - Node Event Handler
//
// Bridges the P2P network layer with the node's state.
//
// Responsibilities:
//   - Receives transactions from peers → validates and adds to mempool
//   - Receives blocks from peers → validates, applies, and updates state
//   - Broadcasts locally produced blocks and accepted transactions
//
// The event handler runs as a tokio task, processing NetworkEvents
// from the P2P layer and issuing NetworkCommands back.

use crate::block::{Block, BlockBuilder, Transaction, validate_and_apply_block};
use crate::p2p::{NetworkCommand, NetworkEvent};
use crate::rpc::{ConfirmedTx, NodeState};

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────
// Chain Sync (via RPC)
// ─────────────────────────────────────────────────────────────────────

/// Sync blocks from a peer's RPC endpoint.
///
/// Fetches blocks in batches of 50 from `peer_url` starting from the
/// node's current block height. Validates and applies each block to
/// bring the node up to date with the peer.
///
/// Returns the number of blocks synced, or an error description.
pub async fn sync_from_peer(
    state: &Arc<RwLock<NodeState>>,
    peer_url: &str,
) -> Result<u64, String> {
    let client = reqwest::Client::new();
    let mut total_synced: u64 = 0;

    // Get peer's block height first
    let peer_height = {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_status",
            "params": [],
            "id": 1
        });
        let resp = client
            .post(peer_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Failed to connect to peer {}: {}", peer_url, e))?;
        let result: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Invalid response from peer: {}", e))?;
        result["result"]["block_height"]
            .as_u64()
            .ok_or_else(|| "Peer did not return block_height".to_string())?
    };

    let our_height = {
        let s = state.read().await;
        s.block_builder.next_block_number()
    };

    if our_height >= peer_height {
        info!(
            "Already at block #{}, peer is at #{} — no sync needed",
            our_height, peer_height
        );
        return Ok(0);
    }

    info!(
        "Chain sync: we have {} blocks, peer has {} — fetching {} blocks",
        our_height,
        peer_height,
        peer_height - our_height
    );

    let mut from_block = our_height;
    let batch_size: u64 = 50;

    loop {
        if from_block >= peer_height {
            break;
        }

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_blocks_range",
            "params": [from_block, batch_size],
            "id": 1
        });

        let resp = client
            .post(peer_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch blocks from peer: {}", e))?;

        let result: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Invalid block batch response: {}", e))?;

        let blocks: Vec<Block> = serde_json::from_value(
            result["result"].clone(),
        )
        .map_err(|e| format!("Failed to deserialize blocks: {}", e))?;

        if blocks.is_empty() {
            break;
        }

        let batch_count = blocks.len() as u64;

        // Apply each block to state
        for block in blocks {
            let block_num = block.header.block_number;
            let mut s = state.write().await;

            let expected_block_number = s.block_builder.next_block_number();
            let expected_parent_hash = s.block_builder.last_block_hash();

            if block_num != expected_block_number {
                return Err(format!(
                    "Block sequence error: expected #{}, got #{}",
                    expected_block_number, block_num
                ));
            }

            match validate_and_apply_block(
                &block,
                &mut s.note_tree,
                &mut s.nullifier_set,
                expected_block_number,
                expected_parent_hash,
            ) {
                Ok(()) => {
                    let block_hash = block.hash();
                    s.block_builder = BlockBuilder::from_state(block_num + 1, block_hash);

                    // Index confirmed transactions
                    for tx in &block.transactions {
                        let tx_hash_hex = format!("0x{}", hex::encode(tx.tx_hash));
                        s.tx_index.insert(
                            tx_hash_hex,
                            ConfirmedTx {
                                block_number: block_num,
                                tx_type: tx.tx_type,
                            },
                        );
                    }

                    // Persist chain metadata
                    let next = s.block_builder.next_block_number();
                    let last_hash = s.block_builder.last_block_hash();
                    if let Err(e) = s.chain_meta.update(next, last_hash) {
                        warn!("Failed to persist chain metadata during sync: {}", e);
                    }

                    s.blocks.push(block);
                    total_synced += 1;
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to apply block #{} during sync: {}",
                        block_num, e
                    ));
                }
            }
        }

        info!(
            "Synced blocks #{} to #{} ({} total so far)",
            from_block,
            from_block + batch_count - 1,
            total_synced
        );
        from_block += batch_count;
    }

    info!("Chain sync complete: {} blocks applied", total_synced);
    Ok(total_synced)
}

/// Run the node event handler loop.
///
/// Processes events from the P2P layer and updates node state accordingly.
/// Also accepts locally-submitted transactions and produced blocks for
/// broadcast to the P2P network.
pub async fn run_event_handler(
    state: Arc<RwLock<NodeState>>,
    mut net_event_rx: mpsc::Receiver<NetworkEvent>,
    net_cmd_tx: mpsc::Sender<NetworkCommand>,
    mut local_tx_rx: mpsc::Receiver<Transaction>,
    mut local_block_rx: mpsc::Receiver<Block>,
) {
    info!("Node event handler started");

    loop {
        tokio::select! {
            // ── Events from P2P network ──────────────────────────
            event = net_event_rx.recv() => {
                match event {
                    Some(NetworkEvent::TransactionReceived(tx)) => {
                        handle_received_transaction(&state, tx).await;
                    }
                    Some(NetworkEvent::BlockReceived(block)) => {
                        handle_received_block(&state, block).await;
                    }
                    Some(NetworkEvent::PeerConnected(peer_id)) => {
                        info!("Peer connected: {}", peer_id);
                    }
                    Some(NetworkEvent::PeerDisconnected(peer_id)) => {
                        debug!("Peer disconnected: {}", peer_id);
                    }
                    None => {
                        info!("Network event channel closed, shutting down event handler");
                        return;
                    }
                }
            }

            // ── Locally submitted transactions (from RPC) ────────
            tx = local_tx_rx.recv() => {
                match tx {
                    Some(tx) => {
                        let tx_hash = format!("0x{}", hex::encode(&tx.tx_hash[..4]));
                        debug!("Broadcasting local transaction {} to peers", tx_hash);
                        let _ = net_cmd_tx.send(NetworkCommand::BroadcastTransaction(tx)).await;
                    }
                    None => {
                        debug!("Local tx channel closed");
                    }
                }
            }

            // ── Locally produced blocks (from consensus) ─────────
            block = local_block_rx.recv() => {
                match block {
                    Some(block) => {
                        info!("Broadcasting local block #{} to peers", block.header.block_number);
                        let _ = net_cmd_tx.send(NetworkCommand::BroadcastBlock(block)).await;
                    }
                    None => {
                        debug!("Local block channel closed");
                    }
                }
            }
        }
    }
}

/// Handle a transaction received from a peer.
///
/// Validates it hasn't been seen before and adds to mempool.
async fn handle_received_transaction(
    state: &Arc<RwLock<NodeState>>,
    tx: Transaction,
) {
    let tx_hash = format!("0x{}", hex::encode(&tx.tx_hash[..4]));
    let mut s = state.write().await;

    // Check if already in mempool or confirmed
    let tx_hash_full = format!("0x{}", hex::encode(tx.tx_hash));
    if s.mempool.contains_tx_hash(&tx_hash_full) {
        debug!("Transaction {} already in mempool, ignoring", tx_hash);
        return;
    }
    if s.tx_index.contains_key(&tx_hash_full) {
        debug!("Transaction {} already confirmed, ignoring", tx_hash);
        return;
    }

    // Check nullifiers
    for nf in &tx.nullifiers {
        match s.nullifier_set.contains(nf) {
            Ok(true) => {
                debug!("Transaction {} has spent nullifier, rejecting", tx_hash);
                return;
            }
            Err(e) => {
                warn!("Nullifier check failed for {}: {}", tx_hash, e);
                return;
            }
            _ => {}
        }
    }

    // Add to mempool (unchecked since we already validated nullifiers)
    s.mempool.submit_unchecked(tx);
    debug!("Added transaction {} from peer to mempool", tx_hash);
}

/// Handle a block received from a peer.
///
/// Validates the block against our current state and applies it if valid.
async fn handle_received_block(
    state: &Arc<RwLock<NodeState>>,
    block: Block,
) {
    let block_num = block.header.block_number;

    let mut s = state.write().await;

    let expected_block_number = s.block_builder.next_block_number();
    let expected_parent_hash = s.block_builder.last_block_hash();

    // Skip blocks we already have
    if block_num < expected_block_number {
        debug!("Block #{} already applied, ignoring", block_num);
        return;
    }

    // Skip blocks from the future (we'll get them via gossip or sync)
    if block_num > expected_block_number {
        info!(
            "Block #{} is ahead of our state (expected #{}), queueing for later",
            block_num, expected_block_number
        );
        // TODO: implement block queue for out-of-order delivery
        return;
    }

    // Validate and apply the block
    match validate_and_apply_block(
        &block,
        &mut s.note_tree,
        &mut s.nullifier_set,
        expected_block_number,
        expected_parent_hash,
    ) {
        Ok(()) => {
            // Update block builder state
            let block_hash = block.hash();
            s.block_builder = crate::block::BlockBuilder::from_state(
                block_num + 1,
                block_hash,
            );

            // Index confirmed transactions
            for tx in &block.transactions {
                let tx_hash_hex = format!("0x{}", hex::encode(tx.tx_hash));
                s.tx_index.insert(tx_hash_hex, ConfirmedTx {
                    block_number: block_num,
                    tx_type: tx.tx_type,
                });
            }

            // Purge confirmed nullifiers from mempool
            let all_nullifiers: Vec<_> = block
                .transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.clone())
                .collect();
            if !all_nullifiers.is_empty() {
                s.mempool.purge_confirmed_nullifiers(&all_nullifiers);
            }

            // Persist chain metadata
            let next = s.block_builder.next_block_number();
            let last_hash = s.block_builder.last_block_hash();
            if let Err(e) = s.chain_meta.update(next, last_hash) {
                warn!("Failed to persist chain metadata: {}", e);
            }

            s.blocks.push(block);

            info!(
                "Applied block #{} from peer ({} txs)",
                block_num,
                s.blocks.last().map_or(0, |b| b.header.tx_count)
            );
        }
        Err(e) => {
            warn!("Rejected block #{} from peer: {}", block_num, e);
        }
    }
}
