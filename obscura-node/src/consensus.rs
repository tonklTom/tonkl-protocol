// Tonkl Protocol - Basic Consensus / Leader Selection
//
// Simple round-robin block producer for the local testnet.
//
// In the current phase this is a lightweight consensus stub:
//   - A fixed validator set (list of node identifiers)
//   - Round-robin leader rotation by block number
//   - Automatic block production on a configurable interval
//   - Nodes that are not the current leader skip their slot
//
// This is intentionally minimal — a future phase will add stake-weighted
// selection, slashing conditions, and BFT finality.

use crate::rpc::NodeState;
use crate::state::field_to_hex;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

// ─────────────────────────────────────────────────────────────────────
// Validator set
// ─────────────────────────────────────────────────────────────────────

/// A validator identified by a simple string ID (e.g., "node-0").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatorId(pub String);

impl std::fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An ordered set of validators that participate in block production.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    validators: Vec<ValidatorId>,
}

impl ValidatorSet {
    /// Create a validator set from a list of IDs.
    /// Panics if the list is empty.
    pub fn new(validators: Vec<ValidatorId>) -> Self {
        assert!(!validators.is_empty(), "validator set cannot be empty");
        Self { validators }
    }

    /// Create a single-validator set (for solo testnet mode).
    pub fn solo(id: &str) -> Self {
        Self {
            validators: vec![ValidatorId(id.to_string())],
        }
    }

    /// How many validators are in the set.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Get the leader for a given block number using round-robin.
    pub fn leader_for_block(&self, block_number: u64) -> &ValidatorId {
        let idx = (block_number as usize) % self.validators.len();
        &self.validators[idx]
    }

    /// Check if a given validator is the leader for a block number.
    pub fn is_leader(&self, validator: &ValidatorId, block_number: u64) -> bool {
        self.leader_for_block(block_number) == validator
    }
}

// ─────────────────────────────────────────────────────────────────────
// Consensus configuration
// ─────────────────────────────────────────────────────────────────────

/// Configuration for the block production loop.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// This node's validator ID
    pub node_id: ValidatorId,
    /// The validator set for leader selection
    pub validator_set: ValidatorSet,
    /// How often to attempt block production
    pub block_interval: Duration,
    /// Maximum transactions per block
    pub max_txs_per_block: usize,
    /// Whether to produce empty blocks (keeps the chain moving)
    pub produce_empty_blocks: bool,
}

impl ConsensusConfig {
    /// Default config for a solo testnet node.
    pub fn solo_testnet() -> Self {
        Self {
            node_id: ValidatorId("node-0".to_string()),
            validator_set: ValidatorSet::solo("node-0"),
            block_interval: Duration::from_secs(5),
            max_txs_per_block: 256,
            produce_empty_blocks: false,
        }
    }

    /// Config for a multi-node testnet.
    pub fn multi_node(node_id: &str, node_ids: Vec<String>, interval_secs: u64) -> Self {
        let validators: Vec<ValidatorId> = node_ids.into_iter().map(ValidatorId).collect();
        Self {
            node_id: ValidatorId(node_id.to_string()),
            validator_set: ValidatorSet::new(validators),
            block_interval: Duration::from_secs(interval_secs),
            max_txs_per_block: 256,
            produce_empty_blocks: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Block production loop
// ─────────────────────────────────────────────────────────────────────

/// Run the block production loop.
///
/// This spawns a background task that:
///   1. Waits for the block interval to elapse
///   2. Checks if this node is the leader for the next block
///   3. If leader and there are pending txs (or produce_empty_blocks), builds a block
///   4. Applies the block to state
///
/// The loop runs until the cancellation token is triggered.
pub async fn run_block_producer(
    state: Arc<RwLock<NodeState>>,
    config: ConsensusConfig,
    cancel: tokio::sync::watch::Receiver<bool>,
) {
    info!(
        "Block producer started: node={}, validators={}, interval={}s",
        config.node_id,
        config.validator_set.len(),
        config.block_interval.as_secs()
    );

    let mut interval = tokio::time::interval(config.block_interval);
    // Skip the first immediate tick
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Check cancellation
                if *cancel.borrow() {
                    info!("Block producer shutting down");
                    return;
                }

                produce_block_if_leader(&state, &config).await;
            }
        }
    }
}

/// Attempt to produce a block if this node is the current leader.
async fn produce_block_if_leader(
    state: &Arc<RwLock<NodeState>>,
    config: &ConsensusConfig,
) {
    let next_block = {
        let s = state.read().await;
        s.block_builder.next_block_number()
    };

    let leader = config.validator_set.leader_for_block(next_block);

    if leader != &config.node_id {
        debug!(
            "Not leader for block #{} (leader is {}), skipping",
            next_block, leader
        );
        return;
    }

    // We are the leader — produce a block
    let mut s = state.write().await;

    let txs = s.mempool.drain_for_block(config.max_txs_per_block);

    if txs.is_empty() && !config.produce_empty_blocks {
        debug!("No pending transactions, skipping block #{}", next_block);
        return;
    }

    // Apply transactions to state
    for tx in &txs {
        for cm in &tx.new_commitments {
            if let Err(e) = s.note_tree.insert(*cm) {
                warn!("Failed to insert commitment: {}", e);
                return;
            }
        }
        if !tx.nullifiers.is_empty() {
            if let Err(e) = s.nullifier_set.insert_batch(&tx.nullifiers) {
                warn!("Failed to insert nullifiers: {}", e);
                return;
            }
        }
    }

    let root = match s.note_tree.root() {
        Ok(r) => field_to_hex(r),
        Err(e) => {
            warn!("Failed to get state root: {}", e);
            return;
        }
    };

    let all_nullifiers: Vec<_> = txs.iter().flat_map(|tx| tx.nullifiers.clone()).collect();

    let block = s.block_builder.build_block(txs, root);
    let header = block.header.clone();

    // Index confirmed transactions
    for tx in &block.transactions {
        let tx_hash_hex = format!("0x{}", hex::encode(tx.tx_hash));
        s.tx_index.insert(tx_hash_hex, crate::rpc::ConfirmedTx {
            block_number: header.block_number,
            tx_type: tx.tx_type,
        });
    }

    info!(
        "Block #{} produced by {} ({} txs, root: {})",
        header.block_number, config.node_id, header.tx_count, header.state_root
    );

    // Persist block metadata so the node survives restarts
    let next = s.block_builder.next_block_number();
    let last_hash = s.block_builder.last_block_hash();
    if let Err(e) = s.chain_meta.update(next, last_hash) {
        warn!("Failed to persist chain metadata: {}", e);
    }

    s.blocks.push(block);

    if !all_nullifiers.is_empty() {
        s.mempool.purge_confirmed_nullifiers(&all_nullifiers);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solo_validator_always_leader() {
        let vs = ValidatorSet::solo("node-0");
        let id = ValidatorId("node-0".to_string());

        for block in 0..100 {
            assert!(vs.is_leader(&id, block));
        }
    }

    #[test]
    fn test_round_robin_rotation() {
        let vs = ValidatorSet::new(vec![
            ValidatorId("node-0".to_string()),
            ValidatorId("node-1".to_string()),
            ValidatorId("node-2".to_string()),
        ]);

        assert_eq!(vs.leader_for_block(0).0, "node-0");
        assert_eq!(vs.leader_for_block(1).0, "node-1");
        assert_eq!(vs.leader_for_block(2).0, "node-2");
        assert_eq!(vs.leader_for_block(3).0, "node-0"); // wraps
        assert_eq!(vs.leader_for_block(4).0, "node-1");
        assert_eq!(vs.leader_for_block(5).0, "node-2");
    }

    #[test]
    fn test_is_leader_check() {
        let vs = ValidatorSet::new(vec![
            ValidatorId("a".to_string()),
            ValidatorId("b".to_string()),
        ]);

        let a = ValidatorId("a".to_string());
        let b = ValidatorId("b".to_string());

        assert!(vs.is_leader(&a, 0));
        assert!(!vs.is_leader(&b, 0));
        assert!(!vs.is_leader(&a, 1));
        assert!(vs.is_leader(&b, 1));
    }

    #[test]
    fn test_consensus_config_solo() {
        let cfg = ConsensusConfig::solo_testnet();
        assert_eq!(cfg.node_id.0, "node-0");
        assert_eq!(cfg.validator_set.len(), 1);
        assert_eq!(cfg.block_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_consensus_config_multi() {
        let cfg = ConsensusConfig::multi_node(
            "node-1",
            vec!["node-0".into(), "node-1".into(), "node-2".into()],
            3,
        );
        assert_eq!(cfg.node_id.0, "node-1");
        assert_eq!(cfg.validator_set.len(), 3);
        assert_eq!(cfg.block_interval, Duration::from_secs(3));
    }

    #[test]
    #[should_panic(expected = "validator set cannot be empty")]
    fn test_empty_validator_set_panics() {
        ValidatorSet::new(vec![]);
    }
}
