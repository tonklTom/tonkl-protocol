// Tonkl Protocol - Transaction Pool (Mempool)
//
// In-memory priority queue of pending transactions awaiting block inclusion.
//
// Prioritization:
//   - Higher fee transactions are included first
//   - Within the same fee tier, earlier arrivals go first (FIFO)
//
// Validation on submission:
//   - Nullifiers must not conflict with the existing nullifier set
//   - Nullifiers must not conflict with other mempool transactions
//   - Basic structural checks (non-empty commitments, etc.)
//
// Future extensions:
//   - Threshold-encrypted mempool (transactions encrypted until inclusion)
//   - Rate limiting per sender
//   - Transaction expiry

use crate::block::Transaction;
use crate::state::NullifierSet;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use tonkl_prover::{fe_to_be_32, FieldElement};

// ─────────────────────────────────────────────────────────────────────
// Mempool Entry
// ─────────────────────────────────────────────────────────────────────

/// A transaction in the mempool, with priority metadata.
#[derive(Debug, Clone)]
struct MempoolEntry {
    tx: Transaction,
    /// Fee per unit (for ordering)
    fee: u64,
    /// Arrival sequence number (lower = earlier)
    sequence: u64,
}

impl PartialEq for MempoolEntry {
    fn eq(&self, other: &Self) -> bool {
        self.tx.tx_hash == other.tx.tx_hash
    }
}

impl Eq for MempoolEntry {}

impl PartialOrd for MempoolEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher fee first, then earlier arrival first
        self.fee
            .cmp(&other.fee)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

// ─────────────────────────────────────────────────────────────────────
// Mempool
// ─────────────────────────────────────────────────────────────────────

/// Transaction pool errors.
#[derive(Debug)]
pub enum MempoolError {
    /// Transaction already in the mempool
    DuplicateTransaction,
    /// Nullifier conflicts with an already-spent nullifier
    SpentNullifier(String),
    /// Nullifier conflicts with another mempool transaction
    NullifierConflict(String),
    /// Transaction has no commitments
    NoCommitments,
    /// State error during nullifier check
    StateError(String),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateTransaction => write!(f, "transaction already in mempool"),
            Self::SpentNullifier(nf) => write!(f, "nullifier already spent: {}", nf),
            Self::NullifierConflict(nf) => write!(f, "nullifier conflicts with mempool tx: {}", nf),
            Self::NoCommitments => write!(f, "transaction has no output commitments"),
            Self::StateError(msg) => write!(f, "state error: {}", msg),
        }
    }
}

impl std::error::Error for MempoolError {}

/// In-memory transaction pool with fee-based prioritization.
pub struct Mempool {
    /// Priority queue (max-heap by fee)
    queue: BinaryHeap<MempoolEntry>,
    /// Track tx hashes to prevent duplicates
    tx_hashes: HashSet<[u8; 32]>,
    /// Track nullifiers claimed by mempool transactions
    pending_nullifiers: HashMap<String, [u8; 32]>, // nf_hex -> tx_hash
    /// Sequence counter for arrival ordering
    next_sequence: u64,
    /// Maximum mempool size
    max_size: usize,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: BinaryHeap::new(),
            tx_hashes: HashSet::new(),
            pending_nullifiers: HashMap::new(),
            next_sequence: 0,
            max_size,
        }
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Iterate over pending transactions without draining the mempool.
    pub fn transactions(&self) -> impl Iterator<Item = &Transaction> {
        self.queue.iter().map(|entry| &entry.tx)
    }

    /// Check whether a transaction with the given hex hash is pending in the mempool.
    /// Accepts both "0x"-prefixed and bare hex strings.
    pub fn contains_tx_hash(&self, tx_hash_hex: &str) -> bool {
        let clean = tx_hash_hex.strip_prefix("0x").unwrap_or(tx_hash_hex);
        match hex::decode(clean) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                self.tx_hashes.contains(&arr)
            }
            _ => false,
        }
    }

    /// Submit a transaction to the mempool.
    /// Validates against the nullifier set and existing mempool entries.
    pub fn submit(
        &mut self,
        tx: Transaction,
        nullifier_set: &NullifierSet,
    ) -> Result<(), MempoolError> {
        // Check for duplicate
        if self.tx_hashes.contains(&tx.tx_hash) {
            return Err(MempoolError::DuplicateTransaction);
        }

        // Check for empty commitments
        if tx.new_commitments.is_empty() {
            return Err(MempoolError::NoCommitments);
        }

        // Check nullifiers against spent set
        for nf in &tx.nullifiers {
            let nf_hex = format!("0x{}", hex::encode(fe_to_be_32(nf)));

            if nullifier_set
                .contains(nf)
                .map_err(|e| MempoolError::StateError(e.to_string()))?
            {
                return Err(MempoolError::SpentNullifier(nf_hex));
            }

            if let Some(existing_tx_hash) = self.pending_nullifiers.get(&nf_hex) {
                if existing_tx_hash != &tx.tx_hash {
                    return Err(MempoolError::NullifierConflict(nf_hex));
                }
            }
        }

        // Evict lowest-fee tx if at capacity
        if self.queue.len() >= self.max_size {
            // Only evict if new tx has higher fee than the lowest
            // Since BinaryHeap is a max-heap, we'd need a min-heap to find
            // the lowest. For simplicity, just reject if full.
            // TODO: Use a double-ended priority queue for proper eviction
            return Err(MempoolError::DuplicateTransaction); // placeholder
        }

        // Record nullifier claims
        for nf in &tx.nullifiers {
            let nf_hex = format!("0x{}", hex::encode(fe_to_be_32(nf)));
            self.pending_nullifiers.insert(nf_hex, tx.tx_hash);
        }

        let fee = tx.fee;
        let sequence = self.next_sequence;
        self.next_sequence += 1;

        self.tx_hashes.insert(tx.tx_hash);
        self.queue.push(MempoolEntry { tx, fee, sequence });

        Ok(())
    }

    /// Submit a transaction without nullifier-set checks.
    /// Caller is responsible for checking nullifiers beforehand.
    /// This avoids borrow-checker issues when both mempool and nullifier_set
    /// are behind the same RwLock.
    pub fn submit_unchecked(&mut self, tx: Transaction) {
        for nf in &tx.nullifiers {
            let nf_hex = format!("0x{}", hex::encode(fe_to_be_32(nf)));
            self.pending_nullifiers.insert(nf_hex, tx.tx_hash);
        }
        let fee = tx.fee;
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.tx_hashes.insert(tx.tx_hash);
        self.queue.push(MempoolEntry { tx, fee, sequence });
    }

    /// Drain up to `max_count` highest-priority transactions for block inclusion.
    pub fn drain_for_block(&mut self, max_count: usize) -> Vec<Transaction> {
        let mut txs = Vec::with_capacity(max_count);

        while txs.len() < max_count {
            match self.queue.pop() {
                Some(entry) => {
                    self.tx_hashes.remove(&entry.tx.tx_hash);
                    // Remove nullifier claims
                    for nf in &entry.tx.nullifiers {
                        let nf_hex = format!("0x{}", hex::encode(fe_to_be_32(nf)));
                        self.pending_nullifiers.remove(&nf_hex);
                    }
                    txs.push(entry.tx);
                }
                None => break,
            }
        }

        txs
    }

    /// Remove transactions that conflict with newly confirmed nullifiers.
    /// Called after a block is applied to the state.
    pub fn purge_confirmed_nullifiers(&mut self, confirmed_nullifiers: &[FieldElement]) {
        let confirmed_set: HashSet<String> = confirmed_nullifiers
            .iter()
            .map(|nf| format!("0x{}", hex::encode(fe_to_be_32(nf))))
            .collect();

        // Rebuild the queue without conflicting transactions
        let old_queue: Vec<MempoolEntry> = self.queue.drain().collect();
        self.tx_hashes.clear();
        self.pending_nullifiers.clear();

        for entry in old_queue {
            let has_conflict = entry.tx.nullifiers.iter().any(|nf| {
                let nf_hex = format!("0x{}", hex::encode(fe_to_be_32(nf)));
                confirmed_set.contains(&nf_hex)
            });

            if !has_conflict {
                // Re-add to mempool
                for nf in &entry.tx.nullifiers {
                    let nf_hex = format!("0x{}", hex::encode(fe_to_be_32(nf)));
                    self.pending_nullifiers.insert(nf_hex, entry.tx.tx_hash);
                }
                self.tx_hashes.insert(entry.tx.tx_hash);
                self.queue.push(entry);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::TxType;
    use crate::state::NullifierSet;
    use tonkl_prover::AcirField;

    fn temp_db() -> sled::Db {
        sled::Config::new().temporary(true).open().unwrap()
    }

    fn make_tx(hash_byte: u8, fee: u64, nullifiers: Vec<FieldElement>) -> Transaction {
        Transaction {
            tx_type: TxType::Transfer,
            tx_hash: {
                let mut h = [0u8; 32];
                h[0] = hash_byte;
                h
            },
            proof: vec![],
            public_inputs: vec![],
            new_commitments: vec![FieldElement::from(hash_byte as u128)],
            nullifiers,
            merkle_root: FieldElement::zero(),
            fee,
            asset_id: FieldElement::from(1u128),
        }
    }

    #[test]
    fn test_empty_mempool() {
        let pool = Mempool::new(100);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_submit_and_drain() {
        let db = temp_db();
        let nf_set = NullifierSet::open(&db).unwrap();
        let mut pool = Mempool::new(100);

        let tx1 = make_tx(1, 10, vec![]);
        let tx2 = make_tx(2, 20, vec![]);
        let tx3 = make_tx(3, 5, vec![]);

        pool.submit(tx1, &nf_set).unwrap();
        pool.submit(tx2, &nf_set).unwrap();
        pool.submit(tx3, &nf_set).unwrap();

        assert_eq!(pool.len(), 3);

        // Drain should return highest fee first
        let drained = pool.drain_for_block(10);
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].fee, 20); // highest fee
        assert_eq!(drained[1].fee, 10);
        assert_eq!(drained[2].fee, 5); // lowest fee

        assert!(pool.is_empty());
    }

    #[test]
    fn test_reject_duplicate_tx() {
        let db = temp_db();
        let nf_set = NullifierSet::open(&db).unwrap();
        let mut pool = Mempool::new(100);

        let tx = make_tx(1, 10, vec![]);
        pool.submit(tx.clone(), &nf_set).unwrap();

        let result = pool.submit(tx, &nf_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_spent_nullifier() {
        let db = temp_db();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        let nf = FieldElement::from(999u128);
        nf_set.insert(nf).unwrap();

        let mut pool = Mempool::new(100);
        let tx = make_tx(1, 10, vec![nf]);

        let result = pool.submit(tx, &nf_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_nullifier_conflict() {
        let db = temp_db();
        let nf_set = NullifierSet::open(&db).unwrap();
        let mut pool = Mempool::new(100);

        let nf = FieldElement::from(42u128);

        let tx1 = make_tx(1, 10, vec![nf]);
        let tx2 = make_tx(2, 20, vec![nf]); // same nullifier, different tx

        pool.submit(tx1, &nf_set).unwrap();
        let result = pool.submit(tx2, &nf_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_purge_confirmed_nullifiers() {
        let db = temp_db();
        let nf_set = NullifierSet::open(&db).unwrap();
        let mut pool = Mempool::new(100);

        let nf1 = FieldElement::from(111u128);
        let nf2 = FieldElement::from(222u128);

        let tx1 = make_tx(1, 10, vec![nf1]);
        let tx2 = make_tx(2, 20, vec![nf2]);

        pool.submit(tx1, &nf_set).unwrap();
        pool.submit(tx2, &nf_set).unwrap();
        assert_eq!(pool.len(), 2);

        // Confirm nf1 — tx1 should be purged
        pool.purge_confirmed_nullifiers(&[nf1]);
        assert_eq!(pool.len(), 1);

        let drained = pool.drain_for_block(10);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].fee, 20); // tx2 remains
    }
}
