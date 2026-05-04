// Tonkl Protocol - Block Format, Builder, and Validator
//
// Defines the on-chain block structure and the logic for producing
// and validating blocks in the single-node testnet.
//
// Block structure:
//   Header: block_number, parent_hash, merkle_root, timestamp, tx_count
//   Body:   list of transactions (each with proof + public inputs)
//
// Transaction types:
//   Transfer (1-in/1-out), Merge (32-in/1-out), Split (1-in/32-out), Mint (0-in/32-out)
//
// Each transaction carries:
//   - Circuit type identifier
//   - Public inputs (serialized field elements)
//   - Proof bytes (opaque to the node; verified by bb)
//   - New commitments to insert into the note tree
//   - Nullifiers to insert into the nullifier set (except mint)

use crate::state::{NoteTree, NullifierSet, StateError, field_to_hex};
use obscura_prover::{FieldElement, fe_to_be_32};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

/// Transaction type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TxType {
    Transfer,  // 1-in/1-out
    Merge,     // 32-in/1-out
    Split,     // 1-in/32-out
    Mint,      // 0-in/32-out
}

/// A shielded transaction ready for block inclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Circuit type
    pub tx_type: TxType,
    /// Unique transaction hash (BLAKE3 of proof + public inputs)
    pub tx_hash: [u8; 32],
    /// Proof bytes (opaque, verified by bb)
    pub proof: Vec<u8>,
    /// Public inputs as hex-encoded field elements
    pub public_inputs: Vec<String>,
    /// New note commitments to add to the tree
    pub new_commitments: Vec<FieldElement>,
    /// Nullifiers to add to the nullifier set (empty for Mint)
    pub nullifiers: Vec<FieldElement>,
    /// Merkle root the transaction was proven against
    pub merkle_root: FieldElement,
    /// Fee (public input)
    pub fee: u64,
    /// Asset ID
    pub asset_id: FieldElement,
}

/// Block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Sequential block number (0 = genesis)
    pub block_number: u64,
    /// BLAKE3 hash of the parent block header (all zeros for genesis)
    pub parent_hash: [u8; 32],
    /// Merkle root AFTER applying all transactions in this block
    pub state_root: String,
    /// Block production timestamp (Unix seconds)
    pub timestamp: u64,
    /// Number of transactions in this block
    pub tx_count: u32,
}

/// A complete block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Compute the BLAKE3 hash of this block's header.
    pub fn hash(&self) -> [u8; 32] {
        let header_bytes = bincode::serialize(&self.header).unwrap_or_default();
        *blake3::hash(&header_bytes).as_bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Block Builder
// ─────────────────────────────────────────────────────────────────────

/// Builds blocks from a set of validated transactions.
pub struct BlockBuilder {
    /// Current block number
    next_block_number: u64,
    /// Hash of the last produced block
    last_block_hash: [u8; 32],
}

impl BlockBuilder {
    pub fn new() -> Self {
        Self {
            next_block_number: 0,
            last_block_hash: [0u8; 32], // Genesis parent
        }
    }

    /// Resume from a known state (e.g., after restart).
    pub fn from_state(next_block_number: u64, last_block_hash: [u8; 32]) -> Self {
        Self {
            next_block_number,
            last_block_hash,
        }
    }

    /// Build a block from the given transactions.
    /// Does NOT validate transactions — caller must ensure they are valid.
    /// Does NOT apply state changes — caller must apply after building.
    pub fn build_block(
        &mut self,
        transactions: Vec<Transaction>,
        state_root: String,
    ) -> Block {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let header = BlockHeader {
            block_number: self.next_block_number,
            parent_hash: self.last_block_hash,
            state_root,
            timestamp: now,
            tx_count: transactions.len() as u32,
        };

        let block = Block {
            header,
            transactions,
        };

        // Update builder state
        self.last_block_hash = block.hash();
        self.next_block_number += 1;

        block
    }

    pub fn next_block_number(&self) -> u64 {
        self.next_block_number
    }

    pub fn last_block_hash(&self) -> [u8; 32] {
        self.last_block_hash
    }
}

// ─────────────────────────────────────────────────────────────────────
// Block Validator
// ─────────────────────────────────────────────────────────────────────

/// Validation errors.
#[derive(Debug)]
pub enum ValidationError {
    State(StateError),
    InvalidBlockNumber { expected: u64, got: u64 },
    InvalidParentHash,
    InvalidStateRoot,
    DuplicateNullifier(String),
    NullifierConflictInBlock(String),
    StaleTransaction { tx_root: String, current_root: String },
    ProofVerificationFailed(String),
    EmptyBlock,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(e) => write!(f, "state error: {}", e),
            Self::InvalidBlockNumber { expected, got } => {
                write!(f, "invalid block number: expected {}, got {}", expected, got)
            }
            Self::InvalidParentHash => write!(f, "invalid parent hash"),
            Self::InvalidStateRoot => write!(f, "invalid state root after applying transactions"),
            Self::DuplicateNullifier(nf) => write!(f, "duplicate nullifier: {}", nf),
            Self::NullifierConflictInBlock(nf) => {
                write!(f, "nullifier conflict within block: {}", nf)
            }
            Self::StaleTransaction { tx_root, current_root } => {
                write!(f, "stale tx: proven against {} but current root is {}", tx_root, current_root)
            }
            Self::ProofVerificationFailed(msg) => write!(f, "proof verification failed: {}", msg),
            Self::EmptyBlock => write!(f, "empty block"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<StateError> for ValidationError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

/// Validate a block against the current state and apply it.
///
/// This performs:
///   1. Header validation (block number, parent hash)
///   2. Per-transaction validation:
///      - Nullifier uniqueness (no double-spend)
///      - No intra-block nullifier conflicts
///   3. State application:
///      - Insert new commitments into the note tree
///      - Insert nullifiers into the nullifier set
///   4. State root verification
///
/// Note: Proof verification is currently a stub — in production, each
/// tx's proof would be verified via `bb verify` with the appropriate VK.
pub fn validate_and_apply_block(
    block: &Block,
    note_tree: &mut NoteTree,
    nullifier_set: &mut NullifierSet,
    expected_block_number: u64,
    expected_parent_hash: [u8; 32],
) -> Result<(), ValidationError> {
    // 1. Header checks
    if block.header.block_number != expected_block_number {
        return Err(ValidationError::InvalidBlockNumber {
            expected: expected_block_number,
            got: block.header.block_number,
        });
    }
    if block.header.parent_hash != expected_parent_hash {
        return Err(ValidationError::InvalidParentHash);
    }

    // 2. Collect all nullifiers in this block, check for intra-block conflicts
    let mut block_nullifiers = std::collections::HashSet::new();
    for tx in &block.transactions {
        for nf in &tx.nullifiers {
            let nf_hex = format!("0x{}", hex::encode(fe_to_be_32(nf)));
            if !block_nullifiers.insert(nf_hex.clone()) {
                return Err(ValidationError::NullifierConflictInBlock(nf_hex));
            }
            // Check against existing nullifier set
            if nullifier_set.contains(nf)? {
                return Err(ValidationError::DuplicateNullifier(nf_hex));
            }
        }
    }

    // 3. Apply state changes
    for tx in &block.transactions {
        // Insert new commitments
        for cm in &tx.new_commitments {
            note_tree.insert(*cm)?;
        }
        // Insert nullifiers
        if !tx.nullifiers.is_empty() {
            nullifier_set.insert_batch(&tx.nullifiers)?;
        }
    }

    // 4. Verify state root
    let actual_root = field_to_hex(note_tree.root()?);
    if actual_root != block.header.state_root {
        return Err(ValidationError::InvalidStateRoot);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use obscura_prover::AcirField;

    fn temp_db() -> sled::Db {
        sled::Config::new().temporary(true).open().unwrap()
    }

    #[test]
    fn test_block_builder_genesis() {
        let mut builder = BlockBuilder::new();
        assert_eq!(builder.next_block_number(), 0);

        let block = builder.build_block(vec![], "0x00".to_string());
        assert_eq!(block.header.block_number, 0);
        assert_eq!(block.header.parent_hash, [0u8; 32]);
        assert_eq!(block.header.tx_count, 0);
        assert_eq!(builder.next_block_number(), 1);
    }

    #[test]
    fn test_block_builder_chain() {
        let mut builder = BlockBuilder::new();

        let b0 = builder.build_block(vec![], "root0".to_string());
        let b1 = builder.build_block(vec![], "root1".to_string());

        assert_eq!(b1.header.block_number, 1);
        assert_eq!(b1.header.parent_hash, b0.hash());
    }

    #[test]
    fn test_validate_empty_genesis() {
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        let state_root = field_to_hex(note_tree.root().unwrap());
        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![], state_root);

        let result = validate_and_apply_block(
            &block,
            &mut note_tree,
            &mut nf_set,
            0,
            [0u8; 32],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_block_with_mint_tx() {
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        // Create a mint transaction (no nullifiers)
        let cm1 = FieldElement::from(1111u128);
        let cm2 = FieldElement::from(2222u128);

        let tx = Transaction {
            tx_type: TxType::Mint,
            tx_hash: [0u8; 32],
            proof: vec![],
            public_inputs: vec![],
            new_commitments: vec![cm1, cm2],
            nullifiers: vec![],
            merkle_root: FieldElement::zero(),
            fee: 0,
            asset_id: FieldElement::from(1u128),
        };

        // Pre-apply to get expected root
        let mut preview_tree = NoteTree::open(&temp_db()).unwrap();
        preview_tree.insert(cm1).unwrap();
        preview_tree.insert(cm2).unwrap();
        let expected_root = field_to_hex(preview_tree.root().unwrap());

        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![tx], expected_root);

        let result = validate_and_apply_block(
            &block,
            &mut note_tree,
            &mut nf_set,
            0,
            [0u8; 32],
        );
        assert!(result.is_ok());
        assert_eq!(note_tree.leaf_count(), 2);
    }

    #[test]
    fn test_validate_rejects_wrong_block_number() {
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        let mut builder = BlockBuilder::new();
        // Build block 0 but skip it
        let _ = builder.build_block(vec![], "root".to_string());
        // Build block 1
        let block = builder.build_block(vec![], "root".to_string());

        // Try to apply as block 0 — should fail
        let result = validate_and_apply_block(
            &block,
            &mut note_tree,
            &mut nf_set,
            0,
            [0u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_duplicate_nullifier() {
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        let nf = FieldElement::from(999u128);

        // Insert nullifier into the set first
        nf_set.insert(nf).unwrap();

        // Try to include a tx that spends the same nullifier
        let tx = Transaction {
            tx_type: TxType::Transfer,
            tx_hash: [1u8; 32],
            proof: vec![],
            public_inputs: vec![],
            new_commitments: vec![FieldElement::from(123u128)],
            nullifiers: vec![nf],
            merkle_root: FieldElement::zero(),
            fee: 0,
            asset_id: FieldElement::from(1u128),
        };

        let state_root = field_to_hex(note_tree.root().unwrap());
        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![tx], state_root);

        let result = validate_and_apply_block(
            &block,
            &mut note_tree,
            &mut nf_set,
            0,
            [0u8; 32],
        );
        assert!(result.is_err());
    }
}
