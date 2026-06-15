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

use crate::rpc::MintPolicy;
use crate::state::{field_to_hex, ChainMeta, NoteTree, NullifierSet, StateError};
use crate::verifier::{serialize_public_inputs, ProofVerifier};
use serde::{Deserialize, Serialize};
use tonkl_prover::{fe_to_be_32, AcirField, FieldElement};

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

/// Transaction type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TxType {
    Transfer, // 1-in/1-out
    Merge,    // 32-in/1-out
    Split,    // 1-in/32-out
    Mint,     // 0-in/32-out
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
    pub fn build_block(&mut self, transactions: Vec<Transaction>, state_root: String) -> Block {
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
    InvalidBlockNumber {
        expected: u64,
        got: u64,
    },
    InvalidParentHash,
    InvalidStateRoot,
    InvalidTransactionHash(String),
    DuplicateNullifier(String),
    NullifierConflictInBlock(String),
    StaleTransaction {
        tx_root: String,
        current_root: String,
    },
    ProofVerificationFailed(String),
    MintPolicy(String),
    EmptyBlock,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(e) => write!(f, "state error: {}", e),
            Self::InvalidBlockNumber { expected, got } => {
                write!(
                    f,
                    "invalid block number: expected {}, got {}",
                    expected, got
                )
            }
            Self::InvalidParentHash => write!(f, "invalid parent hash"),
            Self::InvalidStateRoot => write!(f, "invalid state root after applying transactions"),
            Self::InvalidTransactionHash(msg) => write!(f, "invalid transaction hash: {}", msg),
            Self::DuplicateNullifier(nf) => write!(f, "duplicate nullifier: {}", nf),
            Self::NullifierConflictInBlock(nf) => {
                write!(f, "nullifier conflict within block: {}", nf)
            }
            Self::StaleTransaction {
                tx_root,
                current_root,
            } => {
                write!(
                    f,
                    "stale tx: proven against {} but current root is {}",
                    tx_root, current_root
                )
            }
            Self::ProofVerificationFailed(msg) => write!(f, "proof verification failed: {}", msg),
            Self::MintPolicy(msg) => write!(f, "mint policy violation: {}", msg),
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

fn parse_field_string(hex_str: &str) -> Result<FieldElement, String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() > 32 {
        return Err("field element too large".to_string());
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(FieldElement::from_be_bytes_reduce(&padded))
}

fn fee_to_field(fee: u64) -> FieldElement {
    FieldElement::from(fee as u128)
}

fn ensure_count(tx_type: TxType, label: &str, got: usize, expected: usize) -> Result<(), String> {
    if got != expected {
        return Err(format!(
            "{:?} expects {} {}, got {}",
            tx_type, expected, label, got
        ));
    }
    Ok(())
}

fn ensure_public_inputs_equal(
    tx_type: TxType,
    got: &[FieldElement],
    expected: &[FieldElement],
) -> Result<(), String> {
    ensure_count(tx_type, "public inputs", got.len(), expected.len())?;

    for (index, (actual, expected)) in got.iter().zip(expected.iter()).enumerate() {
        if actual != expected {
            return Err(format!(
                "{:?} public_input[{}] does not match transaction field (got {}, expected {})",
                tx_type,
                index,
                field_to_hex(*actual),
                field_to_hex(*expected),
            ));
        }
    }

    Ok(())
}

/// Validate that public inputs bind to the transaction fields the node applies.
///
/// Proof verification proves the supplied public inputs; this check makes sure
/// those inputs match the commitments, nullifiers, root, fee, and asset fields
/// carried by the transaction.
pub fn validate_public_inputs_match_fields(
    tx_type: TxType,
    public_inputs: &[String],
    new_commitments: &[FieldElement],
    nullifiers: &[FieldElement],
    merkle_root: FieldElement,
    fee: u64,
    asset_id: FieldElement,
) -> Result<(), String> {
    let public_inputs = public_inputs
        .iter()
        .map(|value| parse_field_string(value))
        .collect::<Result<Vec<_>, _>>()?;
    let fee = fee_to_field(fee);

    match tx_type {
        TxType::Transfer => {
            ensure_count(tx_type, "commitments", new_commitments.len(), 2)?;
            ensure_count(tx_type, "nullifiers", nullifiers.len(), 2)?;

            let expected = vec![
                merkle_root,
                nullifiers[0],
                nullifiers[1],
                new_commitments[0],
                new_commitments[1],
                fee,
                asset_id,
            ];
            ensure_public_inputs_equal(tx_type, &public_inputs, &expected)
        }
        TxType::Split => {
            ensure_count(tx_type, "commitments", new_commitments.len(), 32)?;
            ensure_count(tx_type, "nullifiers", nullifiers.len(), 1)?;

            let mut expected = Vec::with_capacity(36);
            expected.push(merkle_root);
            expected.push(nullifiers[0]);
            expected.extend_from_slice(new_commitments);
            expected.push(fee);
            expected.push(asset_id);
            ensure_public_inputs_equal(tx_type, &public_inputs, &expected)
        }
        TxType::Merge => {
            ensure_count(tx_type, "commitments", new_commitments.len(), 1)?;
            ensure_count(tx_type, "nullifiers", nullifiers.len(), 32)?;

            let mut expected = Vec::with_capacity(36);
            expected.push(merkle_root);
            expected.extend_from_slice(nullifiers);
            expected.push(new_commitments[0]);
            expected.push(fee);
            expected.push(asset_id);
            ensure_public_inputs_equal(tx_type, &public_inputs, &expected)
        }
        TxType::Mint => {
            ensure_count(tx_type, "public inputs", public_inputs.len(), 36)?;
            ensure_count(tx_type, "commitments", new_commitments.len(), 32)?;
            ensure_count(tx_type, "nullifiers", nullifiers.len(), 0)?;

            for (index, (actual, expected)) in public_inputs
                .iter()
                .take(32)
                .zip(new_commitments.iter())
                .enumerate()
            {
                if actual != expected {
                    return Err(format!(
                        "Mint public_input[{}] does not match commitment (got {}, expected {})",
                        index,
                        field_to_hex(*actual),
                        field_to_hex(*expected),
                    ));
                }
            }

            if public_inputs[33] != asset_id {
                return Err(format!(
                    "Mint public_input[33] does not match asset_id (got {}, expected {})",
                    field_to_hex(public_inputs[33]),
                    field_to_hex(asset_id),
                ));
            }

            Ok(())
        }
    }
}

pub fn validate_transaction_public_inputs(tx: &Transaction) -> Result<(), String> {
    validate_public_inputs_match_fields(
        tx.tx_type,
        &tx.public_inputs,
        &tx.new_commitments,
        &tx.nullifiers,
        tx.merkle_root,
        tx.fee,
        tx.asset_id,
    )
}

/// Returns true if a transaction consumes input notes (and therefore must be
/// anchored to a known Merkle root). Mint creates notes from authority and has
/// no Merkle membership to prove, so it is exempt.
pub fn tx_requires_anchor(tx_type: TxType) -> bool {
    !matches!(tx_type, TxType::Mint)
}

/// SECURITY (anti-counterfeiting): ensure every input-consuming transaction is
/// anchored to a Merkle root the chain has actually committed. A proof anchored
/// to an attacker-constructed tree is cryptographically valid but lets the
/// attacker spend notes that never existed — so the anchor must be a known
/// historical root. Mint is exempt (no inputs).
pub fn ensure_known_anchors(
    chain_meta: &ChainMeta,
    txs: &[Transaction],
) -> Result<(), ValidationError> {
    for tx in txs {
        if !tx_requires_anchor(tx.tx_type) {
            continue;
        }
        let known = chain_meta
            .is_known_anchor(&tx.merkle_root)
            .map_err(ValidationError::State)?;
        if !known {
            return Err(ValidationError::StaleTransaction {
                tx_root: field_to_hex(tx.merkle_root),
                current_root: "not a known anchor".to_string(),
            });
        }
    }
    Ok(())
}

/// SECURITY (single consensus gate): the invariants every block-apply path MUST
/// enforce before mutating state — anchor validity (anti-counterfeiting) and
/// mint authority/supply policy. Co-located here so no apply path can silently
/// skip one. `validate_and_apply_block` calls this internally; the direct-apply
/// production paths (consensus leader, RPC produce_block) call it explicitly.
pub fn enforce_consensus_rules(
    chain_meta: &ChainMeta,
    mint_policy: &MintPolicy,
    txs: &[Transaction],
) -> Result<(), ValidationError> {
    // Anti-counterfeiting: input-consuming txs must anchor to a committed root.
    ensure_known_anchors(chain_meta, txs)?;
    // Supply soundness: only registered authorities mint, within supply caps.
    mint_policy
        .validate_block_mints(chain_meta, txs)
        .map_err(ValidationError::MintPolicy)?;
    Ok(())
}

fn expected_tx_hash(tx: &Transaction) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&tx.proof);
    for pi in &tx.public_inputs {
        hasher.update(pi.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn validate_transaction_proof(
    tx: &Transaction,
    verifier: &ProofVerifier,
) -> Result<(), ValidationError> {
    let expected_hash = expected_tx_hash(tx);
    if tx.tx_hash != expected_hash {
        return Err(ValidationError::InvalidTransactionHash(format!(
            "got 0x{}, expected 0x{}",
            hex::encode(tx.tx_hash),
            hex::encode(expected_hash),
        )));
    }

    validate_transaction_public_inputs(tx).map_err(ValidationError::ProofVerificationFailed)?;

    if !verifier.is_enabled() {
        return Err(ValidationError::ProofVerificationFailed(
            "external block proof verification is disabled".to_string(),
        ));
    }

    let public_inputs_bytes = serialize_public_inputs(&tx.public_inputs).map_err(|e| {
        ValidationError::ProofVerificationFailed(format!("invalid public inputs: {}", e))
    })?;

    verifier
        .verify(tx.tx_type, &tx.proof, &public_inputs_bytes)
        .map_err(ValidationError::ProofVerificationFailed)
}

fn validate_and_apply_block_inner(
    block: &Block,
    verifier: Option<&ProofVerifier>,
    note_tree: &mut NoteTree,
    nullifier_set: &mut NullifierSet,
    chain_meta: &ChainMeta,
    mint_policy: &MintPolicy,
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

    // 2. Verify proofs/public inputs before any state mutation.
    if let Some(verifier) = verifier {
        for tx in &block.transactions {
            validate_transaction_proof(tx, verifier)?;
        }
    }

    // 2.5 Consensus gate (anti-counterfeiting + supply soundness): anchor
    // validity and mint authority/supply, enforced here so this apply path can
    // never skip them. Runs before any state mutation.
    enforce_consensus_rules(chain_meta, mint_policy, &block.transactions)?;

    // 3. Collect all nullifiers in this block, check for intra-block conflicts
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

    // 4. Apply state changes
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

    // 5. Verify state root
    let actual_root = field_to_hex(note_tree.root()?);
    if actual_root != block.header.state_root {
        return Err(ValidationError::InvalidStateRoot);
    }

    Ok(())
}

/// Validate a block against the current state and apply it.
///
/// This performs:
///   1. Header validation (block number, parent hash)
///   2. Per-transaction validation:
///      - Proof verification
///      - Public input binding to transaction fields
///      - Transaction hash binding to proof and public inputs
///      - Nullifier uniqueness (no double-spend)
///      - No intra-block nullifier conflicts
///   3. State application:
///      - Insert new commitments into the note tree
///      - Insert nullifiers into the nullifier set
///   4. State root verification
pub fn validate_and_apply_block(
    block: &Block,
    verifier: &ProofVerifier,
    note_tree: &mut NoteTree,
    nullifier_set: &mut NullifierSet,
    chain_meta: &ChainMeta,
    mint_policy: &MintPolicy,
    expected_block_number: u64,
    expected_parent_hash: [u8; 32],
) -> Result<(), ValidationError> {
    validate_and_apply_block_inner(
        block,
        Some(verifier),
        note_tree,
        nullifier_set,
        chain_meta,
        mint_policy,
        expected_block_number,
        expected_parent_hash,
    )
}

#[cfg(test)]
fn validate_and_apply_block_unverified_for_test(
    block: &Block,
    note_tree: &mut NoteTree,
    nullifier_set: &mut NullifierSet,
    chain_meta: &ChainMeta,
    mint_policy: &MintPolicy,
    expected_block_number: u64,
    expected_parent_hash: [u8; 32],
) -> Result<(), ValidationError> {
    validate_and_apply_block_inner(
        block,
        None,
        note_tree,
        nullifier_set,
        chain_meta,
        mint_policy,
        expected_block_number,
        expected_parent_hash,
    )
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tonkl_prover::AcirField;

    fn temp_db() -> sled::Db {
        sled::Config::new().temporary(true).open().unwrap()
    }

    /// A mint policy with no registered authorities (any mint is rejected).
    fn empty_policy() -> MintPolicy {
        MintPolicy::from_json("{}").unwrap()
    }

    fn tx_hash_for(proof: &[u8], public_inputs: &[String]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(proof);
        for pi in public_inputs {
            hasher.update(pi.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    fn field_hex(value: FieldElement) -> String {
        field_to_hex(value)
    }

    fn valid_transfer_tx() -> Transaction {
        let proof = vec![9u8; 8];
        let merkle_root = FieldElement::zero();
        let nullifiers = vec![FieldElement::from(1u128), FieldElement::from(2u128)];
        let new_commitments = vec![FieldElement::from(123u128), FieldElement::from(124u128)];
        let fee = 0;
        let asset_id = FieldElement::from(1u128);
        let public_inputs = vec![
            field_hex(merkle_root),
            field_hex(nullifiers[0]),
            field_hex(nullifiers[1]),
            field_hex(new_commitments[0]),
            field_hex(new_commitments[1]),
            field_hex(FieldElement::from(fee)),
            field_hex(asset_id),
        ];
        let tx_hash = tx_hash_for(&proof, &public_inputs);

        Transaction {
            tx_type: TxType::Transfer,
            tx_hash,
            proof,
            public_inputs,
            new_commitments,
            nullifiers,
            merkle_root,
            fee: fee as u64,
            asset_id,
        }
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
        let chain_meta = ChainMeta::open(&db).unwrap();

        let result = validate_and_apply_block_unverified_for_test(
            &block,
            &mut note_tree,
            &mut nf_set,
            &chain_meta,
            &empty_policy(),
            0,
            [0u8; 32],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rejects_unregistered_mint() {
        // SECURITY (supply soundness): a mint for an asset with no registered
        // authority must be rejected by the consensus gate before any state
        // mutation — even on the unverified apply path.
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();
        let chain_meta = ChainMeta::open(&db).unwrap();

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

        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![tx], field_to_hex(FieldElement::zero()));

        let result = validate_and_apply_block_unverified_for_test(
            &block,
            &mut note_tree,
            &mut nf_set,
            &chain_meta,
            &empty_policy(),
            0,
            [0u8; 32],
        );
        assert!(matches!(result, Err(ValidationError::MintPolicy(_))));
        assert_eq!(note_tree.leaf_count(), 0);
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
        let chain_meta = ChainMeta::open(&db).unwrap();
        let result = validate_and_apply_block_unverified_for_test(
            &block,
            &mut note_tree,
            &mut nf_set,
            &chain_meta,
            &empty_policy(),
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

        // Record the tx's anchor so it clears the anchor gate and the test
        // actually exercises duplicate-nullifier rejection.
        let chain_meta = ChainMeta::open(&db).unwrap();
        chain_meta.record_anchor(&FieldElement::zero()).unwrap();

        let result = validate_and_apply_block_unverified_for_test(
            &block,
            &mut note_tree,
            &mut nf_set,
            &chain_meta,
            &empty_policy(),
            0,
            [0u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_external_block_rejects_disabled_verifier() {
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        let tx = valid_transfer_tx();
        let mut preview_tree = NoteTree::open(&temp_db()).unwrap();
        for cm in &tx.new_commitments {
            preview_tree.insert(*cm).unwrap();
        }
        let expected_root = field_to_hex(preview_tree.root().unwrap());
        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![tx], expected_root);
        let verifier = ProofVerifier::disabled();
        let chain_meta = ChainMeta::open(&db).unwrap();

        let result =
            validate_and_apply_block(&block, &verifier, &mut note_tree, &mut nf_set, &chain_meta, &empty_policy(), 0, [0u8; 32]);

        assert!(matches!(
            result,
            Err(ValidationError::ProofVerificationFailed(_))
        ));
        assert_eq!(note_tree.leaf_count(), 0);
    }

    #[test]
    fn test_external_block_rejects_bad_tx_hash() {
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        let mut tx = valid_transfer_tx();
        tx.tx_hash = [0u8; 32];
        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![tx], field_to_hex(FieldElement::zero()));
        let verifier = ProofVerifier::disabled();
        let chain_meta = ChainMeta::open(&db).unwrap();

        let result =
            validate_and_apply_block(&block, &verifier, &mut note_tree, &mut nf_set, &chain_meta, &empty_policy(), 0, [0u8; 32]);

        assert!(matches!(
            result,
            Err(ValidationError::InvalidTransactionHash(_))
        ));
        assert_eq!(note_tree.leaf_count(), 0);
    }

    #[test]
    fn test_external_block_rejects_public_input_mismatch_before_mutation() {
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        let mut tx = valid_transfer_tx();
        tx.public_inputs[3] = field_hex(FieldElement::from(999u128));
        tx.tx_hash = tx_hash_for(&tx.proof, &tx.public_inputs);
        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![tx], field_to_hex(FieldElement::zero()));
        let verifier = ProofVerifier::disabled();
        let chain_meta = ChainMeta::open(&db).unwrap();

        let result =
            validate_and_apply_block(&block, &verifier, &mut note_tree, &mut nf_set, &chain_meta, &empty_policy(), 0, [0u8; 32]);

        assert!(matches!(
            result,
            Err(ValidationError::ProofVerificationFailed(_))
        ));
        assert_eq!(note_tree.leaf_count(), 0);
    }

    #[test]
    fn test_external_block_rejects_missing_vk() {
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();

        let tx = valid_transfer_tx();
        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![tx], field_to_hex(FieldElement::zero()));
        let vk_dir = tempfile::TempDir::new().unwrap();
        let verifier = ProofVerifier::from_vk_dir(vk_dir.path(), "bb").unwrap();
        let chain_meta = ChainMeta::open(&db).unwrap();

        let result =
            validate_and_apply_block(&block, &verifier, &mut note_tree, &mut nf_set, &chain_meta, &empty_policy(), 0, [0u8; 32]);

        assert!(matches!(
            result,
            Err(ValidationError::ProofVerificationFailed(_))
        ));
        assert_eq!(note_tree.leaf_count(), 0);
    }

    // ── Anchor (anti-counterfeiting) tests ──────────────────────────────

    #[test]
    fn test_ensure_known_anchors_rejects_unknown_root() {
        let db = temp_db();
        let chain_meta = crate::state::ChainMeta::open(&db).unwrap();

        // A transfer proven against a root the chain never committed must be
        // rejected — this is the anti-counterfeiting (forged-anchor) defense.
        let tx = valid_transfer_tx(); // merkle_root = zero, unrecorded
        let txs = vec![tx];
        assert!(matches!(
            ensure_known_anchors(&chain_meta, &txs),
            Err(ValidationError::StaleTransaction { .. })
        ));

        // Once the root is a recorded anchor, the same tx is accepted.
        chain_meta.record_anchor(&FieldElement::zero()).unwrap();
        assert!(ensure_known_anchors(&chain_meta, &txs).is_ok());
    }

    #[test]
    fn test_mint_is_exempt_from_anchor_check() {
        let db = temp_db();
        let chain_meta = crate::state::ChainMeta::open(&db).unwrap();

        // Mint consumes no input notes, so it has no Merkle membership to prove
        // and must not be subjected to the anchor check.
        let tx = Transaction {
            tx_type: TxType::Mint,
            tx_hash: [0u8; 32],
            proof: vec![],
            public_inputs: vec![],
            new_commitments: vec![FieldElement::from(1u128)],
            nullifiers: vec![],
            merkle_root: FieldElement::from(999u128), // arbitrary, unrecorded
            fee: 0,
            asset_id: FieldElement::from(1u128),
        };
        assert!(ensure_known_anchors(&chain_meta, &[tx]).is_ok());
    }

    #[test]
    fn test_apply_rejects_unknown_anchor_before_mutation() {
        // SECURITY (anti-counterfeiting, integration): the consensus gate inside
        // the apply path rejects a transfer anchored to a never-committed root,
        // BEFORE any state mutation. Uses the unverified path to isolate the gate
        // (the verified path would reject at proof verification first).
        let db = temp_db();
        let mut note_tree = NoteTree::open(&db).unwrap();
        let mut nf_set = NullifierSet::open(&db).unwrap();
        let chain_meta = ChainMeta::open(&db).unwrap();
        // Anchor (root 0) is intentionally NOT recorded.

        let tx = valid_transfer_tx(); // merkle_root = 0
        let mut builder = BlockBuilder::new();
        let block = builder.build_block(vec![tx], field_to_hex(FieldElement::zero()));

        let result = validate_and_apply_block_unverified_for_test(
            &block,
            &mut note_tree,
            &mut nf_set,
            &chain_meta,
            &empty_policy(),
            0,
            [0u8; 32],
        );
        assert!(matches!(result, Err(ValidationError::StaleTransaction { .. })));
        assert_eq!(note_tree.leaf_count(), 0);
    }
}
