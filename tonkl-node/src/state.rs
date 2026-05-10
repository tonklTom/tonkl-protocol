// Tonkl Protocol - Persistent State Layer
//
// Two core data structures backed by sled (embedded key-value store):
//
// 1. NoteTree: Append-only Poseidon2 Merkle tree (depth 32)
//    - Stores leaf commitments and all intermediate hashes
//    - Computes authentication paths for any leaf
//    - Root is recomputed incrementally on each insertion
//
// 2. NullifierSet: Double-spend prevention
//    - Bloom filter for fast rejection (in-memory)
//    - Persistent sled tree for definitive checks
//    - Once a nullifier is inserted, it can never be removed
//
// Both structures survive process restarts via sled's crash-safe storage.

use tonkl_prover::{poseidon2_hash_2, AcirField, FieldElement, fe_to_be_32};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

// ─────────────────────────────────────────────────────────────────────
// Note Commitment Tree
// ─────────────────────────────────────────────────────────────────────

const TREE_DEPTH: usize = 32;

/// Persistent Poseidon2 Merkle tree.
///
/// Layout in sled:
///   "meta:leaf_count"  -> u64 (number of leaves inserted)
///   "leaf:{index}"     -> 32-byte field element (leaf commitment)
///   "node:{level}:{index}" -> 32-byte field element (internal node)
///
/// Convention (matches tonkl-lib/merkle.nr):
///   - Empty leaf / empty subtree = Field(0)
///   - Internal node = poseidon2_hash_2(left, right)
///   - Level 0 = leaves, Level 31 = root's children, root is at level 32
pub struct NoteTree {
    db: sled::Tree,
    /// Cached leaf count to avoid repeated DB reads
    leaf_count: u64,
}

impl NoteTree {
    /// Open or create a note tree in the given sled database.
    pub fn open(db: &sled::Db) -> Result<Self, StateError> {
        let tree = db.open_tree("note_tree")?;

        // Recover leaf count from DB (0 if fresh)
        let leaf_count = match tree.get("meta:leaf_count")? {
            Some(bytes) => u64::from_le_bytes(
                bytes.as_ref().try_into().map_err(|_| StateError::CorruptedData("leaf_count".into()))?,
            ),
            None => 0,
        };

        Ok(Self {
            db: tree,
            leaf_count,
        })
    }

    /// Number of leaves in the tree.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Current Merkle root.
    /// Convention: empty tree root = Field(0), matching the sparse in-memory builder.
    pub fn root(&self) -> Result<FieldElement, StateError> {
        if self.leaf_count == 0 {
            return Ok(FieldElement::zero());
        }
        // Root is stored as node at level TREE_DEPTH, index 0
        self.get_node(TREE_DEPTH, 0)
    }

    /// Insert a leaf commitment at the next available position.
    /// Returns the leaf index.
    pub fn insert(&mut self, commitment: FieldElement) -> Result<u64, StateError> {
        let index = self.leaf_count;

        // Store the leaf
        let leaf_key = format!("leaf:{}", index);
        self.db.insert(leaf_key.as_bytes(), &fe_to_be_32(&commitment) as &[u8])?;

        // Update internal nodes bottom-up
        let mut current = commitment;
        let mut idx = index;

        for level in 0..TREE_DEPTH {
            let parent_idx = idx / 2;
            let is_right = idx % 2 == 1;

            let sibling = if is_right {
                // Left sibling exists (we're the right child)
                self.get_node_or_empty(level, idx - 1)?
            } else {
                // Right sibling: look up from DB, or Field(0) if absent
                self.get_node_or_empty(level, idx + 1)?
            };

            let parent = if is_right {
                poseidon2_hash_2(sibling, current)
            } else {
                poseidon2_hash_2(current, sibling)
            }.map_err(|e| StateError::CorruptedData(format!("hash error: {}", e)))?;

            // Store the parent node
            let node_key = format!("node:{}:{}", level + 1, parent_idx);
            self.db.insert(node_key.as_bytes(), &fe_to_be_32(&parent) as &[u8])?;

            current = parent;
            idx = parent_idx;
        }

        // Update leaf count
        self.leaf_count = index + 1;
        self.db.insert("meta:leaf_count", &self.leaf_count.to_le_bytes())?;

        // Flush to ensure durability
        self.db.flush()?;

        Ok(index)
    }

    /// Get the authentication path for a leaf at the given index.
    /// Returns (index_bits, siblings) in LSB-first order, matching the circuit convention.
    pub fn get_proof(&self, index: u64) -> Result<MerkleProof, StateError> {
        if index >= self.leaf_count {
            return Err(StateError::IndexOutOfRange(index, self.leaf_count));
        }

        let mut index_bits = [false; TREE_DEPTH];
        let mut siblings = [FieldElement::zero(); TREE_DEPTH];
        let mut idx = index;

        for level in 0..TREE_DEPTH {
            // LSB-first bit decomposition
            index_bits[level] = idx % 2 == 1;

            // Sibling is the other child of our parent
            let sibling_idx = idx ^ 1;
            siblings[level] = self.get_node_or_empty(level, sibling_idx)?;

            idx /= 2;
        }

        Ok(MerkleProof {
            index,
            index_bits,
            siblings,
        })
    }

    /// Get an internal node, or FieldElement::zero() if it doesn't exist.
    fn get_node_or_empty(&self, level: usize, index: u64) -> Result<FieldElement, StateError> {
        if level == 0 {
            // Level 0 = leaves
            let key = format!("leaf:{}", index);
            match self.db.get(key.as_bytes())? {
                Some(bytes) => Ok(bytes_to_field(&bytes)?),
                None => Ok(FieldElement::zero()),
            }
        } else {
            self.get_node_with_default(level, index)
        }
    }

    /// Get an internal node, or Field(0) if not stored.
    /// Matches the sparse Merkle tree convention: empty subtree = Field(0).
    fn get_node_with_default(&self, level: usize, index: u64) -> Result<FieldElement, StateError> {
        let key = format!("node:{}:{}", level, index);
        match self.db.get(key.as_bytes())? {
            Some(bytes) => Ok(bytes_to_field(&bytes)?),
            None => Ok(FieldElement::zero()),
        }
    }

    /// Get an internal node (returns error if not found, unless tree is empty).
    fn get_node(&self, level: usize, index: u64) -> Result<FieldElement, StateError> {
        let key = format!("node:{}:{}", level, index);
        match self.db.get(key.as_bytes())? {
            Some(bytes) => bytes_to_field(&bytes),
            None => {
                if self.leaf_count == 0 {
                    Ok(FieldElement::zero())
                } else {
                    Err(StateError::CorruptedData(format!("missing node at level={}, index={}", level, index)))
                }
            }
        }
    }
}

/// Merkle authentication path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub index: u64,
    pub index_bits: [bool; TREE_DEPTH],
    pub siblings: [FieldElement; TREE_DEPTH],
}

// ─────────────────────────────────────────────────────────────────────
// Nullifier Set
// ─────────────────────────────────────────────────────────────────────

/// Bloom filter parameters.
const BLOOM_BITS: usize = 1 << 20; // ~1M bits = 128 KB
const BLOOM_HASHES: usize = 7;

/// Persistent nullifier set with bloom filter for fast rejection.
pub struct NullifierSet {
    db: sled::Tree,
    bloom: Arc<RwLock<Vec<u8>>>,
    count: u64,
}

impl NullifierSet {
    /// Open or create a nullifier set in the given sled database.
    pub fn open(db: &sled::Db) -> Result<Self, StateError> {
        let tree = db.open_tree("nullifiers")?;

        // Recover count
        let count = match tree.get("meta:count")? {
            Some(bytes) => u64::from_le_bytes(
                bytes.as_ref().try_into().map_err(|_| StateError::CorruptedData("nf_count".into()))?,
            ),
            None => 0,
        };

        // Rebuild bloom filter from stored nullifiers
        let mut bloom = vec![0u8; BLOOM_BITS / 8];
        for entry in tree.iter() {
            let (key, _) = entry?;
            let key_str = std::str::from_utf8(&key).unwrap_or("");
            if let Some(nf_hex) = key_str.strip_prefix("nf:") {
                // field_to_hex produces "0x..." — strip the prefix for hex::decode
                let clean = nf_hex.strip_prefix("0x").unwrap_or(nf_hex);
                if let Ok(nf_bytes) = hex::decode(clean) {
                    bloom_insert(&mut bloom, &nf_bytes);
                }
            }
        }

        Ok(Self {
            db: tree,
            bloom: Arc::new(RwLock::new(bloom)),
            count,
        })
    }

    /// Number of nullifiers in the set.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Check if a nullifier exists (fast path via bloom filter).
    pub fn contains_maybe(&self, nf: &FieldElement) -> bool {
        let bytes = fe_to_be_32(nf);
        let bloom = self.bloom.read().unwrap();
        bloom_check(&bloom, &bytes)
    }

    /// Check if a nullifier exists (definitive, hits disk).
    pub fn contains(&self, nf: &FieldElement) -> Result<bool, StateError> {
        if !self.contains_maybe(nf) {
            return Ok(false);
        }
        let key = format!("nf:{}", field_to_hex(*nf));
        Ok(self.db.contains_key(key.as_bytes())?)
    }

    /// Insert a nullifier. Returns error if already present (double-spend).
    pub fn insert(&mut self, nf: FieldElement) -> Result<(), StateError> {
        let key = format!("nf:{}", field_to_hex(nf));

        if self.db.contains_key(key.as_bytes())? {
            return Err(StateError::DuplicateNullifier(field_to_hex(nf)));
        }

        self.db.insert(key.as_bytes(), &[] as &[u8])?;

        let bytes = fe_to_be_32(&nf);
        {
            let mut bloom = self.bloom.write().unwrap();
            bloom_insert(&mut bloom, &bytes);
        }

        self.count += 1;
        self.db.insert("meta:count", &self.count.to_le_bytes())?;

        self.db.flush()?;
        Ok(())
    }

    /// Batch-insert nullifiers. Returns error on first duplicate.
    pub fn insert_batch(&mut self, nullifiers: &[FieldElement]) -> Result<(), StateError> {
        let mut seen = std::collections::HashSet::new();
        for nf in nullifiers {
            let hx = field_to_hex(*nf);
            if !seen.insert(hx.clone()) {
                return Err(StateError::DuplicateNullifier(hx));
            }
            let key = format!("nf:{}", hx);
            if self.db.contains_key(key.as_bytes())? {
                return Err(StateError::DuplicateNullifier(hx));
            }
        }

        for nf in nullifiers {
            let key = format!("nf:{}", field_to_hex(*nf));
            self.db.insert(key.as_bytes(), &[] as &[u8])?;

            let bytes = fe_to_be_32(nf);
            let mut bloom = self.bloom.write().unwrap();
            bloom_insert(&mut bloom, &bytes);
        }

        self.count += nullifiers.len() as u64;
        self.db.insert("meta:count", &self.count.to_le_bytes())?;
        self.db.flush()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// Encrypted Note Store
// ─────────────────────────────────────────────────────────────────────

/// Persistent store for encrypted note ciphertexts.
///
/// When a sender creates a transaction with outputs for a recipient,
/// the wallet encrypts the note details (value, asset_id, rho) using
/// NaCl sealed box (X25519 + XSalsa20-Poly1305) and stores the
/// ciphertext here, indexed by leaf position.
///
/// Recipients scan this store, trial-decrypt each entry with their
/// scan key, and auto-import any notes they can decrypt.
///
/// Layout in sled:
///   "meta:count"       -> u64 (number of stored ciphertexts)
///   "enc:{leaf_index}" -> raw ciphertext bytes
pub struct EncryptedNoteStore {
    db: sled::Tree,
    count: u64,
}

impl EncryptedNoteStore {
    pub fn open(db: &sled::Db) -> Result<Self, StateError> {
        let tree = db.open_tree("encrypted_notes")?;
        let count = match tree.get("meta:count")? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.as_ref().try_into().map_err(|_| {
                    StateError::CorruptedData("invalid count in encrypted_notes".into())
                })?;
                u64::from_le_bytes(arr)
            }
            None => 0,
        };
        Ok(Self { db: tree, count })
    }

    /// Store a batch of encrypted notes, one per leaf index.
    pub fn store_batch(
        &mut self,
        entries: &[(u64, Vec<u8>)],
    ) -> Result<(), StateError> {
        for (leaf_index, ciphertext) in entries {
            let key = format!("enc:{}", leaf_index);
            self.db.insert(key.as_bytes(), ciphertext.as_slice())?;
        }
        self.count += entries.len() as u64;
        self.db.insert("meta:count", &self.count.to_le_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Retrieve encrypted notes for a range of leaf indices.
    /// Returns (leaf_index, ciphertext) pairs for indices that have data.
    pub fn get_range(
        &self,
        from_index: u64,
        count: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, StateError> {
        let mut results = Vec::new();
        for idx in from_index..from_index + count {
            let key = format!("enc:{}", idx);
            if let Some(bytes) = self.db.get(key.as_bytes())? {
                results.push((idx, bytes.to_vec()));
            }
        }
        Ok(results)
    }

    /// Number of stored ciphertexts.
    pub fn count(&self) -> u64 {
        self.count
    }
}

// ─────────────────────────────────────────────────────────────────────
// Chain Metadata (block height + last block hash)
// ─────────────────────────────────────────────────────────────────────

/// Persistent chain metadata that survives restarts.
///
/// Layout in sled (tree name: "chain_meta"):
///   "block_count"     -> u64 (number of blocks produced)
///   "last_block_hash" -> [u8; 32]
pub struct ChainMeta {
    db: sled::Tree,
}

impl ChainMeta {
    /// Open or create the chain metadata store.
    pub fn open(db: &sled::Db) -> Result<Self, StateError> {
        let tree = db.open_tree("chain_meta")?;
        Ok(Self { db: tree })
    }

    /// Read the persisted block count (0 if fresh).
    pub fn block_count(&self) -> Result<u64, StateError> {
        match self.db.get("block_count")? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| StateError::CorruptedData("block_count".into()))?;
                Ok(u64::from_le_bytes(arr))
            }
            None => Ok(0),
        }
    }

    /// Read the persisted last block hash ([0; 32] if fresh).
    pub fn last_block_hash(&self) -> Result<[u8; 32], StateError> {
        match self.db.get("last_block_hash")? {
            Some(bytes) => {
                let arr: [u8; 32] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| StateError::CorruptedData("last_block_hash".into()))?;
                Ok(arr)
            }
            None => Ok([0u8; 32]),
        }
    }

    /// Persist the new block count and last hash after producing a block.
    pub fn update(&self, block_count: u64, last_hash: [u8; 32]) -> Result<(), StateError> {
        self.db
            .insert("block_count", &block_count.to_le_bytes())?;
        self.db
            .insert("last_block_hash", &last_hash as &[u8])?;
        self.db.flush()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// Bloom Filter Helpers
// ─────────────────────────────────────────────────────────────────────

fn bloom_hash_indices(data: &[u8]) -> [usize; BLOOM_HASHES] {
    let mut indices = [0usize; BLOOM_HASHES];
    for i in 0..BLOOM_HASHES {
        let key = format!("bloom_key_{:02}", i);
        let mut hasher = blake3::Hasher::new_keyed(&padded_key(key.as_bytes()));
        hasher.update(data);
        let hash = hasher.finalize();
        let bytes: [u8; 4] = hash.as_bytes()[0..4].try_into().unwrap();
        indices[i] = (u32::from_le_bytes(bytes) as usize) % BLOOM_BITS;
    }
    indices
}

fn padded_key(key: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    let len = key.len().min(32);
    padded[..len].copy_from_slice(&key[..len]);
    padded
}

fn bloom_insert(bloom: &mut [u8], data: &[u8]) {
    for idx in bloom_hash_indices(data) {
        bloom[idx / 8] |= 1 << (idx % 8);
    }
}

fn bloom_check(bloom: &[u8], data: &[u8]) -> bool {
    for idx in bloom_hash_indices(data) {
        if bloom[idx / 8] & (1 << (idx % 8)) == 0 {
            return false;
        }
    }
    true
}

// ─────────────────────────────────────────────────────────────────────
// Field Element Serialization
// ─────────────────────────────────────────────────────────────────────

fn bytes_to_field(bytes: &[u8]) -> Result<FieldElement, StateError> {
    if bytes.len() != 32 {
        return Err(StateError::CorruptedData(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(FieldElement::from_be_bytes_reduce(&arr))
}

pub fn field_to_hex(f: FieldElement) -> String {
    format!("0x{}", hex::encode(fe_to_be_32(&f)))
}

// ─────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StateError {
    Sled(sled::Error),
    CorruptedData(String),
    IndexOutOfRange(u64, u64),
    DuplicateNullifier(String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sled(e) => write!(f, "sled error: {}", e),
            Self::CorruptedData(msg) => write!(f, "corrupted data: {}", msg),
            Self::IndexOutOfRange(idx, count) => {
                write!(f, "index {} out of range (leaf_count={})", idx, count)
            }
            Self::DuplicateNullifier(nf) => write!(f, "duplicate nullifier: {}", nf),
        }
    }
}

impl std::error::Error for StateError {}

impl From<sled::Error> for StateError {
    fn from(e: sled::Error) -> Self {
        Self::Sled(e)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tonkl_prover::build_merkle_tree;

    fn temp_db() -> sled::Db {
        sled::Config::new().temporary(true).open().unwrap()
    }

    #[test]
    fn test_empty_tree_root() {
        let db = temp_db();
        let tree = NoteTree::open(&db).unwrap();
        assert_eq!(tree.leaf_count(), 0);
        let root = tree.root().unwrap();
        // Empty tree root = Field(0), matching sparse in-memory convention
        assert_eq!(root, FieldElement::zero());
    }

    #[test]
    fn test_single_leaf_matches_in_memory() {
        let db = temp_db();
        let mut tree = NoteTree::open(&db).unwrap();

        let leaf = FieldElement::from(12345u128);
        let idx = tree.insert(leaf).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(tree.leaf_count(), 1);

        let mem_result = build_merkle_tree(&[leaf]).unwrap();
        let disk_root = tree.root().unwrap();
        assert_eq!(disk_root, mem_result.root, "Disk root must match in-memory root");
    }

    #[test]
    fn test_multiple_leaves_match_in_memory() {
        let db = temp_db();
        let mut tree = NoteTree::open(&db).unwrap();

        let leaves: Vec<FieldElement> = (1..=8).map(|i| FieldElement::from(i as u128)).collect();
        for leaf in &leaves {
            tree.insert(*leaf).unwrap();
        }
        assert_eq!(tree.leaf_count(), 8);

        let mem_result = build_merkle_tree(&leaves).unwrap();
        let disk_root = tree.root().unwrap();
        assert_eq!(disk_root, mem_result.root, "8-leaf disk root must match in-memory");
    }

    #[test]
    fn test_merkle_proof_matches_in_memory() {
        let db = temp_db();
        let mut tree = NoteTree::open(&db).unwrap();

        let leaves: Vec<FieldElement> = (1..=4).map(|i| FieldElement::from(i as u128)).collect();
        for leaf in &leaves {
            tree.insert(*leaf).unwrap();
        }

        let mem_result = build_merkle_tree(&leaves).unwrap();

        for i in 0..4 {
            let proof = tree.get_proof(i).unwrap();
            let mem_path = &mem_result.paths[i as usize];

            for level in 0..TREE_DEPTH {
                assert_eq!(
                    proof.index_bits[level], mem_path.index_bits[level],
                    "Bit mismatch at leaf={}, level={}", i, level
                );
                assert_eq!(
                    proof.siblings[level], mem_path.siblings[level],
                    "Sibling mismatch at leaf={}, level={}", i, level
                );
            }
        }
    }

    #[test]
    fn test_tree_persistence() {
        let db = temp_db();
        let root_before;
        {
            let mut tree = NoteTree::open(&db).unwrap();
            for i in 1..=3 {
                tree.insert(FieldElement::from(i as u128)).unwrap();
            }
            root_before = tree.root().unwrap();
        }
        {
            let tree = NoteTree::open(&db).unwrap();
            assert_eq!(tree.leaf_count(), 3);
            assert_eq!(tree.root().unwrap(), root_before);
        }
    }

    #[test]
    fn test_proof_out_of_range() {
        let db = temp_db();
        let tree = NoteTree::open(&db).unwrap();
        let result = tree.get_proof(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_nullifier_set() {
        let db = temp_db();
        let set = NullifierSet::open(&db).unwrap();
        assert_eq!(set.count(), 0);
        let nf = FieldElement::from(999u128);
        assert!(!set.contains(&nf).unwrap());
    }

    #[test]
    fn test_nullifier_insert_and_check() {
        let db = temp_db();
        let mut set = NullifierSet::open(&db).unwrap();
        let nf1 = FieldElement::from(111u128);
        let nf2 = FieldElement::from(222u128);
        set.insert(nf1).unwrap();
        assert!(set.contains(&nf1).unwrap());
        assert!(!set.contains(&nf2).unwrap());
        assert_eq!(set.count(), 1);
        set.insert(nf2).unwrap();
        assert!(set.contains(&nf2).unwrap());
        assert_eq!(set.count(), 2);
    }

    #[test]
    fn test_nullifier_double_spend_rejected() {
        let db = temp_db();
        let mut set = NullifierSet::open(&db).unwrap();
        let nf = FieldElement::from(555u128);
        set.insert(nf).unwrap();
        let result = set.insert(nf);
        assert!(result.is_err());
    }

    #[test]
    fn test_nullifier_batch_insert() {
        let db = temp_db();
        let mut set = NullifierSet::open(&db).unwrap();
        let nfs: Vec<FieldElement> = (1..=10).map(|i| FieldElement::from(i as u128)).collect();
        set.insert_batch(&nfs).unwrap();
        assert_eq!(set.count(), 10);
        for nf in &nfs {
            assert!(set.contains(nf).unwrap());
        }
    }

    #[test]
    fn test_nullifier_batch_duplicate_in_batch() {
        let db = temp_db();
        let mut set = NullifierSet::open(&db).unwrap();
        let nf = FieldElement::from(42u128);
        let result = set.insert_batch(&[nf, nf]);
        assert!(result.is_err());
    }

    #[test]
    fn test_nullifier_persistence() {
        let db = temp_db();
        {
            let mut set = NullifierSet::open(&db).unwrap();
            set.insert(FieldElement::from(777u128)).unwrap();
        }
        {
            let set = NullifierSet::open(&db).unwrap();
            assert_eq!(set.count(), 1);
            assert!(set.contains(&FieldElement::from(777u128)).unwrap());
        }
    }

    #[test]
    fn test_bloom_filter_no_false_negatives() {
        let db = temp_db();
        let mut set = NullifierSet::open(&db).unwrap();
        for i in 0..1000 {
            set.insert(FieldElement::from(i as u128)).unwrap();
        }
        for i in 0..1000 {
            assert!(set.contains_maybe(&FieldElement::from(i as u128)), "False negative at {}", i);
        }
    }
}
