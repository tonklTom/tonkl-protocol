// Tonkl Protocol - JSON-RPC Interface

use crate::block::{Block, BlockBuilder, BlockHeader, Transaction, TxType};
use crate::mempool::Mempool;
use crate::state::{ChainMeta, EncryptedNoteStore, NoteTree, NullifierSet, field_to_hex};
use crate::verifier::{ProofVerifier, serialize_public_inputs};
use http::header;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use tower_http::cors::{AllowOrigin, CorsLayer};
use obscura_prover::{AcirField, FieldElement};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tracing::info;

// ─────────────────────────────────────────────────────────────────────
// RPC Types
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub block_height: u64,
    pub merkle_root: String,
    pub leaf_count: u64,
    pub nullifier_count: u64,
    pub mempool_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofResponse {
    pub index: u64,
    pub index_bits: Vec<bool>,
    pub siblings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTxRequest {
    pub tx_type: String,
    pub proof: String,
    pub public_inputs: Vec<String>,
    pub new_commitments: Vec<String>,
    pub nullifiers: Vec<String>,
    pub merkle_root: String,
    pub fee: u64,
    pub asset_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    pub tx_hash: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxStatusResponse {
    /// "pending" | "confirmed" | "unknown"
    pub status: String,
    /// Block number if confirmed, None otherwise
    pub block_number: Option<u64>,
    /// Number of confirmations (blocks since inclusion)
    pub confirmations: Option<u64>,
    /// Transaction type if known
    pub tx_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedNoteEntry {
    pub leaf_index: u64,
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreEncryptedNotesRequest {
    pub notes: Vec<EncryptedNoteEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreEncryptedNotesResponse {
    pub stored: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEncryptedNotesResponse {
    pub notes: Vec<EncryptedNoteEntry>,
    pub leaf_count: u64,
}

// ─────────────────────────────────────────────────────────────────────
// RPC Trait
// ─────────────────────────────────────────────────────────────────────

#[rpc(server)]
pub trait TonklRpc {
    #[method(name = "get_status")]
    async fn get_status(&self) -> Result<NodeStatus, ErrorObjectOwned>;

    #[method(name = "get_merkle_root")]
    async fn get_merkle_root(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "get_merkle_proof")]
    async fn get_merkle_proof(&self, index: u64) -> Result<MerkleProofResponse, ErrorObjectOwned>;

    #[method(name = "get_nullifier_status")]
    async fn get_nullifier_status(&self, nullifier: String) -> Result<bool, ErrorObjectOwned>;

    /// Submit a transaction. Requires `secret` if TONKL_RPC_SECRET is set.
    #[method(name = "submit_tx")]
    async fn submit_tx(&self, request: SubmitTxRequest, secret: Option<String>) -> Result<SubmitTxResponse, ErrorObjectOwned>;

    #[method(name = "get_tx_status")]
    async fn get_tx_status(&self, tx_hash: String) -> Result<TxStatusResponse, ErrorObjectOwned>;

    #[method(name = "get_block")]
    async fn get_block(&self, block_number: u64) -> Result<Option<Block>, ErrorObjectOwned>;

    /// Get a range of blocks for chain sync. Returns up to 50 blocks starting from `from_block`.
    #[method(name = "get_blocks_range")]
    async fn get_blocks_range(&self, from_block: u64, count: u64) -> Result<Vec<Block>, ErrorObjectOwned>;

    /// Produce a block. Requires `secret` if TONKL_RPC_SECRET is set.
    #[method(name = "produce_block")]
    async fn produce_block(&self, secret: Option<String>) -> Result<BlockHeader, ErrorObjectOwned>;

    /// Store encrypted notes. Requires `secret` if TONKL_RPC_SECRET is set.
    #[method(name = "store_encrypted_notes")]
    async fn store_encrypted_notes(
        &self,
        request: StoreEncryptedNotesRequest,
        secret: Option<String>,
    ) -> Result<StoreEncryptedNotesResponse, ErrorObjectOwned>;

    #[method(name = "get_encrypted_notes")]
    async fn get_encrypted_notes(
        &self,
        from_index: u64,
        count: u64,
    ) -> Result<GetEncryptedNotesResponse, ErrorObjectOwned>;
}

// ─────────────────────────────────────────────────────────────────────
// RPC Rate Limiter (sliding window, in-memory)
// ─────────────────────────────────────────────────────────────────────

/// Per-method rate limit configuration.
struct RateLimit {
    max_requests: usize,
    window: std::time::Duration,
}

/// Simple sliding-window rate limiter.
/// Tracks timestamps of recent calls per method; rejects when the window is full.
/// Uses `std::sync::Mutex` (not tokio) because the critical section is just
/// a VecDeque push/drain — sub-microsecond, never awaits.
struct RpcRateLimiter {
    buckets: Mutex<HashMap<&'static str, VecDeque<Instant>>>,
    limits: HashMap<&'static str, RateLimit>,
}

impl RpcRateLimiter {
    fn new() -> Self {
        let mut limits = HashMap::new();
        // Write endpoints — heavier, stricter limits
        limits.insert("submit_tx", RateLimit { max_requests: 10, window: std::time::Duration::from_secs(60) });
        limits.insert("produce_block", RateLimit { max_requests: 5, window: std::time::Duration::from_secs(60) });
        limits.insert("store_encrypted_notes", RateLimit { max_requests: 20, window: std::time::Duration::from_secs(60) });
        // Read endpoints — generous limits
        limits.insert("get_status", RateLimit { max_requests: 120, window: std::time::Duration::from_secs(60) });
        limits.insert("get_merkle_root", RateLimit { max_requests: 120, window: std::time::Duration::from_secs(60) });
        limits.insert("get_merkle_proof", RateLimit { max_requests: 60, window: std::time::Duration::from_secs(60) });
        limits.insert("get_nullifier_status", RateLimit { max_requests: 60, window: std::time::Duration::from_secs(60) });
        limits.insert("get_tx_status", RateLimit { max_requests: 60, window: std::time::Duration::from_secs(60) });
        limits.insert("get_block", RateLimit { max_requests: 60, window: std::time::Duration::from_secs(60) });
        limits.insert("get_blocks_range", RateLimit { max_requests: 30, window: std::time::Duration::from_secs(60) });
        limits.insert("get_encrypted_notes", RateLimit { max_requests: 60, window: std::time::Duration::from_secs(60) });

        Self {
            buckets: Mutex::new(HashMap::new()),
            limits,
        }
    }

    /// Returns Ok(()) if the call is allowed, Err with a JSON-RPC error if rate limited.
    fn check(&self, method: &'static str) -> Result<(), ErrorObjectOwned> {
        let limit = match self.limits.get(method) {
            Some(l) => l,
            None => return Ok(()), // no limit configured → allow
        };

        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let window = buckets.entry(method).or_insert_with(VecDeque::new);

        // Drain expired entries
        while let Some(&front) = window.front() {
            if now.duration_since(front) > limit.window {
                window.pop_front();
            } else {
                break;
            }
        }

        if window.len() >= limit.max_requests {
            return Err(ErrorObjectOwned::owned(
                -32029,
                format!(
                    "rate limited: {} allows {} requests per {}s",
                    method, limit.max_requests, limit.window.as_secs()
                ),
                None::<()>,
            ));
        }

        window.push_back(now);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// Node State (shared across RPC handlers)
// ─────────────────────────────────────────────────────────────────────

/// Confirmed transaction record for the tx index.
#[derive(Debug, Clone)]
pub struct ConfirmedTx {
    pub block_number: u64,
    pub tx_type: TxType,
}

pub struct NodeState {
    pub note_tree: NoteTree,
    pub nullifier_set: NullifierSet,
    pub encrypted_notes: EncryptedNoteStore,
    pub mempool: Mempool,
    pub block_builder: BlockBuilder,
    pub blocks: Vec<Block>,
    pub verifier: ProofVerifier,
    /// tx_hash (hex) -> confirmation info
    pub tx_index: HashMap<String, ConfirmedTx>,
    /// Persistent chain metadata (block count + last hash)
    pub chain_meta: ChainMeta,
}

pub struct RpcServer {
    state: Arc<RwLock<NodeState>>,
    /// Optional secret token required for write operations (submit_tx, produce_block, store_encrypted_notes).
    /// Set via TONKL_RPC_SECRET environment variable. If empty, write ops are unrestricted (dev mode).
    rpc_secret: Option<String>,
    /// Per-method sliding-window rate limiter.
    rate_limiter: RpcRateLimiter,
    /// Optional channel to broadcast accepted transactions to the P2P layer.
    /// When a transaction is accepted via submit_tx, a clone is sent here
    /// so the P2P layer can gossip it to peers.
    tx_broadcast: Option<mpsc::Sender<Transaction>>,
}

impl RpcServer {
    pub fn new(state: Arc<RwLock<NodeState>>, tx_broadcast: Option<mpsc::Sender<Transaction>>) -> Self {
        let rpc_secret = std::env::var("TONKL_RPC_SECRET").ok().filter(|s| !s.is_empty());
        if rpc_secret.is_some() {
            info!("RPC write operations require TONKL_RPC_SECRET authentication");
        } else {
            tracing::warn!("TONKL_RPC_SECRET not set — write operations are unrestricted (development mode)");
        }
        Self {
            state,
            rpc_secret,
            rate_limiter: RpcRateLimiter::new(),
            tx_broadcast,
        }
    }
}

// ─── Input size limits for DoS prevention ────────────────────────────
const MAX_PROOF_HEX_LEN: usize = 16_384;       // 8 KB decoded
const MAX_COMMITMENTS: usize = 32;               // matches mint circuit max
const MAX_NULLIFIERS: usize = 2;                  // matches transfer circuit max
const MAX_PUBLIC_INPUTS: usize = 20;
const MAX_ENCRYPTED_NOTES_STORE: usize = 64;      // per request

// ─────────────────────────────────────────────────────────────────────
// RPC Implementation
// ─────────────────────────────────────────────────────────────────────

fn internal_error(msg: impl ToString) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32603, msg.to_string(), None::<()>)
}

fn invalid_params(msg: impl ToString) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, msg.to_string(), None::<()>)
}

fn auth_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32001, "authentication required: provide valid secret for write operations", None::<()>)
}

fn parse_field(hex_str: &str) -> Result<FieldElement, ErrorObjectOwned> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| invalid_params(format!("invalid hex: {}", e)))?;
    if bytes.len() > 32 {
        return Err(invalid_params("field element too large"));
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(FieldElement::from_be_bytes_reduce(&padded))
}

#[async_trait]
impl TonklRpcServer for RpcServer {
    async fn get_status(&self) -> Result<NodeStatus, ErrorObjectOwned> {
        self.rate_limiter.check("get_status")?;
        let state = self.state.read().await;
        let root = state.note_tree.root().map_err(|e| internal_error(e))?;

        Ok(NodeStatus {
            block_height: state.block_builder.next_block_number(),
            merkle_root: field_to_hex(root),
            leaf_count: state.note_tree.leaf_count(),
            nullifier_count: state.nullifier_set.count(),
            mempool_size: state.mempool.len(),
        })
    }

    async fn get_merkle_root(&self) -> Result<String, ErrorObjectOwned> {
        self.rate_limiter.check("get_merkle_root")?;
        let state = self.state.read().await;
        let root = state.note_tree.root().map_err(|e| internal_error(e))?;
        Ok(field_to_hex(root))
    }

    async fn get_merkle_proof(&self, index: u64) -> Result<MerkleProofResponse, ErrorObjectOwned> {
        self.rate_limiter.check("get_merkle_proof")?;
        let state = self.state.read().await;
        let leaf_count = state.note_tree.leaf_count();
        if index >= leaf_count && leaf_count > 0 {
            return Err(invalid_params(format!(
                "index {} is out of range (tree has {} leaves)",
                index, leaf_count,
            )));
        }
        let proof = state.note_tree.get_proof(index).map_err(|e| invalid_params(e))?;

        Ok(MerkleProofResponse {
            index: proof.index,
            index_bits: proof.index_bits.to_vec(),
            siblings: proof.siblings.iter().map(|s| field_to_hex(*s)).collect(),
        })
    }

    async fn get_nullifier_status(&self, nullifier: String) -> Result<bool, ErrorObjectOwned> {
        self.rate_limiter.check("get_nullifier_status")?;
        let state = self.state.read().await;
        let nf = parse_field(&nullifier)?;
        state.nullifier_set.contains(&nf).map_err(|e| internal_error(e))
    }

    async fn submit_tx(&self, request: SubmitTxRequest, secret: Option<String>) -> Result<SubmitTxResponse, ErrorObjectOwned> {
        // ── Rate limit ─────────────────────────────────────────
        self.rate_limiter.check("submit_tx")?;

        // ── Auth check ──────────────────────────────────────────
        if let Some(ref expected) = self.rpc_secret {
            match &secret {
                Some(s) if s == expected => {}
                _ => return Err(auth_error()),
            }
        }

        // ── Input size validation (DoS prevention) ──────────────
        if request.proof.len() > MAX_PROOF_HEX_LEN {
            return Err(invalid_params(format!(
                "proof too large: {} chars (max {})", request.proof.len(), MAX_PROOF_HEX_LEN
            )));
        }
        if request.new_commitments.len() > MAX_COMMITMENTS {
            return Err(invalid_params(format!(
                "too many commitments: {} (max {})", request.new_commitments.len(), MAX_COMMITMENTS
            )));
        }
        if request.nullifiers.len() > MAX_NULLIFIERS {
            return Err(invalid_params(format!(
                "too many nullifiers: {} (max {})", request.nullifiers.len(), MAX_NULLIFIERS
            )));
        }
        if request.public_inputs.len() > MAX_PUBLIC_INPUTS {
            return Err(invalid_params(format!(
                "too many public inputs: {} (max {})", request.public_inputs.len(), MAX_PUBLIC_INPUTS
            )));
        }

        let tx_type = match request.tx_type.as_str() {
            "transfer" => TxType::Transfer,
            "merge" => TxType::Merge,
            "split" => TxType::Split,
            "mint" => TxType::Mint,
            other => return Err(invalid_params(format!("unknown tx_type: {}", other))),
        };

        let proof = hex::decode(request.proof.strip_prefix("0x").unwrap_or(&request.proof))
            .map_err(|e| invalid_params(format!("invalid proof hex: {}", e)))?;

        let new_commitments: Vec<FieldElement> = request.new_commitments
            .iter()
            .map(|s| parse_field(s))
            .collect::<Result<_, _>>()?;

        let nullifiers: Vec<FieldElement> = request.nullifiers
            .iter()
            .map(|s| parse_field(s))
            .collect::<Result<_, _>>()?;

        let merkle_root = parse_field(&request.merkle_root)?;
        let asset_id = parse_field(&request.asset_id)?;

        // Compute tx hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(&proof);
        for pi in &request.public_inputs {
            hasher.update(pi.as_bytes());
        }
        let tx_hash = *hasher.finalize().as_bytes();

        let tx = Transaction {
            tx_type,
            tx_hash,
            proof,
            public_inputs: request.public_inputs,
            new_commitments,
            nullifiers,
            merkle_root,
            fee: request.fee,
            asset_id,
        };

        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

        // Verify proof before accepting (read lock is sufficient for verification)
        {
            let state = self.state.read().await;
            if state.verifier.is_enabled() {
                let public_inputs_bytes = serialize_public_inputs(&tx.public_inputs)
                    .map_err(|e| invalid_params(format!("invalid public inputs: {}", e)))?;

                state.verifier.verify(tx_type, &tx.proof, &public_inputs_bytes)
                    .map_err(|e| invalid_params(format!("proof verification failed: {}", e)))?;

                info!("Proof verified for tx {}", tx_hash_hex);
            }
        }

        let mut state = self.state.write().await;

        // Mempool size limit to prevent DoS
        const MAX_MEMPOOL_SIZE: usize = 1000;
        if state.mempool.len() >= MAX_MEMPOOL_SIZE {
            return Err(invalid_params("mempool is full — try again after the next block"));
        }

        // Check nullifiers against set before submitting to mempool
        // (split borrow: check first, then submit)
        for nf in &tx.nullifiers {
            if state.nullifier_set.contains(nf).map_err(|e| internal_error(e))? {
                return Err(invalid_params(format!("nullifier already spent: {}", field_to_hex(*nf))));
            }
        }
        // Clone tx for P2P broadcast before moving into mempool
        let tx_for_broadcast = if self.tx_broadcast.is_some() {
            Some(tx.clone())
        } else {
            None
        };

        state.mempool.submit_unchecked(tx);

        info!("Transaction accepted: {}", tx_hash_hex);

        // Broadcast to P2P peers (non-blocking, fire-and-forget)
        if let (Some(broadcast_tx), Some(tx_data)) = (&self.tx_broadcast, tx_for_broadcast) {
            let _ = broadcast_tx.try_send(tx_data);
        }

        Ok(SubmitTxResponse {
            tx_hash: tx_hash_hex,
            accepted: true,
        })
    }

    async fn get_tx_status(&self, tx_hash: String) -> Result<TxStatusResponse, ErrorObjectOwned> {
        self.rate_limiter.check("get_tx_status")?;
        let state = self.state.read().await;
        let clean_hash = if tx_hash.starts_with("0x") {
            tx_hash.clone()
        } else {
            format!("0x{}", tx_hash)
        };

        // Check if confirmed
        if let Some(confirmed) = state.tx_index.get(&clean_hash) {
            let current_height = state.block_builder.next_block_number();
            let confirmations = current_height.saturating_sub(confirmed.block_number);
            return Ok(TxStatusResponse {
                status: "confirmed".to_string(),
                block_number: Some(confirmed.block_number),
                confirmations: Some(confirmations),
                tx_type: Some(format!("{:?}", confirmed.tx_type)),
            });
        }

        // Check if pending in mempool
        if state.mempool.contains_tx_hash(&clean_hash) {
            return Ok(TxStatusResponse {
                status: "pending".to_string(),
                block_number: None,
                confirmations: None,
                tx_type: None,
            });
        }

        // Unknown
        Ok(TxStatusResponse {
            status: "unknown".to_string(),
            block_number: None,
            confirmations: None,
            tx_type: None,
        })
    }

    async fn get_block(&self, block_number: u64) -> Result<Option<Block>, ErrorObjectOwned> {
        self.rate_limiter.check("get_block")?;
        let state = self.state.read().await;
        Ok(state.blocks.get(block_number as usize).cloned())
    }

    async fn get_blocks_range(&self, from_block: u64, count: u64) -> Result<Vec<Block>, ErrorObjectOwned> {
        self.rate_limiter.check("get_blocks_range")?;

        // Cap at 50 blocks per request to prevent abuse
        let capped_count = count.min(50) as usize;
        let from = from_block as usize;

        let state = self.state.read().await;
        let end = (from + capped_count).min(state.blocks.len());
        if from >= state.blocks.len() {
            return Ok(Vec::new());
        }
        Ok(state.blocks[from..end].to_vec())
    }

    async fn produce_block(&self, secret: Option<String>) -> Result<BlockHeader, ErrorObjectOwned> {
        // ── Rate limit ─────────────────────────────────────────
        self.rate_limiter.check("produce_block")?;

        // ── Auth check ──────────────────────────────────────────
        if let Some(ref expected) = self.rpc_secret {
            match &secret {
                Some(s) if s == expected => {}
                _ => return Err(auth_error()),
            }
        }

        let mut state = self.state.write().await;

        let txs = state.mempool.drain_for_block(256);
        if txs.is_empty() {
            let root = state.note_tree.root().map_err(|e| internal_error(e))?;
            let state_root = field_to_hex(root);
            let block = state.block_builder.build_block(vec![], state_root);
            let header = block.header.clone();
            // Persist chain progress
            let _ = state.chain_meta.update(
                state.block_builder.next_block_number(),
                state.block_builder.last_block_hash(),
            );
            state.blocks.push(block);
            info!("Produced empty block #{}", header.block_number);
            return Ok(header);
        }

        let all_nullifiers: Vec<FieldElement> = txs
            .iter()
            .flat_map(|tx| tx.nullifiers.clone())
            .collect();

        for tx in &txs {
            for cm in &tx.new_commitments {
                state.note_tree.insert(*cm).map_err(|e| internal_error(e))?;
            }
            if !tx.nullifiers.is_empty() {
                state.nullifier_set.insert_batch(&tx.nullifiers)
                    .map_err(|e| internal_error(e))?;
            }
        }

        let root = state.note_tree.root().map_err(|e| internal_error(e))?;
        let state_root = field_to_hex(root);

        let block = state.block_builder.build_block(txs, state_root);
        let header = block.header.clone();

        // Index all confirmed transactions by their hash
        for tx in &block.transactions {
            let tx_hash_hex = format!("0x{}", hex::encode(tx.tx_hash));
            state.tx_index.insert(tx_hash_hex, ConfirmedTx {
                block_number: header.block_number,
                tx_type: tx.tx_type,
            });
        }

        info!(
            "Produced block #{} with {} txs (root: {})",
            header.block_number, header.tx_count, header.state_root
        );

        // Persist chain progress
        let _ = state.chain_meta.update(
            state.block_builder.next_block_number(),
            state.block_builder.last_block_hash(),
        );

        state.blocks.push(block);
        state.mempool.purge_confirmed_nullifiers(&all_nullifiers);

        Ok(header)
    }

    async fn store_encrypted_notes(
        &self,
        request: StoreEncryptedNotesRequest,
        secret: Option<String>,
    ) -> Result<StoreEncryptedNotesResponse, ErrorObjectOwned> {
        // ── Rate limit ─────────────────────────────────────────
        self.rate_limiter.check("store_encrypted_notes")?;

        // ── Auth check ──────────────────────────────────────────
        if let Some(ref expected) = self.rpc_secret {
            match &secret {
                Some(s) if s == expected => {}
                _ => return Err(auth_error()),
            }
        }

        // ── Size limit ──────────────────────────────────────────
        if request.notes.len() > MAX_ENCRYPTED_NOTES_STORE {
            return Err(invalid_params(format!(
                "too many notes: {} (max {} per request)", request.notes.len(), MAX_ENCRYPTED_NOTES_STORE
            )));
        }

        let mut state = self.state.write().await;

        let entries: Vec<(u64, Vec<u8>)> = request
            .notes
            .iter()
            .map(|e| {
                let bytes = hex::decode(
                    e.ciphertext.strip_prefix("0x").unwrap_or(&e.ciphertext),
                )
                .map_err(|err| invalid_params(format!("invalid ciphertext hex: {}", err)))?;
                Ok((e.leaf_index, bytes))
            })
            .collect::<Result<Vec<_>, ErrorObjectOwned>>()?;

        let count = entries.len();
        state
            .encrypted_notes
            .store_batch(&entries)
            .map_err(|e| internal_error(e))?;

        info!("Stored {} encrypted note(s)", count);
        Ok(StoreEncryptedNotesResponse { stored: count })
    }

    async fn get_encrypted_notes(
        &self,
        from_index: u64,
        count: u64,
    ) -> Result<GetEncryptedNotesResponse, ErrorObjectOwned> {
        self.rate_limiter.check("get_encrypted_notes")?;
        let state = self.state.read().await;

        let max_count = count.min(1024);
        let leaf_count = state.note_tree.leaf_count();

        let entries = state
            .encrypted_notes
            .get_range(from_index, max_count)
            .map_err(|e| internal_error(e))?;

        let notes = entries
            .into_iter()
            .map(|(idx, bytes)| EncryptedNoteEntry {
                leaf_index: idx,
                ciphertext: format!("0x{}", hex::encode(bytes)),
            })
            .collect();

        Ok(GetEncryptedNotesResponse { notes, leaf_count })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Server Startup
// ─────────────────────────────────────────────────────────────────────

pub async fn start_rpc_server(
    state: Arc<RwLock<NodeState>>,
    addr: &str,
    tx_broadcast: Option<mpsc::Sender<Transaction>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // CORS: allow only localhost origins for alpha safety.
    // The block explorer and local tools connect from these origins.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin, _| {
            if let Ok(s) = origin.to_str() {
                let s = s.to_lowercase();
                s.starts_with("http://localhost")
                    || s.starts_with("http://127.0.0.1")
                    || s.starts_with("http://[::1]")
            } else {
                false
            }
        }))
        .allow_headers([header::CONTENT_TYPE])
        .allow_methods([http::Method::POST]);

    let middleware = tower::ServiceBuilder::new().layer(cors);

    let server = Server::builder()
        .set_http_middleware(middleware)
        .max_request_body_size(10 * 1024 * 1024) // 10 MB
        .build(addr.parse::<std::net::SocketAddr>()?)
        .await?;

    let rpc_server = RpcServer::new(state, tx_broadcast);
    let handle = server.start(rpc_server.into_rpc());

    info!("JSON-RPC server listening on {} (CORS: localhost-only)", addr);

    handle.stopped().await;
    Ok(())
}
