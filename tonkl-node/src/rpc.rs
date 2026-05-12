// Tonkl Protocol - JSON-RPC Interface

use crate::block::{
    validate_public_inputs_match_fields, Block, BlockBuilder, BlockHeader, Transaction, TxType,
};
use crate::mempool::Mempool;
use crate::state::{field_to_hex, ChainMeta, EncryptedNoteStore, NoteTree, NullifierSet};
use crate::verifier::{serialize_public_inputs, ProofVerifier};
use http::header;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tonkl_prover::{fe_to_be_32, AcirField, FieldElement};
use tower_http::cors::{AllowOrigin, CorsLayer};
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
    async fn get_merkle_proof(
        &self,
        index: u64,
        secret: Option<String>,
    ) -> Result<MerkleProofResponse, ErrorObjectOwned>;

    #[method(name = "get_nullifier_status")]
    async fn get_nullifier_status(
        &self,
        nullifier: String,
        secret: Option<String>,
    ) -> Result<bool, ErrorObjectOwned>;

    /// Submit a transaction. Requires `secret` unless the node was started in
    /// explicit unauthenticated loopback development mode.
    #[method(name = "submit_tx")]
    async fn submit_tx(
        &self,
        request: SubmitTxRequest,
        secret: Option<String>,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned>;

    #[method(name = "get_tx_status")]
    async fn get_tx_status(&self, tx_hash: String) -> Result<TxStatusResponse, ErrorObjectOwned>;

    #[method(name = "get_block")]
    async fn get_block(
        &self,
        block_number: u64,
        secret: Option<String>,
    ) -> Result<Option<Block>, ErrorObjectOwned>;

    /// Get a range of blocks for chain sync. Returns up to 50 blocks starting from `from_block`.
    #[method(name = "get_blocks_range")]
    async fn get_blocks_range(
        &self,
        from_block: u64,
        count: u64,
        secret: Option<String>,
    ) -> Result<Vec<Block>, ErrorObjectOwned>;

    /// Produce a block. Requires `secret` unless the node was started in
    /// explicit unauthenticated loopback development mode.
    #[method(name = "produce_block")]
    async fn produce_block(&self, secret: Option<String>) -> Result<BlockHeader, ErrorObjectOwned>;

    /// Store encrypted notes. Requires `secret` unless the node was started in
    /// explicit unauthenticated loopback development mode.
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
        secret: Option<String>,
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
        limits.insert(
            "submit_tx",
            RateLimit {
                max_requests: 10,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "produce_block",
            RateLimit {
                max_requests: 5,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "store_encrypted_notes",
            RateLimit {
                max_requests: 20,
                window: std::time::Duration::from_secs(60),
            },
        );
        // Read endpoints — generous limits
        limits.insert(
            "get_status",
            RateLimit {
                max_requests: 120,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "get_merkle_root",
            RateLimit {
                max_requests: 120,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "get_merkle_proof",
            RateLimit {
                max_requests: 60,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "get_nullifier_status",
            RateLimit {
                max_requests: 60,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "get_tx_status",
            RateLimit {
                max_requests: 60,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "get_block",
            RateLimit {
                max_requests: 60,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "get_blocks_range",
            RateLimit {
                max_requests: 30,
                window: std::time::Duration::from_secs(60),
            },
        );
        limits.insert(
            "get_encrypted_notes",
            RateLimit {
                max_requests: 60,
                window: std::time::Duration::from_secs(60),
            },
        );

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
                    method,
                    limit.max_requests,
                    limit.window.as_secs()
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

#[derive(Debug, Clone)]
struct MintAuthority {
    pk_x: FieldElement,
    pk_y: FieldElement,
    max_supply: u128,
}

#[derive(Debug, Clone)]
struct MintPublicInputs {
    total_minted: u128,
    asset_id: FieldElement,
    authority_pk_x: FieldElement,
    authority_pk_y: FieldElement,
}

/// Node-side mint policy.
///
/// Mint proofs prove knowledge of the private key behind a public authority,
/// but the node must still decide which authority is allowed for each asset and
/// how much total supply may ever be minted. This policy is intentionally
/// fail-closed: without an explicit configured authority, mint transactions are
/// rejected.
#[derive(Debug, Clone, Default)]
pub struct MintPolicy {
    authorities: HashMap<String, MintAuthority>,
}

impl MintPolicy {
    pub fn from_env() -> Self {
        match std::env::var("TONKL_MINT_AUTHORITIES") {
            Ok(raw) if !raw.trim().is_empty() => match Self::from_json(&raw) {
                Ok(policy) => {
                    info!(
                        "Mint policy loaded for {} asset(s)",
                        policy.authorities.len()
                    );
                    policy
                }
                Err(e) => {
                    tracing::warn!(
                        "Invalid TONKL_MINT_AUTHORITIES: {} — mint transactions will be rejected",
                        e
                    );
                    Self::default()
                }
            },
            _ => {
                tracing::warn!(
                    "TONKL_MINT_AUTHORITIES not set — mint transactions will be rejected"
                );
                Self::default()
            }
        }
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        let parsed: HashMap<String, serde_json::Value> =
            serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {}", e))?;
        let mut authorities = HashMap::new();

        for (asset_id_raw, cfg) in parsed {
            let cfg = cfg
                .as_object()
                .ok_or_else(|| format!("asset {} config must be an object", asset_id_raw))?;
            let asset_id = parse_config_field(&asset_id_raw)
                .map_err(|e| format!("asset {}: {}", asset_id_raw, e))?;
            let asset_key = field_to_hex(asset_id);

            let pk_x_raw = cfg
                .get("pk_x")
                .or_else(|| cfg.get("authority_pk_x"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("asset {} missing pk_x", asset_id_raw))?;
            let pk_y_raw = cfg
                .get("pk_y")
                .or_else(|| cfg.get("authority_pk_y"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("asset {} missing pk_y", asset_id_raw))?;
            let max_supply = cfg
                .get("max_supply")
                .ok_or_else(|| format!("asset {} missing max_supply", asset_id_raw))
                .and_then(parse_u128_json)?;

            authorities.insert(
                asset_key,
                MintAuthority {
                    pk_x: parse_config_field(pk_x_raw)
                        .map_err(|e| format!("asset {} pk_x: {}", asset_id_raw, e))?,
                    pk_y: parse_config_field(pk_y_raw)
                        .map_err(|e| format!("asset {} pk_y: {}", asset_id_raw, e))?,
                    max_supply,
                },
            );
        }

        Ok(Self { authorities })
    }

    pub fn validate_transaction(
        &self,
        chain_meta: &ChainMeta,
        mempool: &Mempool,
        tx: &Transaction,
    ) -> Result<(), String> {
        if tx.tx_type != TxType::Mint {
            return Ok(());
        }

        let details = mint_details_from_public_inputs(&tx.public_inputs)?;
        self.validate_mint_details(chain_meta, Some(mempool), &details)
    }

    pub fn validate_block_mints(
        &self,
        chain_meta: &ChainMeta,
        txs: &[Transaction],
    ) -> Result<(), String> {
        let mut projected_by_asset: HashMap<String, u128> = HashMap::new();

        for tx in txs.iter().filter(|tx| tx.tx_type == TxType::Mint) {
            let details = mint_details_from_public_inputs(&tx.public_inputs)?;
            let asset_key = field_to_hex(details.asset_id);
            self.validate_authority(&asset_key, &details)?;

            let current_or_projected = match projected_by_asset.get(&asset_key) {
                Some(value) => *value,
                None => chain_meta
                    .minted_supply(&asset_key)
                    .map_err(|e| format!("failed to read minted supply: {}", e))?,
            };
            let projected = current_or_projected
                .checked_add(details.total_minted)
                .ok_or_else(|| format!("mint supply overflow for asset {}", asset_key))?;
            let authority = self
                .authorities
                .get(&asset_key)
                .ok_or_else(|| format!("mint disabled for unregistered asset {}", asset_key))?;
            if projected > authority.max_supply {
                return Err(format!(
                    "mint exceeds supply cap for asset {}: projected {}, max {}",
                    asset_key, projected, authority.max_supply
                ));
            }

            projected_by_asset.insert(asset_key, projected);
        }

        Ok(())
    }

    pub fn record_block_mints(
        &self,
        chain_meta: &ChainMeta,
        txs: &[Transaction],
    ) -> Result<(), String> {
        for tx in txs.iter().filter(|tx| tx.tx_type == TxType::Mint) {
            let details = mint_details_from_public_inputs(&tx.public_inputs)?;
            let asset_key = field_to_hex(details.asset_id);
            chain_meta
                .add_minted_supply(&asset_key, details.total_minted)
                .map_err(|e| format!("failed to record minted supply: {}", e))?;
        }
        Ok(())
    }

    fn validate_mint_details(
        &self,
        chain_meta: &ChainMeta,
        mempool: Option<&Mempool>,
        details: &MintPublicInputs,
    ) -> Result<(), String> {
        let asset_key = field_to_hex(details.asset_id);
        let authority = self.validate_authority(&asset_key, details)?;
        let current = chain_meta
            .minted_supply(&asset_key)
            .map_err(|e| format!("failed to read minted supply: {}", e))?;
        let pending = match mempool {
            Some(mempool) => pending_minted_for_asset(mempool, &asset_key)?,
            None => 0,
        };
        let projected = current
            .checked_add(pending)
            .and_then(|value| value.checked_add(details.total_minted))
            .ok_or_else(|| format!("mint supply overflow for asset {}", asset_key))?;

        if projected > authority.max_supply {
            return Err(format!(
                "mint exceeds supply cap for asset {}: current {}, pending {}, requested {}, max {}",
                asset_key, current, pending, details.total_minted, authority.max_supply
            ));
        }

        Ok(())
    }

    fn validate_authority(
        &self,
        asset_key: &str,
        details: &MintPublicInputs,
    ) -> Result<&MintAuthority, String> {
        let authority = self
            .authorities
            .get(asset_key)
            .ok_or_else(|| format!("mint disabled for unregistered asset {}", asset_key))?;

        if details.authority_pk_x != authority.pk_x || details.authority_pk_y != authority.pk_y {
            return Err(format!(
                "mint authority mismatch for asset {}: got ({}, {}), expected ({}, {})",
                asset_key,
                field_to_hex(details.authority_pk_x),
                field_to_hex(details.authority_pk_y),
                field_to_hex(authority.pk_x),
                field_to_hex(authority.pk_y),
            ));
        }

        Ok(authority)
    }
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
    /// Configured mint authorities and supply caps.
    pub mint_policy: MintPolicy,
}

pub struct RpcServer {
    state: Arc<RwLock<NodeState>>,
    /// Secret token required for write operations.
    /// Missing secrets are allowed only when startup selected explicit local dev mode.
    rpc_secret: Option<String>,
    /// Allow metadata-heavy reads without a secret.
    /// Intended only for explicit explorer/public-read deployments or local dev.
    allow_public_metadata_reads: bool,
    /// Per-method sliding-window rate limiter.
    rate_limiter: RpcRateLimiter,
    /// Optional channel to broadcast accepted transactions to the P2P layer.
    /// When a transaction is accepted via submit_tx, a clone is sent here
    /// so the P2P layer can gossip it to peers.
    tx_broadcast: Option<mpsc::Sender<Transaction>>,
}

impl RpcServer {
    pub fn new(
        state: Arc<RwLock<NodeState>>,
        tx_broadcast: Option<mpsc::Sender<Transaction>>,
        allow_unauthenticated_writes: bool,
        allow_public_metadata_reads: bool,
    ) -> Self {
        let rpc_secret = std::env::var("TONKL_RPC_SECRET")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if rpc_secret.is_some() {
            info!("RPC write operations require TONKL_RPC_SECRET authentication");
        } else if allow_unauthenticated_writes {
            tracing::warn!(
                "TONKL_RPC_SECRET not set - write operations are unrestricted by explicit local dev override"
            );
        } else {
            tracing::error!(
                "TONKL_RPC_SECRET not set and unauthenticated writes were not explicitly allowed"
            );
        }
        if allow_public_metadata_reads {
            tracing::warn!("Metadata-heavy RPC reads are public by explicit configuration");
        } else if rpc_secret.is_some() {
            info!("Metadata-heavy RPC reads require TONKL_RPC_SECRET authentication");
        } else {
            tracing::warn!(
                "Metadata-heavy RPC reads are disabled until TONKL_RPC_SECRET is set or public metadata reads are explicitly enabled"
            );
        }
        Self {
            state,
            rpc_secret,
            allow_public_metadata_reads,
            rate_limiter: RpcRateLimiter::new(),
            tx_broadcast,
        }
    }

    fn check_write_auth(&self, secret: Option<&String>) -> Result<(), ErrorObjectOwned> {
        if let Some(ref expected) = self.rpc_secret {
            match secret {
                Some(s) if s == expected => Ok(()),
                _ => Err(auth_error()),
            }
        } else {
            Ok(())
        }
    }

    fn check_metadata_read_auth(&self, secret: Option<&String>) -> Result<(), ErrorObjectOwned> {
        if self.allow_public_metadata_reads {
            return Ok(());
        }

        if let Some(ref expected) = self.rpc_secret {
            match secret {
                Some(s) if s == expected => Ok(()),
                _ => Err(metadata_auth_error()),
            }
        } else {
            Err(metadata_auth_unavailable_error())
        }
    }
}

// ─── Input size limits for DoS prevention ────────────────────────────
const MAX_PROOF_HEX_LEN: usize = 65_536; // 32 KB decoded — UltraHonk proofs are ~16 KB
const MAX_COMMITMENTS: usize = 32; // matches mint circuit max
const MAX_NULLIFIERS: usize = 32; // matches merge circuit max
const MAX_PUBLIC_INPUTS: usize = 64; // mint circuit has 36 public inputs
const MAX_ENCRYPTED_NOTES_STORE: usize = 64; // per request

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
    ErrorObjectOwned::owned(
        -32001,
        "authentication required: provide valid secret for write operations",
        None::<()>,
    )
}

fn metadata_auth_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        -32001,
        "authentication required: provide valid secret for metadata-heavy read operations",
        None::<()>,
    )
}

fn metadata_auth_unavailable_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        -32001,
        "metadata-heavy read operations are not public; set TONKL_RPC_SECRET or start with --allow-public-rpc-metadata for an intentional public explorer",
        None::<()>,
    )
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

fn parse_field(hex_str: &str) -> Result<FieldElement, ErrorObjectOwned> {
    parse_field_string(hex_str).map_err(invalid_params)
}

fn parse_config_field(value: &str) -> Result<FieldElement, String> {
    if value.starts_with("0x") {
        parse_field_string(value)
    } else {
        let parsed = value
            .parse::<u128>()
            .map_err(|e| format!("invalid decimal field: {}", e))?;
        Ok(FieldElement::from(parsed))
    }
}

fn parse_u128_json(value: &serde_json::Value) -> Result<u128, String> {
    if let Some(s) = value.as_str() {
        return s
            .parse::<u128>()
            .map_err(|e| format!("invalid max_supply string: {}", e));
    }
    if let Some(n) = value.as_u64() {
        return Ok(n as u128);
    }
    Err("max_supply must be a non-negative integer or decimal string".to_string())
}

fn parse_public_inputs_string(public_inputs: &[String]) -> Result<Vec<FieldElement>, String> {
    public_inputs
        .iter()
        .map(|value| parse_field_string(value))
        .collect::<Result<Vec<_>, _>>()
}

fn field_to_u128(value: FieldElement, label: &str) -> Result<u128, String> {
    let bytes = fe_to_be_32(&value);
    if bytes[..16].iter().any(|b| *b != 0) {
        return Err(format!("{} exceeds u128 range", label));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[16..]);
    Ok(u128::from_be_bytes(arr))
}

fn mint_details_from_public_inputs(public_inputs: &[String]) -> Result<MintPublicInputs, String> {
    let public_inputs = parse_public_inputs_string(public_inputs)?;
    if public_inputs.len() != 36 {
        return Err(format!(
            "Mint expects 36 public inputs, got {}",
            public_inputs.len()
        ));
    }

    Ok(MintPublicInputs {
        total_minted: field_to_u128(public_inputs[32], "Mint total_minted")?,
        asset_id: public_inputs[33],
        authority_pk_x: public_inputs[34],
        authority_pk_y: public_inputs[35],
    })
}

fn pending_minted_for_asset(mempool: &Mempool, asset_key: &str) -> Result<u128, String> {
    let mut total = 0u128;
    for tx in mempool
        .transactions()
        .filter(|tx| tx.tx_type == TxType::Mint)
    {
        let details = mint_details_from_public_inputs(&tx.public_inputs)?;
        if field_to_hex(details.asset_id) == asset_key {
            total = total
                .checked_add(details.total_minted)
                .ok_or_else(|| format!("pending mint supply overflow for asset {}", asset_key))?;
        }
    }
    Ok(total)
}

fn validate_public_inputs_match_request(
    tx_type: TxType,
    public_inputs: &[String],
    new_commitments: &[FieldElement],
    nullifiers: &[FieldElement],
    merkle_root: FieldElement,
    fee: u64,
    asset_id: FieldElement,
) -> Result<(), ErrorObjectOwned> {
    validate_public_inputs_match_fields(
        tx_type,
        public_inputs,
        new_commitments,
        nullifiers,
        merkle_root,
        fee,
        asset_id,
    )
    .map_err(invalid_params)
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

    async fn get_merkle_proof(
        &self,
        index: u64,
        secret: Option<String>,
    ) -> Result<MerkleProofResponse, ErrorObjectOwned> {
        self.rate_limiter.check("get_merkle_proof")?;
        self.check_metadata_read_auth(secret.as_ref())?;
        let state = self.state.read().await;
        let leaf_count = state.note_tree.leaf_count();
        if index >= leaf_count && leaf_count > 0 {
            return Err(invalid_params(format!(
                "index {} is out of range (tree has {} leaves)",
                index, leaf_count,
            )));
        }
        let proof = state
            .note_tree
            .get_proof(index)
            .map_err(|e| invalid_params(e))?;

        Ok(MerkleProofResponse {
            index: proof.index,
            index_bits: proof.index_bits.to_vec(),
            siblings: proof.siblings.iter().map(|s| field_to_hex(*s)).collect(),
        })
    }

    async fn get_nullifier_status(
        &self,
        nullifier: String,
        secret: Option<String>,
    ) -> Result<bool, ErrorObjectOwned> {
        self.rate_limiter.check("get_nullifier_status")?;
        self.check_metadata_read_auth(secret.as_ref())?;
        let state = self.state.read().await;
        let nf = parse_field(&nullifier)?;
        state
            .nullifier_set
            .contains(&nf)
            .map_err(|e| internal_error(e))
    }

    async fn submit_tx(
        &self,
        request: SubmitTxRequest,
        secret: Option<String>,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned> {
        // ── Rate limit ─────────────────────────────────────────
        self.rate_limiter.check("submit_tx")?;

        // ── Auth check ──────────────────────────────────────────
        self.check_write_auth(secret.as_ref())?;

        // ── Input size validation (DoS prevention) ──────────────
        if request.proof.len() > MAX_PROOF_HEX_LEN {
            return Err(invalid_params(format!(
                "proof too large: {} chars (max {})",
                request.proof.len(),
                MAX_PROOF_HEX_LEN
            )));
        }
        if request.new_commitments.len() > MAX_COMMITMENTS {
            return Err(invalid_params(format!(
                "too many commitments: {} (max {})",
                request.new_commitments.len(),
                MAX_COMMITMENTS
            )));
        }
        if request.nullifiers.len() > MAX_NULLIFIERS {
            return Err(invalid_params(format!(
                "too many nullifiers: {} (max {})",
                request.nullifiers.len(),
                MAX_NULLIFIERS
            )));
        }
        if request.public_inputs.len() > MAX_PUBLIC_INPUTS {
            return Err(invalid_params(format!(
                "too many public inputs: {} (max {})",
                request.public_inputs.len(),
                MAX_PUBLIC_INPUTS
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

        let new_commitments: Vec<FieldElement> = request
            .new_commitments
            .iter()
            .map(|s| parse_field(s))
            .collect::<Result<_, _>>()?;

        let nullifiers: Vec<FieldElement> = request
            .nullifiers
            .iter()
            .map(|s| parse_field(s))
            .collect::<Result<_, _>>()?;

        let merkle_root = parse_field(&request.merkle_root)?;
        let asset_id = parse_field(&request.asset_id)?;

        validate_public_inputs_match_request(
            tx_type,
            &request.public_inputs,
            &new_commitments,
            &nullifiers,
            merkle_root,
            request.fee,
            asset_id,
        )?;

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
            state
                .mint_policy
                .validate_transaction(&state.chain_meta, &state.mempool, &tx)
                .map_err(invalid_params)?;

            if state.verifier.is_enabled() {
                let public_inputs_bytes = serialize_public_inputs(&tx.public_inputs)
                    .map_err(|e| invalid_params(format!("invalid public inputs: {}", e)))?;

                state
                    .verifier
                    .verify(tx_type, &tx.proof, &public_inputs_bytes)
                    .map_err(|e| invalid_params(format!("proof verification failed: {}", e)))?;

                info!("Proof verified for tx {}", tx_hash_hex);
            }
        }

        let mut state = self.state.write().await;

        // Mempool size limit to prevent DoS
        const MAX_MEMPOOL_SIZE: usize = 1000;
        if state.mempool.len() >= MAX_MEMPOOL_SIZE {
            return Err(invalid_params(
                "mempool is full — try again after the next block",
            ));
        }

        // Check nullifiers against set before submitting to mempool
        // (split borrow: check first, then submit)
        for nf in &tx.nullifiers {
            if state
                .nullifier_set
                .contains(nf)
                .map_err(|e| internal_error(e))?
            {
                return Err(invalid_params(format!(
                    "nullifier already spent: {}",
                    field_to_hex(*nf)
                )));
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

    async fn get_block(
        &self,
        block_number: u64,
        secret: Option<String>,
    ) -> Result<Option<Block>, ErrorObjectOwned> {
        self.rate_limiter.check("get_block")?;
        self.check_metadata_read_auth(secret.as_ref())?;
        let state = self.state.read().await;
        Ok(state.blocks.get(block_number as usize).cloned())
    }

    async fn get_blocks_range(
        &self,
        from_block: u64,
        count: u64,
        secret: Option<String>,
    ) -> Result<Vec<Block>, ErrorObjectOwned> {
        self.rate_limiter.check("get_blocks_range")?;
        self.check_metadata_read_auth(secret.as_ref())?;

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
        self.check_write_auth(secret.as_ref())?;

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

        let all_nullifiers: Vec<FieldElement> =
            txs.iter().flat_map(|tx| tx.nullifiers.clone()).collect();

        state
            .mint_policy
            .validate_block_mints(&state.chain_meta, &txs)
            .map_err(invalid_params)?;

        for tx in &txs {
            for cm in &tx.new_commitments {
                state.note_tree.insert(*cm).map_err(|e| internal_error(e))?;
            }
            if !tx.nullifiers.is_empty() {
                state
                    .nullifier_set
                    .insert_batch(&tx.nullifiers)
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
            state.tx_index.insert(
                tx_hash_hex,
                ConfirmedTx {
                    block_number: header.block_number,
                    tx_type: tx.tx_type,
                },
            );
        }

        state
            .mint_policy
            .record_block_mints(&state.chain_meta, &block.transactions)
            .map_err(internal_error)?;

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
        self.check_write_auth(secret.as_ref())?;

        // ── Size limit ──────────────────────────────────────────
        if request.notes.len() > MAX_ENCRYPTED_NOTES_STORE {
            return Err(invalid_params(format!(
                "too many notes: {} (max {} per request)",
                request.notes.len(),
                MAX_ENCRYPTED_NOTES_STORE
            )));
        }

        let mut state = self.state.write().await;

        let entries: Vec<(u64, Vec<u8>)> = request
            .notes
            .iter()
            .map(|e| {
                let bytes = hex::decode(e.ciphertext.strip_prefix("0x").unwrap_or(&e.ciphertext))
                    .map_err(|err| {
                    invalid_params(format!("invalid ciphertext hex: {}", err))
                })?;
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
        secret: Option<String>,
    ) -> Result<GetEncryptedNotesResponse, ErrorObjectOwned> {
        self.rate_limiter.check("get_encrypted_notes")?;
        self.check_metadata_read_auth(secret.as_ref())?;
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
    allow_unauthenticated_writes: bool,
    allow_public_metadata_reads: bool,
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

    let rpc_server = RpcServer::new(
        state,
        tx_broadcast,
        allow_unauthenticated_writes,
        allow_public_metadata_reads,
    );
    let handle = server.start(rpc_server.into_rpc());

    info!(
        "JSON-RPC server listening on {} (CORS: localhost-only)",
        addr
    );

    handle.stopped().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: u128) -> FieldElement {
        FieldElement::from(value)
    }

    fn hex_field(value: u128) -> String {
        field_to_hex(field(value))
    }

    fn hex_fields(values: Vec<FieldElement>) -> Vec<String> {
        values.into_iter().map(field_to_hex).collect()
    }

    fn mint_tx(
        hash_byte: u8,
        amount: u128,
        asset_id: FieldElement,
        authority_pk_x: FieldElement,
        authority_pk_y: FieldElement,
    ) -> Transaction {
        let new_commitments = (0..32)
            .map(|i| field(10_000 + hash_byte as u128 * 100 + i))
            .collect::<Vec<_>>();
        let mut raw_inputs = new_commitments.clone();
        raw_inputs.push(field(amount));
        raw_inputs.push(asset_id);
        raw_inputs.push(authority_pk_x);
        raw_inputs.push(authority_pk_y);

        Transaction {
            tx_type: TxType::Mint,
            tx_hash: [hash_byte; 32],
            proof: vec![hash_byte],
            public_inputs: hex_fields(raw_inputs),
            new_commitments,
            nullifiers: vec![],
            merkle_root: FieldElement::zero(),
            fee: 0,
            asset_id,
        }
    }

    #[test]
    fn transfer_public_inputs_must_match_request_fields() {
        let merkle_root = field(1);
        let nullifiers = vec![field(2), field(3)];
        let new_commitments = vec![field(4), field(5)];
        let fee = 6;
        let asset_id = field(7);
        let public_inputs = hex_fields(vec![
            merkle_root,
            nullifiers[0],
            nullifiers[1],
            new_commitments[0],
            new_commitments[1],
            field(fee),
            asset_id,
        ]);

        assert!(validate_public_inputs_match_request(
            TxType::Transfer,
            &public_inputs,
            &new_commitments,
            &nullifiers,
            merkle_root,
            fee as u64,
            asset_id,
        )
        .is_ok());

        let mut tampered = public_inputs;
        tampered[3] = hex_field(99);
        assert!(validate_public_inputs_match_request(
            TxType::Transfer,
            &tampered,
            &new_commitments,
            &nullifiers,
            merkle_root,
            fee as u64,
            asset_id,
        )
        .is_err());
    }

    #[test]
    fn merge_public_inputs_support_32_nullifiers() {
        let merkle_root = field(10);
        let nullifiers = (0..32).map(|i| field(100 + i)).collect::<Vec<_>>();
        let new_commitments = vec![field(200)];
        let fee = 5;
        let asset_id = field(9);

        let mut raw_inputs = Vec::with_capacity(36);
        raw_inputs.push(merkle_root);
        raw_inputs.extend_from_slice(&nullifiers);
        raw_inputs.push(new_commitments[0]);
        raw_inputs.push(field(fee));
        raw_inputs.push(asset_id);

        assert!(validate_public_inputs_match_request(
            TxType::Merge,
            &hex_fields(raw_inputs),
            &new_commitments,
            &nullifiers,
            merkle_root,
            fee as u64,
            asset_id,
        )
        .is_ok());
    }

    #[test]
    fn mint_public_inputs_bind_commitments_and_asset() {
        let new_commitments = (0..32).map(|i| field(1000 + i)).collect::<Vec<_>>();
        let nullifiers = Vec::new();
        let asset_id = field(2);
        let mut raw_inputs = new_commitments.clone();
        raw_inputs.push(field(12345)); // total_minted
        raw_inputs.push(asset_id);
        raw_inputs.push(field(88)); // authority_pk_x
        raw_inputs.push(field(89)); // authority_pk_y
        let public_inputs = hex_fields(raw_inputs);

        assert!(validate_public_inputs_match_request(
            TxType::Mint,
            &public_inputs,
            &new_commitments,
            &nullifiers,
            field(0),
            0,
            asset_id,
        )
        .is_ok());

        let mut tampered_commitment = public_inputs.clone();
        tampered_commitment[0] = hex_field(777);
        assert!(validate_public_inputs_match_request(
            TxType::Mint,
            &tampered_commitment,
            &new_commitments,
            &nullifiers,
            field(0),
            0,
            asset_id,
        )
        .is_err());

        let mut tampered_asset = public_inputs;
        tampered_asset[33] = hex_field(3);
        assert!(validate_public_inputs_match_request(
            TxType::Mint,
            &tampered_asset,
            &new_commitments,
            &nullifiers,
            field(0),
            0,
            asset_id,
        )
        .is_err());
    }

    #[test]
    fn mint_policy_rejects_unregistered_or_wrong_authority() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain_meta = ChainMeta::open(&db).unwrap();
        let mempool = Mempool::new(10);
        let asset_id = field(1);
        let pk_x = field(88);
        let pk_y = field(89);
        let tx = mint_tx(1, 100, asset_id, pk_x, pk_y);

        assert!(MintPolicy::default()
            .validate_transaction(&chain_meta, &mempool, &tx)
            .is_err());

        let wrong_policy = MintPolicy::from_json(&format!(
            r#"{{"1":{{"pk_x":"{}","pk_y":"{}","max_supply":"1000"}}}}"#,
            field_to_hex(field(90)),
            field_to_hex(pk_y),
        ))
        .unwrap();

        assert!(wrong_policy
            .validate_transaction(&chain_meta, &mempool, &tx)
            .is_err());
    }

    #[test]
    fn mint_policy_counts_pending_mints_against_cap() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain_meta = ChainMeta::open(&db).unwrap();
        let mut mempool = Mempool::new(10);
        let asset_id = field(1);
        let pk_x = field(88);
        let pk_y = field(89);
        let policy = MintPolicy::from_json(&format!(
            r#"{{"1":{{"pk_x":"{}","pk_y":"{}","max_supply":"150"}}}}"#,
            field_to_hex(pk_x),
            field_to_hex(pk_y),
        ))
        .unwrap();

        let pending = mint_tx(1, 100, asset_id, pk_x, pk_y);
        mempool.submit_unchecked(pending);

        let within_cap = mint_tx(2, 50, asset_id, pk_x, pk_y);
        assert!(policy
            .validate_transaction(&chain_meta, &mempool, &within_cap)
            .is_ok());

        let over_cap = mint_tx(3, 51, asset_id, pk_x, pk_y);
        assert!(policy
            .validate_transaction(&chain_meta, &mempool, &over_cap)
            .is_err());
    }

    #[test]
    fn mint_policy_records_persistent_supply() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain_meta = ChainMeta::open(&db).unwrap();
        let mempool = Mempool::new(10);
        let asset_id = field(1);
        let asset_key = field_to_hex(asset_id);
        let pk_x = field(88);
        let pk_y = field(89);
        let policy = MintPolicy::from_json(&format!(
            r#"{{"1":{{"pk_x":"{}","pk_y":"{}","max_supply":"150"}}}}"#,
            field_to_hex(pk_x),
            field_to_hex(pk_y),
        ))
        .unwrap();

        let first = mint_tx(1, 100, asset_id, pk_x, pk_y);
        policy
            .record_block_mints(&chain_meta, &[first])
            .expect("supply recording should succeed");
        assert_eq!(chain_meta.minted_supply(&asset_key).unwrap(), 100);

        let second = mint_tx(2, 51, asset_id, pk_x, pk_y);
        assert!(policy
            .validate_transaction(&chain_meta, &mempool, &second)
            .is_err());
    }
}
