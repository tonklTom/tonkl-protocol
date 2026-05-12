//! tonkl-prover (library crate): pure functions for witness solving,
//! msgpack serialization, and input parsing. The binary in `src/main.rs`
//! is a thin CLI wrapper over this library.
//!
//! Library functions return `Result` rather than calling `process::exit`,
//! so they can be exercised by unit + integration tests.

use acvm::acir::circuit::Program;
use acvm::acir::native_types::WitnessMap;
use acvm::pwg::ACVM;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use hmac::{Hmac, KeyInit, Mac};
use noirc_abi::input_parser::InputValue;
use noirc_abi::Abi;
use num_bigint::BigUint;
use serde_json::Value;
use sha2::Sha512;
use std::collections::BTreeMap;

use acvm_blackbox_solver::BlackBoxFunctionSolver;
use zeroize::Zeroize;

/// Re-export FieldElement and AcirField so callers (main.rs, wallet, node) don't need acvm directly.
pub use acvm::AcirField;
pub use acvm::FieldElement;

/// Library error type. String-wrapped for simplicity; callers format as-is.
pub type Result<T> = std::result::Result<T, String>;

// -- Poseidon2 Hash Functions ------------------------------------------------
//
// Direct Rust implementations of the same Poseidon2 sponge construction used
// by the Noir circuit (hash.nr). Allows the wallet to compute commitments,
// nullifiers, and Merkle hashes without running nargo or the ACVM.
//
// Uses Bn254BlackBoxSolver::poseidon2_permutation (real Barretenberg
// Poseidon2 with proper BN254 round constants) -- identical to what
// std::hash::poseidon2_permutation calls inside the circuit.

/// Poseidon2 permutation: state width t=4 over BN254 scalar field.
/// Equivalent to `std::hash::poseidon2_permutation(state)` in Noir.
fn p2(state: [FieldElement; 4]) -> Result<[FieldElement; 4]> {
    let solver = Bn254BlackBoxSolver::default();
    let result = solver
        .poseidon2_permutation(&state)
        .map_err(|e| format!("Poseidon2 permutation failed: {e}"))?;
    if result.len() != 4 {
        return Err(format!(
            "Poseidon2 returned {} elements, expected 4",
            result.len()
        ));
    }
    Ok([result[0], result[1], result[2], result[3]])
}

/// 2-input Poseidon2 hash. Used for Merkle tree node hashing.
/// Matches `hash_2(a, b)` in hash.nr.
pub fn poseidon2_hash_2(a: FieldElement, b: FieldElement) -> Result<FieldElement> {
    let state = p2([a, b, FieldElement::zero(), FieldElement::zero()])?;
    Ok(state[0])
}

/// 3-input Poseidon2 hash. Used for nullifier: hash(DOMAIN, cm, sk).
/// Matches `hash_3(a, b, c)` in hash.nr.
pub fn poseidon2_hash_3(a: FieldElement, b: FieldElement, c: FieldElement) -> Result<FieldElement> {
    let state = p2([a, b, c, FieldElement::zero()])?;
    Ok(state[0])
}

/// 7-input Poseidon2 sponge hash. Used for note commitment.
/// Three-phase absorption matching `hash_7(a..g)` in hash.nr.
pub fn poseidon2_hash_7(
    a: FieldElement,
    b: FieldElement,
    c: FieldElement,
    d: FieldElement,
    e: FieldElement,
    f: FieldElement,
    g: FieldElement,
) -> Result<FieldElement> {
    // Phase 1: absorb first 3 inputs
    let s1 = p2([a, b, c, FieldElement::zero()])?;
    // Phase 2: XOR (field add) next 3 inputs into rate
    let s2 = p2([s1[0] + d, s1[1] + e, s1[2] + f, s1[3]])?;
    // Phase 3: XOR final input into state[0]
    let s3 = p2([s2[0] + g, s2[1], s2[2], s2[3]])?;
    Ok(s3[0])
}

// -- Note Primitives (wallet-side) -------------------------------------------
//
// These mirror note.nr and constants.nr exactly, allowing the Rust wallet to
// compute commitments and nullifiers without needing nargo or the hasher circuit.

/// Note commitment domain separator (matches constants.nr COMMITMENT_DOMAIN).
pub const COMMITMENT_DOMAIN: u128 = 2;

/// Nullifier domain separator (matches constants.nr NULLIFIER_DOMAIN).
pub const NULLIFIER_DOMAIN: u128 = 1;

/// Note schema version (matches constants.nr NOTE_VERSION).
pub const NOTE_VERSION: u128 = 0;

/// A note's fields, sufficient to compute its commitment.
#[derive(Debug, Clone)]
pub struct NoteFields {
    pub value: FieldElement,
    pub asset_id: FieldElement,
    pub owner_pk_x: FieldElement,
    pub owner_pk_y: FieldElement,
    pub rho: FieldElement,
}

/// Compute note commitment.
/// cm = hash_7(COMMITMENT_DOMAIN, NOTE_VERSION, value, asset_id, pk_x, pk_y, rho)
/// Matches `commitment(note)` in note.nr.
pub fn note_commitment(note: &NoteFields) -> Result<FieldElement> {
    poseidon2_hash_7(
        FieldElement::from(COMMITMENT_DOMAIN),
        FieldElement::from(NOTE_VERSION),
        note.value,
        note.asset_id,
        note.owner_pk_x,
        note.owner_pk_y,
        note.rho,
    )
}

/// Compute note nullifier.
/// nf = hash_3(NULLIFIER_DOMAIN, cm, sk)
/// Matches `nullifier(cm, owner_sk)` in note.nr.
pub fn note_nullifier(cm: FieldElement, owner_sk: FieldElement) -> Result<FieldElement> {
    poseidon2_hash_3(FieldElement::from(NULLIFIER_DOMAIN), cm, owner_sk)
}

/// Derive public key from spending key: pk = sk * G on Grumpkin.
/// Matches `derive_pk(sk)` in note.nr.
///
/// Returns (pk_x, pk_y).
pub fn wallet_derive_pk(sk: FieldElement) -> Result<(FieldElement, FieldElement)> {
    let solver = Bn254BlackBoxSolver::default();

    // Grumpkin generator point: (1, y) where y = sqrt(-16) mod BN254_Fr.
    // The curve equation is y² = x³ - 17 over the BN254 scalar field.
    //
    // multi_scalar_mul(points, scalars_lo, scalars_hi, uses_grumpkin):
    //   points     = [x, y, is_infinite] flattened triplets
    //   scalars_lo = low 128 bits of each scalar
    //   scalars_hi = high 128 bits of each scalar
    //   uses_grumpkin = true (REQUIRED — false yields point-at-infinity)
    let gen_x = FieldElement::from_hex(
        "0x0000000000000000000000000000000000000000000000000000000000000001",
    )
    .ok_or("Failed to parse generator x")?;

    let gen_y = FieldElement::from_hex(
        "0x0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c",
    )
    .ok_or("Failed to parse generator y")?;

    let is_infinite = FieldElement::zero();

    // Split sk into lo/hi 128-bit halves for multi_scalar_mul.
    // The solver expects scalars as pairs of (lo, hi) where scalar = lo + hi * 2^128.
    let sk_bytes = fe_to_be_32(&sk);
    let sk_hi_bytes = &sk_bytes[0..16];
    let sk_lo_bytes = &sk_bytes[16..32];

    let sk_lo = FieldElement::from_hex(&format!(
        "0x{}",
        sk_lo_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .ok_or("Failed to parse sk_lo")?;

    let sk_hi = FieldElement::from_hex(&format!(
        "0x{}",
        sk_hi_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .ok_or("Failed to parse sk_hi")?;

    let (result_x, result_y, _is_inf) = solver
        .multi_scalar_mul(&[gen_x, gen_y, is_infinite], &[sk_lo], &[sk_hi], true)
        .map_err(|e| format!("multi_scalar_mul failed: {e}"))?;

    Ok((result_x, result_y))
}

/// Compute Merkle root from a leaf and its authentication path.
/// Matches `compute_merkle_root` in main.nr.
pub fn compute_merkle_root(
    leaf: FieldElement,
    index_bits: &[bool; 32],
    path: &[FieldElement; 32],
) -> Result<FieldElement> {
    let mut node = leaf;
    for i in 0..32 {
        let sibling = path[i];
        if !index_bits[i] {
            node = poseidon2_hash_2(node, sibling)?;
        } else {
            node = poseidon2_hash_2(sibling, node)?;
        }
    }
    Ok(node)
}

// -- Sparse Merkle Tree Builder -----------------------------------------------
//
// Builds a depth-32 sparse binary Merkle tree from a list of leaf commitments.
// Uses the same Poseidon2 hash_2 as the Noir circuits. Empty subtrees have
// value 0 (matching the circuit convention in merkle.nr: "Empty leaf / empty
// subtree: Field(0)").
//
// This is the off-circuit counterpart to compute_root() in merkle.nr. The
// circuit verifies individual membership proofs; this builder constructs the
// full tree and extracts those proofs.

/// A Merkle authentication path: LSB-first index bits + sibling hashes.
pub struct MerklePath {
    pub index_bits: [bool; 32],
    pub siblings: [FieldElement; 32],
}

/// Result of building a Merkle tree: root + paths for every inserted leaf.
pub struct MerkleTreeResult {
    pub root: FieldElement,
    pub paths: Vec<MerklePath>,
}

/// Build a depth-32 sparse Merkle tree from leaf commitments.
///
/// Leaves are placed at consecutive positions 0..n-1. Subtrees with no
/// leaves have value 0 (not hash(0,0)). This matches the Noir circuit
/// convention where authentication paths use 0 for empty siblings.
///
/// Returns the root and an authentication path for each leaf that can be
/// fed directly to `compute_root()` in the circuit.
pub fn build_merkle_tree(leaves: &[FieldElement]) -> Result<MerkleTreeResult> {
    use std::collections::{HashMap, HashSet};

    let depth = 32usize;
    let n = leaves.len();

    // Sparse representation: only non-zero nodes are stored per level.
    // Missing keys are implicitly FieldElement::zero().
    let mut all_levels: Vec<HashMap<usize, FieldElement>> = Vec::with_capacity(depth + 1);

    // Level 0: leaves
    let mut current: HashMap<usize, FieldElement> = HashMap::new();
    for (i, leaf) in leaves.iter().enumerate() {
        if *leaf != FieldElement::zero() {
            current.insert(i, *leaf);
        }
    }
    all_levels.push(current.clone());

    // Levels 1..32: internal nodes (bottom-up)
    for _level in 0..depth {
        let mut next: HashMap<usize, FieldElement> = HashMap::new();
        let mut seen_parents: HashSet<usize> = HashSet::new();

        for &idx in current.keys() {
            let parent_idx = idx / 2;
            if seen_parents.insert(parent_idx) {
                let left_idx = parent_idx * 2;
                let right_idx = parent_idx * 2 + 1;
                let left = current
                    .get(&left_idx)
                    .copied()
                    .unwrap_or(FieldElement::zero());
                let right = current
                    .get(&right_idx)
                    .copied()
                    .unwrap_or(FieldElement::zero());
                let parent = poseidon2_hash_2(left, right)?;
                next.insert(parent_idx, parent);
            }
        }

        all_levels.push(next.clone());
        current = next;
    }

    let root = current.get(&0).copied().unwrap_or(FieldElement::zero());

    // Extract authentication paths for each leaf
    let mut paths = Vec::with_capacity(n);
    for leaf_idx in 0..n {
        let mut index_bits = [false; 32];
        let mut siblings = [FieldElement::zero(); 32];

        let mut idx = leaf_idx;
        for level in 0..depth {
            index_bits[level] = (idx & 1) == 1;
            let sibling_idx = idx ^ 1;
            siblings[level] = all_levels[level]
                .get(&sibling_idx)
                .copied()
                .unwrap_or(FieldElement::zero());
            idx /= 2;
        }

        paths.push(MerklePath {
            index_bits,
            siblings,
        });
    }

    Ok(MerkleTreeResult { root, paths })
}

// -- HD Key Derivation -------------------------------------------------------
//
// Derives note spending keys from a BIP-39 master seed using the exact Python
// wallet formula:
//
//   sk = PBKDF2-HMAC-SHA512(
//       password = DOMAIN || master_seed || note_index_be8,
//       salt = DOMAIN,
//       iterations = 1,
//   )[0..32] mod BN254_P
//
// where:
//   DOMAIN       = b"Tonkl::note_sk_v1"  (versioned domain tag)
//   master_seed  = 64 bytes (from BIP-39 PBKDF2)
//   note_index   = u64, encoded as 8 big-endian bytes
//   BN254_P      = 21888242871839275222246405745257275088548364400416034343698204186575808495617

/// Domain separation tag for note spending key derivation.
/// Versioned so future protocol upgrades can use a different tag
/// without colliding with existing derived keys.
pub const DERIVATION_DOMAIN: &[u8] = b"Tonkl::note_sk_v1";

/// BN254 scalar field modulus.
const BN254_P_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Derive a note spending key from a master seed and note index.
///
/// Returns the 32-byte big-endian representation of:
///   PBKDF2-HMAC-SHA512(DOMAIN || seed || index, DOMAIN, 1)[0..32] mod BN254_P
///
/// The caller is responsible for zeroizing the returned buffer and
/// the master_seed when no longer needed.
///
/// # Panics
/// Panics if `master_seed.len() != 64`. The BIP-39 seed is always 512 bits.
pub fn derive_note_sk(master_seed: &[u8], note_index: u64) -> [u8; 32] {
    assert_eq!(
        master_seed.len(),
        64,
        "master_seed must be exactly 64 bytes (512-bit BIP-39 seed)"
    );

    // Python parity:
    // hashlib.pbkdf2_hmac("sha512", derive_input, DERIVATION_DOMAIN, 1)[:32]
    let mut derive_input = Vec::with_capacity(DERIVATION_DOMAIN.len() + 64 + 8);
    derive_input.extend_from_slice(DERIVATION_DOMAIN);
    derive_input.extend_from_slice(master_seed);
    derive_input.extend_from_slice(&note_index.to_be_bytes());

    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&derive_input)
        .expect("HMAC accepts keys of any length");
    mac.update(DERIVATION_DOMAIN);
    mac.update(&1u32.to_be_bytes());
    derive_input.zeroize();

    let mut pbkdf2_block = mac.finalize().into_bytes();
    let mut raw_hash = [0u8; 32];
    raw_hash.copy_from_slice(&pbkdf2_block[..32]);
    pbkdf2_block.as_mut_slice().zeroize();

    // Reduce mod BN254_P (matches Python: int.from_bytes(raw, "big") % BN254_P)
    let n = BigUint::from_bytes_be(&raw_hash);
    raw_hash.zeroize();
    let p =
        BigUint::parse_bytes(BN254_P_DECIMAL.as_bytes(), 10).expect("BN254_P constant is valid");
    let reduced = n % p;

    // Convert to 32-byte big-endian, zero-padded on the left
    let be_bytes = reduced.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    out
}

/// Convenience: derive a note sk and return it as a hex string
/// prefixed with "0x", suitable for JSON input to solve_witness.
pub fn derive_note_sk_hex(master_seed: &[u8], note_index: u64) -> String {
    let mut sk = derive_note_sk(master_seed, note_index);
    let mut hex = String::with_capacity(2 + 64);
    hex.push_str("0x");
    for byte in &sk {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    sk.zeroize();
    hex
}

/// Noir compiler versions known to produce wire-compatible witness.gz for
/// this version of tonkl-prover. Update when you've re-verified
/// byte-for-byte compatibility via `scripts/diff_witness_formats.py` or
/// `tests/witness_compatibility.rs`.
pub const SUPPORTED_NOIR_VERSIONS: &[&str] = &["1.0.0-beta.20"];

/// The output of `solve_witness`: one (witness_index, field_bytes) pair
/// per ACVM witness variable, sorted by index (since WitnessMap wraps a
/// BTreeMap internally).
#[derive(Debug)]
pub struct SolvedWitness {
    pub entries: Vec<(u32, [u8; 32])>,
}

/// Full solve path: JSON inputs + compiled circuit → solved witness entries.
///
/// Steps:
///   1. Parse circuit JSON artifact + inputs JSON.
///   2. Verify the circuit's `noir_version` is in `SUPPORTED_NOIR_VERSIONS`.
///   3. Deserialize ACIR bytecode, parse ABI.
///   4. Build InputMap from JSON + ABI, encode to initial WitnessMap.
///   5. Solve via ACVM with `Bn254BlackBoxSolver` (Poseidon2, MSM, etc.).
///   6. Convert solved `WitnessMap<FieldElement>` to `Vec<(u32, [u8; 32])>`.
pub fn solve_witness(circuit_json: &str, inputs_json: &str) -> Result<SolvedWitness> {
    let json_map: BTreeMap<String, Value> =
        serde_json::from_str(inputs_json).map_err(|e| format!("Invalid inputs JSON: {e}"))?;

    let artifact: Value =
        serde_json::from_str(circuit_json).map_err(|e| format!("Invalid circuit JSON: {e}"))?;

    verify_noir_version(&artifact)?;

    let bytecode_b64 = artifact["bytecode"]
        .as_str()
        .ok_or_else(|| "No 'bytecode' field in circuit JSON".to_string())?;
    let bytecode_bytes = BASE64
        .decode(bytecode_b64)
        .map_err(|e| format!("Invalid base64 bytecode: {e}"))?;

    let program: Program<FieldElement> = Program::deserialize_program(&bytecode_bytes)
        .map_err(|e| format!("Failed to deserialize ACIR program: {e}"))?;

    let abi: Abi = serde_json::from_value(artifact["abi"].clone())
        .map_err(|e| format!("Failed to parse ABI: {e}"))?;

    eprintln!(
        "[tonkl-prover] Circuit loaded: {} opcodes, {} ABI params",
        program.functions[0].opcodes.len(),
        abi.parameters.len()
    );

    // Build InputMap from JSON in ABI parameter order.
    let mut input_map: BTreeMap<String, InputValue> = BTreeMap::new();
    for param in &abi.parameters {
        let name = &param.name;
        let json_val = json_map
            .get(name.as_str())
            .ok_or_else(|| format!("Missing input: '{name}'"))?;
        let input_value = json_to_input_value(json_val, name)?;
        input_map.insert(name.clone(), input_value);
    }

    let initial_witness = abi
        .encode(&input_map, None)
        .map_err(|e| format!("ABI encoding failed: {e}"))?;
    drop(input_map);

    let initial_count = initial_witness.clone().into_iter().count();
    eprintln!("[tonkl-prover] Witness map built ({initial_count} initial entries)");

    // ── Solve via ACVM ──────────────────────────────────────────────────
    let circuit = &program.functions[0];
    let blackbox_solver = Bn254BlackBoxSolver::default();
    let mut acvm = ACVM::new(
        &blackbox_solver,
        &circuit.opcodes,
        initial_witness,
        &program.unconstrained_functions,
        &[],
    );

    match acvm.solve() {
        acvm::pwg::ACVMStatus::Solved => {
            eprintln!("[tonkl-prover] ACVM: witness solved successfully");
        }
        acvm::pwg::ACVMStatus::InProgress => {
            return Err("ACVM: solver returned InProgress (unexpected)".to_string());
        }
        acvm::pwg::ACVMStatus::Failure(err) => {
            return Err(format!("ACVM solve failed: {err}"));
        }
        acvm::pwg::ACVMStatus::RequiresForeignCall(_) => {
            return Err("ACVM requires foreign call (oracle) — not supported".to_string());
        }
        acvm::pwg::ACVMStatus::RequiresAcirCall(_) => {
            return Err("ACVM requires ACIR call (recursion) — not supported".to_string());
        }
    }

    let solved: WitnessMap<FieldElement> = acvm.finalize();
    let entries: Vec<(u32, [u8; 32])> = solved
        .into_iter()
        .map(|(witness, field)| (witness.0, fe_to_be_32(&field)))
        .collect();
    eprintln!(
        "[tonkl-prover] Witness finalized ({} entries)",
        entries.len()
    );

    Ok(SolvedWitness { entries })
}

// ── Witness serialization ───────────────────────────────────────────────

/// Convert an acvm `FieldElement` to exactly 32 big-endian bytes.
/// `to_be_bytes()` may return fewer bytes for small values; this pads.
pub fn fe_to_be_32(field: &FieldElement) -> [u8; 32] {
    let be = field.to_be_bytes();
    let mut out = [0u8; 32];
    if be.len() >= 32 {
        out.copy_from_slice(&be[be.len() - 32..]);
    } else {
        out[32 - be.len()..].copy_from_slice(&be);
    }
    out
}

/// Serialize a single-item WitnessStack to the exact msgpack wire format
/// `bb prove` expects. Confirmed byte-exact against nargo beta.20 via
/// `scripts/diff_witness_formats.py` and `tests/witness_compatibility.rs`.
///
/// Wire layout:
///
/// ```text
///   03                               FORMAT_MSGPACK_COMPACT
///   91                               fixarray[1]  (WitnessStack)
///     91                             fixarray[1]  (Vec<StackItem>)
///       92                           fixarray[2]  (StackItem)
///         00                         StackItem.index = 0
///         <map header: fixmap|de|df> WitnessMap
///           <uint>                     witness index
///           c4 20 <32 raw bytes>       field element (msgpack bin8, len=32)
///           ...
/// ```
pub fn serialize_witness_stack_msgpack(entries: &[(u32, [u8; 32])]) -> Vec<u8> {
    // 8-byte envelope + ~37 bytes per entry (worst case).
    let mut out = Vec::with_capacity(8 + entries.len() * 38);

    out.push(0x03); // format discriminator
    out.push(0x91); // WitnessStack
    out.push(0x91); // Vec<StackItem>
    out.push(0x92); // StackItem
    write_msgpack_uint(&mut out, 0); // StackItem.index = 0
    write_msgpack_map_header(&mut out, entries.len() as u32);

    for (idx, be) in entries {
        write_msgpack_uint(&mut out, *idx as u64);
        // bin8: 0xc4 <len:u8> <raw bytes>. Always 32 for BN254 field elements.
        out.push(0xc4);
        out.push(32);
        out.extend_from_slice(be);
    }
    out
}

// ── Msgpack primitive helpers (crate-private; exercised via tests) ─────

/// Write a msgpack unsigned integer in canonical (smallest) form.
fn write_msgpack_uint(buf: &mut Vec<u8>, v: u64) {
    if v <= 0x7F {
        buf.push(v as u8);
    } else if v <= 0xFF {
        buf.push(0xcc);
        buf.push(v as u8);
    } else if v <= 0xFFFF {
        buf.push(0xcd);
        buf.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xFFFF_FFFF {
        buf.push(0xce);
        buf.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        buf.push(0xcf);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

/// Write a msgpack map header for the given entry count.
fn write_msgpack_map_header(buf: &mut Vec<u8>, len: u32) {
    if len <= 0x0F {
        buf.push(0x80 | (len as u8));
    } else if len <= 0xFFFF {
        buf.push(0xde);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdf);
        buf.extend_from_slice(&len.to_be_bytes());
    }
}

// ── Verification ────────────────────────────────────────────────────────

/// Read the `noir_version` field from the circuit artifact and compare
/// against `SUPPORTED_NOIR_VERSIONS`. Returns Err on mismatch so the
/// caller can print a remediation message and exit.
pub fn verify_noir_version(artifact: &Value) -> Result<()> {
    let nv = artifact
        .get("noir_version")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    // `noir_version` is usually `"1.0.0-beta.20+<git-sha>"`. Strip the
    // "+..." suffix for matching.
    let base = nv.split('+').next().unwrap_or(nv);
    if !SUPPORTED_NOIR_VERSIONS.iter().any(|v| *v == base) {
        return Err(format!(
            "Unsupported noir version: {nv}\n  \
             This tonkl-prover was verified against: {}\n  \
             To add a new version:\n  \
                1. Update SUPPORTED_NOIR_VERSIONS in src/lib.rs\n  \
                2. Update the noir tag in Cargo.toml dependencies\n  \
                3. Run scripts/diff_witness_formats.py + cargo test to\n     \
                    verify byte-exact witness compatibility",
            SUPPORTED_NOIR_VERSIONS.join(", ")
        ));
    }
    Ok(())
}

// ── Input parsing ───────────────────────────────────────────────────────

/// Convert a serde_json::Value to a noirc_abi InputValue.
pub fn json_to_input_value(v: &Value, name: &str) -> Result<InputValue> {
    match v {
        Value::String(s) => Ok(InputValue::Field(str_to_field(s, name)?)),
        Value::Number(n) => {
            let s = n.to_string();
            Ok(InputValue::Field(str_to_field(&s, name)?))
        }
        Value::Bool(b) => {
            // [bool; N] ABI parameters: map to Field(0) / Field(1)
            Ok(InputValue::Field(FieldElement::from(if *b {
                1u128
            } else {
                0u128
            })))
        }
        Value::Array(arr) => {
            let fields: Result<Vec<InputValue>> = arr
                .iter()
                .enumerate()
                .map(|(i, item)| json_to_input_value(item, &format!("{name}[{i}]")))
                .collect();
            Ok(InputValue::Vec(fields?))
        }
        other => Err(format!("Unsupported JSON type for '{name}': {other:?}")),
    }
}

/// Parse a string to a FieldElement.
///
/// Supports:
///   - Hex strings starting with "0x"
///   - Decimal integer strings
///   - Boolean literals "true"/"false" (mapped to Field 1/0) — needed for
///     `[bool; N]` ABI parameters since beta.20 removed the u1 type.
pub fn str_to_field(s: &str, name: &str) -> Result<FieldElement> {
    let trimmed = s.trim();

    match trimmed {
        "true" | "True" | "TRUE" => return Ok(FieldElement::from(1u128)),
        "false" | "False" | "FALSE" => return Ok(FieldElement::from(0u128)),
        _ => {}
    }

    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        FieldElement::from_hex(trimmed)
            .ok_or_else(|| format!("Cannot parse '{name}' hex value '{trimmed}' as field"))
    } else {
        match trimmed.parse::<u128>() {
            Ok(n) => Ok(FieldElement::from(n)),
            Err(_) => {
                let big = trimmed
                    .parse::<BigUint>()
                    .map_err(|e| format!("Cannot parse '{name}' value '{trimmed}': {e}"))?;
                let hex_str = format!("0x{}", big.to_str_radix(16));
                FieldElement::from_hex(&hex_str).ok_or_else(|| {
                    format!("Decimal value '{trimmed}' for '{name}' overflows BN254 field")
                })
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── write_msgpack_uint canonical forms ──────────────────────────────

    #[test]
    fn uint_fixint_boundary() {
        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0);
        assert_eq!(b, vec![0x00]);

        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0x7F);
        assert_eq!(b, vec![0x7F]);
    }

    #[test]
    fn uint_uint8_boundary() {
        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0x80);
        assert_eq!(b, vec![0xcc, 0x80]);

        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0xFF);
        assert_eq!(b, vec![0xcc, 0xFF]);
    }

    #[test]
    fn uint_uint16_boundary() {
        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0x100);
        assert_eq!(b, vec![0xcd, 0x01, 0x00]);

        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0xFFFF);
        assert_eq!(b, vec![0xcd, 0xFF, 0xFF]);
    }

    #[test]
    fn uint_uint32_boundary() {
        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0x1_0000);
        assert_eq!(b, vec![0xce, 0x00, 0x01, 0x00, 0x00]);

        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0xFFFF_FFFF);
        assert_eq!(b, vec![0xce, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn uint_uint64_boundary() {
        let mut b = Vec::new();
        write_msgpack_uint(&mut b, 0x1_0000_0000);
        assert_eq!(
            b,
            vec![0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    // ── write_msgpack_map_header canonical forms ────────────────────────

    #[test]
    fn map_fixmap_form() {
        let mut b = Vec::new();
        write_msgpack_map_header(&mut b, 0);
        assert_eq!(b, vec![0x80]);

        let mut b = Vec::new();
        write_msgpack_map_header(&mut b, 0x0F);
        assert_eq!(b, vec![0x8F]);
    }

    #[test]
    fn map_map16_form() {
        let mut b = Vec::new();
        write_msgpack_map_header(&mut b, 0x10);
        assert_eq!(b, vec![0xde, 0x00, 0x10]);

        // 851 entries — the value we see in the real transfer circuit.
        let mut b = Vec::new();
        write_msgpack_map_header(&mut b, 851);
        assert_eq!(b, vec![0xde, 0x03, 0x53]);
    }

    #[test]
    fn map_map32_form() {
        let mut b = Vec::new();
        write_msgpack_map_header(&mut b, 0x1_0000);
        assert_eq!(b, vec![0xdf, 0x00, 0x01, 0x00, 0x00]);
    }

    // ── serialize_witness_stack_msgpack: envelope + entries ─────────────

    #[test]
    fn serialize_empty_witness() {
        let out = serialize_witness_stack_msgpack(&[]);
        assert_eq!(out, vec![0x03, 0x91, 0x91, 0x92, 0x00, 0x80]);
    }

    #[test]
    fn serialize_single_entry_small_fe() {
        let mut fe = [0u8; 32];
        fe[31] = 1;
        let out = serialize_witness_stack_msgpack(&[(0, fe)]);

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x03, 0x91, 0x91, 0x92, 0x00]);
        expected.push(0x81); // fixmap[1]
        expected.push(0x00); // key: witness index 0
        expected.push(0xc4); // bin8
        expected.push(0x20); // length 32
        expected.extend_from_slice(&fe);
        assert_eq!(out, expected);
    }

    #[test]
    fn serialize_fe_with_high_bytes_uses_bin8_not_array() {
        // Regression test. Every FE byte ≥ 0x80 MUST pass through unchanged —
        // NOT wrapped in `cc XX`. If this regresses, bb prove rejects the
        // witness with "error converting into newtype 'WitnessMap'".
        let fe = [0xFFu8; 32];
        let out = serialize_witness_stack_msgpack(&[(0, fe)]);

        let tail = &out[out.len() - 34..];
        assert_eq!(tail[0], 0xc4);
        assert_eq!(tail[1], 0x20);
        assert!(
            tail[2..].iter().all(|&b| b == 0xFF),
            "FE bytes were not passed through raw: got {tail:02x?}"
        );
        // envelope(5) + fixmap(1) + idx(1) + bin-header(2) + payload(32) = 41.
        // Double-encoding would inflate this to ~73.
        assert_eq!(
            out.len(),
            41,
            "double-encoding regression — output is too long"
        );
    }

    #[test]
    fn serialize_851_entries_matches_reference_prefix() {
        let entries: Vec<(u32, [u8; 32])> = (0..851u32).map(|i| (i, [0u8; 32])).collect();
        let out = serialize_witness_stack_msgpack(&entries);
        assert_eq!(
            &out[..12],
            &[0x03, 0x91, 0x91, 0x92, 0x00, 0xde, 0x03, 0x53, 0x00, 0xc4, 0x20, 0x00]
        );
    }

    #[test]
    fn serialize_idx_crosses_fixint_uint8_boundary() {
        // Index = 128 must become `cc 80` (uint8), not `80` (fixmap sigil!).
        let out = serialize_witness_stack_msgpack(&[(128, [0u8; 32])]);
        assert_eq!(out[5], 0x81); // fixmap[1]
        assert_eq!(out[6], 0xcc); // uint8 tag
        assert_eq!(out[7], 0x80); // value = 128
    }

    // ── fe_to_be_32 padding ─────────────────────────────────────────────

    #[test]
    fn fe_zero_pads_to_32_bytes() {
        let fe = FieldElement::from(1u128);
        let be = fe_to_be_32(&fe);
        assert_eq!(be.len(), 32);
        assert_eq!(be[31], 0x01);
        assert!(be[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn fe_roundtrip_via_hex() {
        let fe = FieldElement::from_hex("0x2b0bcc").unwrap();
        let be = fe_to_be_32(&fe);
        assert_eq!(be[29..], [0x2b, 0x0b, 0xcc]);
        assert!(be[..29].iter().all(|&b| b == 0));
    }

    // ── verify_noir_version: accept & reject paths ──────────────────────

    #[test]
    fn verify_noir_version_accepts_pinned() {
        let art = serde_json::json!({
            "noir_version": "1.0.0-beta.20+abc123"
        });
        assert!(verify_noir_version(&art).is_ok());
    }

    #[test]
    fn verify_noir_version_rejects_unpinned() {
        let art = serde_json::json!({
            "noir_version": "1.0.0-beta.21"
        });
        let err = verify_noir_version(&art).unwrap_err();
        assert!(err.contains("Unsupported noir version"));
        assert!(err.contains("1.0.0-beta.21"));
    }

    // ── str_to_field: boundary cases ────────────────────────────────────

    #[test]
    fn str_to_field_bool_literals() {
        assert_eq!(
            str_to_field("true", "t").unwrap(),
            FieldElement::from(1u128)
        );
        assert_eq!(
            str_to_field("false", "f").unwrap(),
            FieldElement::from(0u128)
        );
    }

    #[test]
    fn str_to_field_hex_and_decimal() {
        let a = str_to_field("0x2b", "x").unwrap();
        let b = str_to_field("43", "x").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn str_to_field_big_decimal() {
        // Value > u128 range, should fall through to BigUint path.
        let big = "21888242871839275222246405745257275088548364400416034343698204186575808495615";
        let fe = str_to_field(big, "big").unwrap();
        assert_eq!(fe_to_be_32(&fe)[0] >> 4, 0x3); // top nibble sanity check
    }

    // -- derive_note_sk: HD key derivation -----------------------------------

    #[test]
    fn derive_note_sk_is_deterministic() {
        let seed = [0xABu8; 64];
        let a = derive_note_sk(&seed, 0);
        let b = derive_note_sk(&seed, 0);
        assert_eq!(a, b, "same seed + index must produce same key");
    }

    #[test]
    fn derive_note_sk_different_indices_differ() {
        let seed = [0xABu8; 64];
        let a = derive_note_sk(&seed, 0);
        let b = derive_note_sk(&seed, 1);
        assert_ne!(a, b, "different indices must produce different keys");
    }

    #[test]
    fn derive_note_sk_different_seeds_differ() {
        let seed_a = [0xAAu8; 64];
        let seed_b = [0xBBu8; 64];
        let a = derive_note_sk(&seed_a, 0);
        let b = derive_note_sk(&seed_b, 0);
        assert_ne!(a, b, "different seeds must produce different keys");
    }

    #[test]
    fn derive_note_sk_is_32_bytes_and_less_than_p() {
        let seed = [0x42u8; 64];
        let sk = derive_note_sk(&seed, 99);
        assert_eq!(sk.len(), 32);

        // Verify sk < BN254_P by parsing both as BigUint
        let sk_int = BigUint::from_bytes_be(&sk);
        let p = BigUint::parse_bytes(BN254_P_DECIMAL.as_bytes(), 10).unwrap();
        assert!(sk_int < p, "derived sk must be reduced mod BN254_P");
    }

    #[test]
    fn derive_note_sk_hex_format() {
        let seed = [0x42u8; 64];
        let hex = derive_note_sk_hex(&seed, 0);
        assert!(hex.starts_with("0x"), "must start with 0x prefix");
        assert_eq!(hex.len(), 66, "0x + 64 hex chars = 66");
        // Verify all chars after 0x are valid hex
        assert!(
            hex[2..].chars().all(|c| c.is_ascii_hexdigit()),
            "must be valid hex"
        );
    }

    #[test]
    fn derive_note_sk_zero_seed_works() {
        // Edge case: all-zero seed should still produce a valid key
        let seed = [0u8; 64];
        let sk = derive_note_sk(&seed, 0);
        // Just verify it doesn't panic and produces 32 bytes
        assert_eq!(sk.len(), 32);
        // Should not be all zeros (PBKDF2-HMAC-SHA512 of non-empty input is non-zero)
        assert!(
            sk.iter().any(|&b| b != 0),
            "derived sk should not be all zeros"
        );
    }

    #[test]
    fn derive_note_sk_large_index() {
        // u64::MAX should work fine
        let seed = [0x42u8; 64];
        let sk = derive_note_sk(&seed, u64::MAX);
        assert_eq!(sk.len(), 32);
        // Should differ from index 0
        let sk0 = derive_note_sk(&seed, 0);
        assert_ne!(sk, sk0);
    }

    #[test]
    #[should_panic(expected = "master_seed must be exactly 64 bytes")]
    fn derive_note_sk_rejects_short_seed() {
        let short = [0u8; 32];
        derive_note_sk(&short, 0);
    }

    // -- Poseidon2 hash functions -----------------------------------------------

    #[test]
    fn poseidon2_hash_2_is_deterministic() {
        let a = FieldElement::from(42u128);
        let b = FieldElement::from(99u128);
        let h1 = poseidon2_hash_2(a, b).unwrap();
        let h2 = poseidon2_hash_2(a, b).unwrap();
        assert_eq!(h1, h2, "hash_2 must be deterministic");
    }

    #[test]
    fn poseidon2_hash_2_different_inputs_differ() {
        let h1 = poseidon2_hash_2(FieldElement::from(1u128), FieldElement::from(2u128)).unwrap();
        let h2 = poseidon2_hash_2(FieldElement::from(1u128), FieldElement::from(3u128)).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn poseidon2_hash_3_is_deterministic() {
        let h1 = poseidon2_hash_3(
            FieldElement::from(1u128),
            FieldElement::from(2u128),
            FieldElement::from(3u128),
        )
        .unwrap();
        let h2 = poseidon2_hash_3(
            FieldElement::from(1u128),
            FieldElement::from(2u128),
            FieldElement::from(3u128),
        )
        .unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon2_hash_7_is_deterministic() {
        let h1 = poseidon2_hash_7(
            FieldElement::from(1u128),
            FieldElement::from(2u128),
            FieldElement::from(3u128),
            FieldElement::from(4u128),
            FieldElement::from(5u128),
            FieldElement::from(6u128),
            FieldElement::from(7u128),
        )
        .unwrap();
        let h2 = poseidon2_hash_7(
            FieldElement::from(1u128),
            FieldElement::from(2u128),
            FieldElement::from(3u128),
            FieldElement::from(4u128),
            FieldElement::from(5u128),
            FieldElement::from(6u128),
            FieldElement::from(7u128),
        )
        .unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn commitment_and_nullifier_domain_separation() {
        // Commitment and nullifier of the same note must differ
        // (they use different domain constants and hash arities).
        let note = NoteFields {
            value: FieldElement::from(100u128),
            asset_id: FieldElement::from(1u128),
            owner_pk_x: FieldElement::from(42u128),
            owner_pk_y: FieldElement::from(99u128),
            rho: FieldElement::from(12345u128),
        };
        let cm = note_commitment(&note).unwrap();
        let sk = FieldElement::from(9999u128);
        let nf = note_nullifier(cm, sk).unwrap();
        assert_ne!(cm, nf, "commitment and nullifier must differ");
    }

    #[test]
    fn note_commitment_is_deterministic() {
        let note = NoteFields {
            value: FieldElement::from(100u128),
            asset_id: FieldElement::from(1u128),
            owner_pk_x: FieldElement::from(42u128),
            owner_pk_y: FieldElement::from(99u128),
            rho: FieldElement::from(12345u128),
        };
        let cm1 = note_commitment(&note).unwrap();
        let cm2 = note_commitment(&note).unwrap();
        assert_eq!(cm1, cm2);
    }

    #[test]
    fn different_rho_yields_different_commitment() {
        let note_a = NoteFields {
            value: FieldElement::from(100u128),
            asset_id: FieldElement::from(1u128),
            owner_pk_x: FieldElement::from(42u128),
            owner_pk_y: FieldElement::from(99u128),
            rho: FieldElement::from(1u128),
        };
        let note_b = NoteFields {
            value: FieldElement::from(100u128),
            asset_id: FieldElement::from(1u128),
            owner_pk_x: FieldElement::from(42u128),
            owner_pk_y: FieldElement::from(99u128),
            rho: FieldElement::from(2u128),
        };
        assert_ne!(
            note_commitment(&note_a).unwrap(),
            note_commitment(&note_b).unwrap(),
        );
    }

    #[test]
    fn wallet_derive_pk_is_deterministic() {
        let sk = FieldElement::from(0xdeadbeefu128);
        let (x1, y1) = wallet_derive_pk(sk).unwrap();
        let (x2, y2) = wallet_derive_pk(sk).unwrap();
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn wallet_derive_pk_different_sk_differ() {
        let (x1, _) = wallet_derive_pk(FieldElement::from(1u128)).unwrap();
        let (x2, _) = wallet_derive_pk(FieldElement::from(2u128)).unwrap();
        assert_ne!(x1, x2);
    }

    #[test]
    fn wallet_derive_pk_sk1_is_generator() {
        // 1 * G = G, so pk for sk=1 should be the Grumpkin generator itself.
        let (x, y) = wallet_derive_pk(FieldElement::from(1u128)).unwrap();
        assert_eq!(x, FieldElement::from(1u128));
        assert_eq!(
            y,
            FieldElement::from_hex(
                "0x0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c"
            )
            .unwrap()
        );
    }

    // -- Cross-language parity (pinned against Python tonkl_wallet.py) --
    // Generated by scripts/generate_hd_test_vectors.py using the wallet's
    // PBKDF2-HMAC-SHA512 derivation.

    #[test]
    fn derive_note_sk_cross_language_parity() {
        // all-0xAB seed, index 0
        assert_eq!(
            derive_note_sk(&[0xABu8; 64], 0),
            [
                0x0a, 0xbf, 0x9e, 0x88, 0x7e, 0x41, 0xb3, 0xe0,
                0x01, 0xcf, 0x16, 0xb0, 0x7a, 0x15, 0xdd, 0x0d,
                0xfa, 0x4c, 0x13, 0xf4, 0x45, 0x68, 0xc0, 0xb7,
                0x01, 0x4c, 0x98, 0xf0, 0x5b, 0x78, 0xa8, 0xc3,
            ]
        );
        // all-0xAB seed, index 1
        assert_eq!(
            derive_note_sk(&[0xABu8; 64], 1),
            [
                0x0e, 0x86, 0xcc, 0x4c, 0x71, 0x45, 0x79, 0x67,
                0x1d, 0xc3, 0x81, 0x84, 0x87, 0x6c, 0x06, 0x88,
                0x2d, 0xdb, 0x49, 0xd0, 0x8f, 0x27, 0x16, 0x17,
                0x85, 0xee, 0x18, 0x84, 0x6b, 0x2c, 0x9f, 0xaa,
            ]
        );
        // all-0x42 seed, index 0
        assert_eq!(
            derive_note_sk(&[0x42u8; 64], 0),
            [
                0x1d, 0xc3, 0x8b, 0x40, 0x38, 0xf2, 0xd0, 0xa7,
                0x40, 0x88, 0xb8, 0x28, 0x9a, 0x9a, 0x97, 0x1d,
                0x54, 0x2a, 0xa2, 0xe6, 0x12, 0x89, 0x28, 0x23,
                0x99, 0x09, 0x39, 0x49, 0x78, 0x52, 0xa3, 0x53,
            ]
        );
        // all-0x42 seed, index 99
        assert_eq!(
            derive_note_sk(&[0x42u8; 64], 99),
            [
                0x14, 0xad, 0x18, 0xf3, 0x52, 0x7e, 0x7f, 0x41,
                0x2e, 0xd5, 0xc0, 0x3c, 0x98, 0xe3, 0x23, 0xd7,
                0x16, 0x50, 0xc9, 0x26, 0x58, 0x8c, 0xe1, 0xf3,
                0x44, 0xa3, 0x9a, 0xff, 0xd0, 0x40, 0x18, 0x81,
            ]
        );
        // all-zero seed, index 0
        assert_eq!(
            derive_note_sk(&[0x00u8; 64], 0),
            [
                0x28, 0x6f, 0xc5, 0x81, 0xe7, 0xbe, 0xca, 0x03,
                0x43, 0x19, 0x22, 0x96, 0x3c, 0xf9, 0x71, 0x28,
                0x8c, 0xd6, 0x0a, 0xa1, 0xf7, 0x74, 0xf4, 0xfa,
                0xca, 0x48, 0xf2, 0xdb, 0x1e, 0xec, 0x8a, 0x2b,
            ]
        );
    }

    // -- Merkle tree builder -------------------------------------------------------

    #[test]
    fn build_tree_single_leaf() {
        // Single leaf at position 0, rest empty.
        // Root = hash(hash(hash(...hash(leaf, 0)..., 0), 0), 0)
        let leaf = FieldElement::from(42u128);
        let result = build_merkle_tree(&[leaf]).unwrap();

        // Verify root matches compute_merkle_root with all-zero path
        let bits = [false; 32];
        let path = [FieldElement::zero(); 32];
        let expected_root = compute_merkle_root(leaf, &bits, &path).unwrap();
        assert_eq!(result.root, expected_root);

        // Path should be all zeros (no siblings)
        assert_eq!(result.paths.len(), 1);
        assert!(result.paths[0]
            .siblings
            .iter()
            .all(|s| *s == FieldElement::zero()));
        assert!(result.paths[0].index_bits.iter().all(|b| !b));
    }

    #[test]
    fn build_tree_two_leaves() {
        // Two leaves at positions 0 and 1.
        let leaf_a = FieldElement::from(100u128);
        let leaf_b = FieldElement::from(200u128);
        let result = build_merkle_tree(&[leaf_a, leaf_b]).unwrap();

        // Both paths should produce the same root via compute_merkle_root
        let root_a = compute_merkle_root(
            leaf_a,
            &result.paths[0].index_bits,
            &result.paths[0].siblings,
        )
        .unwrap();
        let root_b = compute_merkle_root(
            leaf_b,
            &result.paths[1].index_bits,
            &result.paths[1].siblings,
        )
        .unwrap();
        assert_eq!(root_a, result.root);
        assert_eq!(root_b, result.root);

        // Leaf 0's sibling at level 0 should be leaf_b
        assert_eq!(result.paths[0].siblings[0], leaf_b);
        // Leaf 1's sibling at level 0 should be leaf_a
        assert_eq!(result.paths[1].siblings[0], leaf_a);
    }

    #[test]
    fn build_tree_four_leaves_matches_merge_circuit() {
        // Mirror the merge circuit test: 4 notes at positions 0-3.
        // Use simple field values as leaf commitments.
        let leaves = [
            FieldElement::from(1000u128),
            FieldElement::from(2000u128),
            FieldElement::from(3000u128),
            FieldElement::from(4000u128),
        ];
        let result = build_merkle_tree(&leaves).unwrap();

        // Every leaf's path must produce the same root
        for (i, leaf) in leaves.iter().enumerate() {
            let computed = compute_merkle_root(
                *leaf,
                &result.paths[i].index_bits,
                &result.paths[i].siblings,
            )
            .unwrap();
            assert_eq!(
                computed, result.root,
                "Leaf {i} path does not reproduce the tree root"
            );
        }

        // Cross-check tree structure manually:
        // h01 = hash(leaves[0], leaves[1])
        // h23 = hash(leaves[2], leaves[3])
        let h01 = poseidon2_hash_2(leaves[0], leaves[1]).unwrap();
        let h23 = poseidon2_hash_2(leaves[2], leaves[3]).unwrap();

        // Leaf 0 siblings: [leaves[1], h23, 0, 0, ...]
        assert_eq!(result.paths[0].siblings[0], leaves[1]);
        assert_eq!(result.paths[0].siblings[1], h23);
        assert!(result.paths[0].siblings[2..]
            .iter()
            .all(|s| *s == FieldElement::zero()));

        // Leaf 2 siblings: [leaves[3], h01, 0, 0, ...]
        assert_eq!(result.paths[2].siblings[0], leaves[3]);
        assert_eq!(result.paths[2].siblings[1], h01);
    }

    #[test]
    fn build_tree_empty() {
        let result = build_merkle_tree(&[]).unwrap();
        assert_eq!(result.root, FieldElement::zero());
        assert!(result.paths.is_empty());
    }
}
