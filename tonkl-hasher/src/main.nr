// Tonkl Hash Oracle
//
// Computes all hash values needed for the transfer circuit's Prover.toml.
// Uses the same Poseidon2 sponge construction as tonkl-transfer/src/hash.nr.
//
// Phase 1b: now derives pk from sk for all notes using the same domain
// constants as the transfer circuit. Removing pk as an input eliminates
// any risk of mismatch between off-circuit pk generation and in-circuit
// pk derivation -- the only source of truth is the sk.
//
// Returns 15 values:
//   (merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2,
//    in1_pk_x, in1_pk_y, in2_pk_x, in2_pk_y,
//    out1_pk_x, out1_pk_y, out2_pk_x, out2_pk_y)

global NOTE_VERSION: Field     = 0;
global NULLIFIER_DOMAIN: Field = 1;
global COMMITMENT_DOMAIN: Field = 2;

use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

// --- Poseidon2 hash primitives (mirrors tonkl-transfer/src/hash.nr) ---
//
// Uses the Barretenberg poseidon2_permutation blackbox with t=4
// (state width 4, rate 3, capacity 1). This is the same construction
// as the transfer circuit -- hashes MUST match between the two circuits.

fn p2(state: [Field; 4]) -> [Field; 4] {
    std::hash::poseidon2_permutation(state)
}

fn hash_2(a: Field, b: Field) -> Field {
    let state = p2([a, b, 0, 0]);
    state[0]
}

fn hash_3(a: Field, b: Field, c: Field) -> Field {
    let state = p2([a, b, c, 0]);
    state[0]
}

fn hash_7(
    a: Field, b: Field, c: Field,
    d: Field, e: Field, f: Field,
    g: Field,
) -> Field {
    let s1 = p2([a, b, c, 0]);
    let s2 = p2([s1[0] + d, s1[1] + e, s1[2] + f, s1[3]]);
    let s3 = p2([s2[0] + g, s2[1], s2[2], s2[3]]);
    s3[0]
}

// --- Key derivation (matches tonkl-transfer/src/note.nr::derive_pk) ---
//
// pk = sk * G  (Grumpkin scalar multiplication)
// Must stay identical to the derive_pk in the transfer circuit.
fn derive_pk(sk: Field) -> (Field, Field) {
    let scalar = EmbeddedCurveScalar::from_field(sk);
    let pk = multi_scalar_mul([EmbeddedCurvePoint::generator()], [scalar]);
    (pk.x, pk.y)
}

// --- Note operations ---

fn note_commitment(value: Field, asset_id: Field, pk_x: Field, pk_y: Field, rho: Field) -> Field {
    hash_7(COMMITMENT_DOMAIN, NOTE_VERSION, value, asset_id, pk_x, pk_y, rho)
}

fn note_nullifier(cm: Field, owner_sk: Field) -> Field {
    hash_3(NULLIFIER_DOMAIN, cm, owner_sk)
}

// Merkle root using [bool; 32] bit array -- avoids u32 division opcodes.
// (beta.20: u1 type was removed, use bool instead.)
fn compute_merkle_root(leaf: Field, index_bits: [bool; 32], path: [Field; 32]) -> Field {
    let mut node = leaf;
    for i in 0..32 {
        if !index_bits[i] {
            node = hash_2(node, path[i]);
        } else {
            node = hash_2(path[i], node);
        }
    }
    node
}

// All note pk values are derived from sk inside this circuit.
// This eliminates any risk of mismatch between Python-generated pk and
// circuit-derived pk -- the sk is the single source of truth.
//
// For output notes, the caller generates a random sk for testing. In a real
// wallet, the recipient publishes their pk (derived from their sk externally);
// the sender would pass that pk directly. This oracle takes sk for uniformity.
//
// Returns 15 values:
//   (merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2,
//    in1_pk_x, in1_pk_y, in2_pk_x, in2_pk_y,
//    out1_pk_x, out1_pk_y, out2_pk_x, out2_pk_y)
fn main(
    in1_value: Field,  in1_asset_id: Field,  in1_rho: Field,  in1_sk: Field,
    in2_value: Field,  in2_asset_id: Field,  in2_rho: Field,  in2_sk: Field,
    out1_value: Field, out1_asset_id: Field, out1_rho: Field, out1_sk: Field,
    out2_value: Field, out2_asset_id: Field, out2_rho: Field, out2_sk: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field) {

    // Derive all public keys from their corresponding secret keys.
    // The transfer circuit enforces this same derivation via assert_ownership.
    let (in1_pk_x, in1_pk_y)   = derive_pk(in1_sk);
    let (in2_pk_x, in2_pk_y)   = derive_pk(in2_sk);
    let (out1_pk_x, out1_pk_y) = derive_pk(out1_sk);
    let (out2_pk_x, out2_pk_y) = derive_pk(out2_sk);

    let cm_in1 = note_commitment(in1_value, in1_asset_id, in1_pk_x, in1_pk_y, in1_rho);
    let cm_in2 = note_commitment(in2_value, in2_asset_id, in2_pk_x, in2_pk_y, in2_rho);

    // Note 0: all index bits are 0 (leftmost position)
    let bits_0: [bool; 32] = [false; 32];

    // Note 1: LSB = 1, rest = 0 (second position)
    let mut bits_1: [bool; 32] = [false; 32];
    bits_1[0] = true;

    // Sibling paths: each note's level-0 sibling is the other note's commitment.
    let mut path_for_0: [Field; 32] = [0; 32];
    path_for_0[0] = cm_in2;

    let mut path_for_1: [Field; 32] = [0; 32];
    path_for_1[0] = cm_in1;

    let merkle_root   = compute_merkle_root(cm_in1, bits_0, path_for_0);
    let merkle_root_2 = compute_merkle_root(cm_in2, bits_1, path_for_1);
    assert(merkle_root == merkle_root_2, "Merkle root mismatch");

    let nf_1 = note_nullifier(cm_in1, in1_sk);
    let nf_2 = note_nullifier(cm_in2, in2_sk);

    let cm_out_1 = note_commitment(out1_value, out1_asset_id, out1_pk_x, out1_pk_y, out1_rho);
    let cm_out_2 = note_commitment(out2_value, out2_asset_id, out2_pk_x, out2_pk_y, out2_rho);

    (
        merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2,
        in1_pk_x, in1_pk_y, in2_pk_x, in2_pk_y,
        out1_pk_x, out1_pk_y, out2_pk_x, out2_pk_y
    )
}
