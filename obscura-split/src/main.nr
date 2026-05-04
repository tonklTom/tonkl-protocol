// Obscura Protocol - Split Circuit (1-in / 32-out, multi-recipient, production)
//
// Proves a valid split of one input note into up to 32 output notes, where
// each output can be owned by a different recipient. This is the multi-send
// primitive: distribute value from a single high-value note to multiple
// parties in one atomic operation.
//
// Zero-knowledge statement:
//   "I know a note in the current note tree (merkle_root), I own it
//    (owner_sk matches the note's registered pk), and I am creating
//    32 output notes whose values sum to the input value minus the fee.
//    Each output note is owned by its specified recipient."
//
// On-chain footprint per proof (public inputs, 36 field elements):
//   merkle_root, nf, cm_outs[32], fee, asset_id
//
// Design notes:
//   - The input note must be owned by owner_sk (verified via
//     assert_ownership). Only the spender needs to know sk.
//   - Each output can have a DIFFERENT owner public key, enabling
//     multi-recipient sends. The sender specifies (pk_x, pk_y) for
//     each recipient -- they do NOT need to know the recipients' sk.
//   - For self-splits (breaking your own note into smaller pieces),
//     derive all output pks from your own sk off-circuit and pass them in.
//   - For splits to fewer than 32 recipients, pad remaining outputs with
//     zero-value notes owned by the sender. This avoids leaking the
//     actual recipient count.
//
// Whitepaper refs:
//   Section 7.5 - Enforced output templates (1-in/32-out split)
//   Section 8.3 - Noir as unified circuit DSL
//   Section 8.6 - MVP Phase 1 circuit scope

use obscura_lib::note::{Note, commitment, nullifier, assert_value_range, assert_ownership, derive_pk};
use obscura_lib::merkle::compute_root;

fn main(
    // PUBLIC INPUTS
    merkle_root: pub Field,
    nf: pub Field,
    cm_outs: pub [Field; 32],
    fee: pub Field,
    asset_id: pub Field,

    // PRIVATE: Input note
    owner_sk: Field,
    in_value: Field,
    in_rho: Field,
    in_merkle_bits: [bool; 32],
    in_merkle_path: [Field; 32],

    // PRIVATE: Output notes (32)
    out_values: [Field; 32],
    out_pk_xs: [Field; 32],
    out_pk_ys: [Field; 32],
    out_rhos: [Field; 32],
) {
    // STEP 1: INPUT NOTE VERIFICATION
    // Derive sender's pk, construct the input note, verify it exists
    // in the tree, and verify the sender owns it.
    let (sender_pk_x, sender_pk_y) = derive_pk(owner_sk);

    let input_note = Note {
        value: in_value,
        asset_id,
        owner_pk_x: sender_pk_x,
        owner_pk_y: sender_pk_y,
        rho: in_rho,
    };
    let cm_in = commitment(input_note);

    // Merkle membership
    let root = compute_root(cm_in, in_merkle_bits, in_merkle_path);
    assert(root == merkle_root, "Input note not in tree");

    // Ownership
    assert_ownership(input_note, owner_sk);

    // Nullifier
    let computed_nf = nullifier(cm_in, owner_sk);
    assert(computed_nf == nf, "Nullifier mismatch");

    // STEP 2: VALUE RANGE CHECKS
    // Prevent BN254 field wraparound attacks on all values.
    assert_value_range(in_value);
    assert_value_range(fee);
    for i in 0..32 {
        assert_value_range(out_values[i]);
    }

    // STEP 3: OUTPUT NOTE CONSTRUCTION & COMMITMENT BINDING
    // Each output note has its own recipient pk. The sender specifies
    // the recipient's public key -- no sk needed for the recipient.
    let mut total_out: Field = 0;
    for i in 0..32 {
        let note_out_i = Note {
            value: out_values[i],
            asset_id,
            owner_pk_x: out_pk_xs[i],
            owner_pk_y: out_pk_ys[i],
            rho: out_rhos[i],
        };
        let computed_cm_i = commitment(note_out_i);
        assert(computed_cm_i == cm_outs[i], "Output commitment mismatch");

        total_out += out_values[i];
    }

    // STEP 4: OUTPUT COMMITMENT UNIQUENESS
    // All 32 output commitments must be distinct to prevent replay.
    // C(32,2) = 496 pairwise checks.
    for i in 0..32 {
        for j in 0..32 {
            if j > i {
                assert(cm_outs[i] != cm_outs[j], "Duplicate output commitment");
            }
        }
    }

    // STEP 5: VALUE CONSERVATION
    // Input value must equal sum of all outputs plus fee.
    assert(in_value == total_out + fee, "Value conservation violated");
}

// ---------------------------------------------------------------------------
// TEST SUITE
// ---------------------------------------------------------------------------

struct SplitTestWitness {
    merkle_root: Field,
    nf: Field,
    cm_outs: [Field; 32],
    fee: Field,
    asset_id: Field,
    owner_sk: Field,
    in_value: Field,
    in_rho: Field,
    in_merkle_bits: [bool; 32],
    in_merkle_path: [Field; 32],
    out_values: [Field; 32],
    out_pk_xs: [Field; 32],
    out_pk_ys: [Field; 32],
    out_rhos: [Field; 32],
}

fn call_split(w: SplitTestWitness) {
    main(
        w.merkle_root,
        w.nf,
        w.cm_outs,
        w.fee,
        w.asset_id,
        w.owner_sk,
        w.in_value,
        w.in_rho,
        w.in_merkle_bits,
        w.in_merkle_path,
        w.out_values,
        w.out_pk_xs,
        w.out_pk_ys,
        w.out_rhos,
    );
}

// Build a valid multi-recipient split witness.
// Input: 1000 units owned by sender_sk
// 4 real outputs (400, 300, 200, 100) to different recipients,
// 28 zero-value padding outputs back to sender.
// Fee: 0
fn build_valid_split_witness() -> SplitTestWitness {
    let sender_sk: Field = 0xae0901;
    let (sender_pk_x, sender_pk_y) = derive_pk(sender_sk);
    let asset_id: Field = 1;

    // Input note: 1000 units owned by sender
    let in_value: Field = 1000;
    let in_rho: Field = 7001;
    let input_note = Note {
        value: in_value, asset_id,
        owner_pk_x: sender_pk_x, owner_pk_y: sender_pk_y,
        rho: in_rho,
    };
    let cm_in = commitment(input_note);

    // Sparse Merkle tree: single leaf at position 0
    let bits: [bool; 32] = [false; 32];
    let path: [Field; 32] = [0; 32];
    let merkle_root = compute_root(cm_in, bits, path);

    // Nullifier
    let nf = nullifier(cm_in, sender_sk);

    // 3 distinct recipients + sender for change
    let recipient_a_sk: Field = 0xaaaa01;
    let recipient_b_sk: Field = 0xbbbb02;
    let recipient_c_sk: Field = 0xcccc03;
    let (a_pk_x, a_pk_y) = derive_pk(recipient_a_sk);
    let (b_pk_x, b_pk_y) = derive_pk(recipient_b_sk);
    let (c_pk_x, c_pk_y) = derive_pk(recipient_c_sk);

    // Output values: 4 real + 28 zero-value padding
    let mut out_values: [Field; 32] = [0; 32];
    out_values[0] = 400;  // to recipient A
    out_values[1] = 300;  // to recipient B
    out_values[2] = 200;  // to recipient C
    out_values[3] = 100;  // change to sender

    // Output public keys: first 3 are recipients, rest are sender
    let mut out_pk_xs: [Field; 32] = [0; 32];
    let mut out_pk_ys: [Field; 32] = [0; 32];
    out_pk_xs[0] = a_pk_x; out_pk_ys[0] = a_pk_y;
    out_pk_xs[1] = b_pk_x; out_pk_ys[1] = b_pk_y;
    out_pk_xs[2] = c_pk_x; out_pk_ys[2] = c_pk_y;
    // Outputs 3-31: all owned by sender
    for i in 3..32 {
        out_pk_xs[i] = sender_pk_x;
        out_pk_ys[i] = sender_pk_y;
    }

    // Distinct rhos for all 32 outputs
    let mut out_rhos: [Field; 32] = [0; 32];
    for i in 0..32 {
        out_rhos[i] = 8001 + (i as Field);
    }

    // Compute all 32 output commitments
    let mut cm_outs: [Field; 32] = [0; 32];
    for i in 0..32 {
        let note_i = Note {
            value: out_values[i],
            asset_id,
            owner_pk_x: out_pk_xs[i],
            owner_pk_y: out_pk_ys[i],
            rho: out_rhos[i],
        };
        cm_outs[i] = commitment(note_i);
    }

    SplitTestWitness {
        merkle_root,
        nf,
        cm_outs,
        fee: 0,
        asset_id,
        owner_sk: sender_sk,
        in_value,
        in_rho,
        in_merkle_bits: bits,
        in_merkle_path: path,
        out_values,
        out_pk_xs,
        out_pk_ys,
        out_rhos,
    }
}

// --- Positive tests ---

#[test]
fn test_valid_split_passes() {
    let w = build_valid_split_witness();
    call_split(w);
}

#[test]
fn test_split_with_fee() {
    let mut w = build_valid_split_witness();
    // Fee = 50, reduce change output (3) from 100 to 50
    w.fee = 50;
    w.out_values[3] = 50;
    // Recompute output 3 commitment
    let note_3 = Note {
        value: 50, asset_id: w.asset_id,
        owner_pk_x: w.out_pk_xs[3], owner_pk_y: w.out_pk_ys[3],
        rho: w.out_rhos[3],
    };
    w.cm_outs[3] = commitment(note_3);
    call_split(w);
}

#[test]
fn test_self_split() {
    // All 32 outputs go back to sender (denomination splitting)
    let sender_sk: Field = 0xae0901;
    let (pk_x, pk_y) = derive_pk(sender_sk);
    let asset_id: Field = 1;

    let in_value: Field = 3200;
    let in_rho: Field = 7001;
    let input_note = Note {
        value: in_value, asset_id,
        owner_pk_x: pk_x, owner_pk_y: pk_y, rho: in_rho,
    };
    let cm_in = commitment(input_note);
    let bits: [bool; 32] = [false; 32];
    let path: [Field; 32] = [0; 32];
    let merkle_root = compute_root(cm_in, bits, path);
    let nf = nullifier(cm_in, sender_sk);

    // 32 outputs of 100 each, all to sender, distinct rhos
    let mut out_values: [Field; 32] = [0; 32];
    let mut out_pk_xs: [Field; 32] = [0; 32];
    let mut out_pk_ys: [Field; 32] = [0; 32];
    let mut out_rhos: [Field; 32] = [0; 32];
    let mut cm_outs: [Field; 32] = [0; 32];

    for i in 0..32 {
        out_values[i] = 100;
        out_pk_xs[i] = pk_x;
        out_pk_ys[i] = pk_y;
        out_rhos[i] = 9001 + (i as Field);
        let n = Note { value: 100, asset_id, owner_pk_x: pk_x, owner_pk_y: pk_y, rho: out_rhos[i] };
        cm_outs[i] = commitment(n);
    }

    let w = SplitTestWitness {
        merkle_root, nf, cm_outs,
        fee: 0, asset_id,
        owner_sk: sender_sk, in_value, in_rho,
        in_merkle_bits: bits, in_merkle_path: path,
        out_values, out_pk_xs, out_pk_ys, out_rhos,
    };
    call_split(w);
}

// --- Negative tests ---

#[test(should_fail_with = "Value conservation violated")]
fn test_reject_value_inflation() {
    let mut w = build_valid_split_witness();
    // Inflate output 0 from 400 to 500 (total = 1100 > 1000)
    w.out_values[0] = 500;
    let note_0 = Note {
        value: 500, asset_id: w.asset_id,
        owner_pk_x: w.out_pk_xs[0], owner_pk_y: w.out_pk_ys[0],
        rho: w.out_rhos[0],
    };
    w.cm_outs[0] = commitment(note_0);
    call_split(w);
}

#[test(should_fail_with = "Input note not in tree")]
fn test_reject_wrong_owner_sk() {
    let mut w = build_valid_split_witness();
    w.owner_sk = 0xbadbad;
    call_split(w);
}

#[test(should_fail_with = "Input note not in tree")]
fn test_reject_bad_merkle_path() {
    let mut w = build_valid_split_witness();
    w.in_merkle_path[3] = 999;
    call_split(w);
}

#[test(should_fail_with = "Nullifier mismatch")]
fn test_reject_wrong_nullifier() {
    let mut w = build_valid_split_witness();
    w.nf = w.nf + 1;
    call_split(w);
}

#[test(should_fail_with = "Output commitment mismatch")]
fn test_reject_output_commitment_tamper() {
    let mut w = build_valid_split_witness();
    w.cm_outs[0] = w.cm_outs[0] + 1;
    call_split(w);
}

#[test(should_fail_with = "Input note not in tree")]
fn test_reject_wrong_asset_id() {
    let mut w = build_valid_split_witness();
    w.asset_id = 99;
    call_split(w);
}

#[test(should_fail_with = "Duplicate output commitment")]
fn test_reject_duplicate_outputs() {
    let mut w = build_valid_split_witness();
    // Make output 1 identical to output 0
    w.out_values[1] = w.out_values[0];
    w.out_pk_xs[1] = w.out_pk_xs[0];
    w.out_pk_ys[1] = w.out_pk_ys[0];
    w.out_rhos[1] = w.out_rhos[0];
    w.cm_outs[1] = w.cm_outs[0];
    call_split(w);
}

#[test(should_fail)]
fn test_reject_overflow_value() {
    let mut w = build_valid_split_witness();
    w.in_value = 18446744073709551615 + 1;
    call_split(w);
}
