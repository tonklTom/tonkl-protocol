// Tonkl Protocol - Transfer Circuit (MVP Phase 1)
//
// Proves a valid 2-input / 2-output shielded token transfer without
// revealing sender, receiver, amounts, or the link between inputs and outputs.
//
// Zero-knowledge statement:
//   "I know two notes that exist in the current note tree (merkle_root),
//    I have authority to spend them (owner_sk matches registered public key),
//    and I am creating two new notes such that no tokens are created or
//    destroyed."
//
// On-chain footprint per proof (public inputs only, 7 field elements):
//   merkle_root, nf_1, nf_2, cm_out_1, cm_out_2, fee, asset_id
//
// Whitepaper refs:
//   Section 7   - UTXO note model, nullifier set
//   Section 7.7 - Note-age randomization (rho field)
//   Section 8.3 - Noir unified DSL
//   Section 8.6 - MVP Phase 1: this circuit is the Phase 1 audit surface
//   Section 12.2 - Trusted setup ceremony

// Local modules kept for backward compatibility with existing tests.
// The canonical source is tonkl_lib; these are re-exports.
mod note;
mod constants;
mod hash;

use tonkl_lib::note::{Note, commitment, nullifier, assert_value_range, assert_ownership};
use tonkl_lib::merkle::compute_root as compute_merkle_root;

fn main(
    // PUBLIC INPUTS - committed on-chain, verified by aggregator
    merkle_root: pub Field,
    nf_1: pub Field,
    nf_2: pub Field,
    cm_out_1: pub Field,
    cm_out_2: pub Field,
    fee: pub Field,
    asset_id: pub Field,

    // PRIVATE: Input note 1
    in1_value: Field,
    in1_owner_pk_x: Field,
    in1_owner_pk_y: Field,
    in1_rho: Field,
    in1_owner_sk: Field,
    in1_merkle_bits: [bool; 32],
    in1_merkle_path: [Field; 32],

    // PRIVATE: Input note 2
    in2_value: Field,
    in2_owner_pk_x: Field,
    in2_owner_pk_y: Field,
    in2_rho: Field,
    in2_owner_sk: Field,
    in2_merkle_bits: [bool; 32],
    in2_merkle_path: [Field; 32],

    // PRIVATE: Output note 1 (primary recipient)
    out1_value: Field,
    out1_owner_pk_x: Field,
    out1_owner_pk_y: Field,
    out1_rho: Field,

    // PRIVATE: Output note 2 (change or second recipient)
    out2_value: Field,
    out2_owner_pk_x: Field,
    out2_owner_pk_y: Field,
    out2_rho: Field,
) {
    // STEP 1: VALUE RANGE CHECKS
    assert_value_range(in1_value);
    assert_value_range(in2_value);
    assert_value_range(out1_value);
    assert_value_range(out2_value);
    assert_value_range(fee);

    // STEP 2: CONSTRUCT INPUT NOTES
    let note_in1 = Note {
        value: in1_value, asset_id,
        owner_pk_x: in1_owner_pk_x, owner_pk_y: in1_owner_pk_y, rho: in1_rho,
    };
    let note_in2 = Note {
        value: in2_value, asset_id,
        owner_pk_x: in2_owner_pk_x, owner_pk_y: in2_owner_pk_y, rho: in2_rho,
    };

    // STEP 3: COMPUTE INPUT NOTE COMMITMENTS
    let cm_in1 = commitment(note_in1);
    let cm_in2 = commitment(note_in2);

    // STEP 4: MERKLE MEMBERSHIP PROOFS
    let computed_root_1 = compute_merkle_root(cm_in1, in1_merkle_bits, in1_merkle_path);
    assert(computed_root_1 == merkle_root, "Input note 1: not in tree");

    let computed_root_2 = compute_merkle_root(cm_in2, in2_merkle_bits, in2_merkle_path);
    assert(computed_root_2 == merkle_root, "Input note 2: not in tree");

    // STEP 5: NULLIFIER BINDING
    let computed_nf1 = nullifier(cm_in1, in1_owner_sk);
    assert(computed_nf1 == nf_1, "Input note 1: nullifier mismatch");

    let computed_nf2 = nullifier(cm_in2, in2_owner_sk);
    assert(computed_nf2 == nf_2, "Input note 2: nullifier mismatch");

    // STEP 6: NULLIFIER UNIQUENESS
    assert(nf_1 != nf_2, "Duplicate nullifier: same note used twice");

    // STEP 7: KEY OWNERSHIP (Phase 1b stub)
    assert_ownership(note_in1, in1_owner_sk);
    assert_ownership(note_in2, in2_owner_sk);

    // STEP 8: OUTPUT COMMITMENT BINDING
    let note_out1 = Note {
        value: out1_value, asset_id,
        owner_pk_x: out1_owner_pk_x, owner_pk_y: out1_owner_pk_y, rho: out1_rho,
    };
    let note_out2 = Note {
        value: out2_value, asset_id,
        owner_pk_x: out2_owner_pk_x, owner_pk_y: out2_owner_pk_y, rho: out2_rho,
    };

    assert(commitment(note_out1) == cm_out_1, "Output note 1: commitment mismatch");
    assert(commitment(note_out2) == cm_out_2, "Output note 2: commitment mismatch");

    // STEP 9: OUTPUT DISTINCTNESS
    assert(cm_out_1 != cm_out_2, "Output commitments must be distinct");

    // STEP 10: VALUE CONSERVATION
    assert(in1_value + in2_value == out1_value + out2_value + fee, "Value conservation violated");

    // STEP 11: NON-ZERO PRIMARY OUTPUT
    assert(out1_value != 0, "Primary output must be non-zero");
}

#[test]
fn test_value_conservation_arithmetic() {
    assert(100 + 50 == 120 + 30 + 0);
}

#[test]
fn test_range_check_max_u64() {
    note::assert_value_range(18446744073709551615);
}

// -- Circuit-level negative test suite ------------------------------------
//
// Each test builds a VALID baseline witness, then tampers exactly one
// element and asserts the circuit rejects it with the expected message.
// This validates that every constraint fires independently.
//
// The baseline: two input notes owned by sk1/sk2 at tree positions 0/1,
// values 100+50, split to 130+20 with fee=0. Merkle depth 32, sparse
// tree (all sibling hashes = 0 except at level 0 where the two notes
// are neighbors).

// Builds a fully-valid set of main() arguments and calls main().
// Returns nothing -- if main() doesn't panic, the witness is valid.
//
// Factored as a struct so individual tests can mutate one field before
// passing to `call_main`.

struct TestWitness {
    merkle_root: Field,
    nf_1: Field,
    nf_2: Field,
    cm_out_1: Field,
    cm_out_2: Field,
    fee: Field,
    asset_id: Field,
    in1_value: Field,
    in1_owner_pk_x: Field,
    in1_owner_pk_y: Field,
    in1_rho: Field,
    in1_owner_sk: Field,
    in1_merkle_bits: [bool; 32],
    in1_merkle_path: [Field; 32],
    in2_value: Field,
    in2_owner_pk_x: Field,
    in2_owner_pk_y: Field,
    in2_rho: Field,
    in2_owner_sk: Field,
    in2_merkle_bits: [bool; 32],
    in2_merkle_path: [Field; 32],
    out1_value: Field,
    out1_owner_pk_x: Field,
    out1_owner_pk_y: Field,
    out1_rho: Field,
    out2_value: Field,
    out2_owner_pk_x: Field,
    out2_owner_pk_y: Field,
    out2_rho: Field,
}

fn call_main(w: TestWitness) {
    main(
        w.merkle_root, w.nf_1, w.nf_2, w.cm_out_1, w.cm_out_2, w.fee, w.asset_id,
        w.in1_value, w.in1_owner_pk_x, w.in1_owner_pk_y, w.in1_rho, w.in1_owner_sk,
        w.in1_merkle_bits, w.in1_merkle_path,
        w.in2_value, w.in2_owner_pk_x, w.in2_owner_pk_y, w.in2_rho, w.in2_owner_sk,
        w.in2_merkle_bits, w.in2_merkle_path,
        w.out1_value, w.out1_owner_pk_x, w.out1_owner_pk_y, w.out1_rho,
        w.out2_value, w.out2_owner_pk_x, w.out2_owner_pk_y, w.out2_rho,
    );
}

fn build_valid_witness() -> TestWitness {
    // Two distinct spending keys
    let sk1: Field = 0xdead01;
    let sk2: Field = 0xdead02;
    let (pk1_x, pk1_y) = note::derive_pk(sk1);
    let (pk2_x, pk2_y) = note::derive_pk(sk2);

    // Output keys (different owners)
    let sk3: Field = 0xdead03;
    let sk4: Field = 0xdead04;
    let (pk3_x, pk3_y) = note::derive_pk(sk3);
    let (pk4_x, pk4_y) = note::derive_pk(sk4);

    let asset_id: Field = 1;
    let in1_rho: Field = 1001;
    let in2_rho: Field = 1002;
    let out1_rho: Field = 2001;
    let out2_rho: Field = 2002;

    // Input notes
    let note_in1 = note::Note { value: 100, asset_id, owner_pk_x: pk1_x, owner_pk_y: pk1_y, rho: in1_rho };
    let note_in2 = note::Note { value: 50,  asset_id, owner_pk_x: pk2_x, owner_pk_y: pk2_y, rho: in2_rho };
    let cm_in1 = note::commitment(note_in1);
    let cm_in2 = note::commitment(note_in2);

    // Sparse Merkle tree: notes at positions 0 and 1.
    // Position 0: sibling at level 0 = cm_in2, rest = 0
    // Position 1: sibling at level 0 = cm_in1, rest = 0
    let mut path_0: [Field; 32] = [0; 32];
    path_0[0] = cm_in2;
    let bits_0: [bool; 32] = [false; 32];

    let mut path_1: [Field; 32] = [0; 32];
    path_1[0] = cm_in1;
    let mut bits_1: [bool; 32] = [false; 32];
    bits_1[0] = true;

    let merkle_root = compute_merkle_root(cm_in1, bits_0, path_0);

    // Nullifiers
    let nf_1 = note::nullifier(cm_in1, sk1);
    let nf_2 = note::nullifier(cm_in2, sk2);

    // Output notes: 100 + 50 = 130 + 20
    let note_out1 = note::Note { value: 130, asset_id, owner_pk_x: pk3_x, owner_pk_y: pk3_y, rho: out1_rho };
    let note_out2 = note::Note { value: 20,  asset_id, owner_pk_x: pk4_x, owner_pk_y: pk4_y, rho: out2_rho };
    let cm_out_1 = note::commitment(note_out1);
    let cm_out_2 = note::commitment(note_out2);

    TestWitness {
        merkle_root,
        nf_1, nf_2,
        cm_out_1, cm_out_2,
        fee: 0,
        asset_id,
        in1_value: 100,
        in1_owner_pk_x: pk1_x, in1_owner_pk_y: pk1_y,
        in1_rho, in1_owner_sk: sk1,
        in1_merkle_bits: bits_0, in1_merkle_path: path_0,
        in2_value: 50,
        in2_owner_pk_x: pk2_x, in2_owner_pk_y: pk2_y,
        in2_rho, in2_owner_sk: sk2,
        in2_merkle_bits: bits_1, in2_merkle_path: path_1,
        out1_value: 130,
        out1_owner_pk_x: pk3_x, out1_owner_pk_y: pk3_y,
        out1_rho,
        out2_value: 20,
        out2_owner_pk_x: pk4_x, out2_owner_pk_y: pk4_y,
        out2_rho,
    }
}

// -- Positive baseline: valid witness must pass ---------------------------

#[test]
fn test_valid_transfer_passes() {
    let w = build_valid_witness();
    call_main(w);
}

// -- STEP 10: Value conservation ------------------------------------------

#[test(should_fail_with = "Value conservation violated")]
fn test_reject_value_conservation_violation() {
    let mut w = build_valid_witness();
    // Inflate output: 131 + 20 = 151 > 150 = 100 + 50
    w.out1_value = 131;
    // Recompute output commitment so commitment binding doesn't fire first
    let sk3: Field = 0xdead03;
    let (pk3_x, pk3_y) = note::derive_pk(sk3);
    let note_out1 = note::Note { value: 131, asset_id: 1, owner_pk_x: pk3_x, owner_pk_y: pk3_y, rho: 2001 };
    w.cm_out_1 = note::commitment(note_out1);
    call_main(w);
}

// -- STEP 11: Non-zero primary output -------------------------------------

#[test(should_fail_with = "Primary output must be non-zero")]
fn test_reject_zero_primary_output() {
    let mut w = build_valid_witness();
    // Set out1 = 0, out2 = 150 (still conserves value)
    w.out1_value = 0;
    w.out2_value = 150;
    // Recompute both output commitments
    let sk3: Field = 0xdead03;
    let sk4: Field = 0xdead04;
    let (pk3_x, pk3_y) = note::derive_pk(sk3);
    let (pk4_x, pk4_y) = note::derive_pk(sk4);
    let note_out1 = note::Note { value: 0,   asset_id: 1, owner_pk_x: pk3_x, owner_pk_y: pk3_y, rho: 2001 };
    let note_out2 = note::Note { value: 150, asset_id: 1, owner_pk_x: pk4_x, owner_pk_y: pk4_y, rho: 2002 };
    w.cm_out_1 = note::commitment(note_out1);
    w.cm_out_2 = note::commitment(note_out2);
    call_main(w);
}

// -- STEP 6: Duplicate nullifier ------------------------------------------

#[test(should_fail_with = "Duplicate nullifier: same note used twice")]
fn test_reject_duplicate_nullifier() {
    let mut w = build_valid_witness();
    // Use note 1 twice: same sk, same commitment, same nullifier
    w.nf_2 = w.nf_1;
    w.in2_value = w.in1_value;
    w.in2_owner_pk_x = w.in1_owner_pk_x;
    w.in2_owner_pk_y = w.in1_owner_pk_y;
    w.in2_rho = w.in1_rho;
    w.in2_owner_sk = w.in1_owner_sk;
    w.in2_merkle_bits = w.in1_merkle_bits;
    w.in2_merkle_path = w.in1_merkle_path;
    // Fix value conservation: 100+100 = 130+70
    w.out2_value = 70;
    let sk4: Field = 0xdead04;
    let (pk4_x, pk4_y) = note::derive_pk(sk4);
    let note_out2 = note::Note { value: 70, asset_id: 1, owner_pk_x: pk4_x, owner_pk_y: pk4_y, rho: 2002 };
    w.cm_out_2 = note::commitment(note_out2);
    call_main(w);
}

// -- STEP 5: Nullifier mismatch -------------------------------------------

#[test(should_fail_with = "Input note 1: nullifier mismatch")]
fn test_reject_wrong_nullifier_1() {
    let mut w = build_valid_witness();
    // Corrupt nf_1
    w.nf_1 = w.nf_1 + 1;
    call_main(w);
}

#[test(should_fail_with = "Input note 2: nullifier mismatch")]
fn test_reject_wrong_nullifier_2() {
    let mut w = build_valid_witness();
    w.nf_2 = w.nf_2 + 1;
    call_main(w);
}

// -- STEP 4: Merkle membership --------------------------------------------

#[test(should_fail_with = "Input note 1: not in tree")]
fn test_reject_bad_merkle_path_1() {
    let mut w = build_valid_witness();
    // Corrupt a sibling in note 1's path
    w.in1_merkle_path[1] = 999;
    call_main(w);
}

#[test(should_fail_with = "Input note 2: not in tree")]
fn test_reject_bad_merkle_path_2() {
    let mut w = build_valid_witness();
    w.in2_merkle_path[1] = 999;
    call_main(w);
}

#[test(should_fail_with = "Input note 1: not in tree")]
fn test_reject_wrong_merkle_root() {
    let mut w = build_valid_witness();
    // Tamper the public merkle_root
    w.merkle_root = w.merkle_root + 1;
    call_main(w);
}

// -- STEP 7: Key ownership ------------------------------------------------

#[test(should_fail_with = "assert_ownership: pk_x mismatch - invalid spending key")]
fn test_reject_wrong_sk_for_input_1() {
    let mut w = build_valid_witness();
    // Use a completely wrong sk -- the derived pk won't match the note's pk.
    // We must also fix the nullifier and Merkle membership to not fire first.
    // Since we're changing sk but NOT the note's pk, ownership check fires.
    // However, nullifier is computed from (cm, sk), so we need to update nf_1.
    let wrong_sk: Field = 0xbad;
    w.in1_owner_sk = wrong_sk;
    // Recompute nf_1 with wrong sk so nullifier check passes
    let cm_in1 = note::commitment(note::Note {
        value: w.in1_value, asset_id: w.asset_id,
        owner_pk_x: w.in1_owner_pk_x, owner_pk_y: w.in1_owner_pk_y,
        rho: w.in1_rho,
    });
    w.nf_1 = note::nullifier(cm_in1, wrong_sk);
    call_main(w);
}

#[test(should_fail_with = "assert_ownership: pk_x mismatch - invalid spending key")]
fn test_reject_wrong_sk_for_input_2() {
    let mut w = build_valid_witness();
    let wrong_sk: Field = 0xbad;
    w.in2_owner_sk = wrong_sk;
    let cm_in2 = note::commitment(note::Note {
        value: w.in2_value, asset_id: w.asset_id,
        owner_pk_x: w.in2_owner_pk_x, owner_pk_y: w.in2_owner_pk_y,
        rho: w.in2_rho,
    });
    w.nf_2 = note::nullifier(cm_in2, wrong_sk);
    call_main(w);
}

// -- STEP 8: Output commitment binding ------------------------------------

#[test(should_fail_with = "Output note 1: commitment mismatch")]
fn test_reject_output_commitment_mismatch_1() {
    let mut w = build_valid_witness();
    // Tamper cm_out_1 without changing the note fields
    w.cm_out_1 = w.cm_out_1 + 1;
    call_main(w);
}

#[test(should_fail_with = "Output note 2: commitment mismatch")]
fn test_reject_output_commitment_mismatch_2() {
    let mut w = build_valid_witness();
    w.cm_out_2 = w.cm_out_2 + 1;
    call_main(w);
}

// -- STEP 9: Output distinctness ------------------------------------------

#[test(should_fail_with = "Output commitments must be distinct")]
fn test_reject_duplicate_output_commitments() {
    let mut w = build_valid_witness();
    // Make out2 identical to out1 (same value, pk, rho)
    w.out2_value = w.out1_value;
    w.out2_owner_pk_x = w.out1_owner_pk_x;
    w.out2_owner_pk_y = w.out1_owner_pk_y;
    w.out2_rho = w.out1_rho;
    w.cm_out_2 = w.cm_out_1;
    // Fix value conservation: 100 + 50 = 130 + 130 won't work, but the
    // distinctness check fires before conservation. We need conservation
    // to also hold: 100 + 50 = 75 + 75 = 150.
    w.out1_value = 75;
    w.out2_value = 75;
    let sk3: Field = 0xdead03;
    let (pk3_x, pk3_y) = note::derive_pk(sk3);
    let note_dup = note::Note { value: 75, asset_id: 1, owner_pk_x: pk3_x, owner_pk_y: pk3_y, rho: 2001 };
    let cm_dup = note::commitment(note_dup);
    w.cm_out_1 = cm_dup;
    w.cm_out_2 = cm_dup;
    w.out2_owner_pk_x = pk3_x;
    w.out2_owner_pk_y = pk3_y;
    w.out2_rho = 2001;
    call_main(w);
}

// -- STEP 1: Value range overflow -----------------------------------------
// BN254 field modulus p - 1 wraps to 0 in u64 range check. This is the
// classic "create tokens from nothing" attack on field-arithmetic circuits.

#[test(should_fail)]
fn test_reject_overflow_input_value() {
    let mut w = build_valid_witness();
    // p - 1 is enormous but wraps to 0 mod 2^64.
    // We can't set value = p-1 literally in Noir, but we can use a value
    // that exceeds u64::MAX. Use 2^64 = 18446744073709551616.
    // Note: Noir Field literals can't exceed the modulus, but we can
    // construct a value > u64::MAX via arithmetic.
    let overflow: Field = 18446744073709551615 + 1; // u64::MAX + 1
    w.in1_value = overflow;
    call_main(w);
}

#[test(should_fail)]
fn test_reject_overflow_output_value() {
    let mut w = build_valid_witness();
    let overflow: Field = 18446744073709551615 + 1;
    w.out1_value = overflow;
    call_main(w);
}

// -- Fee overflow ---------------------------------------------------------

#[test(should_fail)]
fn test_reject_overflow_fee() {
    let mut w = build_valid_witness();
    let overflow: Field = 18446744073709551615 + 1;
    w.fee = overflow;
    call_main(w);
}

// -- Public asset_id tampering --------------------------------------------
// asset_id is baked into every note commitment. Changing the public
// asset_id causes the circuit to recompute different commitments for the
// input notes, so the Merkle membership check fails (the tree contains
// commitments with the ORIGINAL asset_id, not the tampered one).

#[test(should_fail_with = "Input note 1: not in tree")]
fn test_reject_tampered_asset_id() {
    let mut w = build_valid_witness();
    // Change public asset_id from 1 to 99
    w.asset_id = 99;
    call_main(w);
}

// -- Zero spending key edge case ------------------------------------------
// sk=0 is a degenerate key (maps to the identity point on Grumpkin).
// The circuit must reject it because derive_pk(0) != the note's real pk
// (unless the note was intentionally created with pk = 0*G, which would
// be a bug in the wallet).

#[test(should_fail_with = "assert_ownership: pk_x mismatch - invalid spending key")]
fn test_reject_zero_sk() {
    let mut w = build_valid_witness();
    let zero_sk: Field = 0;
    w.in1_owner_sk = zero_sk;
    // Recompute nullifier so nullifier check doesn't fire first
    let cm_in1 = note::commitment(note::Note {
        value: w.in1_value, asset_id: w.asset_id,
        owner_pk_x: w.in1_owner_pk_x, owner_pk_y: w.in1_owner_pk_y,
        rho: w.in1_rho,
    });
    w.nf_1 = note::nullifier(cm_in1, zero_sk);
    call_main(w);
}

// -- Cross-domain attack: nullifier forged as commitment ------------------
// An attacker might try to set nf = commitment(note) hoping the
// nullifier check passes. This must fail because:
//   nullifier = hash_3(NULLIFIER_DOMAIN=1, cm, sk)
//   commitment = hash_7(COMMITMENT_DOMAIN=2, ..., rho)
// Domain separation ensures these are different hash functions.

#[test(should_fail_with = "Input note 1: nullifier mismatch")]
fn test_reject_cross_domain_nullifier_as_commitment() {
    let mut w = build_valid_witness();
    // Try using the commitment itself as the nullifier
    let cm_in1 = note::commitment(note::Note {
        value: w.in1_value, asset_id: w.asset_id,
        owner_pk_x: w.in1_owner_pk_x, owner_pk_y: w.in1_owner_pk_y,
        rho: w.in1_rho,
    });
    w.nf_1 = cm_in1; // forged: use commitment as nullifier
    call_main(w);
}

// -- Zero rho edge case ---------------------------------------------------
// rho=0 is technically valid (the circuit doesn't forbid it), but we
// verify the positive case still works to confirm no accidental zero
// rejection in the hash chain. This is a POSITIVE test.

#[test]
fn test_zero_rho_is_accepted() {
    // Build a custom witness with rho=0 for all notes. As long as
    // the notes differ in other fields, this should pass.
    let sk1: Field = 0xaa01;
    let sk2: Field = 0xaa02;
    let (pk1_x, pk1_y) = note::derive_pk(sk1);
    let (pk2_x, pk2_y) = note::derive_pk(sk2);
    let sk3: Field = 0xaa03;
    let sk4: Field = 0xaa04;
    let (pk3_x, pk3_y) = note::derive_pk(sk3);
    let (pk4_x, pk4_y) = note::derive_pk(sk4);

    let asset_id: Field = 1;
    let note_in1 = note::Note { value: 100, asset_id, owner_pk_x: pk1_x, owner_pk_y: pk1_y, rho: 0 };
    let note_in2 = note::Note { value: 50,  asset_id, owner_pk_x: pk2_x, owner_pk_y: pk2_y, rho: 0 };
    let cm_in1 = note::commitment(note_in1);
    let cm_in2 = note::commitment(note_in2);

    let mut path_0: [Field; 32] = [0; 32];
    path_0[0] = cm_in2;
    let bits_0: [bool; 32] = [false; 32];
    let mut path_1: [Field; 32] = [0; 32];
    path_1[0] = cm_in1;
    let mut bits_1: [bool; 32] = [false; 32];
    bits_1[0] = true;
    let merkle_root = compute_merkle_root(cm_in1, bits_0, path_0);

    let note_out1 = note::Note { value: 130, asset_id, owner_pk_x: pk3_x, owner_pk_y: pk3_y, rho: 0 };
    let note_out2 = note::Note { value: 20,  asset_id, owner_pk_x: pk4_x, owner_pk_y: pk4_y, rho: 0 };

    main(
        merkle_root,
        note::nullifier(cm_in1, sk1), note::nullifier(cm_in2, sk2),
        note::commitment(note_out1), note::commitment(note_out2),
        0, asset_id,
        100, pk1_x, pk1_y, 0, sk1, bits_0, path_0,
        50,  pk2_x, pk2_y, 0, sk2, bits_1, path_1,
        130, pk3_x, pk3_y, 0,
        20,  pk4_x, pk4_y, 0,
    );
}
