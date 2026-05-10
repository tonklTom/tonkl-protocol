// Tonkl Protocol - Merge Circuit (32-in / 1-out)
//
// Proves a valid consolidation of 32 input notes into a single output note,
// all owned by the same spending key. No value is transferred to another
// party -- this is a wallet-maintenance operation that reduces UTXO count.
//
// Zero-knowledge statement:
//   "I know 32 notes in the current note tree (merkle_root), I own all of
//    them (owner_sk derives to each note's registered pk), all share the
//    same asset_id, and I am creating one output note whose value equals
//    the sum of all inputs minus the fee."
//
// On-chain footprint per proof (public inputs, 36 field elements):
//   merkle_root, nullifiers[32], cm_out, fee, asset_id
//
// Design notes:
//   - All 32 inputs must be owned by the SAME spending key. This is enforced
//     by assert_ownership on each input note with the same owner_sk.
//   - The output note's owner pk is derived from owner_sk, ensuring the
//     merged note stays with the original owner.
//   - For merges with fewer than 32 real notes, pad with zero-value notes
//     (valid notes with value=0 that exist in the tree and are owned by
//     the same key). This avoids leaking the actual input count.
//   - No "non-zero output" check: a merge with fee = total input value
//     is a valid burn operation.
//
// Whitepaper refs:
//   Section 7.5 - Enforced output templates (32-in/1-out merge)
//   Section 7.6 - Merge obligation bands
//   Section 8.3 - Noir as unified circuit DSL

use tonkl_lib::note::{Note, commitment, nullifier, assert_value_range, assert_ownership, derive_pk};
use tonkl_lib::hash::hash_2;
use tonkl_lib::merkle::compute_root;

fn main(
    // PUBLIC INPUTS
    merkle_root: pub Field,
    nullifiers: pub [Field; 32],
    cm_out: pub Field,
    fee: pub Field,
    asset_id: pub Field,

    // PRIVATE: Shared owner key
    owner_sk: Field,

    // PRIVATE: Input notes (32)
    in_values: [Field; 32],
    in_rhos: [Field; 32],
    in_merkle_bits: [[bool; 32]; 32],
    in_merkle_paths: [[Field; 32]; 32],

    // PRIVATE: Output note
    out_rho: Field,
) {
    // STEP 1: DERIVE OWNER PUBLIC KEY
    // All input notes must be owned by owner_sk. We derive pk once
    // and reuse it for all inputs and the output.
    let (owner_pk_x, owner_pk_y) = derive_pk(owner_sk);

    // STEP 2: VALUE RANGE CHECKS
    // Prevent BN254 field wraparound attacks on all values.
    for i in 0..32 {
        assert_value_range(in_values[i]);
    }
    assert_value_range(fee);

    // STEP 3: PER-INPUT VERIFICATION
    // For each input: build note, compute commitment, verify Merkle
    // membership, verify ownership, compute nullifier, accumulate value.
    let mut total_value: Field = 0;
    for i in 0..32 {
        let note_i = Note {
            value: in_values[i],
            asset_id,
            owner_pk_x,
            owner_pk_y,
            rho: in_rhos[i],
        };
        let cm_i = commitment(note_i);

        // Merkle membership
        let root_i = compute_root(cm_i, in_merkle_bits[i], in_merkle_paths[i]);
        assert(root_i == merkle_root, "Merkle membership check failed");

        // Ownership
        assert_ownership(note_i, owner_sk);

        // Nullifier
        let computed_nf = nullifier(cm_i, owner_sk);
        assert(computed_nf == nullifiers[i], "Nullifier mismatch");

        total_value += in_values[i];
    }

    // STEP 4: NULLIFIER UNIQUENESS
    // All 32 nullifiers must be distinct (no double-spend).
    // C(32,2) = 496 pairwise checks.
    for i in 0..32 {
        for j in 0..32 {
            if j > i {
                assert(nullifiers[i] != nullifiers[j], "Duplicate nullifier");
            }
        }
    }

    // STEP 5: OUTPUT NOTE CONSTRUCTION & COMMITMENT BINDING
    // Output note is owned by the same key. Value = sum(inputs) - fee.
    let out_value = total_value - fee;
    assert_value_range(out_value);

    let note_out = Note {
        value: out_value,
        asset_id,
        owner_pk_x,
        owner_pk_y,
        rho: out_rho,
    };
    let computed_cm_out = commitment(note_out);
    assert(computed_cm_out == cm_out, "Output commitment mismatch");

    // STEP 6: VALUE CONSERVATION
    // Explicit check: sum of inputs == output + fee.
    assert(total_value == out_value + fee, "Value conservation violated");
}

// ---------------------------------------------------------------------------
// TEST SUITE
// ---------------------------------------------------------------------------

struct MergeTestWitness {
    merkle_root: Field,
    nullifiers: [Field; 32],
    cm_out: Field,
    fee: Field,
    asset_id: Field,
    owner_sk: Field,
    in_values: [Field; 32],
    in_rhos: [Field; 32],
    in_merkle_bits: [[bool; 32]; 32],
    in_merkle_paths: [[Field; 32]; 32],
    out_rho: Field,
}

fn call_merge(w: MergeTestWitness) {
    main(
        w.merkle_root,
        w.nullifiers,
        w.cm_out,
        w.fee,
        w.asset_id,
        w.owner_sk,
        w.in_values,
        w.in_rhos,
        w.in_merkle_bits,
        w.in_merkle_paths,
        w.out_rho,
    );
}

// Build a complete 32-leaf Merkle tree from an array of commitments.
// Returns (root, paths, index_bits) for all 32 leaves.
//
// Tree structure: 32 leaves fill positions 0-31. All higher siblings
// (levels 5-31) are empty (Field(0)), matching the sparse tree convention.
fn build_32_leaf_tree(
    cms: [Field; 32],
) -> (Field, [[Field; 32]; 32], [[bool; 32]; 32]) {
    // Level 1: 16 parent nodes from 32 leaf pairs
    let mut l1: [Field; 16] = [0; 16];
    for i in 0..16 {
        l1[i] = hash_2(cms[2 * i], cms[2 * i + 1]);
    }

    // Level 2: 8 nodes
    let mut l2: [Field; 8] = [0; 8];
    for i in 0..8 {
        l2[i] = hash_2(l1[2 * i], l1[2 * i + 1]);
    }

    // Level 3: 4 nodes
    let mut l3: [Field; 4] = [0; 4];
    for i in 0..4 {
        l3[i] = hash_2(l2[2 * i], l2[2 * i + 1]);
    }

    // Level 4: 2 nodes
    let mut l4: [Field; 2] = [0; 2];
    l4[0] = hash_2(l3[0], l3[1]);
    l4[1] = hash_2(l3[2], l3[3]);

    // Level 5: single node covering all 32 leaves
    let l5 = hash_2(l4[0], l4[1]);

    // Levels 6-31: hash with 0 (empty right subtrees at each level)
    let mut node = l5;
    for _k in 5..32 {
        node = hash_2(node, 0);
    }
    let root = node;

    // Extract authentication paths for each leaf
    let mut paths: [[Field; 32]; 32] = [[0; 32]; 32];
    let mut bits: [[bool; 32]; 32] = [[false; 32]; 32];

    for j in 0..32 {
        // LSB-first bit decomposition of leaf position j
        // Positions 0-31 need bits 0-4; bits 5-31 are always false.
        bits[j][0] = (j & 1) != 0;
        bits[j][1] = (j & 2) != 0;
        bits[j][2] = (j & 4) != 0;
        bits[j][3] = (j & 8) != 0;
        bits[j][4] = (j & 16) != 0;

        // Level 0 sibling: the other leaf in the pair
        paths[j][0] = cms[j ^ 1];

        // Level 1 sibling: the other node in the level-1 pair
        paths[j][1] = l1[(j / 2) ^ 1];

        // Level 2 sibling
        paths[j][2] = l2[(j / 4) ^ 1];

        // Level 3 sibling
        paths[j][3] = l3[(j / 8) ^ 1];

        // Level 4 sibling
        paths[j][4] = l4[(j / 16) ^ 1];

        // Levels 5-31: siblings are 0 (already initialized)
    }

    (root, paths, bits)
}

// Build a valid 32-input merge witness with values 1..32.
// Total value = 528, fee = 0, output = 528.
fn build_valid_merge_witness() -> MergeTestWitness {
    let owner_sk: Field = 0xae0901;
    let (pk_x, pk_y) = derive_pk(owner_sk);
    let asset_id: Field = 1;

    // 32 input notes with distinct values and rhos
    let mut values: [Field; 32] = [0; 32];
    let mut rhos: [Field; 32] = [0; 32];
    for i in 0..32 {
        values[i] = (i as Field) + 1;       // 1, 2, 3, ..., 32
        rhos[i] = 5000 + (i as Field) + 1;  // 5001, 5002, ..., 5032
    }

    // Compute all 32 commitments
    let mut cms: [Field; 32] = [0; 32];
    for i in 0..32 {
        let note_i = Note {
            value: values[i],
            asset_id,
            owner_pk_x: pk_x,
            owner_pk_y: pk_y,
            rho: rhos[i],
        };
        cms[i] = commitment(note_i);
    }

    // Build 32-leaf Merkle tree
    let (root, paths, mbits) = build_32_leaf_tree(cms);

    // Compute all 32 nullifiers
    let mut nfs: [Field; 32] = [0; 32];
    for i in 0..32 {
        nfs[i] = nullifier(cms[i], owner_sk);
    }

    // Output: sum(1..32) = 32*33/2 = 528, fee = 0
    let mut total: Field = 0;
    for i in 0..32 {
        total += values[i];
    }
    let out_rho: Field = 9999;
    let note_out = Note {
        value: total,
        asset_id,
        owner_pk_x: pk_x,
        owner_pk_y: pk_y,
        rho: out_rho,
    };
    let cm_out = commitment(note_out);

    MergeTestWitness {
        merkle_root: root,
        nullifiers: nfs,
        cm_out,
        fee: 0,
        asset_id,
        owner_sk,
        in_values: values,
        in_rhos: rhos,
        in_merkle_bits: mbits,
        in_merkle_paths: paths,
        out_rho,
    }
}

// --- Positive tests ---

#[test]
fn test_valid_merge_passes() {
    let w = build_valid_merge_witness();
    call_merge(w);
}

#[test]
fn test_merge_with_fee() {
    let mut w = build_valid_merge_witness();
    // Fee = 28, output = 528 - 28 = 500
    w.fee = 28;
    let (pk_x, pk_y) = derive_pk(w.owner_sk);
    let note_out = Note {
        value: 500,
        asset_id: w.asset_id,
        owner_pk_x: pk_x,
        owner_pk_y: pk_y,
        rho: w.out_rho,
    };
    w.cm_out = commitment(note_out);
    call_merge(w);
}

// --- Negative tests ---

#[test(should_fail_with = "Output commitment mismatch")]
fn test_reject_value_inflation() {
    let mut w = build_valid_merge_witness();
    // Attacker computes cm_out with inflated value (999 instead of 528).
    // The circuit internally derives out_value = 528 - 0 = 528, so the
    // commitment built by the circuit won't match the tampered cm_out.
    let (pk_x, pk_y) = derive_pk(w.owner_sk);
    let note_out = Note {
        value: 999,
        asset_id: w.asset_id,
        owner_pk_x: pk_x,
        owner_pk_y: pk_y,
        rho: w.out_rho,
    };
    w.cm_out = commitment(note_out);
    call_merge(w);
}

#[test(should_fail_with = "Merkle membership check failed")]
fn test_reject_wrong_owner_sk() {
    let mut w = build_valid_merge_witness();
    // Wrong sk derives different pk, so commitments differ from what's
    // in the tree. Merkle membership fails before ownership check.
    w.owner_sk = 0xbadbad;
    call_merge(w);
}

#[test(should_fail_with = "Duplicate nullifier")]
fn test_reject_duplicate_input() {
    let mut w = build_valid_merge_witness();
    // Copy input 0 into input 1 (same note, same nullifier)
    w.in_values[1] = w.in_values[0];
    w.in_rhos[1] = w.in_rhos[0];
    w.in_merkle_bits[1] = w.in_merkle_bits[0];
    w.in_merkle_paths[1] = w.in_merkle_paths[0];
    w.nullifiers[1] = w.nullifiers[0];
    call_merge(w);
}

#[test(should_fail_with = "Merkle membership check failed")]
fn test_reject_bad_merkle_path() {
    let mut w = build_valid_merge_witness();
    w.in_merkle_paths[0][2] = 999;
    call_merge(w);
}

#[test(should_fail_with = "Nullifier mismatch")]
fn test_reject_wrong_nullifier() {
    let mut w = build_valid_merge_witness();
    w.nullifiers[0] = w.nullifiers[0] + 1;
    call_merge(w);
}

#[test(should_fail_with = "Output commitment mismatch")]
fn test_reject_output_commitment_tamper() {
    let mut w = build_valid_merge_witness();
    w.cm_out = w.cm_out + 1;
    call_merge(w);
}

#[test(should_fail_with = "Merkle membership check failed")]
fn test_reject_wrong_asset_id() {
    let mut w = build_valid_merge_witness();
    // Changing asset_id changes the commitment, so Merkle check fails.
    w.asset_id = 99;
    call_merge(w);
}

#[test(should_fail)]
fn test_reject_overflow_value() {
    let mut w = build_valid_merge_witness();
    // u64::MAX + 1 overflows the 64-bit range check
    w.in_values[0] = 18446744073709551615 + 1;
    call_merge(w);
}
