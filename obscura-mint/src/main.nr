// Obscura Protocol - Mint Circuit (0-in / 32-out, authorized issuance)
//
// Proves authorized creation of up to 32 new notes. The mint authority
// demonstrates knowledge of the secret key behind a publicly known
// authority public key, and creates output notes owned by any recipients.
//
// Zero-knowledge statement:
//   "I know the secret key for the mint authority (authority_pk), and I am
//    creating 32 output notes with the specified asset_id whose values sum
//    to total_minted. Each output note is owned by its specified recipient."
//
// On-chain footprint per proof (public inputs, 36 field elements):
//   cm_outs[32], total_minted, asset_id, authority_pk_x, authority_pk_y
//
// Design notes:
//   - No inputs consumed: minting creates value from nothing, authorized
//     by cryptographic proof of authority.
//   - No Merkle tree or nullifiers: there is nothing to spend.
//   - The mint authority pk is a PUBLIC INPUT, allowing the on-chain
//     contract to verify it matches the registered authority for this
//     asset_id. This prevents unauthorized minting.
//   - Each output can have a DIFFERENT owner public key, enabling direct
//     distribution to multiple recipients in a single mint operation.
//   - For fewer than 32 real recipients, pad remaining outputs with
//     zero-value notes (distinct rhos) to avoid leaking recipient count.
//   - total_minted is a public input so the on-chain contract can enforce
//     supply caps or rate limits without inspecting individual note values.
//
// Whitepaper refs:
//   Section 7.5 - Enforced output templates
//   Section 8.3 - Noir as unified circuit DSL
//   Section 8.6 - MVP Phase 1 circuit scope

use obscura_lib::note::{Note, commitment, assert_value_range, derive_pk};

fn main(
    // PUBLIC INPUTS
    cm_outs: pub [Field; 32],
    total_minted: pub Field,
    asset_id: pub Field,
    authority_pk_x: pub Field,
    authority_pk_y: pub Field,

    // PRIVATE: Mint authority secret key
    authority_sk: Field,

    // PRIVATE: Output notes (32)
    out_values: [Field; 32],
    out_pk_xs: [Field; 32],
    out_pk_ys: [Field; 32],
    out_rhos: [Field; 32],
) {
    // STEP 1: AUTHORITY VERIFICATION
    // Prove the prover knows the sk behind the public authority_pk.
    let (derived_pk_x, derived_pk_y) = derive_pk(authority_sk);
    assert(derived_pk_x == authority_pk_x, "Authority pk_x mismatch");
    assert(derived_pk_y == authority_pk_y, "Authority pk_y mismatch");

    // STEP 2: VALUE RANGE CHECKS
    // Prevent BN254 field wraparound attacks on all values.
    assert_value_range(total_minted);
    for i in 0..32 {
        assert_value_range(out_values[i]);
    }

    // STEP 3: OUTPUT NOTE CONSTRUCTION & COMMITMENT BINDING
    // Each output note can be owned by a different recipient.
    let mut sum_values: Field = 0;
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

        sum_values += out_values[i];
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

    // STEP 5: SUPPLY CONSERVATION
    // The sum of all output values must equal the declared total_minted.
    // This allows the on-chain contract to enforce supply caps using only
    // the public total_minted field, without knowing individual values.
    assert(sum_values == total_minted, "Minted value mismatch");
}

// ---------------------------------------------------------------------------
// TEST SUITE
// ---------------------------------------------------------------------------

struct MintTestWitness {
    cm_outs: [Field; 32],
    total_minted: Field,
    asset_id: Field,
    authority_pk_x: Field,
    authority_pk_y: Field,
    authority_sk: Field,
    out_values: [Field; 32],
    out_pk_xs: [Field; 32],
    out_pk_ys: [Field; 32],
    out_rhos: [Field; 32],
}

fn call_mint(w: MintTestWitness) {
    main(
        w.cm_outs,
        w.total_minted,
        w.asset_id,
        w.authority_pk_x,
        w.authority_pk_y,
        w.authority_sk,
        w.out_values,
        w.out_pk_xs,
        w.out_pk_ys,
        w.out_rhos,
    );
}

// Build a valid mint witness.
// Authority mints 1000 units total:
//   400 to recipient A, 300 to recipient B, 200 to recipient C,
//   100 to recipient D, 0 padding for outputs 4-31.
fn build_valid_mint_witness() -> MintTestWitness {
    let authority_sk: Field = 0xfed001;
    let (authority_pk_x, authority_pk_y) = derive_pk(authority_sk);
    let asset_id: Field = 1;

    // 4 distinct recipients
    let recipient_a_sk: Field = 0xaaaa01;
    let recipient_b_sk: Field = 0xbbbb02;
    let recipient_c_sk: Field = 0xcccc03;
    let recipient_d_sk: Field = 0xdddd04;
    let (a_pk_x, a_pk_y) = derive_pk(recipient_a_sk);
    let (b_pk_x, b_pk_y) = derive_pk(recipient_b_sk);
    let (c_pk_x, c_pk_y) = derive_pk(recipient_c_sk);
    let (d_pk_x, d_pk_y) = derive_pk(recipient_d_sk);

    // Output values: 4 real + 28 zero-value padding
    let mut out_values: [Field; 32] = [0; 32];
    out_values[0] = 400;
    out_values[1] = 300;
    out_values[2] = 200;
    out_values[3] = 100;
    let total_minted: Field = 1000;

    // Output public keys
    let mut out_pk_xs: [Field; 32] = [0; 32];
    let mut out_pk_ys: [Field; 32] = [0; 32];
    out_pk_xs[0] = a_pk_x; out_pk_ys[0] = a_pk_y;
    out_pk_xs[1] = b_pk_x; out_pk_ys[1] = b_pk_y;
    out_pk_xs[2] = c_pk_x; out_pk_ys[2] = c_pk_y;
    out_pk_xs[3] = d_pk_x; out_pk_ys[3] = d_pk_y;
    // Padding outputs owned by authority
    for i in 4..32 {
        out_pk_xs[i] = authority_pk_x;
        out_pk_ys[i] = authority_pk_y;
    }

    // Distinct rhos for all 32 outputs
    let mut out_rhos: [Field; 32] = [0; 32];
    for i in 0..32 {
        out_rhos[i] = 6001 + (i as Field);
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

    MintTestWitness {
        cm_outs,
        total_minted,
        asset_id,
        authority_pk_x,
        authority_pk_y,
        authority_sk,
        out_values,
        out_pk_xs,
        out_pk_ys,
        out_rhos,
    }
}

// --- Positive tests ---

#[test]
fn test_valid_mint_passes() {
    let w = build_valid_mint_witness();
    call_mint(w);
}

#[test]
fn test_mint_single_recipient() {
    // Mint all 1000 to a single recipient, 31 zero-value padding
    let authority_sk: Field = 0xfed001;
    let (authority_pk_x, authority_pk_y) = derive_pk(authority_sk);
    let asset_id: Field = 1;

    let recipient_sk: Field = 0xaaaa01;
    let (r_pk_x, r_pk_y) = derive_pk(recipient_sk);

    let mut out_values: [Field; 32] = [0; 32];
    out_values[0] = 1000;

    let mut out_pk_xs: [Field; 32] = [0; 32];
    let mut out_pk_ys: [Field; 32] = [0; 32];
    out_pk_xs[0] = r_pk_x; out_pk_ys[0] = r_pk_y;
    for i in 1..32 {
        out_pk_xs[i] = authority_pk_x;
        out_pk_ys[i] = authority_pk_y;
    }

    let mut out_rhos: [Field; 32] = [0; 32];
    for i in 0..32 {
        out_rhos[i] = 7001 + (i as Field);
    }

    let mut cm_outs: [Field; 32] = [0; 32];
    for i in 0..32 {
        let n = Note {
            value: out_values[i], asset_id,
            owner_pk_x: out_pk_xs[i], owner_pk_y: out_pk_ys[i],
            rho: out_rhos[i],
        };
        cm_outs[i] = commitment(n);
    }

    let w = MintTestWitness {
        cm_outs, total_minted: 1000, asset_id,
        authority_pk_x, authority_pk_y, authority_sk,
        out_values, out_pk_xs, out_pk_ys, out_rhos,
    };
    call_mint(w);
}

#[test]
fn test_mint_all_32_recipients() {
    // Mint to all 32 recipients with value 10 each = 320 total
    let authority_sk: Field = 0xfed001;
    let (authority_pk_x, authority_pk_y) = derive_pk(authority_sk);
    let asset_id: Field = 1;

    let mut out_values: [Field; 32] = [0; 32];
    let mut out_pk_xs: [Field; 32] = [0; 32];
    let mut out_pk_ys: [Field; 32] = [0; 32];
    let mut out_rhos: [Field; 32] = [0; 32];
    let mut cm_outs: [Field; 32] = [0; 32];

    for i in 0..32 {
        out_values[i] = 10;
        // Each recipient has a unique sk derived from index
        let r_sk = 0xaa0001 + (i as Field);
        let (r_pk_x, r_pk_y) = derive_pk(r_sk);
        out_pk_xs[i] = r_pk_x;
        out_pk_ys[i] = r_pk_y;
        out_rhos[i] = 5001 + (i as Field);

        let n = Note {
            value: 10, asset_id,
            owner_pk_x: r_pk_x, owner_pk_y: r_pk_y,
            rho: out_rhos[i],
        };
        cm_outs[i] = commitment(n);
    }

    let w = MintTestWitness {
        cm_outs, total_minted: 320, asset_id,
        authority_pk_x, authority_pk_y, authority_sk,
        out_values, out_pk_xs, out_pk_ys, out_rhos,
    };
    call_mint(w);
}

// --- Negative tests ---

#[test(should_fail_with = "Authority pk_x mismatch")]
fn test_reject_unauthorized_minter() {
    let mut w = build_valid_mint_witness();
    // Wrong authority sk -- derived pk won't match the public authority_pk
    w.authority_sk = 0xbadbad;
    call_mint(w);
}

#[test(should_fail_with = "Minted value mismatch")]
fn test_reject_supply_inflation() {
    let mut w = build_valid_mint_witness();
    // Declare total_minted = 500 but actual sum = 1000
    w.total_minted = 500;
    call_mint(w);
}

#[test(should_fail_with = "Output commitment mismatch")]
fn test_reject_output_commitment_tamper() {
    let mut w = build_valid_mint_witness();
    w.cm_outs[0] = w.cm_outs[0] + 1;
    call_mint(w);
}

#[test(should_fail_with = "Duplicate output commitment")]
fn test_reject_duplicate_outputs() {
    let mut w = build_valid_mint_witness();
    // Make output 1 identical to output 0
    w.out_values[1] = w.out_values[0];
    w.out_pk_xs[1] = w.out_pk_xs[0];
    w.out_pk_ys[1] = w.out_pk_ys[0];
    w.out_rhos[1] = w.out_rhos[0];
    w.cm_outs[1] = w.cm_outs[0];
    call_mint(w);
}

#[test(should_fail_with = "Output commitment mismatch")]
fn test_reject_wrong_asset_id() {
    let mut w = build_valid_mint_witness();
    // Changing asset_id changes all commitments
    w.asset_id = 99;
    call_mint(w);
}

#[test(should_fail)]
fn test_reject_overflow_value() {
    let mut w = build_valid_mint_witness();
    w.out_values[0] = 18446744073709551615 + 1;
    call_mint(w);
}

#[test(should_fail_with = "Minted value mismatch")]
fn test_reject_hidden_value_inflation() {
    let mut w = build_valid_mint_witness();
    // Inflate output 0 from 400 to 500, recompute its commitment,
    // but keep total_minted at 1000. Sum = 1100 != 1000.
    w.out_values[0] = 500;
    let note_0 = Note {
        value: 500, asset_id: w.asset_id,
        owner_pk_x: w.out_pk_xs[0], owner_pk_y: w.out_pk_ys[0],
        rho: w.out_rhos[0],
    };
    w.cm_outs[0] = commitment(note_0);
    call_mint(w);
}
