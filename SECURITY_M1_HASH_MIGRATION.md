# M1 — Poseidon2 Hash Domain-Separation Migration

**Status:** ✅ APPLIED and verified live (2026-06-08).

Per-arity capacity IVs (2/3/7) are in place across all four hash sites
(`tonkl-lib/src/hash.nr`, `tonkl-transfer/src/hash.nr`, `tonkl-hasher/src/main.nr`,
`tonkl-prover/src/lib.rs`). Circuits were recompiled, all four verification keys
regenerated, chain/wallet state wiped, and genesis regenerated. Verified end to
end: Noir↔Rust parity tests pass (`rust_witness_matches_nargo_reference`,
`derive_note_sk_cross_language_parity`, `build_tree_four_leaves_matches_merge_circuit`),
all four circuits' `nargo test` pass, node 49+15 tests pass, and a live faucet
transfer verified against the regenerated VK on a single-node testnet.

This migration and its regenerated VKs must be committed atomically — never split
the hash sources from the `vks/` artifacts, or a checkout will mis-verify.

The remainder of this document is the original runbook, retained for reference
and for regenerating against a clean checkout.

## Why

The current sponge has no input-length separation, so `hash_2(a,b)` and
`hash_3(a,b,0)` produce identical outputs (both `p2([a,b,0,0])[0]`). The fix adds
a per-arity constant in the **capacity** slot (`state[3]`), which is never
overwritten by input, so each arity is domain-separated:

- `hash_2` capacity IV = `2`
- `hash_3` capacity IV = `3`
- `hash_7` capacity IV = `7`

The empty-subtree convention stays a literal `Field(0)` (it is not a hash output),
so no precomputed empty-node tables change.

## ⚠️ This is a BREAKING change

It changes every commitment, nullifier, and Merkle root. You MUST recompile all
circuits, regenerate verification keys, wipe all chain + wallet state, and
regenerate genesis. Do it as one atomic change — a partial apply (Noir without
Rust, or without regenerated VKs) bricks the protocol.

## Files to edit (keep all four byte-identical in behaviour)

1. `tonkl-lib/src/hash.nr`        — canonical (used by all circuits via note.nr)
2. `tonkl-transfer/src/hash.nr`   — local copy (transfer circuit tests)
3. `tonkl-hasher/src/main.nr`     — hasher circuit copy
4. `tonkl-prover/src/lib.rs`      — Rust prover (node tree + wallet both use this)

### Noir — replace the three function bodies (files 1, 2, 3)

```rust
pub fn hash_2(a: Field, b: Field) -> Field {
    // capacity IV = 2 (arity tag) — domain-separates hash_2 from hash_3/hash_7
    let state = p2([a, b, 0, 2]);
    state[0]
}

pub fn hash_3(a: Field, b: Field, c: Field) -> Field {
    // capacity IV = 3 (arity tag)
    let state = p2([a, b, c, 3]);
    state[0]
}

pub fn hash_7(
    a: Field, b: Field, c: Field,
    d: Field, e: Field, f: Field,
    g: Field,
) -> Field {
    // capacity IV = 7 (arity tag); IV is preserved across all 3 permutations
    let s1 = p2([a, b, c, 7]);
    let s2 = p2([s1[0] + d, s1[1] + e, s1[2] + f, s1[3]]);
    let s3 = p2([s2[0] + g, s2[1], s2[2], s2[3]]);
    s3[0]
}
```

(In `tonkl-hasher/src/main.nr` these are `fn` not `pub fn` — keep that, change only the bodies.)

### Rust — `tonkl-prover/src/lib.rs` (must match the Noir above exactly)

```rust
pub fn poseidon2_hash_2(a: FieldElement, b: FieldElement) -> Result<FieldElement> {
    // capacity IV = 2 (arity tag), must match hash.nr
    let state = p2([a, b, FieldElement::zero(), FieldElement::from(2u128)])?;
    Ok(state[0])
}

pub fn poseidon2_hash_3(a: FieldElement, b: FieldElement, c: FieldElement) -> Result<FieldElement> {
    let state = p2([a, b, c, FieldElement::from(3u128)])?;
    Ok(state[0])
}

pub fn poseidon2_hash_7(
    a: FieldElement, b: FieldElement, c: FieldElement,
    d: FieldElement, e: FieldElement, f: FieldElement,
    g: FieldElement,
) -> Result<FieldElement> {
    let s1 = p2([a, b, c, FieldElement::from(7u128)])?;
    let s2 = p2([s1[0] + d, s1[1] + e, s1[2] + f, s1[3]])?;
    let s3 = p2([s2[0] + g, s2[1], s2[2], s2[3]])?;
    Ok(s3[0])
}
```

## Regeneration runbook (run in order)

```bash
cd ~/Desktop/tonkl-protocol

# 1) Apply the four edits above.

# 2) Recompile circuits + regenerate verification keys
for c in tonkl-transfer tonkl-merge tonkl-split tonkl-mint; do
  ( cd "$c" && nargo compile && bb write_vk -b target/*.json -o target/vk )
done
# hasher (only if you build/use it):
# ( cd tonkl-hasher && nargo compile )

# 3) Refresh the VK directory the NODE loads from.
#    The node reads vk_dir/<transfer|merge|split|mint>/vk. If you keep a top-level
#    vks/ dir, copy the freshly written keys into it:
for c in transfer merge split mint; do
  mkdir -p "vks/$c"
  cp "tonkl-$c/target/vk" "vks/$c/vk"
done

# 4) Rebuild Rust (the prover binds to the new transfer circuit hash at build time)
( cd tonkl-prover && cargo build --release )
( cd tonkl-node   && cargo build --release )

# 5) Wipe ALL stale state (old hashes are now invalid)
rm -rf ~/.tonkl                 # wallet DBs + default node data
#   ALSO remove any testnet data dirs your launcher creates, e.g.:
#   rm -rf ./testnet-data /tmp/tonkl-* 2>/dev/null

# 6) Relaunch — regenerates genesis with the new hash
./tonkl testnet start -n 1

# 7) Verify everything agrees on the new hash
( cd tonkl-prover && cargo test )
( cd tonkl-node   && cargo test )
for c in tonkl-transfer tonkl-merge tonkl-split tonkl-mint; do ( cd "$c" && nargo test ); done
```

## Acceptance check

After relaunch, create a wallet, faucet, prepare notes, and send — a full
shielded transfer must verify and confirm end-to-end. If proofs fail to verify,
the Noir and Rust hash bodies are out of sync (re-diff files 1–4).

## Rollback

`git checkout -- tonkl-lib/src/hash.nr tonkl-transfer/src/hash.nr tonkl-hasher/src/main.nr tonkl-prover/src/lib.rs`,
then repeat steps 2–6 to regenerate against the old hash.
