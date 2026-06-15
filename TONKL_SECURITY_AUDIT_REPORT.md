# Tonkl Protocol — Security Audit Report

**Engagement:** Pre-launch defensive security review
**Target:** Tonkl Protocol — privacy blockchain (Noir/UltraHonk/Barretenberg, BN254, Poseidon2, Grumpkin)
**Repositories:** `tonkl-protocol` (node, circuits, prover, wallet), `tonkl-website` (web wallet)
**Date:** 2026-06-08
**Status of software:** Alpha / pre-public-testnet
**Methodology:** Manual source review across five focused passes (ZK circuits, consensus/state, supply/mint, hash migration, wallet/witness), invariant analysis, code/spec cross-checking, and local test verification. No exploitation against public networks.

> **Disclaimer.** This is a manual review, not a formal verification or a substitute for a dedicated external cryptographic/circuit audit. The most dangerous failure mode for a shielded pool — a missing circuit constraint that still produces a verifying proof — is silent. An independent circuit audit remains a release blocker (B4).

---

## 1. Executive Summary

The Tonkl protocol is well-constructed at the cryptographic core: the Noir circuits enforce value conservation, correct 64-bit range checks, real Grumpkin EC ownership (both key coordinates), domain-separated commitments/nullifiers, Merkle membership, output-commitment binding, and intra-transaction nullifier/commitment distinctness. Every circuit public input is constrained. The node binds proof public inputs to transaction fields before mutating state, enforces nullifier double-spend prevention at three layers, and enforces a fail-closed mint-authority policy.

This engagement found and remediated one **critical** counterfeiting vulnerability and several **high**/**medium** issues. After remediation, the protocol's consensus-layer soundness is materially stronger, and the highest-value fixes have been verified live on a single-node testnet.

### Findings at a glance

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TKL-001 | Critical | Missing Merkle anchor validation (counterfeiting from a forged tree) | ✅ Fixed + verified |
| TKL-002 | High | Block-apply path coverage gap (leader loop skipped mint policy + supply recording) | ✅ Fixed |
| TKL-003 | High | Fail-open proof verification when verifier disabled | ✅ Fixed |
| TKL-004 | High | Consensus checks enforced in callers, not the validator (regression risk) | ✅ Fixed + verified (cargo test) |
| TKL-005 | Medium | Poseidon2 sponge lacked input-length domain separation (`hash_2(a,b)==hash_3(a,b,0)`) | ✅ Fixed + migrated |
| TKL-006 | Low | Anchor retention/pruning + snapshot-backfill policy undefined (anchors ARE persisted) | ⚠️ Open (non-blocking) |
| TKL-007 | Medium | Minted-supply accounting not atomic with block apply | ⚠️ Open |
| TKL-008 | Medium | No duplicate-commitment guard on tree insertion | ⚠️ Open |
| TKL-009 | Medium | M1 doc-vs-reality and non-atomic git state | ✅ Doc fixed; commit pending |
| TKL-010 | Low | Two VK locations (`target/vk` vs `vks/`) can silently drift | ⚠️ Open |
| TKL-011 | Low | Mempool eviction-when-full is a broken placeholder | ⚠️ Open |
| TKL-012 | Low | Round-robin consensus: no finality / equivocation handling | Accepted (permissioned) |
| TKL-013 | Info | merge/split lack a non-zero-output assertion | Info |
| TKL-014 | Info | Transaction fee is burned, not collected | Info |
| TKL-015 | Info | README understates P2P trust (code is stricter) | Doc |
| TKL-016 | Info | `zk_attack_matrix.md` omits the node-anchor control for ZK-007 | Recommendation |
| TKL-017 | Low | Wallet should re-anchor on stale/unknown-anchor rejection | ⚠️ Open |

### Release blockers
- **B1** — Commit the M1 hash migration atomically (four implementation sites + four VKs + doc). *Staged; confirm single-commit atomicity before push.*
- **B2** — ✅ **Satisfied.** Anchor + mint enforcement consolidated inside the validator; node suite green: `cargo test --manifest-path tonkl-node/Cargo.toml` → 50 lib + 15 main + doc tests passing.
- **B4** — Independent external circuit audit. *Open — required before any value-bearing or open-validator deployment.*
- ~~B3 (anchor-history window)~~ — **withdrawn**; anchors are persisted in `chain_meta` (see TKL-006, downgraded to Low/non-blocking).

---

## 2. Scope & Threat Model

**In scope:** `tonkl-transfer`, `tonkl-split`, `tonkl-merge`, `tonkl-mint`, `tonkl-lib` (circuits); `tonkl-prover` (Rust hash/commitment/nullifier/Merkle parity); `tonkl-node` (`block.rs`, `state.rs`, `rpc.rs`, `mempool.rs`, `consensus.rs`, `p2p.rs`, `verifier.rs`); wallet/witness tooling (`tonkl_wallet.py`, `witness_builder.py`, `node_client.py`); the M1 Poseidon2 migration and VK/state consistency.

**Threat model (per the project's own `security/` pack):** the attacker can build arbitrary witnesses, tamper with public inputs, submit proofs via RPC, replay nullifiers, alter asset IDs, and exploit field arithmetic. The attacker must not be able to mutate node state unless the proof and every public transaction field satisfy protocol rules. For multi-node operation the testnet is assumed permissioned with trusted validators (see TKL-012).

**Core invariants under test:**
1. Value conservation (Σin = Σout + fee) with no field-wraparound value creation.
2. Spend authority via EC key ownership; correct nullifier derivation; no double-spend.
3. Membership proofs bind to a *committed* Merkle root (anchor).
4. Mint only by registered authority, within supply caps.
5. Every public input constrained in-circuit; node binds public inputs to applied fields.
6. All block-apply paths enforce the same rules.

---

## 3. Severity Definitions

- **Critical** — Direct break of money supply or ownership soundness (counterfeiting, theft, undetectable double-spend).
- **High** — A path or condition that can lead to a critical outcome, or removes a key defense under realistic operation.
- **Medium** — Soundness-relevant weakness not directly exploitable today, correctness/availability bug with security impact, or a defense that is fragile/easy to regress.
- **Low / Info** — Hardening, documentation, or design clarity.

---

## 4. Detailed Findings

### TKL-001 — Missing Merkle anchor validation *(Critical, Fixed)*

**Location:** `tonkl-node/src/rpc.rs::submit_tx`, `tonkl-node/src/block.rs` (apply path), `state.rs`.

**Description.** Transfer/split/merge circuits prove membership of input notes against a `merkle_root` *supplied by the prover*. The node validated public-input binding and verified the proof, but never checked that `merkle_root` was a root the chain had actually committed. The `StaleTransaction` error type existed but was never constructed — the check was scaffolded and never implemented.

**Impact.** An attacker can construct a private Merkle tree containing fabricated high-value notes they "own," generate a cryptographically valid transfer proof anchored to that fake root, and submit it. The node accepts the proof and applies the output commitments + nullifiers to the *real* tree — minting value from nothing, for any asset, bypassing the mint authority entirely. This is the Zcash-class counterfeiting failure.

**Remediation (applied).** Added a persistent anchor set to `ChainMeta` (`record_anchor` / `is_known_anchor`). Every committed root (genesis, every produced/applied block) is recorded; the live root is seeded at startup. Input-consuming transactions whose `merkle_root` is not a known anchor are rejected at mempool admission and at block application. Mint is exempt (no inputs).

**Verification.** Unit tests (`test_ensure_known_anchors_rejects_unknown_root`, `test_apply_rejects_unknown_anchor_before_mutation`) and a live single-node testnet transfer that was accepted because it anchored to the node's real current root.

---

### TKL-002 — Block-apply path coverage gap *(High, Fixed)*

**Location:** `tonkl-node/src/main.rs` (leader production loop).

**Description.** Two near-duplicate block producers existed (`consensus.rs::produce_block` and the live leader loop in `main.rs`). The `main.rs` loop applied mempool transactions and built blocks **without** calling the mint policy (`validate_block_mints`) or recording minted supply (`record_block_mints`).

**Impact.** On the live production path, per-asset supply caps were not accumulated, weakening the supply-cap guarantee over multiple blocks.

**Remediation (applied).** The leader loop now enforces the consensus gate and records supply. As of this engagement (TKL-004) both are funneled through a single `enforce_consensus_rules` function, eliminating the duplication risk.

---

### TKL-003 — Fail-open verification when verifier disabled *(High, Fixed)*

**Location:** `tonkl-node/src/rpc.rs::submit_tx`.

**Description.** Proof verification ran only `if state.verifier.is_enabled()`. A node started without verification keys accepted unverified transactions into the mempool, which the producer then committed.

**Impact.** A misconfigured node (no VKs / no `bb`) performed zero proof checking; a single-node testnet in that state accepted arbitrary (potentially forged) transactions.

**Remediation (applied).** `submit_tx` now refuses write transactions when the verifier is disabled, unless an explicit `TONKL_ALLOW_UNVERIFIED_TX` dev override is set. Default is fail-closed.

---

### TKL-004 — Consensus checks enforced in callers, not the validator *(High, Fixed this engagement)*

**Location:** `tonkl-node/src/block.rs` and all apply paths.

**Description.** After TKL-001/002, the anchor and mint checks were enforced correctly but *scattered* across each apply path's caller. A future apply path that forgot one would silently reintroduce counterfeiting or unauthorized minting — exactly the class of regression that produced TKL-002.

**Remediation (applied this engagement).** Introduced a single `enforce_consensus_rules(chain_meta, mint_policy, txs)` gate in `block.rs` that performs anchor validation + mint policy. It is called **inside** `validate_and_apply_block` (covering the untrusted P2P/sync ingestion paths, which can no longer skip it) and explicitly by the direct-apply production paths (`consensus.rs`, `main.rs` leader loop, `rpc.rs::produce_block`), so all six paths share one enforcement implementation. Added `ValidationError::MintPolicy`. Added regression tests: `test_apply_rejects_unknown_anchor_before_mutation` (forged anchor rejected before mutation) and `test_validate_rejects_unregistered_mint` (mint without registered authority rejected before mutation); wrong-authority rejection is covered by `rpc::mint_policy_rejects_unregistered_or_wrong_authority`, which the gate now delegates to.

**Verification.** ✅ Confirmed: `cargo test --manifest-path tonkl-node/Cargo.toml` passes (50 lib + 15 main + doc tests), and `git diff --cached --check` is clean. All call sites updated to the new validator signature; the gate's negative tests (`test_apply_rejects_unknown_anchor_before_mutation`, `test_validate_rejects_unregistered_mint`) pass.

---

### TKL-005 — Poseidon2 sponge lacked input-length domain separation *(Medium, Fixed)*

**Location:** `tonkl-lib/src/hash.nr`, `tonkl-transfer/src/hash.nr`, `tonkl-hasher/src/main.nr`, `tonkl-prover/src/lib.rs`.

**Description.** The sponge had no arity tag, so `hash_2(a,b)` and `hash_3(a,b,0)` produced identical output (both `p2([a,b,0,0])[0]`), despite a code comment claiming they were domain-separated. Merkle-node hashing (`hash_2`) and nullifier hashing (`hash_3`) thus shared a hash function in the zero-padded case.

**Impact.** Not directly exploitable in the current circuit set (spending requires EC ownership; `sk=0` is rejected; commitments use `hash_7`), but it violated the protocol's stated domain-separation guarantees and was fragile against future reuse of `hash_3` with attacker-controllable trailing zeros or a leaf/internal-node second-preimage.

**Remediation (applied — M1 migration).** Per-arity capacity IVs (2/3/7) added so `hash_2(a,b) ≠ hash_3(a,b,0)`. The change spans **two languages but four implementation sites**, all of which must be kept byte-identical: `tonkl-lib/src/hash.nr`, `tonkl-transfer/src/hash.nr`, `tonkl-hasher/src/main.nr` (Noir), and `tonkl-prover/src/lib.rs` (Rust). Python carries no separate hash implementation — it delegates note math to the Rust prover — so no Python change was needed, but **all four sites above must be committed together** or a checkout will mis-verify. Circuits recompiled, all four VKs regenerated, chain/wallet state wiped, genesis regenerated.

**Verification.** Noir↔Rust parity tests pass (`rust_witness_matches_nargo_reference`, `derive_note_sk_cross_language_parity`, `build_tree_four_leaves_matches_merge_circuit`); all four circuits' `nargo test` pass; node tests pass; a live faucet transfer verified against the regenerated VK.

---

### TKL-006 — Anchor retention / backfill policy undefined *(Low, Open — non-blocking)*

**Location:** `tonkl-node/src/state.rs::record_anchor` / `is_known_anchor`, startup seeding in `main.rs`.

**Description.** Anchors **are persisted**: `record_anchor` writes each committed root into the sled-backed `chain_meta` tree and `is_known_anchor` reads from it, so the full anchor history survives process restarts (correcting an earlier draft of this finding that claimed anchor history was process-local — it is not). Two narrower items remain: (a) there is no retention/pruning policy, so the anchor set grows unbounded with chain height; and (b) a node that bootstraps from a state snapshot instead of replaying blocks from genesis would not have historical anchors recorded, so snapshot/legacy-chain backfill is undefined. The current sync path replays blocks and records each root, so neither is a current correctness problem.

**Impact.** Storage growth over time; a future snapshot-based bootstrap would require an anchor backfill step. No soundness impact and no current-liveness impact (restarts retain history).

**Recommendation.** Define an anchor retention/pruning policy (e.g., a bounded recent-root window with periodic compaction) and an anchor-backfill step for any non-replay bootstrap. **Not a release blocker.**

---

### TKL-007 — Minted-supply accounting not atomic with apply *(Medium, Open)*

**Location:** `tonkl-node/src/rpc.rs::record_block_mints`, `state.rs::ChainMeta`.

**Description.** `record_block_mints` is a separate sled write performed after `validate_and_apply_block`. If the process dies between commitment insertion and supply recording, a subsequent `validate_block_mints` reads a stale (lower) cumulative supply.

**Impact.** A crash at the wrong moment could allow the supply cap to be exceeded by up to one block's mint volume on restart.

**Recommendation.** Make supply recording part of the same atomic apply, or recompute minted supply from chain history on startup.

---

### TKL-008 — No duplicate-commitment guard on insertion *(Medium, Open)*

**Location:** `tonkl-node/src/state.rs::NoteTree::insert`.

**Description.** The tree appends commitments unconditionally. If the same commitment is inserted at two leaves, both share one nullifier; only one is ever spendable (the nullifier set blocks the second).

**Impact.** Permanent value loss for the duplicate note (not a double-spend). Low severity but a real correctness gap.

**Recommendation.** Reject insertion of an already-present commitment, or explicitly document the value-loss semantics.

---

### TKL-009 — M1 doc-vs-reality and non-atomic git state *(Medium, Doc fixed)*

**Location:** `SECURITY_M1_HASH_MIGRATION.md`, repository git state.

**Description.** The migration doc stated "Drafted, NOT applied" while the hash sources and VKs were in fact modified and regenerated in the working tree — an auditor would have concluded the hash was unchanged. Separately, the M1 changes were uncommitted while dependent fixes were committed; a partial commit (sources without VKs, or vice-versa) would mis-verify.

**Remediation.** Doc updated to "APPLIED + verified" with details. The migration must be committed atomically (all four sources + four VKs + doc in one commit). **Release blocker B1.**

---

### TKL-010 — Two VK locations can drift *(Low, Open)*

**Location:** `tonkl-*/target/vk/vk` (launcher source via `setup_vk_dir`/`find_vk`) and tracked `vks/*/vk`.

**Description.** The launcher loads VKs from each circuit's `target/`; the repo also tracks a top-level `vks/`. Both were refreshed during M1, but they can desynchronize silently because only `target/` is used at runtime.

**Recommendation.** Make `vks/` the single source the launcher reads, or stop tracking `vks/` and treat `target/` as canonical with a regeneration step in CI.

---

### TKL-011 — Mempool eviction is a broken placeholder *(Low, Open)*

**Location:** `tonkl-node/src/mempool.rs::submit`.

**Description.** When the mempool is full, `submit` returns `MempoolError::DuplicateTransaction` (a placeholder) and never evicts by fee.

**Impact.** Availability: under load the node cannot accept higher-fee transactions, and returns a misleading error. No soundness impact.

**Recommendation.** Implement fee-based eviction with a min-priority structure; return a correct "mempool full" error.

---

### TKL-012 — Round-robin consensus: no finality / equivocation handling *(Low, Accepted for permissioned testnet)*

**Location:** `tonkl-node/src/consensus.rs`, `p2p.rs`.

**Description.** Leader selection is deterministic round-robin with no BFT finality, equivocation detection, or fork-choice. A malicious leader cannot forge state (peers re-validate every block, including the consensus gate) but can withhold (liveness) or, in multi-node operation, produce two blocks at one height with no resolution.

**Impact.** Acceptable only for a permissioned testnet with trusted validators. Must be documented as such; not suitable for an open validator set without a real consensus protocol.

---

### TKL-013 — merge/split lack a non-zero-output assertion *(Info)*

The transfer circuit asserts a non-zero primary output; merge/split do not. Value conservation prevents value creation, so this is not a soundness issue, but a fully-zero split/merge burns the input to fee with no output note. Add an explicit assertion or document the intent.

### TKL-014 — Fee is burned, not collected *(Info)*

`Σinputs = Σoutputs + fee` with no fee-recipient note; the fee value is destroyed. Fine for a zero-fee testnet; revisit before introducing a fee market.

### TKL-015 — README understates P2P trust *(Info / Doc)*

The README describes P2P as "unauthenticated." The code is stricter: `gossipsub::ValidationMode::Strict` and `peer_is_trusted` drop gossip from untrusted peers outside local mDNS dev mode, and every ingested block is fully re-validated. Update the documentation to reflect the stronger reality.

### TKL-016 — Attack matrix omits the node-anchor control *(Info / Recommendation)*

`security/zk_attack_matrix.md` maps ZK-007 ("bad Merkle path or root") to circuit-side root recomputation only — it does not list the node's "anchor must be a committed root" control, which is exactly TKL-001. Add a row (e.g., ZK-019) covering node-side anchor validation, mapped to the new Rust tests.

### TKL-017 — Wallet should re-anchor on stale rejection *(Low, Open)*

`tonkl_wallet.py` builds witnesses against the node's current root. Combined with TKL-006, a wallet holding a slightly-stale proof across a node restart receives an "unknown anchor" rejection. The wallet should re-fetch the root and rebuild on such rejections rather than surfacing a hard error.

---

## 5. Positive Observations

- **Circuit soundness.** All four circuits enforce value conservation, correct `u64` range checks (preventing field-wraparound value creation), real Grumpkin EC ownership checking both pk coordinates, correct nullifier derivation and intra-tx distinctness, output-commitment binding and distinctness, asset binding via commitments, and — verified across transfer/split/merge/mint — **every public input is constrained**.
- **Node binding.** `validate_public_inputs_match_fields` binds proof public inputs to the transaction's commitments/nullifiers/root/fee/asset before any state mutation.
- **Double-spend defense in depth.** Nullifier checks at mempool admission, intra-block, and against the persistent set.
- **Mint policy fail-closed.** Unregistered assets cannot be minted; authority pk is bound to the registered per-asset key; supply caps enforced (now on all paths).
- **P2P.** Trusted-peer gossip plus full block re-validation means peer trust affects only DoS, not soundness.
- **Wallet.** Note math delegated to a single Rust implementation (no Python/Rust/Noir triple-drift); spent/stale notes filtered at selection and re-checked at the node.
- **Web wallet** (`tonkl-website`, reviewed in a companion pass — see §5.1 for evidence). Arg-array subprocess spawns (no shell injection), read-only RPC proxy whitelist, session auth, output sanitization, CORS/security headers, secrets gitignored.

### 5.1 Web wallet — review evidence

The `tonkl-website` claims above were reviewed at the source level in a companion pass. This protocol audit's primary scope is the node/circuits/prover/wallet-CLI; the web wallet is a separate repository and warrants its own dedicated review and test suite before launch. Evidence for the claims made:

| Claim | Evidence (file) |
|-------|-----------------|
| No shell injection | All API routes invoke `spawn(PYTHON, args, …)` with **array** args and `stdio` pipes — no `shell: true`, no `exec`. Sites: `src/app/api/{send,faucet,onboard,wallet,prepare-spendable}/route.ts`. |
| Read-only RPC proxy whitelist | `src/app/api/node/route.ts` — `ALLOWED_METHODS` set excludes write methods (`submit_tx`, `produce_block`); non-listed methods rejected. |
| Session auth | `src/lib/session.ts` (`createSession`/`validateSession`/`requireSession`) + `getSessionPassphrase`; protected routes call `requireSession`. |
| Output sanitization | `sanitizeOutput` / `redactWalletOutput` in `send`, `wallet`, and `prepare-spendable` routes redact paths, long hex, and secret fields. |
| CORS + security headers | `src/middleware.ts` — `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, origin-scoped CORS. |
| Secrets gitignored | `.env.local` matched by `.gitignore` and absent from git history (`git check-ignore` / `git log --all -- .env.local`). |

**Caveat.** This is source-level inspection, not a penetration test of the web wallet. A dedicated web-application security review (auth/session lifecycle, rate-limit bypass, SSRF on the node proxy, dependency audit) is recommended before public exposure.

---

## 6. Test Coverage & Attack-Matrix Mapping

The project's `zk_attack_matrix.md` (ZK-001…ZK-018) is largely covered by circuit `should_fail` tests and Rust state/RPC tests. Gaps and additions from this engagement:

- **ZK-007 (bad root):** circuit recomputation tested; **node anchor control added (TKL-001)** with new tests `test_ensure_known_anchors_rejects_unknown_root`, `test_apply_rejects_unknown_anchor_before_mutation`. Recommend adding matrix row ZK-019 (TKL-016).
- **ZK-011/ZK-013 (mint authority/supply):** covered by `rpc::mint_policy_*` tests + new `test_validate_rejects_unregistered_mint`.
- **ZK-015 (proof verifies but fields differ):** covered by `test_external_block_rejects_public_input_mismatch_before_mutation`.
- **ZK-018 (wallet selects spent note):** wallet `get_unspent` filtering + node nullifier rejection.

**Recommended additional local-only tests:**
1. Split/merge output-sum > input (conservation failure).
2. Merge reusing one note in two input slots (duplicate-nullifier failure).
3. Restart node mid-testnet, submit a pre-restart-anchored tx (demonstrates TKL-006).
4. Duplicate-commitment insertion across two blocks (TKL-008).
5. Mempool-full higher-fee submission (TKL-011).
6. CI check asserting identical arity IVs across all four hash sites and `hash_2(a,b) ≠ hash_3(a,b,0)` (locks in TKL-005).

---

## 7. Remediation Status & Release Blockers

**Fixed and verified:** TKL-001, TKL-002, TKL-003, TKL-005 (verified live); TKL-004 (verified via `cargo test`); TKL-009 (doc corrected).
**Open before public testnet:** TKL-007, TKL-008, TKL-010, TKL-011, TKL-017 (all non-blocking hardening).
**Open, non-blocking:** TKL-006 (anchor retention/backfill policy).
**Accepted (documented constraint):** TKL-012.

**Release blockers:**
- **B1** — Atomic M1 commit (four implementation sites + four VKs + doc). *Staged; confirm atomicity before push.*
- **B2** — ✅ Satisfied: consensus gate inside the validator, node suite green (`cargo test`: 50 lib + 15 main + doc).
- **B4** — Independent external circuit audit. The in-circuit constraints reviewed here appear sound, but a manual read is not an audit, and the failure mode is silent.
- *B3 (anchor-history window) withdrawn — anchors are persisted; see TKL-006.*

---

## 8. Conclusion

The core cryptography and circuit design are solid. The most serious issue — a node-side counterfeiting hole (TKL-001) — was a missing validation, not a broken circuit, and is now closed and verified. The remaining work is operational and architectural hardening (anchor windowing, atomic supply accounting, duplicate-commitment guard, VK source-of-truth) plus the non-negotiable external circuit audit before any value-bearing or open-validator deployment. With B1–B4 addressed, Tonkl is a credible candidate for a permissioned closed testnet.

*End of report.*
