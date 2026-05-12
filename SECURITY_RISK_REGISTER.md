# Tonkl Protocol Security Risk Register

Date: 2026-05-12

Scope:
- `tonkl-node`: RPC, block validation, P2P, mempool, wallet CLI helpers
- `tonkl-prover`: circuit public-input binding and key derivation checks
- Cross-repo references where protocol behavior affects `tonkl-website` and Shlem

This register tracks risks found during the May 2026 hardening pass. It is intended to be copied into GitHub issues or committed as the canonical open-risk list for beta readiness.

## Severity

| Severity | Meaning |
| --- | --- |
| P0 Critical | Can permit forged state, fund loss, full consensus bypass, or exposure of critical secrets in beta/public environments. |
| P1 High | Material security issue that should be fixed before beta, but requires a second condition or limited environment to exploit. |
| P2 Medium | Important hardening, privacy, operational, or reliability work that should be scheduled before wider public testing. |
| P3 Low | Tracking, documentation, or cleanup item. |

## Fixed or Validated in This Pass

| ID | Status | Notes |
| --- | --- | --- |
| RESOLVED-001 | Fixed | RPC transaction submission now binds proofs to transaction public inputs before accepting writes. |
| RESOLVED-002 | Fixed | Mint policy and supply tracking now limit minting by configured asset policy. |
| RESOLVED-003 | Fixed | Circuit hash enforcement is wired into prover/node verification flows. |
| RESOLVED-004 | Fixed | HD key derivation parity was corrected and vector generation was added. |
| RESOLVED-005 | Fixed | Wallet CLI JSON outputs used by the website no longer expose scan private keys, spending keys, or token authority secrets. |
| RESOLVED-006 | Fixed 2026-05-12 | Peer/sync block validation now verifies transaction proofs, public input binding, and transaction hashes before state mutation. |
| RESOLVED-007 | Fixed 2026-05-12 | Missing verification keys now fail closed unless `--allow-unverified-local` is explicitly set for isolated loopback development. |
| RESOLVED-008 | Fixed 2026-05-12 | Missing RPC write authentication now fails closed unless `--allow-unauthenticated-rpc-local` is explicitly set for isolated loopback development. |
| RESOLVED-009 | Fixed 2026-05-12 | Wallet CLI now blocks raw private keys, passphrases, and seed words in argv by default, with env/stdin/key-index alternatives and an explicit isolated-test override. |
| RESOLVED-010 | Fixed 2026-05-12 | P2P now defaults to strict peer identity mode; open mDNS discovery is allowed only with `--allow-mdns-local` on loopback outside beta/production. |
| RESOLVED-011 | Fixed 2026-05-12 | Metadata-heavy RPC reads now require `TONKL_RPC_SECRET` unless `--allow-public-rpc-metadata` or isolated unauthenticated local mode is explicitly enabled. |

## Risk Status

| ID | Severity | Area | Status | Suggested GitHub Issue |
| --- | --- | --- | --- | --- |
| TONKL-SEC-001 | P0 Critical | Peer/synced block validation | Fixed 2026-05-12 | Reject peer/sync blocks unless every transaction proof and public input is verified |
| TONKL-SEC-002 | P0 Critical | Node verifier mode | Fixed 2026-05-12 | Fail closed when verification keys are missing outside explicit local dev mode |
| TONKL-SEC-003 | P1 High | RPC writes | Fixed 2026-05-12 | Require RPC write authentication for beta/public nodes |
| TONKL-SEC-004 | P1 High | Wallet CLI secrets | Fixed 2026-05-12 | Remove or deprecate secret-bearing CLI arguments before beta |
| TONKL-SEC-005 | P2 Medium | P2P identity | Fixed 2026-05-12 | Disable open mDNS/bootstrap peer trust outside local dev |
| TONKL-SEC-006 | P2 Medium | Public RPC privacy | Fixed 2026-05-12 | Review public access to encrypted notes, nullifiers, and metadata-heavy reads |

## TONKL-SEC-001: Peer/synced blocks bypass transaction proof verification

Severity: P0 Critical

Status: Fixed 2026-05-12

Original evidence before fix:
- `tonkl-node/src/block.rs` validated headers, duplicate nullifiers, state roots, and state application.
- `tonkl-node/src/block.rs` contained a production note that transaction proof verification was not performed in this path.
- `tonkl-node/src/node.rs` received P2P blocks and applied them through block validation without passing a proof verifier.
- `tonkl-node/src/p2p.rs` can gossip blocks from connected peers.

Impact:
- A peer or sync source may be able to provide a block whose state transition is internally consistent but whose transactions were never proven.
- If P2P or sync is enabled in a beta/public network, this can become a consensus and privacy-system bypass.

Recommendation:
- Pass `ProofVerifier` and mint policy context into block validation.
- Verify every transaction proof, circuit hash, and public-input binding before applying peer or synced blocks.
- Reject blocks if verification is disabled unless a local-only explicit dev flag is set.
- Add regression tests for forged peer blocks, missing proofs, wrong public inputs, wrong circuit hash, and duplicate nullifiers.

Acceptance criteria:
- A peer block containing an invalid transfer proof is rejected before state mutation.
- A peer block containing a valid proof with mismatched public inputs is rejected.
- Local dev tests can still run only when an explicit unverified/local flag is present.

Implementation notes:
- `validate_and_apply_block` now requires a `ProofVerifier`.
- Peer and sync paths pass the node verifier into block validation.
- Block validation checks transaction hash binding, public input binding, proof verification, nullifier conflicts, and state root before accepting external blocks.
- Regression tests cover disabled verifier rejection, missing VK rejection, bad transaction hash rejection, and public input mismatch rejection.

## TONKL-SEC-002: Node can run fail-open with proof verification disabled

Severity: P0 Critical

Status: Fixed 2026-05-12

Original evidence before fix:
- `tonkl-node/src/main.rs` created `ProofVerifier::disabled()` when `--vk-dir` was omitted.
- `tonkl-node/src/verifier.rs` returns success when the verifier is disabled, so startup now gates that mode before public/P2P/sync use.

Impact:
- A node operator can unintentionally run an accepting node with no proof checks.
- This is acceptable for isolated local development only, but dangerous for beta, public RPC, or P2P operation.

Recommendation:
- Replace implicit disabled verification with an explicit flag such as `--allow-unverified-local`.
- Refuse to start in unverified mode when binding to non-loopback addresses, when P2P is enabled, or when `TONKL_ENV=production`.
- Print a loud startup warning for explicit local-only unverified mode.

Acceptance criteria:
- Running without `--vk-dir` fails by default.
- Running without `--vk-dir --allow-unverified-local --bind 127.0.0.1` still supports local test flows.
- Running unverified with public bind or P2P fails at startup.

Implementation notes:
- `tonkl-node run` now fails without `--vk-dir` unless `--allow-unverified-local` is set.
- The local override is rejected with P2P, sync, non-loopback bind, or `TONKL_ENV=beta/production`.
- Unit tests cover loopback detection and each unsafe verifier-mode rejection path.

## TONKL-SEC-003: RPC write authentication is optional

Severity: P1 High

Status: Fixed 2026-05-12

Original evidence before fix:
- `tonkl-node/src/rpc.rs` treated an empty `TONKL_RPC_SECRET` as unrestricted development mode.
- Write paths such as `submit_tx`, `produce_block`, and encrypted note storage only required the secret when configured.

Impact:
- A publicly reachable node with no RPC secret can accept write attempts from anyone who can reach the RPC port.
- This can spam mempool, force block production in dev-style deployments, or store unwanted encrypted-note payloads.

Recommendation:
- Require `TONKL_RPC_SECRET` outside loopback-only local dev.
- Add an explicit local flag for unauthenticated write RPC.
- Make the wallet CLI and launch scripts pass the secret when configured.

Acceptance criteria:
- Public bind without `TONKL_RPC_SECRET` fails startup.
- Loopback local dev remains easy with an explicit dev flag.
- Tests cover authenticated and unauthenticated write attempts.

Implementation notes:
- `tonkl-node run` now requires `TONKL_RPC_SECRET` for write RPC methods unless `--allow-unauthenticated-rpc-local` is set.
- The local override is rejected with P2P, sync, non-loopback bind, or `TONKL_ENV=beta/production`.
- Local single-node integration scripts opt into the explicit local override.
- The multi-node launcher sets an RPC secret because it uses P2P/sync.

## TONKL-SEC-004: Manual CLI still accepts secrets in command-line arguments

Severity: P1 High

Status: Fixed 2026-05-12

Original evidence before fix:
- `tonkl-node/scripts/tonkl_wallet.py` supported secret-bearing flags including `--passphrase`, `--to-sk`, `--from-sk`, `--authority-sk`, `--recipient-sk`, raw address secret arguments, `import-note --sk`, `import-mint --sks`, and restore words through argv.

Impact:
- Secrets passed through command-line arguments can leak through shell history, process inspection, logs, screenshots, or crash reports.
- The website avoids these paths now, but manual beta users and scripts remain exposed.

Recommendation:
- Deprecate command-line secret arguments.
- Provide safer replacements: key index, environment variable, stdin prompt, encrypted wallet storage, or file descriptor input.
- Add warnings now, then remove secret argv support before public beta.

Acceptance criteria:
- Website and recommended scripts never pass private keys, mnemonic words, or passphrases through argv.
- Secret-bearing argv paths warn or fail unless an explicit unsafe dev flag is present.

Implementation notes:
- Secret-bearing argv inputs now fail by default with a clear explanation.
- Safer alternatives were added or documented: `--passphrase-stdin`, `--passphrase-env`, `--sk-env`, `--sks-env`, `--to-sk-env`, `--recipient-sk-env`, `--words-stdin`, `--words-env`, and key-index flows.
- `--allow-secret-argv` and `TONKL_ALLOW_SECRET_ARGV=1` remain available only for isolated tests.
- Launch/testnet quick-start text now points users toward key-index flows.

## TONKL-SEC-005: P2P peer trust and discovery are too open for beta

Severity: P2 Medium

Status: Fixed 2026-05-12

Original evidence before fix:
- `tonkl-node/src/p2p.rs` supports mDNS discovery and bootstrap peers.
- Peer identity is generated per run and is not yet bound to a validator set or allowlist.

Impact:
- Any discovered or configured peer can provide traffic to the node.
- Combined with block-verification gaps this becomes critical; after those are fixed it remains a DoS and network-integrity concern.

Recommendation:
- Disable mDNS outside explicit local dev.
- Add a peer allowlist or validator identity binding for beta.
- Sign validator-produced blocks and verify block producer identity.

Acceptance criteria:
- Beta nodes connect only to configured/allowed peers.
- Blocks include a producer signature or equivalent authorization signal.

Implementation notes:
- P2P now defaults to strict mode with mDNS disabled unless `--allow-mdns-local` is explicitly set.
- `--allow-mdns-local` is rejected for non-loopback P2P binds and when `TONKL_ENV` is beta/production.
- Strict bootstrap multiaddrs must include `/p2p/<peer-id>`, or trusted peer IDs must be supplied with `--trusted-peer`.
- Gossip messages from untrusted peer IDs are dropped before they reach node state handling.
- The local multi-node launcher opts into `--allow-mdns-local` explicitly for loopback-only development.

Remaining follow-up:
- Validator-produced block signatures are still not implemented; keep this as a consensus-authentication follow-up before mainnet.

## TONKL-SEC-006: Public RPC/read paths expose metadata-heavy chain data

Severity: P2 Medium

Status: Fixed 2026-05-12

Original evidence before fix:
- RPC and website proxy paths expose encrypted notes, nullifiers, state roots, block history, and status metadata.
- `get_encrypted_notes` is capped, which helps DoS, but privacy metadata still deserves a policy decision.

Impact:
- Public scraping of nullifiers and encrypted-note metadata can support traffic analysis and wallet timing inference.

Recommendation:
- Decide which read APIs are intentionally public explorer data and which are wallet-sensitive.
- Session-gate wallet-sensitive reads.
- Add tighter rate limits and pagination for public explorer reads.

Acceptance criteria:
- Public explorer endpoints are documented.
- Wallet-sensitive reads require session or local-only access.

Implementation notes:
- `get_merkle_proof`, `get_nullifier_status`, `get_block`, `get_blocks_range`, and `get_encrypted_notes` now require `TONKL_RPC_SECRET` by default.
- `get_status` and `get_merkle_root` remain public low-sensitivity read endpoints.
- `--allow-public-rpc-metadata` must be set deliberately to expose metadata-heavy read methods for explorer-style deployments.
- `--allow-unauthenticated-rpc-local` continues to expose reads only in isolated loopback local development.
- Python clients automatically append `TONKL_RPC_SECRET` to protected read calls when the environment variable is set.
- Chain sync uses `TONKL_SYNC_RPC_SECRET` or falls back to `TONKL_RPC_SECRET` for protected `get_blocks_range` calls.

## Suggested GitHub Issue Split

Create these issues in `tonklTom/tonkl-protocol`:

1. `[P0] Reject peer/sync blocks unless every transaction proof is verified` - fixed locally 2026-05-12
2. `[P0] Fail closed when verification keys are missing outside explicit local dev` - fixed locally 2026-05-12
3. `[P1] Require RPC write authentication for beta/public nodes` - fixed locally 2026-05-12
4. `[P1] Remove secret-bearing wallet CLI arguments before beta` - fixed locally 2026-05-12
5. `[P2] Add P2P peer allowlist or validator identity binding` - fixed locally 2026-05-12 for peer allowlisting; validator block signatures remain follow-up
6. `[P2] Classify and gate metadata-heavy RPC read endpoints` - fixed locally 2026-05-12

## Recheck Commands

Recommended local checks after fixes:

```bash
cd ~/Desktop/tonkl-protocol
cargo test --manifest-path tonkl-node/Cargo.toml
cargo test --manifest-path tonkl-prover/Cargo.toml
rg "ProofVerifier::disabled|verify stub|--to-sk|--from-sk|--authority-sk|--passphrase|TONKL_RPC_SECRET" tonkl-node tonkl-prover
```
