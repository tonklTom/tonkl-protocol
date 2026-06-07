# ZK Attack Matrix

This matrix turns the Zcash Orchard lesson into Tonkl-specific checks. Each
attack should fail deterministically.

| ID | Attack | Target | Expected control | Current check |
| --- | --- | --- | --- | --- |
| ZK-001 | Output value exceeds input value | transfer, split, merge | value conservation assertion | Noir `should_fail` tests |
| ZK-002 | Fee or amount uses field wraparound | all value circuits | `assert_value_range` | Noir overflow tests |
| ZK-003 | Same note used twice in one transaction | transfer, merge | duplicate nullifier rejection | Noir and Rust tests |
| ZK-004 | Replayed spent note | node state | nullifier set duplicate rejection | Rust state/block tests |
| ZK-005 | Wrong spending key | transfer, split, merge | `assert_ownership` | Noir `should_fail` tests |
| ZK-006 | Forged nullifier | transfer, split, merge | nullifier recomputation | Noir `should_fail` tests |
| ZK-007 | Bad Merkle path or root | transfer, split, merge | Merkle root recomputation | Noir `should_fail` tests |
| ZK-008 | Public input commitment tamper | RPC/block validation | public input field binding | Rust RPC/block tests |
| ZK-009 | Public input asset ID tamper | RPC/block validation | public input field binding | Rust RPC/mint tests |
| ZK-010 | Cross-asset transfer or merge | circuits and wallet | asset ID in commitment and wallet filters | Noir/wallet tests |
| ZK-011 | Mint with wrong authority key | mint and node policy | authority proof plus registered-authority policy | Noir/Rust tests |
| ZK-012 | Mint total does not match outputs | mint | minted value sum assertion | Noir `should_fail` tests |
| ZK-013 | Mint exceeds supply cap | node policy | chain metadata supply limit | Rust RPC tests |
| ZK-014 | Duplicate mint commitments | mint | pairwise commitment uniqueness | Noir `should_fail` tests |
| ZK-015 | Proof verifies but submitted fields differ | RPC/block validation | request/public-input binding before state mutation | Rust RPC/block tests |
| ZK-016 | Oversized proof or public inputs | RPC | input size limits | smoke/security tests |
| ZK-017 | Dummy zero-value note creates value | transfer, split, merge | value conservation and range checks | Noir/wallet tests |
| ZK-018 | Wallet selects already-spent note | wallet | nullifier/status filtering | wallet integration tests |

## Manual Red-Team Prompts

Use these against local-only testnet tools. Do not provide production keys,
public RPC access, or GitHub write permission to any red-team model.

1. Build a transfer witness where the output sum is greater than the input sum.
2. Build a transfer with `asset_id = 1`, then submit it as `asset_id = 4`.
3. Build a valid proof, then change `public_inputs[3]` before RPC submission.
4. Try to merge one TNKL note with one sUSDC note.
5. Try to mint with a valid-looking authority public key but the wrong secret key.
6. Try to use `u64::MAX + 1` as an amount.
7. Try to reuse a note in the same transaction by copying its nullifier.
8. Try to submit a note commitment that is not represented in the public inputs.

Any successful attack should be treated as a release blocker.
