# Tonkl Zcash-Class Circuit Audit

This audit pack tracks the class of bug disclosed in Zcash Orchard in June
2026: a zero-knowledge proof can verify successfully while the circuit itself
is missing a constraint that should have rejected the witness.

The immediate Tonkl goal is not to patch a Zcash dependency. Tonkl currently
uses Noir and Barretenberg rather than Orchard or halo2_gadgets. The goal is to
prove that Tonkl rejects the same *class* of attack across circuits, node
validation, and wallet witness generation.

## Scope

- `tonkl-transfer`: two-input/two-output private transfer circuit.
- `tonkl-split`: one-input/thirty-two-output split circuit.
- `tonkl-merge`: thirty-two-input/one-output merge circuit.
- `tonkl-mint`: authorized mint circuit.
- `tonkl-lib`: shared note, nullifier, commitment, ownership, and Merkle helpers.
- `tonkl-node`: public input binding, proof verification, mempool, block apply.
- `tonkl-transfer/scripts/wallet.py`: wallet-side witness and note selection.

## Threat Model

The attacker can build arbitrary witnesses, tamper with public inputs, submit
proofs through RPC, replay old nullifiers, alter asset IDs, and try to exploit
field arithmetic. The attacker should not be able to mutate node state unless
the proof and every public transaction field match the protocol rules.

## Controls Already Present

- Circuit-side value range checks prevent BN254 field wraparound attacks.
- Circuit-side value conservation binds input value, output value, and fee.
- Asset IDs are included in note commitments.
- Nullifiers are derived from note commitment and spending key.
- Ownership assertions derive the public key from the private spending key.
- Merkle membership binds input notes to the public root.
- Output commitments are recomputed inside the circuit.
- Duplicate nullifiers and duplicate output commitments are rejected.
- Node/RPC validation binds public inputs to transaction fields before state
  mutation.
- Mint policy checks registered authority and supply limits at node level.

## Required Audit Result

Before public testnet, every item in `security/zk_attack_matrix.md` should be
covered by at least one deterministic test, manual red-team scenario, or
documented external review.

The repeatable local command is:

```bash
./scripts/zk_security_audit.sh
```

Run it from the repository root after changing circuits, proof handling,
wallet witness generation, RPC transaction submission, or mint policy.
