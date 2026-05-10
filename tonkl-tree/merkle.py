#!/usr/bin/env python3
"""
Tonkl Protocol - In-Memory Poseidon2 Merkle Tree

Sparse depth-32 binary Merkle tree backed by the tonkl-prover Rust binary
for cryptographic hashing. This guarantees exact parameter match with the
Noir circuits (same Barretenberg Poseidon2 permutation, same BN254 field).

Convention (matches merkle.nr):
  - Empty leaf / empty subtree = Field(0)
  - Internal node = hash_2(left_child, right_child) via Poseidon2
  - Authentication paths: LSB-first index bits, bottom-up sibling array

Usage:
    from merkle import MerkleTree

    tree = MerkleTree()
    idx = tree.insert("0xabcdef...")     # insert a leaf commitment
    root = tree.root                      # current Merkle root (hex)
    proof = tree.get_proof(idx)           # {"index_bits": [...], "siblings": [...]}
    witness = tree.witness_data(idx)      # formatted for Noir circuit input

Whitepaper refs:
  Section 7   - Note commitment tree
  Section 8.6 - MVP Phase 1 circuit scope
"""

import json
import os
import subprocess
import sys


class MerkleTree:
    """Sparse Poseidon2 Merkle tree (depth 32) over BN254."""

    DEPTH = 32
    EMPTY = "0x" + "00" * 32

    def __init__(self, prover_path=None):
        """
        Args:
            prover_path: Path to the compiled tonkl-prover binary.
                         Defaults to ../tonkl-prover/target/release/tonkl-prover
                         relative to this file.
        """
        if prover_path is None:
            here = os.path.dirname(os.path.abspath(__file__))
            prover_path = os.path.join(
                here, "..", "tonkl-prover", "target", "release", "tonkl-prover"
            )
        self.prover_path = prover_path
        self.leaves = []
        self._cache = None

    def _check_prover(self):
        """Verify the prover binary exists."""
        if not os.path.isfile(self.prover_path):
            raise FileNotFoundError(
                f"tonkl-prover not found at {self.prover_path}\n"
                "  Build it: cd tonkl-prover && cargo build --release"
            )

    def insert(self, commitment_hex):
        """
        Insert a leaf commitment into the next available position.

        Args:
            commitment_hex: Commitment as a hex string (with or without 0x prefix)
                           or a decimal string.

        Returns:
            The leaf index (0-based).
        """
        idx = len(self.leaves)
        self.leaves.append(str(commitment_hex))
        self._cache = None  # invalidate cached tree
        return idx

    def _compute(self):
        """Rebuild the tree via the Rust prover (cached)."""
        if self._cache is not None:
            return

        if not self.leaves:
            self._cache = {"root": self.EMPTY, "paths": [], "leaf_count": 0}
            return

        self._check_prover()

        input_json = json.dumps({"op": "merkle_tree", "leaves": self.leaves})
        result = subprocess.run(
            [self.prover_path, "compute"],
            input=input_json,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"tonkl-prover merkle_tree failed (exit {result.returncode}):\n"
                f"  stderr: {result.stderr.strip()}"
            )

        self._cache = json.loads(result.stdout)

    @property
    def root(self):
        """Current Merkle root as a hex string."""
        self._compute()
        return self._cache["root"]

    @property
    def leaf_count(self):
        """Number of leaves inserted."""
        return len(self.leaves)

    def get_proof(self, index):
        """
        Get the authentication path for the leaf at the given index.

        Returns:
            dict with "index_bits" (list of bool, LSB-first) and
            "siblings" (list of hex strings, bottom-up).
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self.leaves)})")
        self._compute()
        return self._cache["paths"][index]

    def witness_data(self, index, prefix=""):
        """
        Format Merkle proof as Noir circuit witness fields.

        Args:
            index: Leaf index.
            prefix: Optional prefix for field names (e.g., "in0_").

        Returns:
            dict like {"in0_merkle_bits": [...], "in0_merkle_path": [...]}
        """
        proof = self.get_proof(index)
        return {
            f"{prefix}merkle_bits": proof["index_bits"],
            f"{prefix}merkle_path": proof["siblings"],
        }

    def hash_2(self, a, b):
        """
        Compute Poseidon2 hash_2(a, b) via the prover.

        Args:
            a, b: Field elements as hex or decimal strings.

        Returns:
            Hash result as a hex string.
        """
        self._check_prover()
        input_json = json.dumps({"op": "hash_2", "a": str(a), "b": str(b)})
        result = subprocess.run(
            [self.prover_path, "compute"],
            input=input_json,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"hash_2 failed: {result.stderr.strip()}")
        return json.loads(result.stdout)["hash"]

    def verify_proof(self, leaf_hex, index, proof, expected_root=None):
        """
        Verify a Merkle proof by recomputing the root.

        Args:
            leaf_hex: Leaf commitment (hex string).
            index: Leaf position.
            proof: dict with "index_bits" and "siblings".
            expected_root: If provided, assert equality. Otherwise use self.root.

        Returns:
            True if the proof is valid.
        """
        if expected_root is None:
            expected_root = self.root

        # Recompute root step by step using hash_2
        node = leaf_hex
        for level in range(self.DEPTH):
            sibling = proof["siblings"][level]
            if not proof["index_bits"][level]:
                node = self.hash_2(node, sibling)
            else:
                node = self.hash_2(sibling, node)

        return node == expected_root


def compute_note(prover_path, sk, value, asset_id, rho):
    """
    Compute a full note (pk, commitment, nullifier) via the prover.

    Args:
        prover_path: Path to tonkl-prover binary.
        sk: Spending key (hex string).
        value: Note value (int or string).
        asset_id: Asset ID (int or string).
        rho: Randomness (int or string).

    Returns:
        dict with pk_x, pk_y, commitment, nullifier (all hex strings).
    """
    input_json = json.dumps({
        "op": "full_note",
        "sk": str(sk),
        "value": str(value),
        "asset_id": str(asset_id),
        "rho": str(rho),
    })
    result = subprocess.run(
        [prover_path, "compute"],
        input=input_json,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"full_note failed: {result.stderr.strip()}")
    return json.loads(result.stdout)
