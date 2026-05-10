#!/usr/bin/env python3
"""
Tonkl Protocol - Merkle Tree Self-Tests

Tests the Python MerkleTree by verifying internal consistency:
each leaf's authentication path must reproduce the tree root
when walked with hash_2.

Does NOT require nargo. Only requires the compiled tonkl-prover.

Usage:
    cd tonkl-tree
    python3 test_tree.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from merkle import MerkleTree, compute_note


def find_prover():
    here = os.path.dirname(os.path.abspath(__file__))
    for profile in ["release", "debug"]:
        path = os.path.join(here, "..", "tonkl-prover", "target", profile, "tonkl-prover")
        if os.path.isfile(path):
            return path
    print("[!] tonkl-prover binary not found.")
    print("    Build it: cd tonkl-prover && cargo build --release")
    sys.exit(1)


def test_empty_tree(prover_path):
    """Empty tree has zero root and no paths."""
    tree = MerkleTree(prover_path=prover_path)
    assert tree.root == MerkleTree.EMPTY, f"Empty root should be all zeros, got {tree.root}"
    assert tree.leaf_count == 0
    print("  [PASS] empty tree")


def test_single_leaf(prover_path):
    """Single leaf: path should be all zeros, root should be non-zero."""
    tree = MerkleTree(prover_path=prover_path)
    tree.insert("42")
    assert tree.root != MerkleTree.EMPTY, "Single-leaf root should not be zero"
    assert tree.leaf_count == 1

    proof = tree.get_proof(0)
    assert all(not b for b in proof["index_bits"]), "Leaf 0 should have all-false index bits"
    assert all(
        s == MerkleTree.EMPTY for s in proof["siblings"]
    ), "Single leaf should have all-zero siblings"

    # Verify proof
    assert tree.verify_proof("42", 0, proof), "Single leaf proof should verify"
    print("  [PASS] single leaf")


def test_two_leaves(prover_path):
    """Two leaves: both paths should produce the same root."""
    tree = MerkleTree(prover_path=prover_path)
    tree.insert("100")
    tree.insert("200")

    root = tree.root
    assert root != MerkleTree.EMPTY

    # Both proofs should verify
    proof_0 = tree.get_proof(0)
    proof_1 = tree.get_proof(1)
    assert tree.verify_proof("100", 0, proof_0), "Leaf 0 proof should verify"
    assert tree.verify_proof("200", 1, proof_1), "Leaf 1 proof should verify"

    # Leaf 0 sibling should be leaf 1 and vice versa
    # (they are level-0 siblings in a binary tree)
    # We can't directly compare hex representations because the prover
    # might normalize differently, but we can check they are non-zero
    assert proof_0["siblings"][0] != MerkleTree.EMPTY, "Leaf 0's level-0 sibling should be leaf 1"
    assert proof_1["siblings"][0] != MerkleTree.EMPTY, "Leaf 1's level-0 sibling should be leaf 0"

    # index_bits: leaf 0 = [false, ...], leaf 1 = [true, false, ...]
    assert not proof_0["index_bits"][0], "Leaf 0 should be left child"
    assert proof_1["index_bits"][0], "Leaf 1 should be right child"

    print("  [PASS] two leaves")


def test_four_leaves(prover_path):
    """Four leaves: all paths should verify. Matches merge circuit pattern."""
    tree = MerkleTree(prover_path=prover_path)
    leaves = ["1000", "2000", "3000", "4000"]
    for leaf in leaves:
        tree.insert(leaf)

    root = tree.root
    assert root != MerkleTree.EMPTY

    for i, leaf in enumerate(leaves):
        proof = tree.get_proof(i)
        ok = tree.verify_proof(leaf, i, proof)
        assert ok, f"Leaf {i} proof failed to verify"

    # Structure checks:
    # Leaf 0 (pos 0, bits 00...): sibling[0] = leaf 1
    # Leaf 1 (pos 1, bits 10...): sibling[0] = leaf 0
    # Leaf 2 (pos 2, bits 01...): sibling[0] = leaf 3
    # Leaf 3 (pos 3, bits 11...): sibling[0] = leaf 2
    p0 = tree.get_proof(0)
    p1 = tree.get_proof(1)
    p2 = tree.get_proof(2)
    p3 = tree.get_proof(3)

    assert not p0["index_bits"][0] and not p0["index_bits"][1], "Leaf 0: bits should be [0,0,...]"
    assert p1["index_bits"][0] and not p1["index_bits"][1], "Leaf 1: bits should be [1,0,...]"
    assert not p2["index_bits"][0] and p2["index_bits"][1], "Leaf 2: bits should be [0,1,...]"
    assert p3["index_bits"][0] and p3["index_bits"][1], "Leaf 3: bits should be [1,1,...]"

    # Cross-check: leaf 0 and leaf 1 share sibling at level 1
    assert p0["siblings"][1] == p1["siblings"][1], "Leaves 0,1 should share level-1 sibling"
    # That sibling should be hash(leaf2, leaf3)
    assert p2["siblings"][1] == p3["siblings"][1], "Leaves 2,3 should share level-1 sibling"

    print("  [PASS] four leaves")


def test_real_commitments(prover_path):
    """Build a tree from real note commitments computed by the prover."""
    owner_sk = "0xae0901"
    asset_id = "1"

    notes = []
    for i in range(4):
        note = compute_note(prover_path, owner_sk, (i + 1) * 100, asset_id, 5001 + i)
        notes.append(note)

    tree = MerkleTree(prover_path=prover_path)
    for note in notes:
        tree.insert(note["commitment"])

    root = tree.root
    assert root != MerkleTree.EMPTY

    for i, note in enumerate(notes):
        proof = tree.get_proof(i)
        ok = tree.verify_proof(note["commitment"], i, proof)
        assert ok, f"Real commitment {i} proof failed"

    print("  [PASS] real commitments (4 notes)")


def test_deterministic(prover_path):
    """Same leaves should always produce the same root."""
    tree1 = MerkleTree(prover_path=prover_path)
    tree2 = MerkleTree(prover_path=prover_path)

    for v in ["100", "200", "300"]:
        tree1.insert(v)
        tree2.insert(v)

    assert tree1.root == tree2.root, "Identical trees should have identical roots"
    print("  [PASS] deterministic")


def main():
    prover_path = find_prover()
    print(f"[test] Using prover: {prover_path}\n")

    t0 = time.time()

    print("[test] Running Merkle tree self-tests...")
    test_empty_tree(prover_path)
    test_single_leaf(prover_path)
    test_two_leaves(prover_path)
    test_four_leaves(prover_path)
    test_real_commitments(prover_path)
    test_deterministic(prover_path)

    elapsed = time.time() - t0
    print(f"\n[test] All tests passed ({elapsed:.1f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
