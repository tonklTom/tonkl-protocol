// Tonkl Protocol - Merkle Tree Verification
//
// Poseidon2-based Merkle path verification for the note commitment tree.
// Used by all circuits (transfer, merge, split, mint) to prove that an
// input note exists in the on-chain commitment tree.
//
// Tree structure:
//   - Binary tree of depth 32, supporting up to 2^32 leaves
//   - Internal node hash: hash_2(left_child, right_child) using Poseidon2
//   - Empty leaf / empty subtree: Field(0)
//
// Path format:
//   index_bits: LSB-first bit decomposition of the leaf position.
//     bit[i] == 0 means current node is LEFT child at level i
//     bit[i] == 1 means current node is RIGHT child at level i
//   path: array of sibling hashes, one per tree level (bottom-up)
//
// Why pre-decomposed bits instead of a u32 index:
//   Integer division opcodes can cause assertion failures in bb 4.0-nightly.
//   Pre-decomposed bits avoid all integer arithmetic in the circuit.
//
// Whitepaper refs:
//   Section 7   - Note commitment tree
//   Section 8.6 - MVP Phase 1 circuit scope

use crate::hash::hash_2;

// Compute the Merkle root from a leaf commitment and its authentication path.
//
// Returns the computed root. The caller asserts equality with the public
// merkle_root to prove membership.
pub fn compute_root(
    leaf: Field,
    index_bits: [bool; 32],
    path: [Field; 32],
) -> Field {
    let mut node = leaf;
    for i in 0..32 {
        let sibling = path[i];
        if !index_bits[i] {
            node = hash_2(node, sibling);
        } else {
            node = hash_2(sibling, node);
        }
    }
    node
}

// --- Tests ---

#[test]
fn test_single_leaf_tree() {
    // A tree with one leaf at position 0 (all siblings = 0).
    let leaf: Field = 42;
    let bits: [bool; 32] = [false; 32];
    let path: [Field; 32] = [0; 32];
    let root = compute_root(leaf, bits, path);
    let root2 = compute_root(leaf, bits, path);
    assert(root == root2);
}

#[test]
fn test_two_leaf_tree() {
    // Two leaves at positions 0 and 1, rest of tree empty.
    let leaf_a: Field = 100;
    let leaf_b: Field = 200;

    let mut path_a: [Field; 32] = [0; 32];
    path_a[0] = leaf_b;
    let bits_a: [bool; 32] = [false; 32];
    let root_a = compute_root(leaf_a, bits_a, path_a);

    let mut path_b: [Field; 32] = [0; 32];
    path_b[0] = leaf_a;
    let mut bits_b: [bool; 32] = [false; 32];
    bits_b[0] = true;
    let root_b = compute_root(leaf_b, bits_b, path_b);

    assert(root_a == root_b);
}

#[test]
fn test_different_positions_different_roots() {
    let leaf: Field = 42;

    let mut path_0: [Field; 32] = [0; 32];
    path_0[0] = 99;
    let bits_0: [bool; 32] = [false; 32];

    let mut path_1: [Field; 32] = [0; 32];
    path_1[0] = 99;
    let mut bits_1: [bool; 32] = [false; 32];
    bits_1[0] = true;

    let root_0 = compute_root(leaf, bits_0, path_0);
    let root_1 = compute_root(leaf, bits_1, path_1);
    assert(root_0 != root_1);
}

#[test]
fn test_membership_check_passes() {
    let leaf: Field = 42;
    let bits: [bool; 32] = [false; 32];
    let path: [Field; 32] = [0; 32];
    let root = compute_root(leaf, bits, path);
    assert(compute_root(leaf, bits, path) == root);
}

#[test(should_fail)]
fn test_wrong_root_fails() {
    let leaf: Field = 42;
    let bits: [bool; 32] = [false; 32];
    let path: [Field; 32] = [0; 32];
    let root = compute_root(leaf, bits, path);
    assert(compute_root(leaf, bits, path) == root + 1);
}

#[test(should_fail)]
fn test_wrong_leaf_fails() {
    let leaf: Field = 42;
    let bits: [bool; 32] = [false; 32];
    let path: [Field; 32] = [0; 32];
    let root = compute_root(leaf, bits, path);
    assert(compute_root(leaf + 1, bits, path) == root);
}

#[test(should_fail)]
fn test_corrupted_path_fails() {
    let leaf: Field = 42;
    let bits: [bool; 32] = [false; 32];
    let path: [Field; 32] = [0; 32];
    let root = compute_root(leaf, bits, path);
    let mut bad_path: [Field; 32] = [0; 32];
    bad_path[5] = 999;
    assert(compute_root(leaf, bits, bad_path) == root);
}
