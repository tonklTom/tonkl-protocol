// Tonkl Protocol - Shared Library
//
// Re-exports all shared primitives used across circuit projects:
//   note      - Note struct, commitment, nullifier, derive_pk, assert_ownership
//   hash      - Poseidon2 sponge: hash_2, hash_3, hash_7
//   constants - MERKLE_DEPTH, domain separators, NOTE_VERSION
//   merkle    - Merkle path verification against Poseidon2 tree

pub mod note;
pub mod hash;
pub mod constants;
pub mod merkle;
