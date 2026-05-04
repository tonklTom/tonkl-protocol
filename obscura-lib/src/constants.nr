// Obscura Protocol - Circuit Constants
// Whitepaper refs: Section 7 (UTXO note model), Section 8.6 (MVP Phase 1)

// Merkle tree depth. Depth 32 supports up to 2^32 notes.
// Changing this requires a new trusted setup ceremony.
pub global MERKLE_DEPTH: u32 = 32;

// Note schema version. Increment on any breaking change to Note struct
// or commitment scheme to prevent cross-version replay attacks.
pub global NOTE_VERSION: Field = 0;

// All token values are range-checked to 64 bits.
// Without this, a value of (p-1) wraps around the BN254 field modulus,
// allowing tokens to be created from nothing via overflow.
pub global VALUE_BITS: u32 = 64;

// Poseidon domain separator for nullifier derivation.
// Prevents collision between commitment and nullifier hashes.
pub global NULLIFIER_DOMAIN: Field = 1;

// Poseidon domain separator for note commitment computation.
pub global COMMITMENT_DOMAIN: Field = 2;

// Public key derivation uses Grumpkin scalar multiplication (pk = sk * G)
// via std::embedded_curve_ops. No domain constants needed.
