// Tonkl Protocol - Node Infrastructure
//
// Single-node kernel for local testnet operation.
//
// Modules:
//   state     - Persistent Merkle tree and nullifier set (sled-backed)
//   block     - Block format, builder, and validator
//   mempool   - Transaction pool with fee-based prioritization
//   rpc       - JSON-RPC interface for wallet connection
//   verifier  - ZK proof verification via bb (Barretenberg)
//   consensus - Round-robin leader selection and auto block production

pub mod state;
pub mod block;
pub mod mempool;
pub mod rpc;
pub mod verifier;
pub mod consensus;
