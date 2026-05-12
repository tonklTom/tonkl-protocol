// Tonkl Protocol - Node Infrastructure
//
// Multi-node testnet with P2P gossip, consensus, and proof verification.
//
// Modules:
//   state     - Persistent Merkle tree and nullifier set (sled-backed)
//   block     - Block format, builder, and validator
//   mempool   - Transaction pool with fee-based prioritization
//   rpc       - JSON-RPC interface for wallet connection
//   verifier  - ZK proof verification via bb (Barretenberg)
//   consensus - Round-robin leader selection and auto block production
//   p2p       - libp2p networking (gossipsub, mDNS, chain sync)

pub mod block;
pub mod consensus;
pub mod mempool;
pub mod node;
pub mod p2p;
pub mod rpc;
pub mod state;
pub mod verifier;
