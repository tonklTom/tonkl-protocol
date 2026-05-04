# Tonkl Protocol

> **Privacy-preserving blockchain built on zero-knowledge proofs.**

Tonkl is a UTXO-based blockchain where all transactions are shielded by default. Balances, amounts, and sender/receiver identities are hidden on-chain — only ZK proofs are visible. The protocol uses Noir circuits compiled to UltraHonk proofs via the Barretenberg backend.

> **WARNING: This is alpha software (v0.1.0-beta).** It is for testing and experimentation only. Do not use real funds. Expect bugs, breaking changes, and data wipes between versions. The cryptographic construction has not been formally audited.

---

## Architecture

```
tonkl/
  tonkl                CLI entry point (./tonkl testnet start, ./tonkl wallet, etc.)
  docker-compose.yml   Docker-based testnet quickstart
  obscura-node/        Rust node: state tree, nullifier set, block builder, consensus, JSON-RPC
    scripts/             Python wallet, testnet launcher, genesis, P2P, tests
    explorer/            Self-contained block explorer (HTML)
  obscura-transfer/    Noir circuit: 2-in / 2-out private transfer
  obscura-merge/       Noir circuit: 32-in / 1-out note merge
  obscura-split/       Noir circuit: 1-in / 32-out note split
  obscura-mint/        Noir circuit: 0-in / 32-out token mint
  obscura-tree/        Noir circuit: Merkle tree verification
  obscura-hasher/      Noir library: Poseidon2 hash function
  obscura-prover/      Rust library: Poseidon2, Merkle tree, proof helpers
  obscura-lib/         Shared Rust types
```

**Cryptographic primitives:** Poseidon2 hash, BN254 curve, UltraHonk proving system (Barretenberg).

**Note model:** Each note is a commitment: `Poseidon2(value, asset_id, owner_pk_x, owner_pk_y, rho)`. Spending reveals a nullifier: `Poseidon2(note_commitment, owner_sk)`. The on-chain state is a depth-32 Merkle tree of commitments plus a nullifier set.

**Assets:** Native TNKL token (asset_id=1, 0 decimals) and sUSDC (asset_id=4, 6 decimals) are pre-registered. Custom tokens can be minted by any authority key.

---

## Prerequisites

Before you begin, install:

- **Rust** (stable, 1.75+): https://rustup.rs
- **Noir** (v1.0.0-beta.20): https://noir-lang.org/docs/getting_started/installation
- **Barretenberg** (`bb` CLI): installed alongside Noir
- **Python** (3.10+): for the wallet and testnet scripts
- **Python packages**: `pip install requests pynacl` (optional: `pysqlcipher3` for encrypted wallets)

Verify your setup:

```bash
rustc --version       # 1.75+
nargo --version       # 1.0.0-beta.20
bb --version          # should print version
python3 --version     # 3.10+
```

---

## Try Tonkl in 5 Minutes

The fastest path from zero to sending a shielded transaction. You only need Rust and Python installed.

```bash
# 1. Check you have the basics
./tonkl doctor

# 2. Build the node from source (~2 min)
./tonkl build

# 3. Start a single-node testnet (auto-mines blocks every 5s)
./tonkl testnet start -n 1

# 4. In a new terminal — create a wallet (wizard auto-triggers)
./tonkl wallet

# 5. Get testnet tokens from the faucet
./tonkl wallet faucet

# 6. Send a shielded transfer
./tonkl wallet send 100

# 7. Check your balance
./tonkl wallet balance
```

That's it — you just made a private, zero-knowledge transaction on a local testnet. Everything (balances, amounts, identities) is hidden on-chain.

If you have Docker installed, you can skip the Rust build entirely:

```bash
./tonkl testnet start --docker
```

---

## Quick Start (full details)

### 1. Build the node

```bash
./tonkl build
# Or manually: cd obscura-node && cargo build --release
```

### 2. Compile circuits and generate verification keys

```bash
# Each circuit directory has a Nargo.toml
for circuit in obscura-transfer obscura-merge obscura-split obscura-mint; do
  cd $circuit
  nargo compile
  bb write_vk -b target/*.json -o target/vk
  cd ..
done
```

### 3. Launch a testnet

```bash
./tonkl testnet start        # 3-node testnet (default)
./tonkl testnet start -n 1   # Single node (fastest)
./tonkl testnet start --docker  # Via Docker (no Rust needed)
```

The launcher handles everything — builds if needed, starts nodes with round-robin consensus, generates genesis blocks with pre-funded faucet accounts, and prints connection details.

### 4. Create a wallet

In a new terminal:

```bash
./tonkl wallet
```

The first-run wizard walks you through database encryption, 24-word seed phrase backup with verification, and first key generation.

### 5. Get testnet tokens

```bash
./tonkl wallet faucet
```

### 6. Send a private transfer

```bash
./tonkl wallet send 100
```

### 7. Open the block explorer

Open `obscura-node/explorer/index.html` in a browser and point it at your node URL (default: `http://127.0.0.1:9100`). The explorer features a unified search bar, live activity feed, chain statistics with TX type breakdowns, block navigation, dark/light themes, and a produce-block button for testnet usage. Press `Ctrl+K` to quick-search.

---

## Wallet Commands

| Command | Description |
|---------|-------------|
| `status` | Wallet overview: connection, balances, note counts |
| `balance` | Show balances by asset |
| `notes` | List notes (add `--all` for spent notes) |
| `address` | Show your public key address |
| `send` | Send a private transfer |
| `split` | Split one note into many |
| `merge` | Merge many notes into one |
| `sync` | Sync note states with the node |
| `scan` | Scan for incoming payments |
| `watch` | Auto-scan for incoming payments in background |
| `faucet` | Request testnet tokens from the faucet |
| `init-seed` | Generate a new 24-word seed phrase |
| `restore-seed` | Restore wallet from seed phrase |
| `show-seed` | Display your seed phrase |
| `derive-key` | Derive a new spending key |
| `list-keys` | Show all derived keys |
| `assets` | List supported assets and balances |
| `history` | Show transaction history |
| `register-key` | Register a scan key for auto-receive |
| `register-validator` | Register a validator for staking delegation |
| `validators` | List registered validators |
| `stake` | Delegate OBS to a validator (locks note) |
| `unstake` | Begin unstaking (starts unbonding period) |
| `withdraw-stake` | Withdraw after unbonding completes |
| `claim-rewards` | Claim accrued staking rewards |
| `stakes` | List all staking positions |
| `epoch-advance` | Close current epoch and distribute rewards |
| `epoch-info` | Show epoch details and reward breakdown |
| `validator-set` | Show the active validator set |
| `reward-history` | Show epoch reward distribution history |
| `slash-validator` | Slash a validator for misbehaviour |
| `setup` | Re-run the onboarding wizard |

Run `./tonkl wallet --help` for full usage.

---

## Node RPC API

The node exposes a JSON-RPC 2.0 interface over HTTP. Default port: 9100.

| Method | Description |
|--------|-------------|
| `get_status` | Chain height, Merkle root, leaf count, mempool size |
| `submit_tx` | Submit a shielded transaction with proof |
| `produce_block` | Mine the next block from the mempool |
| `get_block` | Retrieve a block by number |
| `get_merkle_proof` | Get a Merkle inclusion proof for a leaf index |
| `get_nullifiers` | Check if nullifiers have been spent |
| `get_encrypted_notes` | Retrieve encrypted notes for scanning |
| `store_encrypted_notes` | Store encrypted notes for recipients |

Example:

```bash
curl -s http://127.0.0.1:9100 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_status","params":[],"id":1}'
```

---

## Running Tests

The integration test suite exercises the full stack — wallet operations, circuit proving, node RPC, P2P, and more:

```bash
cd obscura-node
python3 scripts/test_wallet_cli.py
```

This requires a built node binary, compiled circuits, and `nargo`/`bb` on PATH. The test spawns its own node process and runs 500+ checks covering all wallet commands, circuit types, multi-asset operations, error recovery, and more.

---

## Project Structure

### Noir Circuits

Each circuit lives in its own directory with a `Nargo.toml`:

- **obscura-transfer** (2-in/2-out): The core private payment circuit. Proves that input notes exist in the Merkle tree, nullifiers are correctly derived, and output commitments are well-formed — all without revealing values or identities.

- **obscura-merge** (32-in/1-out): Consolidates up to 32 notes into a single note. Unused inputs are padded with zero-value dummy notes.

- **obscura-split** (1-in/32-out): Splits one note into up to 32 outputs. Unused outputs are zero-value padding.

- **obscura-mint** (0-in/32-out): Creates new notes from nothing. Requires an authority signature. Used for genesis funding and faucet operations.

### Rust Node (`obscura-node/`)

- `state.rs` — Persistent Merkle tree (sled-backed, depth 32) and nullifier set
- `block.rs` — Block format, block builder, and block validator with proof verification
- `mempool.rs` — Transaction pool with priority ordering
- `rpc.rs` — JSON-RPC server (jsonrpsee) exposing all node methods
- `verifier.rs` — ZK proof verification via the `bb` CLI
- `consensus.rs` — Round-robin leader selection and automatic block production
- `main.rs` — CLI entry point with `run` and `status` commands

### Python Scripts (`obscura-node/scripts/`)

- `obscura_wallet.py` — Full-featured wallet CLI with SQLite storage, BIP-39 seeds, SQLCipher encryption, auto-receive scanning, and multi-asset support
- `node_client.py` — JSON-RPC client for talking to the node
- `witness_builder.py` — Builds circuit witnesses for all four circuit types
- `genesis.py` — Genesis block generator with pre-funded faucet accounts
- `launch_testnet.py` — Multi-node testnet orchestrator
- `p2p.py` — TCP P2P sidecar with gossip protocol
- `bip39.py` — BIP-39 mnemonic generation and key derivation
- `test_wallet_cli.py` — Comprehensive integration test suite (500+ checks)

---

## Security Considerations

This is unaudited alpha software. Known limitations:

- **No formal verification** of the Noir circuits. The constraint system has been tested but not proven correct.
- **Proof generation uses the `bb` CLI** as a subprocess. A malicious `bb` binary could produce invalid proofs.
- **P2P layer is unauthenticated.** Nodes trust peers without identity verification.
- **Basic round-robin consensus.** Leader selection is deterministic round-robin without slashing or BFT finality. A malicious validator can skip slots or produce invalid blocks.
- **SQLCipher encryption is optional.** Unencrypted wallets store spending keys in plaintext SQLite.
- **No formal key management.** Spending keys are hex strings derived from BIP-39 seeds via HMAC-SHA512.

See `Obscura_Security_Audit.docx` for a more detailed security analysis.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Beta Disclaimer

```
TONKL PROTOCOL — BETA SOFTWARE NOTICE

This software is provided "as is" without warranty of any kind, express or
implied. The Tonkl Protocol is experimental alpha software undergoing active
development.

BY USING THIS SOFTWARE, YOU ACKNOWLEDGE THAT:

1. This is NOT production-ready software. It is intended for testing,
   development, and educational purposes only.

2. DO NOT use real funds or assets of any value with this software. All
   tokens on the Tonkl testnet have zero real-world value.

3. The cryptographic circuits and proof systems have NOT been formally
   audited. There may be soundness bugs that allow invalid state transitions.

4. Data loss is expected. Testnet state, wallet databases, and blockchain
   data may be wiped without notice between versions.

5. Breaking changes will occur. The protocol, RPC API, wire format, and
   wallet database schema are all subject to change.

6. The developers accept no liability for any loss, damage, or consequence
   arising from the use of this software.

If you discover a security vulnerability, please report it responsibly
rather than exploiting it on a public testnet.
```
