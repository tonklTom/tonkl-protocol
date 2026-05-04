#!/usr/bin/env python3
"""
Tonkl Protocol -- Genesis Block Generator

Creates a genesis block pre-funded with faucet notes for testnet operation.
Mints TNKL and sUSDC notes controlled by a faucet authority key, then writes
a genesis.json config file describing the initial state.

Usage:
  # Generate genesis with default faucet key
  python3 scripts/genesis.py --node-url http://127.0.0.1:9100

  # Custom faucet key
  python3 scripts/genesis.py --faucet-sk 0xface70 --node-url http://127.0.0.1:9100

  # Write config to specific path
  python3 scripts/genesis.py --output genesis.json --node-url http://127.0.0.1:9100

The script:
  1. Derives the faucet authority public key from --faucet-sk
  2. Builds mint witnesses for TNKL and sUSDC
  3. Generates ZK proofs (nargo execute + bb prove)
  4. Submits mint TXs to the node and produces genesis block(s)
  5. Writes genesis.json with faucet note details
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent  # obscura/

sys.path.insert(0, str(SCRIPT_DIR))
from node_client import TonklClient
from witness_builder import CryptoHelper, WitnessBuilder, NoteOutput

# ─────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────

MINT_DIR = ROOT / "obscura-mint"
MINT_CIRCUIT_JSON = MINT_DIR / "target" / "obscura_mint.json"

DEFAULT_FAUCET_SK = "0xface70"

# Genesis funding: TNKL (asset_id=1) and sUSDC (asset_id=4)
# TNKL: 10 notes × 10,000 = 100,000 TNKL total faucet supply
# sUSDC: 10 notes × 10,000,000,000 (10k USDC with 6 decimals) = 100,000 sUSDC
GENESIS_MINTS = [
    {
        "asset_id": "1",
        "symbol": "TNKL",
        "notes": [
            {"value": 10_000, "rho": "810001"},
            {"value": 10_000, "rho": "810002"},
            {"value": 10_000, "rho": "810003"},
            {"value": 10_000, "rho": "810004"},
            {"value": 10_000, "rho": "810005"},
            {"value": 10_000, "rho": "810006"},
            {"value": 10_000, "rho": "810007"},
            {"value": 10_000, "rho": "810008"},
            {"value": 10_000, "rho": "810009"},
            {"value": 10_000, "rho": "810010"},
        ],
    },
    {
        "asset_id": "4",
        "symbol": "sUSDC",
        "notes": [
            {"value": 10_000_000_000, "rho": "840001"},
            {"value": 10_000_000_000, "rho": "840002"},
            {"value": 10_000_000_000, "rho": "840003"},
            {"value": 10_000_000_000, "rho": "840004"},
            {"value": 10_000_000_000, "rho": "840005"},
            {"value": 10_000_000_000, "rho": "840006"},
            {"value": 10_000_000_000, "rho": "840007"},
            {"value": 10_000_000_000, "rho": "840008"},
            {"value": 10_000_000_000, "rho": "840009"},
            {"value": 10_000_000_000, "rho": "840010"},
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────
# Proving helpers
# ─────────────────────────────────────────────────────────────────────

def nargo_execute(circuit_dir: Path, witness_name: str) -> Path:
    """Run nargo execute and return the witness file path."""
    result = subprocess.run(
        ["nargo", "execute", witness_name],
        cwd=str(circuit_dir),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"nargo execute failed:\n{result.stderr[-500:]}"
        )
    path = circuit_dir / "target" / f"{witness_name}.gz"
    if not path.exists():
        raise FileNotFoundError(f"Witness not found: {path}")
    return path


def bb_prove(
    circuit_json: Path,
    witness_gz: Path,
    vk_path: Path,
    output_dir: Path,
) -> Tuple[Path, Path]:
    """Run bb prove and return (proof_path, public_inputs_path)."""
    proof_dir = output_dir / "proof"
    proof_dir.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [
            "bb", "prove",
            "-b", str(circuit_json),
            "-w", str(witness_gz),
            "-o", str(proof_dir),
            "-k", str(vk_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"bb prove failed:\n{result.stderr[-500:]}")

    proof_path = proof_dir / "proof"
    pi_path = proof_dir / "public_inputs"
    if not proof_path.exists() or not pi_path.exists():
        raise FileNotFoundError(f"Proof artifacts missing in {proof_dir}")
    return proof_path, pi_path


def find_vk(circuit_name: str) -> Path:
    """Locate the verification key for a circuit."""
    base = ROOT / circuit_name / "target"
    for p in [base / "vk" / "vk", base / "vk", base / "vk_dir" / "vk"]:
        if p.exists():
            return p
    raise FileNotFoundError(f"VK not found for {circuit_name}")


# ─────────────────────────────────────────────────────────────────────
# Genesis builder
# ─────────────────────────────────────────────────────────────────────

def build_genesis(
    faucet_sk: str,
    node_url: str,
    output_path: Optional[str] = None,
    verbose: bool = True,
) -> dict:
    """
    Build the genesis block(s) with pre-funded faucet notes.

    Returns a genesis config dict with faucet note details.
    """
    crypto = CryptoHelper()
    client = TonklClient(node_url)

    if verbose:
        print()
        print("  Genesis Block Generator")
        print("  " + "─" * 40)
        print()

    # Wait for node
    if verbose:
        print("  [1] Connecting to node...")
    if not client.wait_for_node(timeout=10.0):
        raise RuntimeError(f"Cannot connect to node at {node_url}")
    status = client.get_status()
    if status.block_height > 0 or status.leaf_count > 0:
        raise RuntimeError(
            f"Node already has state (height={status.block_height}, "
            f"leaves={status.leaf_count}). Genesis requires a fresh node."
        )
    if verbose:
        print(f"      ✓ Node ready at {node_url} (empty state)")

    # Derive faucet authority key
    if verbose:
        print("  [2] Deriving faucet authority key...")
    faucet_pk_x, faucet_pk_y = crypto.derive_pk(faucet_sk)
    if verbose:
        print(f"      ✓ pk_x: {faucet_pk_x[:24]}...")

    # Find VK for mint circuit
    mint_vk = find_vk("obscura-mint")
    if verbose:
        print(f"      ✓ Mint VK loaded")

    # Build and submit mint TX for each asset
    genesis_notes = []
    block_num = 0
    tmp_dir = Path(tempfile.mkdtemp(prefix="obscura-genesis-"))

    try:
        for mint_idx, mint_spec in enumerate(GENESIS_MINTS):
            asset_id = mint_spec["asset_id"]
            symbol = mint_spec["symbol"]
            notes = mint_spec["notes"]
            total = sum(n["value"] for n in notes)

            if verbose:
                print(f"  [{3 + mint_idx}] Minting {symbol} ({len(notes)} notes, total={total:,})...")

            # Build outputs and compute commitments
            outputs = []
            cm_outs = []
            note_details = []

            for note_spec in notes:
                out = NoteOutput(
                    value=note_spec["value"],
                    owner_pk_x=faucet_pk_x,
                    owner_pk_y=faucet_pk_y,
                    rho=note_spec["rho"],
                )
                outputs.append(out)
                cm = crypto.commitment(
                    str(note_spec["value"]), asset_id,
                    faucet_pk_x, faucet_pk_y, note_spec["rho"],
                )
                cm_outs.append(cm)
                note_details.append({
                    "value": note_spec["value"],
                    "asset_id": asset_id,
                    "rho": note_spec["rho"],
                    "commitment": cm,
                })

            # Pad to 32 outputs with zero-value notes
            while len(outputs) < 32:
                pad_rho = str(9000 + len(outputs))
                out = NoteOutput(
                    value=0,
                    owner_pk_x=faucet_pk_x,
                    owner_pk_y=faucet_pk_y,
                    rho=pad_rho,
                )
                outputs.append(out)
                cm = crypto.commitment(
                    "0", asset_id,
                    faucet_pk_x, faucet_pk_y, pad_rho,
                )
                cm_outs.append(cm)

            assert len(cm_outs) == 32

            # Build witness
            builder = WitnessBuilder(client)
            witness_toml = builder.build_mint(
                outputs=outputs[:len(notes)],  # only real outputs
                total_minted=total,
                asset_id=asset_id,
                authority_pk_x=faucet_pk_x,
                authority_pk_y=faucet_pk_y,
                authority_sk=faucet_sk,
                cm_outs=cm_outs,
            )

            # Write Prover.toml
            prover_toml_path = MINT_DIR / "Prover.toml"
            prover_toml_path.write_text(witness_toml)
            if verbose:
                print(f"      ✓ Witness: {len(notes)} notes + {32 - len(notes)} padding")

            # Generate proof: nargo execute + bb prove
            if verbose:
                print(f"      Generating proof...")
            witness_name = f"genesis_{symbol.lower()}"
            witness_gz = nargo_execute(MINT_DIR, witness_name)

            proof_out = tmp_dir / f"proof_{symbol.lower()}"
            proof_path, pi_path = bb_prove(
                MINT_CIRCUIT_JSON, witness_gz, mint_vk, proof_out,
            )
            if verbose:
                print(f"      ✓ Proof generated")

            # Read commitments from public_inputs (what the verifier sees)
            pi_bytes = pi_path.read_bytes()
            verified_cms = []
            for i in range(32):
                chunk = pi_bytes[i * 32 : (i + 1) * 32]
                verified_cms.append("0x" + chunk.hex())

            # Submit to node
            asset_id_hex = "0x" + "00" * 31 + f"{int(asset_id):02x}"
            result = client.submit_from_proof_files(
                tx_type="mint",
                proof_path=str(proof_path),
                public_inputs_path=str(pi_path),
                new_commitments=verified_cms,
                nullifiers=[],
                merkle_root="0x" + "00" * 32,
                fee=0,
                asset_id=asset_id_hex,
            )
            if not result.accepted:
                raise RuntimeError(f"Mint TX for {symbol} rejected by node")
            if verbose:
                print(f"      ✓ TX accepted: {result.tx_hash[:28]}...")

            # Produce block
            header = client.produce_block()
            if verbose:
                print(f"      ✓ Block #{header.block_number} produced")

            # Record note details with their tree indices
            base_index = block_num * 32  # each mint adds 32 leaves
            for i, detail in enumerate(note_details):
                detail["tree_index"] = base_index + i
                detail["block_number"] = header.block_number
            genesis_notes.extend(note_details)
            block_num += 1

    finally:
        # Clean up temp dir
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Build genesis config
    final_status = client.get_status()
    genesis_config = {
        "version": "1.0",
        "chain_id": "tonkl-testnet-1",
        "genesis_time": int(time.time()),
        "faucet": {
            "sk": faucet_sk,
            "pk_x": faucet_pk_x,
            "pk_y": faucet_pk_y,
        },
        "initial_state": {
            "block_height": final_status.block_height,
            "merkle_root": final_status.merkle_root,
            "leaf_count": final_status.leaf_count,
        },
        "funded_notes": genesis_notes,
        "assets": {
            "1": {"symbol": "TNKL", "name": "Tonkl", "decimals": 0},
            "4": {"symbol": "sUSDC", "name": "Shielded USDC", "decimals": 6},
        },
    }

    # Write genesis config
    if output_path is None:
        output_path = str(ROOT / "obscura-node" / "genesis.json")
    Path(output_path).write_text(json.dumps(genesis_config, indent=2) + "\n")

    if verbose:
        print()
        print(f"  ✓ Genesis complete!")
        print(f"    {len(genesis_notes)} funded notes across {len(GENESIS_MINTS)} assets")
        obs_total = sum(n["value"] for n in genesis_notes if n["asset_id"] == "1")
        usdc_total = sum(n["value"] for n in genesis_notes if n["asset_id"] == "4")
        print(f"    Supply: {obs_total:,} TNKL + {usdc_total / 1e6:,.0f} sUSDC")
        print(f"    State:  height={final_status.block_height}, "
              f"leaves={final_status.leaf_count}")
        print()

    return genesis_config


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Tonkl Testnet -- Genesis Block Generator",
    )
    parser.add_argument(
        "--node-url",
        default="http://127.0.0.1:9100",
        help="Node RPC URL (default: http://127.0.0.1:9100)",
    )
    parser.add_argument(
        "--faucet-sk",
        default=DEFAULT_FAUCET_SK,
        help=f"Faucet authority secret key (default: {DEFAULT_FAUCET_SK})",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output genesis.json path (default: obscura-node/genesis.json)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress output",
    )

    args = parser.parse_args()

    try:
        build_genesis(
            faucet_sk=args.faucet_sk,
            node_url=args.node_url,
            output_path=args.output,
            verbose=not args.quiet,
        )
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
