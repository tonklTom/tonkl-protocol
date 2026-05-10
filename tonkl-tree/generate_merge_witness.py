#!/usr/bin/env python3
"""
Tonkl Protocol - Merge Circuit Witness Generator (32-in/1-out)

Generates a complete, valid Prover.toml for the 32-in/1-out merge circuit
using the Python MerkleTree. This is the primary cross-verification test:
if nargo execute succeeds with the generated witness, the Python tree
produces the same Poseidon2 Merkle roots as the Noir circuit.

Usage:
    # Generate witness and write Prover.toml
    python3 generate_merge_witness.py

    # Then verify with nargo:
    cd ../tonkl-merge && nargo execute

    # Or run the full pipeline:
    python3 generate_merge_witness.py --verify

Whitepaper refs:
  Section 7.5 - Merge obligation (32-in/1-out)
  Section 8.6 - MVP Phase 1 scope
"""

import argparse
import json
import os
import subprocess
import sys

# Add parent for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from merkle import MerkleTree, compute_note


NUM_INPUTS = 32


def find_prover():
    """Locate the tonkl-prover binary."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "tonkl-prover", "target", "release", "tonkl-prover"),
        os.path.join(here, "..", "tonkl-prover", "target", "debug", "tonkl-prover"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    print("[!] tonkl-prover binary not found.")
    print("    Build it: cd tonkl-prover && cargo build --release")
    sys.exit(1)


def derive_pk(prover_path, sk):
    """Derive public key from spending key."""
    input_json = json.dumps({"op": "derive_pk", "sk": str(sk)})
    result = subprocess.run(
        [prover_path, "compute"],
        input=input_json,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"derive_pk failed: {result.stderr.strip()}")
    data = json.loads(result.stdout)
    return data["pk_x"], data["pk_y"]


def compute_nullifier(prover_path, cm, sk):
    """Compute nullifier for a commitment."""
    input_json = json.dumps({"op": "nullifier", "cm": str(cm), "owner_sk": str(sk)})
    result = subprocess.run(
        [prover_path, "compute"],
        input=input_json,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nullifier failed: {result.stderr.strip()}")
    return json.loads(result.stdout)["nullifier"]


def compute_commitment(prover_path, value, asset_id, pk_x, pk_y, rho):
    """Compute note commitment."""
    input_json = json.dumps({
        "op": "commitment",
        "value": str(value),
        "asset_id": str(asset_id),
        "owner_pk_x": str(pk_x),
        "owner_pk_y": str(pk_y),
        "rho": str(rho),
    })
    result = subprocess.run(
        [prover_path, "compute"],
        input=input_json,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"commitment failed: {result.stderr.strip()}")
    return json.loads(result.stdout)["commitment"]


def write_prover_toml(path, data):
    """Write a Prover.toml file from a dict, handling nested arrays."""
    lines = []
    for key, val in data.items():
        if isinstance(val, list):
            if len(val) > 0 and isinstance(val[0], list):
                # Nested array: [[...], [...], ...]
                inner_parts = []
                for inner in val:
                    if isinstance(inner[0], bool):
                        items = ", ".join("true" if v else "false" for v in inner)
                    else:
                        items = ", ".join(f'"{v}"' for v in inner)
                    inner_parts.append(f"[{items}]")
                lines.append(f'{key} = [{", ".join(inner_parts)}]')
            elif len(val) > 0 and isinstance(val[0], bool):
                items = ", ".join("true" if v else "false" for v in val)
                lines.append(f'{key} = [{items}]')
            else:
                items = ", ".join(f'"{v}"' for v in val)
                lines.append(f'{key} = [{items}]')
        elif isinstance(val, bool):
            lines.append(f'{key} = {"true" if val else "false"}')
        else:
            lines.append(f'{key} = "{val}"')
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Generate 32-input merge circuit witness")
    parser.add_argument(
        "--verify", action="store_true",
        help="Run nargo execute after generating witness"
    )
    parser.add_argument(
        "--owner-sk", default="0xae0901",
        help="Owner spending key (hex). Default: 0xae0901 (matches circuit tests)"
    )
    parser.add_argument(
        "--asset-id", default="1",
        help="Asset ID. Default: 1"
    )
    parser.add_argument(
        "--fee", default="0",
        help="Transaction fee. Default: 0"
    )
    parser.add_argument(
        "--num-real", type=int, default=32,
        help="Number of real (non-zero value) notes. Rest are zero-value padding. Default: 32"
    )
    args = parser.parse_args()

    prover_path = find_prover()
    print(f"[merkle] Using prover: {prover_path}")

    owner_sk = args.owner_sk
    asset_id = args.asset_id
    fee = int(args.fee)
    num_real = min(args.num_real, NUM_INPUTS)

    # Step 1: Derive owner public key
    print("[merkle] Deriving owner public key...")
    pk_x, pk_y = derive_pk(prover_path, owner_sk)
    print(f"  pk_x = {pk_x[:18]}...")
    print(f"  pk_y = {pk_y[:18]}...")

    # Step 2: Create 32 input notes
    # First num_real have values 1..num_real, rest are zero-value padding
    values = []
    rhos = []
    for i in range(NUM_INPUTS):
        if i < num_real:
            values.append(i + 1)  # values 1, 2, 3, ..., num_real
        else:
            values.append(0)      # zero-value padding notes
        rhos.append(5001 + i)     # distinct rhos for all 32

    total_value = sum(values)
    out_value = total_value - fee

    print(f"[merkle] Building {NUM_INPUTS} input notes ({num_real} real, {NUM_INPUTS - num_real} padding)...")
    print(f"  total={total_value}, fee={fee}, out={out_value}")

    commitments = []
    for i in range(NUM_INPUTS):
        cm = compute_commitment(prover_path, values[i], asset_id, pk_x, pk_y, rhos[i])
        commitments.append(cm)
        if i < 4 or i == NUM_INPUTS - 1:
            print(f"  note[{i}]: value={values[i]}, rho={rhos[i]}, cm={cm[:18]}...")
        elif i == 4:
            print(f"  ... ({NUM_INPUTS - 5} more notes)")

    # Step 3: Build Merkle tree
    print("[merkle] Building Merkle tree (32 leaves)...")
    tree = MerkleTree(prover_path=prover_path)
    for cm in commitments:
        tree.insert(cm)

    root = tree.root
    print(f"  root = {root[:18]}...")

    # Step 4: Compute nullifiers
    print("[merkle] Computing nullifiers...")
    nullifiers = []
    for i in range(NUM_INPUTS):
        nf = compute_nullifier(prover_path, commitments[i], owner_sk)
        nullifiers.append(nf)

    print(f"  nf[0] = {nullifiers[0][:18]}...")
    print(f"  nf[31] = {nullifiers[31][:18]}...")

    # Step 5: Compute output commitment
    out_rho = "9999"
    cm_out = compute_commitment(prover_path, out_value, asset_id, pk_x, pk_y, out_rho)
    print(f"[merkle] Output commitment: {cm_out[:18]}...")

    # Step 6: Assemble Prover.toml (array-based format for 32-input circuit)
    print("[merkle] Assembling witness...")

    # Collect Merkle paths as nested arrays
    all_merkle_bits = []
    all_merkle_paths = []
    for i in range(NUM_INPUTS):
        proof = tree.get_proof(i)
        all_merkle_bits.append(proof["index_bits"])
        all_merkle_paths.append(proof["siblings"])

    witness = {
        "merkle_root": root,
        "nullifiers": nullifiers,
        "cm_out": cm_out,
        "fee": str(fee),
        "asset_id": asset_id,
        "owner_sk": owner_sk,
        "in_values": [str(v) for v in values],
        "in_rhos": [str(r) for r in rhos],
        "in_merkle_bits": all_merkle_bits,
        "in_merkle_paths": all_merkle_paths,
        "out_rho": out_rho,
    }

    # Write Prover.toml
    here = os.path.dirname(os.path.abspath(__file__))
    merge_dir = os.path.join(here, "..", "tonkl-merge")
    toml_path = os.path.join(merge_dir, "Prover.toml")

    write_prover_toml(toml_path, witness)
    print(f"[merkle] Written: {toml_path}")

    # Also write JSON for inspection
    json_path = os.path.join(here, "last_merge_witness.json")
    with open(json_path, "w") as f:
        json.dump(witness, f, indent=2)
    print(f"[merkle] JSON copy: {json_path}")

    # Step 7: Verify (optional)
    if args.verify:
        print("\n[merkle] Running nargo execute for cross-verification...")
        result = subprocess.run(
            ["nargo", "execute", "merge_witness"],
            cwd=merge_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("[merkle] nargo execute PASSED -- Python tree matches Noir 32-input circuit!")
            print(f"  Witness: {merge_dir}/target/merge_witness.gz")
        else:
            print("[merkle] nargo execute FAILED:")
            print(result.stdout)
            print(result.stderr)
            sys.exit(1)

        # Clean up Prover.toml (contains sk)
        os.unlink(toml_path)
        print(f"[merkle] Cleaned up {toml_path}")
    else:
        print(f"\n[merkle] To verify: cd ../tonkl-merge && nargo execute")
        print(f"[merkle] WARNING: {toml_path} contains the spending key -- delete after use")

    return 0


if __name__ == "__main__":
    sys.exit(main())
