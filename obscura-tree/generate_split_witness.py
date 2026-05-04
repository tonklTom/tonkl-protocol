#!/usr/bin/env python3
"""
Tonkl Protocol - Split Circuit Witness Generator (1-in/32-out)

Generates a complete, valid Prover.toml for the 1-in/32-out multi-recipient
split circuit using the Python MerkleTree. Cross-verifies Python tree
output against the Noir circuit by running nargo execute.

Usage:
    # Generate witness and write Prover.toml
    python3 generate_split_witness.py

    # Then verify with nargo:
    cd ../obscura-split && nargo execute

    # Or run the full pipeline:
    python3 generate_split_witness.py --verify

Whitepaper refs:
  Section 7.5 - Enforced output templates (1-in/32-out split)
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


NUM_OUTPUTS = 32


def find_prover():
    """Locate the obscura-prover binary."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "obscura-prover", "target", "release", "obscura-prover"),
        os.path.join(here, "..", "obscura-prover", "target", "debug", "obscura-prover"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    print("[!] obscura-prover binary not found.")
    print("    Build it: cd obscura-prover && cargo build --release")
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
    """Write a Prover.toml file from a dict, handling arrays."""
    lines = []
    for key, val in data.items():
        if isinstance(val, list):
            if len(val) > 0 and isinstance(val[0], bool):
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
    parser = argparse.ArgumentParser(description="Generate 1-in/32-out split circuit witness")
    parser.add_argument(
        "--verify", action="store_true",
        help="Run nargo execute after generating witness"
    )
    parser.add_argument(
        "--owner-sk", default="0xae0901",
        help="Sender spending key (hex). Default: 0xae0901 (matches circuit tests)"
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
        "--in-value", default="1000",
        help="Input note value. Default: 1000"
    )
    parser.add_argument(
        "--num-real", type=int, default=4,
        help="Number of real (non-zero value) output notes. Rest are zero-value padding. Default: 4"
    )
    args = parser.parse_args()

    prover_path = find_prover()
    print(f"[split] Using prover: {prover_path}")

    owner_sk = args.owner_sk
    asset_id = args.asset_id
    fee = int(args.fee)
    in_value = int(args.in_value)
    num_real = min(args.num_real, NUM_OUTPUTS)

    # Step 1: Derive sender public key
    print("[split] Deriving sender public key...")
    sender_pk_x, sender_pk_y = derive_pk(prover_path, owner_sk)
    print(f"  sender_pk_x = {sender_pk_x[:18]}...")
    print(f"  sender_pk_y = {sender_pk_y[:18]}...")

    # Step 2: Create input note
    in_rho = "7001"
    print(f"[split] Building input note (value={in_value}, rho={in_rho})...")
    cm_in = compute_commitment(prover_path, in_value, asset_id, sender_pk_x, sender_pk_y, in_rho)
    print(f"  cm_in = {cm_in[:18]}...")

    # Step 3: Build Merkle tree (single leaf at position 0)
    print("[split] Building Merkle tree (1 leaf)...")
    tree = MerkleTree(prover_path=prover_path)
    tree.insert(cm_in)
    merkle_root = tree.root
    proof = tree.get_proof(0)
    print(f"  root = {merkle_root[:18]}...")

    # Step 4: Compute nullifier
    nf = compute_nullifier(prover_path, cm_in, owner_sk)
    print(f"  nf = {nf[:18]}...")

    # Step 5: Define 32 output recipients
    # First few get real values, rest are zero-value padding to sender
    recipient_sks = ["0xaaaa01", "0xbbbb02", "0xcccc03"]
    real_values = [400, 300, 200]

    # Compute remaining value for change output
    real_total = sum(real_values[:min(len(real_values), num_real - 1)])
    change_value = in_value - real_total - fee

    out_values = []
    out_pk_xs = []
    out_pk_ys = []
    out_rhos = []

    print(f"[split] Building {NUM_OUTPUTS} output notes ({num_real} real, {NUM_OUTPUTS - num_real} padding)...")
    print(f"  in_value={in_value}, fee={fee}")

    for i in range(NUM_OUTPUTS):
        rho = str(8001 + i)
        out_rhos.append(rho)

        if i < len(real_values) and i < num_real - 1:
            # Real recipient
            pk_x, pk_y = derive_pk(prover_path, recipient_sks[i])
            out_values.append(real_values[i])
            out_pk_xs.append(pk_x)
            out_pk_ys.append(pk_y)
            print(f"  out[{i}]: value={real_values[i]}, recipient sk={recipient_sks[i]}")
        elif i == num_real - 1:
            # Change output to sender (or last real output)
            out_values.append(change_value)
            out_pk_xs.append(sender_pk_x)
            out_pk_ys.append(sender_pk_y)
            print(f"  out[{i}]: value={change_value} (change to sender)")
        else:
            # Zero-value padding to sender
            out_values.append(0)
            out_pk_xs.append(sender_pk_x)
            out_pk_ys.append(sender_pk_y)
            if i == num_real:
                print(f"  out[{i}]-out[{NUM_OUTPUTS-1}]: zero-value padding to sender")

    # Compute output commitments
    cms_out = []
    for i in range(NUM_OUTPUTS):
        cm = compute_commitment(prover_path, out_values[i], asset_id, out_pk_xs[i], out_pk_ys[i], out_rhos[i])
        cms_out.append(cm)
        if i < num_real:
            print(f"  cm_out[{i}] = {cm[:18]}...")

    # Step 6: Assemble Prover.toml (array-based format for 32-output circuit)
    print("[split] Assembling witness...")

    witness = {
        # Public inputs
        "merkle_root": merkle_root,
        "nf": nf,
        "cm_outs": cms_out,
        "fee": str(fee),
        "asset_id": asset_id,
        # Private: input note
        "owner_sk": owner_sk,
        "in_value": str(in_value),
        "in_rho": in_rho,
        "in_merkle_bits": proof["index_bits"],
        "in_merkle_path": proof["siblings"],
        # Private: output notes (arrays)
        "out_values": [str(v) for v in out_values],
        "out_pk_xs": out_pk_xs,
        "out_pk_ys": out_pk_ys,
        "out_rhos": [str(r) for r in out_rhos],
    }

    # Write Prover.toml
    here = os.path.dirname(os.path.abspath(__file__))
    split_dir = os.path.join(here, "..", "obscura-split")
    toml_path = os.path.join(split_dir, "Prover.toml")

    write_prover_toml(toml_path, witness)
    print(f"[split] Written: {toml_path}")

    # Also write JSON for inspection
    json_path = os.path.join(here, "last_split_witness.json")
    with open(json_path, "w") as f:
        json.dump(witness, f, indent=2)
    print(f"[split] JSON copy: {json_path}")

    # Step 7: Verify (optional)
    if args.verify:
        print("\n[split] Running nargo execute for cross-verification...")
        result = subprocess.run(
            ["nargo", "execute", "split_witness"],
            cwd=split_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("[split] nargo execute PASSED -- Python tree matches Noir 32-output split circuit!")
            print(f"  Witness: {split_dir}/target/split_witness.gz")
        else:
            print("[split] nargo execute FAILED:")
            print(result.stdout)
            print(result.stderr)
            sys.exit(1)

        # Clean up Prover.toml (contains sk)
        os.unlink(toml_path)
        print(f"[split] Cleaned up {toml_path}")
    else:
        print(f"\n[split] To verify: cd ../obscura-split && nargo execute")
        print(f"[split] WARNING: {toml_path} contains the spending key -- delete after use")

    return 0


if __name__ == "__main__":
    sys.exit(main())
