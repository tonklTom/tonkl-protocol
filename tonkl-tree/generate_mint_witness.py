#!/usr/bin/env python3
"""
Tonkl Protocol - Mint Circuit Witness Generator (0-in/32-out)

Generates a complete, valid Prover.toml for the 0-in/32-out mint circuit.
Cross-verifies Python output against the Noir circuit by running nargo execute.

Usage:
    # Generate witness and write Prover.toml
    python3 generate_mint_witness.py

    # Then verify with nargo:
    cd ../tonkl-mint && nargo execute

    # Or run the full pipeline:
    python3 generate_mint_witness.py --verify

Whitepaper refs:
  Section 7.5 - Enforced output templates
  Section 8.6 - MVP Phase 1 scope
"""

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

NUM_OUTPUTS = 32


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
    """Write a Prover.toml file from a dict."""
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
    parser = argparse.ArgumentParser(description="Generate 0-in/32-out mint circuit witness")
    parser.add_argument(
        "--verify", action="store_true",
        help="Run nargo execute after generating witness"
    )
    parser.add_argument(
        "--authority-sk", default="0xfed001",
        help="Mint authority spending key (hex). Default: 0xfed001 (matches circuit tests)"
    )
    parser.add_argument(
        "--asset-id", default="1",
        help="Asset ID. Default: 1"
    )
    parser.add_argument(
        "--num-real", type=int, default=4,
        help="Number of real (non-zero value) output notes. Rest are zero-value padding. Default: 4"
    )
    args = parser.parse_args()

    prover_path = find_prover()
    print(f"[mint] Using prover: {prover_path}")

    authority_sk = args.authority_sk
    asset_id = args.asset_id
    num_real = min(args.num_real, NUM_OUTPUTS)

    # Step 1: Derive authority public key
    print("[mint] Deriving authority public key...")
    auth_pk_x, auth_pk_y = derive_pk(prover_path, authority_sk)
    print(f"  authority_pk_x = {auth_pk_x[:18]}...")
    print(f"  authority_pk_y = {auth_pk_y[:18]}...")

    # Step 2: Define recipients
    # First num_real-1 get real values, last real output gets remainder,
    # rest are zero-value padding owned by authority.
    recipient_sks = ["0xaaaa01", "0xbbbb02", "0xcccc03", "0xdddd04"]
    real_values = [400, 300, 200, 100]

    out_values = []
    out_pk_xs = []
    out_pk_ys = []
    out_rhos = []

    print(f"[mint] Building {NUM_OUTPUTS} output notes ({num_real} real, {NUM_OUTPUTS - num_real} padding)...")

    for i in range(NUM_OUTPUTS):
        rho = str(6001 + i)
        out_rhos.append(rho)

        if i < num_real and i < len(real_values):
            # Real recipient
            pk_x, pk_y = derive_pk(prover_path, recipient_sks[i])
            out_values.append(real_values[i])
            out_pk_xs.append(pk_x)
            out_pk_ys.append(pk_y)
            print(f"  out[{i}]: value={real_values[i]}, recipient sk={recipient_sks[i]}")
        else:
            # Zero-value padding owned by authority
            out_values.append(0)
            out_pk_xs.append(auth_pk_x)
            out_pk_ys.append(auth_pk_y)
            if i == num_real:
                print(f"  out[{i}]-out[{NUM_OUTPUTS-1}]: zero-value padding to authority")

    total_minted = sum(out_values)
    print(f"  total_minted = {total_minted}")

    # Step 3: Compute output commitments
    cms_out = []
    for i in range(NUM_OUTPUTS):
        cm = compute_commitment(prover_path, out_values[i], asset_id, out_pk_xs[i], out_pk_ys[i], out_rhos[i])
        cms_out.append(cm)
        if i < num_real:
            print(f"  cm_out[{i}] = {cm[:18]}...")

    # Step 4: Assemble Prover.toml
    print("[mint] Assembling witness...")

    witness = {
        # Public inputs
        "cm_outs": cms_out,
        "total_minted": str(total_minted),
        "asset_id": asset_id,
        "authority_pk_x": auth_pk_x,
        "authority_pk_y": auth_pk_y,
        # Private
        "authority_sk": authority_sk,
        "out_values": [str(v) for v in out_values],
        "out_pk_xs": out_pk_xs,
        "out_pk_ys": out_pk_ys,
        "out_rhos": [str(r) for r in out_rhos],
    }

    # Write Prover.toml
    here = os.path.dirname(os.path.abspath(__file__))
    mint_dir = os.path.join(here, "..", "tonkl-mint")
    toml_path = os.path.join(mint_dir, "Prover.toml")

    write_prover_toml(toml_path, witness)
    print(f"[mint] Written: {toml_path}")

    # Also write JSON for inspection
    json_path = os.path.join(here, "last_mint_witness.json")
    with open(json_path, "w") as f:
        json.dump(witness, f, indent=2)
    print(f"[mint] JSON copy: {json_path}")

    # Step 5: Verify (optional)
    if args.verify:
        print("\n[mint] Running nargo execute for cross-verification...")
        result = subprocess.run(
            ["nargo", "execute", "mint_witness"],
            cwd=mint_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("[mint] nargo execute PASSED -- Python matches Noir mint circuit!")
            print(f"  Witness: {mint_dir}/target/mint_witness.gz")
        else:
            print("[mint] nargo execute FAILED:")
            print(result.stdout)
            print(result.stderr)
            sys.exit(1)

        # Clean up Prover.toml (contains sk)
        os.unlink(toml_path)
        print(f"[mint] Cleaned up {toml_path}")
    else:
        print(f"\n[mint] To verify: cd ../tonkl-mint && nargo execute")
        print(f"[mint] WARNING: {toml_path} contains the authority sk -- delete after use")

    return 0


if __name__ == "__main__":
    sys.exit(main())
