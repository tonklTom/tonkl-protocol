#!/usr/bin/env python3
"""
generate_reference_fixture.py
==============================

Captures a nargo-produced "golden truth" witness alongside the circuit JSON
and inputs JSON, so the Rust integration test can verify byte-exact parity
without needing nargo at test time.

Saves to: ../tests/fixtures/
  - reference_circuit.json   (compiled circuit artifact)
  - reference_inputs.json    (JSON dict sent to Rust prover via stdin)
  - reference_witness.msgpack (raw, gunzipped nargo witness — no gzip header)

Run from the obscura-prover directory:
    python3 scripts/generate_reference_fixture.py

Requires:
  - nargo on PATH
  - obscura-hasher compiled (nargo compile in ../obscura-hasher)
  - obscura-transfer compiled (nargo compile in ../obscura-transfer)

SECURITY NOTE: uses fixed DEV keys — NEVER use these values for real funds.
"""

import os
import sys
import gzip
import json
import shutil

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
PROVER_DIR    = os.path.dirname(SCRIPT_DIR)
TRANSFER_DIR  = os.path.join(os.path.dirname(PROVER_DIR), "obscura-transfer")
FIXTURE_DIR   = os.path.join(PROVER_DIR, "tests", "fixtures")

# Import generate_witness from the transfer scripts directory
TRANSFER_SCRIPTS = os.path.join(TRANSFER_DIR, "scripts")
sys.path.insert(0, TRANSFER_SCRIPTS)

import generate_witness as gw  # noqa: E402

CIRCUIT_JSON = os.path.join(TRANSFER_DIR, "target", "obscura_transfer.json")
TARGET_DIR   = os.path.join(TRANSFER_DIR, "target")


def main():
    # ── Preflight checks ─────────────────────────────────────────────────
    if not os.path.isfile(CIRCUIT_JSON):
        print(f"[!] Circuit not compiled: {CIRCUIT_JSON}")
        print("    Run: cd ../obscura-transfer && nargo compile")
        sys.exit(1)

    gw.check_nargo()

    os.makedirs(FIXTURE_DIR, exist_ok=True)
    os.makedirs(TARGET_DIR, exist_ok=True)

    # ── Generate witness inputs (random ephemeral keys) ──────────────────
    # We use the same build_and_write() as the real pipeline. The keys are
    # random each run, which is fine — we capture the exact inputs alongside
    # the witness so the Rust test can reproduce from the same JSON.
    print("[fixture] Generating witness inputs (DEV, random ephemeral keys) ...")
    result = gw.build_and_write()
    if not isinstance(result[0], dict):
        print("[!] Expected FIFO mode (prover dict in memory). Got file path.")
        print("    Ensure mkfifo is available (macOS / Linux).")
        sys.exit(1)

    prover_dict = result[0]

    # ── Convert to JSON (same format the Rust prover receives) ───────────
    json_data = {}
    for k, v in prover_dict.items():
        if isinstance(v, list):
            json_data[k] = [str(x) for x in v]
        else:
            json_data[k] = str(v)

    # ── Run nargo to produce the golden-truth witness ────────────────────
    print("[fixture] Running nargo execute for reference witness ...")
    nargo_gz = os.path.join(TARGET_DIR, "fixture_nargo.gz")

    # Write Prover.toml, execute, rename output
    prover_toml = os.path.join(TRANSFER_DIR, "Prover.toml")
    if os.path.lexists(prover_toml):
        os.unlink(prover_toml)

    gw.write_toml(prover_toml, prover_dict)
    try:
        import subprocess
        r = subprocess.run(
            ["nargo", "execute", "transfer_witness"],
            cwd=TRANSFER_DIR,
            capture_output=True,
            text=True,
        )
    finally:
        gw.secure_delete(prover_toml)

    if r.returncode != 0:
        print("[!] nargo execute failed:")
        print(r.stdout)
        print(r.stderr)
        sys.exit(1)

    default_out = os.path.join(TARGET_DIR, "transfer_witness.gz")
    if not os.path.isfile(default_out):
        print(f"[!] nargo did not produce {default_out}")
        sys.exit(1)
    shutil.move(default_out, nargo_gz)

    # ── Gunzip to get raw msgpack ────────────────────────────────────────
    with gzip.open(nargo_gz, "rb") as f:
        raw_msgpack = f.read()
    print(f"[fixture] nargo witness: {len(raw_msgpack)} bytes raw msgpack")

    # ── Save fixtures ────────────────────────────────────────────────────
    # 1. Circuit JSON (copy from compiled artifact)
    dst_circuit = os.path.join(FIXTURE_DIR, "reference_circuit.json")
    shutil.copy2(CIRCUIT_JSON, dst_circuit)
    print(f"[fixture] Saved: {os.path.relpath(dst_circuit, PROVER_DIR)}")

    # 2. Inputs JSON
    dst_inputs = os.path.join(FIXTURE_DIR, "reference_inputs.json")
    with open(dst_inputs, "w") as f:
        json.dump(json_data, f, indent=2)
    print(f"[fixture] Saved: {os.path.relpath(dst_inputs, PROVER_DIR)}")

    # 3. Raw msgpack witness (nargo golden truth)
    dst_witness = os.path.join(FIXTURE_DIR, "reference_witness.msgpack")
    with open(dst_witness, "wb") as f:
        f.write(raw_msgpack)
    print(f"[fixture] Saved: {os.path.relpath(dst_witness, PROVER_DIR)}")

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    print(f"[OK] Reference fixtures saved to tests/fixtures/")
    print(f"     circuit : {os.path.getsize(dst_circuit):,} bytes")
    print(f"     inputs  : {os.path.getsize(dst_inputs):,} bytes")
    print(f"     witness : {len(raw_msgpack):,} bytes (raw msgpack)")
    print()
    print("Next: run `cargo test --release` to verify the Rust solver")
    print("matches this reference byte-for-byte.")

    # Cleanup temp file
    os.unlink(nargo_gz)

    return 0


if __name__ == "__main__":
    sys.exit(main())
