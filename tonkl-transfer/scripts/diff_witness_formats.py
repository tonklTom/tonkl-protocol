#!/usr/bin/env python3
"""
diff_witness_formats.py
=======================

Diagnostic harness: run the Rust tonkl-prover and `nargo execute` on
IDENTICAL inputs, then byte-diff the resulting witness files. This isolates
the msgpack encoding layer from any input-side divergence.

Output:
  target/witness_nargo.gz   -- produced by `nargo execute`
  target/witness_rust.gz    -- produced by ./tonkl-prover
  target/witness_nargo.mp   -- gunzipped nargo witness (raw msgpack)
  target/witness_rust.mp    -- gunzipped Rust  witness (raw msgpack)

Exit code 0 if bytes match, 1 otherwise. On mismatch, prints first diff
offset, context bytes, and structural interpretation.

This script contains sk on disk briefly (unavoidable for the nargo half of
the diff — nargo reads TOML from the filesystem). The TOML is overwritten
with random bytes and deleted immediately after use. DO NOT run on mainnet
keys. Use ephemeral DEV keys only.
"""

import os
import sys
import gzip
import shutil
import subprocess
import json

# Make sibling generate_witness module importable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import generate_witness as gw  # noqa: E402

TRANSFER_DIR = gw.TRANSFER_DIR
TARGET_DIR   = os.path.join(TRANSFER_DIR, "target")
CIRCUIT_JSON = os.path.join(TARGET_DIR, "tonkl_transfer.json")

RUST_BIN = gw.RUST_PROVER_BIN
RUST_BIN_BAK = RUST_BIN + ".bak"


def ensure_rust_binary_present():
    """If the user moved it to .bak for the nargo-isolation test, restore."""
    if os.path.isfile(RUST_BIN) and os.access(RUST_BIN, os.X_OK):
        return
    if os.path.isfile(RUST_BIN_BAK):
        shutil.move(RUST_BIN_BAK, RUST_BIN)
        os.chmod(RUST_BIN, 0o755)
        print(f"[diff] Restored Rust binary from {RUST_BIN_BAK}")
        return
    print(f"[✗] Rust prover binary not found at {RUST_BIN}")
    print("     Build with: (cd ../tonkl-prover && cargo build --release)")
    sys.exit(1)


def run_nargo_on_prover_dict(prover_dict: dict, out_witness_gz: str) -> None:
    """Write Prover.toml, run nargo execute, rename the output witness."""
    prover_toml = os.path.join(TRANSFER_DIR, "Prover.toml")

    # Remove any leftover symlink / file from prior runs
    if os.path.lexists(prover_toml):
        os.unlink(prover_toml)

    gw.write_toml(prover_toml, prover_dict)
    try:
        r = subprocess.run(
            ["nargo", "execute", "transfer_witness"],
            cwd=TRANSFER_DIR,
            capture_output=True,
            text=True,
        )
    finally:
        # sk is on disk in Prover.toml -- overwrite + delete immediately
        gw.secure_delete(prover_toml)

    if r.returncode != 0:
        print("[✗] nargo execute failed:")
        print(r.stdout)
        print(r.stderr)
        sys.exit(1)

    default_out = os.path.join(TARGET_DIR, "transfer_witness.gz")
    if not os.path.isfile(default_out):
        print(f"[✗] nargo did not produce {default_out}")
        sys.exit(1)
    shutil.move(default_out, out_witness_gz)
    print(f"[nargo] witness  -> {os.path.relpath(out_witness_gz)}")


def run_rust_on_prover_dict(prover_dict: dict, out_witness_gz: str) -> None:
    """Pipe the SAME dict as JSON into tonkl-prover, rename output."""
    rc, stderr = gw._run_rust_prover(prover_dict, CIRCUIT_JSON, out_witness_gz)
    if rc != 0:
        print("[✗] tonkl-prover failed:")
        print(stderr)
        sys.exit(1)
    for line in stderr.strip().splitlines():
        print(f"  [rust] {line}")
    print(f"[rust ] witness  -> {os.path.relpath(out_witness_gz)}")


def gunzip_to(src_gz: str, dst_raw: str) -> bytes:
    with gzip.open(src_gz, "rb") as f:
        data = f.read()
    with open(dst_raw, "wb") as f:
        f.write(data)
    return data


def hex_window(buf: bytes, center: int, radius: int = 16) -> str:
    lo = max(0, center - radius)
    hi = min(len(buf), center + radius + 1)
    parts = []
    for i in range(lo, hi):
        marker = "*" if i == center else " "
        parts.append(f"{marker}{buf[i]:02x}")
    return " ".join(parts) + f"   (offsets {lo}..{hi - 1}, marked byte at {center})"


def byte_diff(a: bytes, b: bytes) -> int:
    """Return first differing offset, or -1 if equal up to min(len)."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return n
    return -1


def main():
    ensure_rust_binary_present()

    if not os.path.isfile(CIRCUIT_JSON):
        print(f"[✗] Circuit not compiled: {CIRCUIT_JSON}")
        print("    Build with: (cd .. && nargo compile)")
        sys.exit(1)

    os.makedirs(TARGET_DIR, exist_ok=True)

    print("[diff] Generating witness inputs (DEV, random ephemeral keys) ...")
    result = gw.build_and_write()
    if isinstance(result[0], dict):
        prover_dict = result[0]
    else:
        # Fallback path wrote a TOML we don't want; read it back
        print("[✗] Expected FIFO mode (prover dict in memory). Got file path.")
        sys.exit(1)

    out_nargo_gz = os.path.join(TARGET_DIR, "witness_nargo.gz")
    out_rust_gz  = os.path.join(TARGET_DIR, "witness_rust.gz")

    print()
    print("[diff] ---- running NARGO path ----")
    run_nargo_on_prover_dict(prover_dict, out_nargo_gz)

    print()
    print("[diff] ---- running RUST  path ----")
    run_rust_on_prover_dict(prover_dict, out_rust_gz)

    print()
    print("[diff] Gunzipping both witnesses ...")
    raw_nargo = gunzip_to(out_nargo_gz, os.path.join(TARGET_DIR, "witness_nargo.mp"))
    raw_rust  = gunzip_to(out_rust_gz,  os.path.join(TARGET_DIR, "witness_rust.mp"))
    print(f"  nargo raw msgpack: {len(raw_nargo)} bytes")
    print(f"  rust  raw msgpack: {len(raw_rust)} bytes")

    # Also diff the gzipped files (bb consumes these directly)
    with open(out_nargo_gz, "rb") as f: gz_nargo = f.read()
    with open(out_rust_gz,  "rb") as f: gz_rust  = f.read()
    print(f"  nargo gzipped   : {len(gz_nargo)} bytes")
    print(f"  rust  gzipped   : {len(gz_rust)} bytes")

    off = byte_diff(raw_nargo, raw_rust)
    if off == -1:
        print()
        print("[✓] msgpack payloads BIT-IDENTICAL.")
        print("    Either gzip framing differs (harmless) or something else is up.")
        gz_off = byte_diff(gz_nargo, gz_rust)
        if gz_off == -1:
            print("[✓] gzipped files also bit-identical.")
        else:
            print(f"[!] gzipped files differ at byte {gz_off} "
                  "(likely header metadata, not payload).")
        return 0

    print()
    print(f"[✗] First msgpack byte difference at offset {off}")
    print(f"    nargo has 0x{raw_nargo[off]:02x}, rust has 0x{raw_rust[off]:02x}")
    print()
    print("  NARGO context:")
    print("    " + hex_window(raw_nargo, off))
    print("  RUST  context:")
    print("    " + hex_window(raw_rust, off))
    print()
    print(f"  saved: target/witness_nargo.mp  ({len(raw_nargo)} bytes)")
    print(f"  saved: target/witness_rust.mp   ({len(raw_rust)}  bytes)")
    print()
    print("  To inspect further:")
    print(f"    xxd target/witness_nargo.mp | sed -n '{max(1, off//16 - 1)},{off//16 + 3}p'")
    print(f"    xxd target/witness_rust.mp  | sed -n '{max(1, off//16 - 1)},{off//16 + 3}p'")
    return 1


if __name__ == "__main__":
    sys.exit(main())
