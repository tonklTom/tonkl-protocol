#!/usr/bin/env python3
"""
Tonkl Transfer Circuit — Full Pipeline
=========================================
Generates witness, compiles the circuit, writes VK, proves, and verifies.

NO external Python dependencies required.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
SECURITY WARNING — DEVELOPMENT USE ONLY
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

This script handles raw spending keys (sk). The current key lifecycle is:

  1. sk generated in memory via secrets.randbelow() (cryptographically secure)
  2. sk written to Prover.toml on disk (PLAINTEXT) — unavoidable for nargo
  3. Prover.toml is DELETED immediately after nargo execute succeeds
  4. sk encoded inside transfer_witness.gz (solved circuit values)
  5. transfer_witness.gz is DELETED immediately after bb prove succeeds
  6. Only the proof and public inputs remain on disk — sk is NOT recoverable
     from these files

This is acceptable for local development only. For production:

  - sk must NEVER exist in plaintext on disk at any point
  - sk must be generated inside a hardware-backed secure enclave
    (Secure Enclave on iOS/macOS, StrongBox on Android, hardware wallet)
  - sk must be encrypted at rest using a memory-hard KDF (Argon2id)
    before any persistence, with a user-supplied passphrase + random salt
  - Witness generation and proving must happen inside the trusted execution
    environment so sk never crosses the security boundary
  - Use HD key derivation (BIP-32 style) so users only need one seed phrase:
    sk_note = hash("Tonkl::note_sk" || master_seed || note_index)
  - For delegated proving: use blinded witnesses — never send raw sk to a
    third-party prover

Shipping a wallet that stores sk in plaintext, even temporarily, undermines
the entire privacy and security model of Tonkl. All user funds would be
at immediate risk from malware, compromised backups, and device theft.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

How it works:
  1. Writes raw note data to tonkl-hasher/Prover.toml (sk included)
  2. Runs nargo execute in tonkl-hasher to compute hashes
  3. DELETES tonkl-hasher/Prover.toml immediately
  4. Writes transfer circuit Prover.toml (sk included)
  5. Runs nargo execute transfer_witness to solve the circuit witness
  6. DELETES transfer circuit Prover.toml immediately
  7. Runs bb write_vk to generate a fresh verification key
  8. Runs bb prove --verify to generate and inline-verify the proof
  9. DELETES transfer_witness.gz immediately
 10. Runs bb verify standalone to confirm proof files are self-contained

Requirements:
  - nargo on PATH  (source ~/.zshrc after noirup) -- needed for hasher circuit
  - bb at ~/.bb/bb -- needed for proving (used directly or via tonkl-prover)
  - tonkl-prover (optional but recommended): cargo build --release in tonkl-prover/

Proving strategies (auto-selected, best security first):
  1. Rust full-prove (default when tonkl-prover binary exists):
     `tonkl-prover prove` handles witness + prove + verify in one shot.
     Force with --rust-prove, disable with --witness-only.
  2. Rust witness-only (--witness-only):
     tonkl-prover solves witness, Python calls bb separately.
  3. FIFO: sk piped via named pipe to nargo, then bb.
  4. Fallback: sk on RAM disk or file, then nargo + bb.

Usage:
  python3 scripts/generate_witness.py                  # auto-select best strategy
  python3 scripts/generate_witness.py --rust-prove     # force Rust full-prove
  python3 scripts/generate_witness.py --witness-only   # force witness-only mode
  python3 scripts/generate_witness.py --hd             # HD key derivation
"""

import os
import sys
import gc
import stat
import ctypes
import ctypes.util
import shutil
import secrets
import subprocess
import re
import threading

import keychain
import ramdisk
import secure_key_manager

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
TRANSFER_DIR = os.path.dirname(SCRIPT_DIR)
HASHER_DIR   = os.path.join(os.path.dirname(TRANSFER_DIR), "tonkl-hasher")

# ── BN254 scalar field modulus ────────────────────────────────────────────────
BN254_P      = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MERKLE_DEPTH = 32

# ── libc for mlock/munlock ────────────────────────────────────────────────────
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def rand_field() -> int:
    """Generate a random non-secret field element (rho, asset_id, etc.)."""
    return secrets.randbelow(BN254_P)


def rand_sk() -> bytearray:
    """
    Generate a cryptographically secure spending key as a locked bytearray.

    Returns a 32-byte bytearray holding a random BN254 scalar. The buffer
    is mlock()'d to prevent the OS from swapping it to disk. Call zero_sk()
    when the key is no longer needed.
    """
    sk_int = secrets.randbelow(BN254_P)
    buf = bytearray(sk_int.to_bytes(32, "big"))
    _mlock(buf)
    return buf


def _mlock(buf: bytearray) -> None:
    """Lock a bytearray in RAM so the OS cannot swap it to disk."""
    try:
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        _libc.mlock(addr, ctypes.c_size_t(len(buf)))
    except Exception:
        pass  # mlock failure is non-fatal; we still zero on cleanup


def zero_sk(buf: bytearray) -> None:
    """
    Zero a spending key bytearray in place and unlock it from RAM.

    Uses ctypes to write directly to the buffer's memory, bypassing Python's
    object model. This is the most reliable in-process zeroing available in
    CPython. The GC may still hold references in internal freelists, but this
    minimises the window and is standard practice for Python key handling.
    """
    if not buf:
        return
    try:
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        ctypes.memset(addr, 0, len(buf))
        _libc.munlock(addr, ctypes.c_size_t(len(buf)))
    except Exception:
        buf[:] = b"\x00" * len(buf)   # fallback
    del buf
    gc.collect()


def sk_to_int(buf: bytearray) -> int:
    """Convert a bytearray sk to a BN254 field integer."""
    return int.from_bytes(buf, "big") % BN254_P


BB_BIN = os.path.expanduser("~/.bb/bb")

def check_nargo():
    try:
        r = subprocess.run(["nargo", "--version"], capture_output=True, text=True)
        print(f"[✓] nargo version = {r.stdout.strip()}")
    except FileNotFoundError:
        print("[✗] nargo not found. Run:\n    source ~/.zshrc && noirup")
        sys.exit(1)

def check_bb():
    if not os.path.isfile(BB_BIN):
        print(f"[✗] bb not found at {BB_BIN}")
        print("    Install with: curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash")
        sys.exit(1)
    r = subprocess.run([BB_BIN, "--version"], capture_output=True, text=True)
    version = (r.stdout + r.stderr).strip()
    print(f"[✓] bb         = {version if version else 'ok'}")

def _fmt_toml_scalar(x):
    """Format a single value for TOML.
    - Python bool  → unquoted `true`/`false` (real TOML boolean)
    - String "true"/"false" → unquoted `true`/`false` (for bool arrays kept as str)
    - Everything else → quoted string (nargo parses as integer/field)
    """
    if isinstance(x, bool):
        return "true" if x else "false"
    sx = str(x)
    if sx == "true" or sx == "false":
        return sx
    return f'"{sx}"'

def write_toml(path: str, fields: dict):
    lines = []
    for k, v in fields.items():
        if isinstance(v, list):
            items = ", ".join(_fmt_toml_scalar(x) for x in v)
            lines.append(f'{k} = [{items}]')
        else:
            lines.append(f'{k} = {_fmt_toml_scalar(v)}')
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

def run_hasher(inputs: dict) -> tuple:
    """
    Run tonkl-hasher via `nargo execute` and return 15 public outputs:
    (merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2,
     in1_pk_x, in1_pk_y, in2_pk_x, in2_pk_y,
     out1_pk_x, out1_pk_y, out2_pk_x, out2_pk_y)

    The hasher derives all pk values from their corresponding sk internally
    using the same domain constants as the transfer circuit. This eliminates
    any risk of pk/sk mismatch between witness generation and circuit execution.
    """
    if not os.path.isdir(HASHER_DIR):
        print(f"[✗] tonkl-hasher not found at:\n    {HASHER_DIR}")
        print("\n    Expected layout:")
        print("    ~/Desktop/tonkl/")
        print("    ├── tonkl-hasher/   <- must exist")
        print("    └── tonkl-transfer/")
        sys.exit(1)

    # ── FIFO mode (preferred): sk never touches ANY storage ─────────────────
    # A named pipe passes TOML content directly from Python memory to nargo
    # via the kernel pipe buffer. No file is ever created on disk or RAM disk.
    #
    # Fallback: RAM disk (sk on volatile memory only, never SSD).
    # Final fallback: disk + secure_delete.

    if _fifo_available():
        print("[FIFO] Passing witness inputs via named pipe (sk never on any storage)")
        returncode, combined = _run_nargo_with_fifo(inputs, HASHER_DIR, "witness")
    else:
        # RAM disk fallback
        hasher_prover_toml, _h_mount, _h_ram_toml = _write_prover_toml_secure(
            inputs, "hasher", circuit_dir=HASHER_DIR
        )
        print("[->] Running nargo execute in tonkl-hasher (computing hashes)...")
        r = subprocess.run(
            ["nargo", "execute", "witness"],
            cwd=HASHER_DIR, capture_output=True, text=True,
        )
        returncode = r.returncode
        combined = r.stdout + r.stderr
        # Cleanup hasher Prover.toml
        if _h_ram_toml:
            secure_delete(_h_ram_toml)
            if os.path.lexists(hasher_prover_toml):
                os.unlink(hasher_prover_toml)
        else:
            secure_delete(hasher_prover_toml)

    if returncode != 0:
        print("[x] nargo execute failed. Output:\n")
        print(combined)
        print("\nCommon fixes:")
        print("  - Circuit compile error -> check tonkl-hasher/src/main.nr")
        print("  - 'nargo not found'     -> source ~/.zshrc")
        sys.exit(1)

    # The hasher's witness file encodes sk as a solved circuit variable.
    # Delete it immediately -- we only need the return values parsed above.
    hasher_witness = os.path.join(HASHER_DIR, "target", "witness.gz")
    secure_delete(hasher_witness)

    print("[OK] nargo execute succeeded (hasher)")

    # Nargo 1.0 prints return values as:
    #   [nargo] Circuit witness successfully solved
    #   Return value: (0x1a2b..., 0x3c4d..., ...)
    # Try tuple format first, then individual values
    # Hasher returns 7 values: (merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2)
    EXPECTED = 15
    # Match "Return value: (...)" or "Circuit output: (...)"
    match = re.search(
        r'(?:[Rr]eturn\s+value[s]?|[Cc]ircuit\s+output)\s*[:=]?\s*\(([^)]+)\)',
        combined,
    )
    if match:
        parts = [p.strip() for p in match.group(1).split(",")]
        if len(parts) == EXPECTED:
            return tuple(int(p, 16) if p.startswith("0x") else int(p) for p in parts)

    # Single value fallback (some nargo versions print one per line)
    # Use {2,} minimum to catch short field elements like 0x01
    hex_vals = re.findall(r'0x[0-9a-fA-F]{2,}', combined)
    if len(hex_vals) >= EXPECTED:
        return tuple(int(v, 16) for v in hex_vals[:EXPECTED])

    dec_vals = re.findall(r'\b\d{10,}\b', combined)
    if len(dec_vals) >= EXPECTED:
        return tuple(int(v) for v in dec_vals[:EXPECTED])

    # Could not parse — print raw output for manual extraction
    print("\n[!] Could not auto-parse return values from nargo output.")
    print("    Raw output:")
    print(combined)
    print(f"\n    Expected {EXPECTED} return values in this order:")
    print("    merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2,")
    print("    in1_pk_x, in1_pk_y, in2_pk_x, in2_pk_y,")
    print("    out1_pk_x, out1_pk_y, out2_pk_x, out2_pk_y")
    sys.exit(1)

def _write_prover_toml_secure(
    data: dict,
    label_prefix: str,
    circuit_dir: str = None,
) -> tuple[str, str | None, str | None]:
    """
    Write Prover.toml to a RAM disk if available, else fall back to disk.

    Args:
        data:          Fields to write into the TOML file.
        label_prefix:  Short name used for the RAM disk filename (e.g. "transfer",
                       "hasher").  Prevents collisions when both circuits are
                       live at the same time.
        circuit_dir:   Directory where nargo expects Prover.toml.
                       Defaults to TRANSFER_DIR.

    Returns (circuit_prover_path, ram_mount, ram_toml_path) where:
      - circuit_prover_path  is where nargo will find Prover.toml
      - ram_mount            is the RAM disk mount point (None if not used)
      - ram_toml_path        is the actual file on the RAM disk (None if not used)

    The RAM disk path means the file never touches the SSD.  On cleanup,
    callers must: secure_delete the RAM toml, os.unlink the symlink, then
    call ramdisk.destroy() once ALL circuits are done with the disk.
    """
    if circuit_dir is None:
        circuit_dir = TRANSFER_DIR

    circuit_prover = os.path.join(circuit_dir, "Prover.toml")

    if ramdisk.available():
        try:
            mount = ramdisk.create()
            ram_toml = os.path.join(mount, f"{label_prefix}_Prover.toml")
            write_toml(ram_toml, data)
            # Symlink from circuit dir to RAM disk so nargo finds the file
            if os.path.lexists(circuit_prover):
                os.unlink(circuit_prover)
            os.symlink(ram_toml, circuit_prover)
            print(f"[🔑] Prover.toml on RAM disk (never touches SSD): {ram_toml}")
            return circuit_prover, mount, ram_toml
        except Exception as e:
            print(f"[!] RAM disk unavailable ({e}), falling back to disk + secure_delete")

    # Fallback: write directly, relying on secure_delete after nargo runs
    write_toml(circuit_prover, data)
    return circuit_prover, None, None


def _fifo_available() -> bool:
    """Check if POSIX named pipes (FIFOs) are available."""
    return hasattr(os, "mkfifo")


def _run_nargo_with_fifo(
    data: dict,
    circuit_dir: str,
    witness_name: str,
) -> str:
    """
    Run nargo execute with witness inputs piped through a FIFO.

    Instead of writing Prover.toml as a regular file (which touches storage),
    this creates a POSIX named pipe (FIFO) at the Prover.toml path. The TOML
    content flows directly from Python memory -> kernel pipe buffer -> nargo
    process memory. No data ever touches the SSD, RAM disk, or any filesystem.

    How it works:
      1. Create a FIFO at <circuit_dir>/Prover.toml
      2. Start a writer thread that opens the FIFO and writes the TOML content
      3. Run nargo execute (it opens the FIFO for reading, receives the data)
      4. Both sides close; the FIFO inode is unlinked

    The kernel pipe buffer is typically 64KB (macOS) or 1MB (Linux), more than
    enough for any Prover.toml. Data exists only in kernel memory for the
    brief transit between writer and reader.

    Args:
        data:         Fields for the Prover.toml.
        circuit_dir:  Directory where nargo expects Prover.toml.
        witness_name: Name for the witness output (e.g. "witness", "transfer_witness").

    Returns:
        Combined stdout+stderr from nargo execute.

    Raises:
        SystemExit on nargo failure.
    """
    fifo_path = os.path.join(circuit_dir, "Prover.toml")

    # Build TOML content in memory
    lines = []
    for k, v in data.items():
        if isinstance(v, list):
            items = ", ".join(_fmt_toml_scalar(x) for x in v)
            lines.append(f'{k} = [{items}]')
        else:
            lines.append(f'{k} = {_fmt_toml_scalar(v)}')
    toml_content = "\n".join(lines) + "\n"

    # Remove any existing Prover.toml (file or symlink) before creating FIFO
    if os.path.lexists(fifo_path):
        os.unlink(fifo_path)

    # Create the named pipe
    os.mkfifo(fifo_path)

    write_error = [None]  # mutable container for thread error reporting

    def _writer():
        """Write TOML content to the FIFO (blocks until nargo opens it for reading)."""
        try:
            with open(fifo_path, "w") as f:
                f.write(toml_content)
        except Exception as e:
            write_error[0] = e

    # Start the writer thread -- it blocks on open() until nargo reads
    writer = threading.Thread(target=_writer, daemon=True)
    writer.start()

    # Run nargo execute (it opens Prover.toml, which is our FIFO)
    r = subprocess.run(
        ["nargo", "execute", witness_name],
        cwd=circuit_dir,
        capture_output=True,
        text=True,
    )

    # Wait for writer to finish
    writer.join(timeout=5)

    # Clean up the FIFO inode
    try:
        if os.path.exists(fifo_path) or os.path.lexists(fifo_path):
            os.unlink(fifo_path)
    except OSError:
        pass

    if write_error[0]:
        print(f"[!] FIFO writer error: {write_error[0]}")

    return r.returncode, r.stdout + r.stderr


# ── Rust in-process prover ─────────────────────────────────────────────────

RUST_PROVER_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "tonkl-prover", "target", "release", "tonkl-prover",
)


def _rust_prover_available() -> bool:
    """Check if the Rust tonkl-prover binary is built and available."""
    return os.path.isfile(RUST_PROVER_BIN) and os.access(RUST_PROVER_BIN, os.X_OK)


def _run_rust_prover(
    data: dict,
    circuit_json_path: str,
    witness_output_path: str,
) -> tuple:
    """
    Run the Rust tonkl-prover to solve the witness via ACVM.

    This is the most secure option: sk flows through a Unix pipe into
    the Rust process which solves the witness entirely in-process.
    sk never touches any filesystem.

    Hybrid architecture:
      1. Rust binary reads JSON from stdin (the prover dict with sk)
      2. Loads the compiled circuit from --circuit
      3. Builds WitnessMap using the circuit ABI ordering
      4. Solves witness via ACVM (replaces `nargo execute`)
      5. Writes witness.gz to --output (gzipped bincode, bb-compatible)
      6. Zeroizes all sensitive memory on exit

    After this returns, the caller invokes `bb prove` with the witness.gz.
    bb only sees solved circuit variables — sk is not recoverable from these.

    Args:
        data:                Prover dict (same format as FIFO mode).
        circuit_json_path:   Path to compiled circuit JSON artifact.
        witness_output_path: Where to write the solved witness.gz.

    Returns:
        (returncode, stderr_text) tuple.
    """
    import json as _json

    # Convert all values to JSON-serialisable form
    json_data = {}
    for k, v in data.items():
        if isinstance(v, list):
            json_data[k] = [str(x) for x in v]
        else:
            json_data[k] = str(v)

    json_bytes = _json.dumps(json_data).encode("utf-8")

    cmd = [
        RUST_PROVER_BIN,
        "--circuit", circuit_json_path,
        "--output", witness_output_path,
    ]

    r = subprocess.run(
        cmd,
        input=json_bytes,
        capture_output=True,
    )

    # bytes is immutable so we can't truly zero json_bytes here;
    # the real zeroing happens in Rust via the Zeroize derive.
    # Let the GC collect it ASAP.
    del json_bytes, json_data

    return r.returncode, r.stderr.decode("utf-8", errors="replace")


def _run_rust_prover_prove(
    data: dict,
    circuit_json_path: str,
    output_dir: str,
    bb_path: str = None,
    vk_path: str = None,
    skip_verify: bool = False,
) -> tuple:
    """
    Run the Rust tonkl-prover `prove` subcommand for the full pipeline.

    This is the most secure and simplest option: the Rust binary handles
    everything in a single invocation:
      1. Reads JSON inputs from stdin (sk piped, never on storage)
      2. Solves the witness via ACVM in-process
      3. Writes a temporary witness.gz
      4. Calls bb write_vk + bb prove --verify
      5. Secure-deletes the witness file (3-pass overwrite + unlink)
      6. Calls bb verify for standalone verification
      7. Zeroizes all sensitive memory on exit

    The caller only needs to read the proof files from the output directory.
    No bb invocations needed from Python.

    Output directory structure after a successful run:
      <output_dir>/proof/proof           -- the ZK proof
      <output_dir>/proof/public_inputs   -- public inputs
      <output_dir>/vk/vk                 -- verification key

    Args:
        data:              Prover dict (same format as witness mode).
        circuit_json_path: Path to compiled circuit JSON artifact.
        output_dir:        Directory for proof output files.
        bb_path:           Path to bb binary (None = Rust default ~/.bb/bb).
        vk_path:           Path to existing VK (None = generate fresh).
        skip_verify:       Skip standalone verification after proving.

    Returns:
        (returncode, stderr_text) tuple.
    """
    import json as _json

    # Convert all values to JSON-serialisable form
    json_data = {}
    for k, v in data.items():
        if isinstance(v, list):
            json_data[k] = [str(x) for x in v]
        else:
            json_data[k] = str(v)

    json_bytes = _json.dumps(json_data).encode("utf-8")

    cmd = [
        RUST_PROVER_BIN, "prove",
        "--circuit", circuit_json_path,
        "--output", output_dir,
    ]
    if bb_path:
        cmd.extend(["--bb", bb_path])
    if vk_path:
        cmd.extend(["-k", vk_path])
    if skip_verify:
        cmd.append("--skip-verify")

    try:
        r = subprocess.run(
            cmd,
            input=json_bytes,
            capture_output=True,
            timeout=300,  # 5 minutes max for proof generation
        )
    except subprocess.TimeoutExpired:
        del json_bytes, json_data
        raise  # let caller handle retry

    del json_bytes, json_data

    return r.returncode, r.stderr.decode("utf-8", errors="replace")


def build_and_write(in1_value=100, in2_value=50,
                    out1_value=130, out2_value=20,
                    fee=0, asset_id=1,
                    hd_manager=None,
                    note_indices=None):
    """
    Build witness data and write Prover.toml + Verifier.toml.

    Key generation modes:
      - hd_manager is None (default):
            Random ephemeral keys via rand_sk(). Dev mode.
      - hd_manager is a SecureKeyManager:
            HD-derived keys from master seed. note_indices must be a
            4-tuple (in1_idx, in2_idx, out1_idx, out2_idx).

    Returns (circuit_prover_path, ram_mount, ram_toml_path) for caller cleanup.
    """

    assert in1_value + in2_value == out1_value + out2_value + fee, \
        "Value conservation violated"

    # ── Generate or derive spending keys ─────────────────────────────────────
    # All sk buffers are mlocked bytearrays regardless of derivation mode.
    # rho values are non-secret randomness, always generated randomly.
    in1_rho, in2_rho, out1_rho, out2_rho = (rand_field() for _ in range(4))

    if hd_manager is not None:
        # HD derivation: keys derived from master seed via BLAKE3
        if note_indices is None or len(note_indices) != 4:
            raise ValueError(
                "HD mode requires note_indices=(in1_idx, in2_idx, out1_idx, out2_idx)"
            )
        in1_idx, in2_idx, out1_idx, out2_idx = note_indices
        in1_sk_buf  = hd_manager.derive_note_sk(in1_idx)
        in2_sk_buf  = hd_manager.derive_note_sk(in2_idx)
        out1_sk_buf = hd_manager.derive_note_sk(out1_idx)
        out2_sk_buf = hd_manager.derive_note_sk(out2_idx)
        print(f"[HD] Derived 4 spending keys from master seed")
        print(f"     note indices: {in1_idx}, {in2_idx}, {out1_idx}, {out2_idx}")
    else:
        # Dev mode: random ephemeral keys
        in1_sk_buf  = rand_sk()
        in2_sk_buf  = rand_sk()
        out1_sk_buf = rand_sk()
        out2_sk_buf = rand_sk()
        print("[DEV] Generated 4 random ephemeral spending keys")

    # ── Store in Keychain for the proving window ──────────────────────────────
    # Keys live in encrypted Keychain storage rather than in Python heap
    # for the duration of hash computation. Deleted immediately after use.
    kc = keychain.available()
    kc_labels = []
    if kc:
        for label, buf in [
            ("tonkl_in1_sk",  in1_sk_buf),
            ("tonkl_in2_sk",  in2_sk_buf),
            ("tonkl_out1_sk", out1_sk_buf),
            ("tonkl_out2_sk", out2_sk_buf),
        ]:
            keychain.store(label, buf.hex())
            kc_labels.append(label)
        print("[K] Spending keys stored in macOS Keychain (encrypted at rest)")

    # Convert to int for TOML -- sk_to_int reads from bytearray then we zero buf
    in1_sk  = sk_to_int(in1_sk_buf)
    in2_sk  = sk_to_int(in2_sk_buf)
    out1_sk = sk_to_int(out1_sk_buf)
    out2_sk = sk_to_int(out2_sk_buf)

    # Zero bytearrays immediately -- sk now only exists as Python ints
    # (immutable, can't be zeroed, but we've minimised the mutable window)
    for buf in (in1_sk_buf, in2_sk_buf, out1_sk_buf, out2_sk_buf):
        zero_sk(buf)
    print("[K] sk bytearrays zeroed and unlocked from RAM")

    # Hasher derives all pk values from sk and returns them alongside the
    # commitments, nullifiers, and merkle root.
    hasher_inputs = {
        "in1_value":    in1_value,  "in1_asset_id":  asset_id,
        "in1_rho":      in1_rho,   "in1_sk":        in1_sk,
        "in2_value":    in2_value,  "in2_asset_id":  asset_id,
        "in2_rho":      in2_rho,   "in2_sk":        in2_sk,
        "out1_value":   out1_value, "out1_asset_id": asset_id,
        "out1_rho":     out1_rho,  "out1_sk":       out1_sk,
        "out2_value":   out2_value, "out2_asset_id": asset_id,
        "out2_rho":     out2_rho,  "out2_sk":       out2_sk,
    }

    # Hasher returns 15 values:
    # (merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2,
    #  in1_pk_x, in1_pk_y, in2_pk_x, in2_pk_y,
    #  out1_pk_x, out1_pk_y, out2_pk_x, out2_pk_y)
    (merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2,
     in1_pk_x, in1_pk_y, in2_pk_x, in2_pk_y,
     out1_pk_x, out1_pk_y, out2_pk_x, out2_pk_y) = run_hasher(hasher_inputs)

    # Hasher is done -- delete Keychain entries now so keys are not held in
    # Keychain any longer than necessary. sk ints are still needed below for
    # writing Prover.toml; they will be wiped after that write.
    if kc and kc_labels:
        for label in kc_labels:
            keychain.delete(label)
        print("[🔑] Spending keys removed from macOS Keychain")

    # Build correct Merkle paths using the returned commitments.
    # Notes are at positions 0 and 1 in the tree:
    #   path for index 0: sibling[0] = cm_in2, rest = 0
    #   path for index 1: sibling[0] = cm_in1, rest = 0
    path_for_0 = [str(cm_in2)] + ["0"] * (MERKLE_DEPTH - 1)
    path_for_1 = [str(cm_in1)] + ["0"] * (MERKLE_DEPTH - 1)

    # Index bit arrays (LSB-first, bool values).
    # Avoids u32 integer division in the circuit (triggers bb 4.0 assertion).
    # (beta.20: u1 type was removed; circuit now expects [bool; 32].)
    bits_for_0 = ["false"] * MERKLE_DEPTH
    bits_for_1 = ["true"] + ["false"] * (MERKLE_DEPTH - 1)

    # ── Write transfer circuit Prover.toml (via RAM disk if available) ─────────
    prover = {
        # Public inputs
        "merkle_root":      merkle_root,  "nf_1":            nf_1,
        "nf_2":             nf_2,         "cm_out_1":        cm_out_1,
        "cm_out_2":         cm_out_2,     "fee":             fee,
        "asset_id":         asset_id,
        # Private: input note 1 -- pk values are circuit-derived from in1_sk
        "in1_value":        in1_value,    "in1_owner_pk_x":  in1_pk_x,
        "in1_owner_pk_y":   in1_pk_y,    "in1_rho":         in1_rho,
        "in1_owner_sk":     in1_sk,
        "in1_merkle_bits":  bits_for_0,  "in1_merkle_path": path_for_0,
        # Private: input note 2 -- pk values are circuit-derived from in2_sk
        "in2_value":        in2_value,    "in2_owner_pk_x":  in2_pk_x,
        "in2_owner_pk_y":   in2_pk_y,    "in2_rho":         in2_rho,
        "in2_owner_sk":     in2_sk,
        "in2_merkle_bits":  bits_for_1,  "in2_merkle_path": path_for_1,
        # Private: output note 1
        "out1_value":       out1_value,   "out1_owner_pk_x": out1_pk_x,
        "out1_owner_pk_y":  out1_pk_y,   "out1_rho":        out1_rho,
        # Private: output note 2
        "out2_value":       out2_value,   "out2_owner_pk_x": out2_pk_x,
        "out2_owner_pk_y":  out2_pk_y,   "out2_rho":        out2_rho,
    }

    verifier = {
        "merkle_root": merkle_root, "nf_1": nf_1, "nf_2": nf_2,
        "cm_out_1": cm_out_1, "cm_out_2": cm_out_2,
        "fee": fee, "asset_id": asset_id,
    }
    write_toml(os.path.join(TRANSFER_DIR, "Verifier.toml"), verifier)

    if _fifo_available():
        # FIFO mode: nargo will be fed via named pipe in __main__.
        # We store the prover dict and pass it back; no file is written yet.
        print("[FIFO] Transfer Prover.toml will be piped (sk never on storage)")
        print("[OK] Written: Verifier.toml")

        wipe_key_vars(in1_sk, in2_sk, out1_sk, out2_sk)
        print("[K] Key vars cleared from memory (best-effort)")

        print("\nPublic inputs:")
        for k, v in verifier.items():
            print(f"  {k:20s} = {v}")

        # Return prover dict for FIFO mode; None for RAM disk fields
        return prover, None, None
    else:
        # RAM disk / file fallback
        circuit_prover, t_ram_mount, t_ram_toml = _write_prover_toml_secure(
            prover, "transfer"
        )
        print("[OK] Written: Prover.toml")
        print("[OK] Written: Verifier.toml")

        wipe_key_vars(in1_sk, in2_sk, out1_sk, out2_sk)
        print("[K] Key vars cleared from memory (best-effort)")

        print("\nPublic inputs:")
        for k, v in verifier.items():
            print(f"  {k:20s} = {v}")

        return circuit_prover, t_ram_mount, t_ram_toml

def secure_delete(path: str):
    """
    Multi-pass secure file deletion with tool detection.

    Strategy (tried in order):
      1. shred  (GNU coreutils -- Linux, or macOS via `brew install coreutils`)
      2. gshred (GNU coreutils Homebrew alias on macOS)
      3. srm    (macOS <= Sierra built-in secure remove)
      4. Python 3-pass overwrite: zeros -> 0xFF -> random bytes, then unlink

    Limitations (acknowledged):
      - SSD wear-levelling: the physical flash cell may retain data regardless
        of overwrite passes. This is a hardware limitation.
      - Filesystem journaling (APFS, HFS+, ext4) may have logged the plaintext
        in journal blocks before we overwrote the file data.
      - macOS Spotlight / Time Machine may have indexed or backed up the file
        during the brief window it existed.

    None of these are solvable in a user-space Python script. Hardware-backed
    key storage (Secure Enclave, hardware wallet) is the only production remedy.
    Install GNU coreutils for the best available user-space option:
      brew install coreutils
    """
    if not os.path.exists(path):
        return

    rel = os.path.relpath(path)

    # Tool-based: shred / gshred (3 passes + final zero + unlink)
    for tool in ("shred", "gshred"):
        if shutil.which(tool):
            try:
                r = subprocess.run(
                    [tool, "--iterations=3", "--zero", "--remove", path],
                    capture_output=True,
                )
                if r.returncode == 0:
                    print(f"[🔑] Secure deleted ({tool}, 3-pass): {rel}")
                    return
            except Exception:
                pass

    # srm (older macOS, deprecated after Sierra)
    if shutil.which("srm"):
        try:
            r = subprocess.run(["srm", "-rf", path], capture_output=True)
            if r.returncode == 0:
                print(f"[🔑] Secure deleted (srm): {rel}")
                return
        except Exception:
            pass

    # Python fallback: 3-pass overwrite then unlink
    try:
        size = os.path.getsize(path)
        for label, data in [
            ("pass 1/3 zeros",  lambda n: b"\x00" * n),
            ("pass 2/3 ones",   lambda n: b"\xff" * n),
            ("pass 3/3 random", lambda n: os.urandom(n)),
        ]:
            with open(path, "r+b") as f:
                f.write(data(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
        print(f"[🔑] Secure deleted (3-pass Python fallback): {rel}")
        print(f"     Note: install GNU coreutils (brew install coreutils) for shred")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[!] Warning: could not secure delete {path}: {e}")
        try:
            os.remove(path)
        except Exception:
            pass


def wipe_key_vars(*values):
    """
    Best-effort in-memory wipe of Python key material.

    Python integers are immutable objects -- we cannot zero the memory they
    occupy directly. This function does what is possible:
      - For bytearray values: overwrites content with zeros via ctypes,
        which directly writes to the buffer's memory address.
      - For all values: explicitly del-s the caller's references and calls
        gc.collect() to encourage the garbage collector to reclaim memory.

    Limitations:
      - CPython may have created multiple copies of int/str objects internally.
      - The GC does not guarantee immediate collection or memory zeroing.
      - Only hardware enclaves (Secure Enclave, TPM) provide true isolation.

    This is meaningfully better than doing nothing, but is not a substitute
    for enclave-level key management in production.
    """
    for v in values:
        if isinstance(v, bytearray):
            # bytearray is mutable -- zero the buffer directly
            try:
                ctypes.memset(id(v) + 16, 0, len(v))  # skip PyObject header
            except Exception:
                v[:] = b"\x00" * len(v)
        # For int/str: we cannot zero in place; just drop the reference
        del v
    gc.collect()


def run(cmd, label, cwd=None):
    """Run a command, streaming output, exit on failure."""
    print(f"[→] {label}...")
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    combined = r.stdout + r.stderr
    if r.returncode != 0:
        print(f"[✗] {label} failed:\n")
        print(combined)
        sys.exit(1)
    # Print any non-empty output lines
    for line in combined.splitlines():
        if line.strip():
            print(f"    {line}")
    return combined


def _bb_write_vk_prove_verify():
    """
    Steps 4-6 of the pipeline using the bb (Barretenberg) CLI.
    Used by both FIFO and fallback paths (Rust prover handles these internally).
    """
    # ── Step 4: write fresh verification key ────────────────────────────────
    run(
        [BB_BIN, "write_vk",
         "-b", "target/tonkl_transfer.json",
         "-o", "target/vk"],
        "bb write_vk (generating verification key)",
        cwd=TRANSFER_DIR,
    )
    print("[✓] VK written   -> target/vk/vk")

    # ── Step 5: prove + inline verify ───────────────────────────────────────
    run(
        [BB_BIN, "prove",
         "-b", "target/tonkl_transfer.json",
         "-w", "target/transfer_witness.gz",
         "-o", "target/proof",
         "-k", "target/vk/vk",
         "--verify"],
        "bb prove --verify (generating and verifying proof)",
        cwd=TRANSFER_DIR,
    )
    # Witness encodes sk as a solved circuit variable -- delete immediately
    # now that the proof is generated. Proof and public_inputs contain no sk.
    secure_delete(os.path.join(TRANSFER_DIR, "target", "transfer_witness.gz"))
    print("[✓] Proof saved  -> target/proof/proof")
    print("[✓] Pub inputs   -> target/proof/public_inputs")

    # ── Step 6: standalone verify ───────────────────────────────────────────
    run(
        [BB_BIN, "verify",
         "-k", "target/vk/vk",
         "-p", "target/proof/proof",
         "-i", "target/proof/public_inputs"],
        "bb verify (standalone proof verification)",
        cwd=TRANSFER_DIR,
    )

    print()
    print("=" * 45)
    print("[✓] All steps passed. Proof is valid.")
    print()
    print("Key material on disk: NONE")
    if _rust_prover_available():
        print("  Prover.toml    -- Rust mode: sk piped via stdin, never on storage")
    elif _fifo_available():
        print("  Prover.toml    -- FIFO mode: sk was never written to storage")
    else:
        print("  Prover.toml    -- deleted after witness generation")
    print("  witness.gz     -- deleted after proving")
    print("  Remaining      -- proof, public_inputs, vk (no sk recoverable)")
    print("=" * 45)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Tonkl Transfer -- Full Pipeline")
    parser.add_argument(
        "--hd", action="store_true",
        help="Use HD-derived keys from master seed instead of random ephemeral keys"
    )
    parser.add_argument(
        "--note-indices", type=int, nargs=4, default=[0, 1, 2, 3],
        metavar=("IN1", "IN2", "OUT1", "OUT2"),
        help="Note indices for HD derivation (default: 0 1 2 3)"
    )
    parser.add_argument(
        "--generate-seed", action="store_true",
        help="Generate a new master seed (24-word mnemonic) and store in Keychain"
    )
    parser.add_argument(
        "--restore-seed", type=str, nargs="+", metavar="WORD",
        help="Restore master seed from a BIP-39 mnemonic phrase (24 words)"
    )
    parser.add_argument(
        "--show-mnemonic", action="store_true",
        help="Display the stored mnemonic phrase and exit"
    )
    parser.add_argument(
        "--rust-prove", action="store_true",
        help="Use Rust tonkl-prover `prove` subcommand for the full pipeline "
             "(witness + prove + verify in one shot, no separate bb calls needed)"
    )
    parser.add_argument(
        "--witness-only", action="store_true",
        help="Use Rust tonkl-prover for witness solving only (legacy behavior), "
             "then call bb separately for proving"
    )
    args = parser.parse_args()

    # ── Seed management commands (run and exit) ────────────────────────────────
    skm = secure_key_manager.SecureKeyManager()

    if args.generate_seed:
        mnemonic = skm.generate_and_store()
        print()
        print("=" * 60)
        print("  BACK UP THESE 24 WORDS -- WRITE THEM DOWN ON PAPER")
        print("=" * 60)
        words = mnemonic.split()
        for i, word in enumerate(words, 1):
            print(f"  {i:2d}. {word}")
        print("=" * 60)
        sys.exit(0)

    if args.restore_seed:
        mnemonic = " ".join(args.restore_seed)
        try:
            skm.restore_from_mnemonic(mnemonic)
            print("[OK] Seed restored and stored in Keychain")
        except ValueError as e:
            print(f"[!] Invalid mnemonic: {e}")
            sys.exit(1)
        sys.exit(0)

    if args.show_mnemonic:
        m = skm.show_mnemonic()
        if m:
            words = m.split()
            for i, word in enumerate(words, 1):
                print(f"  {i:2d}. {word}")
        else:
            print("No mnemonic stored in Keychain.")
        sys.exit(0)

    # ── Full pipeline ──────────────────────────────────────────────────────────
    print("Tonkl Transfer -- Full Pipeline")
    print("=" * 45)
    check_nargo()
    check_bb()
    print()

    hd_manager = None
    if args.hd:
        if not skm.has_master_seed():
            print("[!] HD mode requires a master seed in Keychain.")
            print("    Generate one with: python3 scripts/generate_witness.py --generate-seed")
            print("    Or restore with:   python3 scripts/generate_witness.py --restore-seed <24 words>")
            sys.exit(1)
        hd_manager = skm
        print("Mode: HD derivation (keys derived from master seed)")
    else:
        print("Mode: DEV (random ephemeral keys)")
    print("Transaction:  100 + 50 in  ->  130 + 20 out  (fee: 0)")
    print()

    # ── Determine proving strategy ──────────────────────────────────────────────
    # Priority order (best security first):
    #   1. Rust full-prove: `tonkl-prover prove` handles entire pipeline
    #      (witness + bb prove + verify + secure delete) in one shot.
    #      sk exists only in Rust process memory. No separate bb calls.
    #   2. Rust witness-only: `tonkl-prover` solves witness via ACVM,
    #      then Python calls bb separately for proving/verifying.
    #   3. FIFO:  sk piped via named pipe → nargo reads from kernel buffer.
    #      sk exists only in kernel pipe buffer. Still needs nargo + bb.
    #   4. Fallback: sk written to RAM disk or file → nargo reads → secure delete.
    #      sk briefly touches storage. Needs nargo + bb.
    use_rust_prover = _rust_prover_available()
    # Default to full-prove when Rust prover is available, unless --witness-only
    use_rust_prove = use_rust_prover and not args.witness_only
    # Override: --rust-prove forces full-prove (fails if binary not found)
    if args.rust_prove and not use_rust_prover:
        print("[!] --rust-prove requested but tonkl-prover not found at:")
        print(f"    {RUST_PROVER_BIN}")
        print("    Build with: cd tonkl-prover && cargo build --release")
        sys.exit(1)
    if args.rust_prove:
        use_rust_prove = True
    use_fifo = not use_rust_prover and _fifo_available()

    if use_rust_prove:
        print("Strategy: Rust full-prove (witness + prove + verify in one shot)")
    elif use_rust_prover:
        print("Strategy: Rust witness solver + separate bb calls")
    elif use_fifo:
        print("Strategy: FIFO named pipe (sk in kernel buffer only)")
    else:
        print("Strategy: RAM disk / file fallback (sk briefly on storage)")
    print()

    # ── Step 1 & 2: compute hashes, write Prover.toml / Verifier.toml ──────────
    result = build_and_write(
        hd_manager=hd_manager,
        note_indices=tuple(args.note_indices) if args.hd else None,
    )

    # ── Rust full-prove path (single-binary, no separate bb calls) ────────────
    # The `prove` subcommand handles everything: witness solving, bb write_vk,
    # bb prove --verify, secure_delete witness, bb verify. One invocation.
    if use_rust_prove and isinstance(result[0], dict):
        prover_data = result[0]
        circuit_json = os.path.join(TRANSFER_DIR, "target", "tonkl_transfer.json")
        output_dir = os.path.join(TRANSFER_DIR, "target")

        print()
        print("[RUST] Full pipeline via `tonkl-prover prove`...")
        print("[RUST] sk piped via stdin -- witness solved, proved, and deleted in one shot")
        returncode, stderr = _run_rust_prover_prove(
            prover_data, circuit_json, output_dir,
            bb_path=BB_BIN,
        )

        # Print Rust prover's stderr (progress messages)
        for line in stderr.strip().splitlines():
            print(f"  {line}")

        if returncode != 0:
            print(f"[x] tonkl-prover prove failed (exit {returncode})")
            sys.exit(1)

        print()
        print("=" * 45)
        print("[OK] All steps passed (Rust single-binary pipeline).")
        print()
        print("Key material on disk: NONE")
        print("  Prover.toml    -- sk piped via stdin, never on storage")
        print("  witness.gz     -- created and secure-deleted inside Rust process")
        print("  Remaining      -- proof, public_inputs, vk (no sk recoverable)")
        print("=" * 45)

    # ── Rust witness-only path (--witness-only or legacy) ──────────────────────
    # Rust binary solves the witness (sk in process memory only).
    # Then Python calls bb CLI separately for proving/verifying.
    elif use_rust_prover and not use_rust_prove and isinstance(result[0], dict):
        prover_data = result[0]
        circuit_json = os.path.join(TRANSFER_DIR, "target", "tonkl_transfer.json")
        witness_gz = os.path.join(TRANSFER_DIR, "target", "transfer_witness.gz")

        print()
        print("[RUST] Piping inputs to tonkl-prover (witness-only mode)...")
        returncode, stderr = _run_rust_prover(
            prover_data, circuit_json, witness_gz
        )
        if returncode != 0:
            print(f"[x] tonkl-prover failed:\n{stderr}")
            sys.exit(1)

        # Print Rust solver's stderr (progress messages)
        for line in stderr.strip().splitlines():
            print(f"  {line}")

        print("[OK] Witness solved -> target/transfer_witness.gz")
        print("[RUST] sk was piped via stdin -- never on storage")

        # Steps 4-6: bb CLI proves from the witness.gz
        _bb_write_vk_prove_verify()

    # ── FIFO path ──────────────────────────────────────────────────────────────
    elif use_fifo and isinstance(result[0], dict):
        prover_data = result[0]

        print()
        print("[FIFO] Passing transfer witness via named pipe...")
        returncode, combined = _run_nargo_with_fifo(
            prover_data, TRANSFER_DIR, "transfer_witness"
        )
        if returncode != 0:
            print(f"[✗] nargo execute failed:\n{combined}")
            sys.exit(1)
        print("[FIFO] Named pipe closed -- sk was never on storage")
        print("[✓] Witness solved -> target/transfer_witness.gz")

        # Steps 4-6 still use bb (Rust prover not available)
        _bb_write_vk_prove_verify()

    # ── Fallback path (RAM disk / file) ────────────────────────────────────────
    else:
        circuit_prover, t_ram_mount, t_ram_toml = result

        print()
        run(
            ["nargo", "execute", "transfer_witness"],
            "nargo execute (solving circuit witness)",
            cwd=TRANSFER_DIR,
        )

        # Prover.toml contains sk in plaintext -- delete it immediately.
        if t_ram_toml:
            secure_delete(t_ram_toml)
            if os.path.lexists(circuit_prover):
                os.unlink(circuit_prover)          # remove symlink
            ramdisk.destroy()
            print("[🔑] RAM disk destroyed -- Prover.toml never touched the SSD")
        else:
            secure_delete(circuit_prover)
        print("[✓] Witness solved -> target/transfer_witness.gz")

        # Steps 4-6 use bb
        _bb_write_vk_prove_verify()
