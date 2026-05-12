#!/usr/bin/env python3
"""
Tonkl Protocol -- Composability Test (mint → split → transfer → merge)

Exercises all four circuit types through the live node in a single cohesive
flow, proving that outputs from one circuit type can be consumed by another:

  Phase 1: MINT   — Mint 32 notes (4 real, 28 zero-value padding)
  Phase 2: SPLIT  — Split mint note #2 (200) into 32 smaller notes
  Phase 3: TRANSFER — Spend a split output + mint note #3 (cross-owner)
  Phase 4: MERGE  — Merge 31 remaining split outputs + transfer change → 1 note

Value flow:
  Mint:     [400, 300, 200, 100, 0×28]  (total 1000)
  Split:    note#2 (200) → [100, 50, 30, 20, 0×28]  (to self, sk=0xcccc03)
  Transfer: split[0](100) + note#3(100) → [150 to recipient, 50 change to 0xcccc03]
  Merge:    split[1..31] + transfer_change = 32 notes → 1 note (value=150)

This proves that the UTXO model works end-to-end: notes created by one
circuit type are valid inputs to another, nullifiers prevent double-spends
across circuit boundaries, and the Merkle tree accumulates correctly.

Prerequisites:
  - tonkl-node built:    cd tonkl-node && cargo build --release
  - tonkl-prover built:  cd tonkl-prover && cargo build --release
  - nargo available:       nargo --version  (v1.0.0-beta.20)
  - bb available:          bb --version     (v0.82.2+)
  - Mint proof artifacts:  tonkl-mint/target/proof/{proof, public_inputs}
  - All circuit JSONs compiled via nargo compile
  - All VKs generated via bb write_vk

Usage:
  cd ~/Desktop/tonkl/tonkl-node
  python3 scripts/test_composability.py
"""

import os
import json
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent  # tonkl/
NODE_BIN = ROOT / "tonkl-node" / "target" / "release" / "tonkl-node"
PROVER_BIN = ROOT / "tonkl-prover" / "target" / "release" / "tonkl-prover"

# Mint artifacts (pre-generated)
MINT_PROOF = ROOT / "tonkl-mint" / "target" / "proof" / "proof"
MINT_PI = ROOT / "tonkl-mint" / "target" / "proof" / "public_inputs"

# Circuit JSONs (compiled via nargo compile)
TRANSFER_CIRCUIT = ROOT / "tonkl-transfer" / "target" / "tonkl_transfer.json"
SPLIT_CIRCUIT = ROOT / "tonkl-split" / "target" / "tonkl_split.json"
MERGE_CIRCUIT = ROOT / "tonkl-merge" / "target" / "tonkl_merge.json"

# Circuit directories (for nargo execute)
SPLIT_DIR = ROOT / "tonkl-split"
MERGE_DIR = ROOT / "tonkl-merge"

# VK paths
TRANSFER_VK = ROOT / "tonkl-transfer" / "target" / "vk" / "vk"

# Import client and builder
sys.path.insert(0, str(SCRIPT_DIR))
from node_client import TonklClient, RpcError
from witness_builder import WitnessBuilder, CryptoHelper, NoteInput, NoteOutput

# ─────────────────────────────────────────────────────────────────────
# Keys and Note Parameters
# ─────────────────────────────────────────────────────────────────────
# From generate_mint_witness.py:
#   Note 0: sk=0xaaaa01, value=400, rho=6001
#   Note 1: sk=0xbbbb02, value=300, rho=6002
#   Note 2: sk=0xcccc03, value=200, rho=6003  ← split input
#   Note 3: sk=0xdddd04, value=100, rho=6004  ← transfer input
#   Notes 4-31: sk=0xfed001 (authority), value=0

ASSET_ID = "1"
FEE = 0

# Mint note #2 (split input)
SPLIT_INPUT_SK = "0xcccc03"
SPLIT_INPUT_VALUE = 200
SPLIT_INPUT_RHO = "6003"
SPLIT_INPUT_INDEX = 2

# Split output distribution: 100 + 50 + 30 + 20 = 200, rest zero
SPLIT_REAL_VALUES = [100, 50, 30, 20]
SPLIT_RHO_BASE = 7001  # rhos: 7001, 7002, ..., 7032

# Mint note #3 (transfer input, cross-owner spend)
XFER_INPUT2_SK = "0xdddd04"
XFER_INPUT2_VALUE = 100
XFER_INPUT2_RHO = "6004"
XFER_INPUT2_INDEX = 3

# Transfer outputs: split[0](100) + note3(100) → 150 + 50
XFER_OUT1_VALUE = 150  # to recipient
XFER_OUT2_VALUE = 50   # change back to SPLIT_INPUT_SK (0xcccc03)
XFER_OUT1_RHO = "8001"
XFER_OUT2_RHO = "8002"
XFER_RECIPIENT_SK = "0xee0501"

# Merge output
MERGE_OUT_RHO = "8500"

PORT = 9202
PASS = 0
FAIL = 0
node_proc = None
data_dir = None
vk_dir = None


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def check(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✓ PASS: {name}")
    else:
        FAIL += 1
        msg = f"  ✗ FAIL: {name}"
        if detail:
            msg += f" ({detail})"
        print(msg)


def find_vk(circuit_name: str) -> Path:
    """Locate the verification key for a circuit."""
    base = ROOT / circuit_name / "target"
    for p in [base / "vk" / "vk", base / "vk", base / "vk_dir" / "vk"]:
        if p.exists():
            return p
    raise FileNotFoundError(f"VK not found for {circuit_name}")


def setup_vk_dir() -> Path:
    """Create a temp directory with all VKs for the node."""
    d = Path(tempfile.mkdtemp(prefix="tonkl-comp-vks-"))
    for circuit, folder in [
        ("tonkl-transfer", "transfer"),
        ("tonkl-merge", "merge"),
        ("tonkl-split", "split"),
        ("tonkl-mint", "mint"),
    ]:
        vk_sub = d / folder
        vk_sub.mkdir()
        src = find_vk(circuit)
        (vk_sub / "vk").write_bytes(src.read_bytes())
    return d


def read_mint_commitments() -> list:
    """Read the 32 commitments from the mint public_inputs file."""
    pi_bytes = MINT_PI.read_bytes()
    commitments = []
    for i in range(32):
        chunk = pi_bytes[i * 32 : (i + 1) * 32]
        commitments.append("0x" + chunk.hex())
    return commitments


def mint_policy_env() -> dict:
    pi_bytes = MINT_PI.read_bytes()

    def field_hex(index: int) -> str:
        return "0x" + pi_bytes[index * 32 : (index + 1) * 32].hex()

    env = os.environ.copy()
    env["TONKL_MINT_AUTHORITIES"] = json.dumps({
        str(int(field_hex(33), 16)): {
            "pk_x": field_hex(34),
            "pk_y": field_hex(35),
            "max_supply": str(int(field_hex(32), 16)),
        }
    })
    return env


def start_node(vk_path: Path) -> subprocess.Popen:
    global data_dir
    data_dir = tempfile.mkdtemp(prefix="tonkl-comp-data-")
    proc = subprocess.Popen(
        [
            str(NODE_BIN), "run",
            "--port", str(PORT),
            "--data-dir", data_dir,
            "--vk-dir", str(vk_path),
            "--allow-unauthenticated-rpc-local",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=mint_policy_env(),
    )
    return proc


def cleanup():
    global node_proc, data_dir, vk_dir
    if node_proc is not None:
        node_proc.terminate()
        try:
            node_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node_proc.kill()
            node_proc.wait()
    if data_dir:
        subprocess.run(["rm", "-rf", data_dir], check=False)
    if vk_dir:
        subprocess.run(["rm", "-rf", str(vk_dir)], check=False)


def nargo_execute(circuit_dir: Path, witness_name: str) -> Path:
    """
    Run nargo execute in the given circuit directory.
    Reads Prover.toml from circuit_dir, writes target/<witness_name>.gz.
    Returns the path to the witness file.
    """
    result = subprocess.run(
        ["nargo", "execute", witness_name],
        cwd=str(circuit_dir),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        print(f"  ERROR: nargo execute failed in {circuit_dir.name}")
        print(f"  stdout: {result.stdout[-1000:]}")
        print(f"  stderr: {result.stderr[-1000:]}")
        raise RuntimeError(f"nargo execute failed: {result.stderr[:200]}")

    witness_path = circuit_dir / "target" / f"{witness_name}.gz"
    if not witness_path.exists():
        raise FileNotFoundError(f"Witness not found: {witness_path}")
    return witness_path


def bb_prove(circuit_json: Path, witness_gz: Path, vk_path: Path, output_dir: Path) -> tuple:
    """
    Run bb prove to generate a proof from a witness.
    Returns (proof_path, public_inputs_path).
    """
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
        print(f"  ERROR: bb prove failed")
        print(f"  stderr: {result.stderr[-1000:]}")
        raise RuntimeError(f"bb prove failed: {result.stderr[:200]}")

    proof_path = proof_dir / "proof"
    pi_path = proof_dir / "public_inputs"
    if not proof_path.exists() or not pi_path.exists():
        raise FileNotFoundError(f"Proof artifacts missing in {proof_dir}")

    return proof_path, pi_path


# ─────────────────────────────────────────────────────────────────────
# Main Test
# ─────────────────────────────────────────────────────────────────────

def main():
    global node_proc, vk_dir, PASS, FAIL

    print("=" * 72)
    print("  Tonkl Protocol -- Composability Test")
    print("  mint → split → transfer → merge  (all 4 circuits through the node)")
    print("=" * 72)
    print()

    # ── [0] Preflight ─────────────────────────────────────────────────
    print("[0/12] Preflight checks...")
    missing = []
    for name, path in [
        ("node binary", NODE_BIN),
        ("prover binary", PROVER_BIN),
        ("mint proof", MINT_PROOF),
        ("mint public_inputs", MINT_PI),
        ("transfer circuit JSON", TRANSFER_CIRCUIT),
        ("split circuit JSON", SPLIT_CIRCUIT),
        ("merge circuit JSON", MERGE_CIRCUIT),
        ("transfer VK", TRANSFER_VK),
    ]:
        if not path.exists():
            missing.append(f"  {name}: {path}")

    # Check nargo and bb are on PATH
    for tool in ["nargo", "bb"]:
        if shutil.which(tool) is None:
            missing.append(f"  {tool} not on PATH")

    if missing:
        print("  ERROR: Missing prerequisites:")
        for m in missing:
            print(m)
        sys.exit(1)

    # Check split and merge VKs
    try:
        split_vk = find_vk("tonkl-split")
        merge_vk = find_vk("tonkl-merge")
        print(f"  Split VK: {split_vk}")
        print(f"  Merge VK: {merge_vk}")
    except FileNotFoundError as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    print("  ✓ All artifacts and tools found")

    # ── [1] Setup + start node ────────────────────────────────────────
    print()
    print("[1/12] Starting node...")
    vk_dir = setup_vk_dir()
    node_proc = start_node(vk_dir)
    client = TonklClient(f"http://127.0.0.1:{PORT}", timeout=120.0)

    if not client.wait_for_node(timeout=15.0):
        print("  ERROR: Node failed to start!")
        node_proc.terminate()
        out, _ = node_proc.communicate(timeout=5)
        print(out.decode(errors="replace")[-2000:])
        cleanup()
        sys.exit(1)
    time.sleep(1)
    print("  ✓ Node ready")

    crypto = CryptoHelper(str(PROVER_BIN))
    builder = WitnessBuilder(client)

    # ══════════════════════════════════════════════════════════════════
    # PHASE 1: MINT — Submit existing mint proof → 32 notes
    # ══════════════════════════════════════════════════════════════════
    print()
    print("━" * 72)
    print("  PHASE 1: MINT (0-in / 32-out)")
    print("━" * 72)

    print()
    print("[2/12] Submitting mint proof...")
    mint_cms = read_mint_commitments()

    mint_result = client.submit_from_proof_files(
        tx_type="mint",
        proof_path=str(MINT_PROOF),
        public_inputs_path=str(MINT_PI),
        new_commitments=mint_cms,
        nullifiers=[],
        merkle_root="0x" + "00" * 32,
        fee=0,
    )
    check("mint tx accepted", mint_result.accepted)

    mint_header = client.produce_block()
    check("mint block produced (block 0)", mint_header.block_number == 0,
          f"got block {mint_header.block_number}")
    check("32 leaves after mint", client.get_status().leaf_count == 32,
          f"got {client.get_status().leaf_count}")

    print(f"  Merkle root after mint: {mint_header.state_root[:24]}...")

    # ══════════════════════════════════════════════════════════════════
    # PHASE 2: SPLIT — Split note #2 (200) → 32 outputs
    # ══════════════════════════════════════════════════════════════════
    print()
    print("━" * 72)
    print("  PHASE 2: SPLIT (1-in / 32-out)")
    print("━" * 72)

    # Compute input note data
    print()
    print("[3/12] Computing split input note data...")
    split_pk_x, split_pk_y = crypto.derive_pk(SPLIT_INPUT_SK)
    split_in_cm = crypto.commitment(
        str(SPLIT_INPUT_VALUE), ASSET_ID,
        split_pk_x, split_pk_y, SPLIT_INPUT_RHO,
    )
    check("split input commitment matches mint",
          split_in_cm == mint_cms[SPLIT_INPUT_INDEX],
          f"computed={split_in_cm[:20]} vs tree={mint_cms[SPLIT_INPUT_INDEX][:20]}")

    split_nf = crypto.nullifier(split_in_cm, SPLIT_INPUT_SK)
    print(f"  Split input nf: {split_nf[:24]}...")

    # Build split output notes (all to self for later merge)
    print()
    print("[4/12] Building split witness...")
    split_outputs = []
    split_out_cms = []
    for i in range(32):
        value = SPLIT_REAL_VALUES[i] if i < len(SPLIT_REAL_VALUES) else 0
        rho = str(SPLIT_RHO_BASE + i)
        split_outputs.append(NoteOutput(
            value=value,
            owner_pk_x=split_pk_x,
            owner_pk_y=split_pk_y,
            rho=rho,
        ))
        cm = crypto.commitment(str(value), ASSET_ID, split_pk_x, split_pk_y, rho)
        split_out_cms.append(cm)
        if i < len(SPLIT_REAL_VALUES):
            print(f"  split_out[{i}]: value={value}, rho={rho}, cm={cm[:18]}...")

    total_split_out = sum(SPLIT_REAL_VALUES)
    check("split value conservation",
          total_split_out == SPLIT_INPUT_VALUE,
          f"{total_split_out} != {SPLIT_INPUT_VALUE}")

    split_input = NoteInput(
        index=SPLIT_INPUT_INDEX,
        value=SPLIT_INPUT_VALUE,
        owner_sk=SPLIT_INPUT_SK,
        owner_pk_x=split_pk_x,
        owner_pk_y=split_pk_y,
        rho=SPLIT_INPUT_RHO,
    )

    # Build TOML witness for nargo execute
    split_toml = builder.build_split(
        input_note=split_input,
        outputs=split_outputs,
        fee=FEE,
        asset_id=ASSET_ID,
        nf=split_nf,
        cm_outs=split_out_cms,
        output_format="toml",
    )

    # Write Prover.toml to split circuit directory
    split_prover_toml = SPLIT_DIR / "Prover.toml"
    split_prover_toml.write_text(split_toml)
    check("split Prover.toml written", split_prover_toml.exists())

    # Generate split proof via nargo execute + bb prove
    print()
    print("[5/12] Generating split proof (nargo execute + bb prove)...")
    try:
        split_witness_gz = nargo_execute(SPLIT_DIR, "split_comp_witness")
        print(f"  ✓ nargo execute passed → {split_witness_gz.name}")
        check("split witness generated", True)
    except Exception as e:
        check("split witness generated", False, str(e))
        # Clean up Prover.toml
        split_prover_toml.unlink(missing_ok=True)
        cleanup()
        sys.exit(1)

    # Clean up Prover.toml immediately (contains sk)
    split_prover_toml.unlink(missing_ok=True)

    split_proof_dir = Path(tempfile.mkdtemp(prefix="tonkl-comp-split-"))
    try:
        split_proof_path, split_pi_path = bb_prove(
            SPLIT_CIRCUIT, split_witness_gz, split_vk, split_proof_dir,
        )
        print(f"  ✓ bb prove succeeded")
        check("split proof generated", True)

        proof_size = split_proof_path.stat().st_size
        pi_size = split_pi_path.stat().st_size
        # Split: 36 public inputs * 32 bytes = 1152
        check("split proof size > 0", proof_size > 0, f"got {proof_size}")
        check("split public_inputs is 1152 bytes", pi_size == 1152, f"got {pi_size}")
    except Exception as e:
        check("split proof generated", False, str(e))
        cleanup()
        sys.exit(1)

    # Submit split proof
    print()
    print("[6/12] Submitting split proof to node...")
    post_mint_root = client.get_merkle_root()
    split_tx = client.submit_from_proof_files(
        tx_type="split",
        proof_path=str(split_proof_path),
        public_inputs_path=str(split_pi_path),
        new_commitments=split_out_cms,
        nullifiers=[split_nf],
        merkle_root=post_mint_root,
        fee=FEE,
    )
    check("split tx accepted", split_tx.accepted)
    print(f"  Split TX hash: {split_tx.tx_hash[:24]}...")

    split_header = client.produce_block()
    check("split block produced (block 1)", split_header.block_number == 1,
          f"got block {split_header.block_number}")

    post_split = client.get_status()
    check("64 leaves after split", post_split.leaf_count == 64,
          f"got {post_split.leaf_count}")
    check("split nullifier spent", client.get_nullifier_status(split_nf) == True)
    print(f"  Merkle root after split: {post_split.merkle_root[:24]}...")

    # Verify split tx confirmed
    split_status = client.get_tx_status(split_tx.tx_hash)
    check("split tx confirmed", split_status.status == "confirmed",
          f"got {split_status.status}")

    # Clean up split proof temp dir
    subprocess.run(["rm", "-rf", str(split_proof_dir)], check=False)

    # ══════════════════════════════════════════════════════════════════
    # PHASE 3: TRANSFER — split[0](100) + note#3(100) → 150 + 50
    # ══════════════════════════════════════════════════════════════════
    print()
    print("━" * 72)
    print("  PHASE 3: TRANSFER (2-in / 2-out, cross-owner)")
    print("━" * 72)

    print()
    print("[7/12] Computing transfer note data...")

    # Input 1: split output[0] (index=32, value=100, sk=0xcccc03)
    xfer_in1_index = 32  # first split output
    xfer_in1_value = SPLIT_REAL_VALUES[0]  # 100
    xfer_in1_sk = SPLIT_INPUT_SK  # 0xcccc03
    xfer_in1_rho = str(SPLIT_RHO_BASE)  # "7001"
    xfer_in1_pk_x = split_pk_x
    xfer_in1_pk_y = split_pk_y
    xfer_in1_cm = split_out_cms[0]  # already computed

    # Verify it's in the tree
    xfer_in1_proof = client.get_merkle_proof(xfer_in1_index)
    check("split output[0] has merkle proof",
          len(xfer_in1_proof.siblings) == 32)

    # Input 2: mint note #3 (index=3, value=100, sk=0xdddd04)
    xfer_in2_pk_x, xfer_in2_pk_y = crypto.derive_pk(XFER_INPUT2_SK)
    xfer_in2_cm = crypto.commitment(
        str(XFER_INPUT2_VALUE), ASSET_ID,
        xfer_in2_pk_x, xfer_in2_pk_y, XFER_INPUT2_RHO,
    )
    check("transfer input 2 commitment matches mint",
          xfer_in2_cm == mint_cms[XFER_INPUT2_INDEX],
          f"computed={xfer_in2_cm[:20]} vs tree={mint_cms[XFER_INPUT2_INDEX][:20]}")

    # Nullifiers
    xfer_nf1 = crypto.nullifier(xfer_in1_cm, xfer_in1_sk)
    xfer_nf2 = crypto.nullifier(xfer_in2_cm, XFER_INPUT2_SK)
    print(f"  Transfer nf1 (split[0]): {xfer_nf1[:24]}...")
    print(f"  Transfer nf2 (note#3):   {xfer_nf2[:24]}...")

    # Output 1: 150 to recipient
    xfer_recip_pk_x, xfer_recip_pk_y = crypto.derive_pk(XFER_RECIPIENT_SK)
    xfer_cm_out1 = crypto.commitment(
        str(XFER_OUT1_VALUE), ASSET_ID,
        xfer_recip_pk_x, xfer_recip_pk_y, XFER_OUT1_RHO,
    )

    # Output 2: 50 change back to 0xcccc03 (for later merge)
    xfer_cm_out2 = crypto.commitment(
        str(XFER_OUT2_VALUE), ASSET_ID,
        split_pk_x, split_pk_y, XFER_OUT2_RHO,
    )

    check("transfer value conservation",
          xfer_in1_value + XFER_INPUT2_VALUE == XFER_OUT1_VALUE + XFER_OUT2_VALUE + FEE,
          f"{xfer_in1_value}+{XFER_INPUT2_VALUE} != {XFER_OUT1_VALUE}+{XFER_OUT2_VALUE}+{FEE}")

    print(f"  Output 1 (recipient): value={XFER_OUT1_VALUE}, cm={xfer_cm_out1[:18]}...")
    print(f"  Output 2 (change):    value={XFER_OUT2_VALUE}, cm={xfer_cm_out2[:18]}...")

    # Build transfer witness (JSON for tonkl-prover)
    print()
    print("[8/12] Building transfer witness & generating proof...")
    transfer_inputs = [
        NoteInput(
            index=xfer_in1_index, value=xfer_in1_value,
            owner_sk=xfer_in1_sk,
            owner_pk_x=xfer_in1_pk_x, owner_pk_y=xfer_in1_pk_y,
            rho=xfer_in1_rho,
        ),
        NoteInput(
            index=XFER_INPUT2_INDEX, value=XFER_INPUT2_VALUE,
            owner_sk=XFER_INPUT2_SK,
            owner_pk_x=xfer_in2_pk_x, owner_pk_y=xfer_in2_pk_y,
            rho=XFER_INPUT2_RHO,
        ),
    ]
    transfer_outputs = [
        NoteOutput(
            value=XFER_OUT1_VALUE,
            owner_pk_x=xfer_recip_pk_x, owner_pk_y=xfer_recip_pk_y,
            rho=XFER_OUT1_RHO,
        ),
        NoteOutput(
            value=XFER_OUT2_VALUE,
            owner_pk_x=split_pk_x, owner_pk_y=split_pk_y,
            rho=XFER_OUT2_RHO,
        ),
    ]

    transfer_json = builder.build_transfer(
        inputs=transfer_inputs,
        outputs=transfer_outputs,
        fee=FEE,
        asset_id=ASSET_ID,
        nf_1=xfer_nf1,
        nf_2=xfer_nf2,
        cm_out_1=xfer_cm_out1,
        cm_out_2=xfer_cm_out2,
        output_format="json",
    )

    # Prove via tonkl-prover (stdin JSON)
    xfer_proof_dir = Path(tempfile.mkdtemp(prefix="tonkl-comp-xfer-"))
    xfer_output_dir = xfer_proof_dir / "output"
    xfer_output_dir.mkdir()

    prove_result = subprocess.run(
        [
            str(PROVER_BIN), "prove",
            "-c", str(TRANSFER_CIRCUIT),
            "-o", str(xfer_output_dir),
            "-k", str(TRANSFER_VK),
        ],
        input=transfer_json,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if prove_result.returncode != 0:
        print(f"  ERROR: Transfer proving failed!")
        print(f"  stderr: {prove_result.stderr[-2000:]}")
        check("transfer proof generated", False)
        cleanup()
        sys.exit(1)

    xfer_proof_path = xfer_output_dir / "proof" / "proof"
    xfer_pi_path = xfer_output_dir / "proof" / "public_inputs"
    check("transfer proof generated", xfer_proof_path.exists())
    check("transfer public_inputs exists", xfer_pi_path.exists())

    # Submit transfer proof
    print()
    print("[9/12] Submitting transfer proof to node...")
    post_split_root = client.get_merkle_root()
    xfer_tx = client.submit_from_proof_files(
        tx_type="transfer",
        proof_path=str(xfer_proof_path),
        public_inputs_path=str(xfer_pi_path),
        new_commitments=[xfer_cm_out1, xfer_cm_out2],
        nullifiers=[xfer_nf1, xfer_nf2],
        merkle_root=post_split_root,
        fee=FEE,
    )
    check("transfer tx accepted", xfer_tx.accepted)
    print(f"  Transfer TX hash: {xfer_tx.tx_hash[:24]}...")

    xfer_header = client.produce_block()
    check("transfer block produced (block 2)", xfer_header.block_number == 2,
          f"got block {xfer_header.block_number}")

    post_xfer = client.get_status()
    check("66 leaves after transfer", post_xfer.leaf_count == 66,
          f"got {post_xfer.leaf_count}")
    check("transfer nf1 spent", client.get_nullifier_status(xfer_nf1) == True)
    check("transfer nf2 spent", client.get_nullifier_status(xfer_nf2) == True)
    print(f"  Merkle root after transfer: {post_xfer.merkle_root[:24]}...")

    # Verify transfer tx confirmed
    xfer_status = client.get_tx_status(xfer_tx.tx_hash)
    check("transfer tx confirmed", xfer_status.status == "confirmed",
          f"got {xfer_status.status}")

    # Clean up transfer proof temp dir
    subprocess.run(["rm", "-rf", str(xfer_proof_dir)], check=False)

    # ══════════════════════════════════════════════════════════════════
    # PHASE 4: MERGE — 31 split outputs + transfer change → 1 note
    # ══════════════════════════════════════════════════════════════════
    print()
    print("━" * 72)
    print("  PHASE 4: MERGE (32-in / 1-out)")
    print("━" * 72)

    # Merge inputs:
    #   split_out[1..31] → indices 33-63, all owned by 0xcccc03
    #   transfer_change  → index 65, owned by 0xcccc03
    # Total: 31 + 1 = 32 inputs

    print()
    print("[10/12] Computing merge input note data...")

    merge_inputs = []
    merge_nullifiers = []
    merge_total_value = 0

    # Split outputs 1-31 (indices 33-63)
    for i in range(1, 32):
        tree_index = 32 + i  # split outputs start at index 32
        value = SPLIT_REAL_VALUES[i] if i < len(SPLIT_REAL_VALUES) else 0
        rho = str(SPLIT_RHO_BASE + i)
        cm = split_out_cms[i]

        nf = crypto.nullifier(cm, SPLIT_INPUT_SK)
        merge_nullifiers.append(nf)
        merge_total_value += value

        merge_inputs.append(NoteInput(
            index=tree_index,
            value=value,
            owner_sk=SPLIT_INPUT_SK,
            owner_pk_x=split_pk_x,
            owner_pk_y=split_pk_y,
            rho=rho,
        ))

    # Transfer change note (index 65, value=50)
    xfer_change_index = 65
    xfer_change_cm = xfer_cm_out2
    xfer_change_nf = crypto.nullifier(xfer_change_cm, SPLIT_INPUT_SK)
    merge_nullifiers.append(xfer_change_nf)
    merge_total_value += XFER_OUT2_VALUE

    merge_inputs.append(NoteInput(
        index=xfer_change_index,
        value=XFER_OUT2_VALUE,
        owner_sk=SPLIT_INPUT_SK,
        owner_pk_x=split_pk_x,
        owner_pk_y=split_pk_y,
        rho=XFER_OUT2_RHO,
    ))

    print(f"  Merge: {len(merge_inputs)} inputs, total value = {merge_total_value}")
    check("merge has 32 inputs", len(merge_inputs) == 32)
    check("merge has 32 nullifiers", len(merge_nullifiers) == 32)
    # 50 + 30 + 20 + 0*28 + 50 = 150
    check("merge total value is 150", merge_total_value == 150,
          f"got {merge_total_value}")

    # Compute merge output commitment
    merge_out_value = merge_total_value - FEE
    merge_cm_out = crypto.commitment(
        str(merge_out_value), ASSET_ID,
        split_pk_x, split_pk_y, MERGE_OUT_RHO,
    )
    print(f"  Merge output: value={merge_out_value}, cm={merge_cm_out[:18]}...")

    # Build merge witness (TOML for nargo execute)
    print()
    print("[11/12] Building merge witness & generating proof...")
    merge_toml = builder.build_merge(
        inputs=merge_inputs,
        out_rho=MERGE_OUT_RHO,
        fee=FEE,
        asset_id=ASSET_ID,
        nullifiers=merge_nullifiers,
        cm_out=merge_cm_out,
        output_format="toml",
    )

    # Write Prover.toml to merge circuit directory
    merge_prover_toml = MERGE_DIR / "Prover.toml"
    merge_prover_toml.write_text(merge_toml)
    check("merge Prover.toml written", merge_prover_toml.exists())

    # Generate merge proof via nargo execute + bb prove
    try:
        merge_witness_gz = nargo_execute(MERGE_DIR, "merge_comp_witness")
        print(f"  ✓ nargo execute passed → {merge_witness_gz.name}")
        check("merge witness generated", True)
    except Exception as e:
        check("merge witness generated", False, str(e))
        merge_prover_toml.unlink(missing_ok=True)
        cleanup()
        sys.exit(1)

    # Clean up Prover.toml immediately (contains sk)
    merge_prover_toml.unlink(missing_ok=True)

    merge_proof_dir = Path(tempfile.mkdtemp(prefix="tonkl-comp-merge-"))
    try:
        merge_proof_path, merge_pi_path = bb_prove(
            MERGE_CIRCUIT, merge_witness_gz, merge_vk, merge_proof_dir,
        )
        print(f"  ✓ bb prove succeeded")
        check("merge proof generated", True)

        pi_size = merge_pi_path.stat().st_size
        # Merge: 36 public inputs * 32 bytes = 1152
        check("merge public_inputs is 1152 bytes", pi_size == 1152, f"got {pi_size}")
    except Exception as e:
        check("merge proof generated", False, str(e))
        cleanup()
        sys.exit(1)

    # Submit merge proof
    print()
    print("[12/12] Submitting merge proof to node & verifying final state...")
    post_xfer_root = client.get_merkle_root()
    merge_tx = client.submit_from_proof_files(
        tx_type="merge",
        proof_path=str(merge_proof_path),
        public_inputs_path=str(merge_pi_path),
        new_commitments=[merge_cm_out],
        nullifiers=merge_nullifiers,
        merkle_root=post_xfer_root,
        fee=FEE,
    )
    check("merge tx accepted", merge_tx.accepted)
    print(f"  Merge TX hash: {merge_tx.tx_hash[:24]}...")

    merge_header = client.produce_block()
    check("merge block produced (block 3)", merge_header.block_number == 3,
          f"got block {merge_header.block_number}")

    # ── Final state verification ──────────────────────────────────────
    final = client.get_status()

    # Tree: 32 (mint) + 32 (split) + 2 (transfer) + 1 (merge) = 67 leaves
    check("67 leaves after merge", final.leaf_count == 67,
          f"got {final.leaf_count}")

    # Block height: 4 (blocks 0, 1, 2, 3)
    check("block height is 4", final.block_height == 4,
          f"got {final.block_height}")

    # All merge nullifiers should be spent
    merge_nfs_spent = sum(1 for nf in merge_nullifiers if client.get_nullifier_status(nf))
    check("all 32 merge nullifiers spent", merge_nfs_spent == 32,
          f"only {merge_nfs_spent}/32 spent")

    # Verify merge tx confirmed
    merge_status = client.get_tx_status(merge_tx.tx_hash)
    check("merge tx confirmed", merge_status.status == "confirmed",
          f"got {merge_status.status}")

    # Verify the merge output is in the tree at index 66
    merge_out_proof = client.get_merkle_proof(66)
    check("merge output has merkle proof at index 66",
          len(merge_out_proof.siblings) == 32)

    # ── Cross-circuit double-spend check ──────────────────────────────
    # The split nullifier (note #2) should still be spent
    check("split nullifier still spent", client.get_nullifier_status(split_nf) == True)

    # The transfer nullifiers should still be spent
    check("transfer nf1 still spent", client.get_nullifier_status(xfer_nf1) == True)
    check("transfer nf2 still spent", client.get_nullifier_status(xfer_nf2) == True)

    # Total nullifiers: 1 (split) + 2 (transfer) + 32 (merge) = 35
    check("35 total nullifiers", final.nullifier_count == 35,
          f"got {final.nullifier_count}")

    # Verify all 4 blocks exist and have correct tx types
    for block_num, expected_type in [(0, "Mint"), (1, "Split"), (2, "Transfer"), (3, "Merge")]:
        block = client.get_block(block_num)
        if block:
            txs = block.get("transactions", [])
            if txs:
                actual_type = txs[0].get("tx_type", "unknown")
                check(f"block {block_num} tx type is {expected_type}",
                      actual_type == expected_type, f"got {actual_type}")
            else:
                check(f"block {block_num} has transactions", False, "no txs")
        else:
            check(f"block {block_num} exists", False)

    # Clean up merge proof temp dir
    subprocess.run(["rm", "-rf", str(merge_proof_dir)], check=False)

    # ── Results ───────────────────────────────────────────────────────
    print()
    print("=" * 72)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"  ALL {PASS} TESTS PASSED")
        print()
        print("  Full composability verified:")
        print("    MINT  → 32 notes enter the tree")
        print("    SPLIT → mint output consumed, 32 new notes created")
        print("    TRANSFER → split output + mint note consumed (cross-owner)")
        print("    MERGE → 32 notes consolidated into 1")
        print()
        print("  All four circuit types interoperate through the live node.")
        print("  Nullifiers prevent double-spends across circuit boundaries.")
        print("  Merkle tree accumulates correctly across all operations.")
    else:
        print(f"  Results: {PASS} passed, {FAIL} failed (of {total})")
    print("=" * 72)

    cleanup()
    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        cleanup()
        sys.exit(1)
    except Exception as e:
        print(f"\nUnhandled error: {e}")
        import traceback
        traceback.print_exc()
        cleanup()
        sys.exit(1)
