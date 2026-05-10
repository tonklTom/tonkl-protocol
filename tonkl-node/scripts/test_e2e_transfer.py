#!/usr/bin/env python3
"""
Tonkl Protocol -- End-to-End Transfer Test

The full spend cycle running against a live node:
  1. Start node
  2. Submit existing mint proof → 32 notes enter the tree
  3. Produce block (confirms mint)
  4. Compute note data for two minted notes using tonkl-prover compute
  5. Build transfer witness with live merkle proofs from the node
  6. Generate transfer proof via tonkl-prover prove
  7. Submit transfer proof to the node
  8. Produce block (confirms transfer)
  9. Verify: nullifiers spent, new commitments added, tx confirmed

This exercises the entire stack: circuits, prover, witness builder,
node RPC, mempool, block builder, state transitions.

Prerequisites:
  - tonkl-node built:   cargo build --release
  - tonkl-prover built: cargo build --release
  - Mint proof artifacts: tonkl-mint/target/proof/{proof, public_inputs}
  - Transfer circuit JSON: tonkl-transfer/target/tonkl_transfer.json
  - All VKs generated:    bb write_vk for each circuit

Usage:
  cd ~/Desktop/tonkl/tonkl-node
  python3 scripts/test_e2e_transfer.py
"""

import os
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
MINT_PROOF = ROOT / "tonkl-mint" / "target" / "proof" / "proof"
MINT_PI = ROOT / "tonkl-mint" / "target" / "proof" / "public_inputs"
TRANSFER_CIRCUIT = ROOT / "tonkl-transfer" / "target" / "tonkl_transfer.json"
TRANSFER_VK = ROOT / "tonkl-transfer" / "target" / "vk" / "vk"

# Import client and builder
sys.path.insert(0, str(SCRIPT_DIR))
from node_client import TonklClient, RpcError
from witness_builder import WitnessBuilder, CryptoHelper, NoteInput, NoteOutput

# ─────────────────────────────────────────────────────────────────────
# Test Keys (from generate_mint_witness.py)
# ─────────────────────────────────────────────────────────────────────
# The mint used these recipient secret keys (see tonkl-tree/generate_mint_witness.py):
#   Note 0: sk=0xaaaa01, value=400, rho=6001
#   Note 1: sk=0xbbbb02, value=300, rho=6002
#   Note 2: sk=0xcccc03, value=200, rho=6003
#   Note 3: sk=0xdddd04, value=100, rho=6004
#   Notes 4-31: sk=0xfed001 (authority), value=0
#
# We spend notes 0 and 1 (total 700) and create two outputs (500 + 200).

NOTE_0_SK = "0xaaaa01"
NOTE_0_VALUE = 400
NOTE_0_RHO = "6001"

NOTE_1_SK = "0xbbbb02"
NOTE_1_VALUE = 300
NOTE_1_RHO = "6002"

ASSET_ID = "1"

# Transfer output parameters: 400+300 → 500+200, fee=0
OUT_1_VALUE = 500   # Send 500 to a "recipient"
OUT_2_VALUE = 200   # Change back
OUT_1_RHO = "9001"
OUT_2_RHO = "9002"
RECIPIENT_SK = "0xcc0301"  # Arbitrary new key for the recipient
FEE = 0

PORT = 9201
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
        print(f"  \u2713 PASS: {name}")
    else:
        FAIL += 1
        msg = f"  \u2717 FAIL: {name}"
        if detail:
            msg += f" ({detail})"
        print(msg)


def find_vk(circuit_name: str) -> Path:
    base = ROOT / circuit_name / "target"
    for p in [base / "vk" / "vk", base / "vk", base / "vk_dir" / "vk"]:
        if p.exists():
            return p
    raise FileNotFoundError(f"VK not found for {circuit_name}")


def setup_vk_dir() -> Path:
    d = Path(tempfile.mkdtemp(prefix="tonkl-e2e-vks-"))
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
    # Mint circuit: public inputs are cm_outs[32] + total_minted + asset_id = 34 fields
    # First 32 fields are commitments
    for i in range(32):
        chunk = pi_bytes[i * 32 : (i + 1) * 32]
        commitments.append("0x" + chunk.hex())
    return commitments


def start_node(vk_path: Path) -> subprocess.Popen:
    global data_dir
    data_dir = tempfile.mkdtemp(prefix="tonkl-e2e-data-")
    proc = subprocess.Popen(
        [
            str(NODE_BIN), "run",
            "--port", str(PORT),
            "--data-dir", data_dir,
            "--vk-dir", str(vk_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
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


# ─────────────────────────────────────────────────────────────────────
# Main Test
# ─────────────────────────────────────────────────────────────────────

def main():
    global node_proc, vk_dir, PASS, FAIL

    print("=" * 70)
    print("  Tonkl Protocol -- End-to-End Transfer Test")
    print("  mint → block → build witness → prove → submit → block → verify")
    print("=" * 70)
    print()

    # ── [0] Preflight ─────────────────────────────────────────────────
    print("[0/8] Preflight checks...")
    missing = []
    for name, path in [
        ("node binary", NODE_BIN),
        ("prover binary", PROVER_BIN),
        ("mint proof", MINT_PROOF),
        ("mint public_inputs", MINT_PI),
        ("transfer circuit JSON", TRANSFER_CIRCUIT),
        ("transfer VK", TRANSFER_VK),
    ]:
        if not path.exists():
            missing.append(f"  {name}: {path}")
    if missing:
        print("  ERROR: Missing artifacts:")
        for m in missing:
            print(m)
        sys.exit(1)
    print("  \u2713 All artifacts found")

    # ── [1] Setup + start node ────────────────────────────────────────
    print()
    print("[1/8] Starting node...")
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
    # Give the node a moment to fully initialize all subsystems
    time.sleep(1)
    print("  \u2713 Node ready")

    # ── [2] Submit mint + produce block ───────────────────────────────
    print()
    print("[2/8] Minting notes (submitting existing mint proof)...")
    commitments = read_mint_commitments()

    try:
        mint_result = client.submit_from_proof_files(
            tx_type="mint",
            proof_path=str(MINT_PROOF),
            public_inputs_path=str(MINT_PI),
            new_commitments=commitments,
            nullifiers=[],
            merkle_root="0x" + "00" * 32,
            fee=0,
        )
    except Exception as e:
        print(f"  ERROR: submit_tx failed: {e}")
        # Check if the node crashed
        if node_proc.poll() is not None:
            print(f"  NODE CRASHED (exit code {node_proc.returncode})")
            out, _ = node_proc.communicate(timeout=5)
            print("  --- Node output (last 3000 chars) ---")
            print(out.decode(errors="replace")[-3000:])
        else:
            print("  Node is still running — this may be a request/response issue")
            # Give it a moment and try a simple status call
            time.sleep(1)
            try:
                s = client.get_status()
                print(f"  Node responded to get_status: height={s.block_height}")
            except Exception as e2:
                print(f"  Node also failed get_status: {e2}")
        cleanup()
        sys.exit(1)
    check("mint tx accepted", mint_result.accepted)

    mint_header = client.produce_block()
    check("mint block produced", mint_header.block_number == 0, f"got block {mint_header.block_number}")
    check("mint block has 1 tx", mint_header.tx_count == 1, f"got {mint_header.tx_count}")

    post_mint = client.get_status()
    check("32 leaves in tree", post_mint.leaf_count == 32, f"got {post_mint.leaf_count}")
    print(f"  Merkle root after mint: {post_mint.merkle_root[:24]}...")

    # ── [3] Compute note data ─────────────────────────────────────────
    print()
    print("[3/8] Computing note data via tonkl-prover compute...")
    crypto = CryptoHelper(str(PROVER_BIN))

    # Derive public keys for our spending keys
    note0_pk_x, note0_pk_y = crypto.derive_pk(NOTE_0_SK)
    print(f"  Note 0 pk_x: {note0_pk_x[:24]}...")

    note1_pk_x, note1_pk_y = crypto.derive_pk(NOTE_1_SK)
    print(f"  Note 1 pk_x: {note1_pk_x[:24]}...")

    recipient_pk_x, recipient_pk_y = crypto.derive_pk(RECIPIENT_SK)
    print(f"  Recipient pk_x: {recipient_pk_x[:24]}...")

    # Compute input note commitments (to verify they match what's in the tree)
    note0_cm = crypto.commitment(
        str(NOTE_0_VALUE), ASSET_ID,
        note0_pk_x, note0_pk_y, NOTE_0_RHO,
    )
    print(f"  Note 0 commitment: {note0_cm[:24]}...")
    check("note 0 commitment matches mint output", note0_cm == commitments[0],
          f"computed={note0_cm[:20]} vs tree={commitments[0][:20]}")

    note1_cm = crypto.commitment(
        str(NOTE_1_VALUE), ASSET_ID,
        note1_pk_x, note1_pk_y, NOTE_1_RHO,
    )
    print(f"  Note 1 commitment: {note1_cm[:24]}...")
    check("note 1 commitment matches mint output", note1_cm == commitments[1],
          f"computed={note1_cm[:20]} vs tree={commitments[1][:20]}")

    # Compute nullifiers for input notes
    nf_1 = crypto.nullifier(note0_cm, NOTE_0_SK)
    nf_2 = crypto.nullifier(note1_cm, NOTE_1_SK)
    print(f"  Nullifier 1 (note 0): {nf_1[:24]}...")
    print(f"  Nullifier 2 (note 1): {nf_2[:24]}...")

    # Compute output commitments
    cm_out_1 = crypto.commitment(
        str(OUT_1_VALUE), ASSET_ID,
        recipient_pk_x, recipient_pk_y, OUT_1_RHO,
    )
    cm_out_2 = crypto.commitment(
        str(OUT_2_VALUE), ASSET_ID,
        note0_pk_x, note0_pk_y, OUT_2_RHO,
    )
    print(f"  Output commitment 1: {cm_out_1[:24]}...")
    print(f"  Output commitment 2: {cm_out_2[:24]}...")

    check("value conservation (in=out+fee)",
          NOTE_0_VALUE + NOTE_1_VALUE == OUT_1_VALUE + OUT_2_VALUE + FEE,
          f"{NOTE_0_VALUE}+{NOTE_1_VALUE} != {OUT_1_VALUE}+{OUT_2_VALUE}+{FEE}")

    # ── [4] Build transfer witness ────────────────────────────────────
    print()
    print("[4/8] Building transfer witness (querying node for merkle proofs)...")
    builder = WitnessBuilder(client)

    transfer_inputs = [
        NoteInput(
            index=0, value=NOTE_0_VALUE,
            owner_sk=NOTE_0_SK,
            owner_pk_x=note0_pk_x,
            owner_pk_y=note0_pk_y,
            rho=NOTE_0_RHO,
        ),
        NoteInput(
            index=1, value=NOTE_1_VALUE,
            owner_sk=NOTE_1_SK,
            owner_pk_x=note1_pk_x,
            owner_pk_y=note1_pk_y,
            rho=NOTE_1_RHO,
        ),
    ]
    transfer_outputs = [
        NoteOutput(
            value=OUT_1_VALUE,
            owner_pk_x=recipient_pk_x,
            owner_pk_y=recipient_pk_y,
            rho=OUT_1_RHO,
        ),
        NoteOutput(
            value=OUT_2_VALUE,
            owner_pk_x=note0_pk_x,
            owner_pk_y=note0_pk_y,
            rho=OUT_2_RHO,
        ),
    ]

    # Build JSON witness (tonkl-prover expects JSON on stdin)
    transfer_json = builder.build_transfer(
        inputs=transfer_inputs,
        outputs=transfer_outputs,
        fee=FEE,
        asset_id=ASSET_ID,
        nf_1=nf_1,
        nf_2=nf_2,
        cm_out_1=cm_out_1,
        cm_out_2=cm_out_2,
        output_format="json",
    )

    # Also build TOML for reference/debugging
    transfer_toml = builder.build_transfer(
        inputs=transfer_inputs,
        outputs=transfer_outputs,
        fee=FEE,
        asset_id=ASSET_ID,
        nf_1=nf_1,
        nf_2=nf_2,
        cm_out_1=cm_out_1,
        cm_out_2=cm_out_2,
        output_format="toml",
    )

    # Write both to temp files
    proof_work_dir = Path(tempfile.mkdtemp(prefix="tonkl-e2e-transfer-"))
    prover_toml_path = proof_work_dir / "Prover.toml"
    prover_toml_path.write_text(transfer_toml)
    prover_json_path = proof_work_dir / "witness.json"
    prover_json_path.write_text(transfer_json)

    check("Prover.toml written", prover_toml_path.exists())
    check("witness contains merkle_root", "merkle_root" in transfer_json)
    check("witness contains in1_merkle_path", "in1_merkle_path" in transfer_json)
    check("witness contains in2_merkle_path", "in2_merkle_path" in transfer_json)
    print(f"  Witness files: {proof_work_dir}")

    # ── [5] Generate transfer proof ───────────────────────────────────
    print()
    print("[5/8] Generating transfer proof (this may take ~30s)...")
    proof_output_dir = proof_work_dir / "output"
    proof_output_dir.mkdir()

    # Pipe JSON witness to tonkl-prover prove
    prove_result = subprocess.run(
        [
            str(PROVER_BIN), "prove",
            "-c", str(TRANSFER_CIRCUIT),
            "-o", str(proof_output_dir),
            "-k", str(TRANSFER_VK),
        ],
        input=transfer_json,
        capture_output=True,
        text=True,
        timeout=300,  # 5 minute timeout for proving
    )

    if prove_result.returncode != 0:
        print(f"  ERROR: Proving failed!")
        print(f"  stderr: {prove_result.stderr[-2000:]}")
        check("proof generation succeeded", False, "non-zero exit code")
        # Still try to continue with remaining tests
    else:
        print(f"  \u2713 Proof generated successfully")
        # Check proof artifacts exist
        transfer_proof = proof_output_dir / "proof" / "proof"
        transfer_pi = proof_output_dir / "proof" / "public_inputs"
        check("proof file exists", transfer_proof.exists())
        check("public_inputs file exists", transfer_pi.exists())

        if transfer_proof.exists():
            proof_size = transfer_proof.stat().st_size
            check("proof is 16256 bytes", proof_size == 16256, f"got {proof_size}")

        if transfer_pi.exists():
            pi_size = transfer_pi.stat().st_size
            # 7 public inputs * 32 bytes = 224
            check("public_inputs is 224 bytes", pi_size == 224, f"got {pi_size}")

        # ── [6] Submit transfer proof ─────────────────────────────────
        print()
        print("[6/8] Submitting transfer proof to node...")

        # Read the commitments and nullifiers from the transfer public inputs
        # Public input order: merkle_root, nf_1, nf_2, cm_out_1, cm_out_2, fee, asset_id
        # For submit_tx we need new_commitments and nullifiers separately
        transfer_result = client.submit_from_proof_files(
            tx_type="transfer",
            proof_path=str(transfer_proof),
            public_inputs_path=str(transfer_pi),
            new_commitments=[cm_out_1, cm_out_2],
            nullifiers=[nf_1, nf_2],
            merkle_root=post_mint.merkle_root,
            fee=FEE,
        )
        check("transfer tx accepted", transfer_result.accepted)
        print(f"  TX hash: {transfer_result.tx_hash[:24]}...")

        # Check pending status
        tx_status = client.get_tx_status(transfer_result.tx_hash)
        check("transfer tx is pending", tx_status.status == "pending",
              f"got {tx_status.status}")

        # ── [7] Produce block (confirm transfer) ─────────────────────
        print()
        print("[7/8] Producing block to confirm transfer...")
        transfer_header = client.produce_block()
        check("transfer block produced", transfer_header.block_number == 1,
              f"got block {transfer_header.block_number}")
        check("transfer block has 1 tx", transfer_header.tx_count == 1,
              f"got {transfer_header.tx_count}")
        check("state root changed", transfer_header.state_root != post_mint.merkle_root,
              "root unchanged!")

        # ── [8] Verify final state ────────────────────────────────────
        print()
        print("[8/8] Verifying final state...")

        # State should have 34 leaves (32 from mint + 2 from transfer)
        final_status = client.get_status()
        check("34 leaves in tree", final_status.leaf_count == 34,
              f"got {final_status.leaf_count}")
        check("block height is 2", final_status.block_height == 2,
              f"got {final_status.block_height}")

        # Nullifiers should be spent
        nf1_spent = client.get_nullifier_status(nf_1)
        check("nullifier 1 is spent", nf1_spent == True, f"got {nf1_spent}")
        nf2_spent = client.get_nullifier_status(nf_2)
        check("nullifier 2 is spent", nf2_spent == True, f"got {nf2_spent}")

        # Transaction should be confirmed
        confirmed = client.get_tx_status(transfer_result.tx_hash)
        check("transfer tx confirmed", confirmed.status == "confirmed",
              f"got {confirmed.status}")
        check("confirmed in block 1", confirmed.block_number == 1,
              f"got {confirmed.block_number}")
        check("confirmations >= 1",
              confirmed.confirmations is not None and confirmed.confirmations >= 1,
              f"got {confirmed.confirmations}")
        check("tx_type is Transfer",
              confirmed.tx_type is not None and "Transfer" in confirmed.tx_type,
              f"got {confirmed.tx_type}")

        # Double-spend should fail: try submitting the same nullifiers again
        print()
        print("  Testing double-spend prevention...")
        try:
            client.submit_from_proof_files(
                tx_type="transfer",
                proof_path=str(transfer_proof),
                public_inputs_path=str(transfer_pi),
                new_commitments=[cm_out_1, cm_out_2],
                nullifiers=[nf_1, nf_2],
                merkle_root=post_mint.merkle_root,
                fee=FEE,
            )
            check("double-spend rejected", False, "was accepted!")
        except RpcError as e:
            check("double-spend rejected (RpcError)", True)
            check("error mentions nullifier", "nullifier" in str(e).lower(),
                  str(e)[:80])

        # Verify new output notes exist in the tree
        # They should be at indices 32 and 33
        proof32 = client.get_merkle_proof(32)
        check("output note 1 has merkle proof", len(proof32.siblings) == 32)
        proof33 = client.get_merkle_proof(33)
        check("output note 2 has merkle proof", len(proof33.siblings) == 32)

        # Get the transfer block and inspect it
        transfer_block = client.get_block(1)
        check("transfer block exists", transfer_block is not None)
        if transfer_block:
            txs = transfer_block.get("transactions", [])
            check("block has 1 transaction", len(txs) == 1, f"got {len(txs)}")
            if txs:
                check("tx type is Transfer", txs[0]["tx_type"] == "Transfer",
                      f"got {txs[0]['tx_type']}")

    # ── Cleanup temp proof dir ────────────────────────────────────────
    subprocess.run(["rm", "-rf", str(proof_work_dir)], check=False)

    # ── Results ───────────────────────────────────────────────────────
    print()
    print("=" * 70)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"  ALL {PASS} TESTS PASSED")
        print()
        print("  The full transfer lifecycle works end-to-end:")
        print("    mint notes → produce block → build witness from node state")
        print("    → generate ZK proof → submit to node → produce block")
        print("    → verify nullifiers spent, commitments added, tx confirmed")
        print("    → double-spend correctly rejected")
    else:
        print(f"  Results: {PASS} passed, {FAIL} failed (of {total})")
    print("=" * 70)

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
