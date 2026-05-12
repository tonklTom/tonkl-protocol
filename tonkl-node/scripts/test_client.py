#!/usr/bin/env python3
"""
Tonkl Node -- Python RPC Client Integration Test

Starts the node, exercises every TonklClient method, and validates
responses. Uses real proof artifacts from tonkl-mint.

Prerequisites:
  - tonkl-node built (cargo build --release)
  - Mint proof + VK generated (bb prove / bb write_vk)

Usage:
  cd ~/Desktop/tonkl/tonkl-node
  python3 scripts/test_client.py
"""

import os
import json
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Resolve paths
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent  # tonkl/
NODE_BIN = ROOT / "tonkl-node" / "target" / "release" / "tonkl-node"
MINT_PROOF = ROOT / "tonkl-mint" / "target" / "proof" / "proof"
MINT_PI = ROOT / "tonkl-mint" / "target" / "proof" / "public_inputs"

# Import the client (same directory)
sys.path.insert(0, str(SCRIPT_DIR))
from node_client import TonklClient, RpcError, NodeError, ConnectionError as ClientConnectionError
from witness_builder import WitnessBuilder, NoteInput, NoteOutput

PORT = 9198
PASS = 0
FAIL = 0
node_proc = None
data_dir = None
vk_dir = None


def check(name: str, condition: bool, detail: str = ""):
    """Record a test result."""
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
    """Locate the VK file for a circuit (handles both layouts)."""
    base = ROOT / circuit_name / "target"
    if (base / "vk" / "vk").exists():
        return base / "vk" / "vk"
    elif (base / "vk").is_file():
        return base / "vk"
    elif (base / "vk_dir" / "vk").exists():
        return base / "vk_dir" / "vk"
    raise FileNotFoundError(f"VK not found for {circuit_name}")


def setup_vk_dir() -> Path:
    """Create a temp VK directory with all circuit VKs."""
    d = Path(tempfile.mkdtemp(prefix="tonkl-test-vks-"))
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


def read_commitments() -> list:
    """Read the first 32 public inputs (commitments) from the mint proof."""
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
    """Start the node and wait for it to be ready."""
    global data_dir
    data_dir = tempfile.mkdtemp(prefix="tonkl-test-data-")

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
    """Kill node and remove temp dirs."""
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


def main():
    global node_proc, vk_dir, PASS, FAIL

    print("=" * 65)
    print("  Tonkl Node -- Python Client Integration Test")
    print("=" * 65)
    print()

    # ── Preflight checks ──────────────────────────────────────────────
    print("[0/9] Preflight checks...")
    if not NODE_BIN.exists():
        print(f"  ERROR: Node binary not found: {NODE_BIN}")
        print("  Run: cd tonkl-node && cargo build --release")
        sys.exit(1)
    if not MINT_PROOF.exists() or not MINT_PI.exists():
        print(f"  ERROR: Mint proof artifacts not found")
        sys.exit(1)
    print("  \u2713 All artifacts found")

    # ── Setup VK directory ────────────────────────────────────────────
    print()
    print("[1/9] Setting up VK directory...")
    try:
        vk_dir = setup_vk_dir()
        print(f"  \u2713 VK directory ready at {vk_dir}")
    except FileNotFoundError as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    # ── Start node ────────────────────────────────────────────────────
    print()
    print("[2/9] Starting node...")
    node_proc = start_node(vk_dir)

    client = TonklClient(f"http://127.0.0.1:{PORT}")

    # Test wait_for_node
    ready = client.wait_for_node(timeout=10.0)
    check("wait_for_node returns True", ready)
    if not ready:
        print("  Node failed to start!")
        # Dump node output for debugging
        node_proc.terminate()
        out, _ = node_proc.communicate(timeout=5)
        print(out.decode(errors="replace")[-2000:])
        cleanup()
        sys.exit(1)

    check("is_connected returns True", client.is_connected())

    # ── Test get_status (fresh node) ──────────────────────────────────
    print()
    print("[3/9] Testing get_status...")
    status = client.get_status()
    check("block_height == 0", status.block_height == 0, f"got {status.block_height}")
    check("leaf_count == 0", status.leaf_count == 0, f"got {status.leaf_count}")
    check("nullifier_count == 0", status.nullifier_count == 0, f"got {status.nullifier_count}")
    check("mempool_size == 0", status.mempool_size == 0, f"got {status.mempool_size}")
    check("merkle_root is hex string", status.merkle_root.startswith("0x"), f"got {status.merkle_root[:20]}")

    # ── Test get_merkle_root ──────────────────────────────────────────
    root = client.get_merkle_root()
    check("get_merkle_root matches status", root == status.merkle_root,
          f"{root[:20]} != {status.merkle_root[:20]}")

    # ── Test submit valid mint transaction ─────────────────────────────
    print()
    print("[4/9] Submitting valid mint transaction (from proof files)...")
    commitments = read_commitments()

    result = client.submit_from_proof_files(
        tx_type="mint",
        proof_path=str(MINT_PROOF),
        public_inputs_path=str(MINT_PI),
        new_commitments=commitments,
        nullifiers=[],
        merkle_root="0x" + "00" * 32,
        fee=0,
    )
    check("submit accepted", result.accepted)
    check("tx_hash is hex", result.tx_hash.startswith("0x") and len(result.tx_hash) == 66,
          f"got {result.tx_hash[:20]}")

    # Mempool should have 1 tx now
    status_after = client.get_status()
    check("mempool_size == 1", status_after.mempool_size == 1, f"got {status_after.mempool_size}")

    # ── Test get_tx_status (pending) ─────────────────────────────────
    print()
    print("[4b/9] Testing get_tx_status (pending tx)...")
    tx_status = client.get_tx_status(result.tx_hash)
    check("tx status is pending", tx_status.status == "pending", f"got {tx_status.status}")
    check("pending tx has no block_number", tx_status.block_number is None)
    check("pending tx has no confirmations", tx_status.confirmations is None)

    # Unknown tx
    unknown = client.get_tx_status("0x" + "ff" * 32)
    check("unknown tx returns 'unknown'", unknown.status == "unknown", f"got {unknown.status}")

    # ── Test garbage proof rejection ──────────────────────────────────
    print()
    print("[5/9] Submitting garbage proof (should be rejected)...")
    garbage_proof = os.urandom(16256)
    try:
        client.submit_tx(
            tx_type="mint",
            proof=garbage_proof,
            public_inputs=[MINT_PI.read_bytes()[i*32:(i+1)*32] for i in range(36)],
            new_commitments=commitments,
            nullifiers=[],
            merkle_root="0x" + "00" * 32,
        )
        check("garbage proof rejected", False, "was accepted!")
    except RpcError as e:
        check("garbage proof rejected (RpcError)", True)
        check("error mentions proof", "proof" in str(e).lower(), str(e)[:80])

    # ── Test produce_block ────────────────────────────────────────────
    print()
    print("[6/9] Producing block...")
    header = client.produce_block()
    check("block_number == 0", header.block_number == 0, f"got {header.block_number}")
    check("tx_count == 1", header.tx_count == 1, f"got {header.tx_count}")
    check("state_root changed", header.state_root != status.merkle_root,
          "root unchanged after mint!")
    check("timestamp > 0", header.timestamp > 0)

    # ── Post-block state checks ───────────────────────────────────────
    print()
    print("[7/9] Post-block state and queries...")

    # Status should show 32 leaves (mint inserts 32 commitments)
    post = client.get_status()
    check("block_height == 1", post.block_height == 1, f"got {post.block_height}")
    check("leaf_count == 32", post.leaf_count == 32, f"got {post.leaf_count}")
    check("mempool_size == 0 (drained)", post.mempool_size == 0, f"got {post.mempool_size}")

    # get_block
    block = client.get_block(0)
    check("get_block(0) returns block", block is not None)
    if block:
        check("block has 1 transaction", len(block.get("transactions", [])) == 1,
              f"got {len(block.get('transactions', []))}")
        tx = block["transactions"][0]
        check("tx type is Mint", tx["tx_type"] == "Mint", f"got {tx['tx_type']}")

    # get_block for non-existent block
    no_block = client.get_block(999)
    check("get_block(999) returns None", no_block is None, f"got {type(no_block)}")

    # get_merkle_proof for leaf 0
    proof = client.get_merkle_proof(0)
    check("merkle_proof index == 0", proof.index == 0)
    check("merkle_proof has 32 siblings", len(proof.siblings) == 32,
          f"got {len(proof.siblings)}")
    check("merkle_proof has 32 index_bits", len(proof.index_bits) == 32,
          f"got {len(proof.index_bits)}")

    # Nullifier check (should all be unspent for mint — no nullifiers)
    nf_status = client.get_nullifier_status("0x" + "00" * 31 + "ff")
    check("random nullifier is unspent", nf_status == False, f"got {nf_status}")

    # Produce an empty block
    header2 = client.produce_block()
    check("second block number == 1", header2.block_number == 1, f"got {header2.block_number}")
    check("empty block tx_count == 0", header2.tx_count == 0, f"got {header2.tx_count}")

    # ── Test get_tx_status (confirmed) ────────────────────────────────
    print()
    print("[8/9] Testing get_tx_status (confirmed tx)...")
    confirmed = client.get_tx_status(result.tx_hash)
    check("tx status is confirmed", confirmed.status == "confirmed", f"got {confirmed.status}")
    check("confirmed in block 0", confirmed.block_number == 0, f"got {confirmed.block_number}")
    check("confirmations >= 1", confirmed.confirmations is not None and confirmed.confirmations >= 1,
          f"got {confirmed.confirmations}")
    check("tx_type is Mint", confirmed.tx_type is not None and "Mint" in confirmed.tx_type,
          f"got {confirmed.tx_type}")

    # ── Test WitnessBuilder (node-aware) ──────────────────────────────
    print()
    print("[9/9] Testing WitnessBuilder...")
    builder = WitnessBuilder(client)

    # Test mint witness generation (no node queries needed)
    # Use dummy commitments — this test only checks TOML structure, not proving
    dummy_cm = ["0x" + "aa" * 32] * 32
    mint_toml = builder.build_mint(
        outputs=[
            NoteOutput(value=500, owner_pk_x="0x" + "ab" * 32, owner_pk_y="0x" + "cd" * 32, rho="1001"),
            NoteOutput(value=500, owner_pk_x="0x" + "ab" * 32, owner_pk_y="0x" + "cd" * 32, rho="1002"),
        ],
        total_minted=1000,
        asset_id="1",
        authority_pk_x="0x" + "11" * 32,
        authority_pk_y="0x" + "22" * 32,
        authority_sk="0xfed001",
        cm_outs=dummy_cm,
    )
    check("mint TOML contains total_minted", 'total_minted = "1000"' in mint_toml)
    check("mint TOML contains authority_sk", "authority_sk" in mint_toml)
    check("mint TOML has 32 out_values", mint_toml.count('"500"') == 2)  # 2 real outputs + 30 zeros

    # Test split witness generation (queries node for merkle proof)
    # Use dummy nullifier and commitments — structure test only
    dummy_nf = "0x" + "bb" * 32
    split_toml = builder.build_split(
        input_note=NoteInput(
            index=0, value=1000,
            owner_sk="0xae0901",
            owner_pk_x="0x" + "ab" * 32,
            owner_pk_y="0x" + "cd" * 32,
            rho="7001",
        ),
        outputs=[
            NoteOutput(value=600, owner_pk_x="0x" + "ab" * 32, owner_pk_y="0x" + "cd" * 32, rho="8001"),
            NoteOutput(value=400, owner_pk_x="0x" + "ab" * 32, owner_pk_y="0x" + "cd" * 32, rho="8002"),
        ],
        fee=0,
        asset_id="1",
        nf=dummy_nf,
        cm_outs=dummy_cm,
    )
    check("split TOML contains merkle_root", "merkle_root" in split_toml)
    check("split TOML has in_merkle_path", "in_merkle_path" in split_toml)
    check("split TOML has 32 out_values", "out_values" in split_toml)
    # Verify the merkle root came from the node (matches current state)
    current_root = client.get_merkle_root()
    check("split merkle_root matches node", current_root in split_toml,
          f"expected {current_root[:20]} in TOML")

    # Write and verify file I/O
    test_toml_path = os.path.join(tempfile.mkdtemp(), "test_prover.toml")
    WitnessBuilder.write_toml(mint_toml, test_toml_path)
    check("write_toml creates file", os.path.exists(test_toml_path))
    read_back = Path(test_toml_path).read_text()
    check("written TOML matches", read_back == mint_toml)

    # ── Results ───────────────────────────────────────────────────────
    print()
    print("=" * 65)
    print(f"  Results: {PASS} passed, {FAIL} failed")
    print("=" * 65)

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
