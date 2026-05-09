#!/usr/bin/env python3
"""
Tonkl Protocol -- Multi-Node Testnet Launcher

Spins up a local testnet with 2-3 nodes, generates genesis block(s) on the
primary node, and copies state to secondary nodes so all share the same
initial ledger.

Usage:
  # Launch 3-node testnet with genesis
  python3 scripts/launch_testnet.py

  # Custom node count and ports
  python3 scripts/launch_testnet.py --nodes 2 --base-port 9200

  # Skip genesis (nodes start empty)
  python3 scripts/launch_testnet.py --skip-genesis

  # Custom faucet key
  python3 scripts/launch_testnet.py --faucet-sk 0xface70

Nodes:
  Node 0 (primary):  port = base_port       (default 9100)
  Node 1 (secondary): port = base_port + 1  (default 9101)
  Node 2 (secondary): port = base_port + 2  (default 9102)

The script:
  1. Creates temp data directories for each node
  2. Sets up shared VK directory
  3. Starts all nodes
  4. Runs genesis on the primary node
  5. Stops secondary nodes, copies state from primary, restarts them
  6. Verifies all nodes share the same state
  7. Writes testnet.json with connection details
  8. Waits for Ctrl+C, then shuts everything down
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent  # tonkl/

sys.path.insert(0, str(SCRIPT_DIR))
from node_client import TonklClient
from genesis import build_genesis, find_vk, DEFAULT_FAUCET_SK

# ─────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────

BANNER = r"""
  ┌──────────────────────────────────────────────────────────────┐
  │                                                              │
  │          T O N K L   T E S T N E T                           │
  │          Privacy-Preserving Blockchain                       │
  │                                                              │
  │          Version: 0.2.0-beta (P2P enabled)                    │
  │          Network: tonkl-testnet-1                            │
  │                                                              │
  └──────────────────────────────────────────────────────────────┘
"""

DISCLAIMER = """  WARNING: This is alpha software for testing only.
  Do not use real funds. Expect bugs. Data may be wiped between versions.
"""


def _elapsed(start: float) -> str:
    """Format elapsed time since start."""
    s = time.time() - start
    if s < 1:
        return f"{s*1000:.0f}ms"
    elif s < 60:
        return f"{s:.1f}s"
    else:
        return f"{int(s//60)}m{int(s%60)}s"

# ─────────────────────────────────────────────────────────────────────
# Node management
# ─────────────────────────────────────────────────────────────────────

NODE_BIN = ROOT / "obscura-node" / "target" / "release" / "obscura-node"


class TestnetNode:
    """Manages a single Tonkl node process."""

    def __init__(
        self,
        node_id: int,
        port: int,
        data_dir: str,
        vk_dir: str,
        p2p_port: int = 0,
        bind: str = "127.0.0.1",
        num_nodes: int = 1,
    ):
        self.node_id = node_id
        self.port = port
        self.p2p_port = p2p_port
        self.data_dir = data_dir
        self.vk_dir = vk_dir
        self.bind = bind
        self.num_nodes = num_nodes
        self.url = f"http://{bind}:{port}"
        self.process: Optional[subprocess.Popen] = None
        self.client = TonklClient(self.url, timeout=30.0)

    def start(
        self,
        bootstrap_addr: str = "",
        sync_from: str = "",
    ) -> None:
        """Start the node process.

        Args:
            bootstrap_addr: Multiaddr of a bootstrap peer for P2P discovery.
            sync_from: RPC URL of a peer to sync blocks from on startup.
        """
        if self.process is not None:
            return

        cmd = [
            str(NODE_BIN), "run",
            "--port", str(self.port),
            "--bind", self.bind,
            "--data-dir", self.data_dir,
            "--vk-dir", self.vk_dir,
            "--node-id", f"node-{self.node_id}",
            "--block-interval", "5",
        ]

        # Multi-node: pass validator list for round-robin consensus
        if self.num_nodes > 1:
            validator_ids = ",".join(f"node-{i}" for i in range(self.num_nodes))
            cmd.extend(["--validators", validator_ids])

        # P2P networking
        if self.p2p_port > 0:
            cmd.extend(["--p2p-port", str(self.p2p_port)])
            if bootstrap_addr:
                cmd.extend(["--bootstrap", bootstrap_addr])

        # Chain sync from existing peer
        if sync_from:
            cmd.extend(["--sync-from", sync_from])

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def stop(self) -> None:
        """Stop the node process gracefully."""
        if self.process is None:
            return

        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process = None

    def wait_ready(self, timeout: float = 15.0) -> bool:
        """Wait for the node to become reachable."""
        return self.client.wait_for_node(timeout=timeout)

    def is_running(self) -> bool:
        """Check if the node process is still alive."""
        if self.process is None:
            return False
        return self.process.poll() is None

    def get_status(self) -> dict:
        """Get node status as a dict."""
        s = self.client.get_status()
        return {
            "block_height": s.block_height,
            "merkle_root": s.merkle_root,
            "leaf_count": s.leaf_count,
            "nullifier_count": s.nullifier_count,
            "mempool_size": s.mempool_size,
        }


# ─────────────────────────────────────────────────────────────────────
# VK directory setup
# ─────────────────────────────────────────────────────────────────────

def setup_vk_dir() -> Path:
    """Create a temp directory with all circuit verification keys."""
    d = Path(tempfile.mkdtemp(prefix="obscura-testnet-vks-"))
    for circuit, folder in [
        ("obscura-transfer", "transfer"),
        ("obscura-merge", "merge"),
        ("obscura-split", "split"),
        ("obscura-mint", "mint"),
    ]:
        vk_sub = d / folder
        vk_sub.mkdir()
        src = find_vk(circuit)
        (vk_sub / "vk").write_bytes(src.read_bytes())
    return d


# ─────────────────────────────────────────────────────────────────────
# Testnet orchestrator
# ─────────────────────────────────────────────────────────────────────

class Testnet:
    """Orchestrates a multi-node local testnet."""

    def __init__(
        self,
        num_nodes: int = 3,
        base_port: int = 9100,
        base_p2p_port: int = 9150,
        faucet_sk: str = DEFAULT_FAUCET_SK,
        skip_genesis: bool = False,
        verbose: bool = True,
    ):
        self.num_nodes = num_nodes
        self.base_port = base_port
        self.base_p2p_port = base_p2p_port
        self.faucet_sk = faucet_sk
        self.skip_genesis = skip_genesis
        self.verbose = verbose

        self.nodes: List[TestnetNode] = []
        self.data_dirs: List[str] = []
        self.vk_dir: Optional[Path] = None
        self.genesis_config: Optional[dict] = None
        self._running = False

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def start(self) -> dict:
        """
        Launch the full testnet.

        Returns the testnet config dict (also written to testnet.json).
        """
        launch_start = time.time()

        if self.verbose:
            print(BANNER)
            print(DISCLAIMER)

        # ── Step 1: Preflight ─────────────────────────────────────────
        step_start = time.time()
        self._log("  [1/7] Preflight checks...")
        missing = []
        if not NODE_BIN.exists():
            missing.append(f"Node binary: {NODE_BIN}")
        for tool in ["nargo", "bb"]:
            if shutil.which(tool) is None:
                missing.append(f"{tool} not on PATH")
        if missing:
            self._log("")
            self._log("  Missing prerequisites:")
            for m in missing:
                self._log(f"    ✗ {m}")
            self._log("")
            self._log("  Please install Noir (nargo) and Barretenberg (bb),")
            self._log("  then build the node: cargo build --release")
            raise FileNotFoundError("Prerequisites missing — see above")
        self._log(f"        ✓ Node binary, nargo, bb found ({_elapsed(step_start)})")

        # ── Step 2: Verification keys ─────────────────────────────────
        step_start = time.time()
        self._log("  [2/7] Loading verification keys...")
        self.vk_dir = setup_vk_dir()
        self._log(f"        ✓ 4 circuit VKs ready ({_elapsed(step_start)})")

        # Create data directories
        for i in range(self.num_nodes):
            d = tempfile.mkdtemp(prefix=f"obscura-testnet-node{i}-")
            self.data_dirs.append(d)

        # ── Step 3: Start primary node ────────────────────────────────
        step_start = time.time()
        self._log(f"  [3/7] Starting primary node on port {self.base_port}...")
        primary = TestnetNode(
            node_id=0,
            port=self.base_port,
            data_dir=self.data_dirs[0],
            vk_dir=str(self.vk_dir),
            p2p_port=self.base_p2p_port,
            num_nodes=self.num_nodes,
        )
        primary.start()
        self.nodes.append(primary)

        if not primary.wait_ready():
            raise RuntimeError("Primary node failed to start")
        self._log(f"        ✓ Node 0 listening at {primary.url} ({_elapsed(step_start)})")

        # ── Step 4: Genesis ───────────────────────────────────────────
        step_start = time.time()
        if not self.skip_genesis:
            self._log("  [4/7] Generating genesis block (this takes a minute)...")
            genesis_path = str(Path(self.data_dirs[0]) / "genesis.json")
            self.genesis_config = build_genesis(
                faucet_sk=self.faucet_sk,
                node_url=primary.url,
                output_path=genesis_path,
                verbose=False,  # suppress sub-output; we show our own
            )
            notes = self.genesis_config.get("funded_notes", [])
            obs = sum(n["value"] for n in notes if n["asset_id"] == "1")
            usdc = sum(n["value"] for n in notes if n["asset_id"] == "4")
            self._log(f"        ✓ Minted {obs:,} TNKL + {usdc / 1e6:,.0f} sUSDC ({_elapsed(step_start)})")
        else:
            self._log("  [4/7] Skipping genesis (--skip-genesis)")

        # ── Step 5: P2P sync info ─────────────────────────────────────
        step_start = time.time()
        primary_bootstrap = f"/ip4/127.0.0.1/tcp/{self.base_p2p_port}"
        if self.num_nodes > 1:
            self._log(f"  [5/7] Secondary nodes will sync via P2P + RPC...")
            self._log(f"        Bootstrap peer: {primary_bootstrap}")
            self._log(f"        Sync source:    {primary.url}")
            self._log(f"        ✓ Ready ({_elapsed(step_start)})")
        else:
            self._log("  [5/7] Single node — no replication needed")

        # ── Step 6: Start secondary nodes ─────────────────────────────
        step_start = time.time()
        if self.num_nodes > 1:
            self._log(f"  [6/7] Starting secondary nodes...")
            for i in range(1, self.num_nodes):
                node = TestnetNode(
                    node_id=i,
                    port=self.base_port + i,
                    data_dir=self.data_dirs[i],
                    vk_dir=str(self.vk_dir),
                    p2p_port=self.base_p2p_port + i,
                    num_nodes=self.num_nodes,
                )
                node.start(
                    bootstrap_addr=primary_bootstrap,
                    sync_from=primary.url,
                )
                self.nodes.append(node)

                if not node.wait_ready(timeout=30.0):  # longer timeout for sync
                    raise RuntimeError(f"Node {i} failed to start")
                self._log(f"        ✓ Node {i} listening at {node.url} (P2P :{node.p2p_port})")

            # Verify state consistency
            primary_status = primary.get_status()
            all_match = True
            for node in self.nodes[1:]:
                node_status = node.get_status()
                if (node_status["merkle_root"] != primary_status["merkle_root"]
                        or node_status["block_height"] != primary_status["block_height"]):
                    self._log(f"        ✗ Node {node.node_id} state mismatch!")
                    all_match = False
            if all_match:
                self._log(f"        ✓ All nodes consistent ({_elapsed(step_start)})")
            else:
                self._log(f"        ⚠ State mismatch — nodes may diverge")
        else:
            self._log("  [6/7] Single node — no secondaries")

        # ── Step 7: Write config ──────────────────────────────────────
        step_start = time.time()
        self._log("  [7/7] Writing testnet config...")
        testnet_config = self._build_config()
        config_path = ROOT / "obscura-node" / "testnet.json"
        config_path.write_text(json.dumps(testnet_config, indent=2) + "\n")
        self._log(f"        ✓ Saved to testnet.json ({_elapsed(step_start)})")

        self._running = True

        # ── Bootstrap faucet wallet ──────────────────────────────────
        # Import genesis notes into the default wallet so the faucet
        # command works out of the box.
        if self.genesis_config and self.genesis_config.get("funded_notes"):
            try:
                from obscura_wallet import NodeWallet
                faucet_db = Path.home() / ".tonkl" / "faucet_wallet.db"
                faucet_db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                faucet_wallet = NodeWallet(
                    node_url=self.nodes[0].url,
                    db_path=str(faucet_db),
                )
                imported = 0
                for note in self.genesis_config["funded_notes"]:
                    try:
                        faucet_wallet.import_note(
                            sk=self.faucet_sk,
                            value=note["value"],
                            rho=note["rho"],
                            asset_id=note["asset_id"],
                            tree_index=note.get("tree_index"),
                        )
                        imported += 1
                    except Exception:
                        pass  # skip duplicates on re-run
                faucet_wallet.close()
                self._log(f"        ✓ Faucet wallet loaded ({imported} notes)")
            except Exception as e:
                self._log(f"        ⚠ Faucet wallet setup skipped: {e}")

        # ── Summary card ──────────────────────────────────────────────
        total_time = _elapsed(launch_start)
        self._log("")
        self._log("  ┌──────────────────────────────────────────────────────────────┐")
        self._log("  │  ✓ TESTNET IS RUNNING                                       │")
        self._log("  ├──────────────────────────────────────────────────────────────┤")
        for node in self.nodes:
            role = "primary  " if node.node_id == 0 else "secondary"
            line = f"Node {node.node_id} ({role}): {node.url}  P2P :{node.p2p_port}"
            self._log(f"  │  {line:<59} │")
        self._log("  ├──────────────────────────────────────────────────────────────┤")
        if self.genesis_config:
            notes = self.genesis_config.get("funded_notes", [])
            obs = sum(n["value"] for n in notes if n["asset_id"] == "1")
            usdc = sum(n["value"] for n in notes if n["asset_id"] == "4")
            supply_line = f"Faucet supply: {obs:,} TNKL + {usdc / 1e6:,.0f} sUSDC"
            self._log(f"  │  {supply_line:<59} │")
            key_line = f"Faucet key:    {self.faucet_sk}"
            self._log(f"  │  {key_line:<59} │")
        time_line = f"Launch time:   {total_time}"
        self._log(f"  │  {time_line:<59} │")
        self._log("  └──────────────────────────────────────────────────────────────┘")

        # ── Quick-start guide ─────────────────────────────────────────
        primary_url = self.nodes[0].url
        self._log("")
        self._log("  Quick Start:")
        self._log("")
        self._log("    1. Create a wallet:")
        self._log(f"       python3 scripts/obscura_wallet.py --node {primary_url}")
        self._log("")
        self._log("    2. Get testnet tokens:")
        self._log(f"       python3 scripts/obscura_wallet.py --node {primary_url} faucet --to-sk <your-key>")
        self._log("")
        self._log("    3. Check your balance:")
        self._log(f"       python3 scripts/obscura_wallet.py --node {primary_url} balance")
        self._log("")

        # Check if explorer exists
        explorer_path = ROOT / "obscura-node" / "explorer" / "index.html"
        if explorer_path.exists():
            self._log("    4. Open the block explorer:")
            self._log(f"       file://{explorer_path}")
            self._log(f"       (Set node URL to {primary_url})")
            self._log("")

        self._log("  Press Ctrl+C to stop all nodes.")
        self._log("")

        return testnet_config

    def _build_config(self) -> dict:
        """Build the testnet.json configuration."""
        nodes_config = []
        for node in self.nodes:
            nodes_config.append({
                "id": node.node_id,
                "url": node.url,
                "port": node.port,
                "p2p_port": node.p2p_port,
                "data_dir": node.data_dir,
                "role": "primary" if node.node_id == 0 else "secondary",
            })

        config = {
            "version": "1.0",
            "chain_id": "tonkl-testnet-1",
            "launched_at": int(time.time()),
            "nodes": nodes_config,
            "faucet": {
                "sk": self.faucet_sk,
                "node_url": self.nodes[0].url if self.nodes else None,
            },
        }

        if self.genesis_config:
            config["genesis"] = {
                "block_height": self.genesis_config["initial_state"]["block_height"],
                "merkle_root": self.genesis_config["initial_state"]["merkle_root"],
                "funded_notes_count": len(self.genesis_config["funded_notes"]),
            }

        return config

    def stop(self) -> None:
        """Stop all nodes and clean up."""
        if not self._running and not self.nodes:
            return
        self._running = False

        if self.verbose:
            print()
            print("  Shutting down testnet...")

        for node in reversed(self.nodes):
            node.stop()
            if self.verbose:
                print(f"    ✓ Node {node.node_id} stopped")

        # Clean up data dirs
        for d in self.data_dirs:
            shutil.rmtree(d, ignore_errors=True)

        # Clean up VK dir
        if self.vk_dir:
            shutil.rmtree(str(self.vk_dir), ignore_errors=True)

        if self.verbose:
            print(f"    ✓ Temp directories cleaned up")
            print()
            print("  Testnet stopped. See you next time!")
            print()

    def wait(self) -> None:
        """Block until Ctrl+C, then stop."""
        check_count = 0
        try:
            while self._running:
                # Periodic health check
                for node in self.nodes:
                    if not node.is_running():
                        print(f"\n  ✗ Node {node.node_id} exited unexpectedly!")
                        # Dump captured output so we can see why it crashed
                        if node.process and node.process.stdout:
                            try:
                                remaining = node.process.stdout.read()
                                if remaining:
                                    print(f"    ── Last output from node-{node.node_id} ──")
                                    for line in remaining.decode(errors="replace").strip().splitlines()[-30:]:
                                        print(f"    │ {line}")
                                    print(f"    ──────────────────────────────")
                            except Exception:
                                pass
                        rc = node.process.returncode if node.process else "?"
                        print(f"    Exit code: {rc}")
                        print(f"    Shutting down remaining nodes...")
                        self.stop()
                        return

                # Periodic status heartbeat (every ~60s)
                check_count += 1
                if check_count % 30 == 0 and self.verbose:
                    try:
                        s = self.nodes[0].get_status()
                        ts = time.strftime("%H:%M:%S")
                        print(f"  [{ts}] height={s['block_height']}, "
                              f"leaves={s['leaf_count']}, "
                              f"mempool={s['mempool_size']}, "
                              f"nodes={len(self.nodes)}")
                    except Exception:
                        pass  # node temporarily busy

                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def get_primary(self) -> TestnetNode:
        """Get the primary node."""
        return self.nodes[0]

    def get_client(self, node_id: int = 0) -> TonklClient:
        """Get an RPC client for a specific node."""
        return self.nodes[node_id].client


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Launch a local Tonkl testnet with pre-funded faucet accounts.",
        epilog="""examples:
  %(prog)s                      Launch 3-node testnet (default)
  %(prog)s -n 1                 Single node for quick testing
  %(prog)s --skip-genesis       Start empty (no pre-funded notes)
  %(prog)s --base-port 9200     Use custom ports (9200, 9201, 9202)""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--nodes", "-n",
        type=int,
        default=3,
        choices=[1, 2, 3],
        help="Number of nodes to launch (default: 3)",
    )
    parser.add_argument(
        "--base-port",
        type=int,
        default=9100,
        help="Base RPC port for nodes (default: 9100)",
    )
    parser.add_argument(
        "--faucet-sk",
        default=DEFAULT_FAUCET_SK,
        help=f"Faucet authority secret key (default: {DEFAULT_FAUCET_SK})",
    )
    parser.add_argument(
        "--base-p2p-port",
        type=int,
        default=9150,
        help="Base P2P port for nodes (default: 9150)",
    )
    parser.add_argument(
        "--skip-genesis",
        action="store_true",
        help="Start nodes without genesis block (empty chain)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output except errors",
    )

    args = parser.parse_args()

    testnet = Testnet(
        num_nodes=args.nodes,
        base_port=args.base_port,
        base_p2p_port=args.base_p2p_port,
        faucet_sk=args.faucet_sk,
        skip_genesis=args.skip_genesis,
        verbose=not args.quiet,
    )

    try:
        testnet.start()
        testnet.wait()
    except FileNotFoundError as e:
        # Preflight failures already printed detailed output
        sys.exit(1)
    except KeyboardInterrupt:
        testnet.stop()
    except Exception as e:
        print(f"\n  ✗ Error: {e}", file=sys.stderr)
        testnet.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
