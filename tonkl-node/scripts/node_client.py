#!/usr/bin/env python3
"""
Tonkl Node -- Python RPC Client

Connects a wallet (or any Python code) to a running Tonkl node
via JSON-RPC over HTTP.

Usage:
    from node_client import TonklClient

    client = TonklClient()                       # default: http://127.0.0.1:9100
    client = TonklClient("http://localhost:9200") # custom URL
    # If TONKL_RPC_SECRET is set, write and protected read RPCs include it automatically.

    # Query state
    status = client.get_status()
    root   = client.get_merkle_root()
    proof  = client.get_merkle_proof(index=0)
    spent  = client.get_nullifier_status("0xabc...")

    # Submit a transaction
    result = client.submit_tx(
        tx_type="mint",
        proof=b"...",
        public_inputs=[b"\\x00"*32, ...],
        new_commitments=["0xabc...", ...],
        nullifiers=[],
        merkle_root="0x" + "00"*32,
        fee=0,
        asset_id="0x" + "00"*31 + "01",
    )

    # Submit from proof files (bb output)
    result = client.submit_from_proof_files(
        tx_type="mint",
        proof_path="target/proof/proof",
        public_inputs_path="target/proof/public_inputs",
        new_commitments=["0xabc...", ...],
        nullifiers=[],
        merkle_root="0x" + "00"*32,
        fee=0,
        asset_id="0x" + "00"*31 + "01",
    )

    # Block production (testnet)
    header = client.produce_block()
    block  = client.get_block(0)
"""

import json
import os
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


# ─────────────────────────────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────────────────────────────

class NodeError(Exception):
    """Base error for node RPC failures."""
    pass


class ConnectionError(NodeError):
    """Cannot reach the node."""
    pass


class RpcError(NodeError):
    """The node returned a JSON-RPC error."""
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.rpc_message = message
        self.data = data
        super().__init__(f"RPC error {code}: {message}")


# ─────────────────────────────────────────────────────────────────────
# Response Types
# ─────────────────────────────────────────────────────────────────────

@dataclass
class NodeStatus:
    block_height: int
    merkle_root: str
    leaf_count: int
    nullifier_count: int
    mempool_size: int


@dataclass
class MerkleProof:
    index: int
    index_bits: List[bool]
    siblings: List[str]


@dataclass
class SubmitTxResult:
    tx_hash: str
    accepted: bool


@dataclass
class TxStatus:
    status: str               # "pending" | "confirmed" | "unknown"
    block_number: Optional[int]
    confirmations: Optional[int]
    tx_type: Optional[str]


@dataclass
class BlockHeader:
    block_number: int
    parent_hash: List[int]
    state_root: str
    timestamp: int
    tx_count: int


# ─────────────────────────────────────────────────────────────────────
# Client
# ─────────────────────────────────────────────────────────────────────

class TonklClient:
    """JSON-RPC client for a running Tonkl node."""

    def __init__(
        self,
        url: str = "http://127.0.0.1:9100",
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        rpc_secret: Optional[str] = None,
    ):
        """
        Args:
            url: Node JSON-RPC endpoint (e.g., "http://127.0.0.1:9100")
            timeout: Request timeout in seconds per attempt
            max_retries: Max retries on transient connection failures
            retry_delay: Base delay between retries (doubles each attempt)
            rpc_secret: Optional secret for write and protected read RPCs. Defaults to TONKL_RPC_SECRET.
        """
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        if rpc_secret is None:
            rpc_secret = os.environ.get("TONKL_RPC_SECRET")
        self.rpc_secret = rpc_secret.strip() if rpc_secret and rpc_secret.strip() else None
        self._next_id = 1

    def ping(self) -> bool:
        """Quick health check — returns True if the node responds."""
        try:
            self.get_status()
            return True
        except NodeError:
            return False

    def is_connected(self) -> bool:
        """Alias for ping()."""
        return self.ping()

    def _call(self, method: str, params: Any = None) -> Any:
        """Make a JSON-RPC call and return the result."""
        request_id = self._next_id
        self._next_id += 1

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if params is not None else [],
            "id": request_id,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(f"Cannot connect to {self.url}: {e}") from e
        except Exception as e:
            raise NodeError(f"Request failed: {e}") from e

        if "error" in body and body["error"] is not None:
            err = body["error"]
            raise RpcError(
                code=err.get("code", -1),
                message=err.get("message", "unknown error"),
                data=err.get("data"),
            )

        return body.get("result")

    def _call_with_retry(self, method: str, params: Any = None) -> Any:
        """
        Call with automatic retry on transient ConnectionErrors.

        RpcErrors (the node responded but with an error) are NOT retried —
        those indicate a logical problem (bad proof, invalid params, etc.).
        """
        last_err = None
        delay = self.retry_delay
        for attempt in range(1, self.max_retries + 1):
            try:
                return self._call(method, params)
            except ConnectionError as e:
                last_err = e
                if attempt < self.max_retries:
                    time.sleep(delay)
                    delay *= 2  # exponential backoff
            except RpcError:
                raise  # don't retry application-level errors
        raise last_err  # type: ignore[misc]

    def _write_params(self, *params: Any) -> List[Any]:
        values = list(params)
        if self.rpc_secret:
            values.append(self.rpc_secret)
        return values

    def _read_params(self, *params: Any) -> List[Any]:
        values = list(params)
        if self.rpc_secret:
            values.append(self.rpc_secret)
        return values

    # ─────────────────────────────────────────────────────────────────
    # Query Methods
    # ─────────────────────────────────────────────────────────────────

    def get_status(self) -> NodeStatus:
        """Get the current node status."""
        r = self._call_with_retry("get_status")
        return NodeStatus(
            block_height=r["block_height"],
            merkle_root=r["merkle_root"],
            leaf_count=r["leaf_count"],
            nullifier_count=r["nullifier_count"],
            mempool_size=r["mempool_size"],
        )

    def get_merkle_root(self) -> str:
        """Get the current Merkle tree root as a hex string."""
        return self._call_with_retry("get_merkle_root")

    def get_merkle_proof(self, index: int) -> MerkleProof:
        """
        Get the Merkle authentication path for a leaf at the given index.

        Returns index_bits (LSB-first) and sibling hashes, ready for
        use as circuit witness inputs.
        """
        r = self._call_with_retry("get_merkle_proof", self._read_params(index))
        return MerkleProof(
            index=r["index"],
            index_bits=r["index_bits"],
            siblings=r["siblings"],
        )

    def get_nullifier_status(self, nullifier: str) -> bool:
        """
        Check if a nullifier has been spent.

        Args:
            nullifier: Hex-encoded nullifier (with or without 0x prefix)

        Returns:
            True if the nullifier is spent, False otherwise.
        """
        return self._call_with_retry("get_nullifier_status", self._read_params(nullifier))

    def get_tx_status(self, tx_hash: str) -> TxStatus:
        """
        Get the status of a transaction by its hash.

        Args:
            tx_hash: Hex-encoded transaction hash (with or without 0x prefix)

        Returns:
            TxStatus with status ("pending", "confirmed", or "unknown"),
            plus block_number, confirmations, and tx_type when confirmed.
        """
        r = self._call_with_retry("get_tx_status", [tx_hash])
        return TxStatus(
            status=r["status"],
            block_number=r.get("block_number"),
            confirmations=r.get("confirmations"),
            tx_type=r.get("tx_type"),
        )

    def get_block(self, block_number: int) -> Optional[Dict]:
        """
        Get a block by number.

        Returns the full block (header + transactions) as a dict,
        or None if the block doesn't exist.
        """
        return self._call_with_retry("get_block", self._read_params(block_number))

    # ─────────────────────────────────────────────────────────────────
    # Transaction Submission
    # ─────────────────────────────────────────────────────────────────

    def submit_tx(
        self,
        tx_type: str,
        proof: Union[bytes, str],
        public_inputs: Union[List[bytes], List[str]],
        new_commitments: List[str],
        nullifiers: List[str],
        merkle_root: str,
        fee: int = 0,
        asset_id: str = "0x0000000000000000000000000000000000000000000000000000000000000001",
    ) -> SubmitTxResult:
        """
        Submit a transaction to the node.

        Args:
            tx_type: One of "transfer", "merge", "split", "mint"
            proof: Raw proof bytes or hex string (with or without 0x)
            public_inputs: List of 32-byte field elements (bytes or hex strings)
            new_commitments: Hex-encoded note commitments
            nullifiers: Hex-encoded nullifiers (empty for mint)
            merkle_root: Hex-encoded merkle root the proof was computed against
            fee: Transaction fee
            asset_id: Hex-encoded asset ID

        Returns:
            SubmitTxResult with tx_hash and accepted status
        """
        # Normalize proof to hex string
        if isinstance(proof, bytes):
            proof_hex = "0x" + proof.hex()
        else:
            proof_hex = proof if proof.startswith("0x") else "0x" + proof

        # Normalize public inputs to hex strings
        pi_hex = []
        for pi in public_inputs:
            if isinstance(pi, bytes):
                pi_hex.append("0x" + pi.hex())
            else:
                pi_hex.append(pi if pi.startswith("0x") else "0x" + pi)

        request = {
            "tx_type": tx_type,
            "proof": proof_hex,
            "public_inputs": pi_hex,
            "new_commitments": new_commitments,
            "nullifiers": nullifiers,
            "merkle_root": merkle_root,
            "fee": fee,
            "asset_id": asset_id,
        }

        r = self._call("submit_tx", self._write_params(request))
        return SubmitTxResult(
            tx_hash=r["tx_hash"],
            accepted=r["accepted"],
        )

    def submit_from_proof_files(
        self,
        tx_type: str,
        proof_path: str,
        public_inputs_path: str,
        new_commitments: List[str],
        nullifiers: List[str],
        merkle_root: str,
        fee: int = 0,
        asset_id: str = "0x0000000000000000000000000000000000000000000000000000000000000001",
    ) -> SubmitTxResult:
        """
        Submit a transaction by reading proof artifacts from files.

        This reads the raw binary proof and public_inputs files produced
        by `bb prove` and submits them to the node.

        Args:
            proof_path: Path to the proof file (binary)
            public_inputs_path: Path to the public_inputs file (binary, 32-byte fields)
            (other args same as submit_tx)
        """
        proof_bytes = Path(proof_path).read_bytes()
        pi_bytes = Path(public_inputs_path).read_bytes()

        # Split public_inputs into 32-byte chunks
        if len(pi_bytes) % 32 != 0:
            raise ValueError(
                f"public_inputs file size ({len(pi_bytes)}) is not a multiple of 32"
            )

        public_inputs = []
        for i in range(0, len(pi_bytes), 32):
            chunk = pi_bytes[i:i+32]
            public_inputs.append(chunk)

        return self.submit_tx(
            tx_type=tx_type,
            proof=proof_bytes,
            public_inputs=public_inputs,
            new_commitments=new_commitments,
            nullifiers=nullifiers,
            merkle_root=merkle_root,
            fee=fee,
            asset_id=asset_id,
        )

    # ─────────────────────────────────────────────────────────────────
    # Block Production (Testnet)
    # ─────────────────────────────────────────────────────────────────

    def produce_block(self) -> BlockHeader:
        """
        Trigger block production (testnet only).

        Drains the mempool and produces a new block.
        """
        r = self._call("produce_block", self._write_params())
        return BlockHeader(
            block_number=r["block_number"],
            parent_hash=r["parent_hash"],
            state_root=r["state_root"],
            timestamp=r["timestamp"],
            tx_count=r["tx_count"],
        )

    # ─────────────────────────────────────────────────────────────────
    # Encrypted Note Store
    # ─────────────────────────────────────────────────────────────────

    def store_encrypted_notes(
        self,
        notes: List[dict],
    ) -> int:
        """
        Store encrypted note ciphertexts on the node.

        Args:
            notes: List of {"leaf_index": int, "ciphertext": hex_string}

        Returns:
            Number of notes stored.
        """
        request = {"notes": notes}
        r = self._call("store_encrypted_notes", self._write_params(request))
        return r["stored"]

    def get_encrypted_notes(
        self,
        from_index: int,
        count: int = 256,
    ) -> dict:
        """
        Retrieve encrypted note ciphertexts from the node.

        Args:
            from_index: Starting leaf index.
            count: Max number of leaves to scan (capped at 1024 by node).

        Returns:
            {"notes": [{"leaf_index": int, "ciphertext": hex}], "leaf_count": int}
        """
        r = self._call_with_retry("get_encrypted_notes", self._read_params(from_index, count))
        return {
            "notes": r["notes"],
            "leaf_count": r["leaf_count"],
        }

    # ─────────────────────────────────────────────────────────────────
    # Convenience Helpers
    # ─────────────────────────────────────────────────────────────────

    def is_connected(self) -> bool:
        """Check if the node is reachable."""
        try:
            self.get_status()
            return True
        except NodeError:
            return False

    def wait_for_node(self, timeout: float = 10.0, poll_interval: float = 0.5) -> bool:
        """
        Wait for the node to become reachable.

        Returns True if connected within timeout, False otherwise.
        """
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.is_connected():
                return True
            time.sleep(poll_interval)
        return False

    def wait_for_confirmation(
        self,
        tx_hash: str,
        timeout: float = 30.0,
        poll_interval: float = 0.5,
        min_confirmations: int = 1,
    ) -> TxStatus:
        """
        Poll until a transaction is confirmed with at least `min_confirmations`.

        Args:
            tx_hash: Hex-encoded transaction hash
            timeout: Maximum time to wait in seconds
            poll_interval: Time between polls in seconds
            min_confirmations: Minimum confirmations to wait for

        Returns:
            TxStatus once confirmed

        Raises:
            TimeoutError: If the transaction is not confirmed within timeout
        """
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.get_tx_status(tx_hash)
            if status.status == "confirmed" and (
                status.confirmations is not None
                and status.confirmations >= min_confirmations
            ):
                return status
            time.sleep(poll_interval)
        raise TimeoutError(
            f"Transaction {tx_hash} not confirmed within {timeout}s"
        )

    def submit_and_produce(
        self,
        tx_type: str,
        proof_path: str,
        public_inputs_path: str,
        new_commitments: List[str],
        nullifiers: List[str],
        merkle_root: str = "0x" + "00" * 32,
        fee: int = 0,
        asset_id: str = "0x0000000000000000000000000000000000000000000000000000000000000001",
    ) -> dict:
        """
        Submit a transaction and immediately produce a block (testnet convenience).

        Returns a dict with tx_hash, block_number, and new state_root.
        """
        tx = self.submit_from_proof_files(
            tx_type=tx_type,
            proof_path=proof_path,
            public_inputs_path=public_inputs_path,
            new_commitments=new_commitments,
            nullifiers=nullifiers,
            merkle_root=merkle_root,
            fee=fee,
            asset_id=asset_id,
        )
        block = self.produce_block()
        return {
            "tx_hash": tx.tx_hash,
            "accepted": tx.accepted,
            "block_number": block.block_number,
            "state_root": block.state_root,
            "tx_count": block.tx_count,
        }


# ─────────────────────────────────────────────────────────────────────
# CLI: Quick node interaction from the command line
# ─────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Tonkl Node CLI Client")
    parser.add_argument("--url", default="http://127.0.0.1:9100", help="Node RPC URL")

    sub = parser.add_subparsers(dest="command", required=True)

    # status
    sub.add_parser("status", help="Show node status")

    # root
    sub.add_parser("root", help="Show current Merkle root")

    # proof
    p_proof = sub.add_parser("proof", help="Get Merkle proof for a leaf")
    p_proof.add_argument("index", type=int, help="Leaf index")

    # nullifier
    p_nf = sub.add_parser("nullifier", help="Check if nullifier is spent")
    p_nf.add_argument("hash", help="Nullifier hex (with or without 0x)")

    # tx-status
    p_tx = sub.add_parser("tx-status", help="Check transaction status")
    p_tx.add_argument("hash", help="Transaction hash (with or without 0x)")
    p_tx.add_argument("--wait", action="store_true", help="Poll until confirmed")
    p_tx.add_argument("--timeout", type=float, default=30.0, help="Wait timeout in seconds")

    # submit
    p_submit = sub.add_parser("submit", help="Submit a transaction from proof files")
    p_submit.add_argument("tx_type", choices=["transfer", "merge", "split", "mint"])
    p_submit.add_argument("proof_dir", help="Directory containing proof and public_inputs")
    p_submit.add_argument("--commitments", nargs="+", required=True, help="New commitment hex values")
    p_submit.add_argument("--nullifiers", nargs="*", default=[], help="Nullifier hex values")
    p_submit.add_argument("--merkle-root", default="0x" + "00" * 32)
    p_submit.add_argument("--fee", type=int, default=0)
    p_submit.add_argument("--asset-id", default="0x" + "00" * 31 + "01")

    # block
    sub.add_parser("produce", help="Produce a block (testnet)")

    # get-block
    p_block = sub.add_parser("block", help="Get a block by number")
    p_block.add_argument("number", type=int)

    args = parser.parse_args()
    client = TonklClient(args.url)

    if args.command == "status":
        s = client.get_status()
        print(f"Block height:    {s.block_height}")
        print(f"Merkle root:     {s.merkle_root}")
        print(f"Leaves:          {s.leaf_count}")
        print(f"Nullifiers:      {s.nullifier_count}")
        print(f"Mempool:         {s.mempool_size}")

    elif args.command == "root":
        print(client.get_merkle_root())

    elif args.command == "proof":
        p = client.get_merkle_proof(args.index)
        print(f"Index: {p.index}")
        print(f"Bits:  {p.index_bits[:8]}... ({sum(p.index_bits)} set)")
        for i, s in enumerate(p.siblings[:4]):
            print(f"  Level {i}: {s}")
        if len(p.siblings) > 4:
            print(f"  ... ({len(p.siblings) - 4} more levels)")

    elif args.command == "nullifier":
        spent = client.get_nullifier_status(args.hash)
        print(f"{'SPENT' if spent else 'UNSPENT'}: {args.hash}")

    elif args.command == "tx-status":
        if args.wait:
            try:
                s = client.wait_for_confirmation(args.hash, timeout=args.timeout)
            except TimeoutError as e:
                print(f"TIMEOUT: {e}")
                return
        else:
            s = client.get_tx_status(args.hash)
        print(f"Status:        {s.status}")
        if s.block_number is not None:
            print(f"Block:         {s.block_number}")
        if s.confirmations is not None:
            print(f"Confirmations: {s.confirmations}")
        if s.tx_type is not None:
            print(f"Type:          {s.tx_type}")

    elif args.command == "submit":
        proof_dir = Path(args.proof_dir)
        result = client.submit_from_proof_files(
            tx_type=args.tx_type,
            proof_path=str(proof_dir / "proof"),
            public_inputs_path=str(proof_dir / "public_inputs"),
            new_commitments=args.commitments,
            nullifiers=args.nullifiers,
            merkle_root=args.merkle_root,
            fee=args.fee,
            asset_id=args.asset_id,
        )
        print(f"Accepted: {result.accepted}")
        print(f"TX hash:  {result.tx_hash}")

    elif args.command == "produce":
        h = client.produce_block()
        print(f"Block #{h.block_number}")
        print(f"  State root: {h.state_root}")
        print(f"  TX count:   {h.tx_count}")
        print(f"  Timestamp:  {h.timestamp}")

    elif args.command == "block":
        b = client.get_block(args.number)
        if b is None:
            print(f"Block {args.number} not found")
        else:
            h = b["header"]
            print(f"Block #{h['block_number']}")
            print(f"  State root: {h['state_root']}")
            print(f"  TX count:   {h['tx_count']}")
            print(f"  Timestamp:  {h['timestamp']}")
            for i, tx in enumerate(b.get("transactions", [])):
                print(f"  TX {i}: type={tx['tx_type']} hash=0x{bytes(tx['tx_hash']).hex()[:16]}...")


if __name__ == "__main__":
    main()
