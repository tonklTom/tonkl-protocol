#!/usr/bin/env python3
"""
Tonkl Protocol -- P2P Networking Layer

A Python P2P sidecar that runs alongside each Rust node, providing:
  - TCP peer connections with length-prefixed JSON framing
  - Block and transaction gossip between nodes
  - Static peer list discovery
  - Deduplication of already-seen messages

Architecture:
  Each Tonkl node runs a Rust JSON-RPC server + this P2P sidecar.
  The sidecar:
    1. Listens for inbound TCP connections from other P2P sidecars
    2. Connects outbound to configured peers
    3. When it receives a new TX via gossip → forwards to its local Rust node via RPC
    4. Polls its local node for new blocks → broadcasts to peers
    5. When it receives a new block via gossip → forwards to its local Rust node

Wire protocol:
  Each message is: [4-byte big-endian length] [JSON payload]
  JSON payload: {"type": "...", "data": {...}}

Message types:
  handshake    → Identify peer (node_id, chain_id, block_height)
  new_block    → Broadcast a newly produced block
  new_tx       → Broadcast a new transaction (from mempool)
  get_blocks   → Request blocks by number range
  blocks       → Response with requested blocks
  ping / pong  → Keepalive

Usage:
  from p2p import P2PNode

  node = P2PNode(
      node_id="node-0",
      rpc_url="http://127.0.0.1:9100",
      p2p_port=9150,
      peers=["127.0.0.1:9151", "127.0.0.1:9152"],
  )
  await node.start()
  # ... node runs until stopped ...
  await node.stop()
"""

import asyncio
import json
import hashlib
import struct
import time
import traceback
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from node_client import TonklClient, ConnectionError as NodeConnectionError, RpcError


# ─────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────

PROTOCOL_VERSION = 2
CHAIN_ID = "tonkl-testnet-1"
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB
HANDSHAKE_TIMEOUT = 10.0
PING_INTERVAL = 30.0
RECONNECT_DELAY = 5.0
POLL_INTERVAL = 2.0  # How often to poll local node for new blocks
PEER_EXCHANGE_INTERVAL = 60.0  # How often to exchange peer lists
MAX_PEERS = 25  # Maximum simultaneous connections
MIN_PEERS = 3   # Minimum desired peers (triggers discovery)
GOSSIP_TTL = 5  # Max hops for gossip relay
GOSSIP_FANOUT = 3  # Max peers to relay to (epidemic spread)
BAN_THRESHOLD = -100  # Score below which peers are banned
BAN_DURATION = 300.0  # Seconds to ban a misbehaving peer
SYNC_BATCH_SIZE = 50  # Blocks per sync request
INV_BATCH_SIZE = 100  # Max inventory items per message


# ─────────────────────────────────────────────────────────────────────
# Message Types
# ─────────────────────────────────────────────────────────────────────

class MsgType(str, Enum):
    HANDSHAKE = "handshake"
    NEW_BLOCK = "new_block"
    NEW_TX = "new_tx"
    GET_BLOCKS = "get_blocks"
    BLOCKS = "blocks"
    PING = "ping"
    PONG = "pong"
    # v2: Peer discovery
    GET_PEERS = "get_peers"
    PEERS = "peers"
    # v2: Inventory-based mempool sync
    INV = "inv"           # Advertise hashes we have
    GET_DATA = "get_data"  # Request data for hashes
    # v2: Chain sync
    GET_HEADERS = "get_headers"
    HEADERS = "headers"


@dataclass
class Message:
    """A P2P protocol message."""
    type: str
    data: Dict[str, Any] = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        """Serialize to length-prefixed JSON."""
        payload = json.dumps({"type": self.type, "data": self.data}).encode("utf-8")
        return struct.pack(">I", len(payload)) + payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        """Deserialize from JSON payload (without length prefix)."""
        obj = json.loads(data.decode("utf-8"))
        return cls(type=obj["type"], data=obj.get("data", {}))


def msg_hash(msg: Message) -> str:
    """Compute a short hash for deduplication."""
    raw = json.dumps({"type": msg.type, "data": msg.data}, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────
# Peer Scoring
# ─────────────────────────────────────────────────────────────────────

class PeerScore:
    """
    Tracks peer reputation based on behavior.

    Good actions (valid blocks, valid TXs, timely pongs) increase score.
    Bad actions (invalid messages, protocol violations, timeouts) decrease it.
    Peers below BAN_THRESHOLD are temporarily banned.
    """

    def __init__(self):
        self.score: float = 0.0
        self.blocks_provided: int = 0
        self.txs_provided: int = 0
        self.invalid_messages: int = 0
        self.protocol_violations: int = 0
        self.latency_samples: List[float] = []
        self.banned_until: float = 0.0

    def good_block(self) -> None:
        self.score += 10.0
        self.blocks_provided += 1

    def good_tx(self) -> None:
        self.score += 1.0
        self.txs_provided += 1

    def good_pong(self, latency: float) -> None:
        self.score += 0.5
        self.latency_samples.append(latency)
        if len(self.latency_samples) > 50:
            self.latency_samples = self.latency_samples[-50:]

    def bad_message(self) -> None:
        self.score -= 10.0
        self.invalid_messages += 1

    def protocol_violation(self) -> None:
        self.score -= 50.0
        self.protocol_violations += 1

    def timeout(self) -> None:
        self.score -= 5.0

    @property
    def is_banned(self) -> bool:
        if self.banned_until > 0 and time.time() < self.banned_until:
            return True
        return self.score < BAN_THRESHOLD

    def ban(self) -> None:
        self.banned_until = time.time() + BAN_DURATION

    @property
    def avg_latency(self) -> float:
        if not self.latency_samples:
            return 0.0
        return sum(self.latency_samples) / len(self.latency_samples)

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "blocks_provided": self.blocks_provided,
            "txs_provided": self.txs_provided,
            "invalid_messages": self.invalid_messages,
            "avg_latency_ms": round(self.avg_latency * 1000, 1),
            "is_banned": self.is_banned,
        }


# ─────────────────────────────────────────────────────────────────────
# Peer Connection
# ─────────────────────────────────────────────────────────────────────

class PeerConnection:
    """
    Manages a single TCP connection to a peer.

    Handles framing (length-prefixed JSON), sending, and receiving.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_addr: str,
        inbound: bool = False,
    ):
        self.reader = reader
        self.writer = writer
        self.peer_addr = peer_addr
        self.inbound = inbound
        self.node_id: Optional[str] = None
        self.block_height: int = 0
        self.protocol_version: int = 1
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.last_ping_sent: float = 0.0
        self.score = PeerScore()
        self._closed = False

    async def send(self, msg: Message) -> None:
        """Send a message to this peer."""
        if self._closed:
            return
        try:
            data = msg.to_bytes()
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionError, OSError):
            self._closed = True

    async def recv(self) -> Optional[Message]:
        """Receive the next message from this peer. Returns None on disconnect."""
        try:
            # Read 4-byte length prefix
            length_data = await self.reader.readexactly(4)
            length = struct.unpack(">I", length_data)[0]

            if length > MAX_MESSAGE_SIZE:
                return None  # Reject oversized messages

            # Read payload
            payload = await self.reader.readexactly(length)
            self.last_seen = time.time()
            return Message.from_bytes(payload)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            self._closed = True
            return None

    def close(self) -> None:
        """Close the connection."""
        if not self._closed:
            self._closed = True
            try:
                self.writer.close()
            except Exception:
                pass

    @property
    def is_alive(self) -> bool:
        return not self._closed


# ─────────────────────────────────────────────────────────────────────
# P2P Node
# ─────────────────────────────────────────────────────────────────────

class P2PNode:
    """
    P2P networking sidecar for an Tonkl node.

    Runs alongside the Rust JSON-RPC node, providing gossip-based
    propagation of blocks and transactions between peers.
    """

    def __init__(
        self,
        node_id: str,
        rpc_url: str = "http://127.0.0.1:9100",
        p2p_port: int = 9150,
        peers: Optional[List[str]] = None,
        verbose: bool = True,
    ):
        self.node_id = node_id
        self.rpc_url = rpc_url
        self.p2p_port = p2p_port
        self.seed_peers = peers or []
        self.verbose = verbose

        self.client = TonklClient(rpc_url, timeout=10.0)
        self.connections: Dict[str, PeerConnection] = {}
        self.seen_messages: Set[str] = set()
        self._seen_max = 10_000  # Max seen hashes to keep

        self._server: Optional[asyncio.Server] = None
        self._tasks: List[asyncio.Task] = []
        self._running = False
        self._last_block_height = -1
        self._last_mempool_hashes: Set[str] = set()

        # v2: Peer discovery
        self.known_peers: Set[str] = set(self.seed_peers)  # All known peer addresses
        self.banned_peers: Dict[str, float] = {}  # addr → banned_until timestamp

        # v2: Inventory tracking
        self._tx_inventory: Dict[str, dict] = {}  # tx_hash → tx_data (recent TXs we have)
        self._inv_max = 1000

        # v2: Chain sync state
        self._syncing = False
        self._sync_target: Optional[str] = None  # node_id we're syncing from

        # Stats
        self.stats = {
            "blocks_relayed": 0,
            "txs_relayed": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "peers_connected": 0,
            "peers_discovered": 0,
            "peers_banned": 0,
            "inv_sent": 0,
            "inv_received": 0,
            "sync_blocks_downloaded": 0,
        }

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"  [p2p:{self.node_id}] {msg}")

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the P2P node: listen for connections and connect to peers."""
        self._running = True

        # Start TCP server
        self._server = await asyncio.start_server(
            self._handle_inbound,
            "127.0.0.1",
            self.p2p_port,
        )
        self._log(f"Listening on 127.0.0.1:{self.p2p_port}")

        # Connect to seed peers
        for peer_addr in self.seed_peers:
            task = asyncio.create_task(self._connect_outbound(peer_addr))
            self._tasks.append(task)

        # Start block poller
        self._tasks.append(asyncio.create_task(self._poll_local_node()))

        # Start ping loop
        self._tasks.append(asyncio.create_task(self._ping_loop()))

        # v2: Start peer exchange loop
        self._tasks.append(asyncio.create_task(self._peer_exchange_loop()))

        # v2: Start initial chain sync
        self._tasks.append(asyncio.create_task(self._initial_sync()))

    async def stop(self) -> None:
        """Stop the P2P node and close all connections."""
        self._running = False

        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()

        # Close server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Close all peer connections
        for conn in list(self.connections.values()):
            conn.close()
        self.connections.clear()

        self._log("Stopped")

    # ── Connection handling ──────────────────────────────────────────

    async def _handle_inbound(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a new inbound TCP connection."""
        addr = writer.get_extra_info("peername")
        peer_addr = f"{addr[0]}:{addr[1]}" if addr else "unknown"
        conn = PeerConnection(reader, writer, peer_addr, inbound=True)

        try:
            # Wait for handshake
            msg = await asyncio.wait_for(conn.recv(), timeout=HANDSHAKE_TIMEOUT)
            if msg is None or msg.type != MsgType.HANDSHAKE:
                conn.close()
                return

            conn.node_id = msg.data.get("node_id", peer_addr)
            conn.block_height = msg.data.get("block_height", 0)
            conn.protocol_version = msg.data.get("protocol_version", 1)

            # Verify chain_id
            if msg.data.get("chain_id") != CHAIN_ID:
                self._log(f"Rejected {conn.node_id}: wrong chain_id")
                conn.score.protocol_violation()
                conn.close()
                return

            # Check connection limits
            if len(self.connections) >= MAX_PEERS:
                self._log(f"Rejected {conn.node_id}: max peers reached ({MAX_PEERS})")
                conn.close()
                return

            # Check ban list
            if self._is_banned(peer_addr):
                self._log(f"Rejected {conn.node_id}: banned")
                conn.close()
                return

            # Send our handshake back
            status = self._get_local_height()
            await conn.send(Message(
                type=MsgType.HANDSHAKE,
                data={
                    "node_id": self.node_id,
                    "chain_id": CHAIN_ID,
                    "protocol_version": PROTOCOL_VERSION,
                    "block_height": status,
                    "peer_count": len(self.connections),
                },
            ))

            self.connections[conn.node_id] = conn
            self.stats["peers_connected"] = len(self.connections)
            self._log(f"Inbound peer connected: {conn.node_id} (v{conn.protocol_version})")

            # Message loop
            await self._message_loop(conn)

        except asyncio.TimeoutError:
            self._log(f"Handshake timeout from {peer_addr}")
        except Exception as e:
            self._log(f"Inbound error from {peer_addr}: {e}")
        finally:
            conn.close()
            self.connections.pop(conn.node_id or peer_addr, None)
            self.stats["peers_connected"] = len(self.connections)

    async def _connect_outbound(self, peer_addr: str) -> None:
        """Connect to an outbound peer with reconnection."""
        while self._running:
            # Check ban list before connecting
            if self._is_banned(peer_addr):
                await asyncio.sleep(RECONNECT_DELAY * 10)
                continue

            # Check connection limit
            if len(self.connections) >= MAX_PEERS:
                await asyncio.sleep(RECONNECT_DELAY * 2)
                continue

            try:
                host, port = peer_addr.rsplit(":", 1)
                reader, writer = await asyncio.open_connection(host, int(port))
                conn = PeerConnection(reader, writer, peer_addr, inbound=False)

                # Send handshake
                status = self._get_local_height()
                await conn.send(Message(
                    type=MsgType.HANDSHAKE,
                    data={
                        "node_id": self.node_id,
                        "chain_id": CHAIN_ID,
                        "protocol_version": PROTOCOL_VERSION,
                        "block_height": status,
                        "peer_count": len(self.connections),
                    },
                ))

                # Wait for handshake response
                msg = await asyncio.wait_for(conn.recv(), timeout=HANDSHAKE_TIMEOUT)
                if msg is None or msg.type != MsgType.HANDSHAKE:
                    conn.close()
                    await asyncio.sleep(RECONNECT_DELAY)
                    continue

                conn.node_id = msg.data.get("node_id", peer_addr)
                conn.block_height = msg.data.get("block_height", 0)
                conn.protocol_version = msg.data.get("protocol_version", 1)

                self.connections[conn.node_id] = conn
                self.stats["peers_connected"] = len(self.connections)
                self._log(f"Outbound peer connected: {conn.node_id} (v{conn.protocol_version})")

                # Message loop (blocks until disconnect)
                await self._message_loop(conn)

            except (ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
                pass  # Will retry after delay
            except asyncio.CancelledError:
                return
            except Exception as e:
                self._log(f"Outbound error to {peer_addr}: {e}")
            finally:
                # Clean up and retry
                for nid, c in list(self.connections.items()):
                    if c.peer_addr == peer_addr:
                        c.close()
                        self.connections.pop(nid, None)
                self.stats["peers_connected"] = len(self.connections)

            if self._running:
                await asyncio.sleep(RECONNECT_DELAY)

    # ── Message handling ─────────────────────────────────────────────

    async def _message_loop(self, conn: PeerConnection) -> None:
        """Process messages from a peer until disconnect."""
        while self._running and conn.is_alive:
            msg = await conn.recv()
            if msg is None:
                break

            self.stats["messages_received"] += 1

            # Check if peer is banned mid-session
            if conn.score.is_banned:
                self._ban_peer(conn.peer_addr)
                self._log(f"Disconnecting banned peer: {conn.node_id}")
                break

            if msg.type == MsgType.PING:
                await conn.send(Message(type=MsgType.PONG))

            elif msg.type == MsgType.PONG:
                # Calculate latency from last ping
                if conn.last_ping_sent > 0:
                    latency = time.time() - conn.last_ping_sent
                    conn.score.good_pong(latency)

            elif msg.type == MsgType.NEW_BLOCK:
                await self._handle_new_block(msg, conn)

            elif msg.type == MsgType.NEW_TX:
                await self._handle_new_tx(msg, conn)

            elif msg.type == MsgType.GET_BLOCKS:
                await self._handle_get_blocks(msg, conn)

            elif msg.type == MsgType.BLOCKS:
                await self._handle_blocks(msg, conn)

            # v2: Peer discovery
            elif msg.type == MsgType.GET_PEERS:
                await self._handle_get_peers(msg, conn)

            elif msg.type == MsgType.PEERS:
                await self._handle_peers(msg, conn)

            # v2: Inventory-based mempool sync
            elif msg.type == MsgType.INV:
                await self._handle_inv(msg, conn)

            elif msg.type == MsgType.GET_DATA:
                await self._handle_get_data(msg, conn)

            # v2: Chain sync headers
            elif msg.type == MsgType.GET_HEADERS:
                await self._handle_get_headers(msg, conn)

            elif msg.type == MsgType.HEADERS:
                await self._handle_headers(msg, conn)

            else:
                conn.score.bad_message()

    async def _handle_new_block(self, msg: Message, source: PeerConnection) -> None:
        """Handle a new block received from a peer."""
        h = msg_hash(msg)
        if h in self.seen_messages:
            return
        self._mark_seen(h)

        block_data = msg.data.get("block")
        if not block_data:
            source.score.bad_message()
            return

        # Check TTL
        ttl = msg.data.get("ttl", GOSSIP_TTL)
        if ttl <= 0:
            return  # Message has expired

        block_num = block_data.get("header", {}).get("block_number", "?")
        self._log(f"Received block #{block_num} from {source.node_id}")

        # Forward block's transactions to our local node
        # The local node will validate proofs and apply state changes
        txs = block_data.get("transactions", [])
        for tx in txs:
            try:
                self.client.submit_tx(
                    tx_type=tx.get("tx_type", "transfer"),
                    proof=tx.get("proof", "0x"),
                    public_inputs=tx.get("public_inputs", []),
                    new_commitments=tx.get("new_commitments", []),
                    nullifiers=tx.get("nullifiers", []),
                    merkle_root=tx.get("merkle_root", "0x" + "00" * 32),
                    fee=tx.get("fee", 0),
                    asset_id=tx.get("asset_id", "0x" + "00" * 31 + "01"),
                )
            except (RpcError, NodeConnectionError):
                pass

        # Produce a block on our local node to match
        try:
            self.client.produce_block()
        except Exception:
            pass

        source.score.good_block()
        self.stats["blocks_relayed"] += 1

        # Fanout relay with decremented TTL
        relay_msg = Message(
            type=MsgType.NEW_BLOCK,
            data={**msg.data, "ttl": ttl - 1},
        )
        await self._gossip_relay(relay_msg, exclude=source.node_id)

    async def _handle_new_tx(self, msg: Message, source: PeerConnection) -> None:
        """Handle a new transaction received from a peer."""
        h = msg_hash(msg)
        if h in self.seen_messages:
            return
        self._mark_seen(h)

        tx_data = msg.data.get("tx")
        if not tx_data:
            source.score.bad_message()
            return

        # Check TTL
        ttl = msg.data.get("ttl", GOSSIP_TTL)
        if ttl <= 0:
            return

        tx_hash = tx_data.get("tx_hash", "?")[:16]
        self._log(f"Received TX {tx_hash}... from {source.node_id}")

        # Submit to our local node
        try:
            self.client.submit_tx(
                tx_type=tx_data.get("tx_type", "transfer"),
                proof=tx_data.get("proof", "0x"),
                public_inputs=tx_data.get("public_inputs", []),
                new_commitments=tx_data.get("new_commitments", []),
                nullifiers=tx_data.get("nullifiers", []),
                merkle_root=tx_data.get("merkle_root", "0x" + "00" * 32),
                fee=tx_data.get("fee", 0),
                asset_id=tx_data.get("asset_id", "0x" + "00" * 31 + "01"),
            )
        except (RpcError, NodeConnectionError):
            pass

        # Track in local inventory
        full_hash = tx_data.get("tx_hash", h)
        self._add_to_inventory(full_hash, tx_data)

        source.score.good_tx()
        self.stats["txs_relayed"] += 1

        # Fanout relay with decremented TTL
        relay_msg = Message(
            type=MsgType.NEW_TX,
            data={**msg.data, "ttl": ttl - 1},
        )
        await self._gossip_relay(relay_msg, exclude=source.node_id)

    async def _handle_get_blocks(self, msg: Message, conn: PeerConnection) -> None:
        """Handle a request for blocks by range."""
        from_num = msg.data.get("from", 0)
        to_num = msg.data.get("to", from_num + 10)

        blocks = []
        for num in range(from_num, to_num + 1):
            try:
                block = self.client.get_block(num)
                if block:
                    blocks.append(block)
            except Exception:
                break

        await conn.send(Message(
            type=MsgType.BLOCKS,
            data={"blocks": blocks},
        ))

    async def _handle_blocks(self, msg: Message, conn: PeerConnection) -> None:
        """Handle a blocks response (for syncing)."""
        blocks = msg.data.get("blocks", [])
        for block in blocks:
            # Apply each block
            block_msg = Message(type=MsgType.NEW_BLOCK, data={"block": block})
            await self._handle_new_block(block_msg, conn)

    # ── v2: Peer discovery handlers ─────────────────────────────────

    async def _handle_get_peers(self, msg: Message, conn: PeerConnection) -> None:
        """Respond to a peer list request."""
        # Share known peers (excluding the requester and banned peers)
        peers_to_share = []
        for addr in self.known_peers:
            if addr != conn.peer_addr and not self._is_banned(addr):
                peers_to_share.append(addr)
            if len(peers_to_share) >= 20:
                break

        # Also share currently connected peers' addresses
        for c in self.connections.values():
            if c.peer_addr != conn.peer_addr and c.is_alive:
                if c.peer_addr not in peers_to_share:
                    peers_to_share.append(c.peer_addr)

        await conn.send(Message(
            type=MsgType.PEERS,
            data={"peers": peers_to_share[:20]},
        ))

    async def _handle_peers(self, msg: Message, conn: PeerConnection) -> None:
        """Process a peer list response — discover new peers."""
        new_peers = msg.data.get("peers", [])
        discovered = 0
        for addr in new_peers:
            if not isinstance(addr, str) or ":" not in addr:
                continue
            if addr not in self.known_peers and not self._is_banned(addr):
                self.known_peers.add(addr)
                discovered += 1

        if discovered > 0:
            self.stats["peers_discovered"] += discovered
            self._log(f"Discovered {discovered} new peer(s) from {conn.node_id}")

            # If we need more connections, try connecting to new peers
            if len(self.connections) < MIN_PEERS:
                for addr in new_peers:
                    if addr not in [c.peer_addr for c in self.connections.values()]:
                        task = asyncio.create_task(self._connect_outbound(addr))
                        self._tasks.append(task)
                        break  # Connect one at a time

    # ── v2: Inventory-based mempool sync ─────────────────────────────

    async def _handle_inv(self, msg: Message, conn: PeerConnection) -> None:
        """Handle inventory announcement — request any items we don't have."""
        items = msg.data.get("items", [])
        self.stats["inv_received"] += 1

        # Find items we don't have
        want = []
        for item in items[:INV_BATCH_SIZE]:
            item_type = item.get("type", "tx")
            item_hash = item.get("hash", "")
            if item_type == "tx" and item_hash not in self._tx_inventory:
                want.append(item)

        if want:
            await conn.send(Message(
                type=MsgType.GET_DATA,
                data={"items": want},
            ))

    async def _handle_get_data(self, msg: Message, conn: PeerConnection) -> None:
        """Handle data request — send back requested items."""
        items = msg.data.get("items", [])

        for item in items[:INV_BATCH_SIZE]:
            item_type = item.get("type", "tx")
            item_hash = item.get("hash", "")

            if item_type == "tx" and item_hash in self._tx_inventory:
                tx_data = self._tx_inventory[item_hash]
                await conn.send(Message(
                    type=MsgType.NEW_TX,
                    data={"tx": tx_data, "ttl": GOSSIP_TTL},
                ))

    # ── v2: Chain sync headers ───────────────────────────────────────

    async def _handle_get_headers(self, msg: Message, conn: PeerConnection) -> None:
        """Respond to header request for chain sync."""
        from_height = msg.data.get("from_height", 0)
        count = min(msg.data.get("count", SYNC_BATCH_SIZE), SYNC_BATCH_SIZE)

        headers = []
        for num in range(from_height, from_height + count):
            try:
                block = self.client.get_block(num)
                if block and isinstance(block, dict):
                    header = block.get("header", block)
                    headers.append({
                        "block_number": header.get("block_number", num),
                        "merkle_root": header.get("merkle_root", ""),
                        "tx_count": len(block.get("transactions", [])),
                    })
                else:
                    break
            except Exception:
                break

        await conn.send(Message(
            type=MsgType.HEADERS,
            data={"headers": headers, "from_height": from_height},
        ))

    async def _handle_headers(self, msg: Message, conn: PeerConnection) -> None:
        """Process header response during chain sync."""
        headers = msg.data.get("headers", [])
        if not headers:
            self._syncing = False
            return

        # Request full blocks for headers we're missing
        our_height = self._get_local_height()
        need_blocks = [
            h["block_number"] for h in headers
            if h.get("block_number", 0) > our_height
        ]

        if need_blocks:
            from_num = min(need_blocks)
            to_num = max(need_blocks)
            await conn.send(Message(
                type=MsgType.GET_BLOCKS,
                data={"from": from_num, "to": to_num},
            ))
            self.stats["sync_blocks_downloaded"] += len(need_blocks)

    # ── Broadcasting ─────────────────────────────────────────────────

    async def _broadcast(self, msg: Message, exclude: Optional[str] = None) -> None:
        """Send a message to all connected peers except `exclude`."""
        for node_id, conn in list(self.connections.items()):
            if node_id == exclude:
                continue
            if conn.is_alive:
                await conn.send(msg)
                self.stats["messages_sent"] += 1

    async def broadcast_tx(self, tx_data: dict) -> None:
        """Broadcast a transaction to all peers (called by RPC hook)."""
        msg = Message(type=MsgType.NEW_TX, data={"tx": tx_data})
        self._mark_seen(msg_hash(msg))
        await self._broadcast(msg)

    async def broadcast_block(self, block_data: dict) -> None:
        """Broadcast a block to all peers (called after local production)."""
        msg = Message(type=MsgType.NEW_BLOCK, data={"block": block_data})
        self._mark_seen(msg_hash(msg))
        await self._broadcast(msg)

    # ── v2: Gossip relay (fanout-limited) ──────────────────────────

    async def _gossip_relay(self, msg: Message, exclude: Optional[str] = None) -> None:
        """
        Relay a message to a limited subset of peers (epidemic gossip).

        Instead of broadcasting to all peers, select up to GOSSIP_FANOUT
        peers for relay. This reduces bandwidth while maintaining propagation.
        Peers are selected by score (best peers first).
        """
        candidates = [
            (nid, conn) for nid, conn in self.connections.items()
            if nid != exclude and conn.is_alive and not conn.score.is_banned
        ]

        # Sort by score (highest first) and take top GOSSIP_FANOUT
        candidates.sort(key=lambda x: x[1].score.score, reverse=True)
        targets = candidates[:GOSSIP_FANOUT]

        for node_id, conn in targets:
            await conn.send(msg)
            self.stats["messages_sent"] += 1

    # ── v2: Peer exchange loop ──────────────────────────────────────

    async def _peer_exchange_loop(self) -> None:
        """Periodically request peer lists from connected peers."""
        # Wait a bit before first exchange
        await asyncio.sleep(PEER_EXCHANGE_INTERVAL / 2)

        while self._running:
            try:
                # Request peers from a random connected peer
                alive = [c for c in self.connections.values() if c.is_alive]
                if alive:
                    # Pick the peer we've known longest (most likely to have good peer list)
                    target = min(alive, key=lambda c: c.connected_at)
                    await target.send(Message(type=MsgType.GET_PEERS, data={}))

                # If we're below minimum peers, try connecting to known peers
                if len(self.connections) < MIN_PEERS:
                    connected_addrs = {c.peer_addr for c in self.connections.values()}
                    for addr in self.known_peers:
                        if addr not in connected_addrs and not self._is_banned(addr):
                            task = asyncio.create_task(self._connect_outbound(addr))
                            self._tasks.append(task)
                            break  # One at a time

                # Clean up expired bans
                now = time.time()
                expired = [addr for addr, until in self.banned_peers.items() if until <= now]
                for addr in expired:
                    del self.banned_peers[addr]

                await asyncio.sleep(PEER_EXCHANGE_INTERVAL)

            except asyncio.CancelledError:
                return
            except Exception:
                await asyncio.sleep(PEER_EXCHANGE_INTERVAL)

    # ── v2: Initial chain sync ──────────────────────────────────────

    async def _initial_sync(self) -> None:
        """
        On startup, sync to the highest chain tip among connected peers.

        Waits for at least one peer to connect, then requests headers
        from the peer with the highest block height.
        """
        # Wait for at least one connection
        for _ in range(30):  # Wait up to 30 seconds
            if self.connections:
                break
            await asyncio.sleep(1.0)

        if not self.connections:
            return

        our_height = self._get_local_height()

        # Find the peer with highest block height
        best_peer = None
        best_height = our_height
        for conn in self.connections.values():
            if conn.is_alive and conn.block_height > best_height:
                best_peer = conn
                best_height = conn.block_height

        if best_peer is None or best_height <= our_height:
            self._log("Chain is up to date with peers")
            return

        self._syncing = True
        self._sync_target = best_peer.node_id
        blocks_behind = best_height - our_height
        self._log(f"Chain sync: {blocks_behind} blocks behind {best_peer.node_id}")

        # Request headers starting from our height
        await best_peer.send(Message(
            type=MsgType.GET_HEADERS,
            data={
                "from_height": our_height + 1,
                "count": min(blocks_behind, SYNC_BATCH_SIZE),
            },
        ))

    # ── v2: Inventory management ────────────────────────────────────

    def _add_to_inventory(self, tx_hash: str, tx_data: dict) -> None:
        """Track a transaction in local inventory for serving to peers."""
        self._tx_inventory[tx_hash] = tx_data
        if len(self._tx_inventory) > self._inv_max:
            # Remove oldest entries
            keys = list(self._tx_inventory.keys())
            for k in keys[:self._inv_max // 2]:
                del self._tx_inventory[k]

    async def announce_inventory(self) -> None:
        """Announce our transaction inventory to all peers."""
        if not self._tx_inventory:
            return

        items = [
            {"type": "tx", "hash": h}
            for h in list(self._tx_inventory.keys())[:INV_BATCH_SIZE]
        ]

        msg = Message(type=MsgType.INV, data={"items": items})
        await self._broadcast(msg)
        self.stats["inv_sent"] += 1

    # ── v2: Ban management ──────────────────────────────────────────

    def _is_banned(self, addr: str) -> bool:
        """Check if a peer address is currently banned."""
        until = self.banned_peers.get(addr, 0)
        if until > 0 and time.time() < until:
            return True
        # Clean up expired ban
        if addr in self.banned_peers:
            del self.banned_peers[addr]
        return False

    def _ban_peer(self, addr: str) -> None:
        """Ban a peer address for BAN_DURATION seconds."""
        self.banned_peers[addr] = time.time() + BAN_DURATION
        self.stats["peers_banned"] += 1
        self._log(f"Banned peer {addr} for {BAN_DURATION}s")

        # Disconnect if currently connected
        for nid, conn in list(self.connections.items()):
            if conn.peer_addr == addr:
                conn.close()
                self.connections.pop(nid, None)
                break
        self.stats["peers_connected"] = len(self.connections)

    # ── Local node polling ───────────────────────────────────────────

    async def _poll_local_node(self) -> None:
        """
        Poll the local Rust node for new blocks and broadcast them.

        Also detects new mempool TXs for gossip.
        """
        while self._running:
            try:
                await asyncio.sleep(POLL_INTERVAL)

                status = self.client.get_status()
                current_height = status.block_height

                # Check for new blocks
                if current_height > self._last_block_height:
                    for block_num in range(
                        max(0, self._last_block_height + 1),
                        current_height + 1,
                    ):
                        try:
                            block = self.client.get_block(block_num)
                            if block:
                                await self.broadcast_block(block)
                                self._log(f"Broadcast block #{block_num}")
                        except Exception:
                            pass
                    self._last_block_height = current_height

            except asyncio.CancelledError:
                return
            except Exception:
                pass  # Node unreachable — retry next poll

    # ── Ping keepalive ───────────────────────────────────────────────

    async def _ping_loop(self) -> None:
        """Periodically ping all peers and prune dead/banned connections."""
        while self._running:
            try:
                await asyncio.sleep(PING_INTERVAL)

                dead = []
                for node_id, conn in list(self.connections.items()):
                    if not conn.is_alive or conn.score.is_banned:
                        dead.append(node_id)
                        if conn.score.is_banned:
                            self._ban_peer(conn.peer_addr)
                        continue

                    # Ping if we haven't heard from them recently
                    if time.time() - conn.last_seen > PING_INTERVAL:
                        conn.last_ping_sent = time.time()
                        await conn.send(Message(type=MsgType.PING))

                    # Timeout: no response for 3× ping interval
                    if time.time() - conn.last_seen > PING_INTERVAL * 3:
                        conn.score.timeout()
                        dead.append(node_id)

                for node_id in dead:
                    conn = self.connections.pop(node_id, None)
                    if conn:
                        conn.close()
                self.stats["peers_connected"] = len(self.connections)

            except asyncio.CancelledError:
                return
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────

    def _get_local_height(self) -> int:
        """Get the local node's block height (best effort)."""
        try:
            status = self.client.get_status()
            return status.block_height
        except Exception:
            return 0

    def _mark_seen(self, h: str) -> None:
        """Add a message hash to the seen set, pruning if too large."""
        self.seen_messages.add(h)
        if len(self.seen_messages) > self._seen_max:
            # Remove oldest half (set is unordered, but this is fine for dedup)
            to_remove = list(self.seen_messages)[:self._seen_max // 2]
            for item in to_remove:
                self.seen_messages.discard(item)

    @property
    def peer_count(self) -> int:
        return len(self.connections)

    def get_peers(self) -> List[dict]:
        """Return info about connected peers."""
        return [
            {
                "node_id": conn.node_id,
                "peer_addr": conn.peer_addr,
                "inbound": conn.inbound,
                "block_height": conn.block_height,
                "protocol_version": conn.protocol_version,
                "connected_since": conn.connected_at,
                "last_seen": conn.last_seen,
                "score": conn.score.to_dict(),
            }
            for conn in self.connections.values()
            if conn.is_alive
        ]

    def get_network_stats(self) -> dict:
        """Return comprehensive network statistics."""
        return {
            **self.stats,
            "known_peers": len(self.known_peers),
            "banned_peers": len(self.banned_peers),
            "inventory_size": len(self._tx_inventory),
            "seen_messages": len(self.seen_messages),
            "syncing": self._syncing,
        }


# ─────────────────────────────────────────────────────────────────────
# CLI: Run P2P sidecar standalone
# ─────────────────────────────────────────────────────────────────────

async def _run_cli(args) -> None:
    node = P2PNode(
        node_id=args.node_id,
        rpc_url=args.rpc_url,
        p2p_port=args.p2p_port,
        peers=args.peers.split(",") if args.peers else [],
        verbose=not args.quiet,
    )

    await node.start()
    print(f"P2P sidecar running: {node.node_id} on port {args.p2p_port}")
    print(f"  Protocol:   v{PROTOCOL_VERSION}")
    print(f"  Local node: {args.rpc_url}")
    print(f"  Seed peers: {args.peers or '(none)'}")
    print(f"  Max peers:  {MAX_PEERS}")
    print(f"  Gossip:     fanout={GOSSIP_FANOUT}, TTL={GOSSIP_TTL}")
    print("  Press Ctrl+C to stop.")

    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await node.stop()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Tonkl P2P Sidecar -- Block & TX Gossip",
    )
    parser.add_argument("--node-id", default="node-0", help="Node identifier")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:9100",
                        help="Local Rust node RPC URL")
    parser.add_argument("--p2p-port", type=int, default=9150,
                        help="P2P listen port (default: 9150)")
    parser.add_argument("--peers", default="",
                        help="Comma-separated peer addresses (host:port)")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    asyncio.run(_run_cli(args))


if __name__ == "__main__":
    main()
