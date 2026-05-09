#!/usr/bin/env python3
"""
Tonkl Wallet CLI -- Node-Aware Shielded Wallet

A unified wallet that talks to a live Tonkl node for state and submits
transactions through the full pipeline:

  build witness (from node Merkle state) → prove → submit → confirm

Supports all four circuit types:
  send   (transfer 2-in/2-out)  via obscura-prover
  split  (1-in/32-out)          via nargo execute + bb prove
  merge  (32-in/1-out)          via nargo execute + bb prove
  mint   (0-in/32-out)          via pre-existing proof artifacts

Local state is kept in a SQLite database (~/.tonkl/node_wallet.db) that
tracks owned notes, balances, and transaction history.

Usage:
  # Point at a running node (default: http://127.0.0.1:9100)
  export TONKL_NODE_URL=http://127.0.0.1:9100

  # First time: run the setup wizard
  tonkl wallet                   # auto-triggers onboarding on first run

  # Or use directly:
  tonkl wallet init --sk 0xaaaa01

  # Check balance and notes
  tonkl wallet balance
  tonkl wallet notes

  # Import notes from a mint (provide sk, value, rho for each)
  tonkl wallet import-note --sk 0xaaaa01 --value 400 --rho 6001

  # Send a transfer
  tonkl wallet send 200 --to-pk-x 0x... --to-pk-y 0x... --sk 0xaaaa01

  # Split a note into smaller denominations
  tonkl wallet split <note_id> --values 100,50,30,20

  # Merge notes into one
  tonkl wallet merge <note_id1> <note_id2> ...

  # Sync wallet state against the live node (check nullifiers)
  tonkl wallet sync
"""

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

try:
    from nacl.public import PrivateKey, SealedBox, PublicKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

# ── SQLCipher support (optional, graceful fallback to plain sqlite3) ──
# Install with: pip install sqlcipher3-binary
try:
    import sqlcipher3 as _sqlcipher
    HAS_SQLCIPHER = True
except ImportError:
    HAS_SQLCIPHER = False

# ─────────────────────────────────────────────────────────────────────
# Paths and imports
# ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent  # obscura/

# Binaries and circuit artifacts
PROVER_BIN = ROOT / "obscura-prover" / "target" / "release" / "obscura-prover"
TRANSFER_CIRCUIT = ROOT / "obscura-transfer" / "target" / "obscura_transfer.json"
SPLIT_CIRCUIT = ROOT / "obscura-split" / "target" / "obscura_split.json"
MERGE_CIRCUIT = ROOT / "obscura-merge" / "target" / "obscura_merge.json"
SPLIT_DIR = ROOT / "obscura-split"
MERGE_DIR = ROOT / "obscura-merge"

sys.path.insert(0, str(SCRIPT_DIR))
from node_client import TonklClient, RpcError, NodeError
from witness_builder import (
    WitnessBuilder, CryptoHelper, NoteInput, NoteOutput,
    _dict_to_toml,
)
import bip39

# ─────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────

DEFAULT_NODE_URL = os.environ.get("TONKL_NODE_URL", "http://127.0.0.1:9100")
DEFAULT_DB_DIR = Path.home() / ".tonkl"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "node_wallet.db"
DEFAULT_ASSET_ID = "1"

# ─────────────────────────────────────────────────────────────────────
# Asset registry  (symbol, human name, decimal places)
# ─────────────────────────────────────────────────────────────────────
# asset_id → (symbol, name, decimals)
# Extend this dict as new assets are added to the shielded pool.

ASSET_REGISTRY: dict[str, tuple[str, str, int]] = {
    "1": ("TNKL",  "Tonkl",         0),
    "2": ("sETH",  "Shielded ETH", 18),
    "3": ("sDAI",  "Shielded DAI", 18),
    "4": ("sUSDC", "Shielded USDC", 6),
}


# Runtime cache for custom assets loaded from wallet DB
_custom_assets: dict[str, tuple[str, str, int]] = {}


def _load_custom_assets(conn) -> None:
    """Load custom assets from the wallet database into the runtime cache."""
    global _custom_assets
    try:
        rows = conn.execute("SELECT asset_id, symbol, name, decimals FROM custom_assets").fetchall()
        for r in rows:
            _custom_assets[r["asset_id"]] = (r["symbol"], r["name"], r["decimals"])
    except Exception:
        pass  # table may not exist yet


def _lookup_asset(asset_id: str) -> Optional[tuple]:
    """Look up an asset in both the built-in registry and custom assets."""
    entry = ASSET_REGISTRY.get(str(asset_id))
    if entry:
        return entry
    return _custom_assets.get(str(asset_id))


def asset_symbol(asset_id: str) -> str:
    """Return the ticker symbol for an asset_id, e.g. 'TNKL'."""
    entry = _lookup_asset(asset_id)
    return entry[0] if entry else f"ASSET-{asset_id}"


def asset_name(asset_id: str) -> str:
    """Return the human-readable name for an asset_id."""
    entry = _lookup_asset(asset_id)
    return entry[1] if entry else f"Unknown Asset {asset_id}"


def format_value(value: int, asset_id: str) -> str:
    """
    Format a value with its asset symbol and decimal places.

    Examples:
        format_value(400, "1")  → "400 TNKL"
        format_value(1_500_000, "4")  → "1.5 sUSDC"
    """
    sym = asset_symbol(asset_id)
    entry = _lookup_asset(asset_id)
    if entry and entry[2] > 0:
        decimals = entry[2]
        whole = value // (10 ** decimals)
        frac = value % (10 ** decimals)
        if frac:
            frac_str = f"{frac:0{decimals}d}".rstrip("0")
            return f"{whole}.{frac_str} {sym}"
        return f"{whole} {sym}"
    return f"{value} {sym}"


# ─────────────────────────────────────────────────────────────────────
# Staking constants
# ─────────────────────────────────────────────────────────────────────

STAKING_APY = 0.05          # 5% annual yield (testnet)
STAKING_MIN_AMOUNT = 100    # minimum stake in TNKL
STAKING_ASSET_ID = "1"      # only TNKL can be staked
UNSTAKING_DELAY = 60        # seconds until unstaked funds can be withdrawn (testnet: 60s)
SECONDS_PER_YEAR = 365.25 * 24 * 3600

# ── Epoch & reward distribution constants ─────────────────────────────
EPOCH_DURATION = 120            # seconds per epoch (testnet: 2 min)
REWARD_POOL_PER_EPOCH = 1000    # TNKL minted as rewards per epoch
MAX_ACTIVE_VALIDATORS = 64      # maximum validators in the active set
SLASH_DOWNTIME_PCT = 0.01       # 1% slash for downtime
SLASH_DOUBLE_SIGN_PCT = 0.05    # 5% slash for double-signing
MIN_VALIDATOR_STAKE = 1000      # minimum total stake to be active


def calculate_staking_reward(amount: int, staked_at: float, now: float,
                              commission: float = 0.05) -> int:
    """
    Calculate accrued staking rewards for a position.

    Uses simple interest: reward = amount * APY * (elapsed / year) * (1 - commission).
    Returns the reward as an integer (TNKL has 0 decimals).
    """
    elapsed = max(0.0, now - staked_at)
    gross = amount * STAKING_APY * (elapsed / SECONDS_PER_YEAR)
    net = gross * (1.0 - commission)
    return int(net)


# BN254 scalar field modulus (for key derivation)
BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
HD_DERIVATION_DOMAIN = b"Obscura::note_sk_v1"


# ─────────────────────────────────────────────────────────────────────
# VK resolution
# ─────────────────────────────────────────────────────────────────────

def find_vk(circuit_name: str) -> Path:
    """Locate the verification key for a circuit."""
    base = ROOT / circuit_name / "target"
    for p in [base / "vk" / "vk", base / "vk", base / "vk_dir" / "vk"]:
        if p.exists():
            return p
    raise FileNotFoundError(f"VK not found for {circuit_name}")


TRANSFER_VK = ROOT / "obscura-transfer" / "target" / "vk" / "vk"


# ─────────────────────────────────────────────────────────────────────
# Scan Key Encryption (NaCl sealed box)
# ─────────────────────────────────────────────────────────────────────

def _derive_scan_keypair(spending_sk: str) -> Tuple[bytes, bytes]:
    """
    Derive an X25519 keypair from a spending key for note scanning.

    The scan private key = SHA256(spending_sk || "obscura-scan-v1")[:32],
    clamped to a valid X25519 scalar by NaCl's PrivateKey constructor.

    Returns (scan_sk_bytes, scan_pk_bytes) — both 32 bytes.
    """
    if not HAS_NACL:
        raise RuntimeError("PyNaCl required for scan keys: pip install pynacl")
    seed = hashlib.sha256(
        (spending_sk + ":obscura-scan-v1").encode()
    ).digest()
    sk = PrivateKey(seed)
    return bytes(sk), bytes(sk.public_key)


def encrypt_note_data(
    recipient_scan_pk: bytes,
    value: int,
    asset_id: str,
    rho: str,
    owner_pk_x: str,
    owner_pk_y: str,
) -> bytes:
    """
    Encrypt note details using NaCl sealed box (X25519 + XSalsa20-Poly1305).

    The ciphertext can only be decrypted by the holder of the corresponding
    scan private key (derived from the recipient's spending key).

    Plaintext is a compact JSON object.
    """
    if not HAS_NACL:
        raise RuntimeError("PyNaCl required: pip install pynacl")
    plaintext = json.dumps({
        "v": value,
        "a": asset_id,
        "r": rho,
        "px": owner_pk_x,
        "py": owner_pk_y,
    }, separators=(",", ":")).encode()
    box = SealedBox(PublicKey(recipient_scan_pk))
    return box.encrypt(plaintext)


def decrypt_note_data(
    scan_sk: bytes,
    ciphertext: bytes,
) -> Optional[dict]:
    """
    Try to decrypt a note ciphertext with a scan private key.

    Returns {"v": int, "a": str, "r": str, "px": str, "py": str} on success,
    or None if decryption fails (wrong key).
    """
    if not HAS_NACL:
        return None
    try:
        sk = PrivateKey(scan_sk)
        box = SealedBox(sk)
        plaintext = box.decrypt(ciphertext)
        return json.loads(plaintext)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────
# Database schema
# ─────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS wallet_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_index  INTEGER,              -- leaf index in the on-chain Merkle tree
    value       INTEGER NOT NULL,
    asset_id    TEXT NOT NULL DEFAULT '1',
    owner_sk    TEXT NOT NULL,         -- spending key (hex)
    owner_pk_x  TEXT NOT NULL,
    owner_pk_y  TEXT NOT NULL,
    rho         TEXT NOT NULL,
    commitment  TEXT NOT NULL UNIQUE,
    nullifier   TEXT NOT NULL UNIQUE,
    state       TEXT NOT NULL DEFAULT 'unspent',
    created_at  REAL NOT NULL,
    spent_at    REAL,
    spent_in_tx TEXT
);

CREATE INDEX IF NOT EXISTS idx_notes_state ON notes(state);
CREATE INDEX IF NOT EXISTS idx_notes_commitment ON notes(commitment);
CREATE INDEX IF NOT EXISTS idx_notes_nullifier ON notes(nullifier);

CREATE TABLE IF NOT EXISTS tx_history (
    tx_hash    TEXT PRIMARY KEY,
    tx_type    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    detail     TEXT,                   -- JSON with extra info
    created_at REAL NOT NULL,
    confirmed_at REAL
);

CREATE TABLE IF NOT EXISTS scan_keys (
    spending_sk   TEXT PRIMARY KEY,
    scan_sk       BLOB NOT NULL,       -- X25519 private key (32 bytes)
    scan_pk       BLOB NOT NULL,       -- X25519 public key (32 bytes)
    scan_pk_hex   TEXT NOT NULL UNIQUE, -- hex for display / matching
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_progress (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS master_seed (
    id          INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    mnemonic    TEXT NOT NULL,           -- 24-word BIP-39 phrase
    seed_hex    TEXT NOT NULL,           -- 512-bit seed as hex
    passphrase  TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS derived_keys (
    key_index   INTEGER PRIMARY KEY,     -- derivation index
    spending_sk TEXT NOT NULL UNIQUE,     -- derived spending key (hex)
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_tx (
    tx_hash     TEXT PRIMARY KEY,
    tx_type     TEXT NOT NULL,            -- transfer, split, merge
    input_ids   TEXT NOT NULL,            -- JSON array of note_ids used as inputs
    detail      TEXT,                     -- JSON with output info for recovery
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS faucet_drips (
    recipient_pk TEXT NOT NULL,           -- pk_x of recipient
    asset_id     TEXT NOT NULL,
    amount       INTEGER NOT NULL,
    tx_hash      TEXT,
    dripped_at   REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_faucet_recipient ON faucet_drips(recipient_pk, asset_id, dripped_at);

CREATE TABLE IF NOT EXISTS custom_assets (
    asset_id    TEXT PRIMARY KEY,
    symbol      TEXT NOT NULL,
    name        TEXT NOT NULL,
    decimals    INTEGER NOT NULL DEFAULT 0,
    authority_sk TEXT,                    -- spending key that can mint this asset
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS validators (
    validator_id    TEXT PRIMARY KEY,     -- pk_x of the validator
    name            TEXT NOT NULL,
    commission      REAL NOT NULL DEFAULT 0.05,  -- 0.0-1.0 (5% default)
    total_staked    INTEGER NOT NULL DEFAULT 0,
    is_active       INTEGER NOT NULL DEFAULT 1,
    registered_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS stakes (
    stake_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id         INTEGER NOT NULL,     -- note locked as stake
    validator_id    TEXT NOT NULL,         -- pk_x of validator delegated to
    amount          INTEGER NOT NULL,
    asset_id        TEXT NOT NULL DEFAULT '1',
    owner_sk        TEXT NOT NULL,         -- staker's spending key
    status          TEXT NOT NULL DEFAULT 'active',  -- active | unstaking | withdrawn
    staked_at       REAL NOT NULL,
    unstaked_at     REAL,                  -- when unstake was requested
    withdrawn_at    REAL,                  -- when stake was fully withdrawn
    rewards_claimed REAL NOT NULL DEFAULT 0,  -- total rewards claimed so far
    FOREIGN KEY (note_id) REFERENCES notes(note_id),
    FOREIGN KEY (validator_id) REFERENCES validators(validator_id)
);

CREATE INDEX IF NOT EXISTS idx_stakes_status ON stakes(status);
CREATE INDEX IF NOT EXISTS idx_stakes_validator ON stakes(validator_id);

CREATE TABLE IF NOT EXISTS epochs (
    epoch_number    INTEGER PRIMARY KEY,
    start_time      REAL NOT NULL,
    end_time        REAL,                    -- NULL if current/in-progress
    total_staked    INTEGER NOT NULL DEFAULT 0,
    total_rewards   INTEGER NOT NULL DEFAULT 0,
    active_validators INTEGER NOT NULL DEFAULT 0,
    block_start     INTEGER NOT NULL DEFAULT 0,
    block_end       INTEGER,
    status          TEXT NOT NULL DEFAULT 'active'  -- active | completed
);

CREATE TABLE IF NOT EXISTS epoch_rewards (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_number    INTEGER NOT NULL,
    validator_id    TEXT NOT NULL,
    delegator_sk    TEXT,                    -- NULL for validator's own reward
    stake_amount    INTEGER NOT NULL,
    reward_amount   INTEGER NOT NULL,
    commission_paid INTEGER NOT NULL DEFAULT 0,
    distributed_at  REAL NOT NULL,
    FOREIGN KEY (epoch_number) REFERENCES epochs(epoch_number),
    FOREIGN KEY (validator_id) REFERENCES validators(validator_id)
);

CREATE INDEX IF NOT EXISTS idx_epoch_rewards_epoch ON epoch_rewards(epoch_number);
CREATE INDEX IF NOT EXISTS idx_epoch_rewards_validator ON epoch_rewards(validator_id);

CREATE TABLE IF NOT EXISTS slashing_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    validator_id    TEXT NOT NULL,
    epoch_number    INTEGER NOT NULL,
    reason          TEXT NOT NULL,
    slash_pct       REAL NOT NULL,           -- 0.0-1.0 fraction of stake slashed
    amount_slashed  INTEGER NOT NULL,
    created_at      REAL NOT NULL,
    FOREIGN KEY (validator_id) REFERENCES validators(validator_id)
);
"""


# ─────────────────────────────────────────────────────────────────────
# Database encryption helpers
# ─────────────────────────────────────────────────────────────────────

def _derive_db_key(passphrase: str, salt: Optional[bytes] = None) -> tuple:
    """
    Derive a 256-bit hex key from a passphrase for SQLCipher PRAGMA key.

    Uses PBKDF2-HMAC-SHA256 with 600k iterations. If no salt is provided,
    generates a random 16-byte salt. Returns (hex_key, salt_bytes).

    The salt is stored alongside the encrypted database in a .salt sidecar
    file. This ensures each wallet has a unique encryption key even if the
    same passphrase is used.
    """
    if salt is None:
        salt = os.urandom(16)
    # Include domain separation in the salt
    domain_salt = b"tonkl-wallet-v2:" + salt
    raw = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), domain_salt, 600_000)
    return raw.hex(), salt


def _open_encrypted_db(db_path: str, passphrase: str):
    """
    Open a SQLCipher-encrypted database connection.

    Uses a per-database random salt stored in a .salt sidecar file.
    If the salt file doesn't exist (legacy database), falls back to the
    v1 fixed salt for backwards compatibility, then migrates on next write.

    Returns the connection with row_factory set. Raises ValueError
    if the key is wrong or the DB can't be read.
    """
    salt_path = db_path + ".salt"
    salt = None

    # Try to load existing salt
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as f:
            salt = f.read()
        if len(salt) != 16:
            salt = None  # Invalid salt file, will regenerate

    if salt is not None:
        hex_key, _ = _derive_db_key(passphrase, salt)
    else:
        # First time or legacy database — try with new random salt first,
        # then fall back to legacy fixed salt for backward compatibility
        new_salt = os.urandom(16)
        hex_key, salt = _derive_db_key(passphrase, new_salt)

    # Validate hex_key is strictly hex before embedding in PRAGMA
    if not hex_key or not all(c in "0123456789abcdef" for c in hex_key):
        raise ValueError("Derived key is not valid hex — refusing to use in PRAGMA")

    conn = _sqlcipher.connect(db_path, check_same_thread=False)
    conn.row_factory = _sqlcipher.Row
    conn.execute(f"PRAGMA key = \"x'{hex_key}'\"")

    # Verify the key works
    try:
        conn.execute("SELECT count(*) FROM sqlite_master")
    except Exception:
        conn.close()
        # If no salt file existed, try legacy v1 fixed salt for backward compat
        if not os.path.exists(salt_path):
            legacy_salt = b"obscura-wallet-v1-sqlcipher"
            legacy_raw = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), legacy_salt, 600_000)
            legacy_key = legacy_raw.hex()
            conn = _sqlcipher.connect(db_path, check_same_thread=False)
            conn.row_factory = _sqlcipher.Row
            conn.execute(f"PRAGMA key = \"x'{legacy_key}'\"")
            try:
                conn.execute("SELECT count(*) FROM sqlite_master")
                # Legacy key worked — save a salt file for future opens
                # (Next time user changes passphrase, it will use the new salt)
                return conn
            except Exception:
                conn.close()
        raise ValueError(
            "Failed to open encrypted database. Wrong passphrase?"
        )

    # Save salt file if it doesn't exist yet (new database)
    if not os.path.exists(salt_path):
        try:
            with open(salt_path, "wb") as f:
                f.write(salt)
            os.chmod(salt_path, 0o600)
        except OSError:
            pass  # Non-fatal — salt will be regenerated on next open

    return conn


# ─────────────────────────────────────────────────────────────────────
# Note data class
# ─────────────────────────────────────────────────────────────────────

@dataclass
class WalletNote:
    note_id: int
    tree_index: Optional[int]
    value: int
    asset_id: str
    owner_sk: str
    owner_pk_x: str
    owner_pk_y: str
    rho: str
    commitment: str
    nullifier: str
    state: str
    created_at: float
    spent_at: Optional[float] = None
    spent_in_tx: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────
# Wallet
# ─────────────────────────────────────────────────────────────────────

class NodeWallet:
    """
    Shielded wallet that integrates with a live Tonkl node.

    Local SQLite tracks owned notes and balances. The node provides
    Merkle proofs, nullifier status, and accepts transaction submissions.
    All cryptography is delegated to the obscura-prover binary.
    """

    def __init__(
        self,
        node_url: str = DEFAULT_NODE_URL,
        db_path: Optional[Path] = None,
        passphrase: Optional[str] = None,
    ):
        self.node_url = node_url
        self.client = TonklClient(node_url, timeout=120.0)
        self.crypto = CryptoHelper(str(PROVER_BIN))

        if db_path is None:
            db_path = DEFAULT_DB_PATH
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        self.encrypted = False

        if passphrase and HAS_SQLCIPHER:
            self._conn = _open_encrypted_db(str(self.db_path), passphrase)
            self.encrypted = True
        elif passphrase and not HAS_SQLCIPHER:
            print(
                "\n"
                "  ╔══════════════════════════════════════════════════════════╗\n"
                "  ║  WARNING: SQLCipher is NOT installed.                   ║\n"
                "  ║  Your wallet database will NOT be encrypted.            ║\n"
                "  ║  Seed phrases and keys will be stored in PLAINTEXT.     ║\n"
                "  ║                                                         ║\n"
                "  ║  Install with: pip install sqlcipher3-binary             ║\n"
                "  ╚══════════════════════════════════════════════════════════╝\n",
                file=sys.stderr,
            )
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        else:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            # Check if the file is an encrypted database we can't read
            try:
                self._conn.execute("SELECT count(*) FROM sqlite_master")
            except sqlite3.DatabaseError:
                self._conn.close()
                raise ValueError(
                    "Database appears to be encrypted. "
                    "Use --passphrase to unlock it."
                )

        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

        # Load any custom asset definitions into runtime cache
        _load_custom_assets(self._conn)

        # Auto-recover any pending transactions from a previous crash
        try:
            result = self.recover_pending()
            if result["recovered"] or result["cleared"]:
                print(f"  [recovery] {result['recovered']} TX(s) recovered, "
                      f"{result['cleared']} cleared", file=sys.stderr)
        except Exception:
            pass  # Node unreachable — will retry next time

    def close(self):
        if hasattr(self, '_scanner') and self._scanner is not None:
            self._scanner.stop()
            self._scanner = None
        self._conn.close()

    # ── Background scanning ──────────────────────────────────────────

    _scanner: Optional["BackgroundScanner"] = None

    def start_background_scan(
        self,
        interval: float = 15.0,
        batch_size: int = 256,
        on_notes_found: Optional[Callable[[list], None]] = None,
    ) -> "BackgroundScanner":
        """Start automatic background scanning for incoming notes.

        Requires at least one scan key to be registered.
        Returns the BackgroundScanner instance.
        """
        if self._scanner and self._scanner.running:
            return self._scanner
        self._scanner = BackgroundScanner(
            wallet=self,
            interval=interval,
            batch_size=batch_size,
            on_notes_found=on_notes_found,
        )
        self._scanner.start()
        return self._scanner

    def stop_background_scan(self):
        """Stop background scanning if running."""
        if self._scanner:
            self._scanner.stop()
            self._scanner = None

    # ── BIP-39 Seed Phrase Management ────────────────────────────────

    def generate_seed(self, passphrase: str = "") -> str:
        """
        Generate a new 24-word BIP-39 mnemonic and store the master seed.

        Returns the mnemonic phrase. The caller MUST show it to the user
        for backup — this is the only way to recover their keys.
        """
        if self.has_seed():
            raise ValueError(
                "A master seed already exists. Use 'show-seed' to view it, "
                "or delete the wallet to start fresh."
            )
        mnemonic = bip39.generate_mnemonic(bits=256)
        seed = bip39.mnemonic_to_seed(mnemonic, passphrase)
        self._conn.execute(
            "INSERT INTO master_seed (id, mnemonic, seed_hex, passphrase, created_at) "
            "VALUES (1, ?, ?, ?, ?)",
            (mnemonic, seed.hex(), passphrase, time.time()),
        )
        self._conn.commit()
        return mnemonic

    def restore_seed(self, mnemonic: str, passphrase: str = "") -> None:
        """
        Restore a master seed from a BIP-39 mnemonic phrase.

        Validates the checksum, derives the seed, and stores it.
        Optionally re-derives keys up to the last known index.
        """
        # Validate
        bip39.mnemonic_to_entropy(mnemonic)
        seed = bip39.mnemonic_to_seed(mnemonic, passphrase)

        # Replace existing seed if any
        self._conn.execute("DELETE FROM master_seed")
        self._conn.execute("DELETE FROM derived_keys")
        self._conn.execute(
            "INSERT INTO master_seed (id, mnemonic, seed_hex, passphrase, created_at) "
            "VALUES (1, ?, ?, ?, ?)",
            (mnemonic, seed.hex(), passphrase, time.time()),
        )
        self._conn.commit()

    def has_seed(self) -> bool:
        """Check if a master seed is stored."""
        row = self._conn.execute("SELECT id FROM master_seed WHERE id = 1").fetchone()
        return row is not None

    def get_mnemonic(self) -> Optional[str]:
        """Retrieve the stored mnemonic phrase, or None."""
        row = self._conn.execute(
            "SELECT mnemonic FROM master_seed WHERE id = 1"
        ).fetchone()
        return row["mnemonic"] if row else None

    def _get_seed_hex(self) -> str:
        """Retrieve the master seed hex. Raises if not stored."""
        row = self._conn.execute(
            "SELECT seed_hex FROM master_seed WHERE id = 1"
        ).fetchone()
        if not row:
            raise ValueError(
                "No master seed found. Run 'init-seed' or 'restore-seed' first."
            )
        return row["seed_hex"]

    def derive_spending_key(self, index: int) -> str:
        """
        Derive a spending key from the master seed at the given index.

        Formula:
            sk = HMAC-SHA512(domain || seed || index) mod BN254_P

        The key is stored in derived_keys for tracking. Also auto-registers
        a scan key for the derived spending key.

        Returns the spending key as hex string (0x-prefixed).
        """
        # Check if already derived
        existing = self._conn.execute(
            "SELECT spending_sk FROM derived_keys WHERE key_index = ?", (index,)
        ).fetchone()
        if existing:
            return existing["spending_sk"]

        seed_hex = self._get_seed_hex()
        seed_bytes = bytes.fromhex(seed_hex)

        # Domain-separated HMAC-SHA512 derivation
        derive_input = (
            HD_DERIVATION_DOMAIN
            + seed_bytes
            + index.to_bytes(8, "big")
        )
        raw_hash = hashlib.pbkdf2_hmac("sha512", derive_input, HD_DERIVATION_DOMAIN, 1)[:32]
        sk_int = int.from_bytes(raw_hash, "big") % BN254_P
        sk_hex = "0x" + format(sk_int, "064x")

        # Store
        self._conn.execute(
            "INSERT INTO derived_keys (key_index, spending_sk, created_at) "
            "VALUES (?, ?, ?)",
            (index, sk_hex, time.time()),
        )
        self._conn.commit()

        # Auto-register scan key
        if HAS_NACL:
            try:
                self.register_scan_key(sk_hex)
            except Exception:
                pass  # Non-fatal

        return sk_hex

    def get_derived_keys(self) -> List[dict]:
        """Return all derived spending keys with their indices."""
        rows = self._conn.execute(
            "SELECT key_index, spending_sk FROM derived_keys ORDER BY key_index"
        ).fetchall()
        return [{"index": r["key_index"], "spending_sk": r["spending_sk"]} for r in rows]

    def get_next_key_index(self) -> int:
        """Return the next unused key derivation index."""
        row = self._conn.execute(
            "SELECT MAX(key_index) as mx FROM derived_keys"
        ).fetchone()
        return (row["mx"] + 1) if row and row["mx"] is not None else 0

    def recover_keys(self, count: int = 10) -> List[str]:
        """
        Re-derive spending keys from the master seed (indices 0..count-1).

        Used after restoring from mnemonic to recover all keys and
        re-register scan keys. Returns list of derived spending keys.
        """
        keys = []
        for i in range(count):
            sk = self.derive_spending_key(i)
            keys.append(sk)
        return keys

    # ── Database helpers ──────────────────────────────────────────────

    def _row_to_note(self, row) -> WalletNote:
        return WalletNote(
            note_id=row["note_id"],
            tree_index=row["tree_index"],
            value=row["value"],
            asset_id=row["asset_id"],
            owner_sk=row["owner_sk"],
            owner_pk_x=row["owner_pk_x"],
            owner_pk_y=row["owner_pk_y"],
            rho=row["rho"],
            commitment=row["commitment"],
            nullifier=row["nullifier"],
            state=row["state"],
            created_at=row["created_at"],
            spent_at=row["spent_at"],
            spent_in_tx=row["spent_in_tx"],
        )

    def _insert_note(
        self,
        tree_index: Optional[int],
        value: int,
        asset_id: str,
        owner_sk: str,
        owner_pk_x: str,
        owner_pk_y: str,
        rho: str,
        commitment: str,
        nullifier: str,
        state: str = "unspent",
    ) -> WalletNote:
        now = time.time()
        cursor = self._conn.execute(
            """INSERT OR IGNORE INTO notes
               (tree_index, value, asset_id, owner_sk, owner_pk_x, owner_pk_y,
                rho, commitment, nullifier, state, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tree_index, value, asset_id, owner_sk, owner_pk_x, owner_pk_y,
             rho, commitment, nullifier, state, now),
        )
        self._conn.commit()
        if cursor.lastrowid == 0:
            # Already exists
            row = self._conn.execute(
                "SELECT * FROM notes WHERE commitment = ?", (commitment,)
            ).fetchone()
            return self._row_to_note(row)
        return WalletNote(
            note_id=cursor.lastrowid, tree_index=tree_index,
            value=value, asset_id=asset_id,
            owner_sk=owner_sk, owner_pk_x=owner_pk_x, owner_pk_y=owner_pk_y,
            rho=rho, commitment=commitment, nullifier=nullifier,
            state=state, created_at=now,
        )

    # ── Key derivation ────────────────────────────────────────────────

    def derive_pk(self, sk: str) -> Tuple[str, str]:
        return self.crypto.derive_pk(sk)

    # ── Note import ───────────────────────────────────────────────────

    def import_note(
        self,
        sk: str,
        value: int,
        rho: str,
        asset_id: str = DEFAULT_ASSET_ID,
        tree_index: Optional[int] = None,
    ) -> WalletNote:
        """
        Import a note into the wallet. Computes commitment and nullifier
        from the provided parameters using the prover binary.

        If tree_index is not provided, the wallet will try to find the
        note in the on-chain tree by scanning commitments at known indices.
        """
        pk_x, pk_y = self.crypto.derive_pk(sk)
        cm = self.crypto.commitment(str(value), asset_id, pk_x, pk_y, rho)
        nf = self.crypto.nullifier(cm, sk)

        note = self._insert_note(
            tree_index=tree_index,
            value=value,
            asset_id=asset_id,
            owner_sk=sk,
            owner_pk_x=pk_x,
            owner_pk_y=pk_y,
            rho=rho,
            commitment=cm,
            nullifier=nf,
        )
        return note

    # ── Queries ───────────────────────────────────────────────────────

    def get_unspent(self, asset_id: Optional[str] = None) -> List[WalletNote]:
        if asset_id:
            rows = self._conn.execute(
                "SELECT * FROM notes WHERE state = 'unspent' AND asset_id = ? ORDER BY value DESC",
                (asset_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM notes WHERE state = 'unspent' ORDER BY value DESC",
            ).fetchall()
        return [self._row_to_note(r) for r in rows]

    def get_note(self, note_id: int) -> Optional[WalletNote]:
        row = self._conn.execute(
            "SELECT * FROM notes WHERE note_id = ?", (note_id,)
        ).fetchone()
        return self._row_to_note(row) if row else None

    def get_all_notes(self) -> List[WalletNote]:
        rows = self._conn.execute(
            "SELECT * FROM notes ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_note(r) for r in rows]

    def balance(self) -> dict:
        """Return {asset_id: total_unspent_value}."""
        rows = self._conn.execute(
            "SELECT asset_id, COALESCE(SUM(value), 0) AS total "
            "FROM notes WHERE state = 'unspent' GROUP BY asset_id"
        ).fetchall()
        return {r["asset_id"]: r["total"] for r in rows}

    # ── Coin selection ───────────────────────────────────────────────

    def select_notes(
        self,
        amount: int,
        asset_id: str = DEFAULT_ASSET_ID,
        exclude_ids: Optional[List[int]] = None,
        sender_sk: Optional[str] = None,
        force_pair: bool = False,
    ) -> List[WalletNote]:
        """
        Automatically select unspent notes that cover `amount`.

        Strategy: largest-first greedy — fewest notes, fastest proof.
        The transfer circuit takes exactly 2 inputs, so we select at most 2.

        Args:
            amount: Total value needed (send amount + fee).
            asset_id: Asset to select from.
            exclude_ids: Note IDs to skip (e.g., already reserved).
            sender_sk: If set, only select notes owned by this key.
            force_pair: If True, skip single-note solutions and always
                        return a pair. Used when no zero-value dummy note
                        is available for single-input padding.

        Returns:
            List of 1-2 WalletNote objects whose total value >= amount.

        Raises:
            ValueError: If no combination of 1-2 notes covers the amount.
        """
        exclude = set(exclude_ids or [])
        candidates = [
            n for n in self.get_unspent(asset_id=asset_id)
            if n.note_id not in exclude
            and n.tree_index is not None
            and n.value > 0
            and (sender_sk is None or n.owner_sk == sender_sk)
        ]
        # Already sorted descending by value from get_unspent()

        # Try single note first (unless caller forces pairs)
        if not force_pair:
            for n in candidates:
                if n.value >= amount:
                    return [n]

        # Try pairs (largest + smallest that covers the gap)
        for i, big in enumerate(candidates):
            need = amount - big.value
            # Search from smallest up for tightest fit
            for small in reversed(candidates):
                if small.note_id == big.note_id:
                    continue
                if small.value >= need:
                    return [big, small]

        # No valid combination
        total_available = sum(n.value for n in candidates)
        raise ValueError(
            f"Cannot cover {amount} with 1-2 notes. "
            f"Available: {total_available} across {len(candidates)} notes. "
            f"Consider merging notes first."
        )

    def _find_dummy_note(
        self,
        owner_sk: str,
        asset_id: str = DEFAULT_ASSET_ID,
    ) -> Optional[WalletNote]:
        """
        Find a zero-value note owned by `owner_sk` that exists in the tree.

        Zero-value notes are produced as padding by split and merge operations.
        They're valid circuit inputs — the transfer circuit accepts them as
        the second input since only out1_value must be non-zero.

        Returns None if no zero-value note is available.
        """
        rows = self._conn.execute(
            "SELECT * FROM notes WHERE state = 'unspent' AND value = 0 "
            "AND owner_sk = ? AND asset_id = ? AND tree_index IS NOT NULL "
            "ORDER BY tree_index ASC LIMIT 1",
            (owner_sk, asset_id),
        ).fetchall()
        return self._row_to_note(rows[0]) if rows else None

    def _find_any_dummy_note(
        self,
        asset_id: str = DEFAULT_ASSET_ID,
    ) -> Optional[WalletNote]:
        """
        Find a zero-value note owned by ANY key that exists in the tree.

        Fallback when no dummy is available for the primary input's key
        and no pair can be formed. The transfer circuit allows mixed-owner
        inputs since each input has its own sk/pk/nullifier.
        """
        rows = self._conn.execute(
            "SELECT * FROM notes WHERE state = 'unspent' AND value = 0 "
            "AND asset_id = ? AND tree_index IS NOT NULL "
            "ORDER BY tree_index ASC LIMIT 1",
            (asset_id,),
        ).fetchall()
        return self._row_to_note(rows[0]) if rows else None

    # ── Prover retry logic ───────────────────────────────────────────

    def _run_prover_with_retry(
        self,
        cmd: List[str],
        stdin_data: Optional[str] = None,
        max_retries: int = 2,
        timeout: int = 300,
        label: str = "proof",
    ) -> subprocess.CompletedProcess:
        """
        Run a prover subprocess with retry on transient failures.

        Retries on non-zero exit codes that look transient (signal kills,
        timeouts). Does NOT retry on constraint failures (those are bugs).
        """
        last_err = None
        for attempt in range(1, max_retries + 1):
            try:
                result = subprocess.run(
                    cmd,
                    input=stdin_data,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                if result.returncode == 0:
                    return result

                stderr = result.stderr[-500:]
                # Don't retry on constraint failures — those are deterministic
                if "circuit" in stderr.lower() and ("constraint" in stderr.lower() or "assert" in stderr.lower()):
                    raise RuntimeError(f"{label} failed (constraint error):\n{stderr}")

                last_err = stderr
                if attempt < max_retries:
                    print(f"  ⚠ {label} attempt {attempt} failed, retrying...")
                    time.sleep(1)

            except subprocess.TimeoutExpired:
                last_err = f"Timed out after {timeout}s"
                if attempt < max_retries:
                    print(f"  ⚠ {label} attempt {attempt} timed out, retrying...")

        raise RuntimeError(f"{label} failed after {max_retries} attempts:\n{last_err}")

    # ── Node sync ─────────────────────────────────────────────────────

    def sync(self) -> dict:
        """
        Synchronize wallet state against the live node.

        Checks each unspent note's nullifier against the on-chain nullifier
        set and marks notes as spent if their nullifier has been consumed.

        Returns a summary of changes.
        """
        unspent = self.get_unspent()
        marked_spent = 0
        checked = 0

        for note in unspent:
            checked += 1
            try:
                is_spent = self.client.get_nullifier_status(note.nullifier)
                if is_spent:
                    self._conn.execute(
                        "UPDATE notes SET state = 'spent', spent_at = ? WHERE note_id = ?",
                        (time.time(), note.note_id),
                    )
                    marked_spent += 1
            except NodeError:
                pass  # Node unreachable for this check, skip

        self._conn.commit()

        status = self.client.get_status()
        return {
            "checked": checked,
            "marked_spent": marked_spent,
            "node_height": status.block_height,
            "node_leaves": status.leaf_count,
            "node_nullifiers": status.nullifier_count,
        }

    # ── Pending TX tracking (crash recovery) ──────────────────────

    def _record_pending_tx(
        self, tx_hash: str, tx_type: str, input_ids: List[int], detail: Optional[dict] = None
    ) -> None:
        """Record a submitted TX so we can recover if we crash before updating state."""
        self._conn.execute(
            "INSERT OR REPLACE INTO pending_tx (tx_hash, tx_type, input_ids, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (tx_hash, tx_type, json.dumps(input_ids), json.dumps(detail) if detail else None, time.time()),
        )
        self._conn.commit()

    def _clear_pending_tx(self, tx_hash: str) -> None:
        """Remove a pending TX record after state has been fully updated."""
        self._conn.execute("DELETE FROM pending_tx WHERE tx_hash = ?", (tx_hash,))
        self._conn.commit()

    def recover_pending(self) -> dict:
        """
        Recover from incomplete transactions after a crash.

        For each pending TX:
          - Check the node for its status
          - If confirmed: mark input notes as spent, record in history
          - If unknown/rejected: the TX was lost, inputs are still unspent
          - Either way: clear the pending record

        Returns summary of recovered/cleared transactions.
        """
        rows = self._conn.execute("SELECT * FROM pending_tx").fetchall()
        if not rows:
            return {"recovered": 0, "cleared": 0}

        recovered = 0
        cleared = 0

        for row in rows:
            tx_hash = row["tx_hash"]
            input_ids = json.loads(row["input_ids"])

            try:
                tx_status = self.client.get_tx_status(tx_hash)
            except Exception:
                # Can't reach node — skip, try again next time
                continue

            if tx_status.status == "confirmed":
                # TX succeeded — mark inputs as spent
                now = time.time()
                for nid in input_ids:
                    self._conn.execute(
                        "UPDATE notes SET state = 'spent', spent_at = ?, spent_in_tx = ? "
                        "WHERE note_id = ? AND state = 'unspent'",
                        (now, tx_hash, nid),
                    )
                # Record in history if not already there
                existing = self._conn.execute(
                    "SELECT 1 FROM tx_history WHERE tx_hash = ?", (tx_hash,)
                ).fetchone()
                if not existing:
                    self._conn.execute(
                        "INSERT INTO tx_history (tx_hash, tx_type, status, detail, created_at, confirmed_at) "
                        "VALUES (?, ?, 'confirmed', ?, ?, ?)",
                        (tx_hash, row["tx_type"], row["detail"], row["created_at"], now),
                    )
                self._conn.commit()
                recovered += 1
            else:
                # TX unknown or failed — inputs stay unspent, just clear the record
                cleared += 1

            self._conn.execute("DELETE FROM pending_tx WHERE tx_hash = ?", (tx_hash,))
            self._conn.commit()

        return {"recovered": recovered, "cleared": cleared}

    # ── Faucet ──────────────────────────────────────────────────────

    # Default drip amounts per asset
    FAUCET_DRIP_AMOUNTS = {
        "1": 100,                 # 100 TNKL
        "4": 100_000_000,         # 100 sUSDC (6 decimals)
    }

    # Cooldown in seconds per (recipient, asset) pair
    FAUCET_COOLDOWN = 3600  # 1 hour

    def faucet_drip(
        self,
        recipient_pk_x: str,
        recipient_pk_y: str,
        asset_id: str = DEFAULT_ASSET_ID,
        amount: Optional[int] = None,
        sender_sk: Optional[str] = None,
        cooldown: Optional[int] = None,
    ) -> dict:
        """
        Drip testnet tokens to a recipient address.

        Uses the wallet's existing send() pipeline: selects a faucet-owned
        note, builds a transfer proof, submits, and produces a block.

        Rate-limited: one drip per (recipient, asset) per cooldown period.

        Args:
            recipient_pk_x/y: Recipient public key.
            asset_id: Which asset to drip ("1" for TNKL, "4" for sUSDC).
            amount: Override drip amount. Uses default if None.
            sender_sk: Faucet spending key. Uses first available if None.
            cooldown: Override cooldown in seconds.

        Returns dict with tx_hash, amount, and asset info.
        """
        if cooldown is None:
            cooldown = self.FAUCET_COOLDOWN

        if amount is None:
            amount = self.FAUCET_DRIP_AMOUNTS.get(asset_id)
            if amount is None:
                raise ValueError(
                    f"No default drip amount for asset_id={asset_id}. "
                    f"Supported assets: {list(self.FAUCET_DRIP_AMOUNTS.keys())}"
                )

        # Rate limiting: check last drip to this recipient for this asset
        now = time.time()
        cutoff = now - cooldown
        last_drip = self._conn.execute(
            "SELECT dripped_at FROM faucet_drips "
            "WHERE recipient_pk = ? AND asset_id = ? AND dripped_at > ? "
            "ORDER BY dripped_at DESC LIMIT 1",
            (recipient_pk_x, asset_id, cutoff),
        ).fetchone()

        if last_drip is not None:
            wait_secs = int(cooldown - (now - last_drip["dripped_at"]))
            wait_mins = (wait_secs + 59) // 60
            raise ValueError(
                f"Rate limited: already dripped {asset_symbol(asset_id)} to this "
                f"address recently. Try again in ~{wait_mins} minute(s)."
            )

        # Check faucet has sufficient balance for this asset
        bal = self.balance()
        available = bal.get(asset_id, 0)
        if available < amount:
            raise ValueError(
                f"Faucet has insufficient {asset_symbol(asset_id)} balance: "
                f"{format_value(available, asset_id)} available, "
                f"{format_value(amount, asset_id)} requested."
            )

        # Execute the transfer
        result = self.send(
            to_pk_x=recipient_pk_x,
            to_pk_y=recipient_pk_y,
            to_value=amount,
            sender_sk=sender_sk,
            asset_id=asset_id,
        )

        # Record the drip
        self._conn.execute(
            "INSERT INTO faucet_drips (recipient_pk, asset_id, amount, tx_hash, dripped_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (recipient_pk_x, asset_id, amount, result.get("tx_hash"), now),
        )
        self._conn.commit()

        return {
            "tx_hash": result.get("tx_hash"),
            "amount": amount,
            "asset_id": asset_id,
            "symbol": asset_symbol(asset_id),
            "formatted": format_value(amount, asset_id),
            "recipient_pk_x": recipient_pk_x,
            "recipient_pk_y": recipient_pk_y,
            "recipient_tree_index": result.get("recipient_tree_index"),
            "out1_rho": result.get("out1_rho"),
        }

    def faucet_history(self, limit: int = 20) -> List[dict]:
        """Return recent faucet drip history."""
        rows = self._conn.execute(
            "SELECT * FROM faucet_drips ORDER BY dripped_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "recipient_pk": r["recipient_pk"],
                "asset_id": r["asset_id"],
                "amount": r["amount"],
                "tx_hash": r["tx_hash"],
                "dripped_at": r["dripped_at"],
            }
            for r in rows
        ]

    # ── Custom token creation ──────────────────────────────────────

    def register_asset(
        self,
        asset_id: str,
        symbol: str,
        name: str,
        decimals: int = 0,
        authority_sk: Optional[str] = None,
    ) -> dict:
        """
        Register a new custom asset in the wallet's local registry.

        Args:
            asset_id: Unique numeric ID (as string). Must not collide with built-in assets.
            symbol: Short ticker symbol (e.g. "MYTKN").
            name: Human-readable name (e.g. "My Custom Token").
            decimals: Number of decimal places (0 = whole units).
            authority_sk: Optional spending key authorized to mint this asset.

        Returns dict with the registered asset details.
        """
        # Validate asset_id
        aid = str(asset_id)
        if aid in ASSET_REGISTRY:
            raise ValueError(
                f"Asset ID {aid} is already a built-in asset ({ASSET_REGISTRY[aid][0]}). "
                f"Choose a different ID."
            )

        # Check if already registered
        existing = self._conn.execute(
            "SELECT asset_id FROM custom_assets WHERE asset_id = ?", (aid,)
        ).fetchone()
        if existing:
            raise ValueError(f"Asset ID {aid} is already registered as a custom asset.")

        # Validate symbol
        sym = symbol.upper().strip()
        if not sym or len(sym) > 10:
            raise ValueError("Symbol must be 1-10 characters.")
        if not sym.isalnum():
            raise ValueError("Symbol must be alphanumeric.")

        # Validate decimals
        if decimals < 0 or decimals > 18:
            raise ValueError("Decimals must be between 0 and 18.")

        # Store in database
        now = time.time()
        self._conn.execute(
            "INSERT INTO custom_assets (asset_id, symbol, name, decimals, authority_sk, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (aid, sym, name.strip(), decimals, authority_sk, now),
        )
        self._conn.commit()

        # Update runtime cache
        _custom_assets[aid] = (sym, name.strip(), decimals)

        return {
            "asset_id": aid,
            "symbol": sym,
            "name": name.strip(),
            "decimals": decimals,
            "authority_sk": authority_sk,
        }

    def mint_token(
        self,
        asset_id: str,
        amount: int,
        recipient_sk: Optional[str] = None,
        num_notes: int = 1,
        authority_sk: Optional[str] = None,
    ) -> dict:
        """
        Mint new tokens for a custom asset using the mint circuit.

        This generates a ZK proof and submits a mint transaction to the node.
        Requires nargo and bb to be on PATH.

        Args:
            asset_id: Asset ID to mint.
            amount: Total amount to mint.
            recipient_sk: Recipient spending key. Uses authority_sk if not provided.
            num_notes: Number of notes to split the mint into (1-32).
            authority_sk: Override authority key (defaults to asset's stored authority_sk).

        Returns dict with tx_hash and minted note details.
        """
        import shutil
        import subprocess

        aid = str(asset_id)

        # Resolve authority key
        if authority_sk is None:
            row = self._conn.execute(
                "SELECT authority_sk FROM custom_assets WHERE asset_id = ?", (aid,)
            ).fetchone()
            if row and row["authority_sk"]:
                authority_sk = row["authority_sk"]
            else:
                raise ValueError(
                    f"No authority key for asset {aid}. "
                    f"Provide --authority-sk or register the asset with one."
                )

        # Resolve recipient
        if recipient_sk is None:
            recipient_sk = authority_sk

        # Validate
        if num_notes < 1 or num_notes > 32:
            raise ValueError("num_notes must be between 1 and 32")
        if amount <= 0:
            raise ValueError("amount must be positive")

        # Check toolchain
        for tool in ["nargo", "bb"]:
            if shutil.which(tool) is None:
                raise FileNotFoundError(
                    f"{tool} not found on PATH. "
                    f"Install Noir and Barretenberg to mint tokens."
                )

        # Derive keys
        authority_pk_x, authority_pk_y = self.crypto.derive_pk(authority_sk)
        recipient_pk_x, recipient_pk_y = self.crypto.derive_pk(recipient_sk)

        # Split amount across notes
        per_note = amount // num_notes
        remainder = amount - (per_note * num_notes)
        values = [per_note] * num_notes
        values[0] += remainder  # first note gets the remainder

        # Build outputs and commitments
        from witness_builder import WitnessBuilder, NoteOutput

        outputs = []
        cm_outs = []
        note_details = []
        rho_base = int(time.time() * 1000) % 1_000_000  # unique rho base

        for i, val in enumerate(values):
            rho = str(rho_base + i)
            out = NoteOutput(
                value=val,
                owner_pk_x=recipient_pk_x,
                owner_pk_y=recipient_pk_y,
                rho=rho,
            )
            outputs.append(out)
            cm = self.crypto.commitment(
                str(val), aid, recipient_pk_x, recipient_pk_y, rho,
            )
            cm_outs.append(cm)
            note_details.append({
                "value": val,
                "rho": rho,
                "commitment": cm,
            })

        # Pad to 32
        while len(outputs) < 32:
            pad_rho = str(rho_base + len(outputs) + 9000)
            out = NoteOutput(
                value=0,
                owner_pk_x=authority_pk_x,
                owner_pk_y=authority_pk_y,
                rho=pad_rho,
            )
            outputs.append(out)
            cm = self.crypto.commitment(
                "0", aid, authority_pk_x, authority_pk_y, pad_rho,
            )
            cm_outs.append(cm)

        assert len(cm_outs) == 32

        # Build witness — pass ALL 32 outputs (including padding) so
        # that build_mint doesn't re-pad with different rho values.
        builder = WitnessBuilder(self.client)
        witness_toml = builder.build_mint(
            outputs=outputs,
            total_minted=amount,
            asset_id=aid,
            authority_pk_x=authority_pk_x,
            authority_pk_y=authority_pk_y,
            authority_sk=authority_sk,
            cm_outs=cm_outs,
        )

        # Write Prover.toml
        mint_dir = ROOT / "obscura-mint"
        prover_path = mint_dir / "Prover.toml"
        prover_path.write_text(witness_toml)

        # nargo execute
        witness_name = f"mint_{aid}_{int(time.time())}"
        result = subprocess.run(
            ["nargo", "execute", witness_name],
            cwd=str(mint_dir),
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"nargo execute failed: {result.stderr[-300:]}")

        witness_gz = mint_dir / "target" / f"{witness_name}.gz"
        if not witness_gz.exists():
            raise FileNotFoundError(f"Witness not found: {witness_gz}")

        # bb prove
        mint_json = mint_dir / "target" / "obscura_mint.json"
        mint_vk = find_vk("obscura-mint")

        import tempfile
        tmp_dir = Path(tempfile.mkdtemp(prefix="obscura-mint-"))
        proof_dir = tmp_dir / "proof"
        proof_dir.mkdir()

        try:
            result = subprocess.run(
                ["bb", "prove", "-b", str(mint_json), "-w", str(witness_gz),
                 "-o", str(proof_dir), "-k", str(mint_vk)],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                raise RuntimeError(f"bb prove failed: {result.stderr[-300:]}")

            proof_path = proof_dir / "proof"
            pi_path = proof_dir / "public_inputs"

            # Read verified commitments
            pi_bytes = pi_path.read_bytes()
            verified_cms = []
            for i in range(32):
                chunk = pi_bytes[i * 32 : (i + 1) * 32]
                verified_cms.append("0x" + chunk.hex())

            # Submit to node
            asset_id_hex = "0x" + f"{int(aid):064x}"
            submit_result = self.client.submit_from_proof_files(
                tx_type="mint",
                proof_path=str(proof_path),
                public_inputs_path=str(pi_path),
                new_commitments=verified_cms,
                nullifiers=[],
                merkle_root="0x" + "00" * 32,
                fee=0,
                asset_id=asset_id_hex,
            )

            if not submit_result.accepted:
                raise RuntimeError("Mint transaction rejected by node")

            # Produce block
            header = self.client.produce_block()

            # Import minted notes into wallet
            status = self.client.get_status()
            base_index = status.leaf_count - 32  # the 32 leaves just added

            imported_notes = []
            for i, detail in enumerate(note_details):
                note = self.import_note(
                    sk=recipient_sk,
                    value=detail["value"],
                    rho=detail["rho"],
                    asset_id=aid,
                    tree_index=base_index + i,
                )
                imported_notes.append({
                    "note_id": note.note_id,
                    "value": detail["value"],
                    "tree_index": base_index + i,
                })

            # Record in history
            self._conn.execute(
                "INSERT OR REPLACE INTO tx_history (tx_hash, tx_type, status, detail, created_at, confirmed_at) "
                "VALUES (?, 'mint', 'confirmed', ?, ?, ?)",
                (
                    submit_result.tx_hash,
                    json.dumps({
                        "asset_id": aid,
                        "total_minted": amount,
                        "num_notes": num_notes,
                        "notes": imported_notes,
                    }),
                    time.time(),
                    time.time(),
                ),
            )
            self._conn.commit()

            return {
                "tx_hash": submit_result.tx_hash,
                "block_number": header.block_number,
                "asset_id": aid,
                "amount": amount,
                "formatted": format_value(amount, aid),
                "notes": imported_notes,
            }

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def get_custom_assets(self) -> List[dict]:
        """Return all custom assets registered in this wallet."""
        rows = self._conn.execute(
            "SELECT asset_id, symbol, name, decimals, authority_sk, created_at "
            "FROM custom_assets ORDER BY asset_id"
        ).fetchall()
        return [
            {
                "asset_id": r["asset_id"],
                "symbol": r["symbol"],
                "name": r["name"],
                "decimals": r["decimals"],
                "authority_sk": r["authority_sk"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # ── Staking & delegation ────────────────────────────────────────

    def register_validator(
        self,
        validator_pk_x: str,
        name: str,
        commission: float = 0.05,
    ) -> dict:
        """
        Register a validator in the local wallet for delegation.

        Args:
            validator_pk_x: The validator's public key (x-coordinate, hex).
            name: Human-readable name for the validator.
            commission: Commission rate 0.0-1.0 (default 5%).

        Returns:
            Dict with validator details.
        """
        if not (0.0 <= commission <= 1.0):
            raise ValueError("Commission must be between 0.0 and 1.0")
        if not name or len(name) > 50:
            raise ValueError("Validator name must be 1-50 characters")

        # Check for duplicate
        existing = self._conn.execute(
            "SELECT validator_id FROM validators WHERE validator_id = ?",
            (validator_pk_x,),
        ).fetchone()
        if existing:
            raise ValueError(f"Validator {validator_pk_x[:20]}... already registered")

        now = time.time()
        self._conn.execute(
            "INSERT INTO validators (validator_id, name, commission, total_staked, is_active, registered_at) "
            "VALUES (?, ?, ?, 0, 1, ?)",
            (validator_pk_x, name, commission, now),
        )
        self._conn.commit()

        return {
            "validator_id": validator_pk_x,
            "name": name,
            "commission": commission,
            "registered_at": now,
        }

    def get_validators(self) -> List[dict]:
        """Return all registered validators."""
        rows = self._conn.execute(
            "SELECT validator_id, name, commission, total_staked, is_active, registered_at "
            "FROM validators ORDER BY total_staked DESC"
        ).fetchall()
        now = time.time()
        result = []
        for r in rows:
            # Count active stakes
            active_stakes = self._conn.execute(
                "SELECT COUNT(*) as cnt, COALESCE(SUM(amount), 0) as total "
                "FROM stakes WHERE validator_id = ? AND status = 'active'",
                (r["validator_id"],),
            ).fetchone()
            result.append({
                "validator_id": r["validator_id"],
                "name": r["name"],
                "commission": r["commission"],
                "total_staked": active_stakes["total"] if active_stakes else 0,
                "active_stakes": active_stakes["cnt"] if active_stakes else 0,
                "is_active": bool(r["is_active"]),
                "registered_at": r["registered_at"],
            })
        return result

    def stake(
        self,
        note_id: int,
        validator_id: str,
    ) -> dict:
        """
        Stake a note by delegating it to a validator.

        The note is marked as 'staked' (locked) and a stake record is created.
        Only TNKL (asset_id=1) notes can be staked.

        Args:
            note_id: The note to stake.
            validator_id: The validator pk_x to delegate to.

        Returns:
            Dict with stake details.
        """
        # Verify note exists and is unspent
        row = self._conn.execute(
            "SELECT * FROM notes WHERE note_id = ?", (note_id,)
        ).fetchone()
        if not row:
            raise ValueError(f"Note #{note_id} not found")
        if row["state"] != "unspent":
            raise ValueError(f"Note #{note_id} is {row['state']}, must be unspent to stake")
        if row["asset_id"] != STAKING_ASSET_ID:
            raise ValueError(
                f"Only {asset_symbol(STAKING_ASSET_ID)} can be staked "
                f"(note #{note_id} is {asset_symbol(row['asset_id'])})"
            )
        if row["value"] < STAKING_MIN_AMOUNT:
            raise ValueError(
                f"Minimum stake is {STAKING_MIN_AMOUNT} {asset_symbol(STAKING_ASSET_ID)} "
                f"(note #{note_id} has {row['value']})"
            )

        # Verify validator exists and is active
        val = self._conn.execute(
            "SELECT * FROM validators WHERE validator_id = ?", (validator_id,)
        ).fetchone()
        if not val:
            raise ValueError(f"Validator {validator_id[:20]}... not found. Run 'validators' to see available.")
        if not val["is_active"]:
            raise ValueError(f"Validator {val['name']} is not currently active")

        now = time.time()

        # Lock the note (mark as staked)
        self._conn.execute(
            "UPDATE notes SET state = 'staked' WHERE note_id = ?",
            (note_id,),
        )

        # Create stake record
        cur = self._conn.execute(
            "INSERT INTO stakes (note_id, validator_id, amount, asset_id, owner_sk, status, staked_at) "
            "VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (note_id, validator_id, row["value"], row["asset_id"], row["owner_sk"], now),
        )
        stake_id = cur.lastrowid

        # Update validator total
        self._conn.execute(
            "UPDATE validators SET total_staked = total_staked + ? WHERE validator_id = ?",
            (row["value"], validator_id),
        )
        self._conn.commit()

        return {
            "stake_id": stake_id,
            "note_id": note_id,
            "validator": val["name"],
            "amount": row["value"],
            "formatted": format_value(row["value"], STAKING_ASSET_ID),
            "staked_at": now,
        }

    def unstake(self, stake_id: int) -> dict:
        """
        Begin unstaking a position. Starts the unbonding period.

        After the delay (UNSTAKING_DELAY), the stake can be withdrawn
        which unlocks the original note.

        Args:
            stake_id: The stake to unstake.

        Returns:
            Dict with unstake details including when withdrawal is available.
        """
        row = self._conn.execute(
            "SELECT s.*, v.name as validator_name, v.commission "
            "FROM stakes s JOIN validators v ON s.validator_id = v.validator_id "
            "WHERE s.stake_id = ?",
            (stake_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"Stake #{stake_id} not found")
        if row["status"] != "active":
            raise ValueError(f"Stake #{stake_id} is '{row['status']}', must be 'active' to unstake")

        now = time.time()

        # Calculate final rewards before unstaking
        reward = calculate_staking_reward(
            row["amount"], row["staked_at"], now, row["commission"]
        )

        # Mark as unstaking
        self._conn.execute(
            "UPDATE stakes SET status = 'unstaking', unstaked_at = ? WHERE stake_id = ?",
            (now, stake_id),
        )

        # Reduce validator total
        self._conn.execute(
            "UPDATE validators SET total_staked = MAX(0, total_staked - ?) WHERE validator_id = ?",
            (row["amount"], row["validator_id"]),
        )
        self._conn.commit()

        withdraw_at = now + UNSTAKING_DELAY
        return {
            "stake_id": stake_id,
            "validator": row["validator_name"],
            "amount": row["amount"],
            "formatted": format_value(row["amount"], STAKING_ASSET_ID),
            "pending_reward": reward,
            "pending_reward_formatted": format_value(reward, STAKING_ASSET_ID),
            "withdraw_available_at": withdraw_at,
            "delay_seconds": UNSTAKING_DELAY,
        }

    def withdraw_stake(self, stake_id: int) -> dict:
        """
        Withdraw an unstaked position after the unbonding period.

        Unlocks the original note back to 'unspent' and mints reward.

        Args:
            stake_id: The stake to withdraw.

        Returns:
            Dict with withdrawal details.
        """
        row = self._conn.execute(
            "SELECT s.*, v.name as validator_name, v.commission "
            "FROM stakes s JOIN validators v ON s.validator_id = v.validator_id "
            "WHERE s.stake_id = ?",
            (stake_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"Stake #{stake_id} not found")
        if row["status"] != "unstaking":
            raise ValueError(f"Stake #{stake_id} is '{row['status']}', must be 'unstaking' to withdraw")

        now = time.time()
        if row["unstaked_at"] + UNSTAKING_DELAY > now:
            remaining = int(row["unstaked_at"] + UNSTAKING_DELAY - now)
            raise ValueError(
                f"Unbonding period not complete. {remaining}s remaining."
            )

        # Calculate final reward (from stake start to unstake time)
        reward = calculate_staking_reward(
            row["amount"], row["staked_at"], row["unstaked_at"], row["commission"]
        )

        # Unlock the original note
        self._conn.execute(
            "UPDATE notes SET state = 'unspent' WHERE note_id = ?",
            (row["note_id"],),
        )

        # Mark stake as withdrawn
        self._conn.execute(
            "UPDATE stakes SET status = 'withdrawn', withdrawn_at = ?, rewards_claimed = ? "
            "WHERE stake_id = ?",
            (now, float(reward), stake_id),
        )
        self._conn.commit()

        return {
            "stake_id": stake_id,
            "note_id": row["note_id"],
            "validator": row["validator_name"],
            "amount": row["amount"],
            "formatted": format_value(row["amount"], STAKING_ASSET_ID),
            "reward": reward,
            "reward_formatted": format_value(reward, STAKING_ASSET_ID),
        }

    def claim_rewards(self, stake_id: int) -> dict:
        """
        Claim accrued rewards on an active stake without unstaking.

        Reward is calculated from time since last claim (or stake start).
        On testnet, rewards are credited directly as a balance adjustment
        recorded in tx_history.

        Args:
            stake_id: The stake to claim rewards for.

        Returns:
            Dict with claim details.
        """
        row = self._conn.execute(
            "SELECT s.*, v.name as validator_name, v.commission "
            "FROM stakes s JOIN validators v ON s.validator_id = v.validator_id "
            "WHERE s.stake_id = ?",
            (stake_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"Stake #{stake_id} not found")
        if row["status"] != "active":
            raise ValueError(f"Stake #{stake_id} is '{row['status']}', must be 'active' to claim")

        now = time.time()

        # Total reward from inception
        total_reward = calculate_staking_reward(
            row["amount"], row["staked_at"], now, row["commission"]
        )
        already_claimed = int(row["rewards_claimed"])
        claimable = total_reward - already_claimed

        if claimable <= 0:
            return {
                "stake_id": stake_id,
                "reward": 0,
                "reward_formatted": format_value(0, STAKING_ASSET_ID),
                "message": "No rewards to claim yet (accruing...)",
            }

        # Record the reward as a note import (testnet credit)
        reward_rho = f"reward_{stake_id}_{int(now)}"
        reward_note = self.import_note(
            sk=row["owner_sk"],
            value=claimable,
            rho=reward_rho,
            asset_id=STAKING_ASSET_ID,
        )

        # Update claimed amount
        self._conn.execute(
            "UPDATE stakes SET rewards_claimed = ? WHERE stake_id = ?",
            (float(total_reward), stake_id),
        )

        # Record in tx_history
        self._conn.execute(
            "INSERT OR REPLACE INTO tx_history (tx_hash, tx_type, status, detail, created_at, confirmed_at) "
            "VALUES (?, 'stake_reward', 'confirmed', ?, ?, ?)",
            (
                f"reward_{stake_id}_{int(now)}",
                json.dumps({
                    "stake_id": stake_id,
                    "validator": row["validator_name"],
                    "reward": claimable,
                    "asset_id": STAKING_ASSET_ID,
                }),
                now, now,
            ),
        )
        self._conn.commit()

        return {
            "stake_id": stake_id,
            "reward": claimable,
            "reward_formatted": format_value(claimable, STAKING_ASSET_ID),
            "note_id": reward_note.note_id,
            "total_claimed": total_reward,
        }

    def get_stakes(self, status: Optional[str] = None) -> List[dict]:
        """
        Return all stake positions, optionally filtered by status.

        Args:
            status: Filter by 'active', 'unstaking', or 'withdrawn'. None = all.

        Returns:
            List of stake detail dicts with accrued reward calculations.
        """
        if status:
            rows = self._conn.execute(
                "SELECT s.*, v.name as validator_name, v.commission "
                "FROM stakes s JOIN validators v ON s.validator_id = v.validator_id "
                "WHERE s.status = ? ORDER BY s.staked_at DESC",
                (status,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT s.*, v.name as validator_name, v.commission "
                "FROM stakes s JOIN validators v ON s.validator_id = v.validator_id "
                "ORDER BY s.staked_at DESC"
            ).fetchall()

        now = time.time()
        result = []
        for r in rows:
            accrued = 0
            if r["status"] == "active":
                accrued = calculate_staking_reward(
                    r["amount"], r["staked_at"], now, r["commission"]
                ) - int(r["rewards_claimed"])
            elif r["status"] == "unstaking":
                accrued = calculate_staking_reward(
                    r["amount"], r["staked_at"], r["unstaked_at"], r["commission"]
                ) - int(r["rewards_claimed"])

            result.append({
                "stake_id": r["stake_id"],
                "note_id": r["note_id"],
                "validator": r["validator_name"],
                "validator_id": r["validator_id"],
                "amount": r["amount"],
                "formatted": format_value(r["amount"], STAKING_ASSET_ID),
                "status": r["status"],
                "staked_at": r["staked_at"],
                "unstaked_at": r["unstaked_at"],
                "accrued_reward": max(0, accrued),
                "accrued_reward_formatted": format_value(max(0, accrued), STAKING_ASSET_ID),
                "total_claimed": int(r["rewards_claimed"]),
            })
        return result

    # ── Epoch & reward distribution ──────────────────────────────────

    def advance_epoch(self) -> dict:
        """
        Close the current epoch and open a new one.

        Calculates the active validator set, distributes rewards proportionally
        to stake weight, and records everything in the epochs / epoch_rewards tables.

        Returns:
            Dict with closed epoch summary including distributed rewards.
        """
        now = time.time()

        # Find current active epoch (if any)
        cur = self._conn.execute(
            "SELECT * FROM epochs WHERE status = 'active' ORDER BY epoch_number DESC LIMIT 1"
        ).fetchone()

        if cur is None:
            # Bootstrap: create epoch 0
            self._conn.execute(
                "INSERT INTO epochs (epoch_number, start_time, total_staked, "
                "active_validators, block_start, status) VALUES (0, ?, 0, 0, 0, 'active')",
                (now,),
            )
            self._conn.commit()
            return {
                "action": "bootstrap",
                "epoch": 0,
                "start_time": now,
                "message": "Epoch 0 started (bootstrap)",
            }

        epoch_num = cur["epoch_number"]
        elapsed = now - cur["start_time"]
        if elapsed < EPOCH_DURATION:
            remaining = EPOCH_DURATION - elapsed
            return {
                "action": "wait",
                "epoch": epoch_num,
                "remaining": round(remaining, 1),
                "message": f"Epoch {epoch_num} still active ({remaining:.0f}s remaining)",
            }

        # ── Close the current epoch ──────────────────────────────────
        active_set = self.get_active_validator_set()
        total_staked = sum(v["total_staked"] for v in active_set)

        rewards_distributed = 0
        reward_details = []

        if total_staked > 0 and active_set:
            for v in active_set:
                # Proportional share of the reward pool
                share = v["total_staked"] / total_staked
                validator_reward = int(REWARD_POOL_PER_EPOCH * share)
                commission_amt = int(validator_reward * v["commission"])
                delegator_reward = validator_reward - commission_amt

                # Record the validator's commission reward
                self._conn.execute(
                    "INSERT INTO epoch_rewards (epoch_number, validator_id, delegator_sk, "
                    "stake_amount, reward_amount, commission_paid, distributed_at) "
                    "VALUES (?, ?, NULL, ?, ?, ?, ?)",
                    (epoch_num, v["validator_id"], v["total_staked"],
                     commission_amt, 0, now),
                )

                # Distribute delegator rewards proportionally
                stakes = self._conn.execute(
                    "SELECT stake_id, owner_sk, amount FROM stakes "
                    "WHERE validator_id = ? AND status = 'active'",
                    (v["validator_id"],),
                ).fetchall()

                for s in stakes:
                    if v["total_staked"] > 0:
                        d_share = s["amount"] / v["total_staked"]
                        d_reward = int(delegator_reward * d_share)
                        if d_reward > 0:
                            self._conn.execute(
                                "INSERT INTO epoch_rewards (epoch_number, validator_id, "
                                "delegator_sk, stake_amount, reward_amount, commission_paid, "
                                "distributed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                (epoch_num, v["validator_id"], s["owner_sk"],
                                 s["amount"], d_reward, commission_amt, now),
                            )
                            # Credit to the stake's claimed rewards
                            self._conn.execute(
                                "UPDATE stakes SET rewards_claimed = rewards_claimed + ? "
                                "WHERE stake_id = ?",
                                (d_reward, s["stake_id"]),
                            )

                rewards_distributed += validator_reward
                reward_details.append({
                    "validator": v["name"],
                    "validator_id": v["validator_id"],
                    "share": round(share * 100, 2),
                    "reward": validator_reward,
                    "commission": commission_amt,
                })

        # Mark epoch closed
        self._conn.execute(
            "UPDATE epochs SET end_time = ?, total_staked = ?, total_rewards = ?, "
            "active_validators = ?, status = 'closed' WHERE epoch_number = ?",
            (now, total_staked, rewards_distributed, len(active_set), epoch_num),
        )

        # Open next epoch
        new_epoch = epoch_num + 1
        self._conn.execute(
            "INSERT INTO epochs (epoch_number, start_time, total_staked, "
            "active_validators, block_start, status) VALUES (?, ?, ?, ?, 0, 'active')",
            (new_epoch, now, total_staked, len(active_set)),
        )
        self._conn.commit()

        return {
            "action": "advanced",
            "closed_epoch": epoch_num,
            "new_epoch": new_epoch,
            "total_staked": total_staked,
            "rewards_distributed": rewards_distributed,
            "active_validators": len(active_set),
            "details": reward_details,
        }

    def get_active_validator_set(self) -> List[dict]:
        """
        Return the current active validator set, ordered by total stake descending.

        Validators must be active (is_active=1) and have at least
        MIN_VALIDATOR_STAKE total delegated to be included.  The set is capped
        at MAX_ACTIVE_VALIDATORS.

        Returns:
            List of validator dicts with total_staked computed from live stakes.
        """
        rows = self._conn.execute(
            "SELECT v.validator_id, v.name, v.commission, v.registered_at, "
            "COALESCE(SUM(CASE WHEN s.status = 'active' THEN s.amount ELSE 0 END), 0) "
            "  AS live_stake "
            "FROM validators v "
            "LEFT JOIN stakes s ON v.validator_id = s.validator_id "
            "WHERE v.is_active = 1 "
            "GROUP BY v.validator_id "
            "HAVING live_stake >= ? "
            "ORDER BY live_stake DESC "
            "LIMIT ?",
            (MIN_VALIDATOR_STAKE, MAX_ACTIVE_VALIDATORS),
        ).fetchall()

        return [
            {
                "validator_id": r["validator_id"],
                "name": r["name"],
                "commission": r["commission"],
                "total_staked": r["live_stake"],
                "registered_at": r["registered_at"],
            }
            for r in rows
        ]

    def slash_validator(self, validator_id: str, reason: str = "downtime") -> dict:
        """
        Slash a validator for misbehaviour, reducing all active delegated stakes.

        Args:
            validator_id: The validator to slash.
            reason: 'downtime' or 'double_sign'.

        Returns:
            Dict with slashing details including amount slashed.
        """
        now = time.time()
        pct = SLASH_DOUBLE_SIGN_PCT if reason == "double_sign" else SLASH_DOWNTIME_PCT

        # Verify validator exists
        v = self._conn.execute(
            "SELECT * FROM validators WHERE validator_id = ?",
            (validator_id,),
        ).fetchone()
        if not v:
            raise ValueError(f"Unknown validator: {validator_id}")

        # Get current epoch number
        cur_epoch = self._conn.execute(
            "SELECT epoch_number FROM epochs WHERE status = 'active' "
            "ORDER BY epoch_number DESC LIMIT 1"
        ).fetchone()
        epoch_num = cur_epoch["epoch_number"] if cur_epoch else 0

        # Slash all active stakes for this validator
        stakes = self._conn.execute(
            "SELECT stake_id, amount FROM stakes "
            "WHERE validator_id = ? AND status = 'active'",
            (validator_id,),
        ).fetchall()

        total_slashed = 0
        for s in stakes:
            slash_amt = int(s["amount"] * pct)
            if slash_amt > 0:
                new_amount = s["amount"] - slash_amt
                self._conn.execute(
                    "UPDATE stakes SET amount = ? WHERE stake_id = ?",
                    (new_amount, s["stake_id"]),
                )
                total_slashed += slash_amt

        # Record slashing event
        self._conn.execute(
            "INSERT INTO slashing_events (validator_id, epoch_number, reason, "
            "slash_pct, amount_slashed, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (validator_id, epoch_num, reason, pct, total_slashed, now),
        )

        # Deactivate on double-sign
        if reason == "double_sign":
            self._conn.execute(
                "UPDATE validators SET is_active = 0 WHERE validator_id = ?",
                (validator_id,),
            )

        self._conn.commit()

        return {
            "validator_id": validator_id,
            "validator": v["name"],
            "reason": reason,
            "slash_pct": pct * 100,
            "total_slashed": total_slashed,
            "formatted": format_value(total_slashed, STAKING_ASSET_ID),
            "deactivated": reason == "double_sign",
            "stakes_affected": len(stakes),
        }

    def get_epoch_info(self, epoch_number: Optional[int] = None) -> dict:
        """
        Return detailed information about an epoch.

        Args:
            epoch_number: Specific epoch to query, or None for the current active epoch.

        Returns:
            Dict with epoch details, reward breakdown, and slashing events.
        """
        if epoch_number is not None:
            row = self._conn.execute(
                "SELECT * FROM epochs WHERE epoch_number = ?",
                (epoch_number,),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM epochs ORDER BY epoch_number DESC LIMIT 1"
            ).fetchone()

        if not row:
            return {"error": "No epochs found. Run 'epoch-advance' to bootstrap."}

        epoch_num = row["epoch_number"]
        now = time.time()
        elapsed = now - row["start_time"] if row["status"] == "active" else (
            row["end_time"] - row["start_time"] if row["end_time"] else 0
        )

        # Reward breakdown for closed epochs
        rewards = []
        if row["status"] == "closed":
            rrows = self._conn.execute(
                "SELECT er.*, v.name as validator_name FROM epoch_rewards er "
                "JOIN validators v ON er.validator_id = v.validator_id "
                "WHERE er.epoch_number = ? ORDER BY er.reward_amount DESC",
                (epoch_num,),
            ).fetchall()
            for rr in rrows:
                rewards.append({
                    "validator": rr["validator_name"],
                    "delegator": rr["delegator_sk"][:12] + "..." if rr["delegator_sk"] else "(commission)",
                    "stake_amount": rr["stake_amount"],
                    "reward": rr["reward_amount"],
                    "formatted_reward": format_value(rr["reward_amount"], STAKING_ASSET_ID),
                })

        # Slashing events
        slashes = self._conn.execute(
            "SELECT se.*, v.name as validator_name FROM slashing_events se "
            "JOIN validators v ON se.validator_id = v.validator_id "
            "WHERE se.epoch_number = ?",
            (epoch_num,),
        ).fetchall()

        return {
            "epoch": epoch_num,
            "status": row["status"],
            "start_time": row["start_time"],
            "end_time": row["end_time"],
            "duration": round(elapsed, 1),
            "total_staked": row["total_staked"],
            "total_staked_formatted": format_value(row["total_staked"], STAKING_ASSET_ID),
            "total_rewards": row["total_rewards"],
            "total_rewards_formatted": format_value(row["total_rewards"], STAKING_ASSET_ID),
            "active_validators": row["active_validators"],
            "rewards": rewards,
            "slashing_events": [
                {
                    "validator": s["validator_name"],
                    "reason": s["reason"],
                    "pct": s["slash_pct"] * 100,
                    "slashed": format_value(s["amount_slashed"], STAKING_ASSET_ID),
                }
                for s in slashes
            ],
        }

    def get_reward_history(self, limit: int = 50) -> List[dict]:
        """
        Return recent epoch reward distributions across all epochs.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of reward dicts ordered by most recent first.
        """
        rows = self._conn.execute(
            "SELECT er.*, v.name as validator_name FROM epoch_rewards er "
            "JOIN validators v ON er.validator_id = v.validator_id "
            "ORDER BY er.distributed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

        return [
            {
                "epoch": r["epoch_number"],
                "validator": r["validator_name"],
                "delegator": r["delegator_sk"][:12] + "..." if r["delegator_sk"] else "(commission)",
                "stake_amount": r["stake_amount"],
                "reward": r["reward_amount"],
                "formatted_reward": format_value(r["reward_amount"], STAKING_ASSET_ID),
                "commission_paid": r["commission_paid"],
                "distributed_at": r["distributed_at"],
            }
            for r in rows
        ]

    # ── Scan key management ─────────────────────────────────────────

    def register_scan_key(self, spending_sk: str) -> str:
        """
        Register a spending key for incoming note scanning.

        Derives an X25519 keypair from the spending key and stores it.
        Returns the scan public key (hex) that senders must use.
        """
        scan_sk, scan_pk = _derive_scan_keypair(spending_sk)
        scan_pk_hex = "0x" + scan_pk.hex()

        self._conn.execute(
            """INSERT OR IGNORE INTO scan_keys
               (spending_sk, scan_sk, scan_pk, scan_pk_hex, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (spending_sk, scan_sk, scan_pk, scan_pk_hex, time.time()),
        )
        self._conn.commit()
        return scan_pk_hex

    def get_scan_keys(self) -> List[dict]:
        """Return all registered scan keys."""
        rows = self._conn.execute(
            "SELECT spending_sk, scan_pk_hex FROM scan_keys ORDER BY created_at"
        ).fetchall()
        return [{"spending_sk": r["spending_sk"], "scan_pk_hex": r["scan_pk_hex"]} for r in rows]

    def get_scan_pk_for_sk(self, spending_sk: str) -> Optional[str]:
        """Get the scan public key for a spending key, or None."""
        row = self._conn.execute(
            "SELECT scan_pk_hex FROM scan_keys WHERE spending_sk = ?",
            (spending_sk,),
        ).fetchone()
        return row["scan_pk_hex"] if row else None

    def _get_scan_progress(self) -> int:
        """Get the last scanned leaf index."""
        row = self._conn.execute(
            "SELECT value FROM scan_progress WHERE key = 'last_scanned_index'"
        ).fetchone()
        return row["value"] if row else 0

    def _set_scan_progress(self, index: int):
        """Update the last scanned leaf index."""
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_progress (key, value) VALUES ('last_scanned_index', ?)",
            (index,),
        )
        self._conn.commit()

    # ── Encrypted note storage (sender side) ─────────────────────────

    def _store_encrypted_note(
        self,
        leaf_index: int,
        recipient_scan_pk_hex: str,
        value: int,
        asset_id: str,
        rho: str,
        owner_pk_x: str,
        owner_pk_y: str,
    ):
        """
        Encrypt note data and store on the node for the recipient to scan.

        Called by send/split/merge after confirming the transaction.
        """
        scan_pk_clean = recipient_scan_pk_hex.replace("0x", "")
        scan_pk_bytes = bytes.fromhex(scan_pk_clean)
        ct = encrypt_note_data(scan_pk_bytes, value, asset_id, rho, owner_pk_x, owner_pk_y)
        ct_hex = "0x" + ct.hex()

        try:
            self.client.store_encrypted_notes([{
                "leaf_index": leaf_index,
                "ciphertext": ct_hex,
            }])
        except Exception as e:
            # Non-fatal: the transfer succeeded even if note storage fails
            print(f"  ⚠ Failed to store encrypted note on node: {e}")

    def _store_encrypted_notes_batch(
        self,
        entries: List[dict],
    ):
        """
        Store multiple encrypted notes in one RPC call.

        Each entry: {"leaf_index": int, "scan_pk_hex": str, "value": int,
                      "asset_id": str, "rho": str, "pk_x": str, "pk_y": str}
        """
        rpc_entries = []
        for e in entries:
            scan_pk_bytes = bytes.fromhex(e["scan_pk_hex"].replace("0x", ""))
            ct = encrypt_note_data(
                scan_pk_bytes, e["value"], e["asset_id"],
                e["rho"], e["pk_x"], e["pk_y"],
            )
            rpc_entries.append({
                "leaf_index": e["leaf_index"],
                "ciphertext": "0x" + ct.hex(),
            })

        try:
            self.client.store_encrypted_notes(rpc_entries)
        except Exception as e:
            print(f"  ⚠ Failed to store encrypted notes on node: {e}")

    # ── Scan (receiver side) ─────────────────────────────────────────

    def scan(self, batch_size: int = 256) -> dict:
        """
        Scan the node for incoming notes.

        Fetches encrypted note ciphertexts from the node starting at the
        last scanned leaf index, trial-decrypts each with all registered
        scan keys, verifies the commitment matches, and auto-imports.

        Returns:
            {"scanned": int, "found": int, "imported": list, "up_to_index": int}
        """
        scan_key_rows = self._conn.execute(
            "SELECT spending_sk, scan_sk, scan_pk_hex FROM scan_keys"
        ).fetchall()
        if not scan_key_rows:
            return {"scanned": 0, "found": 0, "imported": [], "up_to_index": 0,
                    "error": "No scan keys registered. Use register-key first."}

        from_index = self._get_scan_progress()
        result = self.client.get_encrypted_notes(from_index, batch_size)
        leaf_count = result["leaf_count"]
        enc_notes = result["notes"]

        found = 0
        imported_notes = []

        for entry in enc_notes:
            leaf_idx = entry["leaf_index"]
            ct_hex = entry["ciphertext"]
            ct_bytes = bytes.fromhex(ct_hex.replace("0x", ""))

            for row in scan_key_rows:
                scan_sk = bytes(row["scan_sk"])
                spending_sk = row["spending_sk"]

                data = decrypt_note_data(scan_sk, ct_bytes)
                if data is None:
                    continue

                # Decrypted! Verify commitment matches on-chain leaf.
                value = data["v"]
                asset_id = data["a"]
                rho = data["r"]
                pk_x = data["px"]
                pk_y = data["py"]

                # Compute expected commitment
                cm = self.crypto.commitment(str(value), asset_id, pk_x, pk_y, rho)
                nf = self.crypto.nullifier(cm, spending_sk)

                # Check if we already have this note
                existing = self._conn.execute(
                    "SELECT note_id FROM notes WHERE commitment = ?", (cm,)
                ).fetchone()
                if existing:
                    break  # Already imported

                # Import the note
                note = self._insert_note(
                    tree_index=leaf_idx,
                    value=value,
                    asset_id=asset_id,
                    owner_sk=spending_sk,
                    owner_pk_x=pk_x,
                    owner_pk_y=pk_y,
                    rho=rho,
                    commitment=cm,
                    nullifier=nf,
                )
                found += 1
                imported_notes.append({
                    "note_id": note.note_id,
                    "value": value,
                    "tree_index": leaf_idx,
                    "asset_id": asset_id,
                })
                break  # Found the right key, move to next note

        # Update scan progress to the current leaf count
        self._set_scan_progress(leaf_count)

        return {
            "scanned": len(enc_notes),
            "found": found,
            "imported": imported_notes,
            "up_to_index": leaf_count,
        }

    def _resolve_scan_pk(self, pk_x: str = None, pk_y: str = None,
                          spending_sk: str = None) -> Optional[str]:
        """
        Resolve a scan public key from either a spending key or pk coordinates.

        If we have the spending_sk, derive the scan_pk directly.
        Otherwise, check if any registered scan key matches the pk.
        Returns hex scan_pk or None.
        """
        if spending_sk:
            try:
                _, scan_pk = _derive_scan_keypair(spending_sk)
                return "0x" + scan_pk.hex()
            except Exception:
                return None
        return None

    # ── Transfer (2-in / 2-out) ───────────────────────────────────────

    def send(
        self,
        to_pk_x: str,
        to_pk_y: str,
        to_value: int,
        from_note_ids: Optional[List[int]] = None,
        sender_sk: Optional[str] = None,
        recipient_sk: Optional[str] = None,
        change_sk: Optional[str] = None,
        change_rho: Optional[str] = None,
        out1_rho: Optional[str] = None,
        asset_id: str = DEFAULT_ASSET_ID,
        fee: int = 0,
        auto_block: bool = True,
    ) -> dict:
        """
        Execute a shielded transfer: build witness → prove → submit → block.

        Fully automatic — just specify amount and recipient. The wallet handles
        coin selection, dummy note padding for single-input transfers, witness
        building, proof generation (with retry), submission, and state updates.

        Args:
            to_pk_x/to_pk_y: Recipient public key.
            to_value: Amount to send to recipient.
            from_note_ids: Optional list of 1-2 note IDs to spend.
                           If None, notes are auto-selected.
            sender_sk: When auto-selecting, only use notes owned by this key.
            change_sk: SK for the change output (defaults to first input's sk).
            change_rho: Rho for the change output (auto-generated if None).
            out1_rho: Rho for the recipient output (auto-generated if None).
            asset_id: Asset ID.
            fee: Transaction fee.
            auto_block: If True, produce a block after submitting.

        Returns dict with tx_hash, proof info, and new note details.
        """
        # Transfer circuit requires out1_value != 0
        if to_value == 0:
            raise ValueError("Transfer primary output must be non-zero")

        # ── Coin selection ────────────────────────────────────────────
        if from_note_ids is not None:
            assert 1 <= len(from_note_ids) <= 2, "Transfer needs 1-2 input notes"
            inputs = []
            for nid in from_note_ids:
                note = self.get_note(nid)
                if note is None:
                    raise ValueError(f"Note #{nid} not found")
                if note.state != "unspent":
                    raise ValueError(f"Note #{nid} is {note.state}, not unspent")
                if note.tree_index is None:
                    raise ValueError(f"Note #{nid} has no tree_index — run sync or set it")
                inputs.append(note)
        else:
            # Auto coin selection
            print("  Selecting notes...")
            inputs = self.select_notes(
                amount=to_value + fee,
                asset_id=asset_id,
                sender_sk=sender_sk,
            )
            print(f"  ✓ Selected {len(inputs)} note(s): "
                  + ", ".join(f"#{n.note_id}({n.value})" for n in inputs))

        # Cross-asset safety: all inputs must match the requested asset
        for n in inputs:
            if n.asset_id != asset_id:
                raise ValueError(
                    f"Note #{n.note_id} is {asset_symbol(n.asset_id)} "
                    f"but transfer is for {asset_symbol(asset_id)}. "
                    f"Use --asset-id {n.asset_id} or select different notes."
                )

        # Value conservation
        total_in = sum(n.value for n in inputs)
        change_value = total_in - to_value - fee
        if change_value < 0:
            raise ValueError(
                f"Insufficient value: inputs={total_in}, send={to_value}, fee={fee}"
            )

        if change_sk is None:
            change_sk = inputs[0].owner_sk
        change_pk_x, change_pk_y = self.crypto.derive_pk(change_sk)

        if out1_rho is None:
            out1_rho = str(int(time.time() * 1000) % 10**9 + 1)
        if change_rho is None:
            change_rho = str(int(time.time() * 1000) % 10**9 + 2)

        # ── Single-input: pad with zero-value dummy or re-select pair ─
        dummy_note = None
        if len(inputs) == 1:
            dummy_note = self._find_dummy_note(
                owner_sk=inputs[0].owner_sk,
                asset_id=asset_id,
            )
            if dummy_note is not None:
                inputs.append(dummy_note)
                print(f"  ✓ Using dummy note #{dummy_note.note_id} (value=0, index={dummy_note.tree_index}) as second input")
            elif from_note_ids is None:
                # Auto-selection picked 1 note but no dummy exists for its key.
                # Strategy 1: Re-select forcing a 2-note pair.
                try:
                    print("  No dummy note available, re-selecting as pair...")
                    inputs = self.select_notes(
                        amount=to_value + fee,
                        asset_id=asset_id,
                        sender_sk=sender_sk,
                        force_pair=True,
                    )
                    print(f"  ✓ Re-selected {len(inputs)} note(s): "
                          + ", ".join(f"#{n.note_id}({n.value})" for n in inputs))
                    # Recalculate change with new inputs
                    total_in = sum(n.value for n in inputs)
                    change_value = total_in - to_value - fee
                    change_sk = inputs[0].owner_sk
                    change_pk_x, change_pk_y = self.crypto.derive_pk(change_sk)
                except ValueError:
                    # Strategy 2: No pair available either. Try a dummy from
                    # ANY key — the circuit allows mixed-owner inputs.
                    print("  No pair available, searching for any dummy note...")
                    any_dummy = self._find_any_dummy_note(asset_id=asset_id)
                    if any_dummy is not None:
                        inputs.append(any_dummy)
                        print(f"  ✓ Using cross-key dummy #{any_dummy.note_id} "
                              f"(owner={any_dummy.owner_sk[:10]}..., index={any_dummy.tree_index})")
                    else:
                        raise ValueError(
                            "Single-input transfer needs a second input but no "
                            "dummy note or second note is available. Run a split "
                            "first to create padding notes."
                        )
            else:
                raise ValueError(
                    "Single-input transfer needs a zero-value dummy note in the "
                    "tree (owned by the same key). Run a split first to create "
                    "padding notes, or provide 2 note IDs manually."
                )

        in1, in2 = inputs[0], inputs[1]

        # Compute nullifiers and output commitments
        nf_1 = self.crypto.nullifier(in1.commitment, in1.owner_sk)
        nf_2 = self.crypto.nullifier(in2.commitment, in2.owner_sk)

        cm_out_1 = self.crypto.commitment(
            str(to_value), asset_id, to_pk_x, to_pk_y, out1_rho,
        )
        cm_out_2 = self.crypto.commitment(
            str(change_value), asset_id, change_pk_x, change_pk_y, change_rho,
        )

        # Build witness from live node state
        builder = WitnessBuilder(self.client)
        transfer_inputs = [
            NoteInput(
                index=in1.tree_index, value=in1.value,
                owner_sk=in1.owner_sk,
                owner_pk_x=in1.owner_pk_x, owner_pk_y=in1.owner_pk_y,
                rho=in1.rho,
            ),
            NoteInput(
                index=in2.tree_index, value=in2.value,
                owner_sk=in2.owner_sk,
                owner_pk_x=in2.owner_pk_x, owner_pk_y=in2.owner_pk_y,
                rho=in2.rho,
            ),
        ]
        transfer_outputs = [
            NoteOutput(value=to_value, owner_pk_x=to_pk_x, owner_pk_y=to_pk_y, rho=out1_rho),
            NoteOutput(value=change_value, owner_pk_x=change_pk_x, owner_pk_y=change_pk_y, rho=change_rho),
        ]

        print("  Building witness from node state...")
        witness_json = builder.build_transfer(
            inputs=transfer_inputs,
            outputs=transfer_outputs,
            fee=fee,
            asset_id=asset_id,
            nf_1=nf_1, nf_2=nf_2,
            cm_out_1=cm_out_1, cm_out_2=cm_out_2,
            output_format="json",
        )

        # Prove via obscura-prover (with retry)
        print("  Generating transfer proof...")
        proof_dir = Path(tempfile.mkdtemp(prefix="obscura-wallet-xfer-"))
        output_dir = proof_dir / "output"
        output_dir.mkdir()

        try:
            self._run_prover_with_retry(
                cmd=[
                    str(PROVER_BIN), "prove",
                    "-c", str(TRANSFER_CIRCUIT),
                    "-o", str(output_dir),
                    "-k", str(TRANSFER_VK),
                ],
                stdin_data=witness_json,
                label="transfer proof",
            )
        except RuntimeError:
            subprocess.run(["rm", "-rf", str(proof_dir)], check=False)
            raise

        proof_path = output_dir / "proof" / "proof"
        pi_path = output_dir / "proof" / "public_inputs"
        print("  ✓ Proof generated")

        # Submit to node
        print("  Submitting to node...")
        merkle_root = self.client.get_merkle_root()
        tx_result = self.client.submit_from_proof_files(
            tx_type="transfer",
            proof_path=str(proof_path),
            public_inputs_path=str(pi_path),
            new_commitments=[cm_out_1, cm_out_2],
            nullifiers=[nf_1, nf_2],
            merkle_root=merkle_root,
            fee=fee,
        )
        print(f"  ✓ TX accepted: {tx_result.tx_hash[:24]}...")

        # Record pending TX for crash recovery (before any state changes)
        input_note_ids = [n.note_id for n in inputs]
        self._record_pending_tx(
            tx_hash=tx_result.tx_hash,
            tx_type="transfer",
            input_ids=input_note_ids,
            detail={"to_value": to_value, "change_value": change_value, "asset_id": asset_id},
        )

        # Produce block if requested
        block_num = None
        if auto_block:
            header = self.client.produce_block()
            block_num = header.block_number
            print(f"  ✓ Block {block_num} produced")

        # Update local state
        now = time.time()
        spent_ids = []
        for note in inputs:
            self._conn.execute(
                "UPDATE notes SET state = 'spent', spent_at = ?, spent_in_tx = ? WHERE note_id = ?",
                (now, tx_result.tx_hash, note.note_id),
            )
            spent_ids.append(note.note_id)

        # Record the change note
        status = self.client.get_status()
        # Change note is the second output, so its tree index = leaf_count - 1
        # Recipient note is at leaf_count - 2
        recipient_tree_idx = status.leaf_count - 2
        change_tree_idx = status.leaf_count - 1

        change_note = None
        if change_value > 0:
            change_note = self._insert_note(
                tree_index=change_tree_idx,
                value=change_value,
                asset_id=asset_id,
                owner_sk=change_sk,
                owner_pk_x=change_pk_x,
                owner_pk_y=change_pk_y,
                rho=change_rho,
                commitment=cm_out_2,
                nullifier=self.crypto.nullifier(cm_out_2, change_sk),
            )

        # Store encrypted notes on the node for recipient scanning
        if HAS_NACL:
            enc_entries = []
            # Recipient output — encrypt for whoever owns to_pk
            # The sender needs to know the recipient's scan_pk. We look it
            # up from to_pk or just encrypt with to_pk-derived scan key.
            # For now, we encrypt using the recipient's pk coordinates as
            # the lookup key — if the sender passed a --to-sk, the recipient
            # can register that sk's scan key.
            # We store for ALL outputs so the recipient can scan.
            enc_entries.append({
                "leaf_index": recipient_tree_idx,
                "scan_pk_hex": self._resolve_scan_pk(spending_sk=recipient_sk),
                "value": to_value,
                "asset_id": asset_id,
                "rho": out1_rho,
                "pk_x": to_pk_x,
                "pk_y": to_pk_y,
            })
            # Change output — encrypt for change key owner
            if change_value >= 0:
                change_scan_pk = self.get_scan_pk_for_sk(change_sk)
                if change_scan_pk:
                    enc_entries.append({
                        "leaf_index": change_tree_idx,
                        "scan_pk_hex": change_scan_pk,
                        "value": change_value,
                        "asset_id": asset_id,
                        "rho": change_rho,
                        "pk_x": change_pk_x,
                        "pk_y": change_pk_y,
                    })
            # Filter out entries without scan_pk
            enc_entries = [e for e in enc_entries if e.get("scan_pk_hex")]
            if enc_entries:
                self._store_encrypted_notes_batch(enc_entries)

        # Record tx
        self._conn.execute(
            """INSERT OR REPLACE INTO tx_history
               (tx_hash, tx_type, status, detail, created_at, confirmed_at)
               VALUES (?, 'transfer', 'confirmed', ?, ?, ?)""",
            (tx_result.tx_hash,
             json.dumps({
                 "inputs": spent_ids,
                 "to_value": to_value, "change_value": change_value,
                 "fee": fee,
                 "auto_selected": from_note_ids is None,
                 "used_dummy": dummy_note is not None,
             }),
             now, now if auto_block else None),
        )
        self._conn.commit()

        # State fully updated — clear pending record
        self._clear_pending_tx(tx_result.tx_hash)

        # Cleanup proof dir
        subprocess.run(["rm", "-rf", str(proof_dir)], check=False)

        return {
            "tx_hash": tx_result.tx_hash,
            "block_number": block_num,
            "inputs_spent": spent_ids,
            "to_value": to_value,
            "change_value": change_value,
            "change_note_id": change_note.note_id if change_note else None,
            "recipient_tree_index": recipient_tree_idx,
            "change_tree_index": change_tree_idx,
            "out1_rho": out1_rho,
            "change_rho": change_rho,
        }

    # ── Split (1-in / 32-out) ─────────────────────────────────────────

    def split(
        self,
        note_id: int,
        values: List[int],
        recipients: Optional[List[Tuple[str, str]]] = None,
        rho_base: Optional[int] = None,
        asset_id: str = DEFAULT_ASSET_ID,
        fee: int = 0,
        auto_block: bool = True,
    ) -> dict:
        """
        Split a note into multiple outputs.

        Args:
            note_id: Note to split.
            values: List of output values (up to 32). Padded with zeros.
            recipients: Optional list of (pk_x, pk_y) for each output.
                        If None, all outputs go to the input note's owner.
            rho_base: Base rho for outputs (rho_base+0, rho_base+1, ...).
            fee: Transaction fee.
            auto_block: If True, produce a block after submitting.

        Returns dict with tx_hash and new note details.
        """
        note = self.get_note(note_id)
        if note is None:
            raise ValueError(f"Note #{note_id} not found")
        if note.state != "unspent":
            raise ValueError(f"Note #{note_id} is {note.state}, not unspent")
        if note.tree_index is None:
            raise ValueError(f"Note #{note_id} has no tree_index")
        if len(values) > 32:
            raise ValueError(f"Split supports up to 32 outputs, got {len(values)}")

        # Cross-asset safety: input note must match requested asset
        if note.asset_id != asset_id:
            raise ValueError(
                f"Note #{note_id} is {asset_symbol(note.asset_id)} "
                f"but split is for {asset_symbol(asset_id)}. "
                f"Use --asset-id {note.asset_id}."
            )

        total_out = sum(values)
        if total_out + fee != note.value:
            raise ValueError(
                f"Value mismatch: input={note.value}, "
                f"outputs={total_out}, fee={fee}, "
                f"need outputs+fee={total_out+fee}"
            )

        if rho_base is None:
            rho_base = int(time.time() * 1000) % 10**9

        owner_pk_x, owner_pk_y = note.owner_pk_x, note.owner_pk_y

        # Build 32 output notes
        split_outputs = []
        split_out_cms = []
        for i in range(32):
            v = values[i] if i < len(values) else 0
            rho = str(rho_base + i)

            if recipients and i < len(recipients):
                px, py = recipients[i]
            else:
                px, py = owner_pk_x, owner_pk_y

            split_outputs.append(NoteOutput(value=v, owner_pk_x=px, owner_pk_y=py, rho=rho))
            cm = self.crypto.commitment(str(v), asset_id, px, py, rho)
            split_out_cms.append(cm)

        # Compute nullifier
        nf = self.crypto.nullifier(note.commitment, note.owner_sk)

        # Build witness (TOML for nargo)
        print("  Building split witness from node state...")
        builder = WitnessBuilder(self.client)
        split_input = NoteInput(
            index=note.tree_index, value=note.value,
            owner_sk=note.owner_sk,
            owner_pk_x=owner_pk_x, owner_pk_y=owner_pk_y,
            rho=note.rho,
        )
        split_toml = builder.build_split(
            input_note=split_input,
            outputs=split_outputs,
            fee=fee,
            asset_id=asset_id,
            nf=nf,
            cm_outs=split_out_cms,
            output_format="toml",
        )

        # Write Prover.toml, nargo execute, bb prove
        print("  Generating split proof (nargo execute + bb prove)...")
        prover_toml = SPLIT_DIR / "Prover.toml"
        prover_toml.write_text(split_toml)

        try:
            witness_gz = self._nargo_execute(SPLIT_DIR, "split_wallet")
            split_vk = find_vk("obscura-split")
            proof_dir = Path(tempfile.mkdtemp(prefix="obscura-wallet-split-"))
            proof_path, pi_path = self._bb_prove(SPLIT_CIRCUIT, witness_gz, split_vk, proof_dir)
            print("  ✓ Split proof generated")
        finally:
            prover_toml.unlink(missing_ok=True)

        # Submit
        print("  Submitting split proof to node...")
        merkle_root = self.client.get_merkle_root()
        tx_result = self.client.submit_from_proof_files(
            tx_type="split",
            proof_path=str(proof_path),
            public_inputs_path=str(pi_path),
            new_commitments=split_out_cms,
            nullifiers=[nf],
            merkle_root=merkle_root,
            fee=fee,
        )
        print(f"  ✓ TX accepted: {tx_result.tx_hash[:24]}...")

        # Record pending TX for crash recovery
        self._record_pending_tx(
            tx_hash=tx_result.tx_hash,
            tx_type="split",
            input_ids=[note.note_id],
            detail={"values": values, "asset_id": asset_id},
        )

        block_num = None
        if auto_block:
            header = self.client.produce_block()
            block_num = header.block_number
            print(f"  ✓ Block {block_num} produced")

        # Update local state
        now = time.time()
        self._conn.execute(
            "UPDATE notes SET state = 'spent', spent_at = ?, spent_in_tx = ? WHERE note_id = ?",
            (now, tx_result.tx_hash, note.note_id),
        )

        # Record new output notes
        status = self.client.get_status()
        base_idx = status.leaf_count - 32  # split adds 32 leaves
        new_notes = []
        for i in range(32):
            v = values[i] if i < len(values) else 0
            rho = str(rho_base + i)
            if recipients and i < len(recipients):
                px, py = recipients[i]
                # We don't know the recipient's sk, can't track these
                sk = note.owner_sk if (px == owner_pk_x and py == owner_pk_y) else ""
            else:
                px, py = owner_pk_x, owner_pk_y
                sk = note.owner_sk

            if sk:  # only track notes we own
                new_note = self._insert_note(
                    tree_index=base_idx + i,
                    value=v,
                    asset_id=asset_id,
                    owner_sk=sk,
                    owner_pk_x=px,
                    owner_pk_y=py,
                    rho=rho,
                    commitment=split_out_cms[i],
                    nullifier=self.crypto.nullifier(split_out_cms[i], sk),
                )
                new_notes.append(new_note)

        # Store encrypted notes for split outputs (self-owned)
        if HAS_NACL:
            scan_pk = self.get_scan_pk_for_sk(note.owner_sk)
            if scan_pk:
                enc_entries = []
                for i in range(32):
                    v = values[i] if i < len(values) else 0
                    rho_str = str(rho_base + i)
                    enc_entries.append({
                        "leaf_index": base_idx + i,
                        "scan_pk_hex": scan_pk,
                        "value": v,
                        "asset_id": asset_id,
                        "rho": rho_str,
                        "pk_x": owner_pk_x,
                        "pk_y": owner_pk_y,
                    })
                self._store_encrypted_notes_batch(enc_entries)

        self._conn.execute(
            """INSERT OR REPLACE INTO tx_history
               (tx_hash, tx_type, status, detail, created_at, confirmed_at)
               VALUES (?, 'split', 'confirmed', ?, ?, ?)""",
            (tx_result.tx_hash,
             json.dumps({"input": note_id, "values": values, "fee": fee, "asset_id": asset_id}),
             now, now if auto_block else None),
        )
        self._conn.commit()

        # State fully updated — clear pending record
        self._clear_pending_tx(tx_result.tx_hash)

        subprocess.run(["rm", "-rf", str(proof_dir)], check=False)

        return {
            "tx_hash": tx_result.tx_hash,
            "block_number": block_num,
            "input_spent": note_id,
            "new_notes": [(n.note_id, n.value, n.tree_index) for n in new_notes],
        }

    # ── Merge (32-in / 1-out) ─────────────────────────────────────────

    def merge(
        self,
        note_ids: List[int],
        out_rho: Optional[str] = None,
        asset_id: str = DEFAULT_ASSET_ID,
        fee: int = 0,
        auto_block: bool = True,
    ) -> dict:
        """
        Merge multiple notes into one.

        All notes must be owned by the same spending key. Padded to 32
        inputs with zero-value notes if fewer than 32 are provided.
        The zero-value padding notes must exist in the tree.

        Args:
            note_ids: List of note IDs to merge (1-32).
            out_rho: Rho for the output note (auto-generated if None).
            fee: Transaction fee.
            auto_block: If True, produce a block after submitting.
        """
        assert 1 <= len(note_ids) <= 32, f"Merge accepts 1-32 inputs, got {len(note_ids)}"

        notes = []
        for nid in note_ids:
            note = self.get_note(nid)
            if note is None:
                raise ValueError(f"Note #{nid} not found")
            if note.state != "unspent":
                raise ValueError(f"Note #{nid} is {note.state}, not unspent")
            if note.tree_index is None:
                raise ValueError(f"Note #{nid} has no tree_index")
            notes.append(note)

        # All must share the same sk
        owner_sk = notes[0].owner_sk
        for n in notes[1:]:
            if n.owner_sk != owner_sk:
                raise ValueError(
                    f"Merge requires all inputs to share the same sk. "
                    f"Note #{n.note_id} has sk={n.owner_sk[:10]}... "
                    f"but expected {owner_sk[:10]}..."
                )

        # All must share the same asset_id
        note_asset = notes[0].asset_id
        for n in notes[1:]:
            if n.asset_id != note_asset:
                raise ValueError(
                    f"Merge requires all inputs to share the same asset. "
                    f"Note #{n.note_id} is {asset_symbol(n.asset_id)} "
                    f"but expected {asset_symbol(note_asset)}."
                )
        # Use the notes' actual asset_id (override the parameter)
        asset_id = note_asset

        total_value = sum(n.value for n in notes)
        out_value = total_value - fee
        if out_value < 0:
            raise ValueError(f"Fee ({fee}) exceeds total input ({total_value})")

        if out_rho is None:
            out_rho = str(int(time.time() * 1000) % 10**9)

        owner_pk_x, owner_pk_y = notes[0].owner_pk_x, notes[0].owner_pk_y

        # Compute output commitment
        cm_out = self.crypto.commitment(
            str(out_value), asset_id, owner_pk_x, owner_pk_y, out_rho,
        )

        # Compute all nullifiers
        merge_inputs = []
        merge_nfs = []
        for n in notes:
            nf = self.crypto.nullifier(n.commitment, n.owner_sk)
            merge_nfs.append(nf)
            merge_inputs.append(NoteInput(
                index=n.tree_index, value=n.value,
                owner_sk=n.owner_sk,
                owner_pk_x=n.owner_pk_x, owner_pk_y=n.owner_pk_y,
                rho=n.rho,
            ))

        # Build witness (TOML for nargo)
        print(f"  Building merge witness ({len(notes)} inputs, total={total_value})...")
        builder = WitnessBuilder(self.client)
        merge_toml = builder.build_merge(
            inputs=merge_inputs,
            out_rho=out_rho,
            fee=fee,
            asset_id=asset_id,
            nullifiers=merge_nfs,
            cm_out=cm_out,
            output_format="toml",
        )

        # Write Prover.toml, nargo execute, bb prove
        print("  Generating merge proof (nargo execute + bb prove)...")
        prover_toml = MERGE_DIR / "Prover.toml"
        prover_toml.write_text(merge_toml)

        try:
            witness_gz = self._nargo_execute(MERGE_DIR, "merge_wallet")
            merge_vk = find_vk("obscura-merge")
            proof_dir = Path(tempfile.mkdtemp(prefix="obscura-wallet-merge-"))
            proof_path, pi_path = self._bb_prove(MERGE_CIRCUIT, witness_gz, merge_vk, proof_dir)
            print("  ✓ Merge proof generated")
        finally:
            prover_toml.unlink(missing_ok=True)

        # Submit
        print("  Submitting merge proof to node...")
        merkle_root = self.client.get_merkle_root()
        tx_result = self.client.submit_from_proof_files(
            tx_type="merge",
            proof_path=str(proof_path),
            public_inputs_path=str(pi_path),
            new_commitments=[cm_out],
            nullifiers=merge_nfs,
            merkle_root=merkle_root,
            fee=fee,
        )
        print(f"  ✓ TX accepted: {tx_result.tx_hash[:24]}...")

        # Record pending TX for crash recovery
        self._record_pending_tx(
            tx_hash=tx_result.tx_hash,
            tx_type="merge",
            input_ids=note_ids,
            detail={"out_value": out_value, "asset_id": asset_id},
        )

        block_num = None
        if auto_block:
            header = self.client.produce_block()
            block_num = header.block_number
            print(f"  ✓ Block {block_num} produced")

        # Update local state
        now = time.time()
        for n in notes:
            self._conn.execute(
                "UPDATE notes SET state = 'spent', spent_at = ?, spent_in_tx = ? WHERE note_id = ?",
                (now, tx_result.tx_hash, n.note_id),
            )

        status = self.client.get_status()
        out_tree_idx = status.leaf_count - 1

        out_note = self._insert_note(
            tree_index=out_tree_idx,
            value=out_value,
            asset_id=asset_id,
            owner_sk=owner_sk,
            owner_pk_x=owner_pk_x,
            owner_pk_y=owner_pk_y,
            rho=out_rho,
            commitment=cm_out,
            nullifier=self.crypto.nullifier(cm_out, owner_sk),
        )

        # Store encrypted note for merge output (self-owned)
        if HAS_NACL:
            scan_pk = self.get_scan_pk_for_sk(owner_sk)
            if scan_pk:
                self._store_encrypted_note(
                    leaf_index=out_tree_idx,
                    recipient_scan_pk_hex=scan_pk,
                    value=out_value,
                    asset_id=asset_id,
                    rho=out_rho,
                    owner_pk_x=owner_pk_x,
                    owner_pk_y=owner_pk_y,
                )

        self._conn.execute(
            """INSERT OR REPLACE INTO tx_history
               (tx_hash, tx_type, status, detail, created_at, confirmed_at)
               VALUES (?, 'merge', 'confirmed', ?, ?, ?)""",
            (tx_result.tx_hash,
             json.dumps({"inputs": note_ids, "out_value": out_value, "fee": fee, "asset_id": asset_id}),
             now, now if auto_block else None),
        )
        self._conn.commit()

        # State fully updated — clear pending record
        self._clear_pending_tx(tx_result.tx_hash)

        subprocess.run(["rm", "-rf", str(proof_dir)], check=False)

        return {
            "tx_hash": tx_result.tx_hash,
            "block_number": block_num,
            "inputs_spent": [n.note_id for n in notes],
            "out_note_id": out_note.note_id,
            "out_value": out_value,
            "out_tree_index": out_tree_idx,
        }

    # ── Proof generation helpers ──────────────────────────────────────

    def _nargo_execute(self, circuit_dir: Path, witness_name: str) -> Path:
        result = subprocess.run(
            ["nargo", "execute", witness_name],
            cwd=str(circuit_dir),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"nargo execute failed in {circuit_dir.name}:\n"
                f"{result.stderr[-500:]}"
            )
        path = circuit_dir / "target" / f"{witness_name}.gz"
        if not path.exists():
            raise FileNotFoundError(f"Witness not found: {path}")
        return path

    def _bb_prove(
        self,
        circuit_json: Path,
        witness_gz: Path,
        vk_path: Path,
        output_dir: Path,
    ) -> Tuple[Path, Path]:
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
            raise RuntimeError(f"bb prove failed:\n{result.stderr[-500:]}")

        proof_path = proof_dir / "proof"
        pi_path = proof_dir / "public_inputs"
        if not proof_path.exists() or not pi_path.exists():
            raise FileNotFoundError(f"Proof artifacts missing in {proof_dir}")
        return proof_path, pi_path


# ─────────────────────────────────────────────────────────────────────
# Background Scanner
# ─────────────────────────────────────────────────────────────────────

class BackgroundScanner:
    """
    Polls the node for new encrypted notes on a background thread.

    Runs wallet.scan() every `interval` seconds, invoking an optional
    callback whenever new notes are found. Thread-safe start/stop.

    Usage:
        scanner = BackgroundScanner(wallet, interval=15)
        scanner.on_notes_found = lambda notes: print(f"Found {len(notes)} notes!")
        scanner.start()
        # ... later ...
        scanner.stop()
    """

    def __init__(
        self,
        wallet: NodeWallet,
        interval: float = 15.0,
        batch_size: int = 256,
        on_notes_found: Optional[Callable[[list], None]] = None,
    ):
        self.wallet = wallet
        self.interval = interval
        self.batch_size = batch_size
        self.on_notes_found = on_notes_found

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Stats
        self.total_scanned = 0
        self.total_found = 0
        self.scan_count = 0
        self.last_error: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        """Start background scanning. No-op if already running."""
        with self._lock:
            if self.running:
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._scan_loop,
                daemon=True,
                name="obscura-scanner",
            )
            self._thread.start()

    def stop(self, timeout: float = 5.0):
        """Stop background scanning and wait for the thread to finish."""
        with self._lock:
            if not self.running:
                return
            self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._thread = None

    def scan_once(self) -> dict:
        """Run a single scan cycle (callable from any thread)."""
        return self._do_scan()

    def _scan_loop(self):
        """Main loop: scan, sleep, repeat until stopped."""
        while not self._stop_event.is_set():
            self._do_scan()
            # Use wait() instead of sleep() so stop() is responsive
            self._stop_event.wait(timeout=self.interval)

    def _do_scan(self) -> dict:
        """Execute one scan cycle."""
        try:
            result = self.wallet.scan(batch_size=self.batch_size)
            self.scan_count += 1
            self.total_scanned += result.get("scanned", 0)
            self.total_found += result.get("found", 0)
            self.last_error = None

            if result.get("found", 0) > 0 and self.on_notes_found:
                self.on_notes_found(result["imported"])

            return result
        except Exception as e:
            self.last_error = str(e)
            return {"scanned": 0, "found": 0, "imported": [], "error": str(e)}


# ─────────────────────────────────────────────────────────────────────
# First-Run Onboarding
# ─────────────────────────────────────────────────────────────────────

WELCOME_BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                  T O N K L   W A L L E T                     ║
║                                                              ║
║              Privacy-Preserving Digital Assets                ║
║                                                              ║
║        Shielded transfers powered by zero-knowledge          ║
║        proofs on the Tonkl Protocol.                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

DISCLAIMER_TEXT = (
    "  ⚠  BETA SOFTWARE — This is an early alpha release.\n"
    "  ⚠  CLI-only interface. Expect bugs.\n"
    "  ⚠  NOT for real value. Testnet tokens have no monetary worth.\n"
    "  ⚠  No warranty. Use at your own risk.\n"
)


def _prompt(msg: str, default: str = "") -> str:
    """Prompt the user for input with an optional default."""
    if default:
        raw = input(f"  {msg} [{default}]: ").strip()
        return raw if raw else default
    return input(f"  {msg}: ").strip()


def _prompt_yn(msg: str, default: bool = True) -> bool:
    """Prompt for a yes/no answer."""
    hint = "Y/n" if default else "y/N"
    raw = input(f"  {msg} ({hint}): ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def _prompt_secret(msg: str) -> str:
    """Prompt for a secret (passphrase) with hidden input where possible."""
    import getpass
    try:
        return getpass.getpass(f"  {msg}: ")
    except Exception:
        return input(f"  {msg}: ")


def run_onboarding(db_path: Path, node_url: str) -> None:
    """
    Interactive first-run setup wizard.

    Guides the user through:
      1. Welcome + disclaimer
      2. Optional passphrase for database encryption
      3. Seed phrase generation + verification (type back 3 random words)
      4. First spending key derivation
      5. Node connection check + summary
    """
    print(WELCOME_BANNER)
    print("  Welcome to Tonkl! Let's set up your wallet.\n")
    print(DISCLAIMER_TEXT)
    print()

    # ── Step 1: Confirm setup ──
    if not _prompt_yn("Ready to create a new wallet?"):
        print("\n  Setup cancelled. Run this command again when you're ready.")
        print("  You can also use 'setup' to start the wizard manually.\n")
        return

    print()
    print("  ─── Step 1 of 4: Database Encryption ───")
    print()
    print("  You can protect your wallet with a passphrase.")
    print("  This encrypts your keys at rest using SQLCipher (AES-256).")
    if not HAS_SQLCIPHER:
        print("  (Note: sqlcipher3 not installed — encryption unavailable)")
        print("  Install later with: pip install sqlcipher3-binary")
        passphrase = None
    else:
        use_passphrase = _prompt_yn("Set a passphrase?", default=True)
        if use_passphrase:
            while True:
                passphrase = _prompt_secret("Enter passphrase")
                if len(passphrase) < 1:
                    print("  Passphrase cannot be empty. Try again.")
                    continue
                confirm = _prompt_secret("Confirm passphrase")
                if passphrase != confirm:
                    print("  Passphrases don't match. Try again.")
                    continue
                break
            print("  ✓ Passphrase set. You'll need it every time you open the wallet.")
        else:
            passphrase = None
            print("  ✓ No passphrase — wallet will be unencrypted.")

    # ── Step 2: Create the wallet ──
    print()
    print("  ─── Step 2 of 4: Creating Wallet ───")
    print()
    wallet = NodeWallet(
        node_url=node_url,
        db_path=db_path,
        passphrase=passphrase,
    )
    print(f"  ✓ Wallet database created at:")
    print(f"    {db_path}")
    if wallet.encrypted:
        print(f"    (encrypted with SQLCipher)")

    # ── Step 3: Seed phrase ──
    print()
    print("  ─── Step 3 of 4: Seed Phrase Backup ───")
    print()
    print("  Your seed phrase is the ONLY way to recover your wallet.")
    print("  Write it down on paper. Do NOT store it digitally.")
    print("  Anyone with these words can access your funds.")
    print()

    mnemonic = wallet.generate_seed(passphrase="")
    words = mnemonic.split()

    print("  ┌────────────────────────────────────────────┐")
    print("  │        YOUR 24-WORD SEED PHRASE             │")
    print("  ├────────────────────────────────────────────┤")
    for i in range(0, 24, 3):
        w1 = f"{i+1:2d}. {words[i]:<12}"
        w2 = f"{i+2:2d}. {words[i+1]:<12}"
        w3 = f"{i+3:2d}. {words[i+2]:<12}"
        print(f"  │  {w1} {w2} {w3}  │")
    print("  └────────────────────────────────────────────┘")
    print()
    print("  ⚠  Clear your terminal history after writing these down.")
    print()

    # Backup confirmation — verify by typing back 3 random words
    print("  ⚠  Have you written down your seed phrase?")
    print("  Let's verify. Please type the requested words.\n")

    import random
    verify_indices = sorted(random.sample(range(24), 3))
    verified = False
    attempts = 0
    max_attempts = 3

    while not verified and attempts < max_attempts:
        all_correct = True
        for idx in verify_indices:
            answer = input(f"  Word #{idx + 1}: ").strip().lower()
            if answer != words[idx].lower():
                print(f"  ✗ Incorrect. Expected word #{idx + 1} to be different.")
                all_correct = False
                break

        if all_correct:
            verified = True
            print("\n  ✓ Seed phrase verified successfully!")
        else:
            attempts += 1
            remaining = max_attempts - attempts
            if remaining > 0:
                print(f"  Please check your written copy and try again ({remaining} attempt{'s' if remaining > 1 else ''} left).\n")
            else:
                print("\n  ⚠  Verification failed. Your seed phrase is shown above.")
                print("  PLEASE write it down carefully before using the wallet.")
                _prompt_yn("I understand and have noted my seed phrase", default=True)

    # ── Step 4: First key derivation ──
    print()
    print("  ─── Step 4 of 4: Generating Your First Key ───")
    print()

    sk = wallet.derive_spending_key(0)
    pk_x, pk_y = wallet.derive_pk(sk)

    # Also register as a scan key for auto-receive
    try:
        scan_pk = wallet.register_scan_key(sk)
    except Exception:
        scan_pk = None

    print(f"  ✓ Spending key derived (index 0)")
    print(f"    Address (pk_x): {pk_x[:32]}...")
    print()

    # Check node connection
    try:
        status = wallet.client.get_status()
        node_ok = True
    except Exception:
        node_ok = False

    # ── Summary ──
    print()
    print("  ╔════════════════════════════════════════════════════╗")
    print("  ║              Setup Complete!                       ║")
    print("  ╠════════════════════════════════════════════════════╣")
    print(f"  ║  Wallet:     {str(db_path)[:38]:<38} ║")
    print(f"  ║  Encrypted:  {'Yes (SQLCipher)' if wallet.encrypted else 'No':<38} ║")
    print(f"  ║  Seed:       24-word phrase (backed up)          ║")
    print(f"  ║  Key #0:     {pk_x[:34]+'...':<38} ║")
    node_str = "Connected" if node_ok else "Not connected (start node first)"
    print(f"  ║  Node:       {node_str:<38} ║")
    print("  ╚════════════════════════════════════════════════════╝")
    print()
    print("  Quick start:")
    print("    tonkl wallet balance          Check your balance")
    print("    tonkl wallet faucet           Get testnet tokens")
    print("    tonkl wallet send 100         Send tokens")
    print("    tonkl wallet --help           See all commands")
    print()

    wallet.close()


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────

def _friendly_error(err: Exception, cmd: str, node_url: str, local_cmds: set) -> None:
    """Print a user-friendly error message with contextual suggestions."""
    msg = str(err)

    # ── Hex format errors ──
    if "invalid literal" in msg and "0x" in msg.lower():
        print(f"\n  ✗ Invalid hex value: {msg}")
        print(f"  Hex keys should look like: 0xabcd1234")
        print()
        return

    # ── Missing note errors ──
    if "not found" in msg.lower() and "note #" in msg.lower():
        print(f"\n  ✗ {msg}")
        print(f"  Run 'notes' to see available notes, or 'sync' to refresh.")
        print()
        return

    # ── Note state errors ──
    if "not unspent" in msg.lower() or "already spent" in msg.lower():
        print(f"\n  ✗ {msg}")
        print(f"  This note has already been spent in a previous transaction.")
        print(f"  Run 'notes' to see your unspent notes.")
        print()
        return

    # ── Insufficient balance ──
    if "insufficient" in msg.lower():
        print(f"\n  ✗ {msg}")
        print(f"  Check your balance with 'balance' or get tokens with 'faucet'.")
        print()
        return

    # ── Missing toolchain ──
    if "nargo" in msg.lower() or "barretenberg" in msg.lower() or ("not found" in msg.lower() and "PATH" in msg):
        print(f"\n  ✗ {msg}")
        print(f"  The proving toolchain is required for this operation.")
        print(f"  Install Noir: https://noir-lang.org/docs/getting_started/installation")
        print()
        return

    # ── Proof generation failures ──
    if "constraint" in msg.lower() or "nargo execute failed" in msg.lower():
        print(f"\n  ✗ Proof generation failed")
        print(f"  This usually means the transaction inputs are invalid.")
        print(f"  Check that your notes, keys, and amounts are correct.")
        if len(msg) > 100:
            print(f"  Detail: {msg[:200]}...")
        else:
            print(f"  Detail: {msg}")
        print()
        return

    # ── Database encryption errors ──
    if "encrypted" in msg.lower() or "passphrase" in msg.lower():
        print(f"\n  ✗ {msg}")
        print(f"  If your wallet is encrypted, use --passphrase to unlock it.")
        print()
        return

    # ── Rate limiting ──
    if "rate limit" in msg.lower():
        print(f"\n  ✗ {msg}")
        print(f"  Use --no-limit to bypass rate limiting (for testing).")
        print()
        return

    # ── Asset errors ──
    if "asset" in msg.lower() and ("collision" in msg.lower() or "already" in msg.lower()):
        print(f"\n  ✗ {msg}")
        print(f"  Run 'assets' or 'list-tokens' to see registered assets.")
        print()
        return

    # ── Recipient missing ──
    if "recipient" in msg.lower():
        print(f"\n  ✗ {msg}")
        print(f"  Specify a recipient with --to-sk <hex> or --to-pk-x/--to-pk-y.")
        print()
        return

    # ── FileNotFoundError ──
    if isinstance(err, FileNotFoundError):
        print(f"\n  ✗ File not found: {msg}")
        print(f"  Check that circuits are compiled and the node is built.")
        print()
        return

    # ── Generic fallback ──
    print(f"\n  ✗ Error: {msg}")
    if cmd and cmd not in local_cmds:
        print(f"  Is the node running at {node_url}?")
    print()


def _friendly_node_error(err, cmd: str, node_url: str, local_cmds: set) -> None:
    """Print a friendly node connection error."""
    msg = str(err)

    if cmd in local_cmds:
        print(f"\n  ⚠ Node unreachable ({msg})")
        print(f"  Local wallet data may be stale. Use 'sync' when the node is back.")
        print()
    else:
        print(f"\n  ✗ Cannot connect to node")
        print(f"    URL: {node_url}")
        print()
        print(f"  Possible fixes:")
        print(f"    1. Start the node:  python3 scripts/launch_testnet.py")
        print(f"    2. Check the URL:   --node-url http://host:port")
        print(f"    3. Use offline:     {', '.join(sorted(local_cmds))}")
        print()


HELP_EPILOG = """
common workflows:

  First time setup:
    %(prog)s                                        (auto-runs setup wizard)
    %(prog)s faucet --to-sk <your-key>              (get testnet tokens)
    %(prog)s balance                                 (check balance)

  Send tokens:
    %(prog)s send 100 --to-sk <recipient-key>       (private transfer)
    %(prog)s send 100 --to-pk-x <hex> --to-pk-y <hex>

  Manage notes:
    %(prog)s notes                                   (list unspent notes)
    %(prog)s split <note-id> --values 50,30,20       (split a note)
    %(prog)s merge <note-ids>                        (merge notes)

  Create custom tokens:
    %(prog)s create-token GOLD --name "Gold" --asset-id 100 --authority-sk 0xkey
    %(prog)s mint-token --asset-id 100 --amount 1000

  Staking:
    %(prog)s register-validator "My Node" --pk-x <hex>  (add a validator)
    %(prog)s stake <note-id> --validator <pk-x>         (delegate TNKL)
    %(prog)s stakes                                     (view positions)
    %(prog)s claim-rewards <stake-id>                   (claim rewards)
    %(prog)s unstake <stake-id>                         (begin withdrawal)
    %(prog)s withdraw-stake <stake-id>                  (complete withdrawal)

  Epochs & rewards:
    %(prog)s epoch-advance                              (close epoch, distribute rewards)
    %(prog)s epoch-info --epoch 0                       (view epoch details)
    %(prog)s validator-set                              (active validator set)
    %(prog)s reward-history                             (reward distribution log)
    %(prog)s slash-validator <id> --reason downtime     (slash a validator)

  Auto-receive:
    %(prog)s register-key <sk>                       (enable auto-detect)
    %(prog)s watch                                   (scan continuously)

environment variables:
  TONKL_NODE_URL    Node RPC URL (overrides --node-url default)
"""


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Tonkl Wallet -- Privacy-preserving shielded wallet CLI",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--node-url", default=DEFAULT_NODE_URL,
        help=f"Node RPC URL (default: {DEFAULT_NODE_URL}, or $TONKL_NODE_URL)",
    )
    parser.add_argument(
        "--db", default=str(DEFAULT_DB_PATH),
        help=f"Wallet database path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--passphrase", default=None,
        help="Passphrase for SQLCipher database encryption (requires sqlcipher3)",
    )
    parser.add_argument(
        "--passphrase-stdin", action="store_true",
        help="Read passphrase from stdin (safer than --passphrase, avoids ps visibility)",
    )
    parser.add_argument(
        "--passphrase-env", default=None,
        help="Read passphrase from this environment variable (safer than --passphrase)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output machine-readable JSON (for Shlem integration)",
    )

    sub = parser.add_subparsers(dest="command", metavar="command")

    # ── Wallet info ──────────────────────────────────────────────────
    sub.add_parser("status", help="Show wallet overview (connection, balances, notes)")
    sub.add_parser("balance", help="Show balances by asset")

    p_notes = sub.add_parser("notes", help="List unspent notes (--all for spent too)")
    p_notes.add_argument("--all", action="store_true", help="Show all notes (including spent)")
    p_notes.add_argument("--asset", default=None, help="Filter by asset ID (e.g., 1, 2)")

    # ── Transactions ───────────────────────────────────────────────────
    p_addr = sub.add_parser("address", help="Show public key address for a spending key")
    p_addr.add_argument("sk", help="Spending key (hex)")

    # ── import-note ───────────────────────────────────────────────────
    p_imp = sub.add_parser("import-note", help="Import a note into the wallet")
    p_imp.add_argument("--sk", required=True, help="Spending key (hex)")
    p_imp.add_argument("--value", type=int, required=True, help="Note value")
    p_imp.add_argument("--rho", required=True, help="Note rho")
    p_imp.add_argument("--asset-id", default=DEFAULT_ASSET_ID, help="Asset ID")
    p_imp.add_argument("--tree-index", type=int, help="Leaf index in Merkle tree")

    # ── import-mint ───────────────────────────────────────────────────
    p_mint = sub.add_parser(
        "import-mint",
        help="Import mint notes (from generate_mint_witness.py parameters)",
    )
    p_mint.add_argument(
        "--sks", required=True,
        help='Comma-separated spending keys (e.g., "0xaaaa01,0xbbbb02,0xcccc03,0xdddd04")',
    )
    p_mint.add_argument(
        "--values", required=True,
        help='Comma-separated values (e.g., "400,300,200,100")',
    )
    p_mint.add_argument(
        "--rho-base", type=int, default=6001,
        help="Base rho (note i gets rho=base+i). Default: 6001",
    )
    p_mint.add_argument("--asset-id", default=DEFAULT_ASSET_ID, help="Asset ID")
    p_mint.add_argument(
        "--tree-base", type=int, default=0,
        help="Base tree index (note i gets index=base+i). Default: 0",
    )

    p_send = sub.add_parser("send", help="Send a private transfer (auto-selects notes, generates proof)")
    p_send.add_argument("amount", type=int, help="Amount to send")
    p_send.add_argument("--to-sk", help="Recipient sk (hex) — derives pk automatically")
    p_send.add_argument("--to-pk-x", help="Recipient pk_x (hex)")
    p_send.add_argument("--to-pk-y", help="Recipient pk_y (hex)")
    p_send.add_argument("--from", dest="from_ids",
                        help="Comma-separated note IDs to spend (1-2). Auto-selected if omitted.")
    p_send.add_argument("--sk", dest="sender_sk",
                        help="Only use notes owned by this key (for auto-selection)")
    p_send.add_argument("--fee", type=int, default=0, help="Transaction fee")
    p_send.add_argument("--asset-id", default=DEFAULT_ASSET_ID, help="Asset ID")
    p_send.add_argument("--no-block", action="store_true", help="Don't produce a block")

    p_split = sub.add_parser("split", help="Split one note into many (up to 32 outputs)")
    p_split.add_argument("note_id", type=int, help="Note ID to split")
    p_split.add_argument("--values", required=True,
                         help="Comma-separated output values (e.g., 100,50,30,20)")
    p_split.add_argument("--fee", type=int, default=0, help="Transaction fee")
    p_split.add_argument("--asset-id", default=DEFAULT_ASSET_ID, help="Asset ID")
    p_split.add_argument("--no-block", action="store_true", help="Don't produce a block")

    p_merge = sub.add_parser("merge", help="Merge many notes into one (up to 32 inputs)")
    p_merge.add_argument("note_ids", help="Comma-separated note IDs to merge")
    p_merge.add_argument("--fee", type=int, default=0, help="Transaction fee")
    p_merge.add_argument("--asset-id", default=DEFAULT_ASSET_ID, help="Asset ID")
    p_merge.add_argument("--no-block", action="store_true", help="Don't produce a block")

    # ── Auto-receive ─────────────────────────────────────────────────
    p_regkey = sub.add_parser("register-key", help="Register a key for auto-detecting incoming payments")
    p_regkey.add_argument("sk", help="Spending key (hex)")

    p_scan = sub.add_parser("scan", help="Scan once for incoming payments")
    p_scan.add_argument("--batch-size", type=int, default=256, help="Max leaves to scan per batch")

    sub.add_parser("scan-keys", help="List registered scan keys for auto-receive")

    p_watch = sub.add_parser("watch", help="Continuously scan for incoming payments (Ctrl+C to stop)")
    p_watch.add_argument("--interval", type=float, default=15.0,
                         help="Scan interval in seconds (default: 15)")
    p_watch.add_argument("--batch-size", type=int, default=256,
                         help="Max leaves to scan per batch")

    # ── Key management ─────────────────────────────────────────────────
    p_iseed = sub.add_parser("init-seed", help="Generate a new 24-word BIP-39 seed phrase")
    p_iseed.add_argument("--bip39-passphrase", default="", dest="bip39_passphrase",
                         help="Optional BIP-39 passphrase (NOT the database passphrase)")

    p_rseed = sub.add_parser("restore-seed", help="Restore wallet from a 24-word seed phrase")
    p_rseed.add_argument("words", nargs="+", help="24 mnemonic words")
    p_rseed.add_argument("--bip39-passphrase", default="", dest="bip39_passphrase",
                         help="Optional BIP-39 passphrase (NOT the database passphrase)")
    p_rseed.add_argument("--recover-keys", type=int, default=10,
                         help="Number of key indices to re-derive (default: 10)")

    # ── show-seed ─────────────────────────────────────────────────────
    sub.add_parser("show-seed", help="Display the stored seed phrase")

    # ── derive-key ────────────────────────────────────────────────────
    p_dkey = sub.add_parser("derive-key", help="Derive a new spending key from the seed")
    p_dkey.add_argument("--index", type=int, default=None,
                        help="Key index (default: next available)")

    # ── list-keys ─────────────────────────────────────────────────────
    sub.add_parser("list-keys", help="List all derived spending keys")

    # ── Assets ────────────────────────────────────────────────────
    sub.add_parser("assets", help="List all assets (built-in + custom) with balances")

    # ── Testnet ───────────────────────────────────────────────────────
    p_faucet = sub.add_parser("faucet", help="Get free testnet tokens (TNKL or sUSDC)")
    p_faucet.add_argument("--to-sk", help="Recipient sk (hex) — derives pk automatically")
    p_faucet.add_argument("--to-sk-env", help="Read recipient sk from this env var (safer than --to-sk)")
    p_faucet.add_argument("--to-pk-x", help="Recipient pk_x (hex)")
    p_faucet.add_argument("--to-pk-y", help="Recipient pk_y (hex)")
    p_faucet.add_argument("--asset-id", default=DEFAULT_ASSET_ID,
                          help="Asset to drip (1=TNKL, 4=sUSDC). Default: 1")
    p_faucet.add_argument("--amount", type=int, default=None,
                          help="Override drip amount (default: 100 TNKL or 100 sUSDC)")
    p_faucet.add_argument("--from-sk", help="Faucet spending key (uses first available if omitted)")
    p_faucet.add_argument("--cooldown", type=int, default=None,
                          help="Cooldown in seconds between drips to same address (default: 3600)")
    p_faucet.add_argument("--no-limit", action="store_true",
                          help="Disable rate limiting (for testing)")

    p_faucet_hist = sub.add_parser("faucet-history", help="Show recent faucet drip history")
    p_faucet_hist.add_argument("--limit", type=int, default=20, help="Max rows to show")

    # ── create-token ──────────────────────────────────────────────────
    p_create = sub.add_parser("create-token", help="Register a new custom token")
    p_create.add_argument("symbol", help="Token symbol (e.g. MYTKN)")
    p_create.add_argument("--name", required=True, help="Token name (e.g. 'My Custom Token')")
    p_create.add_argument("--asset-id", required=True, help="Unique asset ID (number)")
    p_create.add_argument("--decimals", type=int, default=0,
                          help="Decimal places (0 = whole units, 6 = like USDC). Default: 0")
    p_create.add_argument("--authority-sk", help="Spending key authorized to mint this token")
    p_create.add_argument("--initial-supply", type=int, default=0,
                          help="Mint an initial supply (requires --authority-sk and node)")
    p_create.add_argument("--num-notes", type=int, default=1,
                          help="Split initial supply across N notes (default: 1)")

    # ── mint-token ───────────────────────────────────────────────────
    p_minttkn = sub.add_parser("mint-token", help="Mint additional supply of a custom token")
    p_minttkn.add_argument("--asset-id", required=True, help="Asset ID to mint")
    p_minttkn.add_argument("--amount", type=int, required=True, help="Amount to mint")
    p_minttkn.add_argument("--authority-sk", help="Override authority key")
    p_minttkn.add_argument("--recipient-sk", help="Recipient key (defaults to authority)")
    p_minttkn.add_argument("--num-notes", type=int, default=1,
                           help="Split mint across N notes (default: 1)")

    # ── list-tokens ──────────────────────────────────────────────────
    sub.add_parser("list-tokens", help="List all custom tokens registered in this wallet")

    # ── Staking & delegation ──────────────────────────────────────────
    p_regval = sub.add_parser("register-validator", help="Register a validator for delegation")
    p_regval.add_argument("name", help="Validator name (e.g. 'Mainnet Validator 1')")
    p_regval.add_argument("--pk-x", required=True, help="Validator public key x-coordinate (hex)")
    p_regval.add_argument("--commission", type=float, default=0.05,
                          help="Commission rate 0.0-1.0 (default: 0.05 = 5%%)")

    sub.add_parser("validators", help="List all registered validators")

    p_stake = sub.add_parser("stake", help="Stake TNKL by delegating a note to a validator")
    p_stake.add_argument("note_id", type=int, help="Note ID to stake")
    p_stake.add_argument("--validator", required=True, help="Validator pk_x (hex) to delegate to")

    p_unstake = sub.add_parser("unstake", help="Begin unstaking (starts unbonding period)")
    p_unstake.add_argument("stake_id", type=int, help="Stake ID to unstake")

    p_withdraw = sub.add_parser("withdraw-stake", help="Withdraw unstaked position after unbonding")
    p_withdraw.add_argument("stake_id", type=int, help="Stake ID to withdraw")

    p_claim = sub.add_parser("claim-rewards", help="Claim accrued staking rewards")
    p_claim.add_argument("stake_id", type=int, help="Stake ID to claim rewards for")

    p_stakes = sub.add_parser("stakes", help="List all staking positions")
    p_stakes.add_argument("--status", choices=["active", "unstaking", "withdrawn"],
                          help="Filter by status")

    # ── Epoch & validator set ─────────────────────────────────────────
    sub.add_parser("epoch-advance", help="Close the current epoch and distribute rewards")

    p_epochinfo = sub.add_parser("epoch-info", help="Show epoch details")
    p_epochinfo.add_argument("--epoch", type=int, default=None,
                             help="Epoch number (default: current)")

    sub.add_parser("validator-set", help="Show the active validator set")

    p_rewhist = sub.add_parser("reward-history", help="Show epoch reward distribution history")
    p_rewhist.add_argument("--limit", type=int, default=50, help="Max records (default: 50)")

    p_slash = sub.add_parser("slash-validator", help="Slash a validator for misbehaviour")
    p_slash.add_argument("validator_id", help="Validator ID to slash")
    p_slash.add_argument("--reason", choices=["downtime", "double_sign"],
                         default="downtime", help="Slash reason (default: downtime)")

    # ── Maintenance ───────────────────────────────────────────────────
    sub.add_parser("sync", help="Sync note states with the node (mark spent notes)")

    # ── history ───────────────────────────────────────────────────────
    sub.add_parser("history", help="Show transaction history")

    # ── setup ─────────────────────────────────────────────────────────
    sub.add_parser("setup", help="Run the first-time wallet setup wizard")

    args = parser.parse_args()

    # ── Resolve passphrase from stdin or env if requested ──
    if args.passphrase_stdin and not args.passphrase:
        import getpass as _gp
        try:
            args.passphrase = sys.stdin.readline().rstrip("\n")
        except Exception:
            args.passphrase = None
    elif args.passphrase_env and not args.passphrase:
        args.passphrase = os.environ.get(args.passphrase_env, None)

    db_path = Path(args.db)
    is_first_run = not db_path.exists()

    # ── Auto-trigger onboarding on first run ──
    if args.command == "setup" or (args.command is None and is_first_run):
        if not is_first_run and args.command == "setup":
            print()
            print(f"  Wallet already exists at {db_path}")
            print(f"  To start fresh, delete it first:")
            print(f"    rm {db_path}")
            print()
            return
        run_onboarding(db_path=db_path, node_url=args.node_url)
        return

    if args.command is None:
        parser.print_help()
        return

    # Open wallet
    wallet = NodeWallet(
        node_url=args.node_url,
        db_path=db_path,
        passphrase=args.passphrase,
    )

    # Commands that work without a node connection
    LOCAL_COMMANDS = {
        "balance", "notes", "assets", "address", "history",
        "list-keys", "show-seed", "init-seed", "scan-keys",
        "list-tokens", "validators", "stakes",
        "epoch-info", "validator-set", "reward-history",
    }

    try:
        _dispatch(args, wallet)
    except KeyboardInterrupt:
        print("\n  Interrupted.")
    except (ValueError, RuntimeError, FileNotFoundError) as e:
        _friendly_error(e, args.command, args.node_url, LOCAL_COMMANDS)
        sys.exit(1)
    except NodeError as e:
        _friendly_node_error(e, args.command, args.node_url, LOCAL_COMMANDS)
        if args.command not in LOCAL_COMMANDS:
            sys.exit(1)
    finally:
        wallet.close()


def _dispatch(args, wallet: NodeWallet):
    cmd = args.command

    if cmd == "status":
        try:
            ns = wallet.client.get_status()
            node_ok = True
        except NodeError:
            node_ok = False

        bal = wallet.balance()
        all_notes = wallet.get_all_notes()
        unspent = [n for n in all_notes if n.state == "unspent"]
        spent = [n for n in all_notes if n.state == "spent"]

        # Check for pending transactions
        pending = wallet._conn.execute("SELECT COUNT(*) as cnt FROM pending_tx").fetchone()
        pending_count = pending["cnt"] if pending else 0

        print()
        print("  ┌─ Tonkl Wallet ─────────────────────────────┐")
        print(f"  │  Database:  {str(wallet.db_path)[-38:]:<38} │")
        enc_str = "Yes (SQLCipher)" if wallet.encrypted else "No"
        print(f"  │  Encrypted: {enc_str:<38} │")
        node_icon = "✓ Connected" if node_ok else "✗ Unreachable"
        print(f"  │  Node:      {node_icon:<38} │")
        if node_ok:
            chain_str = f"Height {ns.block_height}, {ns.leaf_count:,} leaves"
            print(f"  │  Chain:     {chain_str:<38} │")
        note_str = f"{len(unspent)} unspent, {len(spent)} spent"
        print(f"  │  Notes:     {note_str:<38} │")
        if pending_count > 0:
            pend_str = f"{pending_count} pending (run 'sync' to recover)"
            print(f"  │  Pending:   {pend_str:<38} │")
        print(f"  ├─────────────────────────────────────────────┤")
        if bal:
            for aid, total in sorted(bal.items()):
                val_str = format_value(total, aid)
                name = asset_name(aid)
                bal_line = f"{val_str}  ({name})"
                print(f"  │  {bal_line:<44} │")
        else:
            print(f"  │  {'No balance yet':<44} │")
        print(f"  └─────────────────────────────────────────────┘")
        print()

    elif cmd == "balance":
        bal = wallet.balance()
        if args.json_output:
            result = {
                "status": "ok",
                "balances": {aid: {"raw": total, "formatted": format_value(total, aid), "asset": asset_name(aid)} for aid, total in bal.items()}
            }
            print(json.dumps(result))
        else:
            print()
            if not bal:
                print("  No balance yet. Use 'faucet' to get testnet tokens.")
            else:
                print("  Your balances:")
                print()
                for aid, total in sorted(bal.items()):
                    print(f"    {format_value(total, aid):>20}  {asset_name(aid)}")
            print()

    elif cmd == "notes":
        notes = wallet.get_all_notes() if args.all else wallet.get_unspent()
        if args.asset:
            notes = [n for n in notes if n.asset_id == args.asset]
        if args.json_output:
            result = {
                "status": "ok",
                "notes": [
                    {"id": n.note_id, "value": n.value, "formatted": format_value(n.value, n.asset_id),
                     "asset_id": n.asset_id, "asset": asset_symbol(n.asset_id),
                     "state": n.state, "tree_index": n.tree_index}
                    for n in notes
                ],
                "count": len(notes),
            }
            print(json.dumps(result))
        elif not notes:
            label = "notes" if not args.all else "notes (including spent)"
            print(f"\n  No {label} found.\n")
        else:
            # Group by asset
            by_asset: dict[str, list] = {}
            for n in notes:
                by_asset.setdefault(n.asset_id, []).append(n)
            for aid in sorted(by_asset.keys()):
                asset_notes = by_asset[aid]
                total = sum(n.value for n in asset_notes if n.state == "unspent")
                print(f"\n  {asset_symbol(aid)} ({asset_name(aid)}) — {len(asset_notes)} note(s), total: {format_value(total, aid)}")
                print(f"  {'ID':>4}  {'Index':>5}  {'Value':>12}  {'State':>8}  Commitment")
                print(f"  {'─'*4}  {'─'*5}  {'─'*12}  {'─'*8}  {'─'*20}")
                for n in asset_notes:
                    idx = str(n.tree_index) if n.tree_index is not None else "?"
                    val_str = format_value(n.value, aid)
                    state_icon = "✓" if n.state == "unspent" else "✗"
                    print(f"  {n.note_id:>4}  {idx:>5}  {val_str:>12}  {state_icon} {n.state:<6}  {n.commitment[:22]}...")
            print()

    elif cmd == "address":
        pk_x, pk_y = wallet.derive_pk(args.sk)
        print()
        print(f"  Your address (derived from spending key):")
        print(f"    Public Key X: {pk_x}")
        print(f"    Public Key Y: {pk_y}")
        print()
        print(f"  Share your pk_x and pk_y with senders to receive funds.")
        print()

    elif cmd == "import-note":
        note = wallet.import_note(
            sk=args.sk,
            value=args.value,
            rho=args.rho,
            asset_id=args.asset_id,
            tree_index=args.tree_index,
        )
        print()
        print(f"  ✓ Note imported successfully!")
        print(f"    Note ID:    #{note.note_id}")
        print(f"    Value:      {format_value(note.value, note.asset_id)}")
        print(f"    Tree Index: {note.tree_index}")
        print()

    elif cmd == "import-mint":
        sks = [s.strip() for s in args.sks.split(",")]
        values = [int(v.strip()) for v in args.values.split(",")]
        if len(sks) != len(values):
            raise ValueError(f"Number of keys ({len(sks)}) and values ({len(values)}) must match")

        print()
        for i, (sk, val) in enumerate(zip(sks, values)):
            rho = str(args.rho_base + i)
            idx = args.tree_base + i
            note = wallet.import_note(
                sk=sk, value=val, rho=rho,
                asset_id=args.asset_id, tree_index=idx,
            )
            print(f"  ✓ Note #{note.note_id}: {format_value(val, args.asset_id)} at index {idx}")

        total = sum(values)
        print(f"\n  Imported {len(sks)} notes. Total: {format_value(total, args.asset_id)}")
        print()

    elif cmd == "send":
        # Resolve recipient pk
        to_pk_x = args.to_pk_x
        to_pk_y = args.to_pk_y
        if args.to_sk:
            to_pk_x, to_pk_y = wallet.derive_pk(args.to_sk)
        if not to_pk_x or not to_pk_y:
            raise ValueError(
                "Recipient required: use --to-sk <hex> or --to-pk-x <hex> --to-pk-y <hex>"
            )

        from_ids = None
        if args.from_ids:
            from_ids = [int(x.strip()) for x in args.from_ids.split(",")]

        print()
        print(f"  Sending {format_value(args.amount, args.asset_id)} ...")
        print(f"  Building witness and generating proof (this may take a moment)...")

        result = wallet.send(
            to_pk_x=to_pk_x,
            to_pk_y=to_pk_y,
            to_value=args.amount,
            from_note_ids=from_ids,
            sender_sk=args.sender_sk,
            recipient_sk=args.to_sk,
            asset_id=args.asset_id,
            fee=args.fee,
            auto_block=not args.no_block,
        )

        print()
        print(f"  ✓ Transfer sent successfully!")
        print(f"  ┌────────────────────────────────────────────┐")
        print(f"  │  Amount:  {format_value(args.amount, args.asset_id):<33} │")
        print(f"  │  Change:  {format_value(result['change_value'], args.asset_id):<33} │")
        if args.fee > 0:
            print(f"  │  Fee:     {format_value(args.fee, args.asset_id):<33} │")
        print(f"  │  TX:      {result['tx_hash'][:33]:<33} │")
        if result['block_number'] is not None:
            print(f"  │  Block:   #{result['block_number']:<32} │")
        print(f"  └────────────────────────────────────────────┘")
        print()

    elif cmd == "split":
        values = [int(v.strip()) for v in args.values.split(",")]

        print()
        print(f"  Splitting note #{args.note_id} into {len(values)} outputs...")
        print(f"  Generating proof (this may take a moment)...")

        result = wallet.split(
            note_id=args.note_id,
            values=values,
            asset_id=args.asset_id,
            fee=args.fee,
            auto_block=not args.no_block,
        )

        print()
        print(f"  ✓ Split complete!")
        print(f"    TX: {result['tx_hash'][:32]}...")
        print(f"    Created {len([n for n in result['new_notes'] if n[1] > 0])} notes:")
        for nid, val, idx in result['new_notes']:
            if val > 0:
                print(f"      #{nid}: {format_value(val, args.asset_id):<16} (index {idx})")
        print()

    elif cmd == "merge":
        note_ids = [int(x.strip()) for x in args.note_ids.split(",")]

        print()
        print(f"  Merging {len(note_ids)} notes into one...")
        print(f"  Generating proof (this may take a moment)...")

        result = wallet.merge(
            note_ids=note_ids,
            asset_id=args.asset_id,
            fee=args.fee,
            auto_block=not args.no_block,
        )

        print()
        print(f"  ✓ Merge complete!")
        print(f"    TX:     {result['tx_hash'][:32]}...")
        print(f"    Merged: {len(result['inputs_spent'])} notes into 1")
        print(f"    Result: #{result['out_note_id']} = {format_value(result['out_value'], args.asset_id)} (index {result['out_tree_index']})")
        print()

    elif cmd == "sync":
        print()
        print("  Syncing wallet with node...")
        result = wallet.sync()
        print()
        print(f"  ✓ Sync complete!")
        print(f"    Checked:  {result['checked']} notes")
        if result['marked_spent'] > 0:
            print(f"    Updated:  {result['marked_spent']} note(s) marked as spent")
        else:
            print(f"    Status:   All notes up to date")
        print(f"    Chain:    Height {result['node_height']}, {result['node_leaves']:,} leaves")
        print()

    elif cmd == "history":
        rows = wallet._conn.execute(
            "SELECT * FROM tx_history ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
        if args.json_output:
            result = {
                "status": "ok",
                "transactions": [
                    {"tx_type": r["tx_type"], "status": r["status"],
                     "tx_hash": r["tx_hash"], "created_at": r["created_at"],
                     "detail": json.loads(r["detail"]) if r["detail"] else None}
                    for r in rows
                ],
                "count": len(rows),
            }
            print(json.dumps(result))
        elif not rows:
            print()
            print("  No transactions yet.")
        else:
            print(f"  Transaction History (last {len(rows)}):")
            print(f"  {'─'*62}")
            for row in rows:
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["created_at"]))
                tx_type = row['tx_type']
                status = row['status']
                status_icon = "✓" if status == "confirmed" else "~" if status == "pending" else "?"
                print(f"  {ts}  {status_icon} {tx_type:<8}  {row['tx_hash'][:28]}...")
                if row["detail"]:
                    detail = json.loads(row["detail"])
                    aid = detail.get("asset_id", DEFAULT_ASSET_ID)
                    parts = []
                    if "to_value" in detail:
                        parts.append(f"sent {format_value(detail['to_value'], aid)}")
                    if "change_value" in detail:
                        parts.append(f"change {format_value(detail['change_value'], aid)}")
                    if "out_value" in detail:
                        parts.append(f"output {format_value(detail['out_value'], aid)}")
                    if "values" in detail:
                        parts.append(f"outputs: {detail['values']}")
                    if parts:
                        print(f"  {'':>17}{', '.join(parts)}")
        print()

    elif cmd == "register-key":
        scan_pk_hex = wallet.register_scan_key(args.sk)
        print()
        print(f"  ✓ Scan key registered!")
        print(f"    Your wallet will now auto-detect incoming payments.")
        print(f"    Run 'scan' or 'watch' to check for new notes.")
        print()

    elif cmd == "scan":
        batch = getattr(args, "batch_size", 256)
        print()
        print(f"  Scanning for incoming notes...")
        result = wallet.scan(batch_size=batch)
        print()
        imported = result.get('imported', [])
        num_imported = len(imported) if isinstance(imported, list) else imported
        if num_imported > 0:
            print(f"  ✓ Found {num_imported} new note(s)!")
        else:
            print(f"  No new notes found.")
        print(f"    Scanned:  {result['scanned']} entries")
        print(f"    Position: up to leaf index {result['up_to_index']}")
        print()

    elif cmd == "scan-keys":
        keys = wallet.get_scan_keys()
        print()
        if not keys:
            print("  No scan keys registered.")
            print("  Use 'register-key <sk>' to enable auto-receive scanning.")
        else:
            print(f"  {len(keys)} scan key(s) registered:")
            for k in keys:
                print(f"    Key: {k['spending_sk'][:20]}...")
        print()

    elif cmd == "watch":
        keys = wallet.get_scan_keys()
        if not keys:
            print()
            print("  No scan keys registered. Use 'register-key <sk>' first.")
            print()
            sys.exit(1)

        interval = args.interval
        batch = args.batch_size

        def on_found(notes):
            for n in notes:
                aid = n.get('asset_id', DEFAULT_ASSET_ID)
                print(f"    ✓ New note received: #{n['note_id']} {format_value(n['value'], aid)}")

        scanner = BackgroundScanner(
            wallet, interval=interval, batch_size=batch,
            on_notes_found=on_found,
        )
        print()
        print(f"  Watching for incoming notes...")
        print(f"  Checking every {interval}s with {len(keys)} scan key(s).")
        print(f"  Press Ctrl+C to stop.\n")
        scanner.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  Stopping...")
            scanner.stop()
            print(f"  Done. Found {scanner.total_found} note(s) across "
                  f"{scanner.scan_count} scan cycles.")
            print()

    elif cmd == "init-seed":
        bip39_pp = getattr(args, "bip39_passphrase", "")
        mnemonic = wallet.generate_seed(passphrase=bip39_pp)
        words = mnemonic.split()
        # Auto-derive first key
        sk = wallet.derive_spending_key(0)
        pk_x, pk_y = wallet.derive_pk(sk)

        if args.json_output:
            print(json.dumps({
                "status": "ok",
                "mnemonic": mnemonic,
                "key_index": 0,
                "spending_sk": sk,
                "pk_x": pk_x,
                "pk_y": pk_y,
            }))
        else:
            print()
            print("  ┌────────────────────────────────────────────────┐")
            print("  │  WRITE DOWN THESE 24 WORDS ON PAPER            │")
            print("  │  This is the ONLY way to recover your wallet.  │")
            print("  ├────────────────────────────────────────────────┤")
            for i in range(0, 24, 3):
                w1 = f"{i+1:2d}. {words[i]:<12}"
                w2 = f"{i+2:2d}. {words[i+1]:<12}"
                w3 = f"{i+3:2d}. {words[i+2]:<12}"
                print(f"  │  {w1} {w2} {w3}│")
            print("  └────────────────────────────────────────────────┘")
            print()
            print("  ⚠  Clear your terminal history after writing these down.")
            print("     Run: history -c && clear")
            print()
            print(f"  ✓ First spending key derived (index 0)")
            print(f"    Address: {pk_x[:32]}...")
            print()

    elif cmd == "restore-seed":
        mnemonic = " ".join(args.words)
        bip39_pp = getattr(args, "bip39_passphrase", "")
        wallet.restore_seed(mnemonic, passphrase=bip39_pp)
        print()
        print("  ✓ Seed restored successfully!")
        # Re-derive keys
        count = args.recover_keys
        print(f"  Recovering {count} spending keys...")
        keys = wallet.recover_keys(count=count)
        found_with_notes = 0
        for k in keys:
            notes = wallet._conn.execute(
                "SELECT COUNT(*) as cnt FROM notes WHERE owner_sk = ?", (k,)
            ).fetchone()
        print(f"  ✓ {len(keys)} keys recovered and scan keys registered.")
        print(f"  Run 'scan' to detect incoming notes.")
        print()

    elif cmd == "show-seed":
        mnemonic = wallet.get_mnemonic()
        if not mnemonic:
            print()
            print("  No seed phrase stored.")
            print("  Use 'init-seed' to create one or 'restore-seed' to import one.")
            print()
        else:
            words = mnemonic.split()
            print()
            print("  ⚠  Sensitive — do not share or screenshot.")
            print()
            print("  Your 24-word seed phrase:")
            print()
            for i in range(0, 24, 3):
                w1 = f"{i+1:2d}. {words[i]:<12}"
                w2 = f"{i+2:2d}. {words[i+1]:<12}"
                w3 = f"{i+3:2d}. {words[i+2]:<12}"
                print(f"    {w1} {w2} {w3}")
            print()
            print("  ⚠  Clear your terminal after viewing: history -c && clear")
            print()

    elif cmd == "derive-key":
        if not wallet.has_seed():
            print()
            print("  No seed phrase stored.")
            print("  Use 'init-seed' or 'restore-seed' first.")
            print()
            sys.exit(1)
        idx = args.index if args.index is not None else wallet.get_next_key_index()
        sk = wallet.derive_spending_key(idx)
        pk_x, pk_y = wallet.derive_pk(sk)
        print()
        print(f"  ✓ New key derived (index {idx})")
        print(f"    Address: {pk_x[:32]}...")
        print()

    elif cmd == "list-keys":
        dkeys = wallet.get_derived_keys()
        print()
        if not dkeys:
            print("  No derived keys yet.")
            print("  Use 'init-seed' then 'derive-key' to create some.")
        else:
            if args.json_output:
                keys_out = []
                for dk in dkeys:
                    pk_x, pk_y = wallet.derive_pk(dk["spending_sk"])
                    keys_out.append({
                        "index": dk["index"],
                        "spending_sk": dk["spending_sk"],
                        "pk_x": pk_x,
                        "pk_y": pk_y,
                    })
                print(json.dumps({"status": "ok", "keys": keys_out}, indent=2))
            else:
                print(f"  {len(dkeys)} spending key(s):")
                print()
                for dk in dkeys:
                    pk_x, pk_y = wallet.derive_pk(dk["spending_sk"])
                    print(f"    Key #{dk['index']}:")
                    print(f"      Spending key (sk): {dk['spending_sk']}")
                    print(f"      Address    (pk_x): {pk_x}")
                    print()
        print()

    elif cmd == "assets":
        bal = wallet.balance()
        unspent = wallet.get_unspent()
        # Count notes per asset
        note_counts: dict[str, int] = {}
        for n in unspent:
            note_counts[n.asset_id] = note_counts.get(n.asset_id, 0) + 1
        # Merge known assets from registry + custom assets + any in wallet
        all_ids = sorted(set(
            list(ASSET_REGISTRY.keys()) + list(_custom_assets.keys()) + list(bal.keys())
        ))
        if args.json_output:
            result = {
                "status": "ok",
                "assets": [
                    {"id": aid, "symbol": asset_symbol(aid), "name": asset_name(aid),
                     "balance": bal.get(aid, 0), "formatted": format_value(bal.get(aid, 0), aid),
                     "notes": note_counts.get(aid, 0)}
                    for aid in all_ids
                ],
            }
            print(json.dumps(result))
        else:
            print()
            print(f"  Supported Assets:")
            print(f"  {'─'*60}")
            print(f"  {'ID':>4}  {'Symbol':<8}  {'Name':<20}  {'Balance':>14}  {'Notes':>5}")
            print(f"  {'─'*4}  {'─'*8}  {'─'*20}  {'─'*14}  {'─'*5}")
            for aid in all_ids:
                sym = asset_symbol(aid)
                name = asset_name(aid)
                total = bal.get(aid, 0)
                count = note_counts.get(aid, 0)
                val_str = format_value(total, aid) if total > 0 else f"0 {sym}"
                print(f"  {aid:>4}  {sym:<8}  {name:<20}  {val_str:>14}  {count:>5}")
            print()

    elif cmd == "faucet":
        # Resolve recipient key (--to-sk-env reads from env var for security)
        to_sk = args.to_sk
        if not to_sk and getattr(args, 'to_sk_env', None):
            to_sk = os.environ.get(args.to_sk_env, "")
            if not to_sk:
                _friendly_error(f"Environment variable {args.to_sk_env} is not set or empty")
        if to_sk:
            pk_x, pk_y = wallet.crypto.derive_pk(to_sk)
        elif args.to_pk_x and args.to_pk_y:
            pk_x, pk_y = args.to_pk_x, args.to_pk_y
        else:
            print()
            print("  Please specify a recipient:")
            print("    --to-sk <hex>                  (derives address automatically)")
            print("    --to-pk-x <hex> --to-pk-y <hex> (explicit public key)")
            print()
            sys.exit(1)

        # Use the faucet wallet (separate from user's wallet) if it exists
        faucet_db = Path.home() / ".tonkl" / "faucet_wallet.db"
        if faucet_db.exists() and str(faucet_db) != str(wallet.db_path):
            faucet_wallet = NodeWallet(
                node_url=args.node_url,
                db_path=str(faucet_db),
            )
        else:
            faucet_wallet = wallet

        cooldown = 0 if args.no_limit else args.cooldown
        sym = asset_symbol(args.asset_id)
        print()
        print(f"  Requesting {sym} from faucet...")
        try:
            result = faucet_wallet.faucet_drip(
                recipient_pk_x=pk_x,
                recipient_pk_y=pk_y,
                asset_id=args.asset_id,
                amount=args.amount,
                sender_sk=args.from_sk,
                cooldown=cooldown,
            )
        finally:
            if faucet_wallet is not wallet:
                faucet_wallet.close()

        print()
        print(f"  ✓ Faucet drip complete!")
        print(f"    Amount:    {result['formatted']}")
        print(f"    Recipient: {pk_x[:28]}...")
        print(f"    TX:        {result['tx_hash'][:28]}...")
        print()

        # Import the received note directly into the user's wallet
        if faucet_wallet is not wallet and args.to_sk:
            try:
                # The faucet_drip result has the tx info; we need the
                # recipient tree index from the underlying send() result.
                # Re-derive it from current node state: the recipient note
                # was the second-to-last leaf added in that block.
                tree_idx = result.get("recipient_tree_index")
                if tree_idx is None:
                    # Fallback: query node for current leaf count
                    status = wallet.client.get_status()
                    tree_idx = status.leaf_count - 2  # recipient output

                # We need the rho used for the recipient output. The faucet
                # wallet's send() generated it. It's recorded in the send
                # result but not forwarded through faucet_drip. Query faucet
                # wallet's tx_history for the rho, or just re-derive.
                # Simplest: import using the sk, which recomputes everything.
                wallet.import_note(
                    sk=args.to_sk,
                    value=result["amount"],
                    rho=result.get("out1_rho", str(int(time.time() * 1000) % 10**9 + 1)),
                    asset_id=result["asset_id"],
                    tree_index=tree_idx,
                )
                print(f"  ✓ Note imported to your wallet. Run 'balance' to see it.")
                print()
            except Exception as e:
                print(f"  ⚠ Auto-import failed ({e}). You may need to import manually.")
                print()

    elif cmd == "faucet-history":
        history = wallet.faucet_history(limit=args.limit)
        print()
        if not history:
            print("  No faucet drips yet.")
        else:
            print(f"  Faucet History (last {len(history)}):")
            print(f"  {'─'*56}")
            for d in history:
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(d["dripped_at"]))
                val = format_value(d["amount"], d["asset_id"])
                pk_short = d["recipient_pk"][:20] + "..."
                print(f"  {ts}  {val:>18}  -> {pk_short}")
        print()

    elif cmd == "create-token":
        print()
        print(f"  Creating token {args.symbol.upper()}...")

        result = wallet.register_asset(
            asset_id=args.asset_id,
            symbol=args.symbol,
            name=args.name,
            decimals=args.decimals,
            authority_sk=args.authority_sk,
        )

        print()
        print(f"  ✓ Token registered!")
        print(f"  ┌────────────────────────────────────────────┐")
        sym_line = f"Symbol:    {result['symbol']}"
        print(f"  │  {sym_line:<41} │")
        name_line = f"Name:      {result['name']}"
        print(f"  │  {name_line:<41} │")
        id_line = f"Asset ID:  {result['asset_id']}"
        print(f"  │  {id_line:<41} │")
        dec_line = f"Decimals:  {result['decimals']}"
        print(f"  │  {dec_line:<41} │")
        auth_line = f"Authority: {'Set' if result['authority_sk'] else 'None (read-only)'}"
        print(f"  │  {auth_line:<41} │")
        print(f"  └────────────────────────────────────────────┘")

        # Mint initial supply if requested
        if args.initial_supply > 0:
            if not args.authority_sk:
                print()
                print("  ⚠ --initial-supply requires --authority-sk to mint.")
                print("  Token registered but no supply minted.")
            else:
                print()
                print(f"  Minting initial supply of {format_value(args.initial_supply, args.asset_id)}...")
                print(f"  Generating proof (this may take a moment)...")

                mint_result = wallet.mint_token(
                    asset_id=args.asset_id,
                    amount=args.initial_supply,
                    authority_sk=args.authority_sk,
                    num_notes=args.num_notes,
                )

                print()
                print(f"  ✓ Initial supply minted!")
                print(f"    Amount: {mint_result['formatted']}")
                print(f"    Notes:  {len(mint_result['notes'])}")
                print(f"    TX:     {mint_result['tx_hash'][:32]}...")
                if mint_result.get('block_number') is not None:
                    print(f"    Block:  #{mint_result['block_number']}")
        print()

    elif cmd == "mint-token":
        sym = asset_symbol(args.asset_id)
        print()
        print(f"  Minting {format_value(args.amount, args.asset_id)}...")
        print(f"  Generating proof (this may take a moment)...")

        result = wallet.mint_token(
            asset_id=args.asset_id,
            amount=args.amount,
            authority_sk=args.authority_sk,
            recipient_sk=args.recipient_sk,
            num_notes=args.num_notes,
        )

        print()
        print(f"  ✓ Mint complete!")
        print(f"  ┌────────────────────────────────────────────┐")
        amt_line = f"Amount:  {result['formatted']}"
        print(f"  │  {amt_line:<41} │")
        notes_line = f"Notes:   {len(result['notes'])} created"
        print(f"  │  {notes_line:<41} │")
        tx_line = f"TX:      {result['tx_hash'][:33]}"
        print(f"  │  {tx_line:<41} │")
        if result.get('block_number') is not None:
            blk_line = f"Block:   #{result['block_number']}"
            print(f"  │  {blk_line:<41} │")
        print(f"  └────────────────────────────────────────────┘")
        print()
        for n in result['notes']:
            print(f"    ✓ Note #{n['note_id']}: {format_value(n['value'], args.asset_id)} (index {n['tree_index']})")
        print()

    elif cmd == "list-tokens":
        custom = wallet.get_custom_assets()
        print()
        if not custom:
            print("  No custom tokens registered.")
            print("  Use 'create-token' to register a new token.")
        else:
            print(f"  Custom Tokens ({len(custom)}):")
            print(f"  {'─'*56}")
            print(f"  {'ID':>4}  {'Symbol':<8}  {'Name':<20}  {'Decimals':>8}  {'Auth':>6}")
            print(f"  {'─'*4}  {'─'*8}  {'─'*20}  {'─'*8}  {'─'*6}")
            for a in custom:
                auth = "Yes" if a["authority_sk"] else "No"
                print(f"  {a['asset_id']:>4}  {a['symbol']:<8}  {a['name']:<20}  {a['decimals']:>8}  {auth:>6}")
        print()

    elif cmd == "register-validator":
        result = wallet.register_validator(
            validator_pk_x=args.pk_x,
            name=args.name,
            commission=args.commission,
        )
        print()
        print(f"  ✓ Validator registered!")
        print(f"  ┌────────────────────────────────────────────┐")
        name_line = f"Name:       {result['name']}"
        print(f"  │  {name_line:<41} │")
        pk_line = f"Address:    {result['validator_id'][:33]}"
        print(f"  │  {pk_line:<41} │")
        comm_line = f"Commission: {result['commission']*100:.1f}%"
        print(f"  │  {comm_line:<41} │")
        print(f"  └────────────────────────────────────────────┘")
        print()

    elif cmd == "validators":
        vals = wallet.get_validators()
        print()
        if not vals:
            print("  No validators registered.")
            print("  Use 'register-validator' to add one.")
        else:
            print(f"  Validators ({len(vals)}):")
            print(f"  {'─'*68}")
            print(f"  {'Name':<20}  {'Staked':>12}  {'Stakes':>6}  {'Comm':>6}  {'Status':<8}  Address")
            print(f"  {'─'*20}  {'─'*12}  {'─'*6}  {'─'*6}  {'─'*8}  {'─'*20}")
            for v in vals:
                status = "Active" if v["is_active"] else "Inactive"
                staked = format_value(v["total_staked"], STAKING_ASSET_ID) if v["total_staked"] > 0 else "0 TNKL"
                comm = f"{v['commission']*100:.0f}%"
                print(f"  {v['name']:<20}  {staked:>12}  {v['active_stakes']:>6}  {comm:>6}  {status:<8}  {v['validator_id'][:20]}...")
        print()

    elif cmd == "stake":
        print()
        print(f"  Staking note #{args.note_id}...")
        result = wallet.stake(
            note_id=args.note_id,
            validator_id=args.validator,
        )
        print()
        print(f"  ✓ Stake created!")
        print(f"  ┌────────────────────────────────────────────┐")
        id_line = f"Stake ID:   #{result['stake_id']}"
        print(f"  │  {id_line:<41} │")
        amt_line = f"Amount:     {result['formatted']}"
        print(f"  │  {amt_line:<41} │")
        val_line = f"Validator:  {result['validator']}"
        print(f"  │  {val_line:<41} │")
        apy_line = f"Est. APY:   {STAKING_APY*100:.1f}%"
        print(f"  │  {apy_line:<41} │")
        print(f"  └────────────────────────────────────────────┘")
        print(f"\n  Note #{args.note_id} is now locked. Use 'unstake' to begin withdrawal.")
        print()

    elif cmd == "unstake":
        result = wallet.unstake(stake_id=args.stake_id)
        print()
        print(f"  ✓ Unstaking initiated!")
        print(f"  ┌────────────────────────────────────────────┐")
        id_line = f"Stake ID:   #{result['stake_id']}"
        print(f"  │  {id_line:<41} │")
        amt_line = f"Amount:     {result['formatted']}"
        print(f"  │  {amt_line:<41} │")
        rwd_line = f"Reward:     {result['pending_reward_formatted']}"
        print(f"  │  {rwd_line:<41} │")
        delay_line = f"Unbonding:  {result['delay_seconds']}s"
        print(f"  │  {delay_line:<41} │")
        print(f"  └────────────────────────────────────────────┘")
        print(f"\n  Run 'withdraw-stake {args.stake_id}' after the unbonding period.")
        print()

    elif cmd == "withdraw-stake":
        result = wallet.withdraw_stake(stake_id=args.stake_id)
        print()
        print(f"  ✓ Stake withdrawn!")
        print(f"  ┌────────────────────────────────────────────┐")
        id_line = f"Stake ID:   #{result['stake_id']}"
        print(f"  │  {id_line:<41} │")
        amt_line = f"Returned:   {result['formatted']}"
        print(f"  │  {amt_line:<41} │")
        rwd_line = f"Reward:     {result['reward_formatted']}"
        print(f"  │  {rwd_line:<41} │")
        note_line = f"Note:       #{result['note_id']} (unlocked)"
        print(f"  │  {note_line:<41} │")
        print(f"  └────────────────────────────────────────────┘")
        print()

    elif cmd == "claim-rewards":
        result = wallet.claim_rewards(stake_id=args.stake_id)
        print()
        if result["reward"] == 0:
            print(f"  {result.get('message', 'No rewards to claim yet.')}")
        else:
            print(f"  ✓ Rewards claimed!")
            print(f"  ┌────────────────────────────────────────────┐")
            id_line = f"Stake ID:   #{result['stake_id']}"
            print(f"  │  {id_line:<41} │")
            rwd_line = f"Claimed:    {result['reward_formatted']}"
            print(f"  │  {rwd_line:<41} │")
            note_line = f"New Note:   #{result['note_id']}"
            print(f"  │  {note_line:<41} │")
            print(f"  └────────────────────────────────────────────┘")
        print()

    elif cmd == "stakes":
        stakes = wallet.get_stakes(status=args.status)
        print()
        if not stakes:
            label = f"'{args.status}' " if args.status else ""
            print(f"  No {label}staking positions found.")
            print(f"  Use 'stake <note-id> --validator <pk>' to start staking.")
        else:
            label = f" ({args.status})" if args.status else ""
            print(f"  Staking Positions{label}:")
            print(f"  {'─'*72}")
            print(f"  {'ID':>4}  {'Amount':>12}  {'Validator':<18}  {'Status':<10}  {'Accrued':>12}  {'Claimed':>10}")
            print(f"  {'─'*4}  {'─'*12}  {'─'*18}  {'─'*10}  {'─'*12}  {'─'*10}")
            total_staked = 0
            total_accrued = 0
            for s in stakes:
                print(f"  {s['stake_id']:>4}  {s['formatted']:>12}  {s['validator']:<18}  {s['status']:<10}  {s['accrued_reward_formatted']:>12}  {format_value(s['total_claimed'], STAKING_ASSET_ID):>10}")
                if s["status"] == "active":
                    total_staked += s["amount"]
                    total_accrued += s["accrued_reward"]
            if total_staked > 0:
                print(f"  {'─'*72}")
                print(f"  Total staked: {format_value(total_staked, STAKING_ASSET_ID)}  |  Accrued: {format_value(total_accrued, STAKING_ASSET_ID)}")
        print()

    elif cmd == "epoch-advance":
        result = wallet.advance_epoch()
        print()
        if result["action"] == "bootstrap":
            print(f"  ┌────────────────────────────────────────────┐")
            print(f"  │  Epoch Bootstrapped                        │")
            print(f"  │  Epoch 0 started — awaiting first close.   │")
            print(f"  └────────────────────────────────────────────┘")
        elif result["action"] == "wait":
            print(f"  ┌────────────────────────────────────────────┐")
            print(f"  │  Epoch {result['epoch']:<4} Still Active                │")
            rem_line = f"Remaining: {result['remaining']}s"
            print(f"  │  {rem_line:<41} │")
            print(f"  └────────────────────────────────────────────┘")
        else:
            print(f"  ┌────────────────────────────────────────────┐")
            print(f"  │  Epoch Advanced                            │")
            cl_line = f"Closed:     epoch {result['closed_epoch']}"
            print(f"  │  {cl_line:<41} │")
            nw_line = f"Opened:     epoch {result['new_epoch']}"
            print(f"  │  {nw_line:<41} │")
            rw_line = f"Rewards:    {format_value(result['rewards_distributed'], STAKING_ASSET_ID)} TNKL distributed"
            print(f"  │  {rw_line:<41} │")
            vs_line = f"Validators: {result['active_validators']} active"
            print(f"  │  {vs_line:<41} │")
            if result["details"]:
                print(f"  │{'─'*43}│")
                for d in result["details"]:
                    dl = f"  {d['validator']}: {format_value(d['reward'], STAKING_ASSET_ID)} ({d['share']}%)"
                    print(f"  │  {dl:<41} │")
            print(f"  └────────────────────────────────────────────┘")
        print()

    elif cmd == "epoch-info":
        info = wallet.get_epoch_info(epoch_number=args.epoch)
        print()
        if "error" in info:
            print(f"  {info['error']}")
        else:
            print(f"  ┌────────────────────────────────────────────┐")
            hdr = f"Epoch {info['epoch']} ({info['status']})"
            print(f"  │  {hdr:<41} │")
            print(f"  │{'─'*43}│")
            dur_line = f"Duration:     {info['duration']}s"
            print(f"  │  {dur_line:<41} │")
            stk_line = f"Total Staked: {info['total_staked_formatted']}"
            print(f"  │  {stk_line:<41} │")
            rwd_line = f"Rewards:      {info['total_rewards_formatted']}"
            print(f"  │  {rwd_line:<41} │")
            val_line = f"Validators:   {info['active_validators']}"
            print(f"  │  {val_line:<41} │")
            if info["rewards"]:
                print(f"  │{'─'*43}│")
                print(f"  │  {'Reward Distribution':<41} │")
                for r in info["rewards"][:10]:
                    rl = f"  {r['delegator']}: {r['formatted_reward']}"
                    print(f"  │  {rl:<41} │")
            if info["slashing_events"]:
                print(f"  │{'─'*43}│")
                print(f"  │  {'Slashing Events':<41} │")
                for s in info["slashing_events"]:
                    sl = f"  {s['validator']}: {s['pct']}% ({s['reason']})"
                    print(f"  │  {sl:<41} │")
            print(f"  └────────────────────────────────────────────┘")
        print()

    elif cmd == "validator-set":
        vset = wallet.get_active_validator_set()
        print()
        if not vset:
            print(f"  No active validators meet the minimum stake ({format_value(MIN_VALIDATOR_STAKE, STAKING_ASSET_ID)} TNKL).")
            print(f"  Register validators and delegate stake to activate them.")
        else:
            print(f"  Active Validator Set ({len(vset)}/{MAX_ACTIVE_VALIDATORS}):")
            print(f"  {'─'*60}")
            print(f"  {'#':>3}  {'Validator':<20}  {'Total Staked':>14}  {'Commission':>10}")
            print(f"  {'─'*3}  {'─'*20}  {'─'*14}  {'─'*10}")
            for i, v in enumerate(vset, 1):
                stk_fmt = format_value(v["total_staked"], STAKING_ASSET_ID)
                com_fmt = f"{v['commission']*100:.1f}%"
                print(f"  {i:>3}  {v['name']:<20}  {stk_fmt:>14}  {com_fmt:>10}")
            total = sum(v["total_staked"] for v in vset)
            print(f"  {'─'*60}")
            print(f"  Total staked: {format_value(total, STAKING_ASSET_ID)} TNKL across {len(vset)} validators")
        print()

    elif cmd == "reward-history":
        rewards = wallet.get_reward_history(limit=args.limit)
        print()
        if not rewards:
            print(f"  No reward history found.")
            print(f"  Run 'epoch-advance' to distribute rewards.")
        else:
            print(f"  Reward History (last {len(rewards)}):")
            print(f"  {'─'*72}")
            print(f"  {'Epoch':>5}  {'Validator':<18}  {'Delegator':<16}  {'Reward':>12}  {'Commission':>10}")
            print(f"  {'─'*5}  {'─'*18}  {'─'*16}  {'─'*12}  {'─'*10}")
            for r in rewards:
                com_fmt = format_value(r["commission_paid"], STAKING_ASSET_ID)
                print(f"  {r['epoch']:>5}  {r['validator']:<18}  {r['delegator']:<16}  {r['formatted_reward']:>12}  {com_fmt:>10}")
        print()

    elif cmd == "slash-validator":
        result = wallet.slash_validator(
            validator_id=args.validator_id,
            reason=args.reason,
        )
        print()
        print(f"  ┌────────────────────────────────────────────┐")
        print(f"  │  Validator Slashed                         │")
        print(f"  │{'─'*43}│")
        val_line = f"Validator:  {result['validator']}"
        print(f"  │  {val_line:<41} │")
        rsn_line = f"Reason:     {result['reason']}"
        print(f"  │  {rsn_line:<41} │")
        pct_line = f"Slash:      {result['slash_pct']}%"
        print(f"  │  {pct_line:<41} │")
        amt_line = f"Slashed:    {result['formatted']} TNKL"
        print(f"  │  {amt_line:<41} │")
        aff_line = f"Stakes:     {result['stakes_affected']} affected"
        print(f"  │  {aff_line:<41} │")
        if result["deactivated"]:
            print(f"  │  {'⚠  Validator DEACTIVATED':<41} │")
        print(f"  └────────────────────────────────────────────┘")
        print()

    else:
        print(f"\n  Unknown command: {cmd}")
        print(f"  Run with --help to see available commands.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
