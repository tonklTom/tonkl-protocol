#!/usr/bin/env python3
"""
Obscura Wallet -- SQLite-backed note tracker, balance engine, and transaction builder.

Integrates with:
  - obscura-prover compute  (Poseidon2 hashing, pk derivation)
  - SecureKeyManager         (HD key derivation from master seed)

Schema:
  notes       -- every note the wallet knows about (own + incoming)
  nullifiers  -- spent-note nullifiers (indexed for fast lookup)
  tx_history  -- transaction log with timestamps

Note lifecycle:
  UNSPENT  →  PENDING  →  PROVED  →  CONFIRMED  (normal send)
  UNSPENT  →  UNSPENT                            (receive / deposit)
  PENDING  →  UNSPENT                            (revert on failure / stale)

Usage:
    from wallet import Wallet

    w = Wallet()                          # opens ~/.obscura/wallet.db
    w.deposit(value=1000, asset_id=1)     # create a note from deposit
    print(w.balance())                    # {1: 1000}
    tx = w.build_transfer(to_pk=(x,y), value=500, asset_id=1)
    print(tx)                             # ready-to-prove input JSON
"""

import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import address as addr_mod

# ── HD key manager (optional, for seed-based key derivation) ──────────────
try:
    from secure_key_manager import SecureKeyManager
    _HAS_SKM = True
except ImportError:
    _HAS_SKM = False

# ── SQLCipher support (optional, graceful fallback) ─────────────────────────
# Install with: pip install sqlcipher3-binary
# If unavailable, wallet falls back to plain SQLite with a warning.
try:
    import sqlcipher3 as _sqlcipher
    _HAS_SQLCIPHER = True
except ImportError:
    _HAS_SQLCIPHER = False


def _derive_db_key(passphrase: str) -> str:
    """
    Derive a 256-bit hex key from a passphrase for SQLCipher PRAGMA key.

    Uses PBKDF2-HMAC-SHA256 with 600k iterations and a fixed domain salt.
    The salt is NOT secret — it only provides domain separation so the
    same passphrase used elsewhere yields a different key.
    """
    salt = b"obscura::wallet_db_key_v1"
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000)
    return dk.hex()


def _open_db(db_path: str, passphrase: Optional[str] = None):
    """
    Open a database connection, encrypted if SQLCipher is available
    and a passphrase is provided.

    Returns (connection, encrypted: bool).
    """
    if passphrase and _HAS_SQLCIPHER:
        conn = _sqlcipher.connect(db_path)
        # Use sqlcipher3's own Row class (not sqlite3.Row — they're incompatible)
        conn.row_factory = _sqlcipher.Row
        hex_key = _derive_db_key(passphrase)
        conn.execute(f"PRAGMA key = \"x'{hex_key}'\"")
        # Verify the key works (will throw if wrong key or not encrypted)
        try:
            conn.execute("SELECT count(*) FROM sqlite_master")
        except Exception:
            conn.close()
            raise ValueError(
                "Failed to open encrypted database. Wrong passphrase?"
            )
        return conn, True
    elif passphrase and not _HAS_SQLCIPHER:
        print(
            "[warning] SQLCipher not installed — database will NOT be encrypted.\n"
            "          Install with: pip install sqlcipher3-binary",
            file=sys.stderr,
        )

    conn = sqlite3.connect(db_path)
    # Check if the file is actually an encrypted database we can't read
    try:
        conn.execute("SELECT count(*) FROM sqlite_master")
    except sqlite3.DatabaseError:
        conn.close()
        raise ValueError(
            "Database appears to be encrypted. "
            "Use --passphrase to unlock it."
        )
    return conn, False

# ── Locate the Rust prover binary ───────────────────────────────────────────
_PROVER_SEARCH_PATHS = [
    Path(__file__).resolve().parent.parent.parent / "obscura-prover" / "target" / "release" / "obscura-prover",
    Path.home() / ".obscura" / "bin" / "obscura-prover",
]

def _find_prover() -> Path:
    """Find the obscura-prover binary."""
    for p in _PROVER_SEARCH_PATHS:
        if p.exists() and os.access(p, os.X_OK):
            return p
    raise FileNotFoundError(
        "obscura-prover binary not found. Build with: cd obscura-prover && cargo build --release"
    )


COMPUTE_TIMEOUT_SECS = 30
COMPUTE_MAX_RETRIES = 2
PROVE_TIMEOUT_SECS = 300   # 5 minutes for proof generation
PROVE_MAX_RETRIES = 2


class ProverError(RuntimeError):
    """Raised when the prover binary fails."""
    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def _compute(op_json: dict) -> dict:
    """
    Call `obscura-prover compute` with JSON stdin, return parsed JSON output.

    Retries on timeout or transient errors up to COMPUTE_MAX_RETRIES times.
    """
    prover = _find_prover()
    last_err = None

    for attempt in range(1, COMPUTE_MAX_RETRIES + 1):
        try:
            proc = subprocess.run(
                [str(prover), "compute"],
                input=json.dumps(op_json),
                capture_output=True,
                text=True,
                timeout=COMPUTE_TIMEOUT_SECS,
            )
        except subprocess.TimeoutExpired:
            last_err = f"obscura-prover compute timed out ({COMPUTE_TIMEOUT_SECS}s)"
            if attempt < COMPUTE_MAX_RETRIES:
                print(f"  [retry] Compute timed out, retrying ({attempt}/{COMPUTE_MAX_RETRIES})...")
                continue
            raise ProverError(last_err, retryable=True)

        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            # Signal-based kills (OOM killer, etc.) are retryable
            retryable = proc.returncode < 0 or "memory" in stderr.lower()
            last_err = f"obscura-prover compute failed (exit {proc.returncode}): {stderr}"
            if retryable and attempt < COMPUTE_MAX_RETRIES:
                print(f"  [retry] Compute failed, retrying ({attempt}/{COMPUTE_MAX_RETRIES})...")
                continue
            raise ProverError(last_err, retryable=retryable)

        try:
            return json.loads(proc.stdout.strip())
        except json.JSONDecodeError as e:
            raise ProverError(
                f"obscura-prover compute returned invalid JSON: {e}\n"
                f"stdout: {proc.stdout[:200]}"
            )

    raise ProverError(last_err or "compute failed after retries", retryable=True)


# ── BN254 scalar field modulus (for rho generation) ─────────────────────────
BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617


# ── Asset registry ─────────────────────────────────────────────────────────
# Maps asset_id → (symbol, name, decimals).
# Extend this as new assets are added to the shielded pool.

ASSET_REGISTRY: dict[int, tuple[str, str, int]] = {
    1: ("OBS",  "Obscura",  0),
    2: ("sETH", "Shielded ETH", 18),
    3: ("sDAI", "Shielded DAI",  18),
    4: ("sUSDC","Shielded USDC", 6),
}

def asset_symbol(asset_id: int) -> str:
    """Return the symbol for an asset_id, or 'ASSET-{id}' if unknown."""
    entry = ASSET_REGISTRY.get(asset_id)
    return entry[0] if entry else f"ASSET-{asset_id}"

def asset_name(asset_id: int) -> str:
    """Return the human-readable name for an asset_id."""
    entry = ASSET_REGISTRY.get(asset_id)
    return entry[1] if entry else f"Unknown Asset {asset_id}"

def format_value(value: int, asset_id: int) -> str:
    """Format a value with its asset symbol."""
    sym = asset_symbol(asset_id)
    entry = ASSET_REGISTRY.get(asset_id)
    if entry and entry[2] > 0:
        # Format with decimal places
        decimals = entry[2]
        whole = value // (10 ** decimals)
        frac = value % (10 ** decimals)
        if frac:
            frac_str = f"{frac:0{decimals}d}".rstrip("0")
            return f"{whole}.{frac_str} {sym}"
        return f"{whole} {sym}"
    return f"{value} {sym}"


# ── Note states ─────────────────────────────────────────────────────────────
class NoteState:
    UNSPENT = "unspent"
    PENDING = "pending"    # proving in progress, notes locked
    SPENT   = "spent"      # legacy alias for confirmed
    PROVED  = "proved"     # proof generated, awaiting submission
    CONFIRMED = "confirmed"  # accepted on-chain / by verifier


class TxStatus:
    PENDING   = "pending"    # proving in progress
    PROVED    = "proved"     # proof generated and verified locally
    CONFIRMED = "confirmed"  # accepted on-chain
    FAILED    = "failed"     # proof generation failed, notes reverted


# Stale transaction timeout: if a tx has been pending for longer than this,
# assume the proving process crashed and auto-revert the notes.
STALE_TX_TIMEOUT_SECS = 600  # 10 minutes


# ── Data classes ────────────────────────────────────────────────────────────

@dataclass
class Note:
    """In-memory representation of a wallet note."""
    note_id: int                  # SQLite rowid
    note_index: int               # HD derivation index
    value: int
    asset_id: int
    owner_pk_x: str               # hex, 0x-prefixed
    owner_pk_y: str               # hex, 0x-prefixed
    rho: str                      # hex, 0x-prefixed
    commitment: str               # hex, 0x-prefixed
    nullifier: str                # hex, 0x-prefixed
    state: str = NoteState.UNSPENT
    created_at: float = 0.0
    spent_at: Optional[float] = None
    spent_in_tx: Optional[str] = None


@dataclass
class TransferPlan:
    """Everything needed to build a proving input for a shielded transfer."""
    input_notes: list             # list of Note objects being spent
    output_value: int             # value going to recipient
    output_asset_id: int
    recipient_pk_x: str           # hex
    recipient_pk_y: str           # hex
    change_value: int             # value returning to sender
    change_note_index: int        # HD index for the change note
    fee: int = 0                  # reserved for future fee support


# ── Schema ──────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS notes (
    note_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    note_index    INTEGER NOT NULL,
    value         INTEGER NOT NULL,
    asset_id      INTEGER NOT NULL DEFAULT 1,
    owner_pk_x    TEXT NOT NULL,
    owner_pk_y    TEXT NOT NULL,
    rho           TEXT NOT NULL,
    commitment    TEXT NOT NULL UNIQUE,
    nullifier     TEXT NOT NULL UNIQUE,
    state         TEXT NOT NULL DEFAULT 'unspent',
    created_at    REAL NOT NULL,
    spent_at      REAL,
    spent_in_tx   TEXT
);

CREATE INDEX IF NOT EXISTS idx_notes_state     ON notes(state);
CREATE INDEX IF NOT EXISTS idx_notes_asset     ON notes(asset_id, state);
CREATE INDEX IF NOT EXISTS idx_notes_nullifier ON notes(nullifier);

CREATE TABLE IF NOT EXISTS tx_history (
    tx_id             TEXT PRIMARY KEY,
    direction         TEXT NOT NULL,          -- 'send' or 'receive'
    value             INTEGER NOT NULL,
    asset_id          INTEGER NOT NULL DEFAULT 1,
    counterparty      TEXT,                    -- hid1 address of other party
    sender_address    TEXT,                    -- hid1 address of sender
    input_notes       TEXT,                    -- JSON array of note_ids
    output_notes      TEXT,                    -- JSON array of note_ids
    nullifiers        TEXT,                    -- JSON array of nullifier hashes
    commitments_out   TEXT,                    -- JSON array of output commitments
    proof_path        TEXT,                    -- path to proof file
    public_inputs_path TEXT,                   -- path to public inputs file
    vk_path           TEXT,                    -- path to verification key
    out1_rho          TEXT,                    -- recipient note randomness
    out2_rho          TEXT,                    -- change note randomness
    created_at        REAL NOT NULL,
    confirmed_at      REAL,
    status            TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS wallet_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# ── Wallet ──────────────────────────────────────────────────────────────────

class Wallet:
    """
    SQLite-backed shielded note wallet.

    Stores notes, tracks balances, and builds transaction inputs for proving.
    All cryptographic operations are delegated to the Rust prover binary.
    """

    def __init__(self, db_path: Optional[str] = None, passphrase: Optional[str] = None):
        """
        Open or create the wallet database.

        Args:
            db_path:    Path to wallet.db (default: ~/.obscura/wallet.db)
            passphrase: If provided and SQLCipher is installed, the database
                        is encrypted at rest. The passphrase is stretched via
                        PBKDF2 (600k iterations) before use as the SQLCipher key.
        """
        if db_path is None:
            db_dir = Path.home() / ".obscura"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "wallet.db")
        self.db_path = db_path
        self._conn, self.encrypted = _open_db(db_path, passphrase)
        if not self.encrypted:
            self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()
        # Auto-recover any transactions stuck in pending (e.g. prover crashed)
        self.recover_stale_transactions()

    def _migrate(self):
        """Add columns introduced after the initial schema."""
        existing = {
            r[1] for r in self._conn.execute("PRAGMA table_info(tx_history)")
        }
        migrations = [
            ("sender_address",    "TEXT"),
            ("nullifiers",        "TEXT"),
            ("commitments_out",   "TEXT"),
            ("proof_path",        "TEXT"),
            ("public_inputs_path","TEXT"),
            ("vk_path",           "TEXT"),
            ("out1_rho",          "TEXT"),
            ("out2_rho",          "TEXT"),
            ("confirmed_at",      "REAL"),
        ]
        for col, typ in migrations:
            if col not in existing:
                self._conn.execute(
                    f"ALTER TABLE tx_history ADD COLUMN {col} {typ}"
                )

    def close(self):
        self._conn.close()

    # ── Seed-based key management ──────────────────────────────────────

    def _get_skm(self) -> "SecureKeyManager":
        """Get the SecureKeyManager, raising a clear error if unavailable."""
        if not _HAS_SKM:
            raise RuntimeError(
                "SecureKeyManager not available. Install blake3:\n"
                "  pip3 install blake3 --break-system-packages"
            )
        return SecureKeyManager()

    def has_seed(self) -> bool:
        """Check whether a master seed is stored in Keychain."""
        if not _HAS_SKM:
            return False
        try:
            return SecureKeyManager().has_master_seed()
        except Exception:
            return False

    def init_seed(self, passphrase: str = "") -> str:
        """
        Generate a new 24-word mnemonic and store the master seed.

        Returns the mnemonic phrase. The caller MUST display it for backup.
        """
        skm = self._get_skm()
        if skm.has_master_seed():
            raise ValueError(
                "A master seed already exists. Delete it first with:\n"
                "  python3 wallet.py delete-seed"
            )
        return skm.generate_and_store(passphrase)

    def restore_seed(self, mnemonic: str, passphrase: str = "") -> None:
        """Restore a master seed from a BIP-39 mnemonic phrase."""
        skm = self._get_skm()
        skm.restore_from_mnemonic(mnemonic, passphrase)

    def show_mnemonic(self) -> str | None:
        """Retrieve the stored mnemonic from Keychain (if stored)."""
        if not _HAS_SKM:
            return None
        return SecureKeyManager().show_mnemonic()

    def derive_sk_for_index(self, note_index: int) -> str:
        """
        Derive a spending key for a given note index from the stored seed.

        Returns the sk as a 0x-prefixed hex string. The key material is
        zeroed from memory after conversion.
        """
        skm = self._get_skm()
        sk_int, sk_buf = skm.derive_note_sk_int(note_index)
        sk_hex = f"0x{sk_int:064x}"
        skm.zero_key(sk_buf)
        return sk_hex

    def get_default_sk(self) -> str:
        """
        Get the default spending key (index 0) from the stored seed.

        Used when --sk is not provided on the CLI.
        """
        return self.derive_sk_for_index(0)

    # ── Stale transaction cleanup ───────────────────────────────────────

    def recover_stale_transactions(self) -> int:
        """
        Find transactions stuck in 'pending' state for longer than the
        timeout and revert them. This handles the case where the proving
        process crashed or was killed.

        PROVED transactions are NOT reverted — they have a valid proof
        and are waiting for on-chain confirmation. Only PENDING txs
        (where proving may have crashed) get auto-reverted.

        Returns the number of reverted transactions.
        """
        cutoff = time.time() - STALE_TX_TIMEOUT_SECS
        stale = self._conn.execute(
            "SELECT tx_id FROM tx_history WHERE status = ? AND created_at < ?",
            (TxStatus.PENDING, cutoff),
        ).fetchall()

        count = 0
        for row in stale:
            tx_id = row["tx_id"]
            self._conn.execute(
                "UPDATE notes SET state = ?, spent_in_tx = NULL "
                "WHERE spent_in_tx = ? AND state = ?",
                (NoteState.UNSPENT, tx_id, NoteState.PENDING),
            )
            self._conn.execute(
                "UPDATE tx_history SET status = ? WHERE tx_id = ?",
                (TxStatus.FAILED, tx_id),
            )
            count += 1

        if count:
            self._conn.commit()
            print(f"  [recovery] Reverted {count} stale transaction(s)")

        return count

    # ── Key management ──────────────────────────────────────────────────

    def _next_note_index(self) -> int:
        """Get the next unused HD derivation index."""
        row = self._conn.execute(
            "SELECT COALESCE(MAX(note_index), -1) + 1 AS next_idx FROM notes"
        ).fetchone()
        return row["next_idx"]

    def derive_pk(self, sk_hex: str) -> tuple[str, str]:
        """Derive public key from a spending key via the Rust prover."""
        result = _compute({"op": "derive_pk", "sk": sk_hex})
        return result["pk_x"], result["pk_y"]

    def derive_address(self, sk_hex: str) -> str:
        """Derive a hid1 address from a spending key."""
        pk_x, pk_y = self.derive_pk(sk_hex)
        return addr_mod.encode(pk_x, pk_y)

    def compute_full_note(self, sk_hex: str, value: int, asset_id: int,
                          rho_hex: str) -> dict:
        """
        Compute all note fields from (sk, value, asset_id, rho).
        Returns: {pk_x, pk_y, commitment, nullifier}
        """
        return _compute({
            "op": "full_note",
            "sk": sk_hex,
            "value": str(value),
            "asset_id": str(asset_id),
            "rho": rho_hex,
        })

    # ── Note creation ───────────────────────────────────────────────────

    def _generate_rho(self) -> str:
        """Generate a random rho (note randomness) in the BN254 scalar field."""
        rho_int = int.from_bytes(secrets.token_bytes(32), "big") % BN254_P
        return f"0x{rho_int:064x}"

    def create_note(self, sk_hex: str, note_index: int, value: int,
                    asset_id: int = 1, rho_hex: Optional[str] = None) -> Note:
        """
        Create a new note: derive pk, compute commitment and nullifier,
        store in SQLite.

        Args:
            sk_hex:     Spending key as 0x-prefixed hex.
            note_index: HD derivation index for this note.
            value:      Note value (in smallest denomination).
            asset_id:   Asset type identifier (default 1).
            rho_hex:    Optional randomness; generated if not provided.

        Returns:
            The newly created Note.
        """
        if rho_hex is None:
            rho_hex = self._generate_rho()

        # Delegate all crypto to Rust
        fields = self.compute_full_note(sk_hex, value, asset_id, rho_hex)

        now = time.time()
        cursor = self._conn.execute(
            """INSERT INTO notes
               (note_index, value, asset_id, owner_pk_x, owner_pk_y,
                rho, commitment, nullifier, state, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (note_index, value, asset_id,
             fields["pk_x"], fields["pk_y"],
             rho_hex, fields["commitment"], fields["nullifier"],
             NoteState.UNSPENT, now),
        )
        self._conn.commit()

        return Note(
            note_id=cursor.lastrowid,
            note_index=note_index,
            value=value,
            asset_id=asset_id,
            owner_pk_x=fields["pk_x"],
            owner_pk_y=fields["pk_y"],
            rho=rho_hex,
            commitment=fields["commitment"],
            nullifier=fields["nullifier"],
            state=NoteState.UNSPENT,
            created_at=now,
        )

    def deposit(self, sk_hex: str, value: int, asset_id: int = 1,
                note_index: Optional[int] = None) -> Note:
        """
        Record a deposit (shield) into the wallet.

        This creates an owned note — used when value enters the shielded pool.
        """
        if note_index is None:
            note_index = self._next_note_index()
        note = self.create_note(sk_hex, note_index, value, asset_id)

        tx_id = f"deposit-{note.commitment[:18]}-{int(time.time())}"
        owner_addr = addr_mod.encode(note.owner_pk_x, note.owner_pk_y)
        now = time.time()
        self._conn.execute(
            """INSERT INTO tx_history
               (tx_id, direction, value, asset_id,
                sender_address, input_notes, output_notes,
                commitments_out, created_at, confirmed_at, status)
               VALUES (?, 'receive', ?, ?, ?, '[]', ?, ?, ?, ?, 'confirmed')""",
            (tx_id, value, asset_id,
             owner_addr,
             json.dumps([note.note_id]),
             json.dumps([note.commitment]),
             now, now),
        )
        self._conn.commit()
        return note

    def receive_note(self, sk_hex: str, note_index: int, value: int,
                     asset_id: int, rho_hex: str) -> Note:
        """
        Record receiving a note from a transfer (output side of someone
        else's transaction). The caller provides the exact rho used.
        """
        return self.create_note(sk_hex, note_index, value, asset_id, rho_hex)

    # ── Queries ─────────────────────────────────────────────────────────

    def _row_to_note(self, row: sqlite3.Row) -> Note:
        return Note(
            note_id=row["note_id"],
            note_index=row["note_index"],
            value=row["value"],
            asset_id=row["asset_id"],
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

    def get_unspent_notes(self, asset_id: Optional[int] = None) -> list[Note]:
        """Return all unspent notes, optionally filtered by asset_id."""
        if asset_id is not None:
            rows = self._conn.execute(
                "SELECT * FROM notes WHERE state = ? AND asset_id = ? ORDER BY value DESC",
                (NoteState.UNSPENT, asset_id),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM notes WHERE state = ? ORDER BY asset_id, value DESC",
                (NoteState.UNSPENT,),
            ).fetchall()
        return [self._row_to_note(r) for r in rows]

    def get_note_by_commitment(self, commitment: str) -> Optional[Note]:
        """Look up a note by its commitment hash."""
        row = self._conn.execute(
            "SELECT * FROM notes WHERE commitment = ?", (commitment,)
        ).fetchone()
        return self._row_to_note(row) if row else None

    def is_nullified(self, nullifier: str) -> bool:
        """Check if a nullifier has been spent (or is in any locked state)."""
        row = self._conn.execute(
            "SELECT 1 FROM notes WHERE nullifier = ? AND state IN (?, ?, ?, ?)",
            (nullifier, NoteState.SPENT, NoteState.PENDING,
             NoteState.PROVED, NoteState.CONFIRMED),
        ).fetchone()
        return row is not None

    def balance(self, asset_id: Optional[int] = None) -> dict[int, int]:
        """
        Return total unspent balance per asset.

        If asset_id is given, returns {asset_id: total}.
        Otherwise returns {asset_id: total, ...} for all assets.
        """
        if asset_id is not None:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(value), 0) AS total FROM notes WHERE state = ? AND asset_id = ?",
                (NoteState.UNSPENT, asset_id),
            ).fetchone()
            return {asset_id: row["total"]}

        rows = self._conn.execute(
            "SELECT asset_id, COALESCE(SUM(value), 0) AS total FROM notes WHERE state = ? GROUP BY asset_id",
            (NoteState.UNSPENT,),
        ).fetchall()
        return {r["asset_id"]: r["total"] for r in rows}

    def history(self, limit: int = 50) -> list[dict]:
        """Return recent transaction history."""
        rows = self._conn.execute(
            "SELECT * FROM tx_history ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_tx(self, tx_id_prefix: str) -> Optional[dict]:
        """Look up a transaction by exact ID or prefix match."""
        row = self._conn.execute(
            "SELECT * FROM tx_history WHERE tx_id = ?", (tx_id_prefix,)
        ).fetchone()
        if row:
            return dict(row)
        # Prefix match
        rows = self._conn.execute(
            "SELECT * FROM tx_history WHERE tx_id LIKE ? LIMIT 2",
            (tx_id_prefix + "%",),
        ).fetchall()
        if len(rows) == 1:
            return dict(rows[0])
        if len(rows) > 1:
            raise ValueError(
                f"Ambiguous tx_id prefix '{tx_id_prefix}' matches "
                f"{len(rows)} transactions"
            )
        return None

    # ── Coin selection ──────────────────────────────────────────────────

    def select_notes(self, value: int, asset_id: int = 1) -> list[Note]:
        """
        Select unspent notes that cover the requested value.

        Strategy: largest-first greedy. Selects the fewest notes needed.
        The circuit currently supports 1 input, but this is designed to
        scale to multi-input when the circuit does.

        Raises ValueError if insufficient balance.
        """
        notes = self.get_unspent_notes(asset_id)
        if not notes:
            raise ValueError(f"No unspent notes for asset {asset_id}")

        total_available = sum(n.value for n in notes)
        if total_available < value:
            raise ValueError(
                f"Insufficient balance: need {value}, have {total_available} "
                f"(asset {asset_id})"
            )

        # Largest-first greedy
        selected = []
        running = 0
        for note in notes:  # already sorted DESC by value
            selected.append(note)
            running += note.value
            if running >= value:
                break

        return selected

    # ── Transaction building ────────────────────────────────────────────

    def build_transfer(
        self,
        recipient: str,
        value: int,
        asset_id: int = 1,
    ) -> TransferPlan:
        """
        Build a transfer plan: select input notes, compute change.

        Does NOT mark notes as spent yet — that happens at prove time.

        Args:
            recipient: Either a hid1 address or a raw pk_x hex string.
                       If hid1, decoded automatically. If raw hex, pk_y
                       must be derived separately (or use hid1 addresses).
            value:     Amount to send.
            asset_id:  Asset type.

        Returns a TransferPlan with all the data needed for proving.
        """
        # Decode recipient address
        if recipient.startswith("hid1"):
            pk_x, pk_y = addr_mod.decode(recipient)
        elif recipient.startswith("0x"):
            raise ValueError(
                "Raw hex addresses require both pk_x and pk_y. "
                "Use a hid1 address instead."
            )
        else:
            raise ValueError(
                f"Invalid recipient: '{recipient[:20]}...'. "
                f"Use a hid1 address (hid1q...)."
            )

        input_notes = self.select_notes(value, asset_id)
        total_input = sum(n.value for n in input_notes)
        change = total_input - value

        return TransferPlan(
            input_notes=input_notes,
            output_value=value,
            output_asset_id=asset_id,
            recipient_pk_x=pk_x,
            recipient_pk_y=pk_y,
            change_value=change,
            change_note_index=self._next_note_index(),
        )

    def mark_notes_pending(self, notes: list[Note], tx_id: str) -> None:
        """Mark notes as pending (proving in progress)."""
        for note in notes:
            self._conn.execute(
                "UPDATE notes SET state = ?, spent_in_tx = ? WHERE note_id = ?",
                (NoteState.PENDING, tx_id, note.note_id),
            )
        self._conn.commit()

    def mark_notes_proved(self, notes: list[Note], tx_id: str) -> None:
        """Mark notes as proved (proof generated, awaiting confirmation)."""
        for note in notes:
            self._conn.execute(
                "UPDATE notes SET state = ?, spent_in_tx = ? WHERE note_id = ?",
                (NoteState.PROVED, tx_id, note.note_id),
            )
        self._conn.commit()

    def mark_notes_spent(self, notes: list[Note], tx_id: str) -> None:
        """Mark notes as spent (proof submitted and accepted)."""
        now = time.time()
        for note in notes:
            self._conn.execute(
                "UPDATE notes SET state = ?, spent_at = ?, spent_in_tx = ? WHERE note_id = ?",
                (NoteState.SPENT, now, tx_id, note.note_id),
            )
        self._conn.commit()

    def revert_pending(self, tx_id: str) -> None:
        """Revert pending/proved notes back to unspent (e.g. proof failed)."""
        self._conn.execute(
            "UPDATE notes SET state = ?, spent_in_tx = NULL "
            "WHERE spent_in_tx = ? AND state IN (?, ?)",
            (NoteState.UNSPENT, tx_id, NoteState.PENDING, NoteState.PROVED),
        )
        self._conn.commit()

    def record_send(
        self,
        plan: TransferPlan,
        tx_id: str,
        change_note: Optional[Note] = None,
        sender_address: Optional[str] = None,
        proof_path: Optional[str] = None,
        public_inputs_path: Optional[str] = None,
        vk_path: Optional[str] = None,
        out1_rho: Optional[str] = None,
        out2_rho: Optional[str] = None,
    ) -> None:
        """Record a send transaction in history with full proof artifacts."""
        input_ids = [n.note_id for n in plan.input_notes if n.note_id > 0]
        output_ids = [change_note.note_id] if change_note else []
        nullifiers = [n.nullifier for n in plan.input_notes if n.note_id > 0]
        commitments_out = []
        if change_note:
            commitments_out.append(change_note.commitment)

        # Encode counterparty as hid1 address
        counterparty_addr = addr_mod.encode(
            plan.recipient_pk_x, plan.recipient_pk_y
        )

        self._conn.execute(
            """INSERT INTO tx_history
               (tx_id, direction, value, asset_id, counterparty,
                sender_address, input_notes, output_notes,
                nullifiers, commitments_out,
                proof_path, public_inputs_path, vk_path,
                out1_rho, out2_rho,
                created_at, status)
               VALUES (?, 'send', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
            (tx_id, plan.output_value, plan.output_asset_id,
             counterparty_addr, sender_address,
             json.dumps(input_ids), json.dumps(output_ids),
             json.dumps(nullifiers), json.dumps(commitments_out),
             proof_path, public_inputs_path, vk_path,
             out1_rho, out2_rho,
             time.time()),
        )
        self._conn.commit()

    def prove_tx(self, tx_id: str) -> None:
        """
        Mark a transaction as proved (proof generated and locally verified).

        This is an intermediate state between PENDING and CONFIRMED.
        Notes transition from PENDING → PROVED (still locked, not spendable).
        """
        self._conn.execute(
            "UPDATE tx_history SET status = ? WHERE tx_id = ?",
            (TxStatus.PROVED, tx_id),
        )
        self._conn.execute(
            "UPDATE notes SET state = ? WHERE spent_in_tx = ? AND state = ?",
            (NoteState.PROVED, tx_id, NoteState.PENDING),
        )
        self._conn.commit()

    def confirm_tx(self, tx_id: str) -> None:
        """
        Mark a transaction as confirmed (accepted on-chain / by verifier).

        Notes transition from PROVED → SPENT with a spent_at timestamp.
        Can also handle PENDING → SPENT for legacy/direct confirmation.
        """
        now = time.time()
        self._conn.execute(
            "UPDATE tx_history SET status = ?, confirmed_at = ? WHERE tx_id = ?",
            (TxStatus.CONFIRMED, now, tx_id),
        )
        # Finalize any proved or pending notes associated with this tx
        self._conn.execute(
            "UPDATE notes SET state = ?, spent_at = ? "
            "WHERE spent_in_tx = ? AND state IN (?, ?)",
            (NoteState.SPENT, now, tx_id, NoteState.PROVED, NoteState.PENDING),
        )
        self._conn.commit()

    def fail_tx(self, tx_id: str) -> None:
        """Mark a transaction as failed and revert pending/proved notes."""
        self._conn.execute(
            "UPDATE tx_history SET status = ? WHERE tx_id = ?",
            (TxStatus.FAILED, tx_id),
        )
        # Revert any notes that were pending or proved for this tx
        self._conn.execute(
            "UPDATE notes SET state = ?, spent_in_tx = NULL "
            "WHERE spent_in_tx = ? AND state IN (?, ?)",
            (NoteState.UNSPENT, tx_id, NoteState.PENDING, NoteState.PROVED),
        )
        self._conn.commit()

    # ── Proving pipeline ──────────────────────────────────────────────

    def _build_prover_dict(
        self,
        plan: TransferPlan,
        sender_sk_hex: str,
        out1_rho_hex: Optional[str] = None,
        out2_rho_hex: Optional[str] = None,
    ) -> tuple[dict, str, str]:
        """
        Build the full prover dict matching the 2-in / 2-out transfer circuit.

        The circuit expects two input notes and two output notes. When the
        wallet only has one real input, the second input is a zero-value
        dummy note (same sk, value=0). This satisfies value conservation:
            in1_value + in2_value == out1_value + out2_value + fee

        Returns:
            (prover_dict, out1_rho, out2_rho) — the rhos are needed to
            track the output notes after proving succeeds.
        """
        if len(plan.input_notes) > 2:
            raise ValueError(
                f"Circuit supports max 2 input notes, got {len(plan.input_notes)}"
            )

        if out1_rho_hex is None:
            out1_rho_hex = self._generate_rho()
        if out2_rho_hex is None:
            out2_rho_hex = self._generate_rho()

        in1 = plan.input_notes[0]

        # Second input: real note or zero-value dummy
        if len(plan.input_notes) == 2:
            in2 = plan.input_notes[1]
            in2_sk = sender_sk_hex  # same owner
        else:
            # Dummy note: value=0, same sk/asset, fresh rho
            dummy_rho = self._generate_rho()
            dummy_fields = self.compute_full_note(
                sender_sk_hex, 0, plan.output_asset_id, dummy_rho
            )
            in2 = Note(
                note_id=-1, note_index=-1, value=0,
                asset_id=plan.output_asset_id,
                owner_pk_x=dummy_fields["pk_x"],
                owner_pk_y=dummy_fields["pk_y"],
                rho=dummy_rho,
                commitment=dummy_fields["commitment"],
                nullifier=dummy_fields["nullifier"],
                state="dummy",
            )
            in2_sk = sender_sk_hex

        # Compute output note fields via Rust prover
        out1_fields = _compute({
            "op": "full_note",
            "sk": sender_sk_hex,      # recipient sk is unknown; we use
            "value": str(plan.output_value),  # recipient pk directly below
            "asset_id": str(plan.output_asset_id),
            "rho": out1_rho_hex,
        })
        # Override pk with recipient's actual pk (we don't know their sk)
        out1_cm = _compute({
            "op": "commitment",
            "value": str(plan.output_value),
            "asset_id": str(plan.output_asset_id),
            "owner_pk_x": plan.recipient_pk_x,
            "owner_pk_y": plan.recipient_pk_y,
            "rho": out1_rho_hex,
        })

        out2_fields = self.compute_full_note(
            sender_sk_hex, plan.change_value, plan.output_asset_id, out2_rho_hex
        )

        # Merkle tree: both input notes are leaves. For MVP we build a
        # minimal 2-leaf tree: positions 0 and 1 in a depth-32 tree.
        # Sibling of index 0 is cm_in2, rest of path is zeros.
        # Sibling of index 1 is cm_in1, rest of path is zeros.
        MERKLE_DEPTH = 32
        path_for_0 = [in2.commitment] + [str(0)] * (MERKLE_DEPTH - 1)
        path_for_1 = [in1.commitment] + [str(0)] * (MERKLE_DEPTH - 1)
        bits_for_0 = ["false"] * MERKLE_DEPTH
        bits_for_1 = ["true"] + ["false"] * (MERKLE_DEPTH - 1)

        # Compute Merkle root: hash(cm_in1, cm_in2), then hash up with zeros
        mr_result = _compute({
            "op": "commitment",  # reuse as 2-input hash
            "value": "0", "asset_id": "0",
            "owner_pk_x": in1.commitment,
            "owner_pk_y": in2.commitment,
            "rho": "0",
        })
        # Actually, we need to use poseidon2_hash_2 for Merkle. But the
        # compute subcommand doesn't expose raw hash yet. Let's compute
        # the Merkle root by calling the Rust binary's compute with a
        # dedicated merkle_root op if available, or just use the hasher
        # approach from generate_witness.py.
        #
        # For now, we'll call the hasher circuit via generate_witness.py's
        # run_hasher function to get the correct Merkle root.
        # But that requires nargo + obscura-hasher. Instead, let's add a
        # poseidon2_hash op to the compute subcommand.
        #
        # SIMPLER APPROACH: call obscura-prover compute with the full note
        # data and let the prover's run_hasher equivalent compute merkle root.
        # But that doesn't exist yet.
        #
        # PRAGMATIC APPROACH: use generate_witness.py's infrastructure directly.

        # Import and use the hasher from generate_witness.py
        import importlib.util
        gw_path = os.path.join(os.path.dirname(__file__), "generate_witness.py")
        spec = importlib.util.spec_from_file_location("generate_witness", gw_path)
        gw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gw)

        # Convert sk hex to int for the hasher
        sk_int = int(sender_sk_hex, 16)
        in1_rho_int = int(in1.rho, 16)
        in2_rho_int = int(in2.rho, 16)
        out1_rho_int = int(out1_rho_hex, 16)
        out2_rho_int = int(out2_rho_hex, 16)

        # Derive out2 sk (change goes back to sender)
        out2_pk_x = out2_fields["pk_x"]
        out2_pk_y = out2_fields["pk_y"]

        hasher_inputs = {
            "in1_value": in1.value, "in1_asset_id": in1.asset_id,
            "in1_rho": in1_rho_int, "in1_sk": sk_int,
            "in2_value": in2.value, "in2_asset_id": in2.asset_id,
            "in2_rho": in2_rho_int, "in2_sk": sk_int,
            "out1_value": plan.output_value, "out1_asset_id": plan.output_asset_id,
            "out1_rho": out1_rho_int, "out1_sk": sk_int,
            "out2_value": plan.change_value, "out2_asset_id": plan.output_asset_id,
            "out2_rho": out2_rho_int, "out2_sk": sk_int,
        }

        print("  [hasher] Computing hashes via obscura-hasher...")
        (merkle_root, cm_in1, cm_in2, nf_1, nf_2, cm_out_1, cm_out_2,
         in1_pk_x, in1_pk_y, in2_pk_x, in2_pk_y,
         out1_pk_x, out1_pk_y, out2_pk_x, out2_pk_y) = gw.run_hasher(hasher_inputs)

        # Rebuild Merkle paths using hasher's commitments
        path_for_0 = [str(cm_in2)] + ["0"] * (MERKLE_DEPTH - 1)
        path_for_1 = [str(cm_in1)] + ["0"] * (MERKLE_DEPTH - 1)

        # Build the prover dict matching the circuit's exact field names
        prover = {
            # Public inputs
            "merkle_root": merkle_root, "nf_1": nf_1, "nf_2": nf_2,
            "cm_out_1": cm_out_1, "cm_out_2": cm_out_2,
            "fee": plan.fee, "asset_id": plan.output_asset_id,
            # Input 1
            "in1_value": in1.value,
            "in1_owner_pk_x": in1_pk_x, "in1_owner_pk_y": in1_pk_y,
            "in1_rho": in1_rho_int, "in1_owner_sk": sk_int,
            "in1_merkle_bits": bits_for_0, "in1_merkle_path": path_for_0,
            # Input 2
            "in2_value": in2.value,
            "in2_owner_pk_x": in2_pk_x, "in2_owner_pk_y": in2_pk_y,
            "in2_rho": in2_rho_int, "in2_owner_sk": sk_int,
            "in2_merkle_bits": bits_for_1, "in2_merkle_path": path_for_1,
            # Output 1 (recipient)
            "out1_value": plan.output_value,
            "out1_owner_pk_x": out1_pk_x, "out1_owner_pk_y": out1_pk_y,
            "out1_rho": out1_rho_int,
            # Output 2 (change)
            "out2_value": plan.change_value,
            "out2_owner_pk_x": out2_pk_x, "out2_owner_pk_y": out2_pk_y,
            "out2_rho": out2_rho_int,
        }

        return prover, out1_rho_hex, out2_rho_hex

    def execute_send(
        self,
        recipient: str,
        value: int,
        sender_sk_hex: str,
        asset_id: int = 1,
        max_prove_retries: int = PROVE_MAX_RETRIES,
    ) -> dict:
        """
        Full send pipeline: plan → hash → prove → update wallet state.

        This is the main entry point for sending a shielded transfer.

        Steps:
          1. Build transfer plan (coin selection)
          2. Compute all hashes via obscura-hasher
          3. Call obscura-prover prove (with retries on transient failure)
          4. Transition notes to PROVED state
          5. Create change note in wallet
          6. Record transaction in history
          7. Mark tx as PROVED (confirmation is a separate step)

        Error handling:
          - Hasher failures revert notes before raising
          - Prover timeouts and signal-kills (OOM) trigger automatic retry
          - All failures revert notes to UNSPENT and mark tx as FAILED
          - Retries reuse the same tx_id and prover inputs (deterministic)

        Args:
            recipient:         hid1 address of the recipient.
            value:             Amount to send.
            sender_sk_hex:     Sender's spending key (0x hex).
            asset_id:          Asset type (default 1).
            max_prove_retries: Max proof generation retries (default 2).

        Returns:
            Dict with tx_id, proof_path, and summary info.
        """
        import importlib.util

        # Step 1: Build transfer plan
        plan = self.build_transfer(recipient, value, asset_id)
        tx_id = f"send-{secrets.token_hex(8)}"

        print(f"  [plan] Send {value} to {recipient[:16]}...{recipient[-6:]}")
        print(f"  [plan] Using {len(plan.input_notes)} input(s), change={plan.change_value}")
        print(f"  [plan] tx_id: {tx_id}")

        # Step 2: Build prover dict (calls hasher for Merkle root + hashes)
        # This can fail if the hasher crashes or nargo isn't installed.
        try:
            prover_dict, out1_rho, out2_rho = self._build_prover_dict(
                plan, sender_sk_hex
            )
        except (SystemExit, Exception) as e:
            # run_hasher calls sys.exit(1) on failure — catch it here
            raise ProverError(
                f"Hash computation failed: {e}\n"
                f"Check that nargo is installed and obscura-hasher compiles."
            ) from e

        # Mark notes as pending before proving
        real_notes = [n for n in plan.input_notes if n.note_id > 0]
        self.mark_notes_pending(real_notes, tx_id)

        # Step 3: Call obscura-prover prove (with retries)
        gw_path = os.path.join(os.path.dirname(__file__), "generate_witness.py")
        spec = importlib.util.spec_from_file_location("generate_witness", gw_path)
        gw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gw)

        circuit_json = os.path.join(
            gw.TRANSFER_DIR, "target", "obscura_transfer.json"
        )
        output_dir = os.path.join(gw.TRANSFER_DIR, "target")

        if not os.path.isfile(circuit_json):
            self.revert_pending(tx_id)
            raise FileNotFoundError(
                f"Circuit artifact not found: {circuit_json}\n"
                f"Run: cd obscura-transfer && nargo compile"
            )

        last_prove_err = None
        for attempt in range(1, max_prove_retries + 1):
            print(f"  [prove] Calling obscura-prover prove"
                  f"{f' (attempt {attempt}/{max_prove_retries})' if attempt > 1 else ''}...")

            try:
                returncode, stderr = gw._run_rust_prover_prove(
                    prover_dict, circuit_json, output_dir,
                )
            except subprocess.TimeoutExpired:
                last_prove_err = f"Proof generation timed out ({PROVE_TIMEOUT_SECS}s)"
                print(f"  [error] {last_prove_err}")
                if attempt < max_prove_retries:
                    print(f"  [retry] Retrying...")
                    continue
                break

            # Print prover output
            for line in stderr.strip().splitlines():
                print(f"    {line}")

            if returncode == 0:
                last_prove_err = None
                break

            # Determine if retryable (signal kills, OOM, etc.)
            retryable = returncode < 0 or "memory" in stderr.lower()
            last_prove_err = (
                f"Proof generation failed (exit {returncode}):\n"
                f"{stderr[:500]}"
            )
            print(f"  [error] Prove failed (exit {returncode})")

            if retryable and attempt < max_prove_retries:
                print(f"  [retry] Transient failure, retrying...")
                continue
            elif not retryable:
                # Non-retryable error (e.g. bad witness) — don't waste time
                print(f"  [error] Non-retryable error, aborting")
                break

        if last_prove_err:
            # All retries exhausted — revert everything
            self.fail_tx(tx_id) if self._tx_exists(tx_id) else None
            self.revert_pending(tx_id)
            raise ProverError(last_prove_err, retryable=False)

        print("  [prove] Proof generated successfully")

        # Step 4: Transition notes and tx from PENDING → PROVED
        self.mark_notes_proved(real_notes, tx_id)

        # Step 5: Create change note (if non-zero change)
        change_note = None
        if plan.change_value > 0:
            change_note = self.create_note(
                sk_hex=sender_sk_hex,
                note_index=plan.change_note_index,
                value=plan.change_value,
                asset_id=asset_id,
                rho_hex=out2_rho,
            )
            print(f"  [change] Created change note #{change_note.note_id} "
                  f"value={change_note.value}")

        # Step 6: Record in history with full artifact paths
        proof_path = os.path.join(output_dir, "proof", "proof")
        public_inputs_path = os.path.join(output_dir, "proof", "public_inputs")
        vk_path = os.path.join(output_dir, "vk", "vk")
        sender_addr = self.derive_address(sender_sk_hex)

        self.record_send(
            plan, tx_id, change_note,
            sender_address=sender_addr,
            proof_path=proof_path,
            public_inputs_path=public_inputs_path,
            vk_path=vk_path,
            out1_rho=out1_rho,
            out2_rho=out2_rho,
        )

        # Step 7: Mark tx as PROVED (not confirmed yet — that's a separate step)
        self.prove_tx(tx_id)
        print("  [state] Transaction marked as PROVED — awaiting confirmation")

        # Build receipt for the recipient
        receipt = {
            "version": 1,
            "type": "obscura_note_receipt",
            "value": value,
            "asset_id": asset_id,
            "rho": out1_rho,
            "sender_address": sender_addr,
            "tx_id": tx_id,
        }

        result = {
            "tx_id": tx_id,
            "status": TxStatus.PROVED,
            "value_sent": value,
            "change": plan.change_value,
            "recipient": recipient,
            "proof_path": proof_path,
            "input_notes_spent": [n.note_id for n in real_notes],
            "change_note_id": change_note.note_id if change_note else None,
            "receipt": receipt,
        }
        return result

    def _tx_exists(self, tx_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM tx_history WHERE tx_id = ?", (tx_id,)
        ).fetchone()
        return row is not None

    # ── Note export / import (receive pipeline) ─────────────────────────

    def export_note_receipt(self, tx_id: str) -> dict:
        """
        Export a note receipt that the recipient can use to claim a note.

        The receipt contains everything the recipient needs:
          - value, asset_id, rho  (to recompute commitment with their pk)
          - commitment            (to verify the note is valid)
          - sender_address        (for their records)
          - tx_id                 (for correlation)

        The recipient combines this with their own sk to derive pk, recompute
        the commitment (verifying ownership), and compute the nullifier.
        """
        tx = self.get_tx(tx_id)
        if not tx:
            raise ValueError(f"Transaction not found: {tx_id}")
        if tx["direction"] != "send":
            raise ValueError(f"Can only export receipts for send transactions")

        out1_rho = tx.get("out1_rho")
        if not out1_rho:
            raise ValueError(
                f"Transaction {tx_id} has no out1_rho — "
                f"was it created before the enriched history update?"
            )

        return {
            "version": 1,
            "type": "obscura_note_receipt",
            "value": tx["value"],
            "asset_id": tx["asset_id"],
            "rho": out1_rho,
            "sender_address": tx.get("sender_address"),
            "tx_id": tx_id,
        }

    def receive(
        self,
        sk_hex: str,
        value: int,
        asset_id: int,
        rho_hex: str,
        sender_address: Optional[str] = None,
        note_index: Optional[int] = None,
    ) -> Note:
        """
        Receive an incoming note by reconstructing it from receipt data.

        The receiver provides their sk plus the note parameters from the
        sender's receipt. The wallet:
          1. Derives pk from sk
          2. Computes commitment = Poseidon2(value, asset_id, pk_x, pk_y, rho, ...)
          3. Computes nullifier = Poseidon2(commitment, sk)
          4. Stores the note as unspent
          5. Records a receive transaction

        Args:
            sk_hex:         Receiver's spending key (0x hex)
            value:          Note value from the receipt
            asset_id:       Asset ID from the receipt
            rho_hex:        Note randomness from the receipt
            sender_address: Optional hid1 address of sender (for records)
            note_index:     Optional HD derivation index (auto-assigned if None)

        Returns:
            The newly created Note.
        """
        if note_index is None:
            note_index = self._next_note_index()

        # Compute full note fields using receiver's sk
        fields = self.compute_full_note(sk_hex, value, asset_id, rho_hex)

        # Check for duplicate (same commitment already in wallet)
        existing = self.get_note_by_commitment(fields["commitment"])
        if existing:
            raise ValueError(
                f"Note already in wallet (note #{existing.note_id}, "
                f"commitment={fields['commitment'][:18]}...)"
            )

        # Create the note
        note = self.create_note(
            sk_hex=sk_hex,
            note_index=note_index,
            value=value,
            asset_id=asset_id,
            rho_hex=rho_hex,
        )

        # Record receive transaction
        owner_addr = addr_mod.encode(note.owner_pk_x, note.owner_pk_y)
        tx_id = f"receive-{note.commitment[:18]}-{int(time.time())}"
        now = time.time()
        self._conn.execute(
            """INSERT INTO tx_history
               (tx_id, direction, value, asset_id,
                counterparty, sender_address,
                input_notes, output_notes, commitments_out,
                created_at, confirmed_at, status)
               VALUES (?, 'receive', ?, ?, ?, ?, '[]', ?, ?, ?, ?, 'confirmed')""",
            (tx_id, value, asset_id,
             sender_address, owner_addr,
             json.dumps([note.note_id]),
             json.dumps([note.commitment]),
             now, now),
        )
        self._conn.commit()

        return note

    def import_receipt(self, receipt: dict, sk_hex: str) -> Note:
        """
        Import a note from a receipt dict (as exported by export_note_receipt).

        Validates the receipt format, then calls receive().
        """
        if receipt.get("type") != "obscura_note_receipt":
            raise ValueError("Invalid receipt: missing or wrong 'type' field")
        if receipt.get("version", 0) > 1:
            raise ValueError(f"Unsupported receipt version: {receipt['version']}")

        required = ["value", "asset_id", "rho"]
        for field in required:
            if field not in receipt:
                raise ValueError(f"Invalid receipt: missing '{field}'")

        return self.receive(
            sk_hex=sk_hex,
            value=receipt["value"],
            asset_id=receipt["asset_id"],
            rho_hex=receipt["rho"],
            sender_address=receipt.get("sender_address"),
        )

    # ── Stats ───────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return wallet statistics."""
        total = self._conn.execute("SELECT COUNT(*) AS n FROM notes").fetchone()["n"]
        unspent = self._conn.execute(
            "SELECT COUNT(*) AS n FROM notes WHERE state = ?", (NoteState.UNSPENT,)
        ).fetchone()["n"]
        spent = self._conn.execute(
            "SELECT COUNT(*) AS n FROM notes WHERE state = ?", (NoteState.SPENT,)
        ).fetchone()["n"]
        pending = self._conn.execute(
            "SELECT COUNT(*) AS n FROM notes WHERE state = ?", (NoteState.PENDING,)
        ).fetchone()["n"]
        proved = self._conn.execute(
            "SELECT COUNT(*) AS n FROM notes WHERE state = ?", (NoteState.PROVED,)
        ).fetchone()["n"]
        confirmed = self._conn.execute(
            "SELECT COUNT(*) AS n FROM notes WHERE state = ?", (NoteState.CONFIRMED,)
        ).fetchone()["n"]
        txs = self._conn.execute("SELECT COUNT(*) AS n FROM tx_history").fetchone()["n"]

        # Tx status breakdown
        tx_proved = self._conn.execute(
            "SELECT COUNT(*) AS n FROM tx_history WHERE status = ?", (TxStatus.PROVED,)
        ).fetchone()["n"]
        tx_confirmed = self._conn.execute(
            "SELECT COUNT(*) AS n FROM tx_history WHERE status = ?", (TxStatus.CONFIRMED,)
        ).fetchone()["n"]
        tx_pending = self._conn.execute(
            "SELECT COUNT(*) AS n FROM tx_history WHERE status = ?", (TxStatus.PENDING,)
        ).fetchone()["n"]
        tx_failed = self._conn.execute(
            "SELECT COUNT(*) AS n FROM tx_history WHERE status = ?", (TxStatus.FAILED,)
        ).fetchone()["n"]

        return {
            "db_path": self.db_path,
            "total_notes": total,
            "unspent": unspent,
            "spent": spent,
            "pending": pending,
            "proved": proved,
            "confirmed": confirmed,
            "transactions": txs,
            "tx_proved": tx_proved,
            "tx_confirmed": tx_confirmed,
            "tx_pending": tx_pending,
            "tx_failed": tx_failed,
            "balances": self.balance(),
        }


# ── CLI ─────────────────────────────────────────────────────────────────────

def _resolve_sk(args, wallet: Wallet, label: str = "operation") -> str:
    """
    Resolve the spending key: use --sk if provided, otherwise derive from
    the stored master seed.

    This lets users omit --sk once they've run `wallet.py init`.
    """
    sk = getattr(args, "sk", None)
    if sk:
        return sk

    if not wallet.has_seed():
        print(f"  [error] No --sk provided and no master seed stored.")
        print(f"          Either pass --sk <hex> or run: python3 wallet.py init")
        sys.exit(1)

    try:
        sk = wallet.get_default_sk()
        return sk
    except RuntimeError as e:
        print(f"  [error] Failed to derive key from seed: {e}")
        sys.exit(1)


def _cli():
    """Simple CLI for wallet operations."""
    import argparse

    parser = argparse.ArgumentParser(description="Obscura Wallet")
    parser.add_argument(
        "--passphrase", help="Passphrase for database encryption (requires sqlcipher3)"
    )
    sub = parser.add_subparsers(dest="command")

    # ── Seed management commands ───────────────────────────────────────
    sub.add_parser("init", help="Generate a new 24-word seed phrase and store it")
    sub.add_parser("backup", help="Show the stored 24-word seed phrase")

    restore_p = sub.add_parser("restore", help="Restore wallet from a 24-word seed phrase")
    restore_p.add_argument("words", nargs="+", help="24 mnemonic words")

    sub.add_parser("delete-seed", help="Delete master seed from Keychain (IRREVERSIBLE)")

    # ── Query commands ─────────────────────────────────────────────────
    sub.add_parser("status", help="Show wallet status and balances")
    sub.add_parser("balance", help="Show balances by asset")
    sub.add_parser("history", help="Show transaction history")
    sub.add_parser("notes", help="List unspent notes")

    tx_p = sub.add_parser("tx", help="Show details for a specific transaction")
    tx_p.add_argument("tx_id", help="Transaction ID (or prefix)")

    addr_p = sub.add_parser("address", help="Derive your hid1 address")
    addr_p.add_argument("--sk", help="Spending key (0x hex). Omit to use stored seed.")

    # ── Transaction commands (--sk optional if seed is stored) ─────────
    dep_p = sub.add_parser("deposit", help="Record a deposit")
    dep_p.add_argument("value", type=int, help="Deposit value")
    dep_p.add_argument("--asset-id", type=int, default=1, help="Asset ID")
    dep_p.add_argument("--sk", help="Spending key (0x hex). Omit to use stored seed.")

    send_p = sub.add_parser("send", help="Send a shielded transfer (generates proof)")
    send_p.add_argument("value", type=int, help="Amount to send")
    send_p.add_argument("to", help="Recipient hid1 address")
    send_p.add_argument("--sk", help="Sender spending key (0x hex). Omit to use stored seed.")
    send_p.add_argument("--asset-id", type=int, default=1, help="Asset ID")
    send_p.add_argument("--dry-run", action="store_true", help="Show plan only, don't prove")

    recv_p = sub.add_parser("receive", help="Import an incoming note from a receipt")
    recv_p.add_argument("receipt", help="Receipt JSON string or path to .json file")
    recv_p.add_argument("--sk", help="Receiver spending key (0x hex). Omit to use stored seed.")

    confirm_p = sub.add_parser("confirm", help="Confirm a proved transaction (simulate on-chain acceptance)")
    confirm_p.add_argument("tx_id", help="Transaction ID to confirm (or prefix)")

    export_p = sub.add_parser("export", help="Export a note receipt for the recipient")
    export_p.add_argument("tx_id", help="Transaction ID of the send (or prefix)")
    export_p.add_argument("--save", help="Save receipt to file (default: print to stdout)")

    args = parser.parse_args()

    # Use default db path, with optional encryption
    try:
        w = Wallet(passphrase=args.passphrase)
    except ValueError as e:
        print(f"  [error] {e}")
        sys.exit(1)

    # ── Seed management ────────────────────────────────────────────────

    if args.command == "init":
        try:
            mnemonic = w.init_seed()
        except (RuntimeError, ValueError) as e:
            print(f"  [error] {e}")
            sys.exit(1)

        words = mnemonic.split()
        print()
        print("  " + "=" * 58)
        print("   WRITE DOWN THESE 24 WORDS — THIS IS YOUR ONLY BACKUP")
        print("  " + "=" * 58)
        print()
        for i, word in enumerate(words, 1):
            print(f"    {i:2d}. {word}")
        print()
        print("  " + "=" * 58)
        print("   Seed stored in macOS Keychain (encrypted at rest).")
        print("   Your address:")
        try:
            address = w.derive_address(w.get_default_sk())
            print(f"   {address}")
        except Exception:
            pass
        print("  " + "=" * 58)

    elif args.command == "backup":
        mnemonic = w.show_mnemonic()
        if not mnemonic:
            print("  No mnemonic stored. Run: python3 wallet.py init")
            sys.exit(1)
        words = mnemonic.split()
        print()
        print("  " + "=" * 58)
        print("   YOUR 24-WORD BACKUP PHRASE")
        print("  " + "=" * 58)
        print()
        for i, word in enumerate(words, 1):
            print(f"    {i:2d}. {word}")
        print()
        print("  " + "=" * 58)

    elif args.command == "restore":
        mnemonic = " ".join(args.words)
        word_count = len(args.words)
        if word_count != 24:
            print(f"  [error] Expected 24 words, got {word_count}")
            sys.exit(1)
        try:
            w.restore_seed(mnemonic)
            print("  Seed restored and stored in Keychain.")
            try:
                address = w.derive_address(w.get_default_sk())
                print(f"  Your address: {address}")
            except Exception:
                pass
        except ValueError as e:
            print(f"  [error] Invalid mnemonic: {e}")
            sys.exit(1)
        except RuntimeError as e:
            print(f"  [error] {e}")
            sys.exit(1)

    elif args.command == "delete-seed":
        if not w.has_seed():
            print("  No master seed stored.")
            sys.exit(0)
        confirm = input("  This will DELETE your master seed. Type 'DELETE' to confirm: ")
        if confirm.strip() == "DELETE":
            try:
                skm = w._get_skm()
                skm.delete_all()
                print("  Master seed and mnemonic deleted from Keychain.")
            except RuntimeError as e:
                print(f"  [error] {e}")
                sys.exit(1)
        else:
            print("  Aborted.")

    # ── Query commands ─────────────────────────────────────────────────

    elif args.command == "status":
        s = w.stats()
        enc_label = "encrypted (SQLCipher)" if w.encrypted else "unencrypted"
        seed_label = "stored" if w.has_seed() else "not set"
        print(f"  Database:     {s['db_path']} ({enc_label})")
        print(f"  Master seed:  {seed_label}")
        if w.has_seed():
            try:
                address = w.derive_address(w.get_default_sk())
                print(f"  Address:      {address}")
            except Exception:
                pass
        print(f"  Notes:")
        print(f"    Total:      {s['total_notes']}")
        print(f"    Unspent:    {s['unspent']}")
        print(f"    Pending:    {s['pending']}")
        print(f"    Proved:     {s['proved']}")
        print(f"    Spent:      {s['spent']}")
        print(f"  Transactions: {s['transactions']}")
        print(f"    Proved:     {s['tx_proved']}  (awaiting confirmation)")
        print(f"    Confirmed:  {s['tx_confirmed']}")
        print(f"    Pending:    {s['tx_pending']}")
        print(f"    Failed:     {s['tx_failed']}")
        bal = s["balances"]
        if bal:
            print(f"  Balances:")
            for aid, total in sorted(bal.items()):
                print(f"    {format_value(total, aid):>20}  ({asset_name(aid)})")
        else:
            print(f"  Balances:     (empty)")

    elif args.command == "balance":
        bal = w.balance()
        if not bal:
            print("  No notes in wallet.")
        else:
            for aid, total in sorted(bal.items()):
                print(f"  {format_value(total, aid):>20}  ({asset_name(aid)})")

    elif args.command == "history":
        hist = w.history()
        if not hist:
            print("  No transactions.")
        else:
            for tx in hist:
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(tx["created_at"]))
                direction = tx["direction"]
                aid = tx["asset_id"]
                val_str = format_value(tx["value"], aid)
                status = tx["status"]
                tid = tx["tx_id"]

                # Compact counterparty display
                cp = tx.get("counterparty") or tx.get("sender_address") or ""
                cp_short = f"{cp[:12]}...{cp[-6:]}" if len(cp) > 20 else cp

                # Direction arrow
                arrow = ">>>" if direction == "send" else "<<<"

                line = f"  [{ts}] {arrow} {direction:>7} {val_str:>16} {status:>9}"
                if cp_short:
                    line += f"  {cp_short}"
                line += f"  {tid}"
                print(line)

    elif args.command == "tx":
        try:
            tx = w.get_tx(args.tx_id)
        except ValueError as e:
            print(f"  {e}")
            sys.exit(1)
        if not tx:
            print(f"  Transaction not found: {args.tx_id}")
            sys.exit(1)

        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tx["created_at"]))
        aid = tx["asset_id"]
        print(f"  Transaction: {tx['tx_id']}")
        print(f"  Direction:   {tx['direction']}")
        print(f"  Value:       {format_value(tx['value'], aid)}  ({asset_name(aid)})")
        print(f"  Status:      {tx['status']}")
        print(f"  Created:     {ts}")
        if tx.get("confirmed_at"):
            cts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tx["confirmed_at"]))
            print(f"  Confirmed:   {cts}")
        if tx.get("sender_address"):
            print(f"  From:        {tx['sender_address']}")
        if tx.get("counterparty"):
            print(f"  To:          {tx['counterparty']}")
        if tx.get("input_notes"):
            print(f"  Inputs:      {tx['input_notes']}")
        if tx.get("output_notes"):
            print(f"  Outputs:     {tx['output_notes']}")
        if tx.get("nullifiers"):
            print(f"  Nullifiers:  {tx['nullifiers']}")
        if tx.get("commitments_out"):
            print(f"  Commitments: {tx['commitments_out']}")
        if tx.get("proof_path"):
            print(f"  Proof:       {tx['proof_path']}")
        if tx.get("public_inputs_path"):
            print(f"  Pub inputs:  {tx['public_inputs_path']}")
        if tx.get("vk_path"):
            print(f"  VK:          {tx['vk_path']}")
        if tx.get("out1_rho"):
            print(f"  Out1 rho:    {tx['out1_rho']}")
        if tx.get("out2_rho"):
            print(f"  Out2 rho:    {tx['out2_rho']}")

    elif args.command == "notes":
        notes = w.get_unspent_notes()
        if not notes:
            print("  No unspent notes.")
        else:
            # Group by asset
            by_asset: dict[int, list] = {}
            for n in notes:
                by_asset.setdefault(n.asset_id, []).append(n)

            for aid in sorted(by_asset.keys()):
                asset_notes = by_asset[aid]
                total = sum(n.value for n in asset_notes)
                print(f"  {asset_symbol(aid)} ({asset_name(aid)}) — {len(asset_notes)} note(s), total: {format_value(total, aid)}")
                for n in asset_notes:
                    print(f"    #{n.note_id}  idx={n.note_index}  {format_value(n.value, aid):>16}  cm={n.commitment[:18]}...")

    elif args.command == "address":
        sk = _resolve_sk(args, w)
        address = w.derive_address(sk)
        print(f"  {address}")

    elif args.command == "deposit":
        sk = _resolve_sk(args, w, "deposit")
        note = w.deposit(sk_hex=sk, value=args.value, asset_id=args.asset_id)
        address = addr_mod.encode(note.owner_pk_x, note.owner_pk_y)
        print(f"  Deposited {format_value(note.value, note.asset_id)}")
        print(f"  Note #{note.note_id}, index={note.note_index}")
        print(f"  Address:    {address}")
        print(f"  Commitment: {note.commitment}")

    elif args.command == "send":
        if not addr_mod.is_valid(args.to):
            print(f"  Invalid recipient address: {args.to}")
            sys.exit(1)

        sk = _resolve_sk(args, w, "send")

        if args.dry_run:
            plan = w.build_transfer(
                recipient=args.to,
                value=args.value,
                asset_id=args.asset_id,
            )
            print(f"  Transfer plan (dry run):")
            print(f"    Send:   {plan.output_value} (asset {plan.output_asset_id})")
            print(f"    To:     {args.to[:20]}...{args.to[-8:]}")
            print(f"    Change: {plan.change_value}")
            print(f"    Inputs: {len(plan.input_notes)} note(s)")
            for n in plan.input_notes:
                print(f"      #{n.note_id} value={n.value} cm={n.commitment[:18]}...")
        else:
            try:
                result = w.execute_send(
                    recipient=args.to,
                    value=args.value,
                    sender_sk_hex=sk,
                    asset_id=args.asset_id,
                )
                print()
                print("  " + "=" * 50)
                print(f"  Transfer proved!")
                print(f"    tx_id:     {result['tx_id']}")
                print(f"    Sent:      {format_value(result['value_sent'], args.asset_id)}")
                recip = args.to
                print(f"    To:        {recip[:16]}...{recip[-6:]}")
                print(f"    Change:    {format_value(result['change'], args.asset_id)}")
                print(f"    Proof:     {result['proof_path']}")
                print(f"    Status:    {result['status']}")
                print("  " + "=" * 50)
                print()
                print("  To finalize, confirm the transaction:")
                print(f"    python3 wallet.py confirm {result['tx_id']}")
                print()
                print("  Send this receipt to the recipient so they can claim the note:")
                print(f"  {json.dumps(result['receipt'])}")
            except ProverError as e:
                print(f"  [error] {e}")
                if e.retryable:
                    print("  [hint]  This may be a transient failure. Try again.")
                sys.exit(1)
            except (ValueError, FileNotFoundError, RuntimeError) as e:
                print(f"  [error] {e}")
                sys.exit(1)

    elif args.command == "receive":
        # Parse receipt from JSON string or file
        receipt_arg = args.receipt
        if os.path.isfile(receipt_arg):
            with open(receipt_arg) as f:
                receipt = json.load(f)
        else:
            try:
                receipt = json.loads(receipt_arg)
            except json.JSONDecodeError:
                print(f"  Invalid receipt: not valid JSON and not a file path")
                sys.exit(1)

        sk = _resolve_sk(args, w, "receive")
        try:
            note = w.import_receipt(receipt, sk_hex=sk)
            owner_addr = addr_mod.encode(note.owner_pk_x, note.owner_pk_y)
            print(f"  Received {format_value(note.value, note.asset_id)}")
            print(f"  Note #{note.note_id}, index={note.note_index}")
            print(f"  Address:    {owner_addr}")
            print(f"  Commitment: {note.commitment}")
            if receipt.get("sender_address"):
                sa = receipt["sender_address"]
                print(f"  From:       {sa[:16]}...{sa[-6:]}")
        except ValueError as e:
            print(f"  [error] {e}")
            sys.exit(1)

    elif args.command == "confirm":
        try:
            tx = w.get_tx(args.tx_id)
        except ValueError as e:
            print(f"  {e}")
            sys.exit(1)
        if not tx:
            print(f"  Transaction not found: {args.tx_id}")
            sys.exit(1)
        if tx["status"] == TxStatus.CONFIRMED:
            print(f"  Transaction already confirmed: {tx['tx_id']}")
            sys.exit(0)
        if tx["status"] != TxStatus.PROVED:
            print(f"  Cannot confirm transaction in '{tx['status']}' state "
                  f"(must be '{TxStatus.PROVED}')")
            sys.exit(1)

        w.confirm_tx(tx["tx_id"])
        print(f"  Transaction confirmed: {tx['tx_id']}")
        print(f"  Input notes finalized as spent.")
        bal = w.balance()
        if bal:
            for aid, total in sorted(bal.items()):
                print(f"  Balance: {format_value(total, aid)}")
        else:
            print(f"  Balance: (empty)")

    elif args.command == "export":
        try:
            receipt = w.export_note_receipt(args.tx_id)
            receipt_json = json.dumps(receipt, indent=2)
            if args.save:
                with open(args.save, "w") as f:
                    f.write(receipt_json + "\n")
                print(f"  Receipt saved to {args.save}")
            else:
                print(receipt_json)
        except ValueError as e:
            print(f"  [error] {e}")
            sys.exit(1)

    else:
        parser.print_help()

    w.close()


if __name__ == "__main__":
    _cli()
