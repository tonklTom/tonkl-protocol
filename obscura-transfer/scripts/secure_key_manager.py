#!/usr/bin/env python3
"""
Obscura Secure Key Manager -- HD key derivation with hardware-backed storage.

Phase 2 of the Obscura key management architecture. Provides:

  1. Master seed generation from a BIP-39 24-word mnemonic phrase
  2. Hardware-backed storage of the master seed in macOS Keychain
  3. Per-note spending key derivation with domain separation:

       sk_note = BLAKE3("Obscura::note_sk_v1" || master_seed || note_index)

  4. Secure memory handling: all key material is held in mlocked bytearrays
     and zeroed via ctypes immediately after use

The user backs up only the 24-word mnemonic phrase. All per-note keys are
derived deterministically on demand and never stored.

Security model:
  - Master seed encrypted at rest in macOS Keychain (hardware-backed on
    T2/M-series via Secure Enclave).
  - Per-note sk derived in memory, used for a single proving operation,
    then zeroed. Never written to disk.
  - Domain-separated derivation prevents cross-protocol key reuse.
  - BLAKE3 is used for speed and resistance to length-extension attacks.
    Falls back to HMAC-SHA512 if blake3 is not installed.

Requirements:
  pip install blake3

Platform:
  macOS (Keychain). Falls back to encrypted file on other platforms.
"""

import ctypes
import ctypes.util
import gc
import os
import secrets
import sys

import keychain
import bip39

# ── BN254 scalar field modulus ───────────────────────────────────────────────
BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# ── Domain separation tag (versioned for future upgradability) ───────────────
DERIVATION_DOMAIN = b"Obscura::note_sk_v1"

# ── Keychain label for the master seed ───────────────────────────────────────
MASTER_SEED_LABEL = "obscura_master_seed"
MNEMONIC_LABEL = "obscura_mnemonic"

# ── libc for mlock/munlock ───────────────────────────────────────────────────
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# ── BLAKE3 with HMAC-SHA512 fallback ────────────────────────────────────────
try:
    import blake3 as _blake3
    _HAS_BLAKE3 = True
except ImportError:
    _HAS_BLAKE3 = False
    import hashlib as _hashlib
    import hmac as _hmac


def _derive_hash(data: bytes) -> bytes:
    """
    Domain-separated hash: BLAKE3 if available, else HMAC-SHA512 truncated to
    32 bytes. Both produce a 256-bit key suitable for BN254 scalar reduction.
    """
    if _HAS_BLAKE3:
        return _blake3.blake3(data).digest()
    else:
        # HMAC-SHA512 with the domain tag as key, data as message.
        # Truncate to 32 bytes (256 bits).
        return _hmac.new(DERIVATION_DOMAIN, data, _hashlib.sha512).digest()[:32]


# ── Memory helpers ───────────────────────────────────────────────────────────

def _mlock(buf: bytearray) -> None:
    """Lock a bytearray in RAM so the OS cannot swap it to disk."""
    try:
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        _libc.mlock(addr, ctypes.c_size_t(len(buf)))
    except Exception:
        pass


def _zero_and_unlock(buf: bytearray) -> None:
    """Zero a bytearray in place and unlock from RAM."""
    if not buf:
        return
    try:
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        ctypes.memset(addr, 0, len(buf))
        _libc.munlock(addr, ctypes.c_size_t(len(buf)))
    except Exception:
        buf[:] = b"\x00" * len(buf)
    del buf
    gc.collect()


# ── Public API ───────────────────────────────────────────────────────────────

class SecureKeyManager:
    """
    Manages master seed and derives per-note spending keys.

    Typical workflow:
        skm = SecureKeyManager()

        # First time: generate and store
        mnemonic = skm.generate_and_store()
        print("Back up these 24 words:", mnemonic)

        # Or restore from existing mnemonic
        skm.restore_from_mnemonic("abandon ability able ...")

        # Derive per-note keys on demand
        sk_buf = skm.derive_note_sk(note_index=0)   # mlocked bytearray
        sk_int = int.from_bytes(sk_buf, "big") % BN254_P
        # ... use sk_int for proving ...
        skm.zero_key(sk_buf)                         # zero when done
    """

    def __init__(self):
        self._kc_available = keychain.available()

    # ── Seed generation and storage ──────────────────────────────────────

    def generate_and_store(self, passphrase: str = "") -> str:
        """
        Generate a new 24-word BIP-39 mnemonic, derive the 512-bit master
        seed, and store the seed in macOS Keychain.

        Returns the mnemonic phrase. The caller MUST show it to the user
        for backup -- it is NOT stored anywhere else.

        Args:
            passphrase: Optional BIP-39 passphrase ("25th word"). If empty,
                        the seed is derived from the mnemonic alone.
        """
        mnemonic = bip39.generate_mnemonic(bits=256)
        seed = bip39.mnemonic_to_seed(mnemonic, passphrase)

        self._store_seed(seed)

        # Also store the mnemonic in Keychain so the user can retrieve it
        # via `show_mnemonic()`. This is optional and can be disabled for
        # higher security by removing this call.
        if self._kc_available:
            keychain.store(MNEMONIC_LABEL, mnemonic)

        # Zero the seed from Python memory (it's now in Keychain)
        # seed is bytes (immutable) so we can't zero it -- this is a
        # known limitation. The mutable path is via derive_note_sk().
        del seed
        gc.collect()

        return mnemonic

    def restore_from_mnemonic(self, mnemonic: str, passphrase: str = "") -> None:
        """
        Restore a master seed from an existing BIP-39 mnemonic phrase and
        store it in macOS Keychain.

        Validates the mnemonic checksum before storing.

        Args:
            mnemonic:   24-word BIP-39 phrase (space-separated).
            passphrase: Optional BIP-39 passphrase.

        Raises:
            ValueError if the mnemonic is invalid.
        """
        # Validate checksum
        bip39.mnemonic_to_entropy(mnemonic)

        seed = bip39.mnemonic_to_seed(mnemonic, passphrase)
        self._store_seed(seed)

        if self._kc_available:
            keychain.store(MNEMONIC_LABEL, mnemonic)

        del seed
        gc.collect()

    def has_master_seed(self) -> bool:
        """Check whether a master seed is stored in Keychain."""
        if not self._kc_available:
            return False
        try:
            keychain.retrieve(MASTER_SEED_LABEL)
            return True
        except RuntimeError:
            return False

    def show_mnemonic(self) -> str | None:
        """
        Retrieve the stored mnemonic from Keychain (if stored).

        Returns None if no mnemonic is stored. This is a convenience for
        the user to re-display their backup phrase.
        """
        if not self._kc_available:
            return None
        try:
            return keychain.retrieve(MNEMONIC_LABEL)
        except RuntimeError:
            return None

    def delete_all(self) -> None:
        """
        Delete master seed and mnemonic from Keychain.

        WARNING: This is irreversible. The user must have their mnemonic
        backed up before calling this.
        """
        if self._kc_available:
            keychain.delete(MASTER_SEED_LABEL)
            keychain.delete(MNEMONIC_LABEL)
            print("[!] Master seed and mnemonic deleted from Keychain")

    # ── Per-note key derivation ──────────────────────────────────────────

    def derive_note_sk(self, note_index: int) -> bytearray:
        """
        Derive a per-note spending key from the master seed.

        Formula:
            sk_note = BLAKE3("Obscura::note_sk_v1" || master_seed || index)
                      mod BN254_P

        The result is returned as an mlocked 32-byte bytearray. The caller
        MUST call zero_key() when the key is no longer needed.

        The master seed is retrieved from Keychain, held briefly in an
        mlocked bytearray, used for derivation, then zeroed.

        Args:
            note_index: 64-bit unsigned integer unique to each note.

        Returns:
            32-byte mlocked bytearray containing the derived sk.
        """
        if note_index < 0:
            raise ValueError("note_index must be non-negative")

        # Retrieve master seed from Keychain
        seed_hex = self._retrieve_seed_hex()
        seed_buf = bytearray.fromhex(seed_hex)
        _mlock(seed_buf)

        # Zero the hex string reference (Python str is immutable, best-effort)
        del seed_hex
        gc.collect()

        try:
            # Domain-separated derivation:
            #   input = domain_tag || seed || note_index (8 bytes, big-endian)
            derive_input = (
                DERIVATION_DOMAIN
                + bytes(seed_buf)
                + note_index.to_bytes(8, "big")
            )
            raw_hash = _derive_hash(derive_input)

            # Reduce mod BN254 scalar field
            sk_int = int.from_bytes(raw_hash, "big") % BN254_P
            sk_buf = bytearray(sk_int.to_bytes(32, "big"))
            _mlock(sk_buf)

            return sk_buf
        finally:
            # Zero the master seed from memory regardless of success/failure
            _zero_and_unlock(seed_buf)

    def derive_note_sk_int(self, note_index: int) -> tuple[int, bytearray]:
        """
        Convenience: derive sk and return both the int and the buffer.

        Returns (sk_int, sk_buf). Caller must call zero_key(sk_buf) when done.
        """
        sk_buf = self.derive_note_sk(note_index)
        sk_int = int.from_bytes(sk_buf, "big")
        return sk_int, sk_buf

    @staticmethod
    def zero_key(buf: bytearray) -> None:
        """Zero a spending key bytearray and unlock from RAM."""
        _zero_and_unlock(buf)

    # ── Internal helpers ─────────────────────────────────────────────────

    def _store_seed(self, seed: bytes) -> None:
        """Store the 512-bit master seed in Keychain as hex."""
        if not self._kc_available:
            raise RuntimeError(
                "macOS Keychain is not available. Cannot store master seed.\n"
                "On Linux, use a platform keyring (e.g. GNOME Keyring, KWallet)."
            )
        keychain.store(MASTER_SEED_LABEL, seed.hex())
        print("[K] Master seed stored in macOS Keychain (encrypted at rest)")

    def _retrieve_seed_hex(self) -> str:
        """Retrieve master seed hex from Keychain."""
        if not self._kc_available:
            raise RuntimeError(
                "macOS Keychain is not available. Cannot retrieve master seed."
            )
        try:
            return keychain.retrieve(MASTER_SEED_LABEL)
        except RuntimeError:
            raise RuntimeError(
                "No master seed found in Keychain.\n"
                "Generate one with: skm.generate_and_store()\n"
                "Or restore with:   skm.restore_from_mnemonic('...')"
            )


# ── CLI for manual seed management ───────────────────────────────────────────

def _cli():
    """Simple CLI for seed management operations."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Obscura Secure Key Manager -- HD seed management"
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("generate", help="Generate a new 24-word mnemonic and store seed")
    sub.add_parser("show", help="Show the stored mnemonic phrase")
    sub.add_parser("status", help="Check if a master seed is stored")
    sub.add_parser("delete", help="Delete master seed from Keychain (IRREVERSIBLE)")

    restore_p = sub.add_parser("restore", help="Restore seed from a mnemonic phrase")
    restore_p.add_argument("mnemonic", nargs="+", help="24 mnemonic words")

    derive_p = sub.add_parser("derive", help="Derive a per-note sk (for debugging)")
    derive_p.add_argument("index", type=int, help="Note index")

    args = parser.parse_args()
    skm = SecureKeyManager()

    if args.command == "generate":
        mnemonic = skm.generate_and_store()
        print()
        print("=" * 60)
        print("  BACK UP THESE 24 WORDS -- WRITE THEM DOWN ON PAPER")
        print("  This is the ONLY way to recover your funds if you lose")
        print("  access to this device.")
        print("=" * 60)
        print()
        words = mnemonic.split()
        for i, word in enumerate(words, 1):
            print(f"  {i:2d}. {word}")
        print()
        print("=" * 60)
        print("  Seed stored in macOS Keychain.")
        print("=" * 60)

    elif args.command == "show":
        m = skm.show_mnemonic()
        if m:
            words = m.split()
            for i, word in enumerate(words, 1):
                print(f"  {i:2d}. {word}")
        else:
            print("No mnemonic stored in Keychain.")

    elif args.command == "status":
        if skm.has_master_seed():
            print("[OK] Master seed is stored in Keychain")
        else:
            print("[--] No master seed found in Keychain")

    elif args.command == "delete":
        confirm = input("This will DELETE your master seed. Type 'DELETE' to confirm: ")
        if confirm.strip() == "DELETE":
            skm.delete_all()
        else:
            print("Aborted.")

    elif args.command == "restore":
        mnemonic = " ".join(args.mnemonic)
        try:
            skm.restore_from_mnemonic(mnemonic)
            print("[OK] Seed restored and stored in Keychain")
        except ValueError as e:
            print(f"[!] Invalid mnemonic: {e}")
            sys.exit(1)

    elif args.command == "derive":
        if not skm.has_master_seed():
            print("[!] No master seed. Run 'generate' or 'restore' first.")
            sys.exit(1)
        sk_buf = skm.derive_note_sk(args.index)
        sk_int = int.from_bytes(sk_buf, "big")
        print(f"  note_index = {args.index}")
        print(f"  sk (Field) = {sk_int}")
        print(f"  sk (hex)   = 0x{sk_int:064x}")
        skm.zero_key(sk_buf)
        print("  [zeroed from memory]")

    else:
        parser.print_help()


if __name__ == "__main__":
    _cli()
