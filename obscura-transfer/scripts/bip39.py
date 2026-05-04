#!/usr/bin/env python3
"""
BIP-39 mnemonic encoding/decoding for Obscura master seed management.

Implements the BIP-39 standard:
  1. Generate 256 bits of cryptographic entropy (secrets module)
  2. SHA-256 checksum (first 8 bits appended to entropy)
  3. Split 264 bits into 24 groups of 11 bits
  4. Map each 11-bit value to a word from the 2048-word English list
  5. Derive 512-bit seed via PBKDF2-HMAC-SHA512

The wordlist must be at scripts/bip39_english.txt (one word per line, 2048 words).
Download with:
  curl -o scripts/bip39_english.txt \
    https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt

Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
"""

import hashlib
import hmac
import os
import secrets

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(SCRIPT_DIR, "bip39_english.txt")

_wordlist: list[str] | None = None


def _load_wordlist() -> list[str]:
    """Load and cache the BIP-39 English wordlist (2048 words)."""
    global _wordlist
    if _wordlist is not None:
        return _wordlist

    if not os.path.isfile(WORDLIST_PATH):
        raise FileNotFoundError(
            f"BIP-39 wordlist not found at:\n"
            f"  {WORDLIST_PATH}\n\n"
            f"Download it with:\n"
            f"  curl -o {WORDLIST_PATH} \\\n"
            f"    https://raw.githubusercontent.com/bitcoin/bips/master/"
            f"bip-0039/english.txt"
        )

    with open(WORDLIST_PATH) as f:
        words = [line.strip() for line in f if line.strip()]

    if len(words) != 2048:
        raise ValueError(
            f"BIP-39 wordlist must have exactly 2048 words, got {len(words)}"
        )

    _wordlist = words
    return _wordlist


def generate_entropy(bits: int = 256) -> bytes:
    """
    Generate cryptographically secure entropy for mnemonic generation.

    Args:
        bits: Entropy length in bits. Must be 128, 160, 192, 224, or 256.
              256 bits (24 words) is recommended for maximum security.

    Returns:
        Raw entropy bytes.
    """
    if bits not in (128, 160, 192, 224, 256):
        raise ValueError(
            f"BIP-39 entropy must be 128/160/192/224/256 bits, got {bits}"
        )
    return secrets.token_bytes(bits // 8)


def entropy_to_mnemonic(entropy: bytes) -> str:
    """
    Convert raw entropy bytes to a BIP-39 mnemonic phrase.

    Process:
      1. SHA-256 hash of entropy
      2. Append first (entropy_bits / 32) checksum bits
      3. Split into 11-bit groups
      4. Map each group to a word

    Args:
        entropy: 16-32 bytes of cryptographic entropy.

    Returns:
        Space-separated mnemonic phrase (12-24 words).
    """
    wordlist = _load_wordlist()
    entropy_bits = len(entropy) * 8

    if entropy_bits not in (128, 160, 192, 224, 256):
        raise ValueError(f"Invalid entropy length: {entropy_bits} bits")

    # Checksum: first (entropy_bits // 32) bits of SHA-256(entropy)
    checksum_bits = entropy_bits // 32
    h = hashlib.sha256(entropy).digest()

    # Combine entropy + checksum into a single bit string
    ent_int = int.from_bytes(entropy, "big")
    cs_int = h[0] >> (8 - checksum_bits)
    combined = (ent_int << checksum_bits) | cs_int
    total_bits = entropy_bits + checksum_bits

    # Split into 11-bit groups
    word_count = total_bits // 11
    words = []
    for i in range(word_count):
        shift = (word_count - 1 - i) * 11
        index = (combined >> shift) & 0x7FF
        words.append(wordlist[index])

    return " ".join(words)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """
    Convert a BIP-39 mnemonic phrase back to raw entropy bytes.

    Validates the checksum. Raises ValueError if the mnemonic is invalid.

    Args:
        mnemonic: Space-separated mnemonic phrase (12-24 words).

    Returns:
        Raw entropy bytes.
    """
    wordlist = _load_wordlist()
    words = mnemonic.strip().lower().split()
    word_count = len(words)

    if word_count not in (12, 15, 18, 21, 24):
        raise ValueError(
            f"BIP-39 mnemonic must have 12/15/18/21/24 words, got {word_count}"
        )

    # Look up each word's 11-bit index
    combined = 0
    for word in words:
        try:
            index = wordlist.index(word)
        except ValueError:
            raise ValueError(f"'{word}' is not in the BIP-39 English wordlist")
        combined = (combined << 11) | index

    # Split entropy and checksum
    total_bits = word_count * 11
    checksum_bits = total_bits // 33
    entropy_bits = total_bits - checksum_bits

    # Extract entropy and checksum
    cs_actual = combined & ((1 << checksum_bits) - 1)
    ent_int = combined >> checksum_bits
    entropy = ent_int.to_bytes(entropy_bits // 8, "big")

    # Verify checksum
    h = hashlib.sha256(entropy).digest()
    cs_expected = h[0] >> (8 - checksum_bits)
    if cs_actual != cs_expected:
        raise ValueError(
            "BIP-39 checksum mismatch -- the mnemonic phrase may be mistyped"
        )

    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Derive a 512-bit seed from a BIP-39 mnemonic phrase.

    Uses PBKDF2-HMAC-SHA512 with 2048 iterations as specified by BIP-39.
    The passphrase provides an additional layer of protection (optional).

    Args:
        mnemonic:   Space-separated mnemonic phrase.
        passphrase: Optional passphrase (BIP-39 "25th word"). Empty string
                    if not used.

    Returns:
        64-byte (512-bit) seed suitable for key derivation.
    """
    mnemonic_bytes = mnemonic.encode("utf-8")
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic_bytes, salt, 2048)


def generate_mnemonic(bits: int = 256) -> str:
    """
    Generate a new random BIP-39 mnemonic phrase.

    This is the primary entry point for new wallet creation.

    Args:
        bits: Entropy strength. 256 = 24 words (recommended).

    Returns:
        Space-separated mnemonic phrase.
    """
    return entropy_to_mnemonic(generate_entropy(bits))


def validate(mnemonic: str) -> bool:
    """
    Check whether a mnemonic phrase is valid (correct words + checksum).

    Returns True if valid, False otherwise. Does not raise.
    """
    try:
        mnemonic_to_entropy(mnemonic)
        return True
    except (ValueError, FileNotFoundError):
        return False
