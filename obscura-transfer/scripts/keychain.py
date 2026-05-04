#!/usr/bin/env python3
"""
macOS Keychain integration for Obscura spending key storage.

Uses the `security` CLI to store and retrieve spending keys in the macOS
Keychain. This provides software-backed encryption at minimum, and
hardware-backed storage (Secure Enclave) on T2/M-series Macs.

Security model vs plaintext files:
  - Keys are encrypted at rest by the OS security daemon
  - Access is mediated by the Keychain access control system
  - Hardware-backed on Apple Silicon / T2 Macs via Secure Enclave
  - Keys are NOT accessible to other processes without explicit ACL grant

Known limitations:
  - The `security` CLI briefly holds the key in subprocess memory
  - The key crosses into Python as a string for TOML writing (see ramdisk.py
    for how to ensure that write never touches the SSD)
  - Full production isolation requires Swift/Rust using SecKeyCreateRandomKey
    with kSecAttrTokenIDSecureEnclave, keeping the key inside the enclave and
    never exposing it to userspace Python at all

Platform:
  macOS only. On other platforms, available() returns False and callers
  must fall back to an appropriate platform keystore.
"""

import subprocess
import sys

KEYCHAIN_SERVICE = "com.obscura.wallet"


def available() -> bool:
    """Return True if macOS Keychain is accessible via the security CLI."""
    if sys.platform != "darwin":
        return False
    r = subprocess.run(["which", "security"], capture_output=True)
    return r.returncode == 0


def store(label: str, sk_hex: str) -> None:
    """
    Store a spending key (hex string) in macOS Keychain.

    Uses the generic password keychain item type. Overwrites any existing
    entry with the same label so re-runs don't accumulate stale keys.

    The -T "" flag sets the trusted application list to empty, meaning
    any application that wants to read this item will trigger a Keychain
    prompt. For automated proving, the application should be explicitly
    added to the ACL instead.

    Args:
        label:  Unique identifier for this key (e.g. "obscura_in1_sk_<txid>")
        sk_hex: Hex-encoded spending key, no 0x prefix
    """
    # Remove any stale entry silently
    subprocess.run(
        ["security", "delete-generic-password",
         "-a", label, "-s", KEYCHAIN_SERVICE],
        capture_output=True
    )
    r = subprocess.run(
        ["security", "add-generic-password",
         "-a", label,
         "-s", KEYCHAIN_SERVICE,
         "-w", sk_hex,
         "-T", ""],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"Keychain store failed for label '{label}': {r.stderr.strip()}"
        )


def retrieve(label: str) -> str:
    """
    Retrieve a spending key hex string from macOS Keychain.

    May trigger a Keychain access prompt if the calling process is not
    in the item's ACL. Returns the key as a hex string, no 0x prefix.
    """
    r = subprocess.run(
        ["security", "find-generic-password",
         "-a", label,
         "-s", KEYCHAIN_SERVICE,
         "-w"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"Keychain read failed for label '{label}': {r.stderr.strip()}"
        )
    return r.stdout.strip()


def delete(label: str) -> None:
    """
    Delete a spending key from Keychain. Silent if the entry does not exist.

    Call this immediately after the key is no longer needed. Do not leave
    keys in the Keychain indefinitely unless they are persistent wallet keys
    that require long-term storage with proper ACL configuration.
    """
    subprocess.run(
        ["security", "delete-generic-password",
         "-a", label, "-s", KEYCHAIN_SERVICE],
        capture_output=True
    )


def store_and_delete_after(label: str, sk_hex: str):
    """
    Context manager: store a key for the duration of a `with` block,
    then delete it automatically on exit (even if an exception occurs).

    Usage:
        with keychain.store_and_delete_after("obscura_in1_sk", sk_hex):
            run_nargo(...)
    """
    return _KeychainContext(label, sk_hex)


class _KeychainContext:
    def __init__(self, label: str, sk_hex: str):
        self.label  = label
        self.sk_hex = sk_hex

    def __enter__(self):
        store(self.label, self.sk_hex)
        return self

    def __exit__(self, *_):
        delete(self.label)
