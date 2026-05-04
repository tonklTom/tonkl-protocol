#!/usr/bin/env python3
"""
macOS RAM disk manager for Obscura key material handling.

Creates an in-memory HFS+ volume using hdiutil so that any files written
to it (e.g. Prover.toml containing spending keys) NEVER touch the SSD.
When the RAM disk is destroyed, the data is gone — no SSD wear-levelling
issue, no journaling artefacts, no residual flash cells.

Why this matters:
  Even with multi-pass overwrite, SSDs remap writes through a flash
  translation layer. The original data may remain in a flash cell that the
  OS cannot address. A RAM disk bypasses this entirely by never writing
  to NAND flash in the first place.

Usage:
    import ramdisk

    if ramdisk.available():
        mount = ramdisk.create()                 # /Volumes/ObscuraRAM
        path  = os.path.join(mount, "secret.toml")
        # ... write key material to path ...
        ramdisk.destroy()                        # data gone, RAM freed
    else:
        # Fall back to disk with secure_delete

Platform:
    macOS only (uses hdiutil and diskutil). available() returns False
    on Linux/Windows. On Linux, use /dev/shm or a tmpfs mount instead.
"""

import subprocess
import sys
import os
import atexit

MOUNT_NAME = "ObscuraRAM"
MOUNT_PATH = f"/Volumes/{MOUNT_NAME}"

_device: str | None = None   # /dev/diskN assigned by hdiutil


def available() -> bool:
    """Return True if hdiutil is present (macOS only)."""
    if sys.platform != "darwin":
        return False
    r = subprocess.run(["which", "hdiutil"], capture_output=True)
    return r.returncode == 0


def create(size_mb: int = 8) -> str:
    """
    Create a RAM disk and return its mount path (/Volumes/ObscuraRAM).

    Idempotent: if the RAM disk already exists, returns the existing path.
    Registers an atexit handler so the disk is destroyed on interpreter exit
    even if destroy() is never explicitly called.

    Args:
        size_mb: Size of the RAM disk in megabytes. 8 MB is more than
                 enough for TOML files; increase if proving artifacts are
                 also written here.

    Returns:
        Mount path string, e.g. "/Volumes/ObscuraRAM"

    Raises:
        RuntimeError if hdiutil or diskutil fails.
    """
    global _device

    if _device and os.path.ismount(MOUNT_PATH):
        return MOUNT_PATH   # already mounted

    sectors = (size_mb * 1024 * 1024) // 512   # hdiutil uses 512-byte sectors

    # Attach an in-memory block device
    try:
        r = subprocess.run(
            ["hdiutil", "attach", "-nomount", f"ram://{sectors}"],
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"hdiutil attach failed: {e.stderr.strip()}") from e

    _device = r.stdout.strip()

    # Format the block device as HFS+
    try:
        subprocess.run(
            ["diskutil", "erasevolume", "HFS+", MOUNT_NAME, _device],
            capture_output=True, check=True
        )
    except subprocess.CalledProcessError as e:
        # Clean up the orphaned device before re-raising
        subprocess.run(["hdiutil", "detach", _device], capture_output=True)
        _device = None
        raise RuntimeError(
            f"diskutil erasevolume failed: {e.stderr.strip()}"
        ) from e

    atexit.register(destroy)   # ensure cleanup even on crash
    return MOUNT_PATH


def destroy() -> None:
    """
    Unmount and destroy the RAM disk. All data is immediately gone.

    Safe to call multiple times. No-op if the disk was never created or
    has already been destroyed.
    """
    global _device
    if _device:
        subprocess.run(
            ["hdiutil", "detach", _device, "-force"],
            capture_output=True
        )
        _device = None


def path_for(filename: str) -> str:
    """
    Return the full path for a file on the RAM disk.
    Raises RuntimeError if the RAM disk is not mounted.
    """
    if not _device or not os.path.ismount(MOUNT_PATH):
        raise RuntimeError(
            "RAM disk not mounted — call ramdisk.create() first"
        )
    return os.path.join(MOUNT_PATH, filename)


class mount:
    """
    Context manager: create the RAM disk on enter, destroy on exit.

    Usage:
        with ramdisk.mount() as ram_path:
            toml_path = os.path.join(ram_path, "Prover.toml")
            write_toml(toml_path, prover_data)
            run_nargo_with_symlink(toml_path)
        # RAM disk is now destroyed — data is gone
    """
    def __init__(self, size_mb: int = 8):
        self.size_mb = size_mb
        self.path: str | None = None

    def __enter__(self) -> str:
        self.path = create(self.size_mb)
        return self.path

    def __exit__(self, *_):
        destroy()
