#!/usr/bin/env python3
"""
Obscura address encoding -- bech32m with `hid1` human-readable prefix.

An Obscura address encodes the owner's public key (pk_x, pk_y) as two
32-byte big-endian field elements, concatenated into a 64-byte payload,
then bech32m-encoded with the "hid1" prefix.

Format:
    hid1<bech32m encoded 64 bytes of pk_x || pk_y>

Example:
    hid1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq...

The bech32m encoding provides:
  - Human-readable prefix for easy identification
  - Error detection (BCH checksum catches typos)
  - Case-insensitive (all lowercase by convention)
  - No ambiguous characters (no 1/l/I/0/O confusion in data part)

This uses the BIP-350 bech32m variant (not original bech32) for better
error detection properties.
"""

# ── Bech32m constants ───────────────────────────────────────────────────────
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2bc830a3
HRP = "hid1"


# ── Bech32m implementation (BIP-350) ────────────────────────────────────────

def _bech32_polymod(values: list[int]) -> int:
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> bool:
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == BECH32M_CONST


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


# ── Public API ──────────────────────────────────────────────────────────────

def encode(pk_x_hex: str, pk_y_hex: str) -> str:
    """
    Encode a public key (pk_x, pk_y) as a bech32m address with `hid1` prefix.

    Args:
        pk_x_hex: Public key x-coordinate as 0x-prefixed hex string.
        pk_y_hex: Public key y-coordinate as 0x-prefixed hex string.

    Returns:
        Bech32m-encoded address string like "hid1q..."
    """
    # Strip 0x prefix and pad to 64 hex chars (32 bytes)
    x_hex = pk_x_hex.lower().removeprefix("0x").zfill(64)
    y_hex = pk_y_hex.lower().removeprefix("0x").zfill(64)

    payload = bytes.fromhex(x_hex + y_hex)  # 64 bytes
    assert len(payload) == 64, f"Expected 64 bytes, got {len(payload)}"

    # Convert 8-bit bytes to 5-bit groups for bech32
    data5 = _convertbits(payload, 8, 5, pad=True)
    checksum = _bech32_create_checksum(HRP, data5)

    return HRP + "1" + "".join(CHARSET[d] for d in data5 + checksum)


def decode(addr: str) -> tuple[str, str]:
    """
    Decode a `hid1` bech32m address back to (pk_x_hex, pk_y_hex).

    Args:
        addr: Bech32m address string (case-insensitive).

    Returns:
        Tuple of (pk_x, pk_y) as 0x-prefixed hex strings.

    Raises:
        ValueError if the address is invalid.
    """
    addr = addr.lower().strip()

    # Split at the last '1' separator
    sep = addr.rfind("1")
    if sep < 1:
        raise ValueError("Invalid address: no separator found")

    hrp = addr[:sep]
    data_part = addr[sep + 1:]

    if hrp != HRP:
        raise ValueError(f"Invalid prefix: expected '{HRP}', got '{hrp}'")

    if not all(c in CHARSET for c in data_part):
        raise ValueError("Invalid character in address")

    data5 = [CHARSET.index(c) for c in data_part]

    if not _bech32_verify_checksum(hrp, data5):
        raise ValueError("Invalid checksum")

    # Remove 6-char checksum, convert 5-bit back to 8-bit
    payload_5bit = data5[:-6]
    payload = _convertbits(bytes(payload_5bit), 5, 8, pad=False)

    if payload is None or len(payload) != 64:
        raise ValueError(f"Invalid payload length: expected 64 bytes, got {len(payload) if payload else 'None'}")

    payload = bytes(payload)
    pk_x = payload[:32]
    pk_y = payload[32:]

    return (
        "0x" + pk_x.hex(),
        "0x" + pk_y.hex(),
    )


def is_valid(addr: str) -> bool:
    """Check if an address string is a valid hid1 address."""
    try:
        decode(addr)
        return True
    except (ValueError, Exception):
        return False


# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2 and sys.argv[1].startswith("hid1"):
        # Decode mode
        pk_x, pk_y = decode(sys.argv[1])
        print(f"  pk_x = {pk_x}")
        print(f"  pk_y = {pk_y}")
    elif len(sys.argv) == 3:
        # Encode mode: address.py <pk_x> <pk_y>
        addr = encode(sys.argv[1], sys.argv[2])
        print(addr)
    else:
        print("Usage:")
        print("  Encode:  python3 address.py <pk_x_hex> <pk_y_hex>")
        print("  Decode:  python3 address.py <hid1_address>")
        print()
        # Demo with Grumpkin generator
        demo_x = "0x0000000000000000000000000000000000000000000000000000000000000001"
        demo_y = "0x0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c"
        addr = encode(demo_x, demo_y)
        print(f"  Demo (Grumpkin generator):")
        print(f"  Address: {addr}")
        rt_x, rt_y = decode(addr)
        print(f"  Roundtrip pk_x: {rt_x}")
        print(f"  Roundtrip pk_y: {rt_y}")
        print(f"  Match: {rt_x == demo_x and rt_y == demo_y}")
