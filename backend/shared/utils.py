"""
shared/utils.py
===============
Common utility functions shared across all PA modules.
Eliminates duplicate definitions of xor_bytes, normalize_key, int_to_bits.
"""


def normalize_key(key) -> int:
    """
    Accepts a key in any reasonable format (int, hex string, decimal string)
    and returns it as a Python int for use with GGM_PRF / FeistelPRP.
    """
    if isinstance(key, int):
        return key
    if key is None:
        return 0
    if isinstance(key, (bytes, bytearray)):
        return int.from_bytes(key, "big")
    if isinstance(key, str):
        key = key.strip()
        if key.startswith("0x") or key.startswith("0X"):
            return int(key, 16)
        try:
            return int(key, 16)
        except ValueError:
            return int(key)
    return int(key)


def int_to_bits(value: int, width: int) -> str:
    """Convert integer to zero-padded binary string of given width."""
    return format(value & ((1 << width) - 1), f"0{width}b")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """PKCS#7 pad *data* to a multiple of *block_size* bytes."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Remove PKCS#7 padding; raises ValueError on malformed input."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding byte value")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes (not uniform)")
    return data[:-pad_len]
