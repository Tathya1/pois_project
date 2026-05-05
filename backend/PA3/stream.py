import math
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA2"))

from prf import GGM_PRF
from cpa_utils import int_to_bits

BLOCK_BYTES = 8

def pkcs7_pad(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data, block_size):
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")

    return data[:-pad_len]

def keystream(key, r, length_bytes):
    prf = GGM_PRF()

    blocks = math.ceil(length_bytes / BLOCK_BYTES)
    stream = b""

    for i in range(blocks):
        counter = r + i
        bits = int_to_bits(counter, BLOCK_BYTES * 8)

        out_hex = prf.F(key, bits)
        out_hex = out_hex.zfill(BLOCK_BYTES * 2)

        out_int = int(out_hex, 16)
        stream += out_int.to_bytes(BLOCK_BYTES, "big")

    return stream[:length_bytes]
