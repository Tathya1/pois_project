"""PA7 package — Merkle-Damgård Hash Transform"""
import os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from merkle_damgard import (
    MerkleDamgard, xor_compress, rotate_add_compress, COMPRESS_FNS,
    HASH_SIZE, BLOCK_SIZE, IV_DEFAULT,
    xor_compress_construct_collision, collision_propagation_demo,
)

__all__ = [
    "MerkleDamgard", "xor_compress", "rotate_add_compress", "COMPRESS_FNS",
    "HASH_SIZE", "BLOCK_SIZE", "IV_DEFAULT",
    "xor_compress_construct_collision", "collision_propagation_demo",
]
