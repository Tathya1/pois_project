"""
PA3/cpa_utils.py — forwards to shared.utils (backward-compatible shim).
The whole-backend canonical source is backend/shared/utils.py.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SHARED = os.path.join(_HERE, "..", "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

from utils import normalize_key, int_to_bits, xor_bytes, pkcs7_pad, pkcs7_unpad

__all__ = ["normalize_key", "int_to_bits", "xor_bytes", "pkcs7_pad", "pkcs7_unpad"]
