"""
PA5/mac.py
==========
Implementation of Secure Message Authentication Codes (MACs).

Includes:
1. PRF_MAC: A fixed-length MAC applying the PRF directly.
2. CBC_MAC: A variable-length MAC built by chaining the PRF.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PA2  = os.path.join(_HERE, "..", "PA2")
_SHARED = os.path.join(_HERE, "..", "shared")

for _p in [_PA2, _SHARED]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from prf import GGM_PRF
from utils import normalize_key, pkcs7_pad, xor_bytes

class PRF_MAC:
    """
    Fixed-length MAC using the GGM PRF explicitly.
    m_len must be exactly the block size.
    """
    def __init__(self, block_size=8):
        self.block_size = block_size
        self.prf = GGM_PRF()
        
    def mac(self, key, message: bytes) -> str:
        """Computes MAC over exactly block_size bytes. Pads with 0 if shorter. Truncates if longer."""
        if len(message) > self.block_size:
            message = message[:self.block_size]
        message = message.ljust(self.block_size, b'\x00')
        
        k = normalize_key(key)
        x_bits = ''.join(format(b, '08b') for b in message)
        
        # GGM_PRF returns hex string.
        # Since it processes bit by bit, for 64 bits = 64 PRG invocations.
        return self.prf.F(k, x_bits)
        
    def verify(self, key, message: bytes, tag: str) -> bool:
        """Verifies the given tag against the message."""
        expected = self.mac(key, message)
        return expected == tag

class CBC_MAC:
    """
    Variable-length MAC using CBC-MAC over the GGM PRF.
    Suitable for arbitrary length messages using PKCS7 padding.
    """
    def __init__(self, block_size=8):
        self.block_size = block_size
        self.prf = GGM_PRF()
        
    def mac(self, key, message: bytes) -> str:
        padded = pkcs7_pad(message, self.block_size)
        k = normalize_key(key)
        
        t = b'\x00' * self.block_size
        
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i+self.block_size]
            xored = xor_bytes(t, block)
            x_bits = ''.join(format(b, '08b') for b in xored)
            
            # Compute F_k(t \oplus m_i)
            out_hex = self.prf.F(k, x_bits)
            
            # out_hex might be variable length. Ensure it is block_size bytes.
            t = bytes.fromhex(out_hex.zfill(self.block_size * 2))[-self.block_size:]
            
        return t.hex()
        
    def verify(self, key, message: bytes, tag: str) -> bool:
        expected = self.mac(key, message)
        return expected == tag

def hmac_stub(key, message: bytes) -> str:
    """
    Placeholder for HMAC to be implemented in PA#10.
    """
    raise NotImplementedError("HMAC is scheduled for PA#10")
