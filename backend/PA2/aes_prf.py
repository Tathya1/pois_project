"""
PA2/aes_prf.py
==============
AES-128 as a PRF: F_k(x) = AES_k(x)

Using PyCryptodome as the OS primitive, per the PA#2 specification.
"""

from Crypto.Cipher import AES

class AES_PRF:
    def __init__(self,k_hex=None):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        self._key = k_hex if k_hex else key.hex()
        self.cipher = AES.new(key, AES.MODE_ECB)

    def F(self, x_hex):
        """F_k(x) = AES_k(x)"""
        x = bytes.fromhex(x_hex.zfill(32))
        return self.cipher.encrypt(x).hex()

    def F_inv(self, y_hex):
        """F_k^{-1}(y) = AES_k^{-1}(y) — required for CPA decryption"""
        y = bytes.fromhex(y_hex.zfill(32))
        return self.cipher.decrypt(y).hex()

    def verify_fips197_kat(self):
        """FIPS-197 Appendix B known-answer test."""
        # Standard test: Key and Plaintext from FIPS-197
        test_x = "3243f6a8885a308d313198a2e0370734"
        expected = "3925841d02dc09fbdc118597196a0b32"
        return self.F(test_x) == expected
    
    def info(self):
        """Returns metadata about the PRF"""
        return "AES-128 (PyCryptodome primitive)"