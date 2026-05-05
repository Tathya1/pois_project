"""
PA#17 — CCA-Secure PKC
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA16"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA15"))

from elgamal import ElGamal
from rsa_signature import sign, verify

def signcrypt(pk_enc: dict, sk_sign: dict, message: int) -> dict:
    """CCA PKC Encrypt-then-Sign."""
    elgamal = ElGamal()
    # 1. Encrypt with ElGamal
    CE = elgamal.encrypt(pk_enc["p"], pk_enc["q"], pk_enc["g"], pk_enc["h"], message)
    
    # 2. Sign the ciphertext components (c1, c2)
    CE_str = f"{CE['c1']}:{CE['c2']}"
    sigma = sign(sk_sign, CE_str)
    
    return {"CE": CE, "sigma": sigma}

def verify_decrypt(sk_enc: dict, vk_sign: dict, CE: dict, sigma: int) -> dict:
    """Verify-then-Decrypt for CCA PKC."""
    elgamal = ElGamal()
    
    # 1. Verify signature
    CE_str = f"{CE['c1']}:{CE['c2']}"
    is_valid = verify(vk_sign, CE_str, sigma)
    
    if not is_valid:
        return {"success": False, "error": "Signature invalid, decryption aborted, output ⊥."}
        
    # 2. Decrypt
    m = elgamal.decrypt(sk_enc["p"], sk_enc["x"], CE['c1'], CE['c2'])
    
    return {"success": True, "message": m}
