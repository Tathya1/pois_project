"""
PA#15 — Digital Signatures
"""

import sys
import os
import random
from math import gcd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA12"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA8"))

from rsa import RSA
from dlp_hash import get_default_hash

def sign(sk: dict, message: str) -> int:
    """Hash-then-sign using PA8 dlp_hash and PA12 RSA."""
    m_bytes = message.encode('utf-8')
    h = get_default_hash()
    digest = h.hash(m_bytes)
    digest_int = int.from_bytes(digest, 'big')
    
    rsa = RSA()
    # signature = digest^d mod N
    sigma = rsa.decrypt(sk["N"], sk["d"], digest_int)
    return sigma

def verify(vk: dict, message: str, sigma: int) -> bool:
    """Verify hash-then-sign signature."""
    m_bytes = message.encode('utf-8')
    h = get_default_hash()
    digest = h.hash(m_bytes)
    digest_int = int.from_bytes(digest, 'big')
    
    rsa = RSA()
    # recovered_digest = sigma^e mod N
    recovered_digest = rsa.encrypt(vk["N"], vk["e"], sigma)
    
    return recovered_digest == digest_int

def verify_with_intermediates(vk: dict, message: str, sigma: int) -> dict:
    """Verify hash-then-sign signature and return intermediates."""
    m_bytes = message.encode('utf-8')
    h = get_default_hash()
    digest = h.hash(m_bytes)
    digest_int = int.from_bytes(digest, 'big')
    
    rsa = RSA()
    recovered_digest = rsa.encrypt(vk["N"], vk["e"], sigma)
    
    return {
        "valid": recovered_digest == digest_int,
        "h_m": digest_int,
        "sigma_e": recovered_digest
    }

def sign_raw(sk: dict, message: int) -> int:
    """Raw RSA sign (no hash), vulnerable to multiplicative forgery."""
    rsa = RSA()
    return rsa.decrypt(sk["N"], sk["d"], message)

def verify_raw(vk: dict, message: int, sigma: int) -> bool:
    """Verify raw RSA signature."""
    rsa = RSA()
    recovered = rsa.encrypt(vk["N"], vk["e"], sigma)
    return recovered == message

def verify_raw_with_intermediates(vk: dict, message: int, sigma: int) -> dict:
    """Verify raw RSA signature and return intermediates."""
    rsa = RSA()
    recovered = rsa.encrypt(vk["N"], vk["e"], sigma)
    return {
        "valid": recovered == message,
        "h_m": message,
        "sigma_e": recovered
    }

