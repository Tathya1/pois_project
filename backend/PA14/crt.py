"""
PA#14 — Chinese Remainder Theorem & Breaking Textbook RSA
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA12"))

from rsa import extended_gcd, mod_inverse, mod_exp, RSA

def crt(residues: list[int], moduli: list[int]) -> int:
    """Generic CRT solver."""
    N = 1
    for n in moduli:
        N *= n
    
    result = 0
    for a_i, n_i in zip(residues, moduli):
        m_i = N // n_i
        y_i = mod_inverse(m_i, n_i)
        result = (result + a_i * m_i * y_i) % N
    return result % N

def rsa_dec_crt(sk: dict, c: int) -> int:
    """Garner's CRT based RSA decryption."""
    p = sk["p"]
    q = sk["q"]
    dp = sk["dp"]
    dq = sk["dq"]
    q_inv = sk["q_inv"]
    
    mp = mod_exp(c, dp, p)
    mq = mod_exp(c, dq, q)
    h = (q_inv * (mp - mq)) % p
    return mq + h * q

def integer_nth_root(n: int, k: int) -> int:
    """Integer k-th root of n."""
    if n < 0:
        raise ValueError("Cannot compute root of negative integer")
    if n == 0:
        return 0
    
    low = 1
    high = 1
    while high ** k <= n:
        high *= 2
    
    while low < high:
        mid = (low + high) // 2
        if mid ** k < n:
            low = mid + 1
        else:
            high = mid
            
    if low ** k <= n:
        return low
    return low - 1

def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> tuple[int, int]:
    """
    Håstad's broadcast attack for small public exponent e.
    """
    if len(ciphertexts) != e or len(moduli) != e:
        raise ValueError("Håstad attack requires e ciphertexts and moduli")
        
    x = crt(ciphertexts, moduli)
    m = integer_nth_root(x, e)
    return x, m
