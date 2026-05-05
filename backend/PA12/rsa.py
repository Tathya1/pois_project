"""
PA#12 — Textbook RSA + Garner's CRT Decryption

Implements (no external crypto libraries, uses PA#13 for prime generation):
  - mod_exp(base, exp, mod)          : square-and-multiply (no library pow)
  - extended_gcd(a, b)               : iterative extended Euclidean algorithm
  - mod_inverse(a, n)                : modular inverse via extended GCD
  - RSA.keygen(bits)                 : RSA key pair generation using PA#13 gen_prime
  - RSA.encrypt(N, e, m)             : textbook encryption  C = m^e mod N
  - RSA.decrypt(N, d, c)             : textbook decryption  M = c^d mod N
  - RSA.decrypt_crt(p,q,dp,dq,qinv,c): Garner's CRT decryption (~4x faster)

Warning: Textbook RSA is deterministic and NOT CPA-secure.
Use PKCS#1 v1.5 (pkcs15.py) for any practical encryption.

Dependency: PA#13 (miller_rabin.py) for gen_prime.
"""

import os
import sys
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA13"))

from miller_rabin import gen_prime


# ---------------------------------------------------------------------------
# Core arithmetic (all hand-rolled, no library pow)
# ---------------------------------------------------------------------------

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Square-and-multiply modular exponentiation.
    Computes base^exp mod mod without using Python's built-in pow().
    This is the same algorithm as in PA#13 — included here so PA#12 is
    self-contained and the lineage is explicit.
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Iterative Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).

    Iterative (not recursive) to avoid Python stack overflow on large inputs
    (e.g., 2048-bit RSA moduli).
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t      # (gcd, x, y)


def mod_inverse(a: int, n: int) -> int:
    """
    Modular inverse of a modulo n.
    Returns x in [0, n) such that (a * x) % n == 1.
    Raises ValueError if the inverse does not exist (gcd(a, n) != 1).
    """
    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(
            f"Modular inverse does not exist: gcd({a}, {n}) = {g}"
        )
    return x % n


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------

class RSA:
    """
    Textbook RSA with optional Garner's CRT decryption.

    Standard public exponent e = 65537 (Fermat prime F4).
    """

    E_PUBLIC: int = 65537

    def keygen(self, bits: int = 512) -> dict:
        """
        Generate an RSA key pair.

        Steps:
          1. Generate two (bits//2)-bit probable primes p and q (via PA#13).
          2. N = p * q
          3. phi(N) = (p-1)(q-1)
          4. e = 65537  (verify gcd(e, phi) = 1)
          5. d = e^(-1) mod phi
          6. CRT components: dp = d mod (p-1), dq = d mod (q-1), q_inv = q^(-1) mod p

        Returns a dict with all key components as Python ints.
        """
        half = bits // 2

        # Generate two distinct primes
        p = gen_prime(half, k=40)
        q = gen_prime(half, k=40)
        while q == p:
            q = gen_prime(half, k=40)

        N   = p * q
        phi = (p - 1) * (q - 1)
        e   = self.E_PUBLIC

        # Verify e and phi are coprime (should always hold for e=65537 and safe primes)
        g, _, _ = extended_gcd(e, phi)
        if g != 1:
            raise RuntimeError(
                f"gcd(e={e}, phi) = {g} != 1; try regenerating primes."
            )

        d     = mod_inverse(e, phi)
        dp    = d % (p - 1)            # CRT exponent for p
        dq    = d % (q - 1)            # CRT exponent for q
        q_inv = mod_inverse(q, p)      # q^(-1) mod p  (Garner's coefficient)

        return {
            "N":     N,
            "e":     e,
            "d":     d,
            "p":     p,
            "q":     q,
            "dp":    dp,
            "dq":    dq,
            "q_inv": q_inv,
        }

    def encrypt(self, N: int, e: int, m: int) -> int:
        """
        Textbook RSA encryption: C = m^e mod N.
        Requires 0 <= m < N.
        """
        if not (0 <= m < N):
            raise ValueError(f"Message m={m} must satisfy 0 <= m < N={N}")
        return mod_exp(m, e, N)

    def decrypt(self, N: int, d: int, c: int) -> int:
        """
        Textbook RSA decryption: M = c^d mod N.
        """
        return mod_exp(c, d, N)

    def decrypt_crt(
        self,
        p:     int,
        q:     int,
        dp:    int,
        dq:    int,
        q_inv: int,
        c:     int,
    ) -> int:
        """
        Garner's CRT decryption — approximately 4x faster than standard decrypt.

        Steps:
          mp = c^dp  mod p          (small exponent, small modulus)
          mq = c^dq  mod q          (small exponent, small modulus)
          h  = q_inv * (mp - mq) mod p
          m  = mq + h * q

        This is mathematically equivalent to c^d mod N but avoids the full
        N-sized modular exponentiation.
        """
        mp = mod_exp(c, dp, p)
        mq = mod_exp(c, dq, q)
        h  = (q_inv * (mp - mq)) % p
        return mq + h * q
