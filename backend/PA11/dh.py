"""
PA#11 — Diffie-Hellman Key Exchange

Implements (no external crypto libraries, uses PA#13 for group setup):
  - find_generator(p, q)        : find a generator of the prime-order-q subgroup of Z*_p
  - DH class                    : DH protocol (group generation, Alice/Bob steps)
  - mitm_attack(dh, A, B)       : Man-in-the-Middle attack demonstration

Security basis: Computational Diffie-Hellman (CDH) assumption.
Group: prime-order-q subgroup of Z*_p where p = 2q+1 is a safe prime.

Dependency: PA#13 (miller_rabin.py) for mod_exp and prime generation.
"""

import os
import sys
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA13"))

from miller_rabin import mod_exp, gen_safe_prime, miller_rabin


# ---------------------------------------------------------------------------
# Group setup helpers
# ---------------------------------------------------------------------------

def find_generator(p: int, q: int) -> int:
    """
    Find a generator g of the prime-order-q subgroup of Z*_p,
    where p = 2q + 1 is a safe prime.

    Proof that this works:
      Z*_p has order p-1 = 2q.  Every element has order dividing 2q,
      so possible orders are: 1, 2, q, 2q.
      For a safe prime, the only elements with order 1 or 2 are
      h=1 and h=p-1 (≡ -1 mod p).
      For any other h, g = h^2 mod p is a quadratic residue of order q.
      (squaring maps order-2q elements to order-q, order-q stays order-q,
       order-1 and order-2 map to order-1.)
      So: pick random h in [2, p-2], compute g = h^2 mod p, check g != 1.
    """
    while True:
        h = secrets.randbelow(p - 3) + 2       # h in [2, p-2]
        g = mod_exp(h, 2, p)                   # g = h^2 mod p
        if g != 1:
            return g


# ---------------------------------------------------------------------------
# DH class
# ---------------------------------------------------------------------------

class DH:
    """
    Diffie-Hellman key exchange over the prime-order-q subgroup of Z*_p.

    Public parameters: p (safe prime), q (subgroup order), g (generator).
    Protocol:
      Alice: picks private a in Zq, sends A = g^a mod p.
      Bob:   picks private b in Zq, sends B = g^b mod p.
      Both compute shared secret K = g^ab mod p.
    """

    def __init__(
        self,
        p: int = None,
        q: int = None,
        g: int = None,
        bits: int = 32,
    ):
        """
        If (p, q, g) are provided: use them as group parameters.
        Otherwise: generate a fresh safe prime of `bits` bits.
        """
        if p is not None and q is not None and g is not None:
            self.p = p
            self.q = q
            self.g = g
        else:
            self.p, self.q = gen_safe_prime(bits)
            self.g = find_generator(self.p, self.q)

    # ------------------------------------------------------------------
    # Protocol steps
    # ------------------------------------------------------------------

    def alice_step1(self) -> tuple[int, int]:
        """
        Alice samples private exponent a in Zq and computes
        public value A = g^a mod p.
        Returns (a, A).
        """
        a = secrets.randbelow(self.q - 1) + 1   # a in [1, q-1]
        A = mod_exp(self.g, a, self.p)
        return a, A

    def bob_step1(self) -> tuple[int, int]:
        """
        Bob samples private exponent b in Zq and computes
        public value B = g^b mod p.
        Returns (b, B).
        """
        b = secrets.randbelow(self.q - 1) + 1   # b in [1, q-1]
        B = mod_exp(self.g, b, self.p)
        return b, B

    def alice_step2(self, a: int, B: int) -> int:
        """Alice computes shared secret K = B^a mod p = g^(ab) mod p."""
        return mod_exp(B, a, self.p)

    def bob_step2(self, b: int, A: int) -> int:
        """Bob computes shared secret K = A^b mod p = g^(ab) mod p."""
        return mod_exp(A, b, self.p)

    # ------------------------------------------------------------------
    # Full exchange (convenience)
    # ------------------------------------------------------------------

    def run_exchange(self) -> dict:
        """
        Run a complete DH key exchange and return all values.
        Asserts that Alice's and Bob's shared secrets match.
        """
        a, A = self.alice_step1()
        b, B = self.bob_step1()
        K_alice = self.alice_step2(a, B)
        K_bob   = self.bob_step2(b, A)

        assert K_alice == K_bob, "BUG: shared secrets do not match!"

        return {
            "p":             self.p,
            "q":             self.q,
            "g":             self.g,
            "alice_private": a,
            "alice_public":  A,
            "bob_private":   b,
            "bob_public":    B,
            "shared_secret": K_alice,
            "match":         True,
        }


# ---------------------------------------------------------------------------
# Man-in-the-Middle attack
# ---------------------------------------------------------------------------

def mitm_attack(dh: DH, A: int, B: int) -> dict:
    """
    Demonstrate the MITM attack on unauthenticated DH.

    Eve intercepts Alice's public value A and Bob's public value B,
    substitutes her own value E = g^e mod p for both, then:
      - Establishes shared secret K_AE = A^e = g^(ae) with Alice.
      - Establishes shared secret K_BE = B^e = g^(be) with Bob.

    Neither Alice nor Bob can detect this without authentication
    (which requires digital signatures — PA#15).

    Note: this function simulates Eve's computation only.
    In a real protocol, Eve would need to intercept the network channel.
    """
    e = secrets.randbelow(dh.q - 1) + 1      # Eve's private exponent
    E = mod_exp(dh.g, e, dh.p)               # Eve's public value

    # Eve computes her two shared secrets
    K_AE = mod_exp(A, e, dh.p)              # = g^(ae) — shared with Alice
    K_BE = mod_exp(B, e, dh.p)              # = g^(be) — shared with Bob

    return {
        "eve_private":  e,
        "eve_public":   E,
        "K_alice_eve":  K_AE,
        "K_bob_eve":    K_BE,
        "note": (
            "Eve shares K_alice_eve with Alice and K_bob_eve with Bob. "
            "She relays messages between them, decrypting and re-encrypting each. "
            "Fix: authenticate A and B with digital signatures (PA#15)."
        ),
    }
