"""
PA#16 — ElGamal Public-Key Cryptosystem

Implements (no external crypto libraries):
  - ElGamal key generation, encryption, decryption
  - Re-randomization (IND-CPA security demo)
  - Multiplicative homomorphism: Enc(m1) * Enc(m2) = Enc(m1*m2)
  - DDH-based security discussion

Security basis: Decisional Diffie-Hellman (DDH) assumption.
Group: prime-order-q subgroup of Z*_p where p = 2q+1 is a safe prime.
Semantic security: randomized encryption → ciphertexts differ even for same m.

Dependency: PA#11 (dh.py) for group setup, PA#13 (miller_rabin.py) for primes.
"""

import os
import sys
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA11"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA13"))

from dh import DH, find_generator
from miller_rabin import mod_exp, gen_safe_prime, miller_rabin


# ---------------------------------------------------------------------------
# Extended GCD / modular inverse (self-contained within PA#16)
# ---------------------------------------------------------------------------

def _extended_gcd(a: int, b: int):
    """Iterative Extended Euclidean Algorithm. Returns (gcd, x, y)."""
    old_r, r = a, b
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_r, old_s, (old_r - old_s * a) // b if b else 0


def mod_inverse(a: int, n: int) -> int:
    """Modular inverse of a mod n. Raises ValueError if it does not exist."""
    g, x, _ = _extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"Inverse does not exist: gcd({a}, {n}) = {g}")
    return x % n


# ---------------------------------------------------------------------------
# ElGamal key generation, encryption, decryption
# ---------------------------------------------------------------------------

class ElGamal:
    """
    ElGamal public-key encryption scheme.

    Key space:
      - Public key:  (p, q, g, h)  where h = g^x mod p
      - Private key: x  (in [1, q-1])

    Encryption of m in [1, p-1]:
      - Sample r ← {1, ..., q-1}
      - c1 = g^r mod p           (ephemeral DH key)
      - c2 = m * h^r mod p       (blinded message)
      - Ciphertext: (c1, c2)

    Decryption:
      - s  = c1^x mod p          (shared secret = g^(rx))
      - m  = c2 * s^(-1) mod p

    IND-CPA security: Each encryption uses fresh randomness r, so encrypting
    the same message twice yields different (c1, c2) pairs.
    The scheme is CPA-secure under the DDH assumption.

    Homomorphism (multiplicative):
      Enc(m1, r1) * Enc(m2, r2) = Enc(m1*m2, r1+r2) component-wise:
        (c1_1 * c1_2 mod p, c2_1 * c2_2 mod p) decrypts to m1*m2 mod p.
    """

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def keygen(self, bits: int = 32) -> dict:
        """
        Generate an ElGamal key pair.

        Parameters
        ----------
        bits : int
            Bit-length of the safe prime p. Minimum 16 (toy), 256+ for
            educational security, 2048+ for real security.

        Returns
        -------
        dict with keys: p, q, g, x (private), h (public)
        """
        bits = max(16, bits)
        p, q = gen_safe_prime(bits)
        g = find_generator(p, q)
        # Private key: x ← {1, ..., q-1}
        x = secrets.randbelow(q - 1) + 1
        # Public key: h = g^x mod p
        h = mod_exp(g, x, p)
        return {"p": p, "q": q, "g": g, "x": x, "h": h}

    # ------------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------------

    def encrypt(self, p: int, q: int, g: int, h: int, m: int) -> dict:
        """
        Encrypt message m under public key (p, q, g, h).

        m must be in [1, p-1] (as a group element).

        Returns
        -------
        dict: {c1, c2, r, s}
          c1 = g^r mod p
          c2 = m * h^r mod p
          r  = ephemeral randomness (for educational display only)
          s  = shared secret h^r = g^(xr) mod p
        """
        if not (1 <= m <= p - 1):
            raise ValueError(f"Message m={m} must be in [1, p-1].")
        # Ephemeral key r ← Zq
        r = secrets.randbelow(q - 1) + 1
        c1 = mod_exp(g, r, p)
        s = mod_exp(h, r, p)   # shared secret: g^(xr) mod p
        c2 = m * s % p
        return {"c1": c1, "c2": c2, "r": r, "s": s}

    # ------------------------------------------------------------------
    # Decryption
    # ------------------------------------------------------------------

    def decrypt(self, p: int, x: int, c1: int, c2: int) -> int:
        """
        Decrypt ciphertext (c1, c2) using private key x.

        s   = c1^x mod p   (recovers the shared secret)
        m   = c2 * s^(-1) mod p

        Returns the plaintext m.
        """
        s = mod_exp(c1, x, p)
        s_inv = mod_inverse(s, p)
        return c2 * s_inv % p

    # ------------------------------------------------------------------
    # Re-randomization (IND-CPA demo)
    # ------------------------------------------------------------------

    def rerandomize(self, p: int, q: int, g: int, h: int,
                    c1: int, c2: int) -> dict:
        """
        Produce a *different* but *equivalent* ciphertext for the same
        plaintext, without knowing the plaintext.

        Given Enc(m, r) = (c1, c2):
          New Enc(m, r + r') = (c1 * g^r' mod p, c2 * h^r' mod p)

        This demonstrates that ElGamal ciphertexts are publicly re-randomizable.
        (Important property in mixing / e-voting protocols.)
        """
        r_prime = secrets.randbelow(q - 1) + 1
        new_c1 = c1 * mod_exp(g, r_prime, p) % p
        new_c2 = c2 * mod_exp(h, r_prime, p) % p
        return {"c1": new_c1, "c2": new_c2, "r_prime": r_prime}

    # ------------------------------------------------------------------
    # Multiplicative homomorphism
    # ------------------------------------------------------------------

    def homomorphic_mul(self, p: int,
                        c1_a: int, c2_a: int,
                        c1_b: int, c2_b: int) -> dict:
        """
        Component-wise multiply two ciphertexts:
          Enc(m1) ⊗ Enc(m2) = Enc(m1 * m2 mod p)

        Proof:
          (c1_a * c1_b, c2_a * c2_b)
          = (g^(r1+r2), m1*m2 * h^(r1+r2))
          = Enc(m1 * m2 mod p, r1+r2)

        Decrypting with private key x recovers m1*m2 mod p.
        """
        return {
            "c1": c1_a * c1_b % p,
            "c2": c2_a * c2_b % p,
        }

    # ------------------------------------------------------------------
    # DDH game demo (educational)
    # ------------------------------------------------------------------

    def ddh_game(self, bits: int = 16) -> dict:
        """
        Toy DDH distinguisher demo.

        DDH assumption: (g, g^a, g^b, g^(ab)) is computationally
        indistinguishable from (g, g^a, g^b, g^r) for random r.

        With tiny parameters the discrete log is easily computable,
        so the demo reveals both triples for comparison.

        Returns both a "DH triple" and a "random triple" for comparison.
        """
        bits = max(12, min(bits, 32))
        keys = self.keygen(bits)
        p, q, g = keys["p"], keys["q"], keys["g"]

        a = secrets.randbelow(q - 1) + 1
        b = secrets.randbelow(q - 1) + 1
        r = secrets.randbelow(q - 1) + 1

        g_a = mod_exp(g, a, p)
        g_b = mod_exp(g, b, p)
        g_ab = mod_exp(g, a * b % q, p)   # true DH value
        g_r = mod_exp(g, r, p)             # random value

        return {
            "p": p, "q": q, "g": g,
            "a": a, "b": b,
            "g_a": g_a, "g_b": g_b,
            "dh_triple":     {"g_a": g_a, "g_b": g_b, "g_ab":  g_ab, "type": "DH"},
            "random_triple": {"g_a": g_a, "g_b": g_b, "g_r":   g_r,  "type": "random"},
            "note": (
                "DDH says these two triples are computationally indistinguishable "
                "for large p. For small p here, you can verify by computing "
                "discrete logs (brute-force)."
            ),
        }

    # ------------------------------------------------------------------
    # IND-CPA Game (educational)
    # ------------------------------------------------------------------

    def ind_cpa_game(self, bits: int, rounds: int = 100) -> dict:
        """
        Simulate an IND-CPA game to measure adversary advantage.

        An adversary that can break DDH can win this game. For small groups
        where the discrete log is feasible, we can simulate this.

        Adversary's strategy:
        1. Given public key (p, q, g, h) and a challenge ciphertext (c1, c2).
        2. If the group is small, compute x = log_g(h) via brute force.
        3. With x, decrypt (c1, c2) to get m.
        4. If m == m0, guess 0. If m == m1, guess 1.
        5. If the group is large, computing x is infeasible. Guess randomly.
        """
        success_count = 0
        m0, m1 = 2, 3  # Fixed messages for the game

        # The threshold where brute-force becomes too slow for a demo.
        # A real threshold is much higher (e.g., >256 bits).
        is_small_group = bits <= 16

        for _ in range(rounds):
            keys = self.keygen(bits)
            p, q, g, h = keys["p"], keys["q"], keys["g"], keys["h"]

            # Challenger chooses a bit b and encrypts m_b
            b = secrets.randbelow(2)
            m_to_encrypt = m0 if b == 0 else m1
            enc = self.encrypt(p, q, g, h, m_to_encrypt)
            c1, c2 = enc["c1"], enc["c2"]

            # Adversary's turn to guess b'
            b_guess = -1
            if is_small_group:
                # Simulate adversary breaking crypto by finding x
                try:
                    # Brute-force discrete log to find private key x
                    found_x = -1
                    for test_x in range(1, q):
                        if mod_exp(g, test_x, p) == h:
                            found_x = test_x
                            break
                    
                    if found_x != -1:
                        # Decrypt using the found key
                        dec_m = self.decrypt(p, found_x, c1, c2)
                        if dec_m == m0:
                            b_guess = 0
                        elif dec_m == m1:
                            b_guess = 1
                        else:
                            b_guess = secrets.randbelow(2) # Should not happen
                    else:
                        b_guess = secrets.randbelow(2) # Failed to find x
                except Exception:
                    b_guess = secrets.randbelow(2) # Error, guess
            else:
                # For large groups, adversary cannot compute discrete log.
                # They are forced to guess randomly.
                b_guess = secrets.randbelow(2)

            if b_guess == b:
                success_count += 1

        return {
            "bits": bits,
            "rounds": rounds,
            "success_count": success_count,
            "advantage": (success_count / rounds) - 0.5,
        }
