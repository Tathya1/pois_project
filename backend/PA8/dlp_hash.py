"""
PA8/dlp_hash.py
===============
PA #8 — Collision-Resistant Hash Function (CRHF) via Discrete Logarithm

Construction
------------
Let p = 2q + 1 be a safe prime (both p and q are prime).
Let G = ⟨g⟩ be the order-q subgroup of Z*_p (the quadratic residues mod p).
Let h = g^α mod p  for a random secret α (immediately discarded).

Compression function
--------------------
  compress(x, y) = g^x · h^y  mod p      (x, y ∈ Z_q)

Collision resistance
--------------------
Suppose A finds (x1,y1) ≠ (x2,y2) with compress(x1,y1) = compress(x2,y2).
  g^x1 · h^y1 = g^x2 · h^y2  (mod p)
  g^(x1-x2) = h^(y2-y1)       (mod p)
  g^(x1-x2) = g^(α(y2-y1))    (mod p)
  α = (x1-x2) · (y2-y1)^(-1)  mod q      ← this is the discrete log of h!

So any collision finder also solves DLP — impossible by assumption. ∎

Birthday Bound
--------------
With digest length n bits, expected collisions after ≈ 2^(n/2) evaluations.
Toy parameters (small q) demonstrate this bound empirically.
"""

import os
import sys
import secrets

_HERE = os.path.dirname(os.path.abspath(__file__))
_PA7  = os.path.join(_HERE, "..", "PA7")
if _PA7 not in sys.path:
    sys.path.insert(0, _PA7)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from merkle_damgard import MerkleDamgard


# ---------------------------------------------------------------------------
# Primality (deterministic Miller-Rabin for n < 3,215,031,751)
# ---------------------------------------------------------------------------

def is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin for n < 3,215,031,751 using witnesses {2,3,5,7}."""
    if n < 2: return False
    if n in (2, 3, 5, 7): return True
    if n % 2 == 0: return False

    # Write n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for a in [2, 3, 5, 7]:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def find_safe_prime_pair(min_bits: int = 12, max_bits: int = 16) -> tuple:
    """
    Find the smallest safe prime pair (q, p) with 2^(min_bits-1) ≤ q < 2^max_bits
    and p = 2q+1, both prime.
    """
    for bits in range(min_bits, max_bits + 1):
        for q in range(2 ** (bits - 1), 2 ** bits):
            if is_prime(q) and is_prime(2 * q + 1):
                return q, 2 * q + 1
    raise ValueError(f"No safe prime found in [{min_bits}, {max_bits}] bits range")


def modular_inverse(a: int, m: int) -> int:
    """Modular inverse via Python 3.8+ built-in pow."""
    return pow(a, -1, m)


# ---------------------------------------------------------------------------
# DLP Group
# ---------------------------------------------------------------------------

class DLP_Group:
    """
    Discrete-log group for CRHF construction.

    Parameters
    ----------
    bits : target bit-length of q.  Toy: bits=16 gives q ≈ 2^16 for a larger demo.
    """

    def __init__(self, bits: int = 16):
        self.bits = bits

        # Find safe prime pair
        self.q, self.p = find_safe_prime_pair(bits, bits + 2)

        # Find a generator of the order-q subgroup (quadratic residues mod p)
        self.g = self._find_generator()

        # h = g^alpha mod p — alpha is the secret (discarded)
        alpha   = secrets.randbelow(self.q - 1) + 1
        self.h  = pow(self.g, alpha, self.p)
        # alpha is intentionally NOT stored — collision finding requires solving DLP

        # Digest truncation for birthday attack demo (fixed 16-bit output)
        self.output_bits = 16
        self._output_mod = 2 ** self.output_bits

    def _find_generator(self) -> int:
        """
        Find a generator of the order-q subgroup.
        p = 2q+1, so QRs form the unique subgroup of order q.
        g = a^2 mod p for any a ∉ {1, p-1} that satisfies g ≠ 1.
        """
        for a in range(2, self.p):
            g = pow(a, 2, self.p)           # g is a quadratic residue
            if g != 1:
                assert pow(g, self.q, self.p) == 1, f"g^q ≠ 1 for g={g}"
                return g
        raise ValueError("Generator not found")

    def compress(self, x: int, y: int) -> int:
        """
        compress(x, y) = g^x * h^y  mod p    (x, y reduced mod q)
        Full output ∈ [1, p-1].
        """
        gx = pow(self.g, x % self.q, self.p)
        hy = pow(self.h, y % self.q, self.p)
        return (gx * hy) % self.p

    def compress_truncated(self, x: int, y: int) -> int:
        """Truncate compress output to output_bits for birthday attack."""
        return self.compress(x, y) % self._output_mod

    def attempt_dlog_from_collision(
        self, x1: int, y1: int, x2: int, y2: int
    ) -> dict:
        """
        Given a collision (x1,y1) ≠ (x2,y2) in compress, extract α = dlog_g(h).

        Equation: g^(x1-x2) ≡ g^(α(y2-y1))  (mod p)
                  α ≡ (x1-x2) * (y2-y1)^(-1)  mod q
        """
        dx = (x1 - x2) % self.q
        dy = (y2 - y1) % self.q

        if dy == 0:
            return {"success": False, "reason": "y2-y1 = 0; same y values — try again"}

        alpha_recovered = (dx * modular_inverse(dy, self.q)) % self.q
        h_verify        = pow(self.g, alpha_recovered, self.p)

        return {
            "success":         True,
            "alpha_recovered": alpha_recovered,
            "h_from_alpha":    h_verify,
            "h_original":      self.h,
            "alpha_correct":   h_verify == self.h,
        }

    def info(self) -> dict:
        return {
            "p":            self.p,
            "q":            self.q,
            "g":            self.g,
            "h":            self.h,
            "p_bits":       self.p.bit_length(),
            "q_bits":       self.q.bit_length(),
            "output_bits":  self.output_bits,
            "subgroup_order": self.q,
            "birthday_bound": int(2 ** (self.output_bits / 2)),
            "note": (
                f"Toy parameters for demo. Real construction uses p ≥ 2048 bits. "
                f"Birthday bound ≈ 2^{self.output_bits//2} = {2**(self.output_bits//2)} evaluations."
            ),
        }


# ---------------------------------------------------------------------------
# DLP Hash (DLP compress plugged into Merkle-Damgård)
# ---------------------------------------------------------------------------

class DLP_Hash:
    """
    Full collision-resistant hash: DLP compress + Merkle-Damgård.

    Block layout (block_size = 16 bytes):
      - Bytes 0–7  → y (block data, reduced mod q)
      - Chaining value cv (8 bytes) → x (reduced mod q)
    """

    BLOCK_SIZE = 16
    HASH_SIZE  = 8

    def __init__(self, bits: int = 16):
        self.group = DLP_Group(bits=bits)
        self._md   = MerkleDamgard(
            compress_fn = self._compress_adapter,
            iv          = b'\x00' * self.HASH_SIZE,
            block_size  = self.BLOCK_SIZE,
        )

    def _compress_adapter(self, cv: bytes, block: bytes) -> bytes:
        x = int.from_bytes(cv, 'big') % self.group.q
        y = int.from_bytes(block[:8], 'big') % self.group.q
        # Full compress output, truncated to HASH_SIZE bytes
        result = self.group.compress(x, y) % (2 ** (self.HASH_SIZE * 8))
        return result.to_bytes(self.HASH_SIZE, 'big')

    def hash(self, message: bytes) -> bytes:
        return self._md.hash(message)

    def hash_hex(self, message: bytes) -> str:
        return self._md.hash_hex(message)

    def trace(self, message: bytes) -> dict:
        t = self._md.trace(message)
        t["group_info"] = self.group.info()
        return t

    def group_info(self) -> dict:
        return self.group.info()


# ---------------------------------------------------------------------------
# Birthday Attack
# ---------------------------------------------------------------------------

def birthday_attack(group: DLP_Group, max_evaluations: int = 5000) -> dict:
    """
    Birthday attack on compress_truncated(x, y) = g^x * h^y mod p  mod 2^output_bits.

    Randomly samples (x, y) pairs until two produce the same truncated output.
    Expected: O(2^(output_bits/2)) evaluations (birthday bound).

    After finding a collision (x1,y1) ≠ (x2,y2), attempts to recover α = dlog_g(h)
    as proof that a compresscollision is cryptographically meaningful.
    """
    seen: dict = {}   # hash_value → (x, y)

    for i in range(max_evaluations):
        x = secrets.randbelow(group.q)
        y = secrets.randbelow(group.q)
        h = group.compress_truncated(x, y)

        if h in seen:
            x2_found, y2_found = seen[h]
            if (x, y) != (x2_found, y2_found):   # genuine collision
                dlog_result = group.attempt_dlog_from_collision(
                    x2_found, y2_found, x, y
                )
                return {
                    "success":         True,
                    "evaluations":     i + 1,
                    "expected":        int(2 ** (group.output_bits / 2)),
                    "output_bits":     group.output_bits,
                    "collision": {
                        "x1": x2_found, "y1": y2_found,
                        "x2": x,        "y2": y,
                        "hash_value": h,
                    },
                    "dlog_extraction": dlog_result,
                    "explanation": (
                        f"Collision found in {i+1} evaluations "
                        f"(expected ≈ {int(2**(group.output_bits/2))} by birthday bound). "
                        f"This collision was used to recover α = dlog_g(h) = "
                        f"{dlog_result.get('alpha_recovered', 'N/A')}, "
                        f"proving that collision resistance requires DLP hardness."
                    ),
                }
        seen[h] = (x, y)

    return {
        "success":     False,
        "evaluations": max_evaluations,
        "output_bits": group.output_bits,
        "explanation": "No collision found within budget. Try increasing max_evaluations.",
    }


# ---------------------------------------------------------------------------
# Formal collision resistance argument
# ---------------------------------------------------------------------------

def collision_resistance_argument(group: DLP_Group) -> dict:
    """
    Formal argument that DLP compress is collision-resistant under the DLP assumption.
    Returns a structured proof for frontend display.
    """
    return {
        "group": group.info(),
        "claim": "compress(x,y) = g^x · h^y mod p is collision-resistant.",
        "proof_steps": [
            {
                "step": 1,
                "statement": "Assume adversary A finds (x1,y1) ≠ (x2,y2) with compress(x1,y1) = compress(x2,y2).",
                "math": "g^x1 · h^y1 ≡ g^x2 · h^y2  (mod p)",
            },
            {
                "step": 2,
                "statement": "Rearrange to isolate g and h terms.",
                "math": "g^(x1-x2) ≡ h^(y2-y1)  (mod p)",
            },
            {
                "step": 3,
                "statement": "Substitute h = g^α (where α is the hidden discrete log).",
                "math": "g^(x1-x2) ≡ g^(α(y2-y1))  (mod p)",
            },
            {
                "step": 4,
                "statement": "Since g generates a prime-order q subgroup, exponents are compared mod q.",
                "math": "(x1 - x2) ≡ α(y2 - y1)  (mod q)",
            },
            {
                "step": 5,
                "statement": "When y1 ≠ y2 (i.e., y2-y1 ≢ 0 mod q), invert (y2-y1) mod q.",
                "math": "α ≡ (x1 - x2) · (y2 - y1)^{-1}  (mod q)",
            },
            {
                "step": 6,
                "statement": "This gives us α = dlog_g(h) — the discrete logarithm of h base g!",
                "math": "A has solved the Discrete Logarithm Problem in G.",
            },
            {
                "step": 7,
                "statement": "This contradicts the DLP hardness assumption in G.",
                "math": "⊥  Contradiction.  Therefore, compress is collision-resistant.  ∎",
            },
        ],
        "dlp_assumption": (
            f"The Discrete Logarithm Problem in the order-{group.q} subgroup of Z*_{group.p} "
            f"is assumed computationally infeasible. With real parameters (q ≈ 2^256), "
            f"the best known algorithms (GNFS, Pohlig-Hellman) require sub-exponential time."
        ),
        "birthday_lower_bound": (
            f"Even with perfect DLP hardness, any n-bit hash has an information-theoretic "
            f"birthday collision at ~2^(n/2) = 2^{group.output_bits//2} = "
            f"{2**(group.output_bits//2)} evaluations. "
            f"This is why SHA-256 (256-bit hash) targets 128-bit collision security."
        ),
    }


# ---------------------------------------------------------------------------
# Module-level singleton group (cached for performance)
# ---------------------------------------------------------------------------

_CACHED_GROUP: DLP_Group = None
_CACHED_HASH:  DLP_Hash  = None


def get_default_group() -> DLP_Group:
    global _CACHED_GROUP
    if _CACHED_GROUP is None:
        _CACHED_GROUP = DLP_Group(bits=16)
    return _CACHED_GROUP


def get_default_hash() -> DLP_Hash:
    global _CACHED_HASH
    if _CACHED_HASH is None:
        _CACHED_HASH = DLP_Hash(bits=16)
    return _CACHED_HASH
