"""
Tests for PA#13 — Miller-Rabin Primality Testing

Run with:  pytest test_pa13.py -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from miller_rabin import mod_exp, miller_rabin, is_prime, gen_prime, gen_safe_prime
import pytest


# ---------------------------------------------------------------------------
# Known primes and composites for ground-truth testing
# ---------------------------------------------------------------------------

KNOWN_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    97, 101, 1009, 7919,
    2147483647,   # 2^31 - 1  (Mersenne prime)
    999999999989, # 12-digit prime
]

KNOWN_COMPOSITES = [
    0, 1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 100, 1000,
    561,          # smallest Carmichael number: 3 × 11 × 17
    1105,         # Carmichael: 5 × 13 × 17
    1729,         # Carmichael: 7 × 13 × 19  (Hardy-Ramanujan number)
    999999999990,
]


# ---------------------------------------------------------------------------
# mod_exp
# ---------------------------------------------------------------------------

class TestModExp:
    def test_basic_cases(self):
        assert mod_exp(2, 10, 1000) == 24
        assert mod_exp(3, 0, 100) == 1       # anything^0 = 1
        assert mod_exp(5, 1, 13) == 5        # anything^1 = itself
        assert mod_exp(0, 5, 7) == 0         # 0^n = 0

    def test_mod_one(self):
        assert mod_exp(999, 999, 1) == 0     # anything mod 1 = 0

    def test_fermat_small_prime(self):
        """Fermat's little theorem: a^(p-1) ≡ 1 (mod p) for prime p."""
        for p in [7, 11, 13, 97]:
            assert mod_exp(2, p - 1, p) == 1, f"Fermat failed for p={p}"

    def test_mersenne_prime(self):
        """2^(2^31-2) ≡ 1 (mod 2^31-1) — large modular exponentiation."""
        p = 2147483647
        assert mod_exp(2, p - 1, p) == 1


# ---------------------------------------------------------------------------
# miller_rabin
# ---------------------------------------------------------------------------

class TestMillerRabin:
    def test_known_primes(self):
        for p in KNOWN_PRIMES:
            assert miller_rabin(p, k=20) is True, f"{p} should be PRIME"

    def test_known_composites(self):
        for c in KNOWN_COMPOSITES:
            assert miller_rabin(c, k=20) is False, f"{c} should be COMPOSITE"

    def test_carmichael_561(self):
        """561 fools the Fermat test but Miller-Rabin must reject it."""
        # Confirm Fermat passes
        assert mod_exp(2, 560, 561) == 1, "Fermat test should pass for 561"
        # Confirm Miller-Rabin rejects
        assert miller_rabin(561, k=40) is False, "Miller-Rabin must reject 561"

    def test_edge_cases(self):
        assert miller_rabin(0) is False
        assert miller_rabin(1) is False
        assert miller_rabin(2) is True
        assert miller_rabin(3) is True
        assert miller_rabin(4) is False

    def test_even_numbers(self):
        for n in [6, 8, 100, 1024, 65536]:
            assert miller_rabin(n) is False, f"{n} is even and composite"

    def test_is_prime_wrapper(self):
        assert is_prime(7) is True
        assert is_prime(9) is False


# ---------------------------------------------------------------------------
# gen_prime
# ---------------------------------------------------------------------------

class TestGenPrime:
    @pytest.mark.parametrize("bits", [16, 32, 64])
    def test_output_is_prime(self, bits):
        p = gen_prime(bits, k=40)
        assert miller_rabin(p, k=100), f"gen_prime({bits}) returned non-prime {p}"

    @pytest.mark.parametrize("bits", [16, 32, 64])
    def test_exact_bit_length(self, bits):
        p = gen_prime(bits, k=40)
        assert p.bit_length() == bits, (
            f"Expected {bits} bits, got {p.bit_length()} for p={p}"
        )

    def test_output_is_odd(self):
        for _ in range(5):
            p = gen_prime(32)
            assert p % 2 == 1, f"gen_prime returned even number {p}"

    def test_invalid_bits(self):
        with pytest.raises(ValueError):
            gen_prime(1)


# ---------------------------------------------------------------------------
# gen_safe_prime
# ---------------------------------------------------------------------------

class TestGenSafePrime:
    def test_safe_prime_structure(self):
        """p = 2q + 1 must hold and both p and q must be prime."""
        p, q = gen_safe_prime(32)
        assert p == 2 * q + 1, "Safe prime structure p=2q+1 violated"
        assert miller_rabin(p, k=40), "p must be (probably) prime"
        assert miller_rabin(q, k=40), "q must be (probably) prime"

    def test_returns_tuple(self):
        result = gen_safe_prime(24)
        assert isinstance(result, tuple) and len(result) == 2
