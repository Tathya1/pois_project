"""
Tests for PA#12 — Textbook RSA + PKCS#1 v1.5

Run with:  pytest test_pa12.py -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../PA13"))

from rsa    import RSA, mod_exp, extended_gcd, mod_inverse
from pkcs15 import pkcs15_pad, pkcs15_unpad
import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rsa256():
    """256-bit RSA keys — fast enough for a test suite."""
    return RSA().keygen(bits=256)


@pytest.fixture(scope="module")
def rsa512():
    """512-bit RSA keys — standard toy size."""
    return RSA().keygen(bits=512)


# ---------------------------------------------------------------------------
# mod_exp
# ---------------------------------------------------------------------------

class TestModExp:
    def test_basic(self):
        assert mod_exp(2, 10, 1000) == 24

    def test_exp_zero(self):
        assert mod_exp(7, 0, 100) == 1

    def test_exp_one(self):
        assert mod_exp(7, 1, 100) == 7

    def test_base_zero(self):
        assert mod_exp(0, 5, 13) == 0

    def test_mod_one(self):
        assert mod_exp(999, 999, 1) == 0

    def test_fermat(self):
        """a^(p-1) ≡ 1 (mod p) for prime p."""
        for p in [7, 11, 13, 97, 1009]:
            assert mod_exp(2, p - 1, p) == 1, f"Fermat failed for p={p}"

    def test_rsa_roundtrip_property(self):
        """m^(e*d) ≡ m (mod N) for RSA parameters."""
        # Small toy example
        p, q = 61, 53
        N = p * q
        e = 17
        d = mod_inverse(e, (p - 1) * (q - 1))
        for m in [2, 5, 42, 100]:
            c = mod_exp(m, e, N)
            assert mod_exp(c, d, N) == m


# ---------------------------------------------------------------------------
# extended_gcd
# ---------------------------------------------------------------------------

class TestExtendedGCD:
    def test_basic(self):
        g, x, y = extended_gcd(35, 15)
        assert g == 5
        assert 35 * x + 15 * y == g

    def test_coprime(self):
        g, x, y = extended_gcd(17, 13)
        assert g == 1
        assert 17 * x + 13 * y == 1

    def test_one_zero(self):
        g, x, y = extended_gcd(7, 0)
        assert g == 7

    def test_large(self):
        a = 65537
        b = (2 ** 256 - 429)           # a large even-ish number
        g, x, y = extended_gcd(a, b)
        assert a * x + b * y == g


# ---------------------------------------------------------------------------
# mod_inverse
# ---------------------------------------------------------------------------

class TestModInverse:
    def test_basic(self):
        inv = mod_inverse(3, 7)
        assert (3 * inv) % 7 == 1

    def test_e_phi(self):
        """d = e^(-1) mod phi — the RSA private key relationship."""
        e   = 65537
        phi = (61 - 1) * (53 - 1)
        d   = mod_inverse(e, phi)
        assert (e * d) % phi == 1

    def test_no_inverse(self):
        """gcd(4, 8) = 4 != 1, so no inverse exists."""
        with pytest.raises(ValueError):
            mod_inverse(4, 8)

    def test_result_in_range(self):
        for a, n in [(3, 7), (5, 11), (7, 13)]:
            inv = mod_inverse(a, n)
            assert 0 <= inv < n


# ---------------------------------------------------------------------------
# RSA textbook encrypt / decrypt
# ---------------------------------------------------------------------------

class TestRSATextbook:
    def test_roundtrip(self, rsa256):
        rsa = RSA()
        for m in [1, 2, 42, 1000, 65537]:
            c  = rsa.encrypt(rsa256["N"], rsa256["e"], m)
            m2 = rsa.decrypt(rsa256["N"], rsa256["d"], c)
            assert m2 == m, f"Roundtrip failed for m={m}"

    def test_deterministic(self, rsa256):
        """Textbook RSA is deterministic: same m → same c (insecure!)."""
        rsa = RSA()
        c1 = rsa.encrypt(rsa256["N"], rsa256["e"], 42)
        c2 = rsa.encrypt(rsa256["N"], rsa256["e"], 42)
        assert c1 == c2, "Textbook RSA must be deterministic"

    def test_different_messages_different_ciphertexts(self, rsa256):
        rsa = RSA()
        c1 = rsa.encrypt(rsa256["N"], rsa256["e"], 1)
        c2 = rsa.encrypt(rsa256["N"], rsa256["e"], 2)
        assert c1 != c2

    def test_message_too_large_raises(self, rsa256):
        rsa = RSA()
        with pytest.raises(ValueError):
            rsa.encrypt(rsa256["N"], rsa256["e"], rsa256["N"])

    def test_message_zero(self, rsa256):
        rsa = RSA()
        c = rsa.encrypt(rsa256["N"], rsa256["e"], 0)
        m = rsa.decrypt(rsa256["N"], rsa256["d"], c)
        assert m == 0

    def test_100_random_roundtrips(self, rsa256):
        """100 random messages: encrypt then decrypt must recover original."""
        import secrets as sec
        rsa = RSA()
        N   = rsa256["N"]
        for _ in range(100):
            m  = sec.randbelow(N - 1) + 1
            c  = rsa.encrypt(N, rsa256["e"], m)
            m2 = rsa.decrypt(N, rsa256["d"], c)
            assert m2 == m


# ---------------------------------------------------------------------------
# Garner's CRT decryption
# ---------------------------------------------------------------------------

class TestGarnerCRT:
    def test_crt_equals_standard(self, rsa256):
        """decrypt_crt must return the same result as standard decrypt."""
        rsa = RSA()
        k   = rsa256
        for m in [1, 2, 42, 1000, 65537]:
            c     = rsa.encrypt(k["N"], k["e"], m)
            m_std = rsa.decrypt(k["N"], k["d"], c)
            m_crt = rsa.decrypt_crt(k["p"], k["q"], k["dp"], k["dq"], k["q_inv"], c)
            assert m_std == m_crt == m

    def test_crt_100_random(self, rsa256):
        """100 random ciphertexts: CRT and standard must agree."""
        import secrets as sec
        rsa = RSA()
        k   = rsa256
        for _ in range(100):
            m     = sec.randbelow(k["N"] - 1) + 1
            c     = rsa.encrypt(k["N"], k["e"], m)
            m_std = rsa.decrypt(k["N"], k["d"], c)
            m_crt = rsa.decrypt_crt(k["p"], k["q"], k["dp"], k["dq"], k["q_inv"], c)
            assert m_std == m_crt


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 padding
# ---------------------------------------------------------------------------

class TestPKCS15:
    def test_roundtrip(self):
        """pad then unpad must recover the original message."""
        for msg in [b"hello", b"A" * 10, b"\x00\x01\x02", b""]:
            k  = 64
            em = pkcs15_pad(msg, k)
            assert pkcs15_unpad(em) == msg

    def test_padded_length_equals_k(self):
        for k in [32, 64, 128]:
            em = pkcs15_pad(b"test", k)
            assert len(em) == k

    def test_structure(self):
        """EM[0] == 0x00, EM[1] == 0x02, separator 0x00 exists."""
        em = pkcs15_pad(b"test", 32)
        assert em[0] == 0x00
        assert em[1] == 0x02
        assert b"\x00" in em[2:]

    def test_ps_min_length(self):
        """PS must be at least 8 bytes."""
        k   = 32
        msg = b"hello"
        em  = pkcs15_pad(msg, k)
        sep = em.find(b"\x00", 2)
        assert sep - 2 >= 8

    def test_ps_nonzero(self):
        """All PS bytes must be nonzero."""
        for _ in range(10):
            em  = pkcs15_pad(b"x", 64)
            sep = em.find(b"\x00", 2)
            ps  = em[2:sep]
            assert all(b != 0 for b in ps)

    def test_randomness(self):
        """Two paddings of the same message should differ (random PS)."""
        em1 = pkcs15_pad(b"hello", 64)
        em2 = pkcs15_pad(b"hello", 64)
        assert em1 != em2

    def test_message_too_long(self):
        with pytest.raises(ValueError):
            pkcs15_pad(b"A" * 100, 64)       # 100 > 64 - 11 = 53

    def test_unpad_wrong_first_byte(self):
        bad = bytes([0x01, 0x02] + [0x05] * 8 + [0x00, 0x41])
        with pytest.raises(ValueError, match="0x00"):
            pkcs15_unpad(bad)

    def test_unpad_wrong_block_type(self):
        bad = bytes([0x00, 0x01] + [0x05] * 8 + [0x00, 0x41])
        with pytest.raises(ValueError, match="0x02"):
            pkcs15_unpad(bad)

    def test_unpad_ps_too_short(self):
        # Only 3 PS bytes, needs >= 8
        bad = bytes([0x00, 0x02, 0x01, 0x02, 0x03, 0x00, 0x41])
        with pytest.raises(ValueError, match="too short"):
            pkcs15_unpad(bad)

    def test_unpad_too_short_overall(self):
        with pytest.raises(ValueError):
            pkcs15_unpad(b"\x00\x02\x01")

    def test_full_rsa_pkcs15_roundtrip(self, rsa256):
        """Pad message, encrypt, decrypt, unpad — must recover original."""
        rsa = RSA()
        k   = _modulus_bytes(rsa256["N"])
        msg = b"Hello RSA PKCS15"

        em    = pkcs15_pad(msg, k)
        c     = rsa.encrypt(rsa256["N"], rsa256["e"], int.from_bytes(em, "big"))
        m_int = rsa.decrypt(rsa256["N"], rsa256["d"], c)
        em2   = m_int.to_bytes(k, "big")
        assert pkcs15_unpad(em2) == msg


def _modulus_bytes(N: int) -> int:
    return (N.bit_length() + 7) // 8
