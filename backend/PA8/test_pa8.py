"""
PA8/test_pa8.py — Comprehensive tests for DLP-based CRHF.
Run from: backend/PA8/
"""
import os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PA7  = os.path.join(_HERE, "..", "PA7")
for _p in [_HERE, _PA7]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dlp_hash import (
    is_prime, find_safe_prime_pair,
    DLP_Group, DLP_Hash,
    birthday_attack, collision_resistance_argument,
)


def test_primality():
    """Miller-Rabin must correctly identify primes and composites."""
    primes     = [2, 3, 5, 7, 11, 13, 17, 19, 23, 101, 1009, 32749]
    composites = [1, 4, 6, 9, 15, 100, 1001, 32768]

    for p in primes:
        assert is_prime(p), f"{p} should be prime"
    for c in composites:
        assert not is_prime(c), f"{c} should be composite"
    print("[PASS] Miller-Rabin primality test")


def test_safe_prime_pair():
    """find_safe_prime_pair must return (q, p) with p=2q+1, both prime."""
    q, p = find_safe_prime_pair(min_bits=10, max_bits=13)
    assert is_prime(q), f"q={q} should be prime"
    assert is_prime(p), f"p={p} should be prime"
    assert p == 2 * q + 1, f"p must equal 2q+1, got p={p}, q={q}"
    assert q.bit_length() >= 10
    print(f"[PASS] Safe prime pair: q={q} ({q.bit_length()} bits), p={p}")


def test_generator():
    """Generator g must satisfy g^q ≡ 1 (mod p) and g ≠ 1."""
    group = DLP_Group(bits=11)
    assert pow(group.g, group.q, group.p) == 1, "g^q must ≡ 1 mod p"
    assert group.g != 1, "g must not be 1"
    print(f"[PASS] Generator g={group.g} has order q={group.q} in Z*_{group.p}")


def test_compress_in_group():
    """compress(x, y) must be in [1, p-1]."""
    group = DLP_Group(bits=11)
    for _ in range(20):
        import secrets
        x = secrets.randbelow(group.q)
        y = secrets.randbelow(group.q)
        out = group.compress(x, y)
        assert 1 <= out < group.p, f"compress output {out} not in [1, p-1]"
    print("[PASS] compress(x,y) stays in group Z*_p")


def test_compress_determinism():
    """compress must be deterministic."""
    group = DLP_Group(bits=11)
    out1  = group.compress(42, 17)
    out2  = group.compress(42, 17)
    assert out1 == out2
    print("[PASS] compress is deterministic")


def test_compress_different_inputs():
    """Different (x,y) pairs should (almost certainly) produce different compress outputs."""
    group = DLP_Group(bits=11)
    pairs_seen = set()
    for i in range(10):
        out = group.compress(i, i + 1)
        assert out not in pairs_seen, f"Unexpected collision at ({i}, {i+1})"
        pairs_seen.add(out)
    print("[PASS] compress produces distinct outputs for distinct inputs")


def test_dlp_hash_determinism():
    """DLP_Hash must be deterministic for the same message."""
    dlp = DLP_Hash(bits=11)
    msg = b"determinism test"
    assert dlp.hash_hex(msg) == dlp.hash_hex(msg)
    print("[PASS] DLP_Hash is deterministic")


def test_dlp_hash_size():
    """DLP_Hash output must be exactly HASH_SIZE bytes."""
    dlp = DLP_Hash(bits=11)
    for size in [0, 1, 8, 16, 100]:
        h = dlp.hash(b'A' * size)
        assert len(h) == dlp.HASH_SIZE, f"Hash size wrong for input len {size}"
    print(f"[PASS] DLP_Hash output always {DLP_Hash.HASH_SIZE} bytes")


def test_dlp_hash_avalanche():
    """One-bit change in message must change the hash."""
    dlp = DLP_Hash(bits=11)
    msg  = bytearray(b"avalanche test message for pa8")
    h1   = dlp.hash_hex(bytes(msg))
    msg[0] ^= 0x01
    h2   = dlp.hash_hex(bytes(msg))
    assert h1 != h2, "One-bit change must change hash (avalanche)"
    print(f"[PASS] DLP avalanche: {h1[:8]}… → {h2[:8]}…")


def test_dlp_hash_integration_distinct_lengths():
    """Hash five messages of different lengths and ensure distinct digests."""
    dlp = DLP_Hash(bits=16)
    messages = [
        b"",
        b"a",
        b"abc",
        b"message of length 17",
        b"longer message with more bytes for PA8 integration test",
    ]
    digests = [dlp.hash_hex(m) for m in messages]
    assert len(set(digests)) == len(messages), "Distinct inputs should yield distinct digests"
    print("[PASS] Integration: 5 distinct messages produced distinct digests")


def test_birthday_attack():
    """Birthday attack must find a collision within expected evaluations."""
    group  = DLP_Group(bits=12)   # small group for speed
    result = birthday_attack(group, max_evaluations=20_000)

    assert result["success"], f"Birthday attack failed: {result.get('explanation')}"
    expected = 2 ** (group.output_bits // 2)
    # Allow up to 10x the expected (unlikely to fail due to randomness)
    assert result["evaluations"] <= 10 * expected, (
        f"Too many evaluations: {result['evaluations']} vs expected {expected}"
    )

    # Verify the collision is genuine
    x1, y1 = result["collision"]["x1"], result["collision"]["y1"]
    x2, y2 = result["collision"]["x2"], result["collision"]["y2"]
    assert (x1, y1) != (x2, y2), "Collision inputs must differ"
    assert group.compress_truncated(x1, y1) == group.compress_truncated(x2, y2), (
        "Collision must produce same truncated output"
    )
    print(f"[PASS] Birthday attack: found collision in {result['evaluations']} "
          f"(expected ≈ {expected})")


def test_dlog_extraction_from_collision():
    """After birthday collision, extracted α must satisfy g^α = h."""
    group  = DLP_Group(bits=11)
    result = birthday_attack(group, max_evaluations=10_000)

    if not result["success"]:
        print("[SKIP] Birthday attack did not find collision — skipping dlog test")
        return

    dlog = result["dlog_extraction"]
    if dlog["success"]:
        assert dlog["h_from_alpha"] == dlog["h_original"], (
            "Recovered α must satisfy g^α = h"
        )
        print(f"[PASS] dlog extraction: α={dlog['alpha_recovered']}, h=g^α verified")
    else:
        print("[INFO] dlog extraction skipped (y1=y2 edge case)")


def test_security_argument_structure():
    """Collision resistance argument must have all expected fields."""
    group  = DLP_Group(bits=11)
    arg    = collision_resistance_argument(group)
    assert "claim" in arg
    assert "proof_steps" in arg
    assert len(arg["proof_steps"]) == 7
    assert arg["proof_steps"][-1]["step"] == 7
    print("[PASS] Security argument structure correct (7 steps)")


if __name__ == "__main__":
    print("=== PA#8 Test Suite ===\n")
    test_primality()
    test_safe_prime_pair()
    test_generator()
    test_compress_in_group()
    test_compress_determinism()
    test_compress_different_inputs()
    test_dlp_hash_determinism()
    test_dlp_hash_size()
    test_dlp_hash_avalanche()
    test_dlp_hash_integration_distinct_lengths()
    test_birthday_attack()
    test_dlog_extraction_from_collision()
    test_security_argument_structure()
    print("\n=== ALL PA#8 TESTS PASSED ===")
