"""
PA7/test_pa7.py — Comprehensive tests for Merkle-Damgård transform.
Run from: backend/PA7/
"""
import os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from merkle_damgard import (
    MerkleDamgard, xor_compress, rotate_add_compress,
    HASH_SIZE, BLOCK_SIZE, IV_DEFAULT,
    xor_compress_construct_collision, collision_propagation_demo,
)


def test_padding_length():
    """Padded message must always be a multiple of block_size."""
    md = MerkleDamgard(xor_compress)
    for size in [0, 1, 7, 8, 15, 16, 17, 24, 100, 128, 255]:
        msg    = b'A' * size
        padded = md.pad(msg)
        assert len(padded) % BLOCK_SIZE == 0, f"Padding failed for size {size}"
    print("[PASS] Padding always yields multiple of block_size")


def test_padding_length_field():
    """Last 8 bytes of padded message must be the original bit-length."""
    md = MerkleDamgard(xor_compress)
    for size in [0, 7, 16, 100]:
        msg    = b'X' * size
        padded = md.pad(msg)
        encoded_len = int.from_bytes(padded[-8:], 'big')
        assert encoded_len == size * 8, f"Length field wrong for size={size}"
    print("[PASS] Padding length field encodes original bit-length correctly")


def test_determinism():
    """Same message must always produce same hash."""
    for fn in [xor_compress, rotate_add_compress]:
        md = MerkleDamgard(fn)
        msg = b"deterministic test message"
        h1  = md.hash_hex(msg)
        h2  = md.hash_hex(msg)
        assert h1 == h2, f"Non-deterministic hash for {fn.__name__}"
    print("[PASS] Hashing is deterministic")


def test_different_messages_different_hashes():
    """Different messages (same length) should (almost certainly) have different hashes."""
    for fn in [xor_compress, rotate_add_compress]:
        md = MerkleDamgard(fn)
        h1 = md.hash_hex(b"message one")
        h2 = md.hash_hex(b"message two")
        assert h1 != h2, f"Collision on distinct messages with {fn.__name__}"
    print("[PASS] Distinct messages produce distinct hashes")


def test_hash_size():
    """Output must always be exactly HASH_SIZE bytes."""
    md = MerkleDamgard(xor_compress)
    for size in [0, 1, 16, 100]:
        h = md.hash(b'Z' * size)
        assert len(h) == HASH_SIZE, f"Hash size wrong for input len {size}"
    print(f"[PASS] Hash output is always {HASH_SIZE} bytes")


def test_trace_chain_length():
    """chain must have n_blocks+1 entries (IV + one per block)."""
    md = MerkleDamgard(xor_compress)
    for size in [0, 5, 15, 16, 32]:
        result = md.trace(b'A' * size)
        assert len(result["chain"]) == result["n_blocks"] + 1, (
            f"Chain length mismatch for msg size {size}"
        )
        assert result["chain"][0] == IV_DEFAULT.hex(), "Chain[0] must be IV"
        assert result["chain"][-1] == result["digest"], "Last chain entry must be digest"
    print("[PASS] Trace chain has correct length and starts with IV")


def test_trace_digest_matches_hash():
    """trace()['digest'] must match hash()."""
    md = MerkleDamgard(rotate_add_compress)
    msg = b"trace consistency check"
    h   = md.hash_hex(msg)
    t   = md.trace(msg)
    assert t["digest"] == h, "trace digest != hash"
    print("[PASS] trace() digest matches hash()")


def test_xor_compress_known_collision():
    """B1 ≠ B2 but xor_compress(IV, B1) = xor_compress(IV, B2)."""
    b1, b2 = xor_compress_construct_collision(BLOCK_SIZE)
    assert b1 != b2, "Collision blocks must differ"
    out1 = xor_compress(IV_DEFAULT, b1)
    out2 = xor_compress(IV_DEFAULT, b2)
    assert out1 == out2, "Compress did not collide on known collision pair"
    print(f"[PASS] XOR compress collision: out={out1.hex()}, B1≠B2")


def test_xor_compress_equal_iv():
    """Both colliding blocks should produce the chaining value = IV."""
    b1, b2 = xor_compress_construct_collision(BLOCK_SIZE)
    out = xor_compress(IV_DEFAULT, b1)
    assert out == IV_DEFAULT, f"Expected IV={IV_DEFAULT.hex()}, got {out.hex()}"
    print("[PASS] XOR compress collision: both give back IV (fold=0)")


def test_collision_propagation():
    """Full MD collision: H(B1‖S) = H(B2‖S) when compress(IV,B1)=compress(IV,B2)."""
    result = collision_propagation_demo(compress_fn_name="xor")
    assert result["found"], "Collision demo should always find a collision (XOR)"
    assert result["compress_collision"]["compress_collides"], "Compress must collide"
    assert not result["compress_collision"]["blocks_equal"], "Blocks must differ"
    assert result["full_collision"], "Full MD collision must hold"
    print("[PASS] Collision propagation: H(B1‖S) = H(B2‖S)")


def test_avalanche_effect():
    """One-bit change in message should (almost certainly) change the hash."""
    md  = MerkleDamgard(rotate_add_compress)
    msg = b"avalanche test message"
    h1  = md.hash_hex(msg)
    msg2 = bytearray(msg)
    msg2[0] ^= 0x01
    h2  = md.hash_hex(bytes(msg2))
    assert h1 != h2, "One-bit change should change hash (avalanche)"
    print(f"[PASS] Avalanche: flipping one bit changes hash ({h1[:8]}→{h2[:8]})")


if __name__ == "__main__":
    print("=== PA#7 Test Suite ===\n")
    test_padding_length()
    test_padding_length_field()
    test_determinism()
    test_different_messages_different_hashes()
    test_hash_size()
    test_trace_chain_length()
    test_trace_digest_matches_hash()
    test_xor_compress_known_collision()
    test_xor_compress_equal_iv()
    test_collision_propagation()
    test_avalanche_effect()
    print("\n=== ALL PA#7 TESTS PASSED ===")
