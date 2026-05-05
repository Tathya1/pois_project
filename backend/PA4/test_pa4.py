import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from modes import MODES, BLOCK_BYTES


def _roundtrip(mode: str, key: str, message: bytes):
    enc = MODES.encrypt(mode, key, message)
    cipher = bytes.fromhex(enc["ciphertext"])

    if mode == "CBC":
        recovered = MODES.decrypt(mode, key, cipher, iv=bytes.fromhex(enc["iv"]))
    elif mode == "OFB":
        recovered = MODES.decrypt(mode, key, cipher, iv=bytes.fromhex(enc["iv"]))
    elif mode == "CTR":
        recovered = MODES.decrypt(mode, key, cipher, nonce=bytes.fromhex(enc["nonce"]))
    else:
        raise ValueError("Unsupported mode")

    return recovered


def test_correctness_cbc_lengths():
    key = "1a2b3c4d"

    msgs = [
        b"abc",  # shorter than one block
        b"ABCDEFGH",  # exactly one block
        b"this message spans many blocks for cbc mode",  # multi-block
    ]

    for m in msgs:
        assert _roundtrip("CBC", key, m) == m


def test_correctness_ofb_lengths_and_same_operation():
    key = "1a2b3c4d"

    msgs = [
        b"xy",
        b"12345678",
        b"ofb mode over several blocks of data",
    ]

    for m in msgs:
        enc = MODES.ofb_encrypt(key, m)
        d1 = MODES.ofb_decrypt(key, enc.iv, enc.ciphertext)
        d2 = MODES.ofb_encrypt(key, enc.ciphertext, iv=enc.iv).ciphertext

        assert d1 == m
        assert d2 == m  # encrypt == decrypt operation in OFB


def test_correctness_ctr_lengths():
    key = "1a2b3c4d"

    msgs = [
        b"q",
        b"87654321",
        b"ctr mode supports parallelizable block computations",
    ]

    for m in msgs:
        assert _roundtrip("CTR", key, m) == m


def test_ofb_keystream_precomputation():
    key = "1a2b3c4d"
    iv = bytes.fromhex("0011223344556677")
    m = b"precompute-ofb-keystream"

    ks = MODES._ofb_stream(key, iv, len(m))
    c = bytes(a ^ b for a, b in zip(m, ks))

    recovered = MODES.ofb_decrypt(key, iv, c)
    assert recovered == m


def test_ctr_parallel_block_independence_demo_shape():
    trace = MODES.trace_three_blocks("CTR", "1a2b3c4d", b"A" * (3 * BLOCK_BYTES))

    assert trace["mode"] == "CTR"
    assert len(trace["blocks"]) == 3
    assert all(b.get("parallelizable") for b in trace["blocks"])


def test_cbc_iv_reuse_attack_demo():
    key = "1a2b3c4d"

    # Same first block and same IV -> first ciphertext block matches.
    m1 = b"SAMEBLK1" + b"DIFFBLK2" + b"ZZZZZZZZ"
    m2 = b"SAMEBLK1" + b"OTHERBLK" + b"YYYYYYYY"

    demo = MODES.cbc_iv_reuse_demo(key, m1, m2)

    assert 0 in demo["matchingPlainBlocks"]
    assert 0 in demo["matchingCipherBlocks"]


def test_ofb_keystream_reuse_attack_demo():
    key = "1a2b3c4d"
    m1 = b"attack at dawn"
    m2 = b"attack at dusk"

    demo = MODES.ofb_keystream_reuse_demo(key, m1, m2)

    assert demo["xorsMatch"] is True
    assert demo["cipherXor"] == demo["plainXor"]


def test_flip_bit_error_propagation_patterns():
    key = "1a2b3c4d"
    m = b"BLOCK001BLOCK002BLOCK003"

    cbc = MODES.flip_bit_demo("CBC", key, m, block_index=0, bit_index=0)
    ofb = MODES.flip_bit_demo("OFB", key, m, block_index=1, bit_index=0)
    ctr = MODES.flip_bit_demo("CTR", key, m, block_index=2, bit_index=0)

    assert cbc["corruptedPlaintextBlocks"] == [0, 1]
    assert ofb["corruptedPlaintextBlocks"] == [1]
    assert ctr["corruptedPlaintextBlocks"] == [2]


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__]))
