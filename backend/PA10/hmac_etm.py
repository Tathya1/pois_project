from __future__ import annotations

import hashlib
import os
import secrets
import string
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA8"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA7"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA6"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA3"))

from cca import CCA
from cpa import CPA
from dlp_hash import DLP_Hash
from merkle_damgard import MerkleDamgard


class SHA256PlaceholderHash:
    """
    Placeholder MD-style hash using SHA-256 as a compression primitive.

    This is intentionally educational: it keeps Merkle-Damgard structure explicit
    so length-extension behavior can be demonstrated side-by-side with the PA8 DLP hash.
    """

    BLOCK_SIZE = 64
    HASH_SIZE = 32

    def __init__(self):
        self._md = MerkleDamgard(
            compress_fn=self._compress,
            iv=b"\x00" * self.HASH_SIZE,
            block_size=self.BLOCK_SIZE,
        )

    @staticmethod
    def _compress(cv: bytes, block: bytes) -> bytes:
        return hashlib.sha256(cv + block).digest()

    def hash(self, message: bytes) -> bytes:
        return self._md.hash(message)

    def pad(self, message: bytes) -> bytes:
        return self._md.pad(message)

    def compress(self, cv: bytes, block: bytes) -> bytes:
        return self._md.compress_fn(cv, block)


_DLP_HASH_SINGLETON = DLP_Hash()


class DLPHashAdapter:
    BLOCK_SIZE = DLP_Hash.BLOCK_SIZE
    HASH_SIZE = DLP_Hash.HASH_SIZE

    def __init__(self, impl=None):
        self._impl = impl or _DLP_HASH_SINGLETON

    def hash(self, message: bytes) -> bytes:
        return self._impl.hash(message)

    def pad(self, message: bytes) -> bytes:
        return self._impl._md.pad(message)

    def compress(self, cv: bytes, block: bytes) -> bytes:
        return self._impl._md.compress_fn(cv, block)


def get_hash_impl(hash_type: str = "dlp"):
    htype = (hash_type or "dlp").strip().lower()
    if htype in {"dlp", "pa8"}:
        return DLPHashAdapter()
    if htype in {"sha256", "sha-256", "placeholder-sha256"}:
        return SHA256PlaceholderHash()
    raise ValueError("Unsupported hashType. Use one of: dlp, sha256")


def message_to_bytes(data: bytes | str) -> bytes:
    if isinstance(data, bytes):
        return data
    return str(data).encode("utf-8")


def key_to_bytes(key: bytes | str | int) -> bytes:
    if isinstance(key, bytes):
        return key

    if isinstance(key, int):
        size = max(1, (key.bit_length() + 7) // 8)
        return key.to_bytes(size, "big")

    text = str(key).strip()
    no_prefix = text[2:] if text.startswith("0x") else text

    if no_prefix and len(no_prefix) % 2 == 0 and all(ch in string.hexdigits for ch in no_prefix):
        return bytes.fromhex(no_prefix)

    return text.encode("utf-8")


def secure_compare(left: bytes, right: bytes) -> bool:
    max_len = max(len(left), len(right))
    diff = len(left) ^ len(right)

    for i in range(max_len):
        a = left[i] if i < len(left) else 0
        b = right[i] if i < len(right) else 0
        diff |= a ^ b

    return diff == 0


def naive_compare(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False

    for i in range(len(left)):
        if left[i] != right[i]:
            return False

    return True


class DLPHMAC:
    def __init__(self, hash_impl=None):
        self.hash = hash_impl or get_hash_impl("dlp")
        self.block_size = self.hash.BLOCK_SIZE
        self.tag_bytes = self.hash.HASH_SIZE
        self.tag_bits = self.tag_bytes * 8

    def _normalize_key(self, key: bytes) -> bytes:
        normalized = key
        if len(normalized) > self.block_size:
            normalized = self.hash.hash(normalized)

        if len(normalized) < self.block_size:
            normalized = normalized + (b"\x00" * (self.block_size - len(normalized)))

        return normalized

    def sign(self, key: bytes | str | int, message: bytes | str) -> bytes:
        key_b = self._normalize_key(key_to_bytes(key))
        msg_b = message_to_bytes(message)

        inner_key = bytes((b ^ 0x36) for b in key_b)
        outer_key = bytes((b ^ 0x5C) for b in key_b)

        inner = self.hash.hash(inner_key + msg_b)
        return self.hash.hash(outer_key + inner)

    def verify(self, key: bytes | str | int, message: bytes | str, tag: bytes) -> bool:
        expected = self.sign(key, message)
        return secure_compare(expected, tag)


class NaiveKeyedHash:
    def __init__(self, hash_impl=None):
        self.hash = hash_impl or get_hash_impl("dlp")
        self.tag_bytes = self.hash.HASH_SIZE
        self.tag_bits = self.tag_bytes * 8

    def sign(self, key: bytes | str | int, message: bytes | str) -> bytes:
        key_b = key_to_bytes(key)
        msg_b = message_to_bytes(message)
        return self.hash.hash(key_b + msg_b)

    def verify(self, key: bytes | str | int, message: bytes | str, tag: bytes) -> bool:
        expected = self.sign(key, message)
        return secure_compare(expected, tag)


def forge_length_extension(
    hash_impl,
    message: bytes | str,
    original_tag: bytes,
    suffix: bytes | str,
    guessed_key_len: int,
) -> dict:
    if len(original_tag) != hash_impl.HASH_SIZE:
        raise ValueError("original_tag must be full-length digest")

    msg_b = message_to_bytes(message)
    suffix_b = message_to_bytes(suffix)

    fake_prefixed = (b"A" * guessed_key_len) + msg_b
    padded_fake = hash_impl.pad(fake_prefixed)
    glue = padded_fake[len(fake_prefixed):]

    forged_message = msg_b + glue + suffix_b

    total_forged = fake_prefixed + glue + suffix_b
    total_padded = hash_impl.pad(total_forged)

    remaining_data = total_padded[len(padded_fake):]

    cv = original_tag
    for i in range(0, len(remaining_data), hash_impl.BLOCK_SIZE):
        block = remaining_data[i:i + hash_impl.BLOCK_SIZE]
        cv = hash_impl.compress(cv, block)

    forged_tag = cv

    return {
        "forgedMessage": forged_message,
        "forgedTag": forged_tag,
        "gluePadding": glue,
        "assumedKeyLen": guessed_key_len,
    }


class EncryptThenHMAC:
    def __init__(self, hmac_impl: DLPHMAC | None = None, hash_type: str = "dlp"):
        self.hmac = hmac_impl or DLPHMAC(hash_impl=get_hash_impl(hash_type))

    @staticmethod
    def _packet_bytes(r_hex: str, c_hex: str) -> bytes:
        return bytes.fromhex(r_hex + c_hex)

    def encrypt(self, key_e, key_m, message: str) -> dict:
        r_hex, c_hex = CPA.enc_text(key_e, message)
        tag = self.hmac.sign(key_m, self._packet_bytes(r_hex, c_hex)).hex()
        return {
            "r": r_hex,
            "c": c_hex,
            "tag": tag,
            "tagBytes": self.hmac.tag_bytes,
        }

    def decrypt(self, key_e, key_m, r_hex: str, c_hex: str, tag_hex: str) -> str | None:
        packet = self._packet_bytes(r_hex, c_hex)
        tag = bytes.fromhex(tag_hex)

        if not self.hmac.verify(key_m, packet, tag):
            return None

        try:
            return CPA.dec_text(key_e, r_hex, c_hex)
        except Exception:
            return None


def _flip_one_bit(hex_string: str) -> str:
    data = bytearray(bytes.fromhex(hex_string))
    if not data:
        return hex_string
    data[-1] ^= 0x01
    return bytes(data).hex()


def simulate_euf_cma(rounds: int = 20, queries: int = 50, hash_type: str = "dlp") -> dict:
    hmac_impl = DLPHMAC(hash_impl=get_hash_impl(hash_type))
    forge_success = 0

    for _ in range(rounds):
        key = secrets.token_bytes(16)
        queried = set()

        for _ in range(queries):
            msg = secrets.token_bytes(12)
            queried.add(msg)
            hmac_impl.sign(key, msg)

        forged_message = secrets.token_bytes(12)
        while forged_message in queried:
            forged_message = secrets.token_bytes(12)

        forged_tag = secrets.token_bytes(hmac_impl.tag_bytes)
        if hmac_impl.verify(key, forged_message, forged_tag):
            forge_success += 1

    rate = forge_success / rounds if rounds else 0.0
    return {
        "rounds": rounds,
        "oracleQueries": queries,
        "hashType": hash_type,
        "tagBytes": hmac_impl.tag_bytes,
        "forgeSuccess": forge_success,
        "forgeSuccessRate": rate,
    }


def simulate_cca2(rounds: int = 40, hash_type: str = "dlp") -> dict:
    scheme = EncryptThenHMAC(hash_type=hash_type)

    wins = 0
    tamper_rejects = 0
    tamper_total = 0

    for _ in range(rounds):
        key_e = format(secrets.randbits(64), "x")
        key_m = secrets.token_bytes(16)

        m0 = "message0"
        m1 = "message1"

        bit = secrets.randbelow(2)
        challenge = scheme.encrypt(key_e, key_m, m0 if bit == 0 else m1)

        tampered_c = _flip_one_bit(challenge["c"])
        dec_c = scheme.decrypt(key_e, key_m, challenge["r"], tampered_c, challenge["tag"])
        tamper_total += 1
        if dec_c is None:
            tamper_rejects += 1

        tampered_t = _flip_one_bit(challenge["tag"])
        dec_t = scheme.decrypt(key_e, key_m, challenge["r"], challenge["c"], tampered_t)
        tamper_total += 1
        if dec_t is None:
            tamper_rejects += 1

        guess = secrets.randbelow(2)
        if guess == bit:
            wins += 1

    win_rate = wins / rounds if rounds else 0.0
    advantage = abs(win_rate - 0.5) * 2

    return {
        "hashType": hash_type,
        "rounds": rounds,
        "wins": wins,
        "winRate": win_rate,
        "advantage": advantage,
        "tamperRejectRate": (tamper_rejects / tamper_total) if tamper_total else 0.0,
    }


def _simulate_pa6_cca2(rounds: int = 40) -> dict:
    scheme = CCA()

    wins = 0
    tamper_rejects = 0
    tamper_total = 0

    for _ in range(rounds):
        key_e = format(secrets.randbits(64), "x")
        key_m = format(secrets.randbits(64), "x")

        m0 = "message0"
        m1 = "message1"

        bit = secrets.randbelow(2)
        challenge = scheme.enc(key_e, key_m, m0 if bit == 0 else m1)

        tampered_c = _flip_one_bit(challenge["c"])
        dec_c = scheme.dec(key_e, key_m, challenge["r"], tampered_c, challenge["tag"])
        tamper_total += 1
        if dec_c["rejected"]:
            tamper_rejects += 1

        tampered_t = _flip_one_bit(challenge["tag"])
        dec_t = scheme.dec(key_e, key_m, challenge["r"], challenge["c"], tampered_t)
        tamper_total += 1
        if dec_t["rejected"]:
            tamper_rejects += 1

        guess = secrets.randbelow(2)
        if guess == bit:
            wins += 1

    win_rate = wins / rounds if rounds else 0.0
    advantage = abs(win_rate - 0.5) * 2

    return {
        "rounds": rounds,
        "wins": wins,
        "winRate": win_rate,
        "advantage": advantage,
        "tamperRejectRate": (tamper_rejects / tamper_total) if tamper_total else 0.0,
    }


def compare_cca2_with_pa6(rounds: int = 40, hash_type: str = "dlp") -> dict:
    hmac_scheme = EncryptThenHMAC(hash_type=hash_type)
    pa6_scheme = CCA()

    hmac_enc_total = 0
    hmac_dec_total = 0
    pa6_enc_total = 0
    pa6_dec_total = 0

    hmac_tag_bytes = None
    pa6_tag_bytes = None

    for _ in range(rounds):
        key_e = format(secrets.randbits(64), "x")
        key_m = format(secrets.randbits(64), "x")
        message = secrets.token_hex(8)

        start = time.perf_counter_ns()
        enc_h = hmac_scheme.encrypt(key_e, key_m, message)
        hmac_enc_total += time.perf_counter_ns() - start

        start = time.perf_counter_ns()
        hmac_scheme.decrypt(key_e, key_m, enc_h["r"], enc_h["c"], enc_h["tag"])
        hmac_dec_total += time.perf_counter_ns() - start

        start = time.perf_counter_ns()
        enc_p = pa6_scheme.enc(key_e, key_m, message)
        pa6_enc_total += time.perf_counter_ns() - start

        start = time.perf_counter_ns()
        pa6_scheme.dec(key_e, key_m, enc_p["r"], enc_p["c"], enc_p["tag"])
        pa6_dec_total += time.perf_counter_ns() - start

        hmac_tag_bytes = len(enc_h["tag"]) // 2
        pa6_tag_bytes = len(enc_p["tag"]) // 2

    hmac_cca2 = simulate_cca2(rounds=rounds, hash_type=hash_type)
    pa6_cca2 = _simulate_pa6_cca2(rounds=rounds)

    hmac_enc_ms = (hmac_enc_total / rounds) / 1_000_000
    hmac_dec_ms = (hmac_dec_total / rounds) / 1_000_000
    pa6_enc_ms = (pa6_enc_total / rounds) / 1_000_000
    pa6_dec_ms = (pa6_dec_total / rounds) / 1_000_000

    return {
        "rounds": rounds,
        "hmacScheme": {
            **hmac_cca2,
            "tagBytes": hmac_tag_bytes,
            "avgEncryptMs": hmac_enc_ms,
            "avgDecryptMs": hmac_dec_ms,
        },
        "pa6PrfMacScheme": {
            **pa6_cca2,
            "tagBytes": pa6_tag_bytes,
            "avgEncryptMs": pa6_enc_ms,
            "avgDecryptMs": pa6_dec_ms,
        },
        "comparison": {
            "tagSizeDeltaBytes": (hmac_tag_bytes - pa6_tag_bytes) if hmac_tag_bytes is not None and pa6_tag_bytes is not None else None,
            "encryptCostRatioHmacToPa6": (hmac_enc_ms / pa6_enc_ms) if pa6_enc_ms else None,
            "decryptCostRatioHmacToPa6": (hmac_dec_ms / pa6_dec_ms) if pa6_dec_ms else None,
        },
    }


def timing_leak_demo(iterations: int = 15000) -> dict:
    if iterations <= 0:
        raise ValueError("iterations must be positive")

    hmac_impl = DLPHMAC(hash_impl=get_hash_impl("dlp"))
    key = secrets.token_bytes(16)
    message = b"timing-check"
    tag = hmac_impl.sign(key, message)

    early = bytearray(tag)
    early[0] ^= 0x01

    late = bytearray(tag)
    late[-1] ^= 0x01

    def avg_time(compare_fn, probe: bytes) -> float:
        start = time.perf_counter_ns()
        for _ in range(iterations):
            compare_fn(tag, probe)
        end = time.perf_counter_ns()
        return (end - start) / iterations

    naive_early = avg_time(naive_compare, bytes(early))
    naive_late = avg_time(naive_compare, bytes(late))

    secure_early = avg_time(secure_compare, bytes(early))
    secure_late = avg_time(secure_compare, bytes(late))

    return {
        "iterations": iterations,
        "naiveEarlyNs": naive_early,
        "naiveLateNs": naive_late,
        "secureEarlyNs": secure_early,
        "secureLateNs": secure_late,
        "naiveDeltaNs": naive_late - naive_early,
        "secureDeltaNs": secure_late - secure_early,
    }


class MACHash:
    def __init__(self, public_key: bytes | str = b"public-mac-key", hash_type: str = "dlp"):
        self.hmac = DLPHMAC(hash_impl=get_hash_impl(hash_type))
        self.hash_type = hash_type
        self.public_key = key_to_bytes(public_key)
        self.block_size = self.hmac.block_size
        self.digest_size = self.hmac.tag_bytes

        self._md = MerkleDamgard(
            compress_fn=self._compress,
            iv=b"\x00" * self.digest_size,
            block_size=self.block_size,
        )

    def _compress(self, cv: bytes, block: bytes) -> bytes:
        return self.hmac.sign(self.public_key, cv + block)[: self.digest_size]

    def digest(self, message: bytes | str) -> bytes:
        return self._md.hash(message_to_bytes(message))


def machash_summary(messages: list[str], hash_type: str = "dlp") -> dict:
    mh = MACHash(hash_type=hash_type)
    rows = [{"message": m, "digest": mh.digest(m).hex()} for m in messages]
    distinct = len({r["digest"] for r in rows}) == len(rows)

    proof_steps = [
        "Assume MACHash(M1) = MACHash(M2) for M1 != M2.",
        "In Merkle-Damgard, let i be the first block index where chains differ.",
        "Then compress(CV_i, B_i) = compress(CV'_i, B'_i) with different inputs.",
        "By construction, compress(CV, B) = HMAC_k(CV || B).",
        "So the collision gives equal HMAC tags on two distinct messages (CV || B).",
        "That is an HMAC forgery/collision event, contradicting HMAC security assumptions.",
    ]

    return {
        "hashType": hash_type,
        "allDistinct": distinct,
        "results": rows,
        "compressionDefinition": "h'(cv, block) = HMAC_k(cv || block)",
        "reduction": proof_steps,
        "note": "Finding a collision in MACHash implies breaking the keyed compression behavior of HMAC.",
    }
