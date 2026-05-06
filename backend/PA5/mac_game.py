"""
PA5/mac_game.py
===============
Simulations and Games for PA#5.
Includes the EUF-CMA simulation against a dummy adversary.
"""

import secrets
import random
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SHARED = os.path.join(_HERE, "..", "shared")
_PA7 = os.path.join(_HERE, "..", "PA7")
for _path in (_SHARED, _PA7):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from merkle_damgard import MerkleDamgard, COMPRESS_FNS

def euf_cma_game(mac_class, rounds=20) -> dict:
    """
    Plays the Existential Unforgeability under Chosen-Message Attack (EUF-CMA) game.
    The dummy adversary requests MACs for random messages, then attempts a forgery.
    """
    mac_instance = mac_class()
    key = secrets.randbits(64)
    
    attempts = 0
    successes = 0
    
    for _ in range(rounds):
        # Adversary gets 5 chosen message queries
        queries = []
        for _ in range(5):
            msg = secrets.token_bytes(8)
            tag = mac_instance.mac(key, msg)
            queries.append((msg, tag))
            
        # Adversary attempts a forgery: standard dummy tries to modify one of the queried messages
        msg_forged = queries[0][0][:-1] + bytes([queries[0][0][-1] ^ 0x01])  # flip a bit
        
        # Or generates a completely new random message
        if random.random() > 0.5:
            msg_forged = secrets.token_bytes(8)
            
        # Generates a random tag or reuses an old one
        tag_forged = queries[1][1] if random.random() > 0.5 else secrets.token_hex(8)
        
        attempts += 1
        
        # Check if the forgery is valid AND the message wasn't queried
        queried_msgs = [q[0] for q in queries]
        if msg_forged not in queried_msgs:
            if mac_instance.verify(key, msg_forged, tag_forged):
                successes += 1
                
    return {
        "rounds": rounds,
        "forgery_attempts": attempts,
        "forgery_successes": successes,
        "advantage": successes / attempts if attempts > 0 else 0,
        "conclusion": "Standard MACs resist EUF-CMA. Forgeries should be ~0."
    }


def euf_cma_queries(mac_class, key, n_queries: int = 5, message_len: int = 8) -> list:
    """Generate chosen-message queries for an EUF-CMA demonstration."""
    mac_instance = mac_class()
    queries = []
    for _ in range(n_queries):
        msg = secrets.token_bytes(message_len)
        tag = mac_instance.mac(key, msg)
        queries.append({"message": msg, "tag": tag})
    return queries


def euf_cma_check_forgery(mac_class, key, forged_message: bytes, forged_tag: str, queries: list) -> dict:
    """Check whether a user-supplied forgery is valid and unqueried."""
    mac_instance = mac_class()
    queried_msgs = [q["message"] for q in queries]
    was_queried = forged_message in queried_msgs
    valid = mac_instance.verify(key, forged_message, forged_tag)
    return {
        "valid": valid,
        "was_queried": was_queried,
        "success": valid and not was_queried,
    }

def _looks_like_hex(value: str) -> bool:
    if not value or len(value) % 2 != 0:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def _parse_bytes(value, *, as_hex: bool = False) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if value is None:
        return b""
    if isinstance(value, int):
        width = max(1, (value.bit_length() + 7) // 8)
        return value.to_bytes(width, "big")
    if isinstance(value, str):
        raw = value.strip()
        if as_hex:
            return bytes.fromhex(raw) if _looks_like_hex(raw) else raw.encode()
        if _looks_like_hex(raw):
            return bytes.fromhex(raw)
        return raw.encode()
    return str(value).encode()


def _md_glue_padding(message_len: int, block_size: int) -> bytes:
    """Return MD-strengthening padding for a message of given byte length."""
    msg_len_bits = message_len * 8
    padding = bytearray(b"\x80")
    while (message_len + len(padding) + 8) % block_size != 0:
        padding += b"\x00"
    padding += msg_len_bits.to_bytes(8, "big")
    return bytes(padding)


def _md_continue(md: MerkleDamgard, iv: bytes, suffix: bytes, total_len: int) -> bytes:
    """
    Continue MD hashing from a given chaining value (iv), processing *suffix* and
    final padding for total message length *total_len*.
    """
    msg_len_bits = total_len * 8
    padding = bytearray(b"\x80")
    while (total_len + len(padding) + 8) % md.block_size != 0:
        padding += b"\x00"
    padding += msg_len_bits.to_bytes(8, "big")

    data = suffix + bytes(padding)
    cv = iv
    for i in range(0, len(data), md.block_size):
        block = data[i:i + md.block_size]
        cv = md.compress_fn(cv, block)
    return cv


def length_extension_demo(params: dict | None) -> dict:
    """
    Demonstrate length extension for naive MAC = H(k||m) using Merkle-Damgård.
    Computes a forged tag for m||pad||m' from t=H(k||m) without using k.
    """
    params = params or {}

    message_raw = params.get("message", "comment=hello")
    suffix_raw = params.get("suffix", "&admin=true")
    key_raw = params.get("key", "1a2b3c4d")
    compress_name = params.get("compressFn", "rotate")
    as_hex = bool(params.get("asHex", False))

    message = _parse_bytes(message_raw, as_hex=as_hex)
    suffix = _parse_bytes(suffix_raw, as_hex=as_hex)
    key_bytes = _parse_bytes(key_raw, as_hex=True)

    key_len_guess = params.get("keyLen")
    key_len = int(key_len_guess) if key_len_guess is not None else len(key_bytes)

    compress_fn = COMPRESS_FNS.get(compress_name, list(COMPRESS_FNS.values())[0])
    md = MerkleDamgard(compress_fn)

    # Real tag (server knows key) for H(k||m)
    real_tag = md.hash(key_bytes + message)
    real_tag_hex = real_tag.hex()

    # Attacker computes glue padding from length only (no key) and forges tag.
    glue_padding = _md_glue_padding(key_len + len(message), md.block_size)
    forged_message = message + glue_padding + suffix
    total_len = key_len + len(forged_message)

    forged_tag = _md_continue(md, real_tag, suffix, total_len)
    forged_tag_hex = forged_tag.hex()

    # Server verifies the forged tag by recomputing with key.
    real_forged_tag = md.hash(key_bytes + forged_message).hex()

    return {
        "status": "ok",
        "compressFn": compress_name,
        "keyLen": key_len,
        "messageHex": message.hex(),
        "suffixHex": suffix.hex(),
        "originalTag": real_tag_hex,
        "gluePaddingHex": glue_padding.hex(),
        "forgedMessageHex": forged_message.hex(),
        "forgedTag": forged_tag_hex,
        "verifiedTag": real_forged_tag,
        "matches": forged_tag_hex == real_forged_tag,
        "note": "Forged tag computed from t and |k| only (no access to k).",
    }
