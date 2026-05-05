"""
PA#12 Flask Blueprint — Textbook RSA + PKCS#1 v1.5

Routes:
  POST /pa12/keygen                  — generate RSA key pair
  POST /pa12/encrypt                 — textbook RSA encryption
  POST /pa12/decrypt                 — textbook RSA decryption
  POST /pa12/decrypt-crt             — Garner's CRT decryption (~4x faster)
  POST /pa12/pkcs15/encrypt          — PKCS#1 v1.5 padded encryption
  POST /pa12/pkcs15/decrypt          — PKCS#1 v1.5 padded decryption (returns ⊥ on bad padding)
  POST /pa12/attack/determinism      — show textbook RSA ciphertext reuse vs PKCS#1 randomness
  POST /pa12/attack/bleichenbacher   — simplified Bleichenbacher padding oracle demo
"""

from flask import Blueprint, request, jsonify
import sys
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from rsa    import RSA, mod_exp, mod_inverse
from pkcs15 import pkcs15_pad, pkcs15_unpad

pa12 = Blueprint("pa12", __name__)
_rsa = RSA()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _modulus_bytes(N: int) -> int:
    """Number of bytes needed to represent N (ceiling division)."""
    return (N.bit_length() + 7) // 8


def _int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _find_separator(em: bytes) -> int:
    """Find the 0x00 separator byte in a PKCS#1 EM, starting at index 2."""
    for i in range(2, len(em)):
        if em[i] == 0:
            return i
    return -1


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pa12.route("/pa12/keygen", methods=["POST"])
def pa12_keygen_api():
    """
    Generate an RSA key pair.

    Body:    { "bits": int }   (default 512, range 64–2048)
    Returns: all key components as decimal strings (large ints don't fit in JSON numbers)
      { N, e, d, p, q, dp, dq, q_inv, N_hex, bits, time_ms }
    """
    data = request.get_json(force=True)
    bits = int(data.get("bits", 512))
    bits = max(64, min(bits, 2048))

    t0   = time.perf_counter()
    keys = _rsa.keygen(bits)
    elapsed = (time.perf_counter() - t0) * 1000

    return jsonify({
        "N":       str(keys["N"]),
        "e":       keys["e"],
        "d":       str(keys["d"]),
        "p":       str(keys["p"]),
        "q":       str(keys["q"]),
        "dp":      str(keys["dp"]),
        "dq":      str(keys["dq"]),
        "q_inv":   str(keys["q_inv"]),
        "N_hex":   hex(keys["N"]),
        "bits":    keys["N"].bit_length(),
        "time_ms": round(elapsed, 2),
    })


@pa12.route("/pa12/encrypt", methods=["POST"])
def pa12_encrypt_api():
    """
    Textbook RSA encryption: C = m^e mod N.

    Body:    { "N": str, "e": int (optional, default 65537), "m": str }
    Returns: { c, c_hex }
    """
    data = request.get_json(force=True)
    try:
        N = int(data["N"])
        e = int(data.get("e", 65537))
        m = int(data["m"])
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    try:
        c = _rsa.encrypt(N, e, m)
    except ValueError as ex:
        return jsonify({"error": str(ex)}), 400

    return jsonify({"c": str(c), "c_hex": hex(c)})


@pa12.route("/pa12/decrypt", methods=["POST"])
def pa12_decrypt_api():
    """
    Textbook RSA decryption: M = c^d mod N.

    Body:    { "N": str, "d": str, "c": str }
    Returns: { m, m_hex }
    """
    data = request.get_json(force=True)
    try:
        N = int(data["N"])
        d = int(data["d"])
        c = int(data["c"])
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    m = _rsa.decrypt(N, d, c)
    return jsonify({"m": str(m), "m_hex": hex(m)})


@pa12.route("/pa12/decrypt-crt", methods=["POST"])
def pa12_decrypt_crt_api():
    """
    Garner's CRT decryption — approximately 4x faster than standard decrypt.

    Body:    { "p", "q", "dp", "dq", "q_inv", "c" }  (all as decimal strings)
    Returns: { m, m_hex }
    """
    data = request.get_json(force=True)
    try:
        p     = int(data["p"])
        q     = int(data["q"])
        dp    = int(data["dp"])
        dq    = int(data["dq"])
        q_inv = int(data["q_inv"])
        c     = int(data["c"])
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    m = _rsa.decrypt_crt(p, q, dp, dq, q_inv, c)
    return jsonify({"m": str(m), "m_hex": hex(m)})


@pa12.route("/pa12/pkcs15/encrypt", methods=["POST"])
def pa12_pkcs15_encrypt_api():
    """
    PKCS#1 v1.5 padded RSA encryption.
    Padding injects random bytes → different ciphertext each call.

    Body:    { "N": str, "e": int (optional), "message_hex": str }
    Returns: { c, c_hex, em_hex, ps_len }
    """
    data = request.get_json(force=True)
    try:
        N       = int(data["N"])
        e       = int(data.get("e", 65537))
        message = bytes.fromhex(data["message_hex"])
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    k = _modulus_bytes(N)
    try:
        em = pkcs15_pad(message, k)
    except ValueError as ex:
        return jsonify({"error": str(ex)}), 400

    m_int = _bytes_to_int(em)
    try:
        c = _rsa.encrypt(N, e, m_int)
    except ValueError as ex:
        return jsonify({"error": str(ex)}), 400

    sep = _find_separator(em)
    return jsonify({
        "c":      str(c),
        "c_hex":  hex(c),
        "em_hex": em.hex(),
        "ps_len": sep - 2 if sep >= 0 else 0,
    })


@pa12.route("/pa12/pkcs15/decrypt", methods=["POST"])
def pa12_pkcs15_decrypt_api():
    """
    PKCS#1 v1.5 padded RSA decryption.
    Returns ⊥ (error) on malformed padding — never decrypts invalid ciphertexts.

    Body:    { "N": str, "d": str, "c": str }
    Returns: { message_hex, valid_padding: true }
          or { error, valid_padding: false }  (HTTP 200 so UI can display it)
    """
    data = request.get_json(force=True)
    try:
        N = int(data["N"])
        d = int(data["d"])
        c = int(data["c"])
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    k     = _modulus_bytes(N)
    m_int = _rsa.decrypt(N, d, c)

    try:
        em      = _int_to_bytes(m_int, k)
        message = pkcs15_unpad(em)
        return jsonify({
            "message_hex":   message.hex(),
            "valid_padding": True,
        })
    except (ValueError, OverflowError) as ex:
        return jsonify({
            "error":         f"⊥ — invalid padding: {ex}",
            "valid_padding": False,
        })


@pa12.route("/pa12/attack/determinism", methods=["POST"])
def pa12_attack_determinism_api():
    """
    Demonstrate textbook RSA determinism (CPA insecurity).

    Encrypt the same message twice:
      - Textbook: identical ciphertexts → plaintext leaks.
      - PKCS#1 v1.5: different ciphertexts each time (random PS).

    Body:    { "N": str, "e": int (optional), "message_hex": str }
    Returns: { message, textbook: {c1,c2,identical,verdict}, pkcs15: {c1,c2,identical,verdict} }
    """
    data = request.get_json(force=True)
    try:
        N   = int(data["N"])
        e   = int(data.get("e", 65537))
        msg = bytes.fromhex(data.get("message_hex", "68656c6c6f"))  # "hello"
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    m_int = _bytes_to_int(msg)

    # Textbook: two encryptions of the same integer
    c1_raw = _rsa.encrypt(N, e, m_int)
    c2_raw = _rsa.encrypt(N, e, m_int)

    # PKCS#1 v1.5: two encryptions (each with fresh random PS)
    k  = _modulus_bytes(N)
    try:
        em1 = pkcs15_pad(msg, k)
        em2 = pkcs15_pad(msg, k)
    except ValueError as ex:
        return jsonify({"error": str(ex)}), 400

    c1_pkcs = _rsa.encrypt(N, e, _bytes_to_int(em1))
    c2_pkcs = _rsa.encrypt(N, e, _bytes_to_int(em2))

    sep1 = _find_separator(em1)
    sep2 = _find_separator(em2)

    return jsonify({
        "message": msg.hex(),
        "textbook": {
            "c1":       hex(c1_raw),
            "c2":       hex(c2_raw),
            "identical": c1_raw == c2_raw,
            "verdict":  (
                "INSECURE: identical ciphertexts reveal which plaintext was encrypted"
                if c1_raw == c2_raw
                else "UNEXPECTED: ciphertexts differ (should not happen for textbook RSA)"
            ),
        },
        "pkcs15": {
            "c1":       hex(c1_pkcs),
            "c2":       hex(c2_pkcs),
            "ps1_hex":  em1[2:sep1].hex() if sep1 >= 0 else "",
            "ps2_hex":  em2[2:sep2].hex() if sep2 >= 0 else "",
            "identical": c1_pkcs == c2_pkcs,
            "verdict":  (
                "SECURE: random PS makes each ciphertext unique"
                if c1_pkcs != c2_pkcs
                else "COLLISION: same PS generated (negligible probability)"
            ),
        },
    })


@pa12.route("/pa12/attack/bleichenbacher", methods=["POST"])
def pa12_attack_bleichenbacher_api():
    """
    Simplified Bleichenbacher padding oracle demonstration.

    Shows the concept: a padding oracle (a service that reveals whether
    decryption yields valid PKCS#1 v1.5 format) leaks information.
    In the full attack (~2^20 adaptive queries) an adversary can recover
    the full plaintext without the private key.

    Body:    { "N": str, "d": str, "c": str }
    Returns: { explanation, oracle_queries: [{r, c_modified_hex, padding_valid}] }
    """
    data = request.get_json(force=True)
    try:
        N = int(data["N"])
        d = int(data["d"])
        c = int(data["c"])
        e = int(data.get("e", 65537))
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    k = _modulus_bytes(N)

    def padding_oracle(c_query: int) -> bool:
        """True iff decryption of c_query yields a valid PKCS#1 v1.5 message."""
        m = _rsa.decrypt(N, d, c_query)
        try:
            em = _int_to_bytes(m, k)
            pkcs15_unpad(em)
            return True
        except (ValueError, OverflowError):
            return False

    # Demonstrate 5 adaptive oracle queries with random multipliers
    import secrets as _sec
    queries = []
    for _ in range(5):
        r         = _sec.randbelow(N - 2) + 2
        # c' = r^e * c mod N  — decrypts to r*m mod N (RSA multiplicative homomorphism)
        c_mod     = (mod_exp(r, e, N) * c) % N
        valid     = padding_oracle(c_mod)
        queries.append({
            "r":             str(r),
            "c_modified_hex": hex(c_mod),
            "padding_valid": valid,
        })

    return jsonify({
        "explanation": (
            "Each modified ciphertext c' = r^e * c mod N decrypts to r*m mod N. "
            "The padding oracle reveals whether the decryption begins with 0x00 0x02. "
            "With ~2^20 adaptive queries (Bleichenbacher 1998), an attacker recovers m "
            "without knowing d. This proves PKCS#1 v1.5 is NOT CCA-secure. "
            "Fix: use OAEP padding (PA#17) or Encrypt-then-MAC (PA#6)."
        ),
        "oracle_queries": queries,
    })
