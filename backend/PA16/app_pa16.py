"""
PA#16 — Flask Blueprint: ElGamal PKC

Routes:
  POST /pa16/keygen          → generate ElGamal key pair
  POST /pa16/encrypt         → encrypt a message
  POST /pa16/decrypt         → decrypt a ciphertext
  POST /pa16/rerandomize     → re-randomize a ciphertext (IND-CPA demo)
  POST /pa16/homomorphic     → multiplicative homomorphism demo
  POST /pa16/ddh-game        → DDH distinguisher demo (toy params)
  POST /pa16/ind-cpa-demo    → encrypt same m twice, observe different ciphertexts
  POST /pa16/ind-cpa-game    → simulate IND-CPA game
"""

import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from flask import Blueprint, request, jsonify
from elgamal import ElGamal, mod_exp

pa16 = Blueprint("pa16", __name__)
_eg = ElGamal()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _str_dict(**kwargs):
    """Return a dict with all integer values converted to decimal strings."""
    return {k: str(v) if isinstance(v, int) else v for k, v in kwargs.items()}


def _parse_int(data: dict, key: str) -> int:
    """Parse an integer from JSON (accepts decimal strings or ints)."""
    return int(data[key])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pa16.route("/pa16/keygen", methods=["POST"])
def pa16_keygen():
    """
    Generate an ElGamal key pair.

    Request JSON (optional):
      { "bits": 32 }          ← safe-prime bit-length (16–128 for demos)

    Response JSON:
      { p, q, g, x, h, bits, time_ms }
      p, q, g, h are also returned as hex strings (_hex suffix).
    """
    data = request.get_json() or {}
    bits = max(16, min(int(data.get("bits", 32)), 128))

    t0 = time.perf_counter()
    keys = _eg.keygen(bits)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    return jsonify({
        "p":       str(keys["p"]),
        "q":       str(keys["q"]),
        "g":       str(keys["g"]),
        "x":       str(keys["x"]),   # private key
        "h":       str(keys["h"]),   # public key
        "p_hex":   hex(keys["p"]),
        "g_hex":   hex(keys["g"]),
        "h_hex":   hex(keys["h"]),
        "bits":    bits,
        "time_ms": elapsed_ms,
    })


@pa16.route("/pa16/encrypt", methods=["POST"])
def pa16_encrypt():
    """
    Encrypt a message m under public key (p, q, g, h).

    Request JSON:
      { "p": "...", "q": "...", "g": "...", "h": "...", "m": "..." }

    Response JSON:
      { c1, c2, r, s }
      r and s exposed for educational display only.
    """
    data = request.get_json() or {}
    try:
        p = _parse_int(data, "p")
        q = _parse_int(data, "q")
        g = _parse_int(data, "g")
        h = _parse_int(data, "h")
        m = _parse_int(data, "m")
    except (KeyError, ValueError) as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    try:
        result = _eg.encrypt(p, q, g, h, m)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({
        "c1": str(result["c1"]),
        "c2": str(result["c2"]),
        "r":  str(result["r"]),
        "s":  str(result["s"]),
    })


@pa16.route("/pa16/decrypt", methods=["POST"])
def pa16_decrypt():
    """
    Decrypt ciphertext (c1, c2) using private key x.

    Request JSON:
      { "p": "...", "x": "...", "c1": "...", "c2": "..." }

    Response JSON:
      { m }
    """
    data = request.get_json() or {}
    try:
        p  = _parse_int(data, "p")
        x  = _parse_int(data, "x")
        c1 = _parse_int(data, "c1")
        c2 = _parse_int(data, "c2")
    except (KeyError, ValueError) as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    m = _eg.decrypt(p, x, c1, c2)
    return jsonify({"m": str(m)})


@pa16.route("/pa16/rerandomize", methods=["POST"])
def pa16_rerandomize():
    """
    Re-randomize ciphertext (c1, c2) → different (c1_new, c2_new) for same m.

    Request JSON:
      { "p", "q", "g", "h", "c1", "c2" }

    Response JSON:
      { c1_orig, c2_orig, c1_new, c2_new, r_prime }
    """
    data = request.get_json() or {}
    try:
        p  = _parse_int(data, "p")
        q  = _parse_int(data, "q")
        g  = _parse_int(data, "g")
        h  = _parse_int(data, "h")
        c1 = _parse_int(data, "c1")
        c2 = _parse_int(data, "c2")
    except (KeyError, ValueError) as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    result = _eg.rerandomize(p, q, g, h, c1, c2)
    return jsonify({
        "c1_orig":  data["c1"],
        "c2_orig":  data["c2"],
        "c1_new":   str(result["c1"]),
        "c2_new":   str(result["c2"]),
        "r_prime":  str(result["r_prime"]),
        "note":     "c1_new ≠ c1_orig but both decrypt to the same plaintext.",
    })


@pa16.route("/pa16/homomorphic", methods=["POST"])
def pa16_homomorphic():
    """
    Demonstrate multiplicative homomorphism:
      Enc(m1) ⊗ Enc(m2) = Enc(m1 * m2 mod p)

    Request JSON:
      { "p", "q", "g", "h", "x", "m1", "m2" }

    Response JSON:
      { m1, m2, m_product, enc_m1, enc_m2, enc_product, dec_product, correct }
    """
    data = request.get_json() or {}
    try:
        p  = _parse_int(data, "p")
        q  = _parse_int(data, "q")
        g  = _parse_int(data, "g")
        h  = _parse_int(data, "h")
        x  = _parse_int(data, "x")
        m1 = _parse_int(data, "m1")
        m2 = _parse_int(data, "m2")
    except (KeyError, ValueError) as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    enc1 = _eg.encrypt(p, q, g, h, m1)
    enc2 = _eg.encrypt(p, q, g, h, m2)
    enc_prod = _eg.homomorphic_mul(p, enc1["c1"], enc1["c2"], enc2["c1"], enc2["c2"])
    m_product_expected = m1 * m2 % p
    dec_product = _eg.decrypt(p, x, enc_prod["c1"], enc_prod["c2"])

    return jsonify({
        "m1": str(m1),
        "m2": str(m2),
        "m_product_mod_p": str(m_product_expected),
        "enc_m1":   {"c1": str(enc1["c1"]), "c2": str(enc1["c2"])},
        "enc_m2":   {"c1": str(enc2["c1"]), "c2": str(enc2["c2"])},
        "enc_product": {"c1": str(enc_prod["c1"]), "c2": str(enc_prod["c2"])},
        "dec_product": str(dec_product),
        "correct":  dec_product == m_product_expected,
        "note": "Enc(m1) ⊗ Enc(m2) component-wise decrypts to m1*m2 mod p.",
    })


@pa16.route("/pa16/ddh-game", methods=["POST"])
def pa16_ddh_game():
    """
    Toy DDH distinguisher demo.

    Request JSON (optional):
      { "bits": 16 }

    Response JSON includes both a true DH triple and a random triple.
    """
    data = request.get_json() or {}
    bits = max(12, min(int(data.get("bits", 16)), 32))
    result = _eg.ddh_game(bits)

    return jsonify({
        "p":  str(result["p"]),
        "q":  str(result["q"]),
        "g":  str(result["g"]),
        "a":  str(result["a"]),
        "b":  str(result["b"]),
        "dh_triple": {
            "g_a":  str(result["dh_triple"]["g_a"]),
            "g_b":  str(result["dh_triple"]["g_b"]),
            "g_ab": str(result["dh_triple"]["g_ab"]),
            "type": "DH triple  — g^(ab) mod p",
        },
        "random_triple": {
            "g_a": str(result["random_triple"]["g_a"]),
            "g_b": str(result["random_triple"]["g_b"]),
            "g_r": str(result["random_triple"]["g_r"]),
            "type": "Random triple — g^r mod p",
        },
        "note": result["note"],
    })


@pa16.route("/pa16/ind-cpa-demo", methods=["POST"])
def pa16_ind_cpa_demo():
    """
    IND-CPA demonstration: encrypt the same m twice and show distinct ciphertexts.

    Request JSON:
      { "p", "q", "g", "h", "x", "m" }

    Response JSON:
      { m, enc_1, enc_2, same_c1, same_c2, note }
    """
    data = request.get_json() or {}
    try:
        p = _parse_int(data, "p")
        q = _parse_int(data, "q")
        g = _parse_int(data, "g")
        h = _parse_int(data, "h")
        x = _parse_int(data, "x")
        m = _parse_int(data, "m")
    except (KeyError, ValueError) as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    enc1 = _eg.encrypt(p, q, g, h, m)
    enc2 = _eg.encrypt(p, q, g, h, m)

    return jsonify({
        "m": str(m),
        "enc_1": {"c1": str(enc1["c1"]), "c2": str(enc1["c2"]), "r": str(enc1["r"])},
        "enc_2": {"c1": str(enc2["c1"]), "c2": str(enc2["c2"]), "r": str(enc2["r"])},
        "same_c1": enc1["c1"] == enc2["c1"],
        "same_c2": enc1["c2"] == enc2["c2"],
        "ciphertexts_differ": enc1["c1"] != enc2["c1"] or enc1["c2"] != enc2["c2"],
        "note": (
            "Textbook RSA is deterministic (same m → same ciphertext). "
            "ElGamal is randomized (same m → different ciphertexts each time). "
            "This is the IND-CPA security property."
        ),
    })


@pa16.route("/pa16/ind-cpa-game", methods=["POST"])
def pa16_ind_cpa_game_route():
    """
    Run a simulation of the IND-CPA game.

    Request JSON:
      { "bits": 12, "rounds": 100 }

    Response JSON:
      { bits, rounds, success_count, advantage, time_ms }
    """
    data = request.get_json() or {}
    try:
        bits = int(data.get("bits", 12))
        rounds = int(data.get("rounds", 100))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid 'bits' or 'rounds'"}), 400

    t0 = time.perf_counter()
    result = _eg.ind_cpa_game(bits, rounds)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    return jsonify({
        "bits": result["bits"],
        "rounds": result["rounds"],
        "success_count": result["success_count"],
        "advantage": round(result["advantage"], 4),
        "time_ms": elapsed_ms,
    })
