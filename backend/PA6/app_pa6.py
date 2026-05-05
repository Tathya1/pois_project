"""
PA6/app_pa6.py
==============
Flask blueprint for PA#6 — CCA-Secure Encryption.

Routes
------
POST /pa6/encrypt         → Encrypt-then-MAC: {kE, kM, message} → {r, c, tag}
POST /pa6/decrypt         → Verify-then-Decrypt: {kE, kM, r, c, tag} → {message} or {rejected}
POST /pa6/malleability    → Side-by-side CPA vs CCA tamper demo
POST /pa6/cca2-game       → IND-CCA2 game with dummy adversary
POST /pa6/key-separation  → Key separation warning demo
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _rel in [_HERE, "../PA3", "../PA5", "../shared"]:
    _p = os.path.join(_HERE, _rel) if _rel.startswith("..") else _rel
    if _p not in sys.path:
        sys.path.insert(0, _p)

from flask import Blueprint, request, jsonify

from cca import CCA, cpa_malleability_demo, cca_tamper_demo, key_separation_demo
from cca_game import ind_cca2_game, cpa_vs_cca_comparison

pa6 = Blueprint("pa6", __name__)


# ---------------------------------------------------------------------------
# Encrypt (Encrypt-then-MAC)
# ---------------------------------------------------------------------------

@pa6.route("/encrypt", methods=["POST"])
def cca_encrypt_api():
    try:
        data    = request.get_json(force=True)
        kE      = data.get("kE", "1a2b3c4d")
        kM      = data.get("kM", "deadbeef")
        message = data.get("message", "")

        if not message:
            return jsonify({"error": "No message provided"}), 400

        cca    = CCA()
        result = cca.enc(kE, kM, message)

        return jsonify({
            "kE":     kE,
            "kM":     kM,
            "r":      result["r"],
            "c":      result["c"],
            "tag":    result["tag"],
            "scheme": "Encrypt-then-MAC (PA#3 CPA + PA#5 CBC-MAC)",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Decrypt (Verify-then-Decrypt)
# ---------------------------------------------------------------------------

@pa6.route("/decrypt", methods=["POST"])
def cca_decrypt_api():
    try:
        data  = request.get_json(force=True)
        kE    = data.get("kE", "1a2b3c4d")
        kM    = data.get("kM", "deadbeef")
        r     = data.get("r", "")
        c     = data.get("c", "")
        tag   = data.get("tag", "")

        if not r or not c or not tag:
            return jsonify({"error": "Missing r, c, or tag"}), 400

        cca    = CCA()
        result = cca.dec(kE, kM, r, c, tag)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Malleability demo (CPA vs CCA side-by-side)
# ---------------------------------------------------------------------------

@pa6.route("/malleability", methods=["POST"])
def malleability_api():
    """
    Returns both CPA malleability result AND CCA rejection result
    for the same message + key + bit-flip, enabling the split-panel UI.
    """
    try:
        data      = request.get_json(force=True)
        key       = data.get("key", "1a2b3c4d")
        message   = data.get("message", "hello world____")
        bit_index = int(data.get("bitIndex", 0))

        result = cpa_vs_cca_comparison(key, message, bit_index)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# IND-CCA2 game
# ---------------------------------------------------------------------------

@pa6.route("/cca2-game", methods=["POST"])
def cca2_game_api():
    try:
        data   = request.get_json(force=True)
        rounds = int(data.get("rounds", 20))

        if rounds > 100:
            return jsonify({"error": "Max 100 rounds to keep latency reasonable"}), 400

        result = ind_cca2_game(rounds=rounds)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Key-separation demo
# ---------------------------------------------------------------------------

@pa6.route("/key-separation", methods=["POST"])
def key_separation_api():
    try:
        data    = request.get_json(force=True)
        key     = data.get("key", "1a2b3c4d")
        message = data.get("message", "test message")

        result = key_separation_demo(key, message)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
