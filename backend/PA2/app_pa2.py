"""
PA2/app_pa2.py
==============
Flask blueprint for PA#2 — Pseudorandom Functions (GGM Tree Construction).

Routes
------
POST /prf               → GGM PRF: compute F(k, x) and return tree nodes
POST /prf/aes           → AES PRF (OS primitive): compute F_k(x) = AES_k(x)
POST /prf/aes-compare   → Side-by-side GGM vs AES: functional identity demo
POST /prf/distinguish   → distinguishing game: PRF vs random oracle (q queries)
POST /prg-from-prf      → PA#2b backward: PRF → PRG, runs statistical test
"""

import os
import sys
import random

_HERE = os.path.dirname(os.path.abspath(__file__))
_PA1  = os.path.join(_HERE, "..", "PA1")
_BASE = os.path.join(_HERE, "..")

for _p in [_HERE, _PA1, _BASE]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from flask import Blueprint, request, jsonify

from owf import DLP_OWF
from prg import PRG
from prf import GGM_PRF
from aes_prf import AES_PRF
from prf_comparison import prf_comparison_demo
from prg_from_prf import PRG_from_PRF
from distinguisher import distinguishing_game, prg_from_prf_statistical_test

pa2 = Blueprint("pa2", __name__)



@pa2.route("/prf", methods=["POST"])
def prf_api():
    try:
        data = request.get_json(force=True)
        k_hex = data.get("key", "1a2b3c4d")
        x = data.get("x", "01")

        k = int(k_hex, 16) if k_hex else 0x1a2b3c4d

        owf = DLP_OWF()
        prg_obj = PRG(owf)

        levels = [[k]] 
        current_seeds = [k]

        for bit in x:
            next_level_seeds = []
            for s in current_seeds:
                prg_obj.seed(s)
                out = prg_obj.next_bits(128)
                left  = int(out[:64], 2)
                right = int(out[64:], 2)
                next_level_seeds.extend([left, right])
            
            levels.append(next_level_seeds)
            current_seeds = next_level_seeds

        leaf_index = int(x, 2)
        result_val = levels[-1][leaf_index]
        result_hex = hex(result_val)[2:]

        return jsonify({
            "key": k,
            "x": x,
            "tree": levels, # This now contains n+1 arrays
            "result": result_hex,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# AES PRF (pure-Python, no library)
# ---------------------------------------------------------------------------

@pa2.route("/prf/aes", methods=["POST"])
def prf_aes_api():
    """
    Concrete PRF using pure-Python AES-128.
    Demonstrates the AES plug-in mentioned in the spec.
    """
    try:
        data    = request.get_json(force=True)
        key_hex = data.get("key", "2b7e151628aed2a6abf7158809cf4f3c")  # FIPS KAT key
        x_hex   = data.get("x",   "3243f6a8885a308d313198a2e0370734")

        prf = AES_PRF()
        ct  = prf.F(x_hex)
        inv = prf.F_inv(ct)

        return jsonify({
            "key":          key_hex,
            "x":            x_hex,
            "result":       ct,
            "inverse_ok":   inv == x_hex.zfill(32).lower(),
            "fips197_kat":  prf.verify_fips197_kat(),
            "info":         prf.info(),
            "note": (
                "F_k(x) = AES_k(x) — OS primitive (Python cryptography + OpenSSL AES-128-ECB). "
                "Permitted exception: spec says 'your own AES or the OS primitive'."
            ),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# AES vs GGM: functional identity demonstration
# ---------------------------------------------------------------------------

@pa2.route("/prf/aes-compare", methods=["POST"])
def prf_aes_compare():
    """
    Side-by-side comparison showing GGM PRF and AES PRF are functionally
    identical: both pass NIST tests, both support CPA round-trip, both are
    valid drop-in PRFs with negligible IND-PRF advantage.
    """
    try:
        data       = request.get_json(force=True)
        key_hex    = data.get("key", None)         # None → random key
        n_queries  = int(data.get("n_queries", 200))
        message    = data.get("message", "hello world")

        result = prf_comparison_demo(
            key_hex    = key_hex,
            n_queries  = n_queries,
            test_message = message,
        )
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# PA#2 distinguishing game
# ---------------------------------------------------------------------------

@pa2.route("/prf/distinguish", methods=["POST"])
def prf_distinguish_api():
    """
    Run the IND-PRF distinguishing game:
    query GGM PRF and a random oracle on q random inputs,
    confirm no statistical difference.
    """
    try:
        data = request.get_json(force=True)
        q    = int(data.get("queries", 100))

        result = distinguishing_game(q=q)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# PA#2b backward: PRF → PRG & statistical test
# ---------------------------------------------------------------------------

@pa2.route("/prg-from-prf", methods=["POST"])
def prg_from_prf_api():
    """
    Backward direction: PRF → PRG via G(s) = F_s(0^n) || F_s(1^n).
    Returns the concatenated hex output and NIST test results.
    """
    try:
        data   = request.get_json(force=True)
        seed   = int(data.get("seed", 123456))
        n_bits = int(data.get("n_bits", 1024))

        prg    = PRG_from_PRF()
        # Build enough bits from successive seeds
        bits   = ""
        current_seed = seed
        outputs = []
        while len(bits) < n_bits:
            out_hex = prg.generate(current_seed, n=8)
            out_bits = bin(int(out_hex, 16))[2:].zfill(len(out_hex) * 4)
            bits += out_bits
            outputs.append(out_hex)
            current_seed = int(out_hex[-8:], 16) if len(out_hex) >= 8 else current_seed + 1

        bits = bits[:n_bits]

        from tests import frequency_test, runs_test
        freq = frequency_test(bits)
        runs = runs_test(bits)

        return jsonify({
            "seed":      seed,
            "n_bits":    n_bits,
            "sample_outputs": outputs[:4],
            "frequency": freq,
            "runs":      runs,
            "pass":      freq["pass"] and runs["pass"],
            "note":      "G(s) = F_s(0^n) || F_s(1^n) — PRF used as PRG (backward direction)",
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500