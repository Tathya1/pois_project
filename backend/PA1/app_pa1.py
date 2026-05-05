"""
PA1/app_pa1.py
==============
Flask blueprint for PA#1 — OWF + PRG.

Routes
------
POST /prg           → generate PRG bits from seed
POST /test          → NIST statistical tests on provided bit-string
POST /owf/evaluate  → f(x) = g^x mod p
POST /owf/hardness  → verify_hardness demo (brute-force inversion)
POST /owf-from-prg  → PA#1b: minimal inversion hardness demo (supports 1b.md argument)
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from flask import Blueprint, request, jsonify

from owf import DLP_OWF
from prg import PRG
# OWF_from_PRG class was over-engineered for spec; replaced with minimal demo.
# The formal proof lives in 1b.md. Only a brief inline demo is needed.
from owf_from_prg import demo_inversion_hardness
from tests import frequency_test, runs_test, serial_test

pa1 = Blueprint("pa1", __name__)


# ---------------------------------------------------------------------------
# PRG endpoint
# ---------------------------------------------------------------------------

@pa1.route("/prg", methods=["POST"])
def prg_api():
    try:
        data = request.get_json(force=True)
        seed   = data.get("seed", "123")
        length = int(data.get("length", 32))

        if not seed:
            seed = "123"

        owf = DLP_OWF()
        prg = PRG(owf)
        prg.seed(seed)
        bits = prg.next_bits(length)

        return jsonify({"bits": bits})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# NIST statistical tests
# ---------------------------------------------------------------------------

@pa1.route("/test", methods=["POST"])
def test_api():
    try:
        data = request.get_json(force=True)
        bits = data.get("bits", "")

        if not bits:
            return jsonify({"error": "No bits provided"}), 400

        return jsonify({
            "frequency": frequency_test(bits),
            "runs":      runs_test(bits),
            "serial":    serial_test(bits),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# OWF evaluate
# ---------------------------------------------------------------------------

@pa1.route("/owf/evaluate", methods=["POST"])
def owf_evaluate_api():
    try:
        data = request.get_json(force=True)
        x    = int(data.get("x", "12345"))
        owf  = DLP_OWF()
        y    = owf.evaluate(x)
        return jsonify({"x": x, "y": y, "g": owf.g, "p": owf.p})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# OWF hardness demo
# ---------------------------------------------------------------------------

@pa1.route("/owf/hardness", methods=["POST"])
def owf_hardness_api():
    try:
        data   = request.get_json(force=True)
        trials = int(data.get("trials", 5))
        owf    = DLP_OWF()

        results = []
        for _ in range(trials):
            import random
            x = random.randint(1, 100_000)
            y = owf.evaluate(x)

            found = False
            for guess in range(10_000):
                if owf.evaluate(guess) == y:
                    found = True
                    break
            results.append({"x": x, "y": y, "brute_force_found": found})

        return jsonify({
            "trials": trials,
            "results": results,
            "hardness_confirmed": not any(r["brute_force_found"] for r in results),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# PA#1b backward direction: OWF from PRG
# Formal proof is in 1b.md. This endpoint runs a minimal concrete demo.
# The full OWF_from_PRG class + distinguisher were over-engineered and have
# been commented out in owf_from_prg.py.
# ---------------------------------------------------------------------------

@pa1.route("/owf-from-prg", methods=["POST"])
def owf_from_prg_api():
    """
    PA#1b: run the minimal inversion hardness demo.
    Picks 5 random seeds from [0, 2^32), computes y = G(s),
    brute-forces with budget=10,000 guesses, confirms adversary fails.
    Supports the written proof in 1b.md.
    """
    try:
        data    = request.get_json(force=True)
        n       = int(data.get("n_trials", 5))
        budget  = int(data.get("budget", 10_000))
        result  = demo_inversion_hardness(n_trials=n, budget=budget)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# [COMMENTED OUT] Full OWF_from_PRG class routes — replaced by minimal demo above
# @pa1.route("/owf-from-prg", methods=["POST"])
# def owf_from_prg_api_old():
#     try:
#         data = request.get_json(force=True)
#         mode = data.get("mode", "hardness")
#         owf_prg = OWF_from_PRG()
#         if mode == "hardness":
#             ...
#         elif mode == "distinguisher":
#             ...
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500