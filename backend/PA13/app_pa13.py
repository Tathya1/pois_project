"""
PA#13 Flask Blueprint — Miller-Rabin Primality Testing

Routes:
  GET  /pa13/carmichael-demo   — show 561 fools Fermat but not Miller-Rabin
  POST /pa13/test              — test whether a number is (probably) prime
  POST /pa13/gen               — generate a random probable prime of given bit length
"""

from flask import Blueprint, request, jsonify
import sys
import os
import time
import math

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from miller_rabin import miller_rabin, is_prime, gen_prime, gen_prime_with_count, mod_exp

pa13 = Blueprint("pa13", __name__)


@pa13.route("/pa13/test", methods=["POST"])
def pa13_test_api():
    """
    Test whether a given integer is probably prime using Miller-Rabin.

    Body:   { "n": "integer_string", "rounds": int }
    Returns:
      {
        n, rounds,
        result: "PRIME" | "COMPOSITE",
        probably_prime: bool,
        fermat_pass: bool | null,   (base-2 Fermat test, for comparison)
        time_ms: float,
        note: str                   (highlights Carmichael numbers)
      }
    """
    data = request.get_json(force=True)
    try:
        n = int(str(data.get("n", "17")))
        k = int(data.get("rounds", 40))
        k = max(1, min(k, 100))             # clamp to [1, 100]
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    # Fermat test (base 2) for comparison — naive, fooled by Carmichael numbers
    fermat_pass = None
    if 2 < n < 10 ** 15:
        fermat_pass = bool(mod_exp(2, n - 1, n) == 1)

    t0 = time.perf_counter()
    result = miller_rabin(n, k)
    elapsed = (time.perf_counter() - t0) * 1000

    note = ""
    if fermat_pass and not result:
        note = (
            "Carmichael number: passes the Fermat test but correctly "
            "rejected by Miller-Rabin."
        )

    return jsonify({
        "n": str(n),
        "rounds": k,
        "result": "PRIME" if result else "COMPOSITE",
        "probably_prime": result,
        "fermat_pass": fermat_pass,
        "time_ms": round(elapsed, 3),
        "note": note,
    })


@pa13.route("/pa13/gen", methods=["POST"])
def pa13_gen_api():
    """
    Generate a random probable prime of the requested bit length.

    Body:    { "bits": int }
    Returns: { prime, prime_hex, bits, requested_bits, time_ms }
    """
    data = request.get_json(force=True)
    try:
        bits = int(data.get("bits", 64))
        bits = max(8, min(bits, 2048))
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid bits: {e}"}), 400

    t0 = time.perf_counter()
    p = gen_prime(bits, k=40)
    verified = miller_rabin(p, k=40)
    elapsed = (time.perf_counter() - t0) * 1000

    return jsonify({
        "prime":          str(p),
        "prime_hex":      hex(p),
        "bits":           p.bit_length(),
        "requested_bits": bits,
        "rounds":         40,
        "verified":       bool(verified),
        "time_ms":        round(elapsed, 3),
    })


@pa13.route("/pa13/benchmark", methods=["POST"])
def pa13_benchmark_api():
    """
    Benchmark candidate counts for prime generation vs. ln(n) expectation.

    Body: { "trials": int }
    Returns: { rounds, trials, results: [...] }
    """
    data = request.get_json(silent=True) or {}
    try:
        trials = int(data.get("trials", 3))
        trials = max(1, min(trials, 5))
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid trials: {e}"}), 400

    results = []
    for bits in (512, 1024, 2048):
        total_candidates = 0
        t0 = time.perf_counter()
        for _ in range(trials):
            _, candidates = gen_prime_with_count(bits, k=40)
            total_candidates += candidates
        elapsed = (time.perf_counter() - t0) * 1000

        avg_candidates = total_candidates / trials
        theoretical = bits * math.log(2)
        results.append({
            "bits": bits,
            "avg_candidates": round(avg_candidates, 2),
            "theoretical_ln_n": round(theoretical, 2),
            "ratio": round(avg_candidates / theoretical, 3),
            "time_ms": round(elapsed, 3),
        })

    return jsonify({
        "rounds": 40,
        "trials": trials,
        "results": results,
    })


@pa13.route("/pa13/carmichael-demo", methods=["GET"])
def pa13_carmichael_api():
    """
    Demonstrate that 561 (smallest Carmichael number) fools the naive Fermat test
    but is correctly identified as composite by Miller-Rabin.

    Returns a static JSON explanation with live test results.
    """
    n = 561   # = 3 × 11 × 17

    # Fermat test (base 2): 2^560 ≡ 1 (mod 561) — passes despite n being composite
    fermat_pass = bool(mod_exp(2, n - 1, n) == 1)

    # Miller-Rabin with k=40 rounds — must correctly reject
    mr_result = miller_rabin(n, k=40)

    return jsonify({
        "n":                  n,
        "is_actually_prime":  False,
        "factorization":      "3 × 11 × 17",
        "fermat_test_base2":  fermat_pass,
        "miller_rabin_result": "PRIME" if mr_result else "COMPOSITE",
        "correctly_rejected": not mr_result,
        "explanation": (
            "561 = 3 × 11 × 17 is composite. The naive Fermat test passes because "
            "2^560 ≡ 1 (mod 561) — 561 is a Carmichael number. "
            "Miller-Rabin correctly identifies it as COMPOSITE."
        ),
    })
