"""
PA#19 — Flask Blueprint: Secure AND Gate

Routes:
  POST /pa19/compute         → run secure AND for given (a, b)
  POST /pa19/truth-table     → run all 4 input combos and verify
  POST /pa19/verify-privacy  → demonstrate privacy properties
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from flask import Blueprint, request, jsonify
from secure_and import SecureAND

pa19 = Blueprint("pa19", __name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pa19.route("/pa19/compute", methods=["POST"])
def pa19_compute():
    """
    Run the secure AND protocol for given bits a and b.

    Request JSON:
      { "a": 0|1, "b": 0|1, "bits": 128 }

    Response JSON:
      { alice_bit, bob_bit, expected_output, actual_output, correct, trace, security }
    """
    data = request.get_json() or {}
    try:
        a    = int(data.get("a", 1))
        b    = int(data.get("b", 1))
        bits = max(32, min(int(data.get("bits", 128)), 512))
    except (TypeError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    if a not in (0, 1) or b not in (0, 1):
        return jsonify({"error": "a and b must be 0 or 1"}), 400

    engine = SecureAND(ot_bits=bits)
    result = engine.protocol(a, b)

    # Convert large ints in trace to strings for JSON
    def _j(obj):
        if isinstance(obj, dict):
            return {k: _j(v) for k, v in obj.items()}
        if isinstance(obj, int) and obj > 10**9:
            return str(obj)
        return obj

    return jsonify(_j(result))


@pa19.route("/pa19/truth-table", methods=["POST"])
def pa19_truth_table():
    """
    Run the secure AND protocol for all 4 input combinations.

    Request JSON (optional):
      { "bits": 128 }

    Response JSON:
      { rows: [ {a, b, expected, computed, correct} × 4 ], all_correct }
    """
    data = request.get_json() or {}
    bits = max(32, min(int(data.get("bits", 128)), 512))

    engine = SecureAND(ot_bits=bits)
    rows = engine.truth_table()
    all_correct = all(r["correct"] for r in rows)

    return jsonify({"rows": rows, "all_correct": all_correct})


@pa19.route("/pa19/verify-privacy", methods=["POST"])
def pa19_verify_privacy():
    """
    Demonstrate privacy properties: run AND(a, b) and show that neither
    party learns the other's input during the protocol.

    Request JSON:
      { "a": 0|1, "b": 0|1, "bits": 128 }

    Response JSON: detailed privacy analysis
    """
    data = request.get_json() or {}
    try:
        a    = int(data.get("a", 1))
        b    = int(data.get("b", 0))
        bits = max(32, min(int(data.get("bits", 128)), 512))
    except (TypeError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    if a not in (0, 1) or b not in (0, 1):
        return jsonify({"error": "a and b must be 0 or 1"}), 400

    engine = SecureAND(ot_bits=bits)
    result = engine.protocol(a, b)

    return jsonify({
        "alice_bit":       a,
        "bob_bit":         b,
        "and_result":      result["actual_output"],
        "correct":         result["correct"],
        "alice_sees": {
            "her_own_bit":   a,
            "her_share_r_A": result["trace"]["step1_alice_share"]["r_A"],
            "what_she_knows": (
                f"Alice only knows r_A={result['trace']['step1_alice_share']['r_A']}. "
                "She does NOT see Bob's OT choice bit b. "
                "She cannot determine b from r_A alone."
            ),
        },
        "bob_sees": {
            "his_own_bit":  b,
            "his_share_r_B": result["trace"]["step3_ot_execution"]["bob_received_r_B"],
            "what_he_knows": (
                f"Bob only sees r_B (= r_A ⊕ (a AND b)). "
                "r_A is uniformly random, so r_B is uniformly random "
                "regardless of a. Bob cannot determine a."
            ),
        },
        "reconstruction": {
            "alice_share": result["trace"]["step4_reconstruct"]["alice_share_r_A"],
            "bob_share":   result["trace"]["step4_reconstruct"]["bob_share_r_B"],
            "output":      result["actual_output"],
            "note": "Both parties reveal their shares; XOR reconstructs a AND b.",
        },
        "security_proof": {
            "privacy": (
                "Simulation argument: Alice's view is {r_A}. "
                "Bob's view is {r_B}. Both are uniformly random. "
                "Neither view depends on the other's private input."
            ),
            "correctness": (
                "r_A ⊕ r_B = r_A ⊕ (r_A ⊕ (a AND b)) = a AND b. Always."
            ),
        },
    })


# ---------------------------------------------------------------------------
# Secure XOR (free gate)
# ---------------------------------------------------------------------------

@pa19.route("/pa19/xor", methods=["POST"])
def pa19_xor():
    """
    Run the Secure XOR protocol for given bits a and b.
    XOR is free — no OT needed, only 1 random bit of communication.

    Request JSON:
      { "a": 0|1, "b": 0|1 }

    Response JSON:
      { alice_bit, bob_bit, expected_output, actual_output, correct,
        ot_calls, trace, security }
    """
    data = request.get_json() or {}
    try:
        a = int(data.get("a", 1))
        b = int(data.get("b", 0))
    except (TypeError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    if a not in (0, 1) or b not in (0, 1):
        return jsonify({"error": "a and b must be 0 or 1"}), 400

    engine = SecureAND()
    result = engine.secure_xor(a, b)
    return jsonify(result)


@pa19.route("/pa19/truth-table-xor", methods=["POST"])
def pa19_truth_table_xor():
    """
    Run Secure_XOR for all 4 input combinations.

    Response JSON:
      { rows: [ {a, b, expected, computed, correct} × 4 ], all_correct }
    """
    engine = SecureAND()
    rows = engine.truth_table_xor()
    return jsonify({"rows": rows, "all_correct": all(r["correct"] for r in rows)})


# ---------------------------------------------------------------------------
# Secure NOT (free gate)
# ---------------------------------------------------------------------------

@pa19.route("/pa19/not", methods=["POST"])
def pa19_not():
    """
    Run the Secure NOT operation for Alice's bit a.
    NOT is free — Alice locally flips her share; no communication.

    Request JSON:
      { "a": 0|1 }

    Response JSON:
      { alice_bit, expected_output, actual_output, correct, ot_calls, trace, security }
    """
    data = request.get_json() or {}
    try:
        a = int(data.get("a", 1))
    except (TypeError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    if a not in (0, 1):
        return jsonify({"error": "a must be 0 or 1"}), 400

    engine = SecureAND()
    result = engine.secure_not(a)
    return jsonify(result)

