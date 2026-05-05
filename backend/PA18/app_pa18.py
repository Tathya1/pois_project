"""
PA#18 — Flask Blueprint: 1-out-of-2 Oblivious Transfer

Routes:
  POST /pa18/sender-setup       → generate RSA keys + challenges
  POST /pa18/receiver-query     → receiver blinds their choice
  POST /pa18/sender-respond     → sender masks both messages
  POST /pa18/receiver-decrypt   → receiver recovers chosen message
  POST /pa18/full-protocol      → run complete OT with trace
"""

import os
import sys
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from flask import Blueprint, request, jsonify
from ot import OT12

pa18 = Blueprint("pa18", __name__)
_ot = OT12()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_int(data: dict, key: str) -> int:
    return int(data[key])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pa18.route("/pa18/sender-setup", methods=["POST"])
def pa18_sender_setup():
    """
    Sender setup: generate RSA keypair and two random challenge values.

    Request JSON (optional):
      { "bits": 128 }     ← RSA bit-length (32–512 for demos)

    Response JSON:
      { N, e, d, x0, x1 }   all as decimal strings
      d is exposed for educational transparency.
    """
    data = request.get_json() or {}
    bits = max(32, min(int(data.get("bits", 128)), 512))
    result = _ot.sender_setup(bits)
    return jsonify({
        "N":  str(result["N"]),
        "e":  str(result["e"]),
        "d":  str(result["d"]),
        "x0": str(result["x0"]),
        "x1": str(result["x1"]),
    })


@pa18.route("/pa18/receiver-query", methods=["POST"])
def pa18_receiver_query():
    """
    Receiver blinds their choice and produces query v.

    Request JSON:
      { "N", "e", "x0", "x1", "choice" }

    Response JSON:
      { v, k }   — k is receiver's secret (kept private in real protocol)
    """
    data = request.get_json() or {}
    try:
        N      = _parse_int(data, "N")
        e      = _parse_int(data, "e")
        x0     = _parse_int(data, "x0")
        x1     = _parse_int(data, "x1")
        choice = int(data["choice"])
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    result = _ot.receiver_query(N, e, x0, x1, choice)
    return jsonify({
        "v": str(result["v"]),
        "k": str(result["k"]),
    })


@pa18.route("/pa18/sender-respond", methods=["POST"])
def pa18_sender_respond():
    """
    Sender masks both messages and sends them to the receiver.

    Request JSON:
      { "N", "d", "x0", "x1", "v", "m0_hex", "m1_hex" }

    Response JSON:
      { m0_enc_hex, m1_enc_hex, k0, k1 }
      k0, k1 exposed for demo only.
    """
    data = request.get_json() or {}
    try:
        N  = _parse_int(data, "N")
        d  = _parse_int(data, "d")
        x0 = _parse_int(data, "x0")
        x1 = _parse_int(data, "x1")
        v  = _parse_int(data, "v")
        m0 = bytes.fromhex(data["m0_hex"])
        m1 = bytes.fromhex(data["m1_hex"])
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    result = _ot.sender_respond(N, d, x0, x1, v, m0, m1)
    return jsonify({
        "m0_enc_hex": result["m0_enc"].hex(),
        "m1_enc_hex": result["m1_enc"].hex(),
        "k0": str(result["k0"]),
        "k1": str(result["k1"]),
    })


@pa18.route("/pa18/receiver-decrypt", methods=["POST"])
def pa18_receiver_decrypt():
    """
    Receiver decrypts their chosen message.

    Request JSON:
      { "choice", "k", "m0_enc_hex", "m1_enc_hex" }

    Response JSON:
      { message_hex, message_text }
    """
    data = request.get_json() or {}
    try:
        choice    = int(data["choice"])
        k         = _parse_int(data, "k")
        m0_enc    = bytes.fromhex(data["m0_enc_hex"])
        m1_enc    = bytes.fromhex(data["m1_enc_hex"])
    except (KeyError, ValueError) as ex:
        return jsonify({"error": str(ex)}), 400

    m = _ot.receiver_decrypt(choice, k, m0_enc, m1_enc)
    return jsonify({
        "message_hex":  m.hex(),
        "message_text": m.decode("utf-8", errors="replace"),
    })


@pa18.route("/pa18/full-protocol", methods=["POST"])
def pa18_full_protocol():
    """
    Run the complete 1-of-2 OT protocol and return a step-by-step trace.

    Request JSON (optional):
      { "m0": "...", "m1": "...", "choice": 0|1, "bits": 128 }

    Response JSON:
      { choice, expected, recovered, success, trace, security }
    """
    data   = request.get_json() or {}
    m0_str = data.get("m0", "Secret message 0")
    m1_str = data.get("m1", "Secret message 1")
    choice = int(data.get("choice", 0))
    bits   = max(32, min(int(data.get("bits", 128)), 512))

    result = _ot.run_protocol(
        m0_str.encode(), m1_str.encode(), choice, bits
    )

    # Make trace JSON-serializable (k values are ints → strings)
    def _serialize(obj):
        if isinstance(obj, dict):
            return {k: _serialize(v) for k, v in obj.items()}
        if isinstance(obj, int) and obj > 10**6:
            return str(obj)
        return obj

    return jsonify(_serialize(result))


@pa18.route("/pa18/bulk-test", methods=["POST"])
def pa18_bulk_test():
    """
    Run N trials of the OT protocol with random inputs.

    Request JSON (optional):
      { "trials": 100, "bits": 64 }

    Response JSON:
      { trials, successes, failures, success_rate }
    """
    data = request.get_json() or {}
    num_trials = int(data.get("trials", 100))
    bits = int(data.get("bits", 64))
    successes = 0

    for _ in range(num_trials):
        m0 = os.urandom(16)
        m1 = os.urandom(16)
        choice = secrets.randbelow(2)
        result = _ot.run_protocol(m0, m1, choice, bits)
        if result["success"]:
            successes += 1

    return jsonify({
        "trials": num_trials,
        "successes": successes,
        "failures": num_trials - successes,
        "success_rate": (successes / num_trials) * 100 if num_trials > 0 else 0,
    })


@pa18.route("/pa18/cheat-attempt", methods=["POST"])
def pa18_cheat_attempt():
    """
    Demonstrate sender privacy: a receiver who chose b cannot decrypt m_{1-b}.

    The receiver holds k (from their honest choice b). They try to use the
    same k to unmask the *other* ciphertext. The result is garbled — provably
    so because k_{1-b} ≠ k without inverting RSA.

    Request JSON (optional):
      { "m0": "...", "m1": "...", "choice": 0|1, "bits": 128 }

    Response JSON:
      { choice, honest_choice_msg, cheat_attempt_msg,
        cheat_succeeded (always False), explanation }
    """
    data   = request.get_json() or {}
    m0_str = data.get("m0", "Secret message 0")
    m1_str = data.get("m1", "Secret message 1")
    choice = int(data.get("choice", 0))
    bits   = max(32, min(int(data.get("bits", 128)), 512))

    # Run honest protocol
    result = _ot.run_protocol(
        m0_str.encode(), m1_str.encode(), choice, bits
    )

    # Extract session values from the trace
    trace = result["trace"]
    k_str = trace["step2_receiver_query"]["k"]
    m0_enc = bytes.fromhex(trace["step3_sender_response"]["m0_enc"])
    m1_enc = bytes.fromhex(trace["step3_sender_response"]["m1_enc"])

    # Honest decryption (choice = b)
    honest_msg = _ot.receiver_decrypt(
        choice, int(k_str), m0_enc, m1_enc
    ).decode("utf-8", errors="replace")

    # Cheat attempt: try to decrypt the other message with the same k
    wrong_choice = 1 - choice
    cheat_raw    = _ot.receiver_decrypt(
        wrong_choice, int(k_str), m0_enc, m1_enc
    )
    cheat_msg    = cheat_raw.decode("utf-8", errors="replace")

    # Was the cheat successful? (it never should be)
    target_msg   = m1_str if wrong_choice == 1 else m0_str
    cheat_ok     = cheat_msg == target_msg

    return jsonify({
        "choice":             choice,
        "honest_message":     honest_msg,
        "hidden_message":     "??",       # what receiver should see for m_{1-b}
        "cheat_target":       target_msg, # what receiver was trying to learn
        "cheat_result":       cheat_msg,  # what they actually got
        "cheat_succeeded":    cheat_ok,   # always False (provable)
        "explanation": (
            f"Receiver chose b={choice} and holds k. "
            f"Trying to use k to decrypt m{wrong_choice} "
            f"produces garbled output: '{cheat_msg}' ≠ '{target_msg}'. "
            "k₁₋ᵦ ≠ k without inverting RSA-OW, so the ciphertext "
            "is masked with an unknown key — decryption always fails."
        ),
    })

