from flask import Blueprint, request, jsonify
import secrets
import uuid

from cpa import CPA
from cpa_game import simulate_ind_cpa_dummy, simulate_rounds

pa3 = Blueprint("pa3", __name__)

CPA_SESSIONS = {}

@pa3.route("/enc", methods=["POST"])
def cpa_enc_api():
    cpa = CPA()
    data = request.get_json(force=True)

    key = data.get("key", "1a2b3c4d")
    message = data.get("message", "")
    reuse_nonce = bool(data.get("reuseNonce", False))
    r_hex = data.get("r")

    r_override = int(r_hex, 16) if (reuse_nonce and r_hex) else None
    r_out, c_out = cpa.enc_text(key, message, r=r_override)

    return jsonify({
        "r": r_out,
        "c": c_out
    })


@pa3.route("/dec", methods=["POST"])
def cpa_dec_api():
    cpa = CPA()
    data = request.get_json(force=True)

    key = data.get("key", "1a2b3c4d")
    r_hex = data.get("r")
    c_hex = data.get("c")

    if not r_hex or not c_hex:
        return jsonify({"error": "Missing r or c"}), 400

    try:
        message = cpa.dec_text(key, r_hex, c_hex)
        return jsonify({
            "message": message,
            "messageHex": message.encode("utf-8").hex()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@pa3.route("/challenge", methods=["POST"])
def cpa_challenge_api():
    cpa = CPA()
    data = request.get_json(force=True)

    m0 = data.get("m0", "")
    m1 = data.get("m1", "")
    reuse_nonce = bool(data.get("reuseNonce", False))
    session_id = data.get("sessionId")

    if len(m0) != len(m1):
        return jsonify({"error": "m0 and m1 must be equal length"}), 400

    if not session_id or session_id not in CPA_SESSIONS:
        session_id = uuid.uuid4().hex
        CPA_SESSIONS[session_id] = {
            "key": secrets.randbits(64),
            "reuse_nonce": reuse_nonce,
            "fixed_r": None,
            "last_b": None
        }

    session = CPA_SESSIONS[session_id]
    session["reuse_nonce"] = reuse_nonce
    if reuse_nonce and session["fixed_r"] is None:
        session["fixed_r"] = secrets.randbits(64)

    b = secrets.randbelow(2)
    session["last_b"] = b
    message = m0 if b == 0 else m1

    r_override = session["fixed_r"] if reuse_nonce else None
    r_out, c_out = cpa.enc_text(session["key"], message, r=r_override)

    return jsonify({
        "sessionId": session_id,
        "r": r_out,
        "c": c_out
    })


@pa3.route("/oracle", methods=["POST"])
def cpa_oracle_api():
    cpa = CPA()
    data = request.get_json(force=True)

    session_id = data.get("sessionId")
    message = data.get("message", "")
    if not session_id or session_id not in CPA_SESSIONS:
        return jsonify({"error": "Invalid session"}), 400

    session = CPA_SESSIONS[session_id]
    r_override = session["fixed_r"] if session["reuse_nonce"] else None
    r_out, c_out = cpa.enc_text(session["key"], message, r=r_override)

    return jsonify({
        "r": r_out,
        "c": c_out
    })


@pa3.route("/guess", methods=["POST"])
def cpa_guess_api():
    data = request.get_json(force=True)

    session_id = data.get("sessionId")
    guess = data.get("guess")
    if session_id not in CPA_SESSIONS:
        return jsonify({"error": "Invalid session"}), 400

    session = CPA_SESSIONS[session_id]
    if session["last_b"] is None:
        return jsonify({"error": "No active challenge"}), 400

    correct = int(guess) == int(session["last_b"])
    return jsonify({
        "correct": correct,
        "b": session["last_b"]
    })


@pa3.route("/simulate", methods=["POST"])
def cpa_simulate_api():
    data = request.get_json(force=True)
    rounds = int(data.get("rounds", 1))
    oracle_queries = int(data.get("oracleQueries", 50))
    print("Started")

    result = simulate_ind_cpa_dummy(rounds=rounds, oracle_queries=oracle_queries)
    print("Finished")
    return jsonify(result)


@pa3.route("/rounds", methods=["POST"])
def cpa_rounds_api():
    data = request.get_json(force=True)
    rounds = int(data.get("rounds", 20))
    reuse_nonce = bool(data.get("reuseNonce", False))

    result = simulate_rounds(rounds=rounds, reuse_nonce=reuse_nonce)
    return jsonify(result)