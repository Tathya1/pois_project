"""
PA5/app_pa5.py
==============
Flask blueprint for PA#5 — Message Authentication Codes.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import secrets

from flask import Blueprint, request, jsonify

from mac import PRF_MAC, CBC_MAC, hmac_stub
from mac_game import (
    euf_cma_game,
    euf_cma_queries,
    euf_cma_check_forgery,
    length_extension_demo,
    _parse_bytes,
)

pa5 = Blueprint("pa5", __name__)

EUF_SESSIONS = {}
EUF_SESSIONS_MAX = 100

@pa5.route("/mac", methods=["POST"])
def mac_api():
    try:
        data = request.get_json(force=True)
        key = data.get("key", "1a2b3c4d")
        message_hex = data.get("messageHex", "")
        variant = data.get("variant", "PRF_MAC")  # PRF_MAC or CBC_MAC

        if not message_hex:
            return jsonify({"error": "No message provided"}), 400
        
        if variant == "HMAC":
            return jsonify({"error": "HMAC not implemented yet"}), 400
        
        if variant == "PRF_MAC" and len(message_hex) != 8:
            return jsonify({"error": "PRF_MAC requires 8-byte message"}), 400
            
        message_bytes = bytes.fromhex(message_hex)
        
        mac_instance = PRF_MAC() if variant == "PRF_MAC" else CBC_MAC()
        tag = mac_instance.mac(key, message_bytes)
        
        return jsonify({
            "key": key,
            "messageHex": message_hex,
            "variant": variant,
            "tag": tag
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@pa5.route("/verify", methods=["POST"])
def verify_api():
    try:
        data = request.get_json(force=True)
        key = data.get("key", "1a2b3c4d")
        message_hex = data.get("messageHex", "")
        tag = data.get("tag", "")
        variant = data.get("variant", "PRF_MAC")
        
        if not message_hex or not tag:
            return jsonify({"error": "Missing message or tag"}), 400
            
        message_bytes = bytes.fromhex(message_hex)
        
        if variant == "HMAC":
            return jsonify({"error": "HMAC not implemented yet"}), 400
        
        if variant == "PRF_MAC" and len(message_hex) != 8:
            return jsonify({"error": "PRF_MAC requires 8-byte message"}), 400
        
        mac_instance = PRF_MAC() if variant == "PRF_MAC" else CBC_MAC()
        valid = mac_instance.verify(key, message_bytes, tag)
        
        return jsonify({
            "key": key,
            "messageHex": message_hex,
            "tag": tag,
            "variant": variant,
            "valid": valid
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@pa5.route("/euf-cma-game", methods=["POST"])
def euf_cma_api():
    try:
        data = request.get_json(force=True)
        rounds = int(data.get("rounds", 20))
        variant = data.get("variant", "PRF_MAC")
        include_queries = bool(data.get("includeQueries", False))
        session_id = data.get("sessionId")
        forged_message_raw = data.get("forgedMessage")
        forged_tag = data.get("forgedTag")

        mac_class = PRF_MAC if variant == "PRF_MAC" else CBC_MAC

        if session_id and forged_message_raw and forged_tag:
            session = EUF_SESSIONS.get(session_id)
            if not session:
                return jsonify({"error": "Invalid or expired session"}), 400

            key = session["key"]
            queries = session["queries"]
            mac_class = session["mac_class"]

            forged_message = _parse_bytes(forged_message_raw)
            if mac_class is PRF_MAC and len(forged_message) != 8:
                return jsonify({"error": "PRF_MAC requires 8-byte message"}), 400

            check = euf_cma_check_forgery(mac_class, key, forged_message, forged_tag, queries)
            return jsonify({
                "sessionId": session_id,
                "queries": [
                    {"messageHex": q["message"].hex(), "tag": q["tag"]}
                    for q in queries
                ],
                "user_forgery": {
                    "messageHex": forged_message.hex(),
                    "tag": forged_tag,
                    **check,
                },
            })

        result = euf_cma_game(mac_class, rounds=rounds)

        if include_queries:
            if len(EUF_SESSIONS) >= EUF_SESSIONS_MAX:
                EUF_SESSIONS.clear()

            key = secrets.randbits(64)
            queries = euf_cma_queries(mac_class, key, n_queries=5, message_len=8)
            session_id = secrets.token_hex(8)
            EUF_SESSIONS[session_id] = {
                "key": key,
                "queries": queries,
                "mac_class": mac_class,
            }
            result.update({
                "sessionId": session_id,
                "queries": [
                    {"messageHex": q["message"].hex(), "tag": q["tag"]}
                    for q in queries
                ],
            })

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@pa5.route("/length-extension", methods=["POST"])
def length_extensions_api():
    try:
        data = request.get_json(force=True) if request.data else {}
        return jsonify(length_extension_demo(data))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
