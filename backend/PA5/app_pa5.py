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

from flask import Blueprint, request, jsonify

from mac import PRF_MAC, CBC_MAC, hmac_stub
from mac_game import euf_cma_game, length_extension_demo

pa5 = Blueprint("pa5", __name__)

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
        
        mac_class = PRF_MAC if variant == "PRF_MAC" else CBC_MAC
        result = euf_cma_game(mac_class, rounds=rounds)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@pa5.route("/length-extension", methods=["POST"])
def length_extensions_api():
    try:
        return jsonify(length_extension_demo(None))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
