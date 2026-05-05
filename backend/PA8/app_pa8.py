"""
PA8/app_pa8.py
==============
Flask blueprint for PA#8 — DLP-Based Collision-Resistant Hash Function.

Routes
------
GET  /pa8/group-info          → DLP group parameters (p, q, g, h, birthday bound)
POST /pa8/hash                → Hash a message with DLP-MD construction
POST /pa8/trace               → Hash + full chain trace
POST /pa8/birthday-attack     → Run birthday attack on truncated DLP compress
GET  /pa8/security-argument   → Formal collision resistance proof
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PA7  = os.path.join(_HERE, "..", "PA7")
for _p in [_HERE, _PA7]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from flask import Blueprint, request, jsonify

from dlp_hash import (
    DLP_Hash, birthday_attack, collision_resistance_argument,
    get_default_group, get_default_hash,
)

pa8 = Blueprint("pa8", __name__)


@pa8.route("/group-info", methods=["GET"])
def pa8_group_info():
    """Return DLP group parameters — called once on PA8 panel mount."""
    try:
        group = get_default_group()
        return jsonify(group.info())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@pa8.route("/hash", methods=["POST"])
def pa8_hash():
    try:
        data    = request.get_json(force=True)
        raw     = data.get("message", "hello CRHF")
        as_hex  = bool(data.get("asHex", False))
        message = bytes.fromhex(raw) if as_hex else raw.encode()

        dlp = get_default_hash()
        return jsonify({
            "message": raw,
            "digest":  dlp.hash_hex(message),
            "group":   dlp.group_info(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@pa8.route("/trace", methods=["POST"])
def pa8_trace():
    """Hash + chain trace for visualization."""
    try:
        data    = request.get_json(force=True)
        raw     = data.get("message", "hello CRHF")
        as_hex  = bool(data.get("asHex", False))
        message = bytes.fromhex(raw) if as_hex else raw.encode()

        dlp    = get_default_hash()
        result = dlp.trace(message)
        result["message_str"] = raw
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@pa8.route("/birthday-attack", methods=["POST"])
def pa8_birthday_attack():
    """
    Run birthday attack on truncated DLP compress.
    Expected evaluations ≈ 2^(output_bits/2).
    """
    try:
        data    = request.get_json(force=True)
        max_ev  = int(data.get("max_evaluations", 5000))
        if max_ev > 50_000:
            return jsonify({"error": "max_evaluations capped at 50,000"}), 400

        group  = get_default_group()
        result = birthday_attack(group, max_evaluations=max_ev)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@pa8.route("/security-argument", methods=["GET"])
def pa8_security_argument():
    """Return the formal collision-resistance proof steps."""
    try:
        group  = get_default_group()
        result = collision_resistance_argument(group)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
