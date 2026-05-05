"""
PA7/app_pa7.py
==============
Flask blueprint for PA#7 — Merkle-Damgård Transform.

Routes
------
POST /pa7/hash            → hash a message with chosen compress function
POST /pa7/trace           → hash + full chain trace for visualization
POST /pa7/compress-compare → run both compress functions, compare results
POST /pa7/collision-demo   → construct compress collision → MD collision demo
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from flask import Blueprint, request, jsonify

from merkle_damgard import (
    MerkleDamgard, COMPRESS_FNS, xor_compress, rotate_add_compress,
    collision_propagation_demo, HASH_SIZE, BLOCK_SIZE, IV_DEFAULT,
)

pa7 = Blueprint("pa7", __name__)


def _get_compress_fn(name: str):
    return COMPRESS_FNS.get(name, xor_compress)


@pa7.route("/hash", methods=["POST"])
def pa7_hash():
    try:
        data = request.get_json(force=True)
        raw         = data.get("message", "hello world")
        compress_fn = data.get("compressFn", "xor")
        as_hex      = bool(data.get("asHex", False))

        message = bytes.fromhex(raw) if as_hex else raw.encode()
        md      = MerkleDamgard(_get_compress_fn(compress_fn))

        return jsonify({
            "message":     raw,
            "compressFn":  compress_fn,
            "digest":      md.hash_hex(message),
            "block_size":  BLOCK_SIZE,
            "hash_size":   HASH_SIZE,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@pa7.route("/trace", methods=["POST"])
def pa7_trace():
    """Full chain trace — used by the MD Visualizer."""
    try:
        data = request.get_json(force=True)
        raw         = data.get("message", "hello world")
        compress_fn = data.get("compressFn", "xor")
        as_hex      = bool(data.get("asHex", False))

        message = bytes.fromhex(raw) if as_hex else raw.encode()
        md      = MerkleDamgard(_get_compress_fn(compress_fn))

        result = md.trace(message)
        result["compressFn"] = compress_fn
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@pa7.route("/compress-compare", methods=["POST"])
def pa7_compress_compare():
    """Compare xor and rotate compress functions on the same message."""
    try:
        data = request.get_json(force=True)
        raw    = data.get("message", "compare me")
        as_hex = bool(data.get("asHex", False))

        message = bytes.fromhex(raw) if as_hex else raw.encode()

        md_xor    = MerkleDamgard(xor_compress)
        md_rotate = MerkleDamgard(rotate_add_compress)

        trace_xor    = md_xor.trace(message)
        trace_rotate = md_rotate.trace(message)

        return jsonify({
            "message":     raw,
            "xor":         {"digest": trace_xor["digest"],    "chain": trace_xor["chain"]},
            "rotate":      {"digest": trace_rotate["digest"], "chain": trace_rotate["chain"]},
            "digests_match": trace_xor["digest"] == trace_rotate["digest"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@pa7.route("/collision-demo", methods=["POST"])
def pa7_collision_demo():
    """
    Construct compress collision → show full MD collision.
    B1 ≠ B2 but H(B1 ‖ S) = H(B2 ‖ S) for any suffix S.
    """
    try:
        data        = request.get_json(force=True)
        compress_fn = data.get("compressFn", "xor")
        suffix_str  = data.get("suffix", "any_suffix_works")
        suffix      = suffix_str.encode()

        result = collision_propagation_demo(compress_fn_name=compress_fn, suffix=suffix)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
