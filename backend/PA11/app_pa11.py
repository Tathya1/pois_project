"""
PA#11 Flask Blueprint — Diffie-Hellman Key Exchange

Routes:
  POST /pa11/params        — generate group parameters (p, q, g)
  POST /pa11/exchange      — run a full DH exchange (both parties)
  POST /pa11/alice-step1   — Alice generates her (private, public) key pair
  POST /pa11/bob-step1     — Bob generates his (private, public) key pair
  POST /pa11/alice-step2   — Alice computes shared secret from her private + Bob's public
  POST /pa11/bob-step2     — Bob computes shared secret from his private + Alice's public
  POST /pa11/mitm          — Eve performs a MITM attack on an in-progress exchange
"""

from flask import Blueprint, request, jsonify
import sys
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from dh import DH, mitm_attack

pa11 = Blueprint("pa11", __name__)


# ---------------------------------------------------------------------------
# Helper: build a DH instance from request body
# ---------------------------------------------------------------------------

def _dh_from_data(data: dict) -> DH:
    """
    Build a DH instance from request parameters.
    If (p, q, g) are all present: use them.
    Otherwise: generate a fresh group of `bits` bits (default 32).
    """
    p = data.get("p")
    q = data.get("q")
    g = data.get("g")
    bits = int(data.get("bits", 32))
    bits = max(16, min(bits, 128))      # clamp: demo range

    if p is not None and q is not None and g is not None:
        return DH(p=int(p), q=int(q), g=int(g))
    return DH(bits=bits)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pa11.route("/pa11/params", methods=["POST"])
def pa11_params_api():
    """
    Generate DH group parameters (safe prime p, subgroup order q, generator g).

    Body:    { "bits": int }   (default 32, max 128 for demo speed)
    Returns: { p, q, g, p_hex, q_hex, g_hex, bits, time_ms }
    """
    data = request.get_json(force=True)
    bits = int(data.get("bits", 32))
    bits = max(16, min(bits, 128))

    t0 = time.perf_counter()
    dh = DH(bits=bits)
    elapsed = (time.perf_counter() - t0) * 1000

    return jsonify({
        "p":       dh.p,
        "q":       dh.q,
        "g":       dh.g,
        "p_hex":   hex(dh.p),
        "q_hex":   hex(dh.q),
        "g_hex":   hex(dh.g),
        "bits":    bits,
        "time_ms": round(elapsed, 2),
    })


@pa11.route("/pa11/exchange", methods=["POST"])
def pa11_exchange_api():
    """
    Run a full DH key exchange between Alice and Bob.
    Optionally accepts existing (p, q, g); otherwise generates fresh params.

    Body:    { "p": int, "q": int, "g": int }  or  { "bits": int }
    Returns: { p, q, g, alice_public, bob_public, shared_secret, match, time_ms }
    """
    data = request.get_json(force=True)

    t0 = time.perf_counter()
    dh = _dh_from_data(data)
    result = dh.run_exchange()
    elapsed = (time.perf_counter() - t0) * 1000

    return jsonify({
        "p":             result["p"],
        "q":             result["q"],
        "g":             result["g"],
        "alice_public":  result["alice_public"],
        "bob_public":    result["bob_public"],
        "shared_secret": result["shared_secret"],
        "match":         result["match"],
        "time_ms":       round(elapsed, 2),
    })


@pa11.route("/pa11/alice-step1", methods=["POST"])
def pa11_alice_step1_api():
    """
    Alice generates her private exponent a and public value A = g^a mod p.

    Body:    { "p": int, "q": int, "g": int }  or  { "bits": int }
    Returns: { private: a, public: A, p, q, g }
    """
    data = request.get_json(force=True)
    dh = _dh_from_data(data)
    a, A = dh.alice_step1()
    return jsonify({
        "private": a,
        "public":  A,
        "p":       dh.p,
        "q":       dh.q,
        "g":       dh.g,
    })


@pa11.route("/pa11/bob-step1", methods=["POST"])
def pa11_bob_step1_api():
    """
    Bob generates his private exponent b and public value B = g^b mod p.

    Body:    { "p": int, "q": int, "g": int }  or  { "bits": int }
    Returns: { private: b, public: B, p, q, g }
    """
    data = request.get_json(force=True)
    dh = _dh_from_data(data)
    b, B = dh.bob_step1()
    return jsonify({
        "private": b,
        "public":  B,
        "p":       dh.p,
        "q":       dh.q,
        "g":       dh.g,
    })


@pa11.route("/pa11/alice-step2", methods=["POST"])
def pa11_alice_step2_api():
    """
    Alice computes shared secret K = B^a mod p.

    Body:    { "p": int, "q": int, "g": int, "a": int, "B": int }
    Returns: { shared_secret: K }
    """
    data = request.get_json(force=True)
    try:
        p = int(data["p"])
        q = int(data["q"])
        g = int(data["g"])
        a = int(data["a"])
        B = int(data["B"])
    except (KeyError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

    dh = DH(p=p, q=q, g=g)
    K = dh.alice_step2(a, B)
    return jsonify({"shared_secret": K})


@pa11.route("/pa11/bob-step2", methods=["POST"])
def pa11_bob_step2_api():
    """
    Bob computes shared secret K = A^b mod p.

    Body:    { "p": int, "q": int, "g": int, "b": int, "A": int }
    Returns: { shared_secret: K }
    """
    data = request.get_json(force=True)
    try:
        p = int(data["p"])
        q = int(data["q"])
        g = int(data["g"])
        b = int(data["b"])
        A = int(data["A"])
    except (KeyError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

    dh = DH(p=p, q=q, g=g)
    K = dh.bob_step2(b, A)
    return jsonify({"shared_secret": K})


@pa11.route("/pa11/mitm", methods=["POST"])
def pa11_mitm_api():
    """
    Demonstrate an MITM attack on an ongoing DH exchange.
    Eve intercepts Alice's public A and Bob's public B,
    substitutes her own E for both, and establishes separate
    shared secrets with each party.

    Body:    { "p": int, "q": int, "g": int, "alice_public": int, "bob_public": int }
    Returns: { eve_public, K_alice_eve, K_bob_eve, note }
    """
    data = request.get_json(force=True)
    try:
        p = int(data["p"])
        q = int(data["q"])
        g = int(data["g"])
        A = int(data["alice_public"])
        B = int(data["bob_public"])
    except (KeyError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

    dh = DH(p=p, q=q, g=g)
    result = mitm_attack(dh, A, B)

    return jsonify({
        "eve_public":   result["eve_public"],
        "K_alice_eve":  result["K_alice_eve"],
        "K_bob_eve":    result["K_bob_eve"],
        "note":         result["note"],
    })
