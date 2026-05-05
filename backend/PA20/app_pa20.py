"""
PA#20 — Flask Blueprint: Secure 2-Party MPC (GMW Protocol)

Routes:
  GET  /pa20/circuits              → list all available circuits
  POST /pa20/evaluate              → evaluate a named circuit
  POST /pa20/demo-inner-product    → (a0 AND b0) XOR (a1 AND b1)
  POST /pa20/demo-majority         → maj(a, b0, b1)
  POST /pa20/demo-equality         → 1-bit equality
  POST /pa20/millionaire           → Millionaire's Problem: x > y (n-bit)
  POST /pa20/equality-n            → n-bit equality: x == y
  POST /pa20/addition              → n-bit addition: x + y mod 2^n
  GET  /pa20/lineage               → end-to-end call-chain trace
"""

import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from flask import Blueprint, request, jsonify
from mpc import GMWCircuit, DEMO_CIRCUITS, _build_millionaire, _build_equality_n, _build_adder

pa20 = Blueprint("pa20", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int_to_bits(val: int, n: int, msb_first: bool = True) -> list:
    """Convert integer to list of n bits. MSB-first by default."""
    bits = [(val >> (n - 1 - i)) & 1 for i in range(n)]
    return bits if msb_first else list(reversed(bits))


def _bits_to_int(bits: list, msb_first: bool = True) -> int:
    """Convert bit list to integer."""
    if msb_first:
        return sum(b << (len(bits) - 1 - i) for i, b in enumerate(bits))
    return sum(b << i for i, b in enumerate(bits))



def _make_serializable(obj):
    """Recursively convert large ints to strings for JSON serialization."""
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_make_serializable(v) for v in obj]
    if isinstance(obj, int) and obj > 10**9:
        return str(obj)
    return obj


def _remap_result(result: dict) -> dict:
    """
    Normalise the dict returned by GMWCircuit.evaluate() so the JSON
    response uses the field names expected by the test suite:
      outputs    → output
      gate_trace → gates
      stats.*    → n_ands, n_free_gates, n_xors, n_nots (flat, top-level)
    """
    stats = result.get("stats", {})
    out = dict(result)
    out["output"]       = result.get("outputs", [])
    out["gates"]        = result.get("gate_trace", [])
    out["n_ands"]       = stats.get("and_gates",  0)
    out["n_free_gates"] = stats.get("free_gates", 0)
    out["n_xors"]       = stats.get("xor_gates",  0)
    out["n_nots"]       = stats.get("not_gates",   0)
    return out


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pa20.route("/pa20/circuits", methods=["GET"])
def pa20_circuits():
    """
    List the available demo circuits.

    Response JSON:
      { circuits: [ {name, description, n_alice, n_bob, n_gates} ] }
    """
    info = []
    for key, circ in DEMO_CIRCUITS.items():
        info.append({
            "name":        key,                  # short key: "and_xor", "majority", "equality"
            "title":       circ["name"],          # human-readable title
            "description": circ["description"],
            "n_alice":     circ["n_alice"],
            "n_bob":       circ["n_bob"],
            "n_gates":     len(circ["gates"]),
            "gates":       circ["gates"],         # full gate list
            "outputs":     circ["outputs"],
        })
    return jsonify({"circuits": info})


@pa20.route("/pa20/evaluate", methods=["POST"])
def pa20_evaluate():
    """
    Evaluate a named demo circuit on given inputs.

    Request JSON:
      {
        "circuit":       "and_xor"|"majority"|"equality",
        "alice_inputs":  [0|1, ...],
        "bob_inputs":    [0|1, ...],
        "bits":          128          ← OT bit-length
      }

    Response JSON:
      { alice_inputs, bob_inputs, outputs, gate_trace, stats, security }
    """
    data = request.get_json() or {}
    # Accept both "circuit_name" (test convention) and "circuit" (legacy)
    circuit_key = data.get("circuit_name", data.get("circuit", "and_xor"))
    if circuit_key not in DEMO_CIRCUITS:
        return jsonify({"error": f"Unknown circuit '{circuit_key}'. "
                                 f"Available: {list(DEMO_CIRCUITS)}"}), 400

    circuit = DEMO_CIRCUITS[circuit_key]
    alice_inputs = [int(x) for x in data.get("alice_inputs", [0] * circuit["n_alice"])]
    bob_inputs   = [int(x) for x in data.get("bob_inputs",   [0] * circuit["n_bob"])]
    bits = max(32, min(int(data.get("bits", 128)), 512))

    if len(alice_inputs) != circuit["n_alice"]:
        return jsonify({"error": f"Circuit needs {circuit['n_alice']} Alice inputs, got {len(alice_inputs)}"}), 400
    if len(bob_inputs) != circuit["n_bob"]:
        return jsonify({"error": f"Circuit needs {circuit['n_bob']} Bob inputs, got {len(bob_inputs)}"}), 400

    evaluator = GMWCircuit(circuit, ot_bits=bits)
    result = evaluator.evaluate(alice_inputs, bob_inputs)

    return jsonify(_make_serializable(_remap_result({
        "circuit_name":  circuit_key,
        "circuit_title": circuit["name"],
        "circuit_desc":  circuit["description"],
        **result,
    })))


@pa20.route("/pa20/demo-inner-product", methods=["POST"])
def pa20_demo_inner_product():
    """
    Evaluate (a0 AND b0) XOR (a1 AND b1) — 2-bit inner product mod 2.

    Request JSON:
      { "a0": 0|1, "a1": 0|1, "b0": 0|1, "b1": 0|1, "bits": 128 }
    """
    data = request.get_json() or {}
    a0 = int(data.get("a0", 1)); a1 = int(data.get("a1", 0))
    b0 = int(data.get("b0", 1)); b1 = int(data.get("b1", 1))
    bits = max(32, min(int(data.get("bits", 128)), 512))

    circuit   = DEMO_CIRCUITS["and_xor"]
    evaluator = GMWCircuit(circuit, ot_bits=bits)
    result    = evaluator.evaluate([a0, a1], [b0, b1])

    expected = (a0 & b0) ^ (a1 & b1)
    return jsonify(_make_serializable(_remap_result({
        "alice_inputs":  [a0, a1],
        "bob_inputs":    [b0, b1],
        "formula":       f"({a0} AND {b0}) XOR ({a1} AND {b1}) = {expected}",
        "expected":      expected,
        **result,
    })))


@pa20.route("/pa20/demo-majority", methods=["POST"])
def pa20_demo_majority():
    """
    Evaluate maj(a, b0, b1): majority of Alice's 1 bit and Bob's 2 bits.

    Request JSON:
      { "a": 0|1, "b0": 0|1, "b1": 0|1, "bits": 128 }
    """
    data = request.get_json() or {}
    a  = int(data.get("a",  1))
    b0 = int(data.get("b0", 1))
    b1 = int(data.get("b1", 0))
    bits = max(32, min(int(data.get("bits", 128)), 512))

    circuit   = DEMO_CIRCUITS["majority"]
    evaluator = GMWCircuit(circuit, ot_bits=bits)
    result    = evaluator.evaluate([a], [b0, b1])

    expected = 1 if (a + b0 + b1) >= 2 else 0
    return jsonify(_make_serializable(_remap_result({
        "alice_inputs":  [a],
        "bob_inputs":    [b0, b1],
        "formula":       f"maj({a}, {b0}, {b1}) = {expected}",
        "expected":      expected,
        **result,
    })))


@pa20.route("/pa20/demo-equality", methods=["POST"])
def pa20_demo_equality():
    """
    Evaluate a == b: 1-bit equality between Alice's and Bob's single bits.

    Request JSON:
      { "a": 0|1, "b": 0|1, "bits": 128 }
    """
    data = request.get_json() or {}
    a = int(data.get("a", 1))
    b = int(data.get("b", 1))
    bits = max(32, min(int(data.get("bits", 128)), 512))

    circuit   = DEMO_CIRCUITS["equality"]
    evaluator = GMWCircuit(circuit, ot_bits=bits)
    result    = evaluator.evaluate([a], [b])

    expected = int(a == b)
    return jsonify(_make_serializable(_remap_result({
        "alice_inputs":  [a],
        "bob_inputs":    [b],
        "formula":       f"{a} == {b} → {expected}",
        "expected":      expected,
        **result,
    })))


# ---------------------------------------------------------------------------
# Mandatory Circuit 1 — Millionaire's Problem
# ---------------------------------------------------------------------------

@pa20.route("/pa20/millionaire", methods=["POST"])
def pa20_millionaire():
    """
    Millionaire's Problem: does Alice have more than Bob?

    Request JSON:
      { "x": int (Alice's wealth), "y": int (Bob's wealth),
        "n": 4,   ← bit-width (2–8)
        "bits": 64 }   ← OT bit-length

    Response JSON:
      { x, y, n, x_gt_y, result_text, x_bits, y_bits, output,
        n_ands, n_free_gates, gate_trace, time_ms, privacy_note }
    """
    data = request.get_json() or {}
    n    = max(2, min(int(data.get("n", 4)), 8))
    bits = max(32, min(int(data.get("bits", 64)), 512))
    x    = int(data.get("x", 7))  & ((1 << n) - 1)
    y    = int(data.get("y", 12)) & ((1 << n) - 1)

    x_bits = _int_to_bits(x, n, msb_first=True)
    y_bits = _int_to_bits(y, n, msb_first=True)

    circuit   = _build_millionaire(n)
    evaluator = GMWCircuit(circuit, ot_bits=bits)

    t0 = time.time()
    result = evaluator.evaluate(x_bits, y_bits)
    elapsed_ms = round((time.time() - t0) * 1000, 1)

    x_gt_y = bool(result["outputs"][0])
    if x > y:
        result_text = "Alice is richer"
    elif x < y:
        result_text = "Bob is richer"
    else:
        result_text = "Equal"

    return jsonify(_make_serializable(_remap_result({
        "x":           x,
        "y":           y,
        "n":           n,
        "x_bits":      x_bits,
        "y_bits":      y_bits,
        "x_gt_y":      x_gt_y,
        "result_text": result_text,
        "time_ms":     elapsed_ms,
        "privacy_note": (
            "Neither party reveals their wealth. "
            "Alice's x and Bob's y are secret-shared across all AND/OT calls. "
            "Only the final comparison bit (x > y) is revealed."
        ),
        **result,
    })))


# ---------------------------------------------------------------------------
# Mandatory Circuit 2 — n-bit Equality
# ---------------------------------------------------------------------------

@pa20.route("/pa20/equality-n", methods=["POST"])
def pa20_equality_n():
    """
    n-bit equality: x == y, where Alice has x and Bob has y.

    Request JSON:
      { "x": int, "y": int, "n": 4, "bits": 64 }
    """
    data = request.get_json() or {}
    n    = max(2, min(int(data.get("n", 4)), 8))
    bits = max(32, min(int(data.get("bits", 64)), 512))
    x    = int(data.get("x", 5)) & ((1 << n) - 1)
    y    = int(data.get("y", 5)) & ((1 << n) - 1)

    x_bits = _int_to_bits(x, n, msb_first=True)
    y_bits = _int_to_bits(y, n, msb_first=True)

    circuit   = _build_equality_n(n)
    evaluator = GMWCircuit(circuit, ot_bits=bits)

    t0 = time.time()
    result = evaluator.evaluate(x_bits, y_bits)
    elapsed_ms = round((time.time() - t0) * 1000, 1)

    equal = bool(result["outputs"][0])
    return jsonify(_make_serializable(_remap_result({
        "x":           x,
        "y":           y,
        "n":           n,
        "x_bits":      x_bits,
        "y_bits":      y_bits,
        "equal":       equal,
        "result_text": f"{x} == {y} → {'True' if equal else 'False'}",
        "time_ms":     elapsed_ms,
        **result,
    })))


# ---------------------------------------------------------------------------
# Mandatory Circuit 3 — n-bit Ripple-Carry Addition
# ---------------------------------------------------------------------------

@pa20.route("/pa20/addition", methods=["POST"])
def pa20_addition():
    """
    n-bit secure addition: (x + y) mod 2^n.

    Request JSON:
      { "x": int, "y": int, "n": 4, "bits": 64 }

    Inputs are LSB-first for the adder circuit.
    """
    data = request.get_json() or {}
    n    = max(2, min(int(data.get("n", 4)), 8))
    bits = max(32, min(int(data.get("bits", 64)), 512))
    x    = int(data.get("x", 3)) & ((1 << n) - 1)
    y    = int(data.get("y", 5)) & ((1 << n) - 1)

    x_bits = _int_to_bits(x, n, msb_first=False)   # LSB-first
    y_bits = _int_to_bits(y, n, msb_first=False)

    circuit   = _build_adder(n)
    evaluator = GMWCircuit(circuit, ot_bits=bits)

    t0 = time.time()
    result = evaluator.evaluate(x_bits, y_bits)
    elapsed_ms = round((time.time() - t0) * 1000, 1)

    sum_bits  = result["outputs"]                   # LSB-first
    sum_int   = _bits_to_int(sum_bits, msb_first=False)
    expected  = (x + y) % (1 << n)
    correct   = sum_int == expected

    return jsonify(_make_serializable(_remap_result({
        "x":           x,
        "y":           y,
        "n":           n,
        "x_bits":      x_bits,
        "y_bits":      y_bits,
        "sum_int":     sum_int,
        "sum_bits":    sum_bits,
        "expected":    expected,
        "correct":     correct,
        "result_text": f"({x} + {y}) mod 2^{n} = {sum_int}",
        "time_ms":     elapsed_ms,
        **result,
    })))


# ---------------------------------------------------------------------------
# End-to-End Lineage Trace
# ---------------------------------------------------------------------------

@pa20.route("/pa20/lineage", methods=["GET"])
def pa20_lineage():
    """
    Demonstrate the full cryptographic lineage by evaluating one AND gate
    and timing each layer of the stack.

    Response JSON: { chain, timing_ms, ot_calls, description }
    """
    import os
    import sys

    # Run one AND gate and measure wall-clock time
    from mpc import _build_millionaire, GMWCircuit
    circuit = _build_millionaire(2)   # tiny 2-bit circuit for speed
    evaluator = GMWCircuit(circuit, ot_bits=64)

    t_total = time.time()
    result = evaluator.evaluate([1, 0], [0, 1])   # 2 > 1 → True
    elapsed_ms = round((time.time() - t_total) * 1000, 1)

    and_count = result["stats"]["and_gates"]

    chain = [
        {
            "layer": "PA#20",
            "module": "mpc.py / GMWCircuit.evaluate()",
            "role":  "Boolean circuit evaluator. Traverses gates in topological order.",
            "calls": "PA#19 for every AND gate.",
        },
        {
            "layer": "PA#19",
            "module": "secure_and.py / SecureAND.protocol()",
            "role":  "OT-based 2-party Secure AND gate (GMW sub-protocol).",
            "calls": "PA#18 OT12.run_protocol() for each cross-term.",
        },
        {
            "layer": "PA#18",
            "module": "ot.py / OT12.run_protocol()",
            "role":  "1-of-2 RSA-based Oblivious Transfer (EGL protocol).",
            "calls": "PA#12 RSA.keygen() once per OT setup.",
        },
        {
            "layer": "PA#12",
            "module": "rsa.py / RSA.keygen()",
            "role":  "Textbook RSA key generation (N=p·q, e=65537, d=e⁻¹ mod φ(N)).",
            "calls": "PA#13 gen_prime() × 2 to generate p and q.",
        },
        {
            "layer": "PA#13",
            "module": "miller_rabin.py / gen_prime()",
            "role":  "Miller-Rabin primality testing to generate RSA primes.",
            "calls": "Terminates the chain — no further crypto dependency.",
        },
    ]

    return jsonify({
        "description": (
            "Evaluating a single AND gate in PA#20 ultimately triggers "
            "PA#19 → PA#18 → PA#12 → PA#13, spanning the full cryptographic stack."
        ),
        "demo_circuit": "2-bit Millionaire's Problem (x=2, y=1 → x>y=True)",
        "and_gates_evaluated": and_count,
        "total_time_ms": elapsed_ms,
        "chain": chain,
        "security_foundation": (
            "The chain grounds MPC security in RSA hardness (PA#12/PA#18), "
            "which itself rests on difficulty of factoring large primes (PA#13). "
            "This is the essence of the cryptomania → MPC reduction."
        ),
    })

