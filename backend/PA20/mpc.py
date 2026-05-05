"""
PA#20 — Secure 2-Party MPC (GMW Protocol for Boolean Circuits)

Problem:
  Alice has private inputs A = (a_0, a_1, ...) ∈ {0,1}^n.
  Bob   has private inputs B = (b_0, b_1, ...) ∈ {0,1}^m.
  They want to evaluate a shared boolean circuit f(A, B) without
  either party learning the other's inputs beyond what f reveals.

Protocol: GMW (Goldreich-Micali-Wigderson) for 2-party computation.

Gate types:
  - XOR gate: "free" — each party locally XORs their wire shares.
  - AND gate: costs one 1-of-2 OT (PA#19 secure AND sub-protocol).
  - NOT gate: "free" — one party flips their share (convention: Alice).
  - CONST gate: output is a known constant (no secret sharing needed).

Wire representation:
  Each wire w has a secret XOR sharing: w = w_A ⊕ w_B,
  where w_A is Alice's share and w_B is Bob's share.
  The actual wire value w is only known after both parties reveal
  their shares (at the output wires).

Circuit format (dict):
  {
    "n_alice": int,              ← number of Alice's input wires
    "n_bob":   int,              ← number of Bob's input wires
    "gates": [
      { "type": "AND"|"XOR"|"NOT", "in": [w1, w2], "out": w3 },
      ...
    ],
    "outputs": [w_out, ...]     ← output wire indices
  }
  Wire indices:
    0 .. n_alice-1          → Alice's inputs
    n_alice .. n_alice+n_bob-1 → Bob's inputs
    n_alice+n_bob ..         → gate outputs (assigned in order)

Dependency: PA#19 (secure_and.py) for AND gates.
"""

import os
import sys
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA19"))

from secure_and import SecureAND


# ---------------------------------------------------------------------------
# Helper: secret-share a single bit
# ---------------------------------------------------------------------------

def _share_bit(bit: int) -> tuple[int, int]:
    """
    Create an additive XOR sharing of a bit: (share_A, share_B) with share_A XOR share_B = bit.
    """
    s = secrets.randbelow(2)
    return s, s ^ bit


# ---------------------------------------------------------------------------
# GMW circuit evaluator
# ---------------------------------------------------------------------------

class GMWCircuit:
    """
    2-party GMW protocol evaluator for small boolean circuits.

    Usage:
      circuit = {
          "n_alice": 2, "n_bob": 2,
          "gates": [
              {"type": "AND", "in": [0, 2], "out": 4},
              {"type": "XOR", "in": [1, 3], "out": 5},
              {"type": "XOR", "in": [4, 5], "out": 6},
          ],
          "outputs": [6]
      }
      evaluator = GMWCircuit(circuit)
      result = evaluator.evaluate(alice_inputs=[1, 0], bob_inputs=[1, 1])
    """

    def __init__(self, circuit: dict, ot_bits: int = 128):
        self.circuit  = circuit
        self._and_engine = SecureAND(ot_bits=ot_bits)

    def evaluate(self, alice_inputs: list, bob_inputs: list) -> dict:
        """
        Evaluate the circuit on Alice's and Bob's private inputs.

        Returns
        -------
        dict with: alice_inputs, bob_inputs, outputs, wire_values (after reconstruction),
                   gate_trace, and security annotation.
        """
        n_alice = self.circuit["n_alice"]
        n_bob   = self.circuit["n_bob"]
        gates   = self.circuit["gates"]
        outputs = self.circuit["outputs"]

        assert len(alice_inputs) == n_alice
        assert len(bob_inputs)   == n_bob

        # Total wires = inputs + one per gate
        n_wires = n_alice + n_bob + len(gates)
        alice_shares = [0] * n_wires
        bob_shares   = [0] * n_wires

        # -- Input sharing --
        input_shares = {}
        for i, bit in enumerate(alice_inputs):
            a_s, b_s = _share_bit(bit)
            alice_shares[i] = a_s
            bob_shares[i]   = b_s
            input_shares[i] = {"alice": a_s, "bob": b_s, "value": bit, "owner": "Alice"}

        for j, bit in enumerate(bob_inputs):
            idx = n_alice + j
            a_s, b_s = _share_bit(bit)
            alice_shares[idx] = a_s
            bob_shares[idx]   = b_s
            input_shares[idx] = {"alice": a_s, "bob": b_s, "value": bit, "owner": "Bob"}

        gate_trace = []

        # -- Gate evaluation --
        for gate_idx, gate in enumerate(gates):
            gtype = gate["type"].upper()
            in_wires  = gate["in"]
            out_wire  = gate["out"]

            if gtype == "XOR":
                # Free: each party XORs their shares locally
                a_s = alice_shares[in_wires[0]] ^ alice_shares[in_wires[1]]
                b_s = bob_shares[in_wires[0]]   ^ bob_shares[in_wires[1]]
                alice_shares[out_wire] = a_s
                bob_shares[out_wire]   = b_s
                gate_trace.append({
                    "gate": gate_idx, "type": "XOR",
                    "in_wires": in_wires, "out_wire": out_wire,
                    "in_values": [
                        alice_shares[in_wires[0]] ^ bob_shares[in_wires[0]],
                        alice_shares[in_wires[1]] ^ bob_shares[in_wires[1]],
                    ],
                    "out_value": a_s ^ b_s,
                    "cost": "free (local XOR)",
                })

            elif gtype == "AND":
                # Requires OT sub-protocol (PA#19)
                # Wire values (for trace)
                w0 = alice_shares[in_wires[0]] ^ bob_shares[in_wires[0]]
                w1 = alice_shares[in_wires[1]] ^ bob_shares[in_wires[1]]

                # Alice's private share values on the input wires
                alice_a = alice_shares[in_wires[0]]
                alice_b = alice_shares[in_wires[1]]
                bob_a   = bob_shares[in_wires[0]]
                bob_b   = bob_shares[in_wires[1]]

                # Compute (alice_share_0 AND alice_share_1),
                # (alice_share_0 AND bob_share_1),
                # (bob_share_0 AND alice_share_1),
                # (bob_share_0 AND bob_share_1)  via secure AND:

                # GMW AND: c = (a0⊕b0) AND (a1⊕b1)
                # = (a0 AND a1) ⊕ (a0 AND b1) ⊕ (b0 AND a1) ⊕ (b0 AND b1)
                # Alice computes locally: a0 AND a1
                # Uses OT for cross terms: a0 AND b1,  b0 AND a1
                # Bob computes locally: b0 AND b1

                local_alice = alice_a & alice_b          # Alice local
                local_bob   = bob_a   & bob_b            # Bob local

                # Cross term 1: secure_and(alice_a, bob_b) — Alice has a0, Bob has b1
                ct1 = self._and_engine.protocol(alice_a, bob_b)
                ct1_result = ct1["actual_output"]

                # Cross term 2: secure_and(bob_a, alice_b) — Alice has b0 (acting as "a"), Bob has a1 (acting as "b")
                ct2 = self._and_engine.protocol(bob_a, alice_b)
                ct2_result = ct2["actual_output"]

                # XOR all four terms
                out_share = local_alice ^ ct1_result ^ ct2_result ^ local_bob

                # Distribute new output sharing
                a_s, b_s = _share_bit(out_share)
                alice_shares[out_wire] = a_s
                bob_shares[out_wire]   = b_s

                gate_trace.append({
                    "gate": gate_idx, "type": "AND",
                    "in_wires": in_wires, "out_wire": out_wire,
                    "in_values": [w0, w1],
                    "out_value": w0 & w1,
                    "computed":  out_share,
                    "correct":   out_share == (w0 & w1),
                    "cost": "1 OT sub-protocol (PA#19)",
                })

            elif gtype == "NOT":
                # Free: one party (Alice) flips her share
                a_s = alice_shares[in_wires[0]] ^ 1
                b_s = bob_shares[in_wires[0]]
                alice_shares[out_wire] = a_s
                bob_shares[out_wire]   = b_s
                gate_trace.append({
                    "gate": gate_idx, "type": "NOT",
                    "in_wires": in_wires, "out_wire": out_wire,
                    "in_value":  alice_shares[in_wires[0]] ^ bob_shares[in_wires[0]],
                    "out_value": a_s ^ b_s,
                    "cost": "free (Alice flips share)",
                })

            else:
                raise ValueError(f"Unknown gate type: {gtype}")

        # -- Reconstruct output wires --
        output_values = []
        wire_recon = {}
        for w in outputs:
            val = alice_shares[w] ^ bob_shares[w]
            output_values.append(val)
            wire_recon[w] = {"alice_share": alice_shares[w],
                              "bob_share":   bob_shares[w],
                              "value":        val}

        and_gate_count = sum(1 for g in gates if g["type"].upper() == "AND")
        xor_gate_count = sum(1 for g in gates if g["type"].upper() == "XOR")
        not_gate_count = sum(1 for g in gates if g["type"].upper() == "NOT")

        return {
            "alice_inputs": alice_inputs,
            "bob_inputs":   bob_inputs,
            "outputs":      output_values,
            "gate_trace":   gate_trace,
            "output_wires": wire_recon,
            "stats": {
                "total_gates": len(gates),
                "and_gates":   and_gate_count,
                "xor_gates":   xor_gate_count,
                "not_gates":   not_gate_count,
                "ot_calls":    and_gate_count,
                "free_gates":  xor_gate_count + not_gate_count,
            },
            "security": (
                "GMW guarantees: neither party learns the other's inputs beyond "
                "what the output f(A, B) reveals. XOR gates are free; each AND "
                "gate costs one OT (PA#19). Privacy follows from PA#18/PA#19."
            ),
        }


# ---------------------------------------------------------------------------
# Pre-built demo circuits
# ---------------------------------------------------------------------------

def _circuit_and_xor() -> dict:
    """
    f(a0, a1, b0, b1) = (a0 AND b0) XOR (a1 AND b1)
    
    Wires: a0=0, a1=1, b0=2, b1=3
    Gates:
      AND(0,2)→4  : a0 AND b0
      AND(1,3)→5  : a1 AND b1
      XOR(4,5)→6  : output
    """
    return {
        "name": "(a0 AND b0) XOR (a1 AND b1)",
        "description": "2-bit inner product mod 2 — checks if any matching pair of bits are both 1",
        "n_alice": 2,
        "n_bob":   2,
        "gates": [
            {"type": "AND", "in": [0, 2], "out": 4},
            {"type": "AND", "in": [1, 3], "out": 5},
            {"type": "XOR", "in": [4, 5], "out": 6},
        ],
        "outputs": [6],
    }


def _circuit_majority() -> dict:
    """
    Majority gate: maj(a, b, c) = (a AND b) OR (a AND c) OR (b AND c)
                                = (a AND b) XOR (a AND c) XOR (b AND c)
                                  (since at most one OR operand is true when exactly two agree)
    Wait: let's do maj(a, b0, b1):
      = (a AND b0) XOR (a AND b1) XOR (b0 AND b1)
    Wires: a=0, b0=1, b1=2 (Alice has a, Bob has b0, b1)
    Gates:
      AND(0,1)→3
      AND(0,2)→4
      AND(1,2)→5
      XOR(3,4)→6
      XOR(6,5)→7  output
    """
    return {
        "name": "maj(a, b0, b1)",
        "description": "Majority of 3 bits: Alice has 1 bit, Bob has 2 bits",
        "n_alice": 1,
        "n_bob":   2,
        "gates": [
            {"type": "AND", "in": [0, 1], "out": 3},
            {"type": "AND", "in": [0, 2], "out": 4},
            {"type": "AND", "in": [1, 2], "out": 5},
            {"type": "XOR", "in": [3, 4], "out": 6},
            {"type": "XOR", "in": [6, 5], "out": 7},
        ],
        "outputs": [7],
    }


def _circuit_equality() -> dict:
    """
    Equality check: (a XOR b) XNOR 0  = NOT(a XOR b) = equality of two bits.
    Alice has a, Bob has b; output = 1 iff a == b.
    Wires: a=0, b=1
    Gates:
      XOR(0,1)→2   : a XOR b
      NOT(2)→3      : NOT(a XOR b) = (a == b)
    """
    return {
        "name": "a == b",
        "description": "1-bit equality check: output 1 iff Alice's bit equals Bob's bit",
        "n_alice": 1,
        "n_bob":   1,
        "gates": [
            {"type": "XOR", "in": [0, 1], "out": 2},
            {"type": "NOT", "in": [2],    "out": 3},
        ],
        "outputs": [3],
    }


# ---------------------------------------------------------------------------
# Circuit builder helper (for programmatic construction)
# ---------------------------------------------------------------------------

class _CB:
    """Fluent circuit builder — tracks wire indices automatically."""

    def __init__(self, n_alice: int, n_bob: int):
        self.n_alice = n_alice
        self.n_bob   = n_bob
        self.gates: list = []
        self._w = n_alice + n_bob

    def _next(self) -> int:
        w = self._w; self._w += 1; return w

    def xor(self, a: int, b: int) -> int:
        w = self._next()
        self.gates.append({"type": "XOR", "in": [a, b], "out": w})
        return w

    def and_(self, a: int, b: int) -> int:
        w = self._next()
        self.gates.append({"type": "AND", "in": [a, b], "out": w})
        return w

    def not_(self, a: int) -> int:
        w = self._next()
        self.gates.append({"type": "NOT", "in": [a], "out": w})
        return w

    def or_(self, a: int, b: int) -> int:
        """OR(a,b) = (a XOR b) XOR (a AND b)  — costs 1 AND gate."""
        xab = self.xor(a, b)
        aab = self.and_(a, b)
        return self.xor(xab, aab)

    def build(self, name: str, description: str, outputs: list) -> dict:
        return {
            "name":        name,
            "description": description,
            "n_alice":     self.n_alice,
            "n_bob":       self.n_bob,
            "gates":       list(self.gates),
            "outputs":     outputs,
        }


# ---------------------------------------------------------------------------
# Mandatory circuit 1 — Millionaire's Problem (x > y, n-bit)
# ---------------------------------------------------------------------------

def _build_millionaire(n: int = 4) -> dict:
    """
    Millionaire's Problem: x > y for n-bit integers.

    Alice: x[0..n-1] MSB-first (wire 0 = x MSB).
    Bob:   y[0..n-1] MSB-first (wire n = y MSB).

    Ripple comparator from MSB to LSB.
    Maintain gt ("x greater so far") and eq ("equal so far").
    At each bit i:
        gi      = x[i] AND NOT(y[i])            ← x wins at this bit
        eq_i    = NOT(x[i] XOR y[i])            ← equal at this bit
        contrib = eq AND gi                      ← equal above AND x wins here
        gt      = OR(gt, contrib)               ← update greater flag
        eq      = eq AND eq_i                   ← update equal flag

    AND gates = 1 + (n-1)*4   (for n=4: 13 AND gates = 13 OT calls)
    """
    assert n >= 2
    cb = _CB(n, n)

    # Bit 0 (MSB) — initialise gt and eq
    not_y0 = cb.not_(n)            # NOT(y[0])
    gt     = cb.and_(0, not_y0)    # x[0] AND NOT(y[0])
    d0     = cb.xor(0, n)          # x[0] XOR y[0]
    eq     = cb.not_(d0)           # XNOR = equal at bit 0

    for i in range(1, n):
        xi      = i
        yi      = n + i
        not_yi  = cb.not_(yi)
        gi      = cb.and_(xi, not_yi)    # x[i] wins at bit i
        di      = cb.xor(xi, yi)
        ei      = cb.not_(di)            # equal at bit i
        contrib = cb.and_(eq, gi)        # prior-equal AND x wins here
        gt      = cb.or_(gt, contrib)    # new greater
        eq      = cb.and_(eq, ei)        # new equal

    return cb.build(
        f"millionaire_{n}bit",
        f"{n}-bit Millionaire's Problem: x > y  "
        f"(Alice→x MSB-first, Bob→y MSB-first; "
        f"OT calls = 1+{n-1}×4 = {1+(n-1)*4})",
        [gt],
    )


# ---------------------------------------------------------------------------
# Mandatory circuit 2 — n-bit Secure Equality (x == y)
# ---------------------------------------------------------------------------

def _build_equality_n(n: int = 4) -> dict:
    """
    n-bit equality: x == y.

    Alice: x[0..n-1].  Bob: y[0..n-1].
    diff_i    = x[i] XOR y[i]           (n free XOR gates)
    any_diff  = OR(diff_0, …, diff_{n-1})  (n-1 AND gates via OR=XOR+AND+XOR)
    equal     = NOT(any_diff)             (1 free NOT gate)

    AND gates = n-1   (for n=4: 3 OT calls)
    """
    cb    = _CB(n, n)
    diffs = [cb.xor(i, n + i) for i in range(n)]   # n free XOR gates
    any_diff = diffs[0]
    for i in range(1, n):
        any_diff = cb.or_(any_diff, diffs[i])        # n-1 AND gates
    equal = cb.not_(any_diff)
    return cb.build(
        f"equality_{n}bit",
        f"{n}-bit Equality: x == y  "
        f"(Alice→x, Bob→y, bit-indexed 0=MSB; OT calls = {n-1})",
        [equal],
    )


# ---------------------------------------------------------------------------
# Mandatory circuit 3 — n-bit Ripple-Carry Adder (x + y mod 2^n)
# ---------------------------------------------------------------------------

def _build_adder(n: int = 4) -> dict:
    """
    n-bit ripple-carry adder: (x + y) mod 2^n.

    Alice: x[0..n-1] LSB-first.  Bob: y[0..n-1] LSB-first.
    Outputs: sum[0..n-1] LSB-first.

    Half adder  (bit 0):  1 AND gate.
    Full adder  (bits 1..n-2): 3 AND gates each (carry uses OR = 1 AND).
    Last bit    (bit n-1): 0 AND (only sum needed, carry discarded).

    AND gates = 1 + 3*(n-2)   (for n=4: 7 OT calls)
    """
    assert n >= 2
    cb   = _CB(n, n)
    outs = []

    # Bit 0 — half adder
    s0    = cb.xor(0, n)
    carry = cb.and_(0, n)
    outs.append(s0)

    # Bits 1..n-2 — full adder (need carry-out)
    for i in range(1, n - 1):
        xi    = i
        yi    = n + i
        s     = cb.xor(xi, yi)
        si    = cb.xor(s, carry)       # sum bit i
        c_ab  = cb.and_(xi, yi)
        c_sc  = cb.and_(s, carry)
        carry = cb.or_(c_ab, c_sc)     # carry out (1 extra AND)
        outs.append(si)

    # Bit n-1 — only sum needed (mod 2^n discards carry out)
    x_msb = n - 1
    y_msb = n + n - 1
    s_top = cb.xor(x_msb, y_msb)
    outs.append(cb.xor(s_top, carry))

    and_count = 1 + 3 * (n - 2)
    return cb.build(
        f"adder_{n}bit",
        f"{n}-bit Ripple-Carry Adder: (x + y) mod 2^{n}  "
        f"(Alice→x LSB-first, Bob→y LSB-first; OT calls = {and_count})",
        outs,
    )


# ---------------------------------------------------------------------------
# Circuit registry
# ---------------------------------------------------------------------------

DEMO_CIRCUITS = {
    # Legacy / basic demos
    "and_xor":      _circuit_and_xor(),
    "majority":     _circuit_majority(),
    "equality":     _circuit_equality(),       # 1-bit equality
    # Three mandatory circuits (spec §5.3)
    "millionaire":  _build_millionaire(4),     # 4-bit Millionaire's
    "equality_n":   _build_equality_n(4),      # 4-bit n-bit equality
    "adder":        _build_adder(4),           # 4-bit ripple-carry adder
}

