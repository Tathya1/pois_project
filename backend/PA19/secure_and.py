"""
PA#19 — Secure 2-Party AND Gate (OT-based, GMW-style)

Problem:
  Alice has private bit a ∈ {0,1}.
  Bob   has private bit b ∈ {0,1}.
  Goal: both parties learn a AND b, without either party revealing their input
  to the other.

Protocol (based on GMW / OT-based secret sharing):
  1. Alice samples random bit r_A (her output share).
  2. Alice prepares two OT messages:
         m_0 = r_A XOR (a AND 0) = r_A          (Bob's bit = 0)
         m_1 = r_A XOR (a AND 1) = r_A XOR a    (Bob's bit = 1)
     Note: m_{bob_b} = r_A XOR (a AND bob_b), so Bob receives r_B = r_A XOR (a AND b).
  3. Bob uses 1-of-2 OT (PA#18) with choice = b to receive m_b = r_B.
  4. Bob's output share: r_B.
     Alice's output share: r_A.
  5. Reconstruct: output = r_A XOR r_B = r_A XOR (r_A XOR (a AND b)) = a AND b.

Privacy:
  - Alice privacy: Bob receives m_b = r_A XOR (a AND b) via OT. 
    Without knowing r_A, Bob cannot determine a from r_B.
    (r_A is uniformly random → r_B is uniformly random regardless of a.)
  - Bob privacy: Alice never sees Bob's choice bit b (OT receiver privacy from PA#18).
    Alice only knows r_A; cannot determine b from r_A.

Correctness: r_A XOR r_B = a AND b  (always).

Dependency: PA#18 (ot.py) for the 1-of-2 OT sub-protocol.
"""

import os
import sys
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA18"))

from ot import OT12


class SecureAND:
    """
    Secure 2-party AND gate using 1-of-2 OT (PA#18).

    Output: additive XOR secret-sharing of a AND b.
    Reconstruction requires both parties to reveal their shares.
    """

    def __init__(self, ot_bits: int = 128):
        """
        Parameters
        ----------
        ot_bits : int
            RSA bit-length for the OT sub-protocol.
            128–256 is fine for demos; 2048 for real security.
        """
        self._ot     = OT12()
        self._ot_bits = ot_bits

    # ------------------------------------------------------------------
    # Full protocol
    # ------------------------------------------------------------------

    def protocol(self, alice_bit: int, bob_bit: int) -> dict:
        """
        Run the full secure AND protocol.

        Parameters
        ----------
        alice_bit : int  Alice's private bit (0 or 1)
        bob_bit   : int  Bob's   private bit (0 or 1)

        Returns
        -------
        dict with: alice_bit, bob_bit, expected_output, actual_output,
                   correct, trace, security
        """
        assert alice_bit in (0, 1), "Alice's bit must be 0 or 1"
        assert bob_bit   in (0, 1), "Bob's bit must be 0 or 1"

        # -- Step 1: Alice samples random output share --
        r_A = secrets.randbelow(2)   # ∈ {0, 1}

        # -- Step 2: Alice prepares OT messages --
        m_0 = bytes([r_A])                  # Bob receives this if b=0
        m_1 = bytes([r_A ^ alice_bit])      # Bob receives this if b=1
        # In both cases Bob receives r_A XOR (a AND b)

        # -- Step 3: Run 1-of-2 OT (PA#18) --
        setup    = self._ot.sender_setup(self._ot_bits)
        N, e, d  = setup["N"], setup["e"], setup["d"]
        x0, x1   = setup["x0"], setup["x1"]

        query    = self._ot.receiver_query(N, e, x0, x1, bob_bit)
        v, k     = query["v"], query["k"]

        response = self._ot.sender_respond(N, d, x0, x1, v, m_0, m_1)

        r_B_bytes = self._ot.receiver_decrypt(
            bob_bit, k, response["m0_enc"], response["m1_enc"]
        )
        r_B = r_B_bytes[0] if r_B_bytes else 0

        # -- Step 4: Reconstruct --
        actual_output   = r_A ^ r_B
        expected_output = alice_bit & bob_bit

        return {
            "alice_bit":      alice_bit,
            "bob_bit":        bob_bit,
            "expected_output": expected_output,
            "actual_output":   actual_output,
            "correct":         actual_output == expected_output,
            "trace": {
                "step1_alice_share": {
                    "r_A":  r_A,
                    "note": "Alice samples random bit r_A — her secret output share.",
                },
                "step2_alice_ot_messages": {
                    "m_0": r_A,
                    "m_1": r_A ^ alice_bit,
                    "note": (
                        f"m_0 = r_A = {r_A}  (sent if Bob's bit=0)\n"
                        f"m_1 = r_A ⊕ a = {r_A ^ alice_bit}  (sent if Bob's bit=1)\n"
                        f"→ Bob always gets r_A ⊕ (a AND b) = {r_A} ⊕ "
                        f"({alice_bit} AND {bob_bit}) = {r_A ^ (alice_bit & bob_bit)}"
                    ),
                },
                "step3_ot_execution": {
                    "ot_choice": bob_bit,
                    "bob_received_r_B": r_B,
                    "k0": str(response["k0"]),
                    "k1": str(response["k1"]),
                    "note": (
                        f"1-of-2 OT with Bob's choice={bob_bit}. "
                        f"Bob receives m_{bob_bit} = {r_B} = r_A ⊕ (a AND b)."
                    ),
                },
                "step4_reconstruct": {
                    "alice_share_r_A": r_A,
                    "bob_share_r_B":   r_B,
                    "output":          actual_output,
                    "note": (
                        f"r_A ⊕ r_B = {r_A} ⊕ {r_B} = {actual_output} "
                        f"= {alice_bit} AND {bob_bit} ✓"
                        if actual_output == expected_output
                        else "ERROR: shares did not reconstruct correctly"
                    ),
                },
            },
            "security": {
                "alice_privacy": (
                    f"Bob received r_B={r_B} (= r_A ⊕ (a AND b)) via OT. "
                    "r_A is uniformly random → r_B reveals nothing about a."
                ),
                "bob_privacy": (
                    f"Alice never sees Bob's OT choice bit. "
                    "Alice only holds r_A; cannot determine b from r_A alone."
                ),
            },
        }

    # ------------------------------------------------------------------
    # Verify all 4 AND combinations
    # ------------------------------------------------------------------

    def truth_table(self) -> list:
        """
        Run the secure AND protocol for all 4 input combinations and
        return a truth table with correctness verification.
        """
        rows = []
        for a in (0, 1):
            for b in (0, 1):
                result = self.protocol(a, b)
                rows.append({
                    "a": a, "b": b,
                    "expected": a & b,
                    "computed": result["actual_output"],
                    "correct":  result["correct"],
                })
        return rows

    # ------------------------------------------------------------------
    # Secure XOR (free — no OT needed)
    # ------------------------------------------------------------------

    def secure_xor(self, alice_bit: int, bob_bit: int) -> dict:
        """
        Secure XOR over Z₂ (free — only 1 random bit of communication).

        Protocol (additive secret sharing):
          1. Alice samples random r ← {0,1}.
          2. Alice sends r to Bob (only message in this protocol).
          3. Alice's output share: a ⊕ r.
             Bob's output share:   b ⊕ r.
          4. Reconstruction: (a⊕r) ⊕ (b⊕r) = a ⊕ b.

        Privacy:
          - Bob receives r (uniformly random) — reveals nothing about a.
          - Alice never sees b — learns nothing about b.
          No OT calls required.
        """
        assert alice_bit in (0, 1), "Alice's bit must be 0 or 1"
        assert bob_bit   in (0, 1), "Bob's bit must be 0 or 1"

        r            = secrets.randbelow(2)
        alice_share  = alice_bit ^ r
        bob_share    = bob_bit   ^ r
        xor_output   = alice_share ^ bob_share     # = alice_bit ^ bob_bit
        expected     = alice_bit ^ bob_bit

        return {
            "alice_bit":       alice_bit,
            "bob_bit":         bob_bit,
            "expected_output": expected,
            "actual_output":   xor_output,
            "correct":         xor_output == expected,
            "ot_calls":        0,
            "trace": {
                "step1_alice_mask": {
                    "r":    r,
                    "note": (
                        f"Alice samples random mask r={r} and sends it to Bob. "
                        "Bob cannot determine a from r alone."
                    ),
                },
                "step2_shares": {
                    "alice_share": alice_share,
                    "bob_share":   bob_share,
                    "note": (
                        f"Alice's share = a⊕r = {alice_bit}⊕{r} = {alice_share}. "
                        f"Bob's share   = b⊕r = {bob_bit}⊕{r} = {bob_share}."
                    ),
                },
                "step3_reconstruct": {
                    "alice_share": alice_share,
                    "bob_share":   bob_share,
                    "output":      xor_output,
                    "note": (
                        f"{alice_share} ⊕ {bob_share} = {xor_output} "
                        f"= {alice_bit} ⊕ {bob_bit} ✓"
                        if xor_output == expected
                        else "ERROR: reconstruction mismatch"
                    ),
                },
            },
            "security": {
                "alice_privacy": (
                    f"Bob receives only r={r} (uniform random bit). "
                    "He cannot determine a from r alone."
                ),
                "bob_privacy": (
                    "Alice never communicates with Bob about b. "
                    "Alice only holds alice_share = a⊕r; cannot determine b."
                ),
                "no_ot_needed": (
                    "XOR is free in GMW: only 1 bit of communication. "
                    "No public-key operations required."
                ),
            },
        }

    # ------------------------------------------------------------------
    # Secure NOT (free — no communication)
    # ------------------------------------------------------------------

    def secure_not(self, alice_bit: int) -> dict:
        """
        Secure NOT (free — zero communication required).

        Alice holds bit a. She locally flips her share: NOT(a) = a ⊕ 1 = 1 − a.
        No message to Bob; no OT call. Trivially private.
        """
        assert alice_bit in (0, 1), "Alice's bit must be 0 or 1"

        not_output = 1 - alice_bit

        return {
            "alice_bit":       alice_bit,
            "expected_output": not_output,
            "actual_output":   not_output,
            "correct":         True,
            "ot_calls":        0,
            "trace": {
                "step1_alice_flips": {
                    "input":  alice_bit,
                    "output": not_output,
                    "note": (
                        f"Alice locally computes NOT({alice_bit}) = {not_output}. "
                        "Zero communication with Bob."
                    ),
                },
            },
            "security": {
                "no_communication": (
                    "NOT requires zero interaction. "
                    "No information is exchanged — trivially private."
                ),
            },
        }

    # ------------------------------------------------------------------
    # XOR truth table (all 4 combos)
    # ------------------------------------------------------------------

    def truth_table_xor(self) -> list:
        """Run Secure_XOR for all 4 input combinations."""
        rows = []
        for a in (0, 1):
            for b in (0, 1):
                result = self.secure_xor(a, b)
                rows.append({
                    "a": a, "b": b,
                    "expected": a ^ b,
                    "computed": result["actual_output"],
                    "correct":  result["correct"],
                })
        return rows

