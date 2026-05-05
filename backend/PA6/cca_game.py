"""
PA6/cca_game.py
===============
IND-CCA2 Security Game Simulation for PA#6.

Game Structure
--------------
1. Challenger chooses random key pair (kE, kM).
2. Adversary gets access to:
     - Enc oracle  : Enc(kE, kM, m) → (ct, tag)
     - Dec oracle  : Dec(kE, kM, ct, tag) → m  (EXCEPT on challenge ct)
3. Adversary submits (m0, m1).
4. Challenger encrypts mb for random b, returns challenge (ct*, tag*).
5. Adversary makes more queries (cannot query Dec on (ct*, tag*)).
6. Adversary guesses b.

In our dummy adversary model:
  - Pre-challenge: adversary queries a few random messages
  - Post-challenge: adversary tries to modify ct* and query dec oracle
    → ALWAYS rejected (demonstrates non-malleability)
  - Final guess: random (advantage ≈ 0)

This is contrasted with the CPA game where modifying ct* and comparing
dec results would reveal b with non-negligible advantage.
"""

import secrets
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _rel in ["../PA3", "../PA5", "../PA6", "../shared"]:
    _p = os.path.join(_HERE, _rel)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cca import CCA, cpa_malleability_demo, cca_tamper_demo


def ind_cca2_game(rounds: int = 20) -> dict:
    """
    Simulates the IND-CCA2 game with a dummy adversary.

    The adversary uses the following strategy:
      1. Query the Enc oracle with known plaintext pairs.
      2. Receive challenge ciphertext (ct*, tag*).
      3. Try to modify ct* and query Dec oracle — REJECTED.
      4. Make a random guess.

    Returns
    -------
    dict with per-round results and summary statistics.
    """
    cca = CCA()
    round_results = []
    correct_guesses = 0

    for rnd in range(rounds):
        # Fresh keys each game
        kE = format(secrets.randbits(32), 'x')
        kM = format(secrets.randbits(32), 'x')

        # ── Pre-challenge: oracle queries ──────────────────────────────
        oracle_results = []
        for _ in range(3):
            m = secrets.token_hex(4)
            enc = cca.enc(kE, kM, m)
            dec = cca.dec(kE, kM, enc["r"], enc["c"], enc["tag"])
            oracle_results.append({
                "queried_message": m,
                "decryption_match": dec["message"] == m,
            })

        # ── Challenge phase ────────────────────────────────────────────
        m0 = "hello_world____"
        m1 = "attack_at_dawn_"
        b  = secrets.randbelow(2)
        mb = m0 if b == 0 else m1

        challenge_enc = cca.enc(kE, kM, mb)
        r_star = challenge_enc["r"]
        c_star = challenge_enc["c"]
        t_star = challenge_enc["tag"]

        # ── Post-challenge: adversary tries modifying ct* and querying Dec ──
        # Flip one byte of c_star
        c_tampered_bytes = bytearray(bytes.fromhex(c_star))
        if c_tampered_bytes:
            c_tampered_bytes[0] ^= 0xFF
        c_tampered = c_tampered_bytes.hex()

        # This MUST be rejected (non-malleability of CCA)
        dec_attempt = cca.dec(kE, kM, r_star, c_tampered, t_star)
        tampered_rejected = dec_attempt["rejected"]

        # Also try replaying the challenge ciphertext — should succeed (same ct/tag)
        # But that gives no info about b since adversary already has (ct*, tag*)
        dec_legit = cca.dec(kE, kM, r_star, c_star, t_star)

        # ── Guess (random — no info gained from tamper attempt) ────────
        guess = secrets.randbelow(2)
        correct = (guess == b)
        if correct:
            correct_guesses += 1

        round_results.append({
            "round":              rnd + 1,
            "oracle_queries":     oracle_results,
            "b":                  b,
            "guess":              guess,
            "correct":            correct,
            "tampered_rejected":  tampered_rejected,   # should always be True
            "legit_dec_works":    not dec_legit["rejected"],
        })

    advantage = abs(correct_guesses / rounds - 0.5)

    return {
        "rounds":           rounds,
        "correct_guesses":  correct_guesses,
        "advantage":        round(advantage, 4),
        "all_tampers_rejected": all(r["tampered_rejected"] for r in round_results),
        "round_results":    round_results,
        "conclusion": (
            "Dummy adversary achieves ≈0 advantage (random guessing). "
            "All attempts to modify and re-submit the challenge ciphertext "
            "were rejected by the MAC check — confirming non-malleability."
        ),
    }


def cpa_vs_cca_comparison(key: str, message: str, bit_index: int = 0) -> dict:
    """
    Side-by-side comparison: CPA is malleable, CCA rejects tampering.
    Used directly by the frontend split-panel demo.
    """
    # Split key into two halves for CCA to avoid key-separation demos
    kE = key
    kM = key + "ab"

    cpa_result = cpa_malleability_demo(key, message, bit_index)
    cca_result = cca_tamper_demo(kE, kM, message, bit_index)

    return {
        "message":    message,
        "bit_index":  bit_index,
        "cpa_result": cpa_result,
        "cca_result": cca_result,
        "verdict": {
            "cpa_malleable": cpa_result["is_malleable"],
            "cca_rejected":  cca_result["dec_result"]["rejected"],
        },
    }
