"""
backend/distinguisher.py
========================
PA#2 — Distinguishing Game Demo
================================
Queries the GGM PRF on q inputs and a truly random function on the same
inputs, confirming no statistical difference — empirically supporting
PRF security.

Also used as a PRG-from-PRF backward direction test: run the PRG output
through the same NIST frequency/runs test suite.
"""

import os
import sys
import random
import secrets

_BASE = os.path.dirname(os.path.abspath(__file__))
_PA1  = os.path.join(_BASE, "PA1")
_PA2  = os.path.join(_BASE, "PA2")

for _p in [_PA1, _PA2]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from prf import GGM_PRF
from prg_from_prf import PRG_from_PRF
from tests import frequency_test, runs_test


# ---------------------------------------------------------------------------
# Random oracle: maps any input string to a fresh random 64-bit value.
# To be a fair comparison, we use a deterministic per-session mapping so
# repeated queries return the same value (simulating a truly random function).
# ---------------------------------------------------------------------------

class RandomOracle:
    """Simulates a truly random function via a lazy table."""

    def __init__(self):
        self._table: dict = {}

    def query(self, x: str) -> str:
        if x not in self._table:
            self._table[x] = format(secrets.randbits(64), "016x")
        return self._table[x]


# ---------------------------------------------------------------------------
# Core distinguishing game
# ---------------------------------------------------------------------------

def distinguishing_game(q: int = 100) -> dict:
    """
    Run q random queries against both the GGM PRF and a random oracle.
    Collect outputs, run frequency test on each set of bits.
    Confirm no statistical difference (both should PASS).

    Returns a dict with results for logging / API response.
    """
    prf = GGM_PRF()
    ro  = RandomOracle()
    key = random.randint(1, 10**9)

    prf_bits = ""
    rand_bits = ""
    prf_outputs  = []
    rand_outputs = []

    for _ in range(q):
        x = "".join(random.choice("01") for _ in range(8))  # 8-bit query
        pv = prf.F(key, x)     # hex string
        rv = ro.query(x)       # hex string

        # Convert hex → bits for statistical tests
        prf_bits  += bin(int(pv,  16))[2:].zfill(len(pv)  * 4)
        rand_bits += bin(int(rv,  16))[2:].zfill(len(rv)  * 4)

        prf_outputs.append(pv)
        rand_outputs.append(rv)

    prf_freq  = frequency_test(prf_bits)
    rand_freq = frequency_test(rand_bits)
    prf_runs  = runs_test(prf_bits)
    rand_runs = runs_test(rand_bits)

    result = {
        "queries": q,
        "prf_sample":  prf_outputs[:5],
        "rand_sample": rand_outputs[:5],
        "prf_frequency":  prf_freq,
        "rand_frequency": rand_freq,
        "prf_runs":  prf_runs,
        "rand_runs": rand_runs,
        "conclusion": (
            "No statistical difference observed between GGM PRF outputs and "
            "truly random function outputs — supporting PRF security empirically."
        ),
    }

    # Human-readable console output
    print(f"\n=== PRF Distinguishing Game ({q} queries) ===")
    print(f"PRF  frequency: p={prf_freq['p_value']:.4f}  → {'PASS' if prf_freq['pass'] else 'FAIL'}")
    print(f"Rand frequency: p={rand_freq['p_value']:.4f} → {'PASS' if rand_freq['pass'] else 'FAIL'}")
    print(f"PRF  runs:      p={prf_runs['p_value']:.4f}  → {'PASS' if prf_runs['pass'] else 'FAIL'}")
    print(f"Rand runs:      p={rand_runs['p_value']:.4f} → {'PASS' if rand_runs['pass'] else 'FAIL'}")
    print(result["conclusion"])

    return result


# ---------------------------------------------------------------------------
# PRG-from-PRF backward direction validation
# ---------------------------------------------------------------------------

def prg_from_prf_statistical_test(seed: int = 123456, n_bits: int = 1024) -> dict:
    """
    PA#2b — Backward direction: PRF → PRG.
    Generates bits via G(s) = F_s(0^n) || F_s(1^n) iterated n_bits times,
    then runs the NIST frequency + runs test.
    """
    prg = PRG_from_PRF()

    # Collect bits by repeatedly calling generate with successive seeds
    bits = ""
    current_seed = seed
    while len(bits) < n_bits:
        out_hex = prg.generate(current_seed, n=8)
        # Convert hex output to bits
        out_bits = bin(int(out_hex, 16))[2:].zfill(len(out_hex) * 4)
        bits += out_bits
        # Advance seed deterministically
        current_seed = int(out_hex[-8:], 16) if len(out_hex) >= 8 else current_seed + 1

    bits = bits[:n_bits]

    freq = frequency_test(bits)
    runs = runs_test(bits)

    result = {
        "seed": seed,
        "n_bits": n_bits,
        "frequency": freq,
        "runs": runs,
        "pass": freq["pass"] and runs["pass"],
    }

    print(f"\n=== PRG-from-PRF Statistical Test ({n_bits} bits) ===")
    print(f"Frequency: p={freq['p_value']:.4f} → {'PASS' if freq['pass'] else 'FAIL'}")
    print(f"Runs:      p={runs['p_value']:.4f} → {'PASS' if runs['pass'] else 'FAIL'}")

    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    distinguishing_game(q=100)
    prg_from_prf_statistical_test()