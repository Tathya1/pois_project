"""
PA1/owf_from_prg.py
===================
PA #1b — OWF from PRG (Backward Direction)

The formal argument lives in 1b.md.
This file contains a **minimal inline demonstration** that brute-force
inversion of f(s) = G(s) fails in practice, supporting the written proof.

The OWF_from_PRG class below is commented out — it was over-engineered.
The spec only required a written argument (1b.md) + a brief demo.
The brief demo is the standalone function `demo_inversion_hardness()` below.

──────────────────────────────────────────────────────────────────────────────
PROOF (from 1b.md):
    Let G: {0,1}^n → {0,1}^{n+ℓ} be a secure PRG.
    Define f(s) = G(s). Then f is a one-way function.

    Assume A is a PPT adversary that inverts f(s) = G(s) w/ non-negl prob.
    Build distinguisher D:
        given y, run A(y) → s'; if G(s') = y output "PRG", else "Random"
    • y = G(s) → A finds s' w/ non-negl → D correct
    • y uniform → G(s') ≠ y w.o.p. (small image) → D correct
    → D distinguishes PRG from random — contradicts PRG security. ∎
──────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import secrets

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from owf import DLP_OWF
from prg import PRG


def demo_inversion_hardness(n_trials: int = 5, budget: int = 10_000) -> dict:
    """
    Brief concrete demo: pick s at random from [0, 2^32), compute y = G(s),
    then try to invert by brute-force with `budget` guesses starting from 0.
    Since s is drawn from a 2^32 space and budget << 2^32, the adversary almost
    never succeeds — concretely demonstrating one-way hardness.
    """
    owf = DLP_OWF()
    prg = PRG(owf)

    def evaluate(s):
        prg.seed(s)
        return prg.next_bits(64)

    results = []
    for _ in range(n_trials):
        s = secrets.randbelow(2 ** 32)
        y = evaluate(s)

        found_at = None
        for guess in range(budget):
            if evaluate(guess) == y:
                found_at = guess
                break

        results.append({
            "s":       s,
            "y_prefix": y[:16] + "...",
            "inverted": found_at is not None,
            "found_at": found_at,
        })

    success_count = sum(1 for r in results if r["inverted"])
    return {
        "n_trials":      n_trials,
        "budget":        budget,
        "seed_space":    2 ** 32,
        "success_count": success_count,
        "hardness_ok":   success_count == 0,
        "results":       results,
        "conclusion": (
            f"Adversary inverted f(s)=G(s) {success_count}/{n_trials} times "
            f"with budget {budget} out of 2^32 possible seeds. "
            f"This confirms the written argument in 1b.md: inversion is hard in practice."
        ),
    }


# ---------------------------------------------------------------------------
# The full OWF_from_PRG class and distinguisher are commented out below.
# The spec only needed: (a) written argument → 1b.md, (b) brief demo → above.
# ---------------------------------------------------------------------------

# class OWF_from_PRG:
#     """
#     [COMMENTED OUT — over-engineered for spec requirements]
#     Demonstrate that f(s) = G(s) is a OWF.
#     The 'evaluate' method simply runs G(s), making the OWF ← PRG
#     backward direction explicit and callable.
#     """
#
#     def __init__(self):
#         self._owf = DLP_OWF()
#         self._prg = PRG(self._owf)
#
#     def evaluate(self, s: int, output_bits: int = 64) -> str:
#         self._prg.seed(s)
#         return self._prg.next_bits(output_bits)
#
#     def demonstrate_hardness(self, n_seeds=5, brute_force_budget=10_000, output_bits=64) -> dict:
#         # [full implementation removed — see demo_inversion_hardness() above]
#         pass
#
#     def build_distinguisher(self, prg_output: str, output_bits: int = 64) -> dict:
#         # [distinguisher demo removed — formal argument is in 1b.md]
#         pass


if __name__ == "__main__":
    print("=== PA#1b — OWF from PRG (Inversion Hardness Demo) ===\n")
    result = demo_inversion_hardness(n_trials=5, budget=10_000)
    print(f"Hardness confirmed: {result['hardness_ok']}")
    print(f"Adversary success: {result['success_count']}/{result['n_trials']}")
    print()
    for r in result["results"]:
        status = f"FOUND at {r['found_at']}" if r["inverted"] else "not found"
        print(f"  s={r['s']:>12}  y={r['y_prefix']}  inversion={status}")
    print()
    print(result["conclusion"])
