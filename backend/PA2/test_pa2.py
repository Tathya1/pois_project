import os
import sys
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA1"))

from prg_from_prf import PRG_from_PRF
from tests import frequency_test, runs_test, serial_test
from distinguisher import distinguishing_game, run_substitution_test

def prg_from_prf_statistical_test_bits(n_seeds: int = 50):
    prg_builder = PRG_from_PRF()
    aggregated_bits = ""

    for _ in range(n_seeds):
        seed = random.randint(1, 2147483646)
        hex_out = prg_builder.generate(seed, n=8)
        bits = bin(int(hex_out, 16))[2:].zfill(len(hex_out) * 4)
        aggregated_bits += bits

    freq = frequency_test(aggregated_bits)
    runs = runs_test(aggregated_bits)
    serial = serial_test(aggregated_bits)

    print(f"\n=== PRG-from-PRF Statistical Test ({len(aggregated_bits)} bits) ===")
    print(f"Frequency: p={freq['p_value']:.4f} → {'PASS' if freq['pass'] else 'FAIL'}")
    print(f"Runs:      p={runs['p_value']:.4f} → {'PASS' if runs['pass'] else 'FAIL'}")

    return {"freq": freq, "runs": runs, "serial": serial}


def main():
    prg_from_prf_statistical_test_bits()
    distinguishing_game(q=100)
    run_substitution_test()


if __name__ == "__main__":
    main()