import os
import sys
import random
import secrets

# Ensure paths are correct
_BASE = os.path.dirname(os.path.abspath(__file__))
_PA1  = os.path.join(_BASE, "../PA1")
for _p in [_PA1]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from prf import GGM_PRF
from prg_from_prf import PRG_from_PRF
from tests import frequency_test, runs_test, serial_test
from aes_prf import AES_PRF


class RandomOracle:
    def __init__(self):
        self._table = {}

    def query(self, x: str) -> str:
        if x not in self._table:
            self._table[x] = format(secrets.randbits(32), "08x")
        return self._table[x]


def distinguishing_game(q: int = 100) -> dict:
    prf = GGM_PRF()
    ro  = RandomOracle()
    key = random.randint(1, 2147483646) 

    prf_bits = ""
    rand_bits = ""

    for _ in range(q):
        x = "".join(random.choice("01") for _ in range(8))  
        
        pv = prf.F(key, x) # Result from GGM PRF
        rv = ro.query(x)   # Result from Random Oracle

        prf_bits  += bin(int(pv, 16))[2:].zfill(32)
        rand_bits += bin(int(rv, 16))[2:].zfill(32)

    prf_freq = frequency_test(prf_bits)
    rand_freq = frequency_test(rand_bits)
    
    print(f"\n=== PRF Distinguishing Game ({q} queries) ===")
    print(f"PRF  Freq p-value: {prf_freq['p_value']:.4f} -> {'PASS' if prf_freq['pass'] else 'FAIL'}")
    print(f"Rand Freq p-value: {rand_freq['p_value']:.4f} -> {'PASS' if rand_freq['pass'] else 'FAIL'}")
    
    return {"prf": prf_freq, "rand": rand_freq}

def prg_from_prf_statistical_test(n_seeds: int = 50):
    """
    PA#2b: Implement G(s) = Fs(0n) || Fs(1n).
    We test this by taking multiple random seeds, generating the 
    doubled output for each, and running NIST tests on the aggregate.
    """
    prg_builder = PRG_from_PRF()
    aggregated_bits = ""

    for _ in range(n_seeds):
        seed = random.randint(1, 2147483646)
        
        bits = prg_builder.generate(seed, n=8) 
        aggregated_bits += bits

    freq = frequency_test(aggregated_bits)
    runs = runs_test(aggregated_bits)
    serial = serial_test(aggregated_bits)

    print(f"\n=== PRG-from-PRF Statistical Test ({len(aggregated_bits)} bits) ===")
    print(f"Frequency: p={freq['p_value']:.4f} → {'PASS' if freq['pass'] else 'FAIL'}")
    print(f"Runs:      p={runs['p_value']:.4f} → {'PASS' if runs['pass'] else 'FAIL'}")

    return {"freq": freq, "runs": runs}

def run_substitution_test():
    print(f"\n--- Testing AES prf ---")
    prf_instance = AES_PRF()
    
    bits = ""
    key = random.randint(1, 2**32)
    for i in range(100):
        query = bin(i)[2:].zfill(8)
        out_hex = prf_instance.F(query)
        bits += bin(int(out_hex, 16))[2:].zfill(len(out_hex) * 4)

    freq = frequency_test(bits)
    runs = runs_test(bits)

    print(f"[AES] Frequency Test: {'✅ PASS' if freq['pass'] else '❌ FAIL'} (p={freq['p_value']:.4f})")
    print(f"[AES] Runs Test:      {'✅ PASS' if runs['pass'] else '❌ FAIL'} (p={runs['p_value']:.4f})")

    return freq['pass'] and runs['pass']

if __name__ == "__main__":
    distinguishing_game(q=100)
    prg_from_prf_statistical_test(n_seeds=100)
    run_substitution_test()