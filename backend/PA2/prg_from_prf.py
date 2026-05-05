import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(BASE_DIR, "../PA1"))

from prf import GGM_PRF

class PRG_from_PRF:
    def __init__(self):
        self.prf = GGM_PRF()

    def generate(self, seed, n=8):
        zero = "0" * n
        one = "1" * n

        left = self.prf.F(seed, zero)
        right = self.prf.F(seed, one)

        return left + right