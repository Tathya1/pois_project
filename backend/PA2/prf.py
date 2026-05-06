import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(BASE_DIR, "../PA1"))

from prg import PRG
from owf import DLP_OWF

class GGM_PRF:
    def __init__(self):
        self.owf = DLP_OWF()

    def F(self, k, x):
        """
        k: key (the initial seed, an integer or decimal string)
        x: bit string input (the 'path' in the tree)
        """
        prg = PRG(self.owf)
        
        state = int(k) % self.owf.p

        for bit in x:
            prg.seed(str(state))
            
            out = prg.next_bits(128)

            left_bits = out[:64]
            right_bits = out[64:]
            mask = (1 << 64) - 1

            if bit == '0':
                state = int(left_bits, 2) & mask
            else:
                state = int(right_bits, 2) & mask

        return format(state, '016x')