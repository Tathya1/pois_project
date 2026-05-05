"""
PA2 package — Pseudorandom Functions (GGM Tree Construction)
=============================================================
Public exports:
  GGM_PRF      — Forward: PRG → PRF via GGM tree construction
  PRG_from_PRF — Backward: PRF → PRG via G(s) = F_s(0^n) || F_s(1^n)
  AES_PRF      — Concrete PRF using pure-Python AES-128 (no libraries)
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Also need PA1 on the path for GGM_PRF's dependency on PRG/OWF
_PA1 = os.path.join(_HERE, "..", "PA1")
if _PA1 not in sys.path:
    sys.path.insert(0, _PA1)

from prf import GGM_PRF
from prg_from_prf import PRG_from_PRF
from aes_prf import AES_PRF

__all__ = ["GGM_PRF", "PRG_from_PRF", "AES_PRF"]
