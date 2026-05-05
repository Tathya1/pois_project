"""
PA3 package — CPA-Secure Symmetric Encryption
==============================================
Public exports:
  CPA   — Enc(k,m)→(r,c) and Dec(k,r,c)→m using PRF-based CTR construction
  simulate_ind_cpa_dummy — IND-CPA game with dummy adversary (advantage ≈ 0)
  simulate_rounds        — IND-CPA game with/without nonce reuse
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

_PA2 = os.path.join(_HERE, "..", "PA2")
_PA1 = os.path.join(_HERE, "..", "PA1")
for _p in [_PA2, _PA1]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cpa import CPA
from cpa_game import simulate_ind_cpa_dummy, simulate_rounds

__all__ = ["CPA", "simulate_ind_cpa_dummy", "simulate_rounds"]
