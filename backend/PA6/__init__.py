"""
PA6 package — CCA-Secure Symmetric Encryption
==============================================
Public exports:
  CCA               — Encrypt-then-MAC construction (PA#3 CPA + PA#5 CBC-MAC)
  cpa_malleability_demo — Shows CPA scheme is malleable
  cca_tamper_demo       — Shows CCA scheme rejects tampered ciphertexts
  key_separation_demo   — Shows why kE ≠ kM is required
  ind_cca2_game         — IND-CCA2 game simulation with dummy adversary
  cpa_vs_cca_comparison — Side-by-side CPA vs CCA demo
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

for _rel in ["../PA3", "../PA5", "../shared"]:
    _p = os.path.join(_HERE, _rel)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cca import CCA, cpa_malleability_demo, cca_tamper_demo, key_separation_demo
from cca_game import ind_cca2_game, cpa_vs_cca_comparison

__all__ = [
    "CCA",
    "cpa_malleability_demo",
    "cca_tamper_demo",
    "key_separation_demo",
    "ind_cca2_game",
    "cpa_vs_cca_comparison",
]
