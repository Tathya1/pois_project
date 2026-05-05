"""
PA1 package — One-Way Functions & Pseudorandom Generators
=========================================================
Public exports:
  DLP_OWF   — Discrete-log one-way function  f(x) = g^x mod p
  PRG       — Iterative hard-core-bit PRG     G(x0) = b(x0) || b(x1) || ...
  frequency_test, runs_test, serial_test — NIST SP 800-22 randomness tests

PA#1b backward direction (OWF from PRG):
  - Formal proof: backend/PA1/1b.md
  - Minimal demo: demo_inversion_hardness() in owf_from_prg.py
  - OWF_from_PRG class was over-engineered; commented out in owf_from_prg.py
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from owf import DLP_OWF
from prg import PRG
from owf_from_prg import demo_inversion_hardness
from tests import frequency_test, runs_test, serial_test

# OWF_from_PRG removed — spec only needed 1b.md + brief demo
# from owf_from_prg import OWF_from_PRG

__all__ = [
    "DLP_OWF",
    "PRG",
    "demo_inversion_hardness",
    "frequency_test",
    "runs_test",
    "serial_test",
]
