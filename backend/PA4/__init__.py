"""
PA4 package — Modes of Operation (CBC / OFB / CTR)
====================================================
Public exports:
  BlockModes — unified Encrypt/Decrypt/Trace for CBC, OFB, CTR
  MODES      — singleton instance (use directly)
  FeistelPRP — the 6-round Feistel PRP used as the block cipher
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

for _rel in ["../PA1", "../PA2", "../PA3"]:
    _p = os.path.join(_HERE, _rel)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from modes import BlockModes, MODES, FeistelPRP

__all__ = ["BlockModes", "MODES", "FeistelPRP"]
