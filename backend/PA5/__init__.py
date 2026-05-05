"""
PA5 package — Message Authentication Codes (MACs)
=================================================
Public exports:
  PRF_MAC — Fixed-length MAC using the PRF directly.
  CBC_MAC — Variable-length MAC using CBC mode over the PRF.
  hmac_stub — Forward pointer to HMAC implementation (PA10).
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from mac import PRF_MAC, CBC_MAC, hmac_stub
from mac_game import euf_cma_game, length_extension_demo

__all__ = ["PRF_MAC", "CBC_MAC", "hmac_stub", "euf_cma_game", "length_extension_demo"]
