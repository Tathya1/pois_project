"""
PA6/cca.py
==========
PA #6 — CCA-Secure Symmetric Encryption (Encrypt-then-MAC)
===========================================================

Construction
------------
  Enc(kE, kM, m):
    1. (r, c) = CPA.enc(kE, m)          # CPA-secure encryption (PA#3)
    2. ct     = r_hex || c_hex           # combined ciphertext bytes
    3. tag    = MAC.mac(kM, ct)          # authenticate the CIPHERTEXT (PA#5)
    4. return (ct_hex, tag)

  Dec(kE, kM, ct_hex, tag):
    1. if not MAC.verify(kM, ct_hex, tag): return None  (⊥ reject)
    2. split ct_hex → r_hex, c_hex
    3. return CPA.dec(kE, r_hex, c_hex)

Security argument
-----------------
Any adversary that wins IND-CCA2 must either:
  (a) forge a valid MAC tag on a modified ciphertext — breaks EUF-CMA of the MAC, or
  (b) win the IND-CPA game without modifying the ciphertext — breaks CPA security.
Both are computationally infeasible → CCA is secure.

Malleability of raw CPA (PA#3) is also demonstrated here for contrast.
"""

import os
import sys

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PA3    = os.path.join(_HERE, "..", "PA3")
_PA5    = os.path.join(_HERE, "..", "PA5")
_SHARED = os.path.join(_HERE, "..", "shared")

for _p in [_HERE, _PA3, _PA5, _SHARED]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cpa import CPA
from mac import CBC_MAC
from stream import BLOCK_BYTES, pkcs7_unpad
from utils import normalize_key, xor_bytes


# ---------------------------------------------------------------------------
# CCA scheme (Encrypt-then-MAC)
# ---------------------------------------------------------------------------

class CCA:
    """
    CCA-Secure encryption via Encrypt-then-MAC.

    Two independent keys kE (encryption) and kM (MAC) MUST be used.
    Key separation is required; reusing a single key for both enables
    subtle correlation attacks (demonstrated in key_separation_demo).
    """

    def __init__(self):
        self._cpa = CPA()
        self._mac = CBC_MAC()   # Variable-length MAC — handles arbitrary ct length

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def enc(self, kE, kM, message: str) -> dict:
        """
        Encrypt-then-MAC.

        Parameters
        ----------
        kE      : encryption key (hex/int string)
        kM      : MAC key        (hex/int string)
        message : plaintext string

        Returns
        -------
        dict with keys: r, c, tag
          r   — nonce hex (needed for decryption)
          c   — ciphertext hex
          tag — MAC hex over (r || c)
        """
        r_hex, c_hex = self._cpa.enc_text(kE, message)

        # Authenticate the *ciphertext* (r || c) — Encrypt-then-MAC
        ct_bytes = bytes.fromhex(r_hex.zfill(16) + c_hex)
        tag = self._mac.mac(kM, ct_bytes)

        return {
            "r":   r_hex,
            "c":   c_hex,
            "tag": tag,
        }

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def dec(self, kE, kM, r_hex: str, c_hex: str, tag: str) -> dict:
        """
        Verify MAC then decrypt. Returns ⊥ (rejection) if MAC fails.

        Returns
        -------
        dict with keys:
          rejected : bool  — True if MAC verification failed
          message  : str   — decrypted plaintext (only if not rejected)
        """
        ct_bytes = bytes.fromhex(r_hex.zfill(16) + c_hex)
        if not self._mac.verify(kM, ct_bytes, tag):
            return {"rejected": True, "message": None}

        msg = self._cpa.dec_text(kE, r_hex, c_hex)
        return {"rejected": False, "message": msg}


# ---------------------------------------------------------------------------
# Malleability demo for raw CPA (PA#3)
# ---------------------------------------------------------------------------

def cpa_malleability_demo(key: str, message: str, bit_index: int = 0) -> dict:
    """
    Shows that the raw CPA scheme (PA#3) is MALLEABLE.

    An attacker who flips bit `bit_index` of the ciphertext c gets a
    predictably modified decryption — a classical malleability attack.

    The CPA construction is  c = keystream ⊕ m,  so flipping c[i]
    flips exactly m[i] in the decryption.

    Returns
    -------
    dict with:
      original_message   : str
      modified_message   : str  (one bit flipped from original)
      bit_flipped        : int
      byte_flipped       : int
      is_malleable       : bool (True when modified ≠ original — always expected)
    """
    cpa = CPA()
    r_hex, c_hex = cpa.enc_text(key, message)

    # Flip one bit in ciphertext byte `byte_index`
    byte_index = bit_index // 8
    bit_in_byte = 7 - (bit_index % 8)          # MSB-first

    c_bytes = bytearray(bytes.fromhex(c_hex))
    if byte_index < len(c_bytes):
        c_bytes[byte_index] ^= (1 << bit_in_byte)
    c_modified = c_bytes.hex()

    # Decrypt the tampered ciphertext — this will "succeed" (no integrity check)
    try:
        modified_message = cpa.dec_text(key, r_hex, c_modified)
    except Exception as e:
        modified_message = f"(decrypt error: {e})"

    return {
        "original_message":  message,
        "r":                 r_hex,
        "c_original":        c_hex,
        "c_modified":        c_modified,
        "bit_flipped":       bit_index,
        "byte_flipped":      byte_index,
        "modified_message":  modified_message,
        "is_malleable":      modified_message != message,
        "explanation": (
            "CPA encryption (stream cipher construction) is malleable: "
            "flipping bit i of ciphertext c flips bit i of plaintext m "
            "because c = G(k,r) ⊕ m. No integrity check exists."
        ),
    }


# ---------------------------------------------------------------------------
# Malleability rejection demo for CCA
# ---------------------------------------------------------------------------

def cca_tamper_demo(kE: str, kM: str, message: str, bit_index: int = 0) -> dict:
    """
    Shows that the CCA scheme (Encrypt-then-MAC) REJECTS tampered ciphertexts.

    Same bit-flip attack as cpa_malleability_demo, but applied to a CCA ciphertext.
    The MAC check catches the modification and returns ⊥.

    Returns
    -------
    dict with:
      original_enc    : dict  {r, c, tag} from CCA.enc
      tampered_c      : str   (modified ciphertext hex)
      dec_result      : dict  {rejected: True}  — always rejected
      explanation     : str
    """
    cca = CCA()
    enc_result = cca.enc(kE, kM, message)

    r_hex = enc_result["r"]
    c_hex = enc_result["c"]
    tag   = enc_result["tag"]

    # Flip the same bit in c
    byte_index  = bit_index // 8
    bit_in_byte = 7 - (bit_index % 8)

    c_bytes = bytearray(bytes.fromhex(c_hex))
    if byte_index < len(c_bytes):
        c_bytes[byte_index] ^= (1 << bit_in_byte)
    c_modified = c_bytes.hex()

    # Attempt decryption with tampered c (tag is for original c — mismatch)
    dec_result = cca.dec(kE, kM, r_hex, c_modified, tag)

    return {
        "original_enc":  enc_result,
        "tampered_c":    c_modified,
        "bit_flipped":   bit_index,
        "dec_result":    dec_result,              # rejected=True always
        "explanation": (
            "Encrypt-then-MAC is non-malleable: any modification to (r, c) "
            "invalidates the MAC tag computed over (r || c). The decryption "
            "oracle returns ⊥ without ever touching the encryption layer."
        ),
    }


# ---------------------------------------------------------------------------
# Key-separation demo (shows why kE ≠ kM is required)
# ---------------------------------------------------------------------------

def key_separation_demo(k: str, message: str) -> dict:
    """
    Demonstrates a concrete correlation when using the SAME key for both
    encryption and MAC (violating key separation).

    Attack idea (one-block messages):
      - CPA uses keystream block KS = PRF_k(r)
      - CBC-MAC on a single block x returns PRF_k(x)
      - If kE == kM, a MAC oracle query on r reveals KS
      - Then m = c ⊕ KS (full plaintext recovery for 1 block)

    We simulate the MAC oracle query on r and show plaintext recovery with
    kE == kM, while the same attempt FAILS when kM ≠ kE.
    """
    cca = CCA()
    mac = CBC_MAC()

    # Keep the demo to one block so the recovery is total. For PKCS#7, this
    # means message length < BLOCK_BYTES (otherwise a full padding block is added).
    max_len = max(BLOCK_BYTES - 1, 1)
    message_used = message[:max_len] if message else ""
    note = None
    if len(message) > max_len:
        note = f"Message truncated to {max_len} bytes for the 1-block demo."

    def _recover_with_mac_oracle(k_mac: str, r_hex: str, c_hex: str) -> dict:
        r_int = int(r_hex, 16)
        r_bytes = r_int.to_bytes(BLOCK_BYTES, "big")

        # CBC-MAC pads: for 7-byte input, the padded block ends with 0x01.
        # If r ends with 0x01, MAC_k(r[0:7]) = PRF_k(r) = keystream block.
        oracle_query = r_bytes[:-1]
        keystream_hex = mac.mac(k_mac, oracle_query)
        keystream = bytes.fromhex(keystream_hex)

        c_bytes = bytes.fromhex(c_hex)
        first_block = c_bytes[:BLOCK_BYTES]
        recovered_block = xor_bytes(first_block, keystream)

        recovered_message = None
        if len(c_bytes) == BLOCK_BYTES:
            try:
                recovered_message = pkcs7_unpad(recovered_block, BLOCK_BYTES).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                recovered_message = None

        return {
            "mac_oracle_on_r": keystream_hex,
            "oracle_query": oracle_query.hex(),
            "recovered_block": recovered_block.hex(),
            "recovered_message": recovered_message,
        }

    def _enc_with_r(kE: str, kM: str, msg: str, r_int: int) -> dict:
        r_hex, c_hex = CPA.enc_text(kE, msg, r=r_int)
        ct_bytes = bytes.fromhex(r_hex.zfill(16) + c_hex)
        tag = mac.mac(kM, ct_bytes)
        return {"r": r_hex, "c": c_hex, "tag": tag}

    # Choose r so its last byte is 0x01, enabling the MAC-oracle trick above.
    r_prefix = os.urandom(BLOCK_BYTES - 1)
    r_bytes = r_prefix + b"\x01"
    r_int = int.from_bytes(r_bytes, "big")

    # Proper encryption with different keys — secure
    enc_sep = _enc_with_r(kE=k, kM=k + "ff", msg=message_used, r_int=r_int)
    sep_attack = _recover_with_mac_oracle(k + "ff", enc_sep["r"], enc_sep["c"])

    # "Broken" — same key for both
    enc_same = _enc_with_r(kE=k, kM=k, msg=message_used, r_int=r_int)
    same_attack = _recover_with_mac_oracle(k, enc_same["r"], enc_same["c"])

    same_success = same_attack["recovered_message"] == message_used
    sep_success = sep_attack["recovered_message"] == message_used

    return {
        "message": message,
        "message_used": message_used,
    "note": note or "Chosen r ends with 0x01 so CBC-MAC(r[0:7]) reveals PRF_k(r).",
        "attack": {
            "same_key": {
                "kE": k,
                "kM": k,
                "enc": enc_same,
                **same_attack,
                "success": same_success,
            },
            "separate_keys": {
                "kE": k,
                "kM": k + "ff",
                "enc": enc_sep,
                **sep_attack,
                "success": sep_success,
            },
        },
        "warning": (
            "Using kE == kM violates key separation. With a MAC oracle, an "
            "adversary can compute PRF_k(r) = keystream and decrypt a 1-block "
            "ciphertext: m = c ⊕ PRF_k(r). This breaks the proof and leaks plaintext."
        ),
    }
