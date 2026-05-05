"""
PA7/merkle_damgard.py
=====================
PA #7 — Merkle-Damgård Hash Transform

Overview
--------
The Merkle-Damgård construction turns any collision-resistant compression
function  f : {0,1}^n × {0,1}^b → {0,1}^n  into a collision-resistant
hash for ARBITRARY-LENGTH inputs.

Algorithm
---------
  pad(M):                           # MD-strengthening
      append 0x80 byte
      zero-pad until |M| ≡ b−8  (mod b)
      append 64-bit big-endian bit-length of original M

  hash(M):
      padded = pad(M)               # multiple of b bytes
      H  ← IV                      # fixed initial value
      for each b-byte block Bi in padded:
          H ← f(H, Bi)             # compress
      return H

Security Theorem
----------------
If f is collision-resistant, then the MD hash is collision-resistant.
Proof: any MD collision M ≠ M' with H(M)=H(M') implies a collision in f.

This module also provides two toy compress functions for demonstration:
  xor_compress        — trivially broken (folds and XORs)
  rotate_add_compress — slightly harder toy
And the full collision propagation demo.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SHARED = os.path.join(_HERE, "..", "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HASH_SIZE  = 4   # chaining value / digest size in bytes (32 bits)
BLOCK_SIZE = 8   # compression block size in bytes (64 bits)
IV_DEFAULT = b'\x00' * HASH_SIZE


# ---------------------------------------------------------------------------
# Compress functions (toy — intentionally broken for demo)
# ---------------------------------------------------------------------------

def xor_compress(cv: bytes, block: bytes) -> bytes:
    """
    XOR-fold compression function.

    Algorithm: fold block into len(cv) bytes by XOR-ing each cv-sized chunk,
    then XOR with the chaining value.

    TRIVIALLY BROKEN: compress(iv, B) = compress(iv, B') for any B, B' with the
    same XOR fold (e.g. B  = 0x00*16  and  B' = 0x01*8 || 0x01*8 both fold to 0).
    Used ONLY for the MD framework demonstration.
    """
    n = len(cv)
    folded = bytearray(n)
    for i in range(0, len(block), n):
        chunk = block[i:i + n]
        chunk = chunk.ljust(n, b'\x00')     # pad partial tail chunk
        for j in range(n):
            folded[j] ^= chunk[j]
    return bytes(cv[j] ^ folded[j] for j in range(n))


def rotate_add_compress(cv: bytes, block: bytes) -> bytes:
    """
    Rotate-then-XOR compression function. Slightly stronger toy.

    Algorithm:
      1. Left-rotate cv_int by 5 bits within 64 bits.
      2. XOR with first len(cv) bytes of block.
      3. Add remaining block chunks (mod 2^64).

    Still a toy (not collision-resistant), but produces different chains from
    xor_compress, illustrating how the choice of f impacts hash behavior.
    """
    n     = len(cv)
    n_bits = n * 8
    mask   = (1 << n_bits) - 1

    cv_int    = int.from_bytes(cv, 'big')
    block_int = int.from_bytes(block[:n].ljust(n, b'\x00'), 'big')

    rotated = ((cv_int << 5) | (cv_int >> (n_bits - 5))) & mask
    result  = rotated ^ block_int

    for i in range(n, len(block), n):
        chunk_int = int.from_bytes(block[i:i + n].ljust(n, b'\x00'), 'big')
        result = (result + chunk_int) & mask

    return result.to_bytes(n, 'big')


# Map name → function (used by API)
COMPRESS_FNS = {
    "xor":    xor_compress,
    "rotate": rotate_add_compress,
}


# ---------------------------------------------------------------------------
# Merkle-Damgård class
# ---------------------------------------------------------------------------

class MerkleDamgard:
    """
    Merkle-Damgård hash transform.

    Parameters
    ----------
    compress_fn : callable (cv: bytes, block: bytes) -> bytes
    iv          : bytes — initial chaining value (len = hash_size)
    block_size  : int   — bytes per compression block (must fit 8-byte length)
    """

    def __init__(self, compress_fn, iv: bytes = None, block_size: int = None):
        self.compress_fn = compress_fn
        self.iv          = iv         if iv         is not None else IV_DEFAULT
        self.block_size  = block_size if block_size is not None else BLOCK_SIZE
        self.hash_size   = len(self.iv)

        assert self.block_size > self.hash_size, (
            "block_size must be larger than hash_size to allow padding length field"
        )

    # ------------------------------------------------------------------
    # Padding
    # ------------------------------------------------------------------

    def pad(self, message: bytes) -> bytes:
        """
        MD-strengthening padding.

        Appends  0x80 | 0x00… | 64-bit-big-endian-bit-length
        so that total length ≡ 0  (mod block_size).
        """
        msg_len_bits = len(message) * 8
        padded = bytearray(message) + bytearray(b'\x80')

        target = self.block_size - 8          # last 8 bytes = length field
        while len(padded) % self.block_size != target:
            padded += b'\x00'

        padded += msg_len_bits.to_bytes(8, 'big')
        assert len(padded) % self.block_size == 0
        return bytes(padded)

    # ------------------------------------------------------------------
    # Hash
    # ------------------------------------------------------------------

    def hash(self, message: bytes) -> bytes:
        """Hash arbitrary bytes → hash_size bytes."""
        padded = self.pad(message)
        cv = self.iv
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            cv = self.compress_fn(cv, block)
        return cv

    def hash_hex(self, message: bytes) -> str:
        return self.hash(message).hex()

    # ------------------------------------------------------------------
    # Trace (chain visualization)
    # ------------------------------------------------------------------

    def trace(self, message: bytes) -> dict:
        """
        Hash with full chain visualization.

        Returns
        -------
        dict:
          message_hex   : original message as hex
          padded_hex    : full padded message as hex (with padding annotated)
          n_blocks      : number of compression blocks
          blocks        : list of block hex strings
          padding_blocks: list of which block indices contain padding
          chain         : list of hex chaining values:
                          chain[0]=IV, chain[i+1]=f(chain[i], block[i])
          digest        : final hash hex
          padding_info  : breakdown of padding bytes
        """
        padded = self.pad(message)
        orig_len = len(message)
        n_blocks = len(padded) // self.block_size

        blocks = [padded[i:i + self.block_size]
                  for i in range(0, len(padded), self.block_size)]

        # Track which bytes are data vs padding vs length
        data_end    = orig_len                     # exclusive
        len_start   = len(padded) - 8
        marker_pos  = orig_len                     # 0x80 byte position

        # Annotate each block
        block_annotations = []
        for idx, blk in enumerate(blocks):
            blk_start = idx * self.block_size
            blk_end   = blk_start + self.block_size
            ann = {
                "index":     idx,
                "hex":       blk.hex(),
                "has_data":  blk_start < data_end,
                "has_pad":   blk_end > data_end and blk_start < len_start,
                "has_length": blk_end > len_start,
            }
            block_annotations.append(ann)

        # Build chain
        cv    = self.iv
        chain = [cv.hex()]
        for blk in blocks:
            cv = self.compress_fn(cv, blk)
            chain.append(cv.hex())

        return {
            "message_bytes": orig_len,
            "message_hex":   message.hex() if message else "",
            "padded_hex":    padded.hex(),
            "block_size":    self.block_size,
            "hash_size":     self.hash_size,
            "n_blocks":      n_blocks,
            "blocks":        block_annotations,
            "chain":         chain,
            "digest":        chain[-1],
            "padding_info": {
                "original_bytes":    orig_len,
                "original_bits":     orig_len * 8,
                "padded_bytes":      len(padded),
                "zero_pad_bytes":    len(padded) - orig_len - 1 - 8,
                "marker_byte_pos":   marker_pos,
                "length_field_pos":  len_start,
            },
        }


# ---------------------------------------------------------------------------
# Collision-resistance violation: compress collision → MD collision
# ---------------------------------------------------------------------------

def xor_compress_construct_collision(block_size: int = BLOCK_SIZE) -> tuple:
    """
    Construct a deterministic collision in xor_compress.

    B1 = 0x00 * block_size            → fold = 0 → compress(IV, B1) = IV
    B2 = 0x01 * (block_size//2) +
         0x01 * (block_size - block_size//2)  → fold = 0 → same

    Returns (B1, B2) as bytes — two distinct blocks with the same compress output.
    """
    b1 = b'\x00' * block_size
    half = block_size // 2
    b2   = b'\x01' * half + b'\x01' * (block_size - half)  # = b'\x01' * block_size
    # Verify they differ
    assert b1 != b2, "Collision construction produced identical blocks"
    return b1, b2


def collision_propagation_demo(
    compress_fn_name: str = "xor",
    suffix: bytes = b"same_suffix",
) -> dict:
    """
    Demonstrate that a compress collision propagates to a full MD collision.

    1. Constructs two distinct blocks B1, B2 with compress(IV, B1) = compress(IV, B2).
    2. For any suffix S: H(B1 ‖ S) = H(B2 ‖ S).

    Returns a dict suitable for the frontend visualizer.
    """
    compress_fn = COMPRESS_FNS.get(compress_fn_name, xor_compress)
    md = MerkleDamgard(compress_fn)

    # --- Step 1: compress collision ---
    if compress_fn_name == "xor":
        b1, b2 = xor_compress_construct_collision(BLOCK_SIZE)
        found_in_trials = 1
    else:
        # For rotate compress, brute-force a collision (small space via truncation)
        import secrets
        seen: dict = {}
        b1 = b2 = None
        found_in_trials = 0
        for _ in range(100_000):
            blk = secrets.token_bytes(BLOCK_SIZE)
            out = compress_fn(IV_DEFAULT, blk)[:4]   # truncate for feasibility
            found_in_trials += 1
            if out in seen:
                b1 = seen[out]
                b2 = blk
                if b1 != b2:
                    break
            else:
                seen[out] = blk
        if b1 is None or b1 == b2:
            return {"found": False, "error": "Could not find collision in budget"}

    # Verify compress collision
    out1 = compress_fn(IV_DEFAULT, b1)
    out2 = compress_fn(IV_DEFAULT, b2)
    compress_collides = (out1 == out2)

    # --- Step 2: full MD collision ---
    m1 = b1 + suffix
    m2 = b2 + suffix
    h1 = md.hash_hex(m1)
    h2 = md.hash_hex(m2)

    # Chain traces for visualization
    trace1 = md.trace(m1)
    trace2 = md.trace(m2)

    return {
        "found":              True,
        "compress_fn":        compress_fn_name,
        "found_in_trials":    found_in_trials,
        "iv":                 IV_DEFAULT.hex(),
        "compress_collision": {
            "block1_hex":       b1.hex(),
            "block2_hex":       b2.hex(),
            "compress_output":  out1.hex(),
            "blocks_equal":     b1 == b2,
            "compress_collides": compress_collides,
        },
        "suffix_hex":         suffix.hex(),
        "message1_hex":       m1.hex(),
        "message2_hex":       m2.hex(),
        "hash1":              h1,
        "hash2":              h2,
        "full_collision":     h1 == h2,
        "trace1":             trace1,
        "trace2":             trace2,
        "explanation": (
            "A single compress collision (round 1) propagates to a full hash collision. "
            "After block B1 and B2 produce the SAME chaining value, all subsequent "
            "blocks process identically → H(B1 ‖ S) = H(B2 ‖ S) for ANY suffix S. "
            "This proves CRHF of compress is NECESSARY for CRHF of the full hash."
        ),
    }
