"""
PA#12 — PKCS#1 v1.5 Padding for RSA Encryption (RFC 2313)

Implements:
  - pkcs15_pad(message, k)    : pad a message for RSA encryption
  - pkcs15_unpad(em)          : strip and validate PKCS#1 v1.5 padding (returns ⊥ on failure)

Padding structure (block type 0x02, encryption):
  EM = 0x00 || 0x02 || PS (random nonzero bytes, len >= 8) || 0x00 || message
  Total length of EM = k  (k = modulus byte length)

Security properties:
  - PS bytes are cryptographically random and nonzero → ciphertext is non-deterministic.
  - PKCS#1 v1.5 is CPA-secure but NOT CCA-secure (Bleichenbacher 1998 attack).
  - Modern replacement is OAEP (PA#17 addresses full CCA-secure PKC).
"""

import secrets

# Padding overhead constants (from RFC 2313)
HEADER_LEN    = 2     # 0x00 || 0x02
SEPARATOR_LEN = 1     # 0x00 separator before message
MIN_PS_LEN    = 8     # minimum padding string length
OVERHEAD      = HEADER_LEN + SEPARATOR_LEN + MIN_PS_LEN   # = 11 bytes total


def pkcs15_pad(message: bytes, k: int) -> bytes:
    """
    Apply PKCS#1 v1.5 Type-02 (encryption) padding.

    Args:
        message : plaintext bytes to embed
        k       : RSA modulus length in bytes  (= ceil(N.bit_length() / 8))

    Returns:
        Padded encoded message EM of exactly k bytes.

    Raises:
        ValueError  if len(message) > k - 11  (message too long)

    Structure:
        EM = 0x00 || 0x02 || PS || 0x00 || message
        where PS is (k - 3 - len(message)) random nonzero bytes.
    """
    m_len  = len(message)
    max_m  = k - OVERHEAD
    if m_len > max_m:
        raise ValueError(
            f"Message too long for PKCS#1 v1.5: "
            f"{m_len} bytes, maximum is {max_m} bytes for k={k}"
        )

    ps_len = k - HEADER_LEN - SEPARATOR_LEN - m_len

    # Build PS: exactly ps_len cryptographically random NONZERO bytes
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.randbits(8)
        if b != 0:
            ps.append(b)

    em = bytes([0x00, 0x02]) + bytes(ps) + bytes([0x00]) + message
    assert len(em) == k, f"BUG: padded length {len(em)} != k {k}"
    return em


def pkcs15_unpad(em: bytes) -> bytes:
    """
    Strip and validate PKCS#1 v1.5 Type-02 padding.

    Returns the embedded message on success.
    Raises ValueError (i.e., outputs ⊥) on any malformed padding.

    Checks:
      1. EM[0] == 0x00
      2. EM[1] == 0x02  (encryption block type)
      3. A 0x00 separator exists after the padding string
      4. PS length >= 8
      5. All PS bytes are nonzero
    """
    if len(em) < OVERHEAD:
        raise ValueError(
            f"Encoded message too short: {len(em)} bytes, need >= {OVERHEAD}"
        )

    if em[0] != 0x00:
        raise ValueError(f"First byte must be 0x00, got 0x{em[0]:02x}")

    if em[1] != 0x02:
        raise ValueError(
            f"Block type must be 0x02 (encryption), got 0x{em[1]:02x}"
        )

    # Find the 0x00 separator after PS  (search from index 2 onward)
    sep_idx = em.find(b"\x00", 2)
    if sep_idx < 0:
        raise ValueError("No 0x00 separator found after padding string")

    ps_len = sep_idx - 2
    if ps_len < MIN_PS_LEN:
        raise ValueError(
            f"Padding string too short: {ps_len} bytes, minimum is {MIN_PS_LEN}"
        )

    # Verify all PS bytes are nonzero
    ps = em[2:sep_idx]
    zero_positions = [i for i, b in enumerate(ps) if b == 0]
    if zero_positions:
        raise ValueError(
            f"Padding string contains zero byte at position(s): {zero_positions}"
        )

    return em[sep_idx + 1:]
