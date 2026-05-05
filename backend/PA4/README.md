# PA#4 — Block Cipher Modes

This module implements:

- CBC mode: `CBC Enc(k, IV, M)` and `CBC Dec(k, IV, C)`
- OFB mode: `OFB Enc(k, IV, M)` and `OFB Dec(k, IV, C)`
- Randomized CTR mode: `CTR Enc(k, M)` and `CTR Dec(k, r, C)`
- Unified selector API: `encrypt(mode, key, message)` / `decrypt(mode, key, ciphertext, ...)`
- Attack demos:
  - CBC IV reuse leakage
  - OFB keystream reuse leakage (`C1 xor C2 = M1 xor M2`)

## Implementation notes

- Block size: 64 bits (8 bytes).
- Underlying block cipher: a small 64-bit Feistel PRP using PA#2 `GGM_PRF` as round function.
- CBC uses PKCS#7 padding.
- OFB and CTR are stream-like and do not pad.

## Files

- `modes.py`: mode implementations + demos + animation traces
- `test_pa4.py`: correctness and security-demo tests

## Run tests

From `backend/`:

- `python3 -m pytest PA#4/test_pa4.py`
