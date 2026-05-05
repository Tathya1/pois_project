Summary of All Fixes Applied
🔴 Fix 1 — Pure-Python AES (PA#2)
Problem: aes_prf.py used from Crypto.Cipher import AES (PyCryptodome) — violating the No-Library Rule.

Fix: Created PA2/aes_core.py — a complete FIPS 197 AES-128 implementation in pure Python (~250 lines), including:

Full S-box, GF(2⁸) arithmetic, key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey
Both encrypt and decrypt
FIPS 197 Appendix B known-answer test that runs at import time (got 3925841d02dc09fbdc118597196a0b32 ✅)
aes_prf.py now wraps aes_core.py with F(x) and F_inv(x).

🟡 Fix 2 — OWF←PRG Backward Direction Code (PA#1b)
Problem: Only a markdown theory writeup existed (1b.md). No runnable code.

Fix: Created PA1/owf_from_prg.py (OWF_from_PRG class) with:

evaluate(s) — concretely demonstrates f(s) = G(s) as a OWF
demonstrate_hardness() — samples 5 random seeds from 2³² space, brute-forces up to 10,000 guesses, confirms 0 found
build_distinguisher(y) — implements the formal reduction: D(y) labels "PRG" or "Random" based on whether a preimage is found
New API endpoint /owf-from-prg exposes both modes. PA1Panel now has a "Backward" tab showing the demo live.

🟡 Fix 3 — Broken distinguisher.py Path
Problem: Referenced PA#1 (with #) which doesn't exist on the filesystem.

Fix: Rewrote distinguisher.py with correct paths + added a proper RandomOracle class that uses a lazy table for fair comparison, plus prg_from_prf_statistical_test() for PA#2b validation.

🟢 Fix 4 — Package Structure (__init__.py + shared/utils.py)
Created shared/utils.py — canonical source for normalize_key, xor_bytes, int_to_bits, pkcs7_pad/unpad
Created PA1/__init__.py, PA2/__init__.py, PA3/__init__.py, PA4/__init__.py — proper Python packages with clean exports
Updated app.py — clean path registration, package-qualified imports
PA3/cpa_utils.py is now a shim that re-exports from shared/utils.py
🟢 Fix 5 — New API Endpoints
Endpoint	What it does
POST /owf/evaluate	OWF f(x) = gˣ mod p
POST /owf/hardness	Brute-force inversion fails demo
POST /owf-from-prg	PA#1b backward reduction
POST /prf/aes	Pure-Python AES PRF
POST /prf/distinguish	PRF distinguishing game
POST /prg-from-prf	PRF→PRG backward + NIST tests


