# POIS Project: Deep Codebase Analysis & Implementation Plan for PA#5–PA#8

## 1. Existing Codebase Audit (PA#1–PA#4)

### 1.1 Project Structure (Current)

```
POIS/
├── backend/
│   ├── app.py              ← Flask entrypoint; registers PA1–PA4 blueprints
│   ├── PA1/                ← OWF + PRG + NIST tests
│   │   ├── owf.py          (DLP_OWF)
│   │   ├── prg.py          (PRG)
│   │   ├── tests.py        (frequency, runs, serial)
│   │   ├── app_pa1.py      (Flask blueprint: /prg, /test)
│   │   └── test_pa1.py
│   ├── PA2/                ← GGM-PRF + AES-PRF + backward PRG←PRF
│   │   ├── prf.py          (GGM_PRF)
│   │   ├── aes_prf.py      (AES_PRF — uses PyCryptodome ⚠️)
│   │   ├── prg_from_prf.py (PRG_from_PRF)
│   │   ├── app_pa2.py      (Flask blueprint)
│   │   └── test_pa2.py
│   ├── PA3/                ← CPA-secure encryption (CTR-style with GGM PRF)
│   │   ├── cpa.py          (CPA.enc / CPA.dec)
│   │   ├── stream.py       (keystream via GGM_PRF)
│   │   ├── cpa_game.py     (IND-CPA game simulation)
│   │   ├── cpa_utils.py    (normalize_key, xor_bytes, int_to_bits)
│   │   ├── app_pa3.py      (Flask blueprint)
│   │   └── test_pa3.py
│   └── PA4/                ← Modes of Operation (CBC, OFB, CTR + attacks)
│       ├── modes.py        (BlockModes, FeistelPRP)
│       ├── app_pa4.py      (Flask blueprint)
│       └── test_pa4.py
├── distinguisher.py        ← top-level distinguisher utility
└── api/routes/             ← empty (unused)

frontend/
├── src/
│   ├── App.jsx             ← Tab switcher: PA1/PA2/PA3/PA4
│   ├── components/
│   │   ├── PA1Panel.jsx    (PRG output viewer + randomness test button)
│   │   ├── PA2Panel.jsx    (GGM tree visualiser)
│   │   ├── PA3Panel.jsx    (IND-CPA game, nonce-reuse toggle)
│   │   └── PA4Panel.jsx    (mode animator, flip-bit, IV-reuse attacks)
│   ├── foundations/        (AESFoundation.js, DLPFoundation.js — stubs)
│   └── reductions/         (reducer.js, routingTable.js — stubs)
```

---

## 2. What's Done — and What's Missing

### PA #1 — OWF + PRG ✅ (mostly complete)

| Requirement | Status | Notes |
|---|---|---|
| DLP OWF `evaluate(x)` | ✅ | `g=5, p=2^31-1` (Mersenne prime, safe) |
| `verify_hardness()` demo | ✅ | Brute-force up to 10,000 |
| PRG from OWF (HILL iterative) | ✅ | Hard-core bit = LSB of `f(x)` |
| OWF from PRG (backward) | ⚠️ | Only a `1b.md` write-up; no code stub |
| NIST tests (frequency, runs, serial) | ✅ | `tests.py` — uses scipy |
| `seed(s)` / `next_bits(n)` interface | ✅ | Exposed correctly |
| Live PRG output viewer (frontend) | ✅ | PA1Panel with seed input + randomness test |

**Issues found:**  
- `owf.py` is a standalone class, not importable cleanly from outside PA1 without path hacks — acceptable but needs clean module path.
- The backward OWF←PRG has no code (`1b.md` is just a markdown note).

---

### PA #2 — GGM PRF ✅ (mostly complete)

| Requirement | Status | Notes |
|---|---|---|
| GGM PRF `F(k, x)` via PA#1 PRG | ✅ | `prf.py` correctly follows bits of x |
| PRG from PRF backward direction | ✅ | `prg_from_prf.py` G(s) = Fs(0^n)‖Fs(1^n) |
| AES plug-in PRF | ⚠️ | `aes_prf.py` uses **PyCryptodome** (`from Crypto.Cipher import AES`) — **violates no-library rule** |
| Distinguishing game demo | ⚠️ | No statistical test run on PRG_from_PRF output |
| GGM tree visualiser (frontend) | ✅ | PA2Panel shows tree with path highlighting |
| F(k, x) interface for PA3/PA4/PA5 | ✅ | `GGM_PRF().F(key, x_bits)` |

**Issues found:**  
- `aes_prf.py` imports `from Crypto.Cipher import AES` — this is a prohibited library. Needs a pure-Python AES or must rely on OS primitives only.
- The GGM PRF accumulates state inefficiently (creates new `PRG` object per bit traversal step).

---

### PA #3 — CPA-Secure Encryption ✅ (complete)

| Requirement | Status | Notes |
|---|---|---|
| `Enc(k, m)` → `(r, c)` via C=⟨r, Fk(r)⊕m⟩ | ✅ | `cpa.py` |
| Multi-block support (counter extension) | ✅ | `stream.py` counter loop |
| PKCS7 padding | ✅ | `pkcs7_pad/unpad` |
| CPA game simulation (dummy adversary) | ✅ | `cpa_game.py` |
| Broken variant (nonce reuse demo) | ✅ | `reuse_nonce=True` path |
| `Enc(k,m)→(r,c)` / `Dec(k,r,c)→m` interface for PA#6 | ✅ | `CPA.enc_text / dec_text` |
| IND-CPA interactive game (frontend) | ✅ | PA3Panel |

**Issues found:**  
- None functionally. The `CPA` class is a `@staticmethod` class, which is fine.
- Uses PA#2 `GGM_PRF` correctly (no library bypass).

---

### PA #4 — Modes of Operation ✅ (complete)

| Requirement | Status | Notes |
|---|---|---|
| CBC enc/dec + random IV | ✅ | `modes.py:BlockModes.cbc_encrypt/decrypt` |
| OFB enc/dec + precomputable stream | ✅ | `modes.py:BlockModes.ofb_*` |
| CTR enc/dec + parallel structure | ✅ | `modes.py:BlockModes.ctr_*` |
| Unified API `Encrypt(mode, k, M)` | ✅ | `MODES.encrypt/decrypt` |
| CBC IV-reuse attack demo | ✅ | `cbc_iv_reuse_demo` |
| OFB keystream-reuse attack demo | ✅ | `ofb_keystream_reuse_demo` |
| Bit-flip error propagation demo | ✅ | `flip_bit_demo` |
| Block cipher visualiser (frontend) | ✅ | PA4Panel with animated trace |
| Uses own PRF (FeistelPRP over GGM_PRF) | ✅ | `FeistelPRP` in modes.py |

**Issues found:**  
- None functionally. Excellent implementation.

---

## 3. Critical Problems to Fix Before PA#5

> [!WARNING]
> **`aes_prf.py` uses PyCryptodome** — violates the "No-Library Rule". For assignments going forward (PA#5 uses whichever PRF is the foundation), this must be either: (a) replaced with a pure-Python AES, or (b) left as an alternate path clearly labeled "OS-level exception" if we treat it as the one allowed library (OS-level AES). Since the spec says "OS-level randomness" is the only exception (not AES), we should build a minimal self-contained AES for completeness. **For now, PA#5–PA#8 will use GGM_PRF (which is clean).** We'll note the AES issue.

---

## 4. Proposed Module Restructuring

> [!IMPORTANT]
> The current project has path hacks (`sys.path.insert`) scattered everywhere. Before adding PA#5–PA#8, we should adopt a clean package layout. Each PA becomes a Python package with a clean `__init__.py` that exports its public interface.

### Proposed New Structure

```
backend/
├── app.py                    ← Flask entrypoint
├── shared/
│   └── utils.py              ← xor_bytes, normalize_key, int_to_bits (dedup)
├── pa1/
│   ├── __init__.py           ← exports: DLP_OWF, PRG
│   ├── owf.py
│   ├── prg.py
│   ├── tests.py
│   └── routes.py             ← Flask blueprint (was app_pa1.py)
├── pa2/
│   ├── __init__.py           ← exports: GGM_PRF, PRG_from_PRF
│   ├── prf.py
│   ├── prg_from_prf.py
│   └── routes.py
├── pa3/
│   ├── __init__.py           ← exports: CPA
│   ├── cpa.py
│   ├── stream.py
│   ├── cpa_game.py
│   └── routes.py
├── pa4/
│   ├── __init__.py           ← exports: BlockModes, MODES
│   ├── modes.py
│   └── routes.py
├── pa5/                      ← NEW: MACs
│   ├── __init__.py           ← exports: PRF_MAC, CBC_MAC, hmac_stub
│   ├── mac.py                ← PRF_MAC + CBC_MAC
│   ├── mac_game.py           ← EUF-CMA game simulation
│   └── routes.py
├── pa6/                      ← NEW: CCA-Secure Encryption
│   ├── __init__.py           ← exports: CCA_Enc, CCA_Dec
│   ├── cca.py                ← Encrypt-then-MAC
│   ├── cca_game.py           ← IND-CCA2 game
│   └── routes.py
├── pa7/                      ← NEW: Merkle-Damgård Transform
│   ├── __init__.py           ← exports: MerkleDamgard
│   ├── merkle_damgard.py
│   └── routes.py
└── pa8/                      ← NEW: DLP-based CRHF
    ├── __init__.py           ← exports: DLP_Hash
    ├── dlp_hash.py           ← DLP compression function + full CRHF
    └── routes.py

frontend/src/
├── components/
│   ├── PA1Panel.jsx … PA4Panel.jsx   ← existing
│   ├── PA5Panel.jsx                  ← NEW: MAC forge demo
│   ├── PA6Panel.jsx                  ← NEW: Malleability attack panel
│   ├── PA7Panel.jsx                  ← NEW: MD chain viewer
│   └── PA8Panel.jsx                  ← NEW: DLP hash + collision hunt
└── App.jsx                           ← add tabs for PA5–PA8
```

---

## 5. Implementation Plan: PA#5 → PA#8

### Dependency Chain

```
PA1 (OWF, PRG) → PA2 (GGM_PRF) → PA3 (CPA.enc/dec) → PA4 (BlockModes)
                                                              ↓
                                                         PA5 (MAC)
                                                              ↓
                                                         PA6 (CCA = CPA + MAC)
                                                              ↓
                                               PA7 (Merkle-Damgård framework)
                                                              ↓
                                               PA8 (DLP compression + full CRHF)
```

---

### Phase 0 — Restructuring (Do First)

Before any new PA:

1. Rename `PA1/` → `pa1/`, etc. (lowercase) and add `__init__.py` for clean imports.
2. Create `shared/utils.py` with common helpers (`xor_bytes`, `normalize_key`, `int_to_bits`).
3. Rename `app_paX.py` → `routes.py` inside each package.
4. Update `app.py` to use `from pa1.routes import pa1_bp`, etc.
5. Remove all `sys.path.insert` hacks — proper package imports replace them.

---

### Phase 1 — PA#5: Secure MACs

**Files to create:** `backend/pa5/mac.py`, `backend/pa5/mac_game.py`, `backend/pa5/routes.py`

#### `mac.py` — What to implement

```python
# PRF-MAC (fixed-length, one block)
class PRF_MAC:
    def mac(self, key, message_bytes) -> bytes   # = F_k(m)
    def verify(self, key, message_bytes, tag) -> bool

# CBC-MAC (variable-length)
class CBC_MAC:
    def mac(self, key, message_bytes) -> bytes   # chain F_k over blocks
    def verify(self, key, message_bytes, tag) -> bool

# HMAC stub (forward pointer to PA#10)
def hmac_stub(key, message):
    raise NotImplementedError("HMAC implemented in PA#10")
```

Both depend on `pa2.GGM_PRF`. The PRF call is `F(key_int, x_bits_string)`.

#### `mac_game.py` — What to implement

```python
def euf_cma_game(mac_instance, rounds=20) -> dict
    # Returns: forgery_attempts, forgery_successes (expected: 0 successes)
    
def length_extension_demo(naive_hash_fn) -> dict
    # Shows that H(k||m) is broken by extending with m'
    # Note: needs PA8 hash; for PA5, use a toy XOR hash as placeholder
```

#### Backend API routes (Flask)

| Endpoint | Method | Description |
|---|---|---|
| `/pa5/mac` | POST | `{key, message, variant}` → `{tag}` |
| `/pa5/verify` | POST | `{key, message, tag, variant}` → `{valid}` |
| `/pa5/euf-cma-game` | POST | `{rounds}` → `{attempts, successes, advantage}` |
| `/pa5/mac-as-prf-test` | POST | `{}` → `{p_value, pass}` (backward: MAC ⇒ PRF) |

#### Frontend: PA5Panel.jsx

- Shows list of signed messages + forge attempt form
- Counter: forgery attempts vs successes
- Separate tab: length-extension demo (toy hash)

---

### Phase 2 — PA#6: CCA-Secure Encryption

**Files to create:** `backend/pa6/cca.py`, `backend/pa6/cca_game.py`, `backend/pa6/routes.py`

#### `cca.py` — What to implement

```python
class CCA:
    def enc(self, kE, kM, message) -> (ciphertext, tag)
        # 1. CE = CPA.enc(kE, message)
        # 2. t = MAC.mac(kM, CE)
        # 3. return (CE, t)
        
    def dec(self, kE, kM, ciphertext, tag) -> bytes or None
        # 1. if not MAC.verify(kM, ciphertext, tag): return None (⊥)
        # 2. return CPA.dec(kE, ciphertext)

# Malleability demo: show PA3 CPA scheme is malleable
def malleability_demo(key, message) -> dict
    # Flip bit i of C = ⟨r, F_k(r)⊕m⟩
    # Show recovered plaintext has bit i flipped → proof of malleability
    
def key_separation_demo(k) -> dict
    # Show that using same key for enc+mac creates exploitable correlation
```

#### `cca_game.py`

```python
def ind_cca2_game(rounds=20) -> dict
    # Adversary has enc oracle + dec oracle (rejects challenge ciphertext)
    # Returns: advantage ≈ 0 for valid scheme
```

#### Backend API routes

| Endpoint | Method | Description |
|---|---|---|
| `/pa6/encrypt` | POST | `{kE, kM, message}` → `{ciphertext, tag}` |
| `/pa6/decrypt` | POST | `{kE, kM, ciphertext, tag}` → `{message}` or `{rejected: true}` |
| `/pa6/malleability-cpa` | POST | `{key, message, bitIndex}` → shows CPA is malleable |
| `/pa6/malleability-cca` | POST | `{kE, kM, ciphertext, tag, bitIndex}` → shows CCA rejects |
| `/pa6/cca2-game` | POST | `{rounds}` → `{advantage}` |

#### Frontend: PA6Panel.jsx

- Two-panel layout: CPA side (malleable) vs CCA side (rejected)
- Bit-flip tool on left shows corrupted plaintext; right shows ⊥
- Both update live

---

### Phase 3 — PA#7: Merkle-Damgård Transform

**Files to create:** `backend/pa7/merkle_damgard.py`, `backend/pa7/routes.py`

#### `merkle_damgard.py` — What to implement

```python
class MerkleDamgard:
    def __init__(self, compress_fn, iv: bytes, block_size: int):
        # compress_fn: (chaining_value: bytes, block: bytes) -> bytes
        # iv: initial value (fixed 0^n per spec)
        # block_size: b bits
        
    def pad(self, message: bytes) -> bytes:
        # MD-strengthening: message || 1 || 0* || len(message) as 64-bit big-endian
        # Total padded length is multiple of block_size bytes
        
    def hash(self, message: bytes) -> bytes:
        # 1. padded = self.pad(message)
        # 2. split into blocks of block_size bytes
        # 3. z = iv; for each block: z = compress_fn(z, block)
        # 4. return z

# Toy XOR compression function for testing isolation
def xor_compress(chaining_val: bytes, block: bytes) -> bytes:
    return xor_bytes(chaining_val, block[:len(chaining_val)])

# Collision propagation demo
def collision_propagation_demo(compress_fn, iv, block_size) -> dict:
    # Find two (x,y) pairs that collide under compress_fn
    # Show they also collide under full MD hash
```

#### Backend API routes

| Endpoint | Method | Description |
|---|---|---|
| `/pa7/hash` | POST | `{message, compress_fn}` → `{digest, blocks, chain}` |
| `/pa7/trace` | POST | `{message}` → `{blocks_hex[], chain_values[], digest}` |
| `/pa7/collision-demo` | POST | `{}` → `{input1, input2, hash1, hash2, collides}` |

#### Frontend: PA7Panel.jsx

- Text/hex input for message → shows MD padding breakdown
- Animated chain: z₀ → h(z₀,M₁) → h(z₁,M₂) → … with hex labels
- Edit any block → chain recomputes from that block onwards (avalanche demo)

---

### Phase 4 — PA#8: DLP-Based CRHF

**Files to create:** `backend/pa8/dlp_hash.py`, `backend/pa8/routes.py`

#### `dlp_hash.py` — What to implement

```python
class DLP_Group:
    """Safe-prime subgroup of Z*_p where DLP is hard."""
    def __init__(self, bits=64):  # toy: 64-bit; for security: 256-bit
        self.p: int  # safe prime p = 2q+1
        self.q: int  # prime order
        self.g: int  # generator of order-q subgroup
        self.h: int  # h = g^alpha mod p, alpha discarded
        
    def compress(self, x: int, y: int) -> int:
        # h(x,y) = g^x * h^y mod p
        # Collision resistance ← DLP hardness
        
class DLP_Hash:
    """Full CRHF: DLP compression function plugged into Merkle-Damgård."""
    def __init__(self, group: DLP_Group):
        self.md = MerkleDamgard(
            compress_fn=self._compress_adapter,
            iv=b'\x00' * 8,
            block_size=8  # 8 bytes per block (maps to two Zq inputs)
        )
        
    def _compress_adapter(self, cv: bytes, block: bytes) -> bytes:
        x = int.from_bytes(cv, 'big') % self.group.q
        y = int.from_bytes(block, 'big') % self.group.q
        result = self.group.compress(x, y)
        return result.to_bytes(8, 'big')
        
    def hash(self, message: bytes) -> bytes:
        return self.md.hash(message)
    
    def hash_hex(self, message: bytes) -> str:
        return self.hash(message).hex()

# Birthday attack on truncated DLP hash
def birthday_attack(hash_fn, n_bits: int) -> dict:
    # Naive approach: hash random inputs, detect collision via dict
    # Returns: {input1, input2, hash_value, evaluations}
    
# Collision resistance demo
def collision_resistance_demo(group: DLP_Group) -> dict:
    # Show collision would require solving DLP
    # Tiny params: brute-force collision for q≈2^16 to confirm O(2^(n/2)) work
```

#### Backend API routes

| Endpoint | Method | Description |
|---|---|---|
| `/pa8/hash` | POST | `{message}` → `{digest_hex}` |
| `/pa8/birthday-attack` | POST | `{n_bits}` → `{input1, input2, digest, evaluations}` |
| `/pa8/collision-demo` | POST | `{}` → collision resistance argument |

#### Frontend: PA8Panel.jsx

- Message input → shows DLP hash as hex string
- "Collision hunt" button → runs birthday attack (n=16 bits), progress bar
- Progress bar: counter vs 2^(n/2) threshold
- Shows two colliding inputs when found

---

## 6. Key Design Decisions

### 6.1 Key Format Consistency

**Problem:** PA#2 `GGM_PRF.F(key, x)` expects `key` as an integer (it calls `int(k)`), but PA#3 and PA#5 pass keys as strings/hex. The `normalize_key(key)` helper in `cpa_utils.py` converts everything to int.

**Decision:** Keep `normalize_key` in `shared/utils.py`, used by all PA modules.

### 6.2 Block Size

Current block size = **8 bytes** (64 bits), consistent across PA1–PA4 (`BLOCK_BYTES = 8`). PA#5 MAC and PA#6 CCA will use the same block size. PA#7 MD will use 8-byte blocks. PA#8 DLP hash output will be 8 bytes (to match chain values).

### 6.3 No-Library Rule Compliance

- PA#1: ✅ Pure Python (uses `math`, `random` — OK)
- PA#2: ⚠️ `aes_prf.py` uses PyCryptodome (unused in main chain — GGM_PRF is used)
- PA#3–4: ✅ Chain is GGM_PRF only
- PA#5–8: Will use GGM_PRF chain only — **fully compliant**

### 6.4 DLP Parameters for PA#8

For the interactive demo, use **toy parameters**: q ≈ 2^16 (instant computation, visible birthday collision in ~256 evaluations). For the "full-size" hash shown alongside, use q ≈ 2^64 (which is still toy by real standards but makes the DLP look hard enough).

---

## 7. Frontend Integration Plan

The current `App.jsx` has a simple tab switcher. We will extend it:

```jsx
const TABS = [
  { id: 'PA1', label: 'PRG (PA#1)' },
  { id: 'PA2', label: 'PRF (PA#2)' },
  { id: 'PA3', label: 'CPA (PA#3)' },
  { id: 'PA4', label: 'Modes (PA#4)' },
  { id: 'PA5', label: 'MAC (PA#5)' },      // NEW
  { id: 'PA6', label: 'CCA (PA#6)' },      // NEW
  { id: 'PA7', label: 'MD Hash (PA#7)' },  // NEW
  { id: 'PA8', label: 'CRHF (PA#8)' },     // NEW
];
```

Each panel is self-contained and communicates only with its own backend blueprint.

---

## 8. What I Need Your Approval On

> [!IMPORTANT]
> **Restructuring first vs. adding PA#5 directly?** 
> I recommend doing a lightweight restructure (adding `__init__.py` to each PA folder and creating `shared/utils.py`) before adding PA#5. This prevents the path-hack debt from growing. However, if you want to move fast, I can add PA#5 in the existing flat style and restructure later.

> [!WARNING]
> **`aes_prf.py` uses PyCryptodome** which violates the no-library rule. The AES PRF is not in the dependency chain for PA#5–PA#8 (which all use GGM_PRF), so it won't cause a violation there. But graders may flag it. Should I replace it with a pure-Python AES stub or just leave it as-is?

> [!NOTE]  
> **DLP group size:** For PA#8 demo, I'll use q ≈ 2^16 for the birthday attack visualization (finds collision in ~256 hashes) and q ≈ 2^30 for the "full" hash shown. This is toy-sized but visually impressive. Let me know if you want larger parameters.

---

## 9. Execution Order (Next Steps)

1. **[Phase 0]** Light restructure → add `__init__.py` per PA, create `shared/utils.py`
2. **[Phase 1]** PA#5 backend (`mac.py`, `mac_game.py`, `routes.py`) + Flask registration
3. **[Phase 1]** PA#5 frontend (`PA5Panel.jsx`) + App.jsx tab
4. **[Phase 2]** PA#6 backend (`cca.py`, `cca_game.py`, `routes.py`)
5. **[Phase 2]** PA#6 frontend (`PA6Panel.jsx`) + App.jsx tab
6. **[Phase 3]** PA#7 backend (`merkle_damgard.py`, `routes.py`) with toy XOR compression
7. **[Phase 3]** PA#7 frontend (`PA7Panel.jsx`) with chain animation
8. **[Phase 4]** PA#8 backend (`dlp_hash.py`, `routes.py`) — plugs PA#7 MD transform
9. **[Phase 4]** PA#8 frontend (`PA8Panel.jsx`) with birthday attack progress bar
10. **[Verify]** Run all test files, check end-to-end API calls from frontend

