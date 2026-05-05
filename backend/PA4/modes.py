# pyright: reportMissingImports=false
import os
import sys
import secrets
from dataclasses import dataclass
from typing import Dict, List, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA2"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA3"))

from prf import GGM_PRF
from cpa_utils import normalize_key, xor_bytes

BLOCK_BYTES = 8
BLOCK_BITS = BLOCK_BYTES * 8
MASK_32 = (1 << 32) - 1
MASK_64 = (1 << 64) - 1
DEFAULT_ROUNDS = 6


def _int_to_bits(value: int, width: int) -> str:
    return format(value & ((1 << width) - 1), f"0{width}b")


def _chunks(data: bytes, block_size: int = BLOCK_BYTES) -> List[bytes]:
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def pkcs7_pad(data: bytes, block_size: int = BLOCK_BYTES) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_BYTES) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")

    return data[:-pad_len]


class FeistelPRP:
    """
    A tiny 64-bit Feistel-based PRP built from the PA#2 GGM PRF.
    This gives us both E_k and D_k needed for CBC while still reusing PA#2 primitives.
    """

    def __init__(self, rounds: int = DEFAULT_ROUNDS):
        self.rounds = rounds
        self.prf = GGM_PRF()

    def _f(self, key: int, round_idx: int, half_block: int) -> int:
        # Domain separation by round index + 32-bit input.
        # Input size to PRF = 8 + 32 = 40 bits.
        prf_in = _int_to_bits(round_idx, 8) + _int_to_bits(half_block, 32)
        out_hex = self.prf.F(key, prf_in)
        out_hex = out_hex.zfill(16)[-16:]
        out_int = int(out_hex, 16)
        return out_int & MASK_32

    def encrypt_block(self, key: int, block: bytes) -> bytes:
        if len(block) != BLOCK_BYTES:
            raise ValueError("Block must be exactly 8 bytes")

        v = int.from_bytes(block, "big")
        left = (v >> 32) & MASK_32
        right = v & MASK_32

        for rnd in range(self.rounds):
            left, right = right, left ^ self._f(key, rnd, right)

        out = ((left & MASK_32) << 32) | (right & MASK_32)
        return out.to_bytes(BLOCK_BYTES, "big")

    def decrypt_block(self, key: int, block: bytes) -> bytes:
        if len(block) != BLOCK_BYTES:
            raise ValueError("Block must be exactly 8 bytes")

        v = int.from_bytes(block, "big")
        left = (v >> 32) & MASK_32
        right = v & MASK_32

        for rnd in reversed(range(self.rounds)):
            left, right = right ^ self._f(key, rnd, left), left

        out = ((left & MASK_32) << 32) | (right & MASK_32)
        return out.to_bytes(BLOCK_BYTES, "big")


@dataclass
class EncryptResult:
    mode: str
    ciphertext: bytes
    iv: bytes | None = None
    nonce: bytes | None = None

    def to_dict(self) -> Dict[str, str]:
        out = {
            "mode": self.mode,
            "ciphertext": self.ciphertext.hex(),
        }
        if self.iv is not None:
            out["iv"] = self.iv.hex()
        if self.nonce is not None:
            out["nonce"] = self.nonce.hex()
        return out


class BlockModes:
    def __init__(self):
        self.block = FeistelPRP()

    def cbc_encrypt(self, key, message: bytes, iv: bytes | None = None) -> EncryptResult:
        key = normalize_key(key)
        iv = iv if iv is not None else secrets.token_bytes(BLOCK_BYTES)
        if len(iv) != BLOCK_BYTES:
            raise ValueError("IV must be 8 bytes")

        padded = pkcs7_pad(message, BLOCK_BYTES)
        prev = iv
        c_blocks = []

        for p in _chunks(padded, BLOCK_BYTES):
            x = xor_bytes(p, prev)
            c = self.block.encrypt_block(key, x)
            c_blocks.append(c)
            prev = c

        return EncryptResult(mode="CBC", ciphertext=b"".join(c_blocks), iv=iv)

    def cbc_decrypt(self, key, iv: bytes, ciphertext: bytes) -> bytes:
        key = normalize_key(key)
        if len(iv) != BLOCK_BYTES:
            raise ValueError("IV must be 8 bytes")
        if len(ciphertext) % BLOCK_BYTES != 0:
            raise ValueError("CBC ciphertext length must be multiple of block size")

        prev = iv
        p_blocks = []

        for c in _chunks(ciphertext, BLOCK_BYTES):
            x = self.block.decrypt_block(key, c)
            p = xor_bytes(x, prev)
            p_blocks.append(p)
            prev = c

        return pkcs7_unpad(b"".join(p_blocks), BLOCK_BYTES)

    def _cbc_decrypt_raw(self, key, iv: bytes, ciphertext: bytes) -> bytes:
        """CBC decryption without PKCS#7 unpadding (used for error-propagation demos)."""
        key = normalize_key(key)
        if len(iv) != BLOCK_BYTES:
            raise ValueError("IV must be 8 bytes")
        if len(ciphertext) % BLOCK_BYTES != 0:
            raise ValueError("CBC ciphertext length must be multiple of block size")

        prev = iv
        p_blocks = []

        for c in _chunks(ciphertext, BLOCK_BYTES):
            x = self.block.decrypt_block(key, c)
            p = xor_bytes(x, prev)
            p_blocks.append(p)
            prev = c

        return b"".join(p_blocks)

    def _ofb_stream(self, key, iv: bytes, length: int) -> bytes:
        key = normalize_key(key)
        if len(iv) != BLOCK_BYTES:
            raise ValueError("IV must be 8 bytes")

        state = iv
        out = b""
        blocks = (length + BLOCK_BYTES - 1) // BLOCK_BYTES

        for _ in range(blocks):
            state = self.block.encrypt_block(key, state)
            out += state

        return out[:length]

    def ofb_encrypt(self, key, message: bytes, iv: bytes | None = None) -> EncryptResult:
        iv = iv if iv is not None else secrets.token_bytes(BLOCK_BYTES)
        ks = self._ofb_stream(key, iv, len(message))
        c = xor_bytes(message, ks)
        return EncryptResult(mode="OFB", ciphertext=c, iv=iv)

    def ofb_decrypt(self, key, iv: bytes, ciphertext: bytes) -> bytes:
        # OFB decrypt is identical to encrypt (same keystream xor).
        ks = self._ofb_stream(key, iv, len(ciphertext))
        return xor_bytes(ciphertext, ks)

    def _ctr_stream(self, key, nonce: bytes, length: int) -> bytes:
        key = normalize_key(key)
        if len(nonce) != BLOCK_BYTES:
            raise ValueError("Nonce must be 8 bytes")

        r = int.from_bytes(nonce, "big")
        out = b""
        blocks = (length + BLOCK_BYTES - 1) // BLOCK_BYTES

        # Naturally parallelizable by block index i.
        for i in range(blocks):
            counter = (r + i) & MASK_64
            ctr_block = counter.to_bytes(BLOCK_BYTES, "big")
            out += self.block.encrypt_block(key, ctr_block)

        return out[:length]

    def ctr_encrypt(self, key, message: bytes, nonce: bytes | None = None) -> EncryptResult:
        nonce = nonce if nonce is not None else secrets.token_bytes(BLOCK_BYTES)
        ks = self._ctr_stream(key, nonce, len(message))
        c = xor_bytes(message, ks)
        return EncryptResult(mode="CTR", ciphertext=c, nonce=nonce)

    def ctr_decrypt(self, key, nonce: bytes, ciphertext: bytes) -> bytes:
        ks = self._ctr_stream(key, nonce, len(ciphertext))
        return xor_bytes(ciphertext, ks)

    def encrypt(self, mode: str, key, message: bytes) -> Dict[str, str]:
        mode = (mode or "").upper().strip()

        if mode == "CBC":
            return self.cbc_encrypt(key, message).to_dict()
        if mode == "OFB":
            return self.ofb_encrypt(key, message).to_dict()
        if mode == "CTR":
            return self.ctr_encrypt(key, message).to_dict()

        raise ValueError("Unsupported mode. Use one of: CBC, OFB, CTR")

    def decrypt(self, mode: str, key, ciphertext: bytes, *, iv: bytes | None = None, nonce: bytes | None = None) -> bytes:
        mode = (mode or "").upper().strip()

        if mode == "CBC":
            if iv is None:
                raise ValueError("CBC decryption requires iv")
            return self.cbc_decrypt(key, iv, ciphertext)

        if mode == "OFB":
            if iv is None:
                raise ValueError("OFB decryption requires iv")
            return self.ofb_decrypt(key, iv, ciphertext)

        if mode == "CTR":
            if nonce is None:
                raise ValueError("CTR decryption requires nonce")
            return self.ctr_decrypt(key, nonce, ciphertext)

        raise ValueError("Unsupported mode. Use one of: CBC, OFB, CTR")

    def trace_three_blocks(self, mode: str, key, message: bytes) -> Dict:
        """
        Returns intermediate values in hex for a 3-block message animation.
        """
        mode = mode.upper().strip()
        blocks = _chunks(message[: BLOCK_BYTES * 3].ljust(BLOCK_BYTES * 3, b"\x00"), BLOCK_BYTES)

        if mode == "CBC":
            iv = secrets.token_bytes(BLOCK_BYTES)
            prev = iv
            out = []
            c_blocks = []
            key_n = normalize_key(key)
            for idx, p in enumerate(blocks):
                x = xor_bytes(p, prev)
                c = self.block.encrypt_block(key_n, x)
                out.append(
                    {
                        "index": idx,
                        "plain": p.hex(),
                        "prev": prev.hex(),
                        "xor": x.hex(),
                        "cipher": c.hex(),
                    }
                )
                c_blocks.append(c)
                prev = c
            return {
                "mode": mode,
                "iv": iv.hex(),
                "blocks": out,
                "ciphertext": b"".join(c_blocks).hex(),
            }

        if mode == "OFB":
            iv = secrets.token_bytes(BLOCK_BYTES)
            state = iv
            out = []
            c_blocks = []
            key_n = normalize_key(key)
            for idx, p in enumerate(blocks):
                state_in = state
                state = self.block.encrypt_block(key_n, state)
                c = xor_bytes(p, state)
                out.append(
                    {
                        "index": idx,
                        "plain": p.hex(),
                        "stateIn": state_in.hex(),
                        "keystream": state.hex(),
                        "cipher": c.hex(),
                    }
                )
                c_blocks.append(c)
            return {
                "mode": mode,
                "iv": iv.hex(),
                "blocks": out,
                "ciphertext": b"".join(c_blocks).hex(),
                "note": "OFB keystream can be precomputed once IV is known.",
            }

        if mode == "CTR":
            nonce = secrets.token_bytes(BLOCK_BYTES)
            r = int.from_bytes(nonce, "big")
            out = []
            c_blocks = []
            key_n = normalize_key(key)
            for idx, p in enumerate(blocks):
                counter = (r + idx) & MASK_64
                ctr_block = counter.to_bytes(BLOCK_BYTES, "big")
                ks = self.block.encrypt_block(key_n, ctr_block)
                c = xor_bytes(p, ks)
                out.append(
                    {
                        "index": idx,
                        "plain": p.hex(),
                        "counter": ctr_block.hex(),
                        "keystream": ks.hex(),
                        "cipher": c.hex(),
                        "parallelizable": True,
                    }
                )
                c_blocks.append(c)
            return {
                "mode": mode,
                "nonce": nonce.hex(),
                "blocks": out,
                "ciphertext": b"".join(c_blocks).hex(),
                "note": "Each counter block is independent -> parallel block computation.",
            }

        raise ValueError("Unsupported mode. Use one of: CBC, OFB, CTR")

    def flip_bit_demo(self, mode: str, key, message: bytes, block_index: int, bit_index: int = 0) -> Dict:
        mode = mode.upper().strip()
        message = message[: BLOCK_BYTES * 3].ljust(BLOCK_BYTES * 3, b"\x00")

        enc = self.encrypt(mode, key, message)
        c = bytearray(bytes.fromhex(enc["ciphertext"]))

        byte_pos = block_index * BLOCK_BYTES + (bit_index // 8)
        if byte_pos < 0 or byte_pos >= len(c):
            raise ValueError("Invalid block/bit position")

        c[byte_pos] ^= 1 << (bit_index % 8)

        if mode == "CBC":
            iv = bytes.fromhex(enc["iv"])
            recovered = self._cbc_decrypt_raw(key, iv, bytes(c))
            original = self._cbc_decrypt_raw(key, iv, bytes.fromhex(enc["ciphertext"]))
        elif mode == "OFB":
            recovered = self.decrypt(mode, key, bytes(c), iv=bytes.fromhex(enc["iv"]))
            original = self.decrypt(mode, key, bytes.fromhex(enc["ciphertext"]), iv=bytes.fromhex(enc["iv"]))
        else:
            recovered = self.decrypt(mode, key, bytes(c), nonce=bytes.fromhex(enc["nonce"]))
            original = self.decrypt(mode, key, bytes.fromhex(enc["ciphertext"]), nonce=bytes.fromhex(enc["nonce"]))

        o_blocks = _chunks(original[: BLOCK_BYTES * 3].ljust(BLOCK_BYTES * 3, b"\x00"), BLOCK_BYTES)
        r_blocks = _chunks(recovered[: BLOCK_BYTES * 3].ljust(BLOCK_BYTES * 3, b"\x00"), BLOCK_BYTES)

        corrupted = [i for i, (a, b) in enumerate(zip(o_blocks, r_blocks)) if a != b]

        return {
            "mode": mode,
            "corruptedPlaintextBlocks": corrupted,
            "originalPlainBlocks": [b.hex() for b in o_blocks],
            "corruptedPlainBlocks": [b.hex() for b in r_blocks],
            "ciphertext": enc["ciphertext"],
            "tamperedCiphertext": bytes(c).hex(),
        }

    def cbc_iv_reuse_demo(self, key, message_a: bytes, message_b: bytes) -> Dict:
        iv = secrets.token_bytes(BLOCK_BYTES)
        e1 = self.cbc_encrypt(key, message_a, iv=iv)
        e2 = self.cbc_encrypt(key, message_b, iv=iv)

        p1 = _chunks(pkcs7_pad(message_a, BLOCK_BYTES), BLOCK_BYTES)
        p2 = _chunks(pkcs7_pad(message_b, BLOCK_BYTES), BLOCK_BYTES)
        c1 = _chunks(e1.ciphertext, BLOCK_BYTES)
        c2 = _chunks(e2.ciphertext, BLOCK_BYTES)

        count = min(len(c1), len(c2), len(p1), len(p2))
        matching_plain = [i for i in range(count) if p1[i] == p2[i]]
        matching_cipher = [i for i in range(count) if c1[i] == c2[i]]

        return {
            "iv": iv.hex(),
            "messageA": message_a.hex(),
            "messageB": message_b.hex(),
            "cipherA": e1.ciphertext.hex(),
            "cipherB": e2.ciphertext.hex(),
            "plainBlocksA": [b.hex() for b in p1],
            "plainBlocksB": [b.hex() for b in p2],
            "cipherBlocksA": [b.hex() for b in c1],
            "cipherBlocksB": [b.hex() for b in c2],
            "matchingPlainBlocks": matching_plain,
            "matchingCipherBlocks": matching_cipher,
            "note": "With IV reuse in CBC, equal plaintext blocks under same chaining context yield equal ciphertext blocks.",
        }

    def ofb_keystream_reuse_demo(self, key, message_a: bytes, message_b: bytes) -> Dict:
        iv = secrets.token_bytes(BLOCK_BYTES)
        e1 = self.ofb_encrypt(key, message_a, iv=iv)
        e2 = self.ofb_encrypt(key, message_b, iv=iv)

        min_len = min(len(e1.ciphertext), len(e2.ciphertext), len(message_a), len(message_b))

        cx = xor_bytes(e1.ciphertext[:min_len], e2.ciphertext[:min_len])
        px = xor_bytes(message_a[:min_len], message_b[:min_len])

        return {
            "iv": iv.hex(),
            "cipherA": e1.ciphertext.hex(),
            "cipherB": e2.ciphertext.hex(),
            "cipherXor": cx.hex(),
            "plainXor": px.hex(),
            "xorsMatch": cx == px,
            "note": "Reusing IV in OFB reuses keystream, so C1 xor C2 = M1 xor M2.",
        }


MODES = BlockModes()
