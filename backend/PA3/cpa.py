import secrets

from cpa_utils import normalize_key, xor_bytes
from stream import keystream, BLOCK_BYTES, pkcs7_pad, pkcs7_unpad

class CPA:
    @staticmethod
    def enc(key, message_bytes, r=None):
        key = normalize_key(key)

        if r is None:
            r = secrets.randbits(BLOCK_BYTES * 8)

        padded = pkcs7_pad(message_bytes, BLOCK_BYTES)

        stream = keystream(key, r, len(padded))
        cipher = xor_bytes(padded, stream)

        return r, cipher

    @staticmethod
    def dec(key, r, ciphertext):
        key = normalize_key(key)

        stream = keystream(key, r, len(ciphertext))
        padded = xor_bytes(ciphertext, stream)

        return pkcs7_unpad(padded, BLOCK_BYTES)

    @staticmethod
    def enc_text(key, message, r=None):
        r_int, cipher = CPA.enc(key, message.encode("utf-8"), r=r)
        return format(r_int, "016x"), cipher.hex()

    @staticmethod
    def dec_text(key, r_hex, c_hex):
        r_int = int(r_hex, 16)
        cipher = bytes.fromhex(c_hex)

        message = CPA.dec(key, r_int, cipher)
        return message.decode("utf-8", errors="replace")