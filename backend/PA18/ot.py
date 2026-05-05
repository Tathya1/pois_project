"""
PA#18 — 1-out-of-2 Oblivious Transfer (OT)

Protocol: Even-Goldreich-Lempel (EGL) RSA-based 1-of-2 OT.

Setup:
  Sender S has messages m0, m1 ∈ {0,1}^*.
  Receiver R has choice bit b ∈ {0, 1}.
  Goal: R receives m_b; S learns nothing about b; R learns nothing about m_{1-b}.

Protocol steps:
  1. S generates RSA keypair (N, e, d) and sends N, e (public) to R.
  2. S picks two random values x0, x1 in Z_N and sends them to R.
  3. R with choice b: picks random k in Z_N, computes
         v = (x_b + k^e) mod N
     and sends v to S.  (S cannot determine b from v without breaking RSA.)
  4. S computes:
         k0 = (v - x0)^d mod N      ← equals k  iff  b == 0
         k1 = (v - x1)^d mod N      ← equals k  iff  b == 1
     S sends: (m0 ⊕ H(k0), m1 ⊕ H(k1))  to R.
  5. R computes: m_b = (masked_m_b) ⊕ H(k).

Privacy:
  - Receiver privacy: v = x_b + k^e mod N.  Without k, S cannot tell which x_b
    was used, so S cannot determine b (RSA-OW assumption).
  - Sender privacy: R only knows k. Without the RSA private key d, R cannot
    compute k_{1-b} from v, x0, x1 — so m_{1-b} stays hidden.

Dependency: PA#12 (rsa.py) for RSA key generation and mod_exp.
"""

import os
import sys
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA12"))

from rsa import RSA as RSAImpl, mod_exp, mod_inverse


# ---------------------------------------------------------------------------
# Key-derivation helper (no hashlib — use integer folding)
# ---------------------------------------------------------------------------

def _kdf(k: int, length: int) -> bytes:
    """
    Toy key-derivation function: expand k into `length` bytes.
    Method: XOR-fold k mod 2^(8*length) across successive bit-windows.
    Good enough for an educational demo; NOT cryptographically secure.
    """
    mask = (1 << (8 * length)) - 1
    # Mix k with itself shifted by 13 bits to spread entropy
    mixed = k ^ (k >> 13) ^ (k << 7 & mask)
    return (mixed & mask).to_bytes(length, "big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (a and b must be the same length)."""
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# OT class
# ---------------------------------------------------------------------------

class OT12:
    """
    1-out-of-2 RSA-based Oblivious Transfer.

    All arithmetic is performed with PA#12's mod_exp / RSA primitives.
    No external crypto libraries.
    """

    # ------------------------------------------------------------------
    # Step 1 — Sender setup
    # ------------------------------------------------------------------

    def sender_setup(self, bits: int = 256) -> dict:
        """
        Sender generates an RSA keypair and two random challenges.

        Parameters
        ----------
        bits : int
            RSA modulus bit-length.  Use ≥ 512 for any security;
            smaller values (64–256) are fine for demo / test speed.

        Returns
        -------
        dict: {N, e, d, x0, x1}
          N, e: public (sent to receiver)
          d:    private (kept by sender; exposed here for demo transparency)
          x0, x1: random challenges in Z_N (sent to receiver)
        """
        bits = max(32, bits)
        rsa = RSAImpl()
        keys = rsa.keygen(bits)
        N  = int(keys["N"])
        e  = int(keys["e"])
        d  = int(keys["d"])
        # Random challenges in Z_N
        x0 = secrets.randbelow(N - 1) + 1
        x1 = secrets.randbelow(N - 1) + 1
        return {"N": N, "e": e, "d": d, "x0": x0, "x1": x1}

    # ------------------------------------------------------------------
    # Step 2 — Receiver query
    # ------------------------------------------------------------------

    def receiver_query(self, N: int, e: int, x0: int, x1: int,
                       choice: int) -> dict:
        """
        Receiver blinds their choice bit and sends v to the sender.

        Parameters
        ----------
        N, e : int  RSA public key
        x0, x1 : int  sender's challenge values
        choice : int  0 or 1 — which message the receiver wants

        Returns
        -------
        dict: {v, k}
          v: blinded query to send to sender
          k: receiver's secret (kept private; used for decryption in step 4)
        """
        assert choice in (0, 1), "choice must be 0 or 1"
        x_b = x0 if choice == 0 else x1
        # Random k ∈ [1, N-1]
        k = secrets.randbelow(N - 2) + 1
        # Blind: v = x_b + k^e mod N
        v = (x_b + mod_exp(k, e, N)) % N
        return {"v": v, "k": k, "choice": choice}

    # ------------------------------------------------------------------
    # Step 3 — Sender response
    # ------------------------------------------------------------------

    def sender_respond(self, N: int, d: int,
                       x0: int, x1: int, v: int,
                       m0: bytes, m1: bytes) -> dict:
        """
        Sender computes masked messages without learning receiver's choice.

        Parameters
        ----------
        N, d : int  RSA private key
        x0, x1 : int  sender's challenge values
        v : int  receiver's blinded query
        m0, m1 : bytes  the two messages

        Returns
        -------
        dict: {m0_enc, m1_enc, k0, k1}
          m0_enc = m0 ⊕ H(k0),  m1_enc = m1 ⊕ H(k1)
          k0, k1 exposed for demo; in a real protocol only sender knows them.
        """
        msg_len = max(len(m0), len(m1))
        # Recover candidate keys
        k0 = mod_exp((v - x0) % N, d, N)
        k1 = mod_exp((v - x1) % N, d, N)
        # Pad messages to equal length
        m0_padded = m0.ljust(msg_len, b"\x00")
        m1_padded = m1.ljust(msg_len, b"\x00")
        # Mask with derived keys
        m0_enc = _xor_bytes(m0_padded, _kdf(k0, msg_len))
        m1_enc = _xor_bytes(m1_padded, _kdf(k1, msg_len))
        return {
            "m0_enc": m0_enc,
            "m1_enc": m1_enc,
            "k0": k0,
            "k1": k1,
            "msg_len": msg_len,
        }

    # ------------------------------------------------------------------
    # Step 4 — Receiver decryption
    # ------------------------------------------------------------------

    def receiver_decrypt(self, choice: int, k: int,
                         m0_enc: bytes, m1_enc: bytes) -> bytes:
        """
        Receiver decrypts their chosen message.

        Parameters
        ----------
        choice : int  0 or 1
        k : int       receiver's secret from step 2
        m0_enc, m1_enc : bytes  masked messages from sender

        Returns
        -------
        bytes: the recovered message m_choice (stripped of zero-padding)
        """
        m_enc = m0_enc if choice == 0 else m1_enc
        pad   = _kdf(k, len(m_enc))
        return _xor_bytes(m_enc, pad).rstrip(b"\x00")

    # ------------------------------------------------------------------
    # Full protocol (convenience)
    # ------------------------------------------------------------------

    def run_protocol(self, m0: bytes, m1: bytes,
                     choice: int, bits: int = 128) -> dict:
        """
        Run all four steps and return a detailed trace.

        Parameters
        ----------
        m0, m1  : bytes  sender's two messages
        choice  : int    receiver's choice bit (0 or 1)
        bits    : int    RSA modulus bit-length

        Returns
        -------
        dict with full protocol trace, including recovered message and
        correctness / privacy annotations.
        """
        # Step 1
        setup = self.sender_setup(bits)
        N, e, d = setup["N"], setup["e"], setup["d"]
        x0, x1  = setup["x0"], setup["x1"]

        # Step 2
        query = self.receiver_query(N, e, x0, x1, choice)
        v, k  = query["v"], query["k"]

        # Step 3
        response = self.sender_respond(N, d, x0, x1, v, m0, m1)

        # Step 4
        recovered = self.receiver_decrypt(
            choice, k, response["m0_enc"], response["m1_enc"]
        )

        expected = (m0 if choice == 0 else m1).rstrip(b"\x00")
        success  = recovered == expected

        return {
            "choice":    choice,
            "expected":  expected.decode("utf-8", errors="replace"),
            "recovered": recovered.decode("utf-8", errors="replace"),
            "success":   success,
            "trace": {
                "step1_sender_setup": {
                    "N":   str(N), "e": str(e),
                    "x0":  str(x0), "x1": str(x1),
                    "note": "Sender generates RSA keypair + two random challenges x0, x1.",
                },
                "step2_receiver_query": {
                    "choice": choice,
                    "k":   str(k),
                    "v":   str(v),
                    "note": (
                        f"Receiver blinds x{choice} with secret k: "
                        f"v = x{choice} + k^e mod N."
                    ),
                },
                "step3_sender_response": {
                    "k0":       str(response["k0"]),
                    "k1":       str(response["k1"]),
                    "m0_enc":   response["m0_enc"].hex(),
                    "m1_enc":   response["m1_enc"].hex(),
                    "note": (
                        "Sender computes k0=(v−x0)^d, k1=(v−x1)^d. "
                        f"Exactly k{choice}=k (the other is random). "
                        "Masks both messages with H(k0), H(k1)."
                    ),
                },
                "step4_receiver_decrypt": {
                    "recovered": recovered.decode("utf-8", errors="replace"),
                    "note": (
                        f"Receiver unmasks m{choice} using H(k). "
                        f"m{1-choice} remains hidden."
                    ),
                },
            },
            "security": {
                "receiver_privacy": (
                    "Sender sees only v. Without breaking RSA-OW, sender "
                    "cannot determine which x_b was used → cannot learn b."
                ),
                "sender_privacy": (
                    f"Receiver holds k. k{1-choice} ≠ k, so m{1-choice} "
                    "is masked with an unknown key → stays hidden."
                ),
            },
        }
