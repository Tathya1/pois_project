"""
Tests for PA#17 — CCA-Secure PKC
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../PA16"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../PA15"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../PA12"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../PA8"))

from elgamal import ElGamal
from rsa import RSA
from cca_pkc import signcrypt, verify_decrypt

@pytest.fixture(scope="module")
def keys():
    elgamal = ElGamal()
    elg_keys = elgamal.keygen(bits=32)
    
    rsa = RSA()
    rsa_keys = rsa.keygen(bits=256)
    
    return {
        "pk_enc": {"p": elg_keys["p"], "q": elg_keys["q"], "g": elg_keys["g"], "h": elg_keys["h"]},
        "sk_enc": {"p": elg_keys["p"], "x": elg_keys["x"]},
        "sk_sign": rsa_keys,
        "vk_sign": {"N": rsa_keys["N"], "e": rsa_keys["e"]}
    }

def test_signcrypt_roundtrip(keys):
    msg = 42
    result = signcrypt(keys["pk_enc"], keys["sk_sign"], msg)
    
    CE = result["CE"]
    sigma = result["sigma"]
    
    dec_result = verify_decrypt(keys["sk_enc"], keys["vk_sign"], CE, sigma)
    assert dec_result["success"]
    assert dec_result["message"] == msg

def test_tampered_ciphertext_fails(keys):
    msg = 42
    result = signcrypt(keys["pk_enc"], keys["sk_sign"], msg)
    
    CE = result["CE"]
    sigma = result["sigma"]
    
    # CCA attack: tamper with c2
    CE["c2"] = (CE["c2"] * 2) % keys["pk_enc"]["p"]
    
    dec_result = verify_decrypt(keys["sk_enc"], keys["vk_sign"], CE, sigma)
    assert not dec_result["success"]
    assert "Signature invalid" in dec_result["error"]
