"""
Tests for PA#15 — Digital Signatures
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../PA12"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../PA8"))

from rsa import RSA
from rsa_signature import sign, verify, sign_raw, verify_raw, verify_with_intermediates

@pytest.fixture(scope="module")
def keys():
    rsa = RSA()
    return rsa.keygen(bits=256)

def test_sign_verify_roundtrip(keys):
    msg = "test message"
    sigma = sign(keys, msg)
    assert verify(keys, msg, sigma)

def test_verify_tampered_fails(keys):
    msg = "test message"
    sigma = sign(keys, msg)
    assert not verify(keys, "test message tampered", sigma)

def test_sign_raw_roundtrip(keys):
    msg_int = 12345
    sigma = sign_raw(keys, msg_int)
    assert verify_raw(keys, msg_int, sigma)

def test_multiplicative_forgery(keys):
    m1 = 2
    m2 = 3
    s1 = sign_raw(keys, m1)
    s2 = sign_raw(keys, m2)
    
    m_forged = (m1 * m2) % keys["N"]
    s_forged = (s1 * s2) % keys["N"]
    
    assert verify_raw(keys, m_forged, s_forged)

def test_verify_with_intermediates(keys):
    msg = "test message"
    sigma = sign(keys, msg)
    res = verify_with_intermediates(keys, msg, sigma)
    assert res["valid"]
    assert res["h_m"] == res["sigma_e"]
