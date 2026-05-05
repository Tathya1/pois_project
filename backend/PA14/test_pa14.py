"""
Tests for PA#14 — Chinese Remainder Theorem & Håstad's Broadcast Attack
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../PA12"))

from crt import crt, integer_nth_root, hastad_attack
from rsa import RSA

def test_crt_basic():
    # x = 2 mod 3
    # x = 3 mod 5
    # x = 2 mod 7
    # Answer is 23
    assert crt([2, 3, 2], [3, 5, 7]) == 23

def test_integer_nth_root_exact():
    assert integer_nth_root(27, 3) == 3
    assert integer_nth_root(1000000, 3) == 100
    assert integer_nth_root(2**30, 3) == 1024

def test_integer_nth_root_floor():
    assert integer_nth_root(28, 3) == 3
    assert integer_nth_root(999999, 3) == 99

def test_hastad_attack():
    rsa = RSA()
    e = 3
    message = 42
    
    keys = [rsa.keygen(bits=64) for _ in range(e)]
    moduli = [k["N"] for k in keys]
    ciphertexts = [rsa.encrypt(k["N"], e, message) for k in keys]
    
    x, recovered_m = hastad_attack(ciphertexts, moduli, e)
    assert recovered_m == message
    assert x == message ** 3
