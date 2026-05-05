import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "..", "shared"))
sys.path.insert(0, os.path.join(BASE_DIR, "..", "PA2"))

from mac import PRF_MAC, CBC_MAC
from mac_game import euf_cma_game

def test_prf_mac():
    key = "1a2b3c4d"
    mac = PRF_MAC()
    
    msg1 = b"12345678"
    t1 = mac.mac(key, msg1)
    
    assert mac.verify(key, msg1, t1)
    assert not mac.verify(key, msg1, "0000000000000000")
    
    # Test padding/truncating implicitly
    msg2 = b"short"
    t2 = mac.mac(key, msg2)
    assert mac.verify(key, msg2, t2)
    assert mac.mac(key, b"short\x00\x00\x00") == t2
    
def test_cbc_mac():
    key = "1a2b3c4d"
    mac = CBC_MAC()
    
    msg1 = b"this is a much longer message to test cbc mac over multiple blocks"
    t1 = mac.mac(key, msg1)
    
    assert mac.verify(key, msg1, t1)
    
    # modify msg
    msg2 = b"this is a much longer message to test cbc mac over multiple block" + b"t"
    t2 = mac.mac(key, msg2)
    assert t1 != t2
    assert not mac.verify(key, msg1, t2)
    assert not mac.verify(key, msg2, t1)

def test_euf_cma():
    res1 = euf_cma_game(PRF_MAC, rounds=5)
    assert res1["forgery_successes"] == 0
    res2 = euf_cma_game(CBC_MAC, rounds=5)
    assert res2["forgery_successes"] == 0

if __name__ == "__main__":
    test_prf_mac()
    test_cbc_mac()
    test_euf_cma()
    print("All PA5 tests passed!")
