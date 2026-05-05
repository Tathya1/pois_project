"""
PA5/mac_game.py
===============
Simulations and Games for PA#5.
Includes the EUF-CMA simulation against a dummy adversary.
"""

import secrets
import random
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SHARED = os.path.join(_HERE, "..", "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

from utils import normalize_key

def euf_cma_game(mac_class, rounds=20) -> dict:
    """
    Plays the Existential Unforgeability under Chosen-Message Attack (EUF-CMA) game.
    The dummy adversary requests MACs for random messages, then attempts a forgery.
    """
    mac_instance = mac_class()
    key = secrets.randbits(64)
    
    attempts = 0
    successes = 0
    
    for _ in range(rounds):
        # Adversary gets 5 chosen message queries
        queries = []
        for _ in range(5):
            msg = secrets.token_bytes(8)
            tag = mac_instance.mac(key, msg)
            queries.append((msg, tag))
            
        # Adversary attempts a forgery: standard dummy tries to modify one of the queried messages
        msg_forged = queries[0][0][:-1] + bytes([queries[0][0][-1] ^ 0x01])  # flip a bit
        
        # Or generates a completely new random message
        if random.random() > 0.5:
            msg_forged = secrets.token_bytes(8)
            
        # Generates a random tag or reuses an old one
        tag_forged = queries[1][1] if random.random() > 0.5 else secrets.token_hex(8)
        
        attempts += 1
        
        # Check if the forgery is valid AND the message wasn't queried
        queried_msgs = [q[0] for q in queries]
        if msg_forged not in queried_msgs:
            if mac_instance.verify(key, msg_forged, tag_forged):
                successes += 1
                
    return {
        "rounds": rounds,
        "forgery_attempts": attempts,
        "forgery_successes": successes,
        "advantage": successes / attempts if attempts > 0 else 0,
        "conclusion": "Standard MACs resist EUF-CMA. Forgeries should be ~0."
    }

def length_extension_demo(naive_hash_fn) -> dict:
    """
    Toy demo showing how H(k||m) is broken by length extension if H is Merkle-Damgard.
    Since we don't have PA#8 hash yet, this returns a placeholder explanation.
    """
    return {
        "status": "Placeholder",
        "explanation": "Length extension attacks on naive H(k||m) MACs will be fully demonstrated after PA#7 and PA#8 (Merkle-Damgard and CRHF) are implemented."
    }
