"""PA8 package — DLP-Based Collision-Resistant Hash Function"""
import os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
_PA7  = os.path.join(_HERE, "..", "PA7")
for _p in [_HERE, _PA7]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dlp_hash import (
    DLP_Group, DLP_Hash, birthday_attack,
    collision_resistance_argument,
    get_default_group, get_default_hash,
    is_prime, find_safe_prime_pair,
)

__all__ = [
    "DLP_Group", "DLP_Hash", "birthday_attack",
    "collision_resistance_argument",
    "get_default_group", "get_default_hash",
    "is_prime", "find_safe_prime_pair",
]
