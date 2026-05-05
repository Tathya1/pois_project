from flask import Blueprint, request, jsonify
import sys
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA12"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA14"))

from rsa import RSA, mod_exp
from pkcs15 import pkcs15_pad
from crt import hastad_attack, rsa_dec_crt

pa14 = Blueprint('pa14', __name__, url_prefix='/pa14')

@pa14.route('/hastad', methods=['POST'])
def hastad_demo():
    data = request.get_json() or {}
    message = data.get('message', 42)
    e = 3
    
    rsa = RSA()
    keys = [rsa.keygen(bits=64) for _ in range(e)]
    moduli = [k["N"] for k in keys]
    ciphertexts = [rsa.encrypt(k["N"], e, message) for k in keys]
    
    x, recovered_m = hastad_attack(ciphertexts, moduli, e)
    
    return jsonify({
        "success": recovered_m == message,
        "original_message": message,
        "recovered_integer": str(x),
        "recovered_message": recovered_m,
        "ciphertexts": ciphertexts,
        "moduli": moduli
    })

@pa14.route('/benchmark', methods=['GET'])
def benchmark_rsa():
    rsa = RSA()
    iterations = 1000
    results = {}

    for bits in [1024, 2048]:
        # Generate key and a test message
        keys = rsa.keygen(bits=bits)
        m = 123456789
        c = rsa.encrypt(keys["N"], keys["e"], m)
        
        # Standard Decryption Benchmark
        start_std = time.perf_counter()
        for _ in range(iterations):
            _ = mod_exp(c, keys["d"], keys["N"])
        end_std = time.perf_counter()
        
        # CRT Decryption Benchmark
        start_crt = time.perf_counter()
        for _ in range(iterations):
            _ = rsa_dec_crt(keys, c)
        end_crt = time.perf_counter()
        
        std_time = end_std - start_std
        crt_time = end_crt - start_crt
        
        results[f"{bits}"] = {
            "standard_time": round(std_time, 4),
            "crt_time": round(crt_time, 4),
            "speedup": round(std_time / crt_time, 2)
        }

    return jsonify(results)

@pa14.route('/hastad_padded', methods=['POST'])
def hastad_padded_demo():
    data = request.get_json() or {}
    message_val = data.get('message', 42)
    e = 3
    
    rsa = RSA()
    keys = [rsa.keygen(bits=512) for _ in range(e)] 
    moduli = [k["N"] for k in keys]
    
    ciphertexts = []
    m_bytes = int(message_val).to_bytes((int(message_val).bit_length() + 7) // 8 or 1, 'big')
    
    for k in keys:
        N = k["N"]
        k_bytes = (N.bit_length() + 7) // 8
        # Each padding is unique due to random bytes in PKCS#1 v1.5
        padded_m = pkcs15_pad(m_bytes, k_bytes)
        padded_m_int = int.from_bytes(padded_m, 'big')
        c = rsa.encrypt(N, e, padded_m_int)
        ciphertexts.append(c)
        
    x, recovered_m_int = hastad_attack(ciphertexts, moduli, e)
    
    return jsonify({
        "success": False,
        "recovered_integer": str(x),
        "recovered_message": "Garbage Value",
        "ciphertexts": ciphertexts,
        "moduli": moduli,
        "explanation": "Padding adds random bytes. Even if m is the same, padded_m1 != padded_m2."
    })