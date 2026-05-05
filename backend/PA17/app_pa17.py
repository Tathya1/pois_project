from flask import Blueprint, request, jsonify
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA16"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA15"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA17"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA12"))

from elgamal import ElGamal
from rsa import RSA
from cca_pkc import signcrypt, verify_decrypt

pa17 = Blueprint('pa17', __name__, url_prefix='/pa17')

# Store keys in memory
keys = {}

@pa17.route('/keygen', methods=['POST'])
def keygen():
    elgamal = ElGamal()
    elg_keys = elgamal.keygen(bits=32)
    
    rsa = RSA()
    rsa_keys = rsa.keygen(bits=256)
    
    keys['pk_enc'] = {"p": elg_keys["p"], "q": elg_keys["q"], "g": elg_keys["g"], "h": elg_keys["h"]}
    keys['sk_enc'] = {"p": elg_keys["p"], "x": elg_keys["x"]}
    
    keys['sk_sign'] = rsa_keys
    keys['vk_sign'] = {"N": rsa_keys["N"], "e": rsa_keys["e"]}
    
    return jsonify({"success": True})

@pa17.route('/encrypt', methods=['POST'])
def encrypt_demo():
    data = request.get_json() or {}
    message = data.get('message', 42)
    
    if 'pk_enc' not in keys:
        keygen()
        
    try:
        result = signcrypt(keys['pk_enc'], keys['sk_sign'], message)
        
        # Convert large ints to strings
        result['sigma'] = str(result['sigma'])
        result['CE']['c1'] = str(result['CE']['c1'])
        result['CE']['c2'] = str(result['CE']['c2'])
        
        return jsonify({"success": True, "ciphertext": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@pa17.route('/decrypt', methods=['POST'])
def decrypt_demo():
    data = request.get_json() or {}
    CE = data.get('CE')
    sigma = data.get('sigma')
    tampered = data.get('tampered', False)
    
    if 'sk_enc' not in keys:
        return jsonify({"success": False, "error": "No keys"})
        
    try:
        sigma = int(sigma)
        CE['c1'] = int(CE['c1'])
        CE['c2'] = int(CE['c2'])
    except Exception:
        pass
        
    if tampered:
        # Tamper with CE to simulate CCA attacker
        CE['c2'] = (CE['c2'] * 2) % keys['pk_enc']['p']
        
    try:
        result = verify_decrypt(keys['sk_enc'], keys['vk_sign'], CE, sigma)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@pa17.route('/plain_elgamal_tamper', methods=['POST'])
def plain_elgamal_tamper():
    data = request.get_json() or {}
    CE = data.get('CE')
    
    if 'sk_enc' not in keys:
        return jsonify({"success": False, "error": "No keys"})
        
    try:
        CE['c1'] = int(CE['c1'])
        CE['c2'] = int(CE['c2'])
    except Exception:
        pass
        
    # Tamper with CE
    CE['c2'] = (CE['c2'] * 2) % keys['pk_enc']['p']
    
    elgamal = ElGamal()
    m = elgamal.decrypt(keys['sk_enc']["p"], keys['sk_enc']["x"], CE['c1'], CE['c2'])
    
    return jsonify({"success": True, "tampered_CE": CE, "decrypted_message": m, "warning": "Decrypted to 2m, demonstrating malleability!"})

# --- IND-CCA2 GAME STATE ---
game_state = {
    "target_ct": None,
    "target_m": None,
    "oracle_queries": 0
}

@pa17.route('/game/start', methods=['POST'])
def start_cca_game():
    import random
    if 'pk_enc' not in keys: keygen()
    
    # Adversary chooses two messages (we'll pick for simplicity)
    m0, m1 = 100, 150
    b = random.randint(0, 1)
    target_m = m1 if b else m0
    
    # Signcrypt the target message
    res = signcrypt(keys['pk_enc'], keys['sk_sign'], target_m)
    
    game_state['target_ct'] = res
    game_state['target_m'] = target_m
    game_state['oracle_queries'] = 0
    
    # Convert large ints to strings for JSON
    challenge = {
        "sigma": str(res['sigma']),
        "CE": {"c1": str(res['CE']['c1']), "c2": str(res['CE']['c2'])}
    }
    return jsonify({"success": True, "challenge": challenge})

@pa17.route('/game/oracle', methods=['POST'])
def decryption_oracle():
    data = request.get_json() or {}
    CE = data.get('CE')
    sigma = data.get('sigma')
    
    # CCA2 Rule: You cannot query the exact challenge ciphertext
    if (str(CE.get('c1')) == str(game_state['target_ct']['CE']['c1']) and 
        str(CE.get('c2')) == str(game_state['target_ct']['CE']['c2'])):
        return jsonify({"success": False, "error": "Oracle Refusal: Cannot query target ciphertext!"})

    try:
        game_state['oracle_queries'] += 1
        # Attempt to verify and decrypt
        res = verify_decrypt(keys['sk_enc'], keys['vk_sign'], 
                             {"c1": int(CE['c1']), "c2": int(CE['c2'])}, 
                             int(sigma))
        return jsonify(res)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
