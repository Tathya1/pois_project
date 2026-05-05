from flask import Flask, Blueprint, request, jsonify
from flask_cors import CORS  # 1. IMPORTANT: Install with 'pip install flask-cors'
import sys
import os

# Set up paths for your crypto modules
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA12"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA15"))

# Import your custom crypto functions
from rsa import RSA
from rsa_signature import (
    sign, verify, 
    sign_raw, verify_raw, verify_with_intermediates, verify_raw_with_intermediates
)

app = Flask(__name__)
CORS(app) # 2. Enable CORS so React can talk to Flask

pa15 = Blueprint('pa15', __name__, url_prefix='/pa15')

# Store keys and state
keys = {}
state = {
    "rsa_keys": None,
    "elgamal_keys": None,
    "elgamal_sk": None,
    "oracle_queries": set(),
    "query_count": 0
}

def ensure_keys():
    """Helper to ensure RSA keys exist before signing/verifying."""
    if 'sk' not in keys:
        rsa = RSA()
        k = rsa.keygen(bits=512) # Use 512 for better security demo
        keys['sk'] = k
        keys['vk'] = {"N": k["N"], "e": k["e"]}

# --- RSA ROUTES ---

@pa15.route('/rsa/sign', methods=['POST']) # Updated URL to match React
def sign_demo():
    data = request.get_json() or {}
    message = data.get('message', 'hello world')
    use_raw = data.get('use_raw', False) # Match React key 'use_raw'
    
    ensure_keys()
        
    try:
        if use_raw:
            # For raw RSA, we treat the message as an integer (or convert it)
            m_int = int(message) if message.isdigit() else int.from_bytes(message.encode(), 'big')
            sigma = sign_raw(keys['sk'], m_int)
        else:
            sigma = sign(keys['sk'], message)
            
        return jsonify({
            "success": True, 
            "signature": hex(sigma)[2:], 
            "vk": {"N": hex(keys['vk']["N"])[2:], "e": keys['vk']["e"]}
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@pa15.route('/rsa/verify', methods=['POST'])
def verify_demo():
    data = request.get_json() or {}
    message = data.get('message', '')
    sigma_hex = data.get('signature', '0')
    use_raw = data.get('use_raw', False)
    
    if 'vk' not in keys:
        return jsonify({"success": False, "error": "No keys generated"})
        
    try:
        sigma = int(sigma_hex, 16)
        if use_raw:
            m_input = int(message) if message.isdigit() else int.from_bytes(message.encode(), 'big')
            res = verify_raw_with_intermediates(keys['vk'], m_input, sigma)
        else:
            res = verify_with_intermediates(keys['vk'], message, sigma)
            
        return jsonify({
            "success": True, 
            "valid": res["valid"],
            "h_m": hex(res["h_m"])[2:] if not use_raw else hex(res["m"])[2:],
            "sigma_e": hex(res["sigma_e"])[2:],
            "message": message
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@pa15.route('/rsa/forge', methods=['POST'])
def forge_demo():
    data = request.get_json() or {}
    m1 = int(data.get('m1', 3))
    m2 = int(data.get('m2', 7))
    
    ensure_keys()
        
    s1 = sign_raw(keys['sk'], m1)
    s2 = sign_raw(keys['sk'], m2)
    
    # The vulnerability: s_forged = (m1*m2)^d = m1^d * m2^d = s1 * s2
    s_forged = (s1 * s2) % keys['sk']['N']
    m_forged = (m1 * m2) % keys['sk']['N']
    
    is_valid = verify_raw(keys['vk'], m_forged, s_forged)
    
    return jsonify({
        "success": True, 
        "m_forged": str(m_forged),
        "s_forged": hex(s_forged)[2:],
        "valid": is_valid
    })

# --- EUF-CMA GAME ROUTES ---
@pa15.route('/game/reset', methods=['POST'])
def reset_game():
    """Resets the game state for a fresh run."""
    from rsa import RSA
    rsa = RSA()
    state["rsa_keys"] = rsa.keygen(bits=512)
    state["oracle_queries"] = set()
    state["query_count"] = 0
    return jsonify({"success": True, "message": "Game reset with new keys"})

@pa15.route('/game/oracle', methods=['POST'])
def oracle():
    if state["query_count"] >= 50:
        return jsonify({"success": False, "error": "Oracle limit reached (50/50)"})
    
    data = request.get_json()
    msg = data.get('message', '')
    
    if not state["rsa_keys"]:
        from rsa import RSA
        rsa = RSA()
        state["rsa_keys"] = rsa.keygen(bits=512)
        
    from rsa_signature import sign
    sigma = sign(state["rsa_keys"], msg)
    state["oracle_queries"].add(msg)
    state["query_count"] += 1
    
    return jsonify({
        "success": True, 
        "sigma": hex(sigma)[2:],
        "count": state["query_count"]
    })

@pa15.route('/game/challenge', methods=['POST'])
def challenge():
    data = request.get_json()
    msg = data.get('message', '')
    sigma_hex = data.get('signature', '')
    
    # Rule: Adversary cannot submit a message already queried to the oracle
    if msg in state["oracle_queries"]:
        return jsonify({"success": False, "error": "Message already signed by oracle!"})
    
    try:
        from rsa_signature import verify
        sigma = int(sigma_hex, 16)
        is_valid = verify(state["rsa_keys"], msg, sigma)
        return jsonify({"success": True, "valid": is_valid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# --- ELGAMAL ROUTES ---

app.register_blueprint(pa15)

if __name__ == '__main__':
    app.run(debug=True, port=5000)