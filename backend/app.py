"""
backend/app.py
==============
Flask application entrypoint for the POIS Cryptographic Primitives API.

Blueprint registration
----------------------
pa1  — OWF + PRG          (routes in PA1/app_pa1.py)
pa2  — GGM PRF + AES PRF  (routes in PA2/app_pa2.py)
pa3  — CPA Encryption     (routes in PA3/app_pa3.py)
pa4  — Modes of Operation (routes in PA4/app_pa4.py)

Future blueprints (PA#5–PA#8) will be registered below as implemented.
"""

from flask import Flask
from flask_cors import CORS
import os
import sys

_BASE = os.path.dirname(os.path.abspath(__file__))

# Register all PA directories + shared on sys.path so blueprints can import
# their own modules with bare names (e.g. `from owf import DLP_OWF`).
for _sub in [
    "shared", "PA1", "PA2", "PA3", "PA4", "PA5", "PA6", "PA7", "PA8", "PA9", "PA10",
    "PA11", "PA12", "PA13", "PA14", "PA15", "PA16", "PA17", "PA18", "PA19", "PA20"
]:
    _p = os.path.join(_BASE, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Also put the backend root on the path (needed by distinguisher.py)
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from PA1.app_pa1 import pa1
from PA2.app_pa2 import pa2
from PA3.app_pa3 import pa3
from PA4.app_pa4 import pa4
from PA5.app_pa5 import pa5
from PA6.app_pa6 import pa6
from PA7.app_pa7 import pa7
from PA8.app_pa8 import pa8
from PA9.app_pa9 import pa9
from PA10.app_pa10 import pa10
from app_pa11 import pa11
from app_pa12 import pa12
from app_pa13 import pa13
from app_pa14 import pa14
from app_pa15 import pa15
from app_pa16 import pa16
from app_pa17 import pa17
from app_pa18 import pa18
from app_pa19 import pa19
from app_pa20 import pa20

app = Flask(__name__)
CORS(app)

app.register_blueprint(pa1)                      # routes: /prg, /test
app.register_blueprint(pa2)                      # routes: /prf
app.register_blueprint(pa3, url_prefix="/cpa")   # routes: /cpa/challenge, etc.
app.register_blueprint(pa4, url_prefix="/pa4")
app.register_blueprint(pa5, url_prefix="/pa5")
app.register_blueprint(pa6, url_prefix="/pa6")
app.register_blueprint(pa7, url_prefix="/pa7")
app.register_blueprint(pa8, url_prefix="/pa8")
app.register_blueprint(pa9, url_prefix="/pa9")
app.register_blueprint(pa10, url_prefix="/pa10")
app.register_blueprint(pa11)
app.register_blueprint(pa12)
app.register_blueprint(pa13)
app.register_blueprint(pa14)
app.register_blueprint(pa15)
app.register_blueprint(pa16)
app.register_blueprint(pa17)
app.register_blueprint(pa18)
app.register_blueprint(pa19)
app.register_blueprint(pa20)

if __name__ == "__main__":
    app.run(debug=True, port=5000)