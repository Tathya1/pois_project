# Principles of Information Security (POIS) - Minicrypt Explorer

This repository contains the interactive implementations for the **POIS Programming Assignments (PA#1 through PA#8)**. It is built strictly following the "No-Library Rule", meaning all cryptographic primitives (PRGs, PRFs, Block Ciphers, MACs) are constructed from scratch using native Python primitives and mathematics.

## Prerequisites

Ensure you have the following installed on your system:
- **Python 3.10+**
- **Node.js 18+** & **npm**

---

## 1. Starting the Backend API

The backend is built in Flask and serves the heavy cryptographic logic (key expansions, tree constructions, mathematical reductions, etc.) to the UI.

1. Navigate to the backend directory:
   ```bash
   cd project/POIS/backend
   ```
2. Set up a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: The only external requirement should be `flask`, `flask-cors`, and `scipy` for NIST statistical tests. PyCryptodome is absolutely prohibited within the core implementations).*
4. Run the Flask Server:
   ```bash
   python3 app.py
   ```
   You should see terminal output indicating the server is running on `http://127.0.0.1:5000`.

---

## 2. Starting the Frontend UI (React)

The frontend is a React application that provides "Explorers" and visualizers for each cryptographic concept (e.g., GGM tree visualizer, Block mode animators, CCA malleability demos).

1. Open a new terminal window/tab.
2. Navigate to the frontend directory:
   ```bash
   cd project/POIS/frontend
   ```
3. Install dependencies (only needed the first time):
   ```bash
   npm install
   ```
4. Start the development server:
   ```bash
   npm run dev
   ```
   *(For Vite, it's typically `npm run dev`. If using Create React App, it might be `npm start`)*
5. Open your browser and navigate to `http://localhost:5173` (or `http://localhost:3000` depending on the bundler).

---

## 3. Running Cryptographic Unit Tests (CLI)

Even without the UI, you can rigorously test the individual mathematical models and "Cryptographic Games" (like IND-CPA, EUF-CMA). 

Each Programming Assignment contains a `test_paX.py` suite. Run them with:
```bash
cd project/POIS/backend
python3 PA1/test_pa1.py    # Tests OWF evaluate, PRG bits, NIST Randomness metrics
python3 PA2/test_pa2.py    # Tests pure-Python AES, GGM tree properties, Indistinguishability
python3 PA3/test_pa3.py    # Tests IND-CPA games, nonce-reuse destruction
python3 PA4/test_pa4.py    # Tests CBC/OFB/CTR, Error Propagations, bit-flipping
python3 PA5/test_pa5.py    # Tests CBC-MAC vs PRF-MAC, EUF-CMA games
python3 PA6/test_pa6.py    # Tests CCA enc/dec, MAC rejection, malleability, IND-CCA2 game
```

## 4. Current Supported Assignments

The interface contains individual tabs showcasing interactive elements for each Programming Assignment:
- **PA#1: PRG (Pseudorandom Generators)** - Generates bits sequentially from an OWF Hard-core predicate.
- **PA#2: PRF (Pseudorandom Functions)** - Maps the PRG to a stateful GGM tree and contains the pure-Python AES-128 plug-in. 
- **PA#3: CPA-Secure Encryption** - Demonstrates Encrypt-Then-Extract Nonce algorithms, including visual "Nonce-Reuse" vulnerabilities.
- **PA#4: Modes of Operation** - Features a 3-block flow animator to show *how* data transforms in CBC, OFB, and CTR modes.
- **PA#5: Secure MACs** - Showcases `PRF_MAC` vs `CBC_MAC` alongside an interactive EUF-CMA (Existential Unforgeability) dummy game simulator.
- **PA#6: CCA-Secure Encryption** - Split-panel demo showing CPA (malleable, red) vs CCA Encrypt-then-MAC (non-malleable, green). Includes an IND-CCA2 game and key-separation warning.

## Troubleshooting

- **CORS Errors in Browser Console:** Ensure your backend is running exactly on port `5000` (which is what the frontend expects).
- **ModuleNotFoundError in console:** Make sure you are executing the Python code strictly from the `backend/` directory root so the cross-package imports (e.g., `import shared.utils`) resolve properly.
