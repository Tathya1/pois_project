import { useState } from "react";
import "./PA6Panel.css";

const API = "http://localhost:5000";

const toHex = (s) =>
  Array.from(new TextEncoder().encode(s))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const hexToBytes = (hex) => {
  if (!hex) return new Uint8Array();
  const clean = hex.length % 2 === 0 ? hex : `0${hex}`;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

const bytesToHex = (bytes) =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const TABS = [
  { id: "malleability", label: "CPA vs CCA (Malleability)" },
  { id: "enc_dec",      label: "Encrypt / Decrypt" },
  { id: "game",         label: "IND-CCA2 Game" },
  { id: "key_sep",      label: "Key Separation" },
];

export default function PA6Panel() {
  const [activeTab, setActiveTab] = useState("malleability");

  // ── Shared inputs ──────────────────────────────────────────────────────
  const [key,     setKey]     = useState("1a2b3c4d");
  const [kE,      setKE]      = useState("1a2b3c4d");
  const [kM,      setKM]      = useState("deadbeef");
  const [message, setMessage] = useState("hello world!!!!!");
  const [error,   setError]   = useState("");

  // ── Malleability demo ─────────────────────────────────────────────────
  const [bitIndex,       setBitIndex]       = useState(0);
  const [mallResult,     setMallResult]     = useState(null);
  const [mallLoading,    setMallLoading]    = useState(false);

  // ── Encrypt/Decrypt ───────────────────────────────────────────────────
  const [encResult, setEncResult] = useState(null);
  const [decResult, setDecResult] = useState(null);

  // ── IND-CCA2 game ─────────────────────────────────────────────────────
  const [rounds,      setRounds]      = useState(20);
  const [gameResult,  setGameResult]  = useState(null);
  const [gameLoading, setGameLoading] = useState(false);

  // ── Key-separation demo ───────────────────────────────────────────────
  const [keySepResult, setKeySepResult] = useState(null);

  // ── API helpers ───────────────────────────────────────────────────────
  const post = async (path, body) => {
    const res  = await fetch(`${API}${path}`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok || data.error) throw new Error(data.error || "API error");
    return data;
  };

  // ── Malleability ──────────────────────────────────────────────────────
  const runMalleability = async () => {
    setMallLoading(true);
    setError("");
    try {
      const data = await post("/pa6/malleability", {
        key, message, bitIndex: Number(bitIndex),
      });
      setMallResult(data);
    } catch (e) { setError(e.message); }
    setMallLoading(false);
  };

  // ── Encrypt ───────────────────────────────────────────────────────────
  const runEncrypt = async () => {
    setError("");
    try {
      const data = await post("/pa6/encrypt", { kE, kM, message });
      setEncResult(data);
      setDecResult(null);
    } catch (e) { setError(e.message); }
  };

  // ── Decrypt ───────────────────────────────────────────────────────────
  const runDecrypt = async () => {
    if (!encResult) { setError("Encrypt first."); return; }
    setError("");
    try {
      const data = await post("/pa6/decrypt", {
        kE, kM, r: encResult.r, c: encResult.c, tag: encResult.tag,
      });
      setDecResult(data);
    } catch (e) { setError(e.message); }
  };

  // ── Tamper + try decrypt (should reject) ──────────────────────────────
  const runTamperAndDecrypt = async () => {
    if (!encResult) { setError("Encrypt first."); return; }
    setError("");
    try {
      const cBytes = hexToBytes(encResult.c);
      if (cBytes.length > 0) cBytes[0] ^= 0xff;
      const cTampered = bytesToHex(cBytes);

      const data = await post("/pa6/decrypt", {
        kE, kM, r: encResult.r, c: cTampered, tag: encResult.tag,
      });
      setDecResult({ ...data, tampered: true });
    } catch (e) { setError(e.message); }
  };

  // ── IND-CCA2 game ─────────────────────────────────────────────────────
  const runGame = async () => {
    setGameLoading(true);
    setError("");
    try {
      const data = await post("/pa6/cca2-game", { rounds });
      setGameResult(data);
    } catch (e) { setError(e.message); }
    setGameLoading(false);
  };

  // ── Key separation ────────────────────────────────────────────────────
  const runKeySep = async () => {
    setError("");
    try {
      const data = await post("/pa6/key-separation", { key, message });
      setKeySepResult(data);
    } catch (e) { setError(e.message); }
  };

  return (
    <div className="panel">
      <h3>PA#6 — CCA-Secure Encryption (Encrypt-then-MAC)</h3>

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {TABS.map((t) => (
          <button key={t.id} onClick={() => { setActiveTab(t.id); setError(""); }}
            style={{ fontWeight: activeTab === t.id ? "bold" : "normal",
                     background: activeTab === t.id ? "#1e40af" : "#1e293b",
                     color: "#e2e8f0", border: "none", borderRadius: 8,
                     padding: "8px 14px", cursor: "pointer" }}>
            {t.label}
          </button>
        ))}
      </div>

      {error && <p className="pa6-err">⚠ {error}</p>}

      {/* ═══════════════════════════════════════════════════════════════════
          TAB 1 — MALLEABILITY DEMO (split panel)
      ════════════════════════════════════════════════════════════════════ */}
      {activeTab === "malleability" && (
        <div className="pa6-grid">
          <div className="pa6-info">
            <b>Key educational demo:</b> CPA (PA#3) is <em>malleable</em> — an attacker can flip
            bits in the ciphertext and get a predictably corrupted decryption. CCA (PA#6)
            immediately rejects any tampered ciphertext via the MAC check (returns ⊥).
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <label className="pa6-grid">
              Shared key
              <input value={key} onChange={(e) => setKey(e.target.value)} />
            </label>
            <label className="pa6-grid">
              Message (pad to ≥8 chars)
              <input value={message} onChange={(e) => setMessage(e.target.value)} />
            </label>
            <label className="pa6-grid">
              Bit-flip index (0–63)
              <input type="number" min={0} max={63} value={bitIndex}
                onChange={(e) => setBitIndex(e.target.value)} />
            </label>
          </div>

          <div className="pa6-row">
            <button className="primary" onClick={runMalleability} disabled={mallLoading}>
              {mallLoading ? "Running…" : "Run Bit-flip Attack on Both Schemes"}
            </button>
          </div>

          {mallResult && (
            <div className="pa6-split">
              {/* CPA side — red */}
              <div className="pa6-side cpa">
                <h4>
                  CPA (PA#3){" "}
                  <span className="pa6-malleable-badge bad">MALLEABLE ⚠</span>
                </h4>
                <div className="pa6-result-box rejected">
                  <div>original : <b>{mallResult.cpa_result.original_message}</b></div>
                  <div>modified : <b>{mallResult.cpa_result.modified_message}</b></div>
                  <div>bit flipped in byte {mallResult.cpa_result.byte_flipped}</div>
                </div>
                <div className="pa6-info" style={{ fontSize: "0.78rem" }}>
                  c = Keystream ⊕ m. Flipping c[i] flips m[i] — no integrity check exists.
                </div>
              </div>

              {/* CCA side — green */}
              <div className="pa6-side cca">
                <h4>
                  CCA (PA#6){" "}
                  <span className="pa6-malleable-badge good">NON-MALLEABLE ✓</span>
                </h4>
                <div className="pa6-result-box accepted">
                  <div>Tampered ciphertext submitted to Dec oracle.</div>
                  <div style={{ marginTop: 6 }}>
                    Result:{" "}
                    <b>
                      {mallResult.cca_result.dec_result.rejected
                        ? "⊥ REJECTED"
                        : "✓ (unexpected — should not happen)"}
                    </b>
                  </div>
                </div>
                <div className="pa6-info" style={{ fontSize: "0.78rem" }}>
                  MAC was computed over (r ‖ c). Any modification invalidates the tag →
                  decryption is never reached.
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          TAB 2 — ENCRYPT / DECRYPT
      ════════════════════════════════════════════════════════════════════ */}
      {activeTab === "enc_dec" && (
        <div className="pa6-grid">
          <div className="pa6-info">
            Two independent keys are required: <b>kE</b> for encryption (PA#3 CPA) and
            <b> kM</b> for authentication (PA#5 CBC-MAC). Using the same key violates
            key separation (see "Key Separation" tab).
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <label className="pa6-grid">
              kE (Encryption key)
              <input value={kE} onChange={(e) => setKE(e.target.value)} />
            </label>
            <label className="pa6-grid">
              kM (MAC key — must differ from kE)
              <input value={kM} onChange={(e) => setKM(e.target.value)} />
            </label>
            <label className="pa6-grid">
              Plaintext message
              <input value={message} onChange={(e) => setMessage(e.target.value)} />
            </label>
          </div>

          <div className="pa6-row">
            <button className="primary" onClick={runEncrypt}>Enc-then-MAC</button>
            <button className="success" onClick={runDecrypt} disabled={!encResult}>
              Verify-then-Dec
            </button>
            <button className="danger" onClick={runTamperAndDecrypt} disabled={!encResult}>
              Tamper c + Dec (→ ⊥)
            </button>
          </div>

          {encResult && (
            <div className="pa6-result-box neutral">
              <div><b>r</b>   = {encResult.r}</div>
              <div><b>c</b>   = {encResult.c}</div>
              <div><b>tag</b> = {encResult.tag}</div>
              <div style={{ marginTop: 6, fontSize: "0.78rem", color: "#64748b" }}>
                {encResult.scheme}
              </div>
            </div>
          )}

          {decResult && (
            <div className={`pa6-result-box ${decResult.rejected ? "rejected" : "accepted"}`}>
              {decResult.tampered && <div>⚠ Tampered ciphertext submitted</div>}
              {decResult.rejected
                ? <div><b>⊥ REJECTED</b> — MAC verification failed. Plaintext never revealed.</div>
                : <div><b>✓ Decrypted:</b> {decResult.message}</div>
              }
            </div>
          )}
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          TAB 3 — IND-CCA2 GAME
      ════════════════════════════════════════════════════════════════════ */}
      {activeTab === "game" && (
        <div className="pa6-grid">
          <div className="pa6-info">
            In the IND-CCA2 game the adversary gets both an <b>Enc oracle</b> and a
            <b> Dec oracle</b> (except on the challenge ciphertext). Any attempt to modify
            the challenge and submit to the Dec oracle is rejected. The adversary is left with
            random guessing → advantage ≈ 0.
          </div>

          <label className="pa6-grid">
            Number of rounds (max 100)
            <input type="number" min={5} max={100} value={rounds}
              onChange={(e) => setRounds(Number(e.target.value))} />
          </label>

          <div className="pa6-row">
            <button className="primary" onClick={runGame} disabled={gameLoading}>
              {gameLoading ? "Simulating game…" : `Run IND-CCA2 Game (${rounds} rounds)`}
            </button>
          </div>

          {gameResult && (
            <>
              <div className="pa6-result-box neutral">
                <div className="pa6-stat-row">
                  <span>Rounds played</span>
                  <b>{gameResult.rounds}</b>
                </div>
                <div className="pa6-stat-row">
                  <span>Correct guesses</span>
                  <b>{gameResult.correct_guesses} / {gameResult.rounds}</b>
                </div>
                <div className="pa6-stat-row">
                  <span>All tampers rejected</span>
                  <b style={{ color: gameResult.all_tampers_rejected ? "#4ade80" : "#f87171" }}>
                    {gameResult.all_tampers_rejected ? "✓ YES" : "✗ NO (BUG!)"}
                  </b>
                </div>
                <div className="pa6-stat-row">
                  <span>Adversary advantage</span>
                  <b style={{ color: gameResult.advantage < 0.15 ? "#4ade80" : "#facc15" }}>
                    {(gameResult.advantage * 100).toFixed(1)}%
                    {gameResult.advantage < 0.15 ? " ✓ (≈ 0, negligible)" : " ⚠ (above expected)"}
                  </b>
                </div>

                <div style={{ marginTop: 8 }}>
                  <div style={{ fontSize: "0.78rem", color: "#64748b" }}>
                    Advantage (|correct/rounds − 0.5|)
                  </div>
                  <div className="pa6-adv-bar">
                    <div className="pa6-adv-fill"
                      style={{ width: `${Math.min(gameResult.advantage * 200, 100)}%`,
                               background: gameResult.advantage < 0.15 ? "#10b981" : "#facc15" }}
                    />
                  </div>
                </div>
              </div>

              <div className="pa6-info">{gameResult.conclusion}</div>
            </>
          )}
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          TAB 4 — KEY SEPARATION
      ════════════════════════════════════════════════════════════════════ */}
      {activeTab === "key_sep" && (
        <div className="pa6-grid">
          <div className="pa6-warn">
            <b>Key Separation Requirement (Formal):</b> The Encrypt-then-MAC security proof
            requires kE and kM to be <em>independently and uniformly sampled</em>.
            Using kE = kM breaks the hybrid argument in the proof and may allow an adversary
            to use the MAC oracle as an encryption oracle (or vice-versa).
          </div>

          <label className="pa6-grid">
            Shared key k (used as kE and kM in the "broken" variant)
            <input value={key} onChange={(e) => setKey(e.target.value)} />
          </label>
          <label className="pa6-grid">
            Message
            <input value={message} onChange={(e) => setMessage(e.target.value)} />
          </label>

          <div className="pa6-row">
            <button className="neutral" onClick={runKeySep}>Run Key Separation Demo</button>
          </div>

          {keySepResult && (
            <>
              <div className="pa6-split">
                <div className="pa6-side cca">
                  <h4>✓ Proper: kE ≠ kM</h4>
                  <div className="pa6-result-box accepted">
                    <div>kE = {keySepResult.attack?.separate_keys?.kE ?? keySepResult.proper_keys.kE}</div>
                    <div>kM = {keySepResult.attack?.separate_keys?.kM ?? keySepResult.proper_keys.kM}</div>
                    <div>r   = {keySepResult.attack?.separate_keys?.enc?.r ?? keySepResult.proper_keys.enc.r}</div>
                    <div>tag = {keySepResult.attack?.separate_keys?.enc?.tag ?? keySepResult.proper_keys.enc.tag}</div>
                    {keySepResult.attack && (
                      <>
                        <div>MAC(kM, r) = {keySepResult.attack.separate_keys.mac_oracle_on_r}</div>
                        <div>
                          recovered = {keySepResult.attack.separate_keys.recovered_message ?? "(failed)"}
                        </div>
                      </>
                    )}
                  </div>
                </div>
                <div className="pa6-side cpa">
                  <h4>⚠ Broken: kE = kM</h4>
                  <div className="pa6-result-box rejected">
                    <div>kE = kM = {keySepResult.attack?.same_key?.kE ?? keySepResult.same_key.kE}</div>
                    <div>r   = {keySepResult.attack?.same_key?.enc?.r ?? keySepResult.same_key.enc.r}</div>
                    <div>tag = {keySepResult.attack?.same_key?.enc?.tag ?? keySepResult.same_key.enc.tag}</div>
                    {keySepResult.attack && (
                      <>
                        <div>MAC(k, r) = {keySepResult.attack.same_key.mac_oracle_on_r}</div>
                        <div>
                          recovered = {keySepResult.attack.same_key.recovered_message ?? "(failed)"}
                        </div>
                        <div>
                          success = {keySepResult.attack.same_key.success ? "YES" : "NO"}
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>
              {keySepResult.note && (
                <div className="pa6-info" style={{ fontSize: "0.78rem" }}>{keySepResult.note}</div>
              )}
              <div className="pa6-warn" style={{ fontSize: "0.8rem" }}>
                {keySepResult.warning}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
