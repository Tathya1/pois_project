import { useState } from "react";

// Helper components for layout
const Badge = ({ ok, label }) => (
  <span style={{
    fontSize: "10px", padding: "2px 6px", borderRadius: "4px", marginLeft: "8px",
    background: ok ? "rgba(16, 185, 129, 0.2)" : "rgba(248, 113, 113, 0.2)",
    color: ok ? "#10b981" : "#f87171", border: `1px solid ${ok ? "#10b981" : "#f87171"}`
  }}>{label}</span>
);

const Field = ({ label, value }) => (
  <div style={{ marginBottom: "10px" }}>
    <div style={{ fontSize: "10px", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px" }}>{label}</div>
    <div style={{ fontFamily: "monospace", wordBreak: "break-all", color: "#e2e8f0", fontSize: "12px", background: "#0f172a", padding: "4px", borderRadius: "4px" }}>
        {value ? (String(value).length > 60 ? String(value).slice(0, 60) + "..." : value) : "—"}
    </div>
  </div>
);

export default function PA17Panel() {
  const [loading, setLoading] = useState(false);
  
  // Section 1: Original Workspace States
  const [message, setMessage] = useState(42);
  const [encryptedData, setEncryptedData] = useState(null);
  const [decryptResult, setDecryptResult] = useState(null);
  const [plainTamperResult, setPlainTamperResult] = useState(null);

  // Section 2: CCA2 Game States
  const [ccaChallenge, setCcaChallenge] = useState(null);
  const [oracleResponse, setOracleResponse] = useState(null);

  // Helper: Truncate long strings
  const trunc = (str, len) => str && str.length > len ? str.slice(0, len) + "..." : str;

  // --- Workspace Logic ---
  const handleEncrypt = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa17/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: Number(message) }),
      });
      const data = await res.json();
      if (data.success) setEncryptedData(data.ciphertext);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  const handleDecrypt = async (tampered) => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa17/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...encryptedData, tampered }),
      });
      const data = await res.json();
      setDecryptResult(data);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  const plainElgamalTamper = async () => {
    setLoading(true);
    // Simulate hitting an oracle that doesn't check signatures (vulnerable ElGamal)
    try {
      const res = await fetch("http://127.0.0.1:5000/pa17/plain_elgamal_tamper", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...encryptedData, tamper_type: 'multiply' }),
      });
      const data = await res.json();
      setPlainTamperResult(data);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  // --- Game Logic ---
  const startCCAGame = async () => {
    setLoading(true);
    const res = await fetch("http://127.0.0.1:5000/pa17/game/start", { method: "POST" });
    const data = await res.json();
    setCcaChallenge(data.challenge);
    setOracleResponse(null);
    setLoading(false);
  };

const queryOracle = async (type) => {
    setLoading(true);
    
    // 1. Create a modified copy of the challenge
    let tamperedChallenge = { ...ccaChallenge };

    if (type === 'multiply') {
      // In a real ElGamal malleability attack, we multiply c2 by a constant (e.g., 2)
      // This demonstrates that E(m) can be turned into E(2m)
      // We send a flag or perform the math if c2 is a number/BigInt
      tamperedChallenge = {
        ...ccaChallenge,
        CE: {
          ...ccaChallenge.CE,
          // If the backend expects the math done client-side:
          c2: ccaChallenge.CE.c2 * 2 
        },
        tamper_type: 'multiply' // Inform the backend this is a manipulated request
      };
    }

    try {
      const res = await fetch("http://127.0.0.1:5000/pa17/game/oracle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // 2. Send the tampered version
        body: JSON.stringify(tamperedChallenge),
      });
      const data = await res.json();
      setOracleResponse(data);
    } catch (e) { 
      console.error(e); 
    }
    setLoading(false);
  };

  return (
    <div style={{ padding: "30px", maxWidth: "1200px", margin: "0 auto", color: "#e2e8f0", background: "#0f172a", minHeight: "100vh" }}>
      <header style={{ marginBottom: "30px", borderBottom: "1px solid #334155", paddingBottom: "10px" }}>
        <h2 style={{ margin: 0 }}>PA#17 Signcryption Ecosystem</h2>
        <p style={{ color: "#94a3b8", fontSize: "14px" }}>Demonstrating IND-CCA2 security through Sign-then-Encrypt.</p>
      </header>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "30px" }}>
        
        {/* SECTION A: WORKSPACE */}
        <section>
          <div className="result-card" style={{ background: "#1e293b", padding: "20px", borderRadius: "12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "15px" }}>
              <strong style={{ fontSize: "18px" }}>Signcryption Flow</strong>
              <Badge ok={true} label="Secure" />
            </div>
            
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: "12px", color: "#94a3b8" }}>Message (m)</label>
              <input 
                type="number" 
                value={message} 
                onChange={e => setMessage(e.target.value)}
                style={{ width: "100%", padding: "8px", background: "#0f172a", border: "1px solid #334155", color: "white", borderRadius: "4px" }}
              />
            </div>

            <button onClick={handleEncrypt} disabled={loading} style={{ width: '100%', marginBottom: 14, padding: "10px", background: "#3b82f6", color: "white", border: "none", borderRadius: "4px", cursor: "pointer" }}>
              {loading ? "Processing..." : "Sign then Encrypt"}
            </button>

            {encryptedData && (
              <div style={{ background: "#0f172a", padding: "10px", borderRadius: "6px", marginBottom: 14 }}>
                <Field label="ElGamal (c1)" value={encryptedData.CE?.c1} />
                <Field label="ElGamal (c2)" value={encryptedData.CE?.c2} />
                <Field label="Signature (σ)" value={encryptedData.sigma} />
              </div>
            )}

            {encryptedData && (
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => handleDecrypt(false)} disabled={loading} style={{ flex: 1, padding: "8px", background: "#334155", color: "white", border: "none", borderRadius: "4px" }}>
                  Verify & Decrypt
                </button>
                <button onClick={() => handleDecrypt(true)} disabled={loading} style={{ flex: 1, padding: "8px", border: "1px solid #f87171", color: "#f87171", background: "transparent", borderRadius: "4px" }}>
                  Tamper & Decrypt
                </button>
              </div>
            )}

            {decryptResult && (
              <div style={{ marginTop: 14, padding: "10px", borderRadius: "4px", background: decryptResult.success ? "rgba(16, 185, 129, 0.1)" : "rgba(248, 113, 113, 0.1)" }}>
                <div style={{ fontSize: "11px", fontWeight: "bold" }}>{decryptResult.success ? "RESULT" : "ERROR"}</div>
                <div>{decryptResult.success ? decryptResult.message : decryptResult.error}</div>
              </div>
            )}

            <hr style={{ margin: "20px 0", border: "0", borderTop: "1px solid #334155" }} />

            {/* Plain ElGamal Comparison */}
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "10px" }}>
                <strong>Plain ElGamal (Malleable)</strong>
                <Badge ok={false} label="Vulnerable" />
              </div>
              <button onClick={plainElgamalTamper} disabled={loading || !encryptedData} style={{ width: '100%', padding: "8px", background: "#475569", color: "white", border: "none", borderRadius: "4px" }}>
                Submit Tampered C_E to Oracle
              </button>

              {plainTamperResult && (
                <div style={{ marginTop: 14, padding: "10px", border: "1px solid #fbbf24", borderRadius: "4px" }}>
                  <div style={{ color: "#fbbf24", fontWeight: "bold", fontSize: "12px" }}>⚠ Exploit Successful</div>
                  <div style={{ fontSize: "12px", color: "#94a3b8" }}>Oracle Decrypted: {plainTamperResult.message}</div>
                  <div style={{ fontSize: "10px", marginTop: "5px" }}>Notice: This is 2 × {message}</div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* SECTION B: IND-CCA2 SECURITY GAME */}
        <section>
          <div className="card" style={{ background: "#1e293b", padding: "20px", borderRadius: "12px", border: "1px solid #3b82f6" }}>
            <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "8px" }}>
               <div style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#3b82f6" }}></div>
               IND-CCA2 Challenge
            </h3>
            <p style={{ fontSize: "13px", color: "#94a3b8", lineHeight: "1.5" }}>
              Adversary Goal: Distinguish if the challenge ciphertext encrypts 100 or 200.
              The oracle will reject the original challenge but might decrypt tampered versions.
            </p>

            <button onClick={startCCAGame} disabled={loading} style={{ width: "100%", padding: "12px", background: "#3b82f6", color: "white", border: "none", borderRadius: "6px", fontWeight: "bold", marginBottom: "20px", cursor: "pointer" }}>
              {ccaChallenge ? "Reset Challenge" : "Receive Challenge CT"}
            </button>

            {ccaChallenge && (
              <div style={{ background: "#0f172a", padding: "15px", borderRadius: "8px" }}>
                <div style={{ fontSize: "11px", color: "#3b82f6", fontWeight: "bold", marginBottom: "10px" }}>CHALLENGE ACTIVE</div>
                
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  <button onClick={() => queryOracle('identity')} style={{ background: "#334155", color: "white", border: "none", padding: "10px", borderRadius: "4px", fontSize: "12px", cursor: "pointer" }}>
                    Query Oracle: Original CT
                  </button>
                  <button onClick={() => queryOracle('multiply')} style={{ background: "rgba(59, 130, 246, 0.1)", border: "1px solid #3b82f6", color: "#3b82f6", padding: "10px", borderRadius: "4px", fontSize: "12px", cursor: "pointer" }}>
                    Query Oracle: Malleability Attack (c₂ × 2)
                  </button>
                </div>

                {oracleResponse && (
                  <div style={{ marginTop: "20px", borderTop: "1px solid #334155", paddingTop: "15px" }}>
                    <div style={{ color: oracleResponse.success ? "#10b981" : "#f87171", fontWeight: "bold" }}>
                        {oracleResponse.success ? "🔓 Oracle Decrypted!" : "🛑 Oracle Aborted"}
                    </div>
                    <p style={{ fontSize: "12px", marginTop: "8px", color: "#94a3b8" }}>
                        {oracleResponse.success 
                          ? `The oracle returned: ${oracleResponse.message}.` 
                          : `The oracle refused/failed: ${oracleResponse.error}`}
                    </p>
                    {!oracleResponse.success && oracleResponse.error?.includes("Signature") && (
                        <div style={{ fontSize: "11px", background: "rgba(248, 113, 113, 0.1)", padding: "8px", borderRadius: "4px", marginTop: "5px", color: "#fca5a5" }}>
                            <strong>Security Proof:</strong> Signature verification failed. This prevents the Chosen Ciphertext Attack.
                        </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}