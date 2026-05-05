import { useState } from "react";
import "./PA13Panel.css";
import "./PA12Panel.css";

// Shared components
const Field = ({ label, value }) => (
  <div style={{ marginBottom: "8px" }}>
    <div style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>{label}</div>
    <div style={{ fontFamily: "monospace", wordBreak: "break-all", color: "#e2e8f0" }}>{value ?? "—"}</div>
  </div>
);

const Badge = ({ ok, label }) => (
  <span style={{
    fontSize: '10px',
    padding: '2px 6px',
    borderRadius: '4px',
    background: ok ? '#065f46' : '#991b1b',
    color: ok ? '#34d399' : '#f87171',
    marginLeft: '8px'
  }}>
    {label}
  </span>
);

export default function PA15Panel() {
  const [activeTab, setActiveTab] = useState("rsa");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // States for RSA
  const [message, setMessage] = useState("hello world");
  const [signature, setSignature] = useState(null);
  const [useRaw, setUseRaw] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [forgeM1, setForgeM1] = useState("3");
  const [forgeM2, setForgeM2] = useState("7");
  const [forgeResult, setForgeResult] = useState(null);

  // States for EUF-CMA
  const [oracleMsg, setOracleMsg] = useState("");
  const [history, setHistory] = useState([]);
  const [challenge, setChallenge] = useState({ m: "", s: "" });
  const [gameResult, setGameResult] = useState(null);

  // States for ElGamal
const runAutomatedGame = async () => {
    setLoading(true);
    setGameResult(null);
    setHistory([]);

    try {
      // 1. Reset the server-side game state
      await fetch("http://127.0.0.1:5000/pa15/game/reset", { method: "POST" });

      // 2. Query the Oracle 50 times automatically
      let lastSignature = "";
      const tempHistory = [];

      for (let i = 1; i <= 50; i++) {
        const m_i = `Chosen Message #${i}`;
        const res = await fetch("http://127.0.0.1:5000/pa15/game/oracle", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: m_i })
        });
        const data = await res.json();
        if (data.success) {
          lastSignature = data.sigma;
          if (i % 10 === 0 || i === 50) {
            tempHistory.push({ m: m_i, s: data.sigma });
          }
        }
      }
      setHistory(tempHistory);

      // 3. Attempt Forgery (m*, sigma*)
      // We pick a message the oracle NEVER saw
      const mStar = "Attack_Success_Message_99";
      // An adversary might try to reuse a previous signature (this will fail in secure RSA)
      const sigmaStar = lastSignature; 
      
      setChallenge({ m: mStar, s: sigmaStar });

      // 4. Submit to Challenge Oracle
      const resChallenge = await fetch("http://127.0.0.1:5000/pa15/game/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: mStar, signature: sigmaStar })
      });
      const dataChallenge = await resChallenge.json();
      setGameResult(dataChallenge.valid);

    } catch (err) {
      console.error("Game failed", err);
    } finally {
      setLoading(false);
    }
  };

  const trunc = (str, len) => (str && str.length > len ? str.substring(0, len) + "..." : str);

  // RSA Logic
  const sign = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa15/rsa/sign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, use_raw: useRaw })
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setSignature(data.signature);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const verify = async (msg, sig, tamper = false) => {
    setLoading(true);
    const finalMsg = tamper ? msg + "_tampered" : msg;
    try {
      const res = await fetch("http://127.0.0.1:5000/pa15/rsa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: finalMsg, signature: sig, use_raw: useRaw })
      });
      const data = await res.json();
      setVerifyResult({ ...data, message: finalMsg });
    } catch (err) {
      setError("Verification failed");
    } finally {
      setLoading(false);
    }
  };

  const forge = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa15/rsa/forge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ m1: forgeM1, m2: forgeM2 })
      });
      const data = await res.json();
      setForgeResult(data);
    } catch (err) {
      setError("Forgery calculation failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="pa15-container" style={{ padding: "20px", maxWidth: "900px", margin: "0 auto", color: "#e2e8f0" }}>
      <h2 style={{ color: "#e2e8f0" }}>PA#15 — Digital Signature Ecosystem</h2>
      
      <div className="tabs" style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
        {["rsa", "euf-cma"].map(tab => (
          <button 
            key={tab} 
            className={activeTab === tab ? "tab-active" : "tab-inactive"}
            onClick={() => setActiveTab(tab)}
            style={{ 
                padding: "8px 16px", 
                cursor: "pointer",
                background: activeTab === tab ? "#3b82f6" : "#334155",
                color: "white",
                border: "none",
                borderRadius: "4px"
            }}
          >
            {tab.toUpperCase()}
          </button>
        ))}
      </div>

      {activeTab === "rsa" && (
        <section className="card" style={{ background: "#1e293b", padding: "20px", borderRadius: "8px" }}>
          <h3>RSA Sign & Multiplicative Forgery</h3>
          <p className="sub" style={{ color: "#94a3b8", fontSize: "14px" }}>
            Demonstrates Hash-then-Sign using RSA. Without hashing (Raw RSA), the signature scheme is vulnerable to multiplicative forgery.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20, marginTop: 20 }}>
            <div className="result-card" style={{ background: "#0f172a", padding: "15px", borderRadius: "8px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 15 }}>
                <strong>Sign & Verify</strong>
                <Badge ok={!useRaw} label={useRaw ? "Raw RSA" : "Hash-then-Sign"} />
              </div>
              
              <div style={{ marginBottom: 14 }}>
                <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, cursor: "pointer", color: "#f87171" }}>
                  <input type="checkbox" checked={useRaw} onChange={e => setUseRaw(e.target.checked)} />
                  Use Raw RSA (Warning: Vulnerable)
                </label>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <label style={{ fontSize: "12px" }}>Message</label>
                <input 
                  type={useRaw ? "number" : "text"} 
                  value={message} 
                  onChange={e => setMessage(e.target.value)} 
                  placeholder="Message to sign"
                  style={{ padding: "8px", borderRadius: "4px", border: "1px solid #334155", background: "#1e293b", color: "white" }}
                />
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <button onClick={sign} disabled={loading} style={{ flex: 1 }}>Sign</button>
                  <button onClick={() => verify(message, signature, false)} disabled={loading || !signature} style={{ flex: 1 }}>Verify</button>
                  <button onClick={() => verify(message, signature, true)} disabled={loading || !signature} style={{ flex: 1.5, color: "#f87171" }}>Tamper & Verify</button>
                </div>
              </div>

              {error && <div style={{ color: "#f87171", marginTop: 10, fontSize: "12px" }}>{error}</div>}

              {signature && (
                <div style={{ marginTop: 14 }}>
                  <Field label="Signature (σ) [Hex]" value={trunc(signature, 120)} />
                </div>
              )}

              {verifyResult && (
                <div style={{ marginTop: 14, padding: "10px", background: verifyResult.valid ? "#064e3b" : "#450a0a", borderRadius: "4px" }}>
                    <div style={{ fontSize: "12px", fontWeight: "bold" }}>
                        {verifyResult.valid ? "✓ Valid Signature" : "✗ Invalid Signature"}
                    </div>
                    <div style={{ fontSize: "10px", marginTop: 4, fontFamily: "monospace" }}>
                        Recov: {trunc(verifyResult.sigma_e, 40)}
                    </div>
                </div>
              )}
            </div>

            <div className="result-card" style={{ background: "#0f172a", padding: "15px", borderRadius: "8px", opacity: useRaw ? 1 : 0.5 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 15 }}>
                <strong>Multiplicative Forgery</strong>
                <Badge ok={false} label="Attack" />
              </div>
              
              <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: "11px" }}>m₁</label>
                  <input style={{ width: "100%", background: "#1e293b", color: "white", border: "1px solid #334155" }} type="number" value={forgeM1} onChange={e => setForgeM1(e.target.value)} disabled={!useRaw} />
                </div>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: "11px" }}>m₂</label>
                  <input style={{ width: "100%", background: "#1e293b", color: "white", border: "1px solid #334155" }} type="number" value={forgeM2} onChange={e => setForgeM2(e.target.value)} disabled={!useRaw} />
                </div>
              </div>

              <button onClick={forge} disabled={loading || !useRaw} style={{ width: '100%' }}>
                Demonstrate Forgery
              </button>

              {forgeResult && (
                <div style={{ marginTop: 14 }}>
                  <Field label="Forged Msg (m₁×m₂)" value={forgeResult.m_forged} />
                  <Field label="Forged Sig (s₁×s₂)" value={trunc(String(forgeResult.s_forged), 80)} />
                  <div style={{ color: forgeResult.valid ? "#4ade80" : "#f87171", fontSize: "12px", fontWeight: "bold" }}>
                    {forgeResult.valid ? "✓ Forgery Successful!" : "✗ Forgery Failed"}
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>
      )}

      {activeTab === "euf-cma" && (
        <section className="card" style={{ background: "#1e293b", padding: "20px", borderRadius: "8px" }}>
          <h3>EUF-CMA Security Game</h3>
          <p className="sub" style={{ color: "#94a3b8", marginBottom: "15px" }}>
            The adversary wins if they can produce a valid signature for a message they never sent to the oracle.
          </p>
          
          <button 
            onClick={runAutomatedGame} 
            disabled={loading}
            style={{ 
              width: "100%", 
              padding: "12px", 
              background: "#3b82f6", 
              fontWeight: "bold", 
              marginBottom: "20px",
              cursor: loading ? "not-allowed" : "pointer"
            }}
          >
            {loading ? "🔄 Querying Oracle (50 times)..." : "🚀 Run Automated Attack"}
          </button>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
            <div style={{ background: "#0f172a", padding: "15px", borderRadius: "8px" }}>
                <div style={{ fontSize: "12px", color: "#94a3b8", marginBottom: "10px" }}>Oracle History (Sample)</div>
                {history.map((h, i) => (
                    <div key={i} style={{ fontSize: "10px", borderBottom: "1px solid #1e293b", padding: "4px 0" }}>
                        <strong>M:</strong> {h.m} <br/>
                        <span style={{ color: "#64748b" }}>S: {h.s.substring(0, 30)}...</span>
                    </div>
                ))}
            </div>

            <div style={{ border: "2px solid #3b82f6", padding: "15px", borderRadius: "8px" }}>
                <div style={{ color: "#3b82f6", fontSize: "12px", fontWeight: "bold", marginBottom: "10px" }}>Forgery Attempt</div>
                <Field label="Target Message (m*)" value={challenge.m} />
                <Field label="Forged Signature (σ*)" value={challenge.s.substring(0, 40) + "..."} />
                
                {gameResult !== null && (
                    <div style={{ 
                        marginTop: "20px", 
                        padding: "15px", 
                        borderRadius: "4px", 
                        textAlign: "center",
                        background: gameResult ? "#065f46" : "#450a0a",
                        border: `1px solid ${gameResult ? "#34d399" : "#f87171"}`
                    }}>
                        <div style={{ fontSize: "16px", fontWeight: "bold" }}>
                            {gameResult ? "✅ SUCCESS: SCHEME BROKEN" : "❌ FAILED: SCHEME SECURE"}
                        </div>
                        <p style={{ fontSize: "11px", marginTop: "5px" }}>
                            {gameResult 
                                ? "The adversary successfully forged a signature!" 
                                : "The signature for the new message was rejected."}
                        </p>
                    </div>
                )}
            </div>
          </div>
        </section>
      )}

    </div>
  );
}