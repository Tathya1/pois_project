import { useState } from "react";
import "./PA13Panel.css";
import "./PA12Panel.css";

// Helper Sub-components
const Badge = ({ ok, label }) => (
  <span style={{
    padding: "2px 8px",
    borderRadius: "4px",
    fontSize: "11px",
    background: ok ? "#059669" : "#dc2626",
    color: "white",
    marginLeft: "8px"
  }}>
    {label}
  </span>
);

const Field = ({ label, value }) => (
  <div style={{ marginBottom: "8px" }}>
    <div style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>{label}</div>
    <div style={{ fontFamily: "monospace", wordBreak: "break-all", color: "#e2e8f0" }}>{value}</div>
  </div>
);

export default function PA14Panel() {
  // --- State Hooks ---
  const [activeTab, setActiveTab] = useState("broadcast");
  const [message, setMessage] = useState(42);
  const [usePadding, setUsePadding] = useState(false);
  const [result, setResult] = useState(null);
  const [bench, setBench] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [cubeRootRevealed, setCubeRootRevealed] = useState(false);

  // --- Helpers ---
  const trunc = (str, len) => {
    if (!str) return "";
    const s = String(str);
    return s.length > len ? s.substring(0, len) + "..." : s;
  };

  // --- API Calls ---
  const runAttack = async () => {
    setLoading(true);
    setError(null);
    setCubeRootRevealed(false);
    
    const endpoint = usePadding ? "/pa14/hastad_padded" : "/pa14/hastad";
    
    try {
      const res = await fetch(`http://127.0.0.1:5000${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: Number(message) }),
      });
      
      if (!res.ok) throw new Error("Server error occurred during attack.");
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const runBenchmark = async () => {
    setLoading(true);
    try {
      const res = await fetch(`http://127.0.0.1:5000/pa14/benchmark`);
      const data = await res.json();
      setBench(data);
    } catch (err) {
      setError("Failed to fetch benchmark data.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="pa14-container" style={{ padding: "20px", maxWidth: "900px", margin: "0 auto" }}>
      <h2 style={{ color: "#e2e8f0" }}>PA#14 — RSA CRT & Håstad's Attack</h2>
      
      <div className="tabs" style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
        {["broadcast", "benchmark"].map(tab => (
          <button 
            key={tab} 
            className={activeTab === tab ? "tab-active" : "tab-inactive"}
            onClick={() => setActiveTab(tab)}
            style={{ padding: "8px 16px", cursor: "pointer" }}
          >
            {tab.toUpperCase()}
          </button>
        ))}
      </div>

      {/* SECTION 1: BROADCAST ATTACK */}
      {activeTab === "broadcast" && (
        <section className="card" style={{ background: "#1e293b", padding: "20px", borderRadius: "8px" }}>
          <h2 style={{ marginBottom: 4, color: "#e2e8f0" }}>Håstad's Broadcast Attack</h2>
          <p className="sub" style={{ color: "#94a3b8", marginBottom: "20px" }}>
            Demonstrates the danger of using textbook RSA with a small public exponent ($e=3$)
            to send the same message to multiple recipients.
          </p>

          <div style={{ display: "flex", gap: 15, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 14 }}>
            <div style={{ flex: "1 1 180px" }}>
              <label style={{ display: "block", color: "#cbd5e1", marginBottom: "5px" }}>Message (m)</label>
              <input
                type="number"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                style={{ width: "100%", padding: "8px", borderRadius: "4px", border: "1px solid #475569", background: "#0f172a", color: "white" }}
              />
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 8 }}>
              <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, cursor: "pointer", color: "#e2e8f0" }}>
                <input
                  type="checkbox"
                  checked={usePadding}
                  onChange={(e) => setUsePadding(e.target.checked)}
                />
                Use PKCS#1 v1.5 Padding
              </label>
            </div>
            <button onClick={runAttack} disabled={loading} style={{ padding: "10px 20px", background: "#3b82f6", color: "white", border: "none", borderRadius: "4px", cursor: "pointer" }}>
              {loading ? "Running Attack..." : "Run Broadcast Attack"}
            </button>
          </div>

          {error && <div className="err" style={{ color: "#ef4444", marginTop: "10px" }}>{error}</div>}

          {result && (
            <div style={{ marginTop: "20px" }}>
              <div style={{ 
                padding: "12px", 
                borderRadius: "4px", 
                background: result.success ? "#450a0a" : "#064e3b", 
                color: result.success ? "#fca5a5" : "#6ee7b7",
                marginBottom: "15px"
              }}>
                {result.success
                  ? `🔴 CRT Complete! The system intercepted enough ciphertexts to recover the message.`
                  : `🟢 Attack Failed! Extraction failed (likely due to padding randomized values).`}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 12 }}>
                {result.moduli.map((n, i) => (
                  <div key={i} style={{ background: "#0f172a", padding: "12px", borderRadius: "6px", border: "1px solid #334155" }}>
                    <Field label={`Recipient ${i + 1} Modulus (N)`} value={trunc(n, 40)} />
                    <Field label="Ciphertext (c)" value={trunc(result.ciphertexts[i], 40)} />
                  </div>
                ))}
              </div>

              <div className="result-card" style={{ marginTop: 20, padding: "15px", borderTop: "1px solid #475569" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <strong>Attacker View (CRT + Cube Root)</strong>
                  <Badge ok={!result.success} label={result.success ? "Vulnerable" : "Secure"} />
                </div>
                
                {result.recovered_integer && (
                  <div style={{ marginTop: "10px" }}>
                    <Field label="Recovered Integer (m³ mod N₁N₂N₃)" value={trunc(result.recovered_integer, 80)} />
                  </div>
                )}
                
                {!cubeRootRevealed ? (
                  <button onClick={() => setCubeRootRevealed(true)} style={{ marginTop: "10px", width: '100%', background: '#f59e0b', color: 'black', fontWeight: "bold", padding: "8px", border: "none", borderRadius: "4px", cursor: "pointer" }}>
                    Reveal Extracted Cube Root
                  </button>
                ) : (
                  <div style={{ marginTop: 12, padding: "10px", background: result.success ? "#1e3a8a" : "#334155", borderRadius: "4px" }}>
                    <div style={{ fontSize: "11px", color: "#94a3b8" }}>EXTRACTED MESSAGE (∛x)</div>
                    <div style={{ fontSize: "1.2rem", fontWeight: "bold", color: "white" }}>
                      {result.success ? result.recovered_message : "Garbage Value"}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      )}

      {/* SECTION 2: BENCHMARK */}
      {activeTab === "benchmark" && (
        <section className="card" style={{ background: "#1e293b", padding: "20px", borderRadius: "8px" }}>
          <h3>Performance: Standard vs. CRT Decryption</h3>
          <p className="sub" style={{ color: "#94a3b8" }}>Comparing 1,000 decryptions using Garner’s Algorithm to speed up modular exponentiation.</p>
          <button onClick={runBenchmark} disabled={loading} style={{ margin: "15px 0", padding: "10px 20px", background: "#10b981", color: "white", border: "none", borderRadius: "4px", cursor: "pointer" }}>
            {loading ? "Running..." : "Run 1000x Benchmark"}
          </button>
          
          {bench && (
            <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "10px" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #475569", textAlign: "left", color: "#cbd5e1" }}>
                  <th style={{ padding: "10px" }}>Key Size</th>
                  <th>Standard (s)</th>
                  <th>CRT (s)</th>
                  <th>Speedup</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(bench).map(([size, data]) => (
                  <tr key={size} style={{ borderBottom: "1px solid #334155", color: "#e2e8f0" }}>
                    <td style={{ padding: "10px" }}>{size}-bit</td>
                    <td>{data.standard_time}s</td>
                    <td>{data.crt_time}s</td>
                    <td style={{ color: "#10b981", fontWeight: "bold" }}>{data.speedup}x</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}
    </div>
  );
}