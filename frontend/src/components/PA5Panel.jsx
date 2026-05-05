import { useState } from "react";
import "./PA5Panel.css";

const toHex = (s) => Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, '0')).join('');

export default function PA5Panel() {
  const [activeTab, setActiveTab] = useState("auth"); // 'auth' | 'game' | 'length_ext'
  
  const [key, setKey] = useState("1a2b3c4d");
  const [message, setMessage] = useState("hello world");
  const [tag, setTag] = useState("");
  const [variant, setVariant] = useState("CBC_MAC");
  
  const [authResult, setAuthResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [gameRounds, setGameRounds] = useState(20);
  const [gameResult, setGameResult] = useState(null);
  const [gameLoading, setGameLoading] = useState(false);

  // For testing length extension
  const [leResult, setLeResult] = useState(null);

  const handleMac = async () => {
    setLoading(true);
    setError(null);
    setAuthResult(null);
    
    try {
      const msgHex = toHex(message);
      const res = await fetch("http://localhost:5000/pa5/mac", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, messageHex: msgHex, variant })
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "MAC failed");
      
      setTag(data.tag);
      setAuthResult({ type: "mac", result: data });
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  };

  const handleVerify = async () => {
    setLoading(true);
    setError(null);
    setAuthResult(null);
    
    try {
      const msgHex = toHex(message);
      const res = await fetch("http://localhost:5000/pa5/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, messageHex: msgHex, tag, variant })
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "Verify failed");
      
      setAuthResult({ type: "verify", result: data });
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  };

  const runEufCmaGame = async () => {
    setGameLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:5000/pa5/euf-cma-game", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rounds: gameRounds, variant })
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "Game failed");
      setGameResult(data);
    } catch (e) {
      setError(e.message);
    }
    setGameLoading(false);
  };

  const runLengthExtension = async () => {
    try {
      const res = await fetch("http://localhost:5000/pa5/length-extension", {
        method: "POST"
      });
      const data = await res.json();
      setLeResult(data);
    } catch (e) {
      setError(e.message);
    }
  };

  const TABS = [
    { id: "auth", label: "MAC & Verify" },
    { id: "game", label: "EUF-CMA Game" },
    { id: "length_ext", label: "Length Extension" }
  ];

  return (
    <div className="panel">
      <h3>PA#5 — Message Authentication Codes</h3>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            style={{ fontWeight: activeTab === t.id ? "bold" : "normal" }}>
            {t.label}
          </button>
        ))}
      </div>
      
      {error && <div className="pa5-error">{error}</div>}

      {activeTab === "auth" && (
        <div className="pa5-grid">
          <label>
            Variant
            <select value={variant} onChange={(e) => setVariant(e.target.value)}>
              <option value="CBC_MAC">CBC-MAC (Variable Length)</option>
              <option value="PRF_MAC">PRF-MAC (Fixed Length - 8 bytes)</option>
              <option value="HMAC">HMAC (Fixed Length - 8 bytes)</option>
            </select>
          </label>
          <label>
            Key (hex/int)
            <input value={key} onChange={(e) => setKey(e.target.value)} />
          </label>
          <label>
            Message
            <input value={message} onChange={(e) => setMessage(e.target.value)} />
          </label>
          <label>
            Tag (hex)
            <input value={tag} onChange={(e) => setTag(e.target.value)} placeholder="Computed or manually input for verification" />
          </label>

          <div className="pa5-row">
            <button onClick={handleMac} disabled={loading}>Generate MAC</button>
            <button onClick={handleVerify} disabled={loading}>Verify Tag</button>
          </div>

          {authResult && authResult.type === "mac" && (
            <div className="output-box">
              <strong>MAC generated:</strong> {authResult.result.tag}
            </div>
          )}
          
          {authResult && authResult.type === "verify" && (
            <div className={authResult.result.valid ? "pa5-success" : "pa5-error"}>
              <strong>Verification Result: </strong>
              {authResult.result.valid ? "✅ VALID" : "❌ INVALID (Forgery rejected)"}
            </div>
          )}
        </div>
      )}

      {activeTab === "game" && (
        <div className="pa5-grid">
          <div className="pa5-info">
            In the Existential Unforgeability under Chosen-Message Attack (EUF-CMA) game, a dummy adversary is given oracle access to MACs for random messages, and tries to forge a valid tag for a new message. Secure MACs should resist this and yield ~0 advantage.
          </div>
          
          <label>
            Variant
            <select value={variant} onChange={(e) => setVariant(e.target.value)}>
              <option value="CBC_MAC">CBC-MAC</option>
              <option value="PRF_MAC">PRF-MAC</option>
            </select>
          </label>
          
          <label>
            Rounds
            <input type="number" value={gameRounds} onChange={(e) => setGameRounds(Number(e.target.value))} />
          </label>
          
          <div className="pa5-row">
            <button onClick={runEufCmaGame} disabled={gameLoading}>
               {gameLoading ? "Running Game..." : "Run EUF-CMA Game"}
            </button>
          </div>

          {gameResult && (
            <div className="output-box">
              <p><strong>Rounds played:</strong> {gameResult.rounds}</p>
              <p><strong>Forgery Attempts:</strong> {gameResult.forgery_attempts}</p>
              <p><strong>Successful Forgeries:</strong> <span style={{color: gameResult.forgery_successes === 0 ? '#10b981' : '#ef4444'}}>{gameResult.forgery_successes}</span></p>
              <p><strong>Advantage:</strong> {(gameResult.advantage * 100).toFixed(2)}%</p>
              <p className="pa5-info" style={{marginTop: '10px'}}>{gameResult.conclusion}</p>
            </div>
          )}
        </div>
      )}

      {activeTab === "length_ext" && (
        <div className="pa5-grid">
          <div className="pa5-info">
            H(k||m) is susceptible to length extension attacks if H is a Merkle-Damgard hash function.
          </div>
          
          <div className="pa5-row">
            <button onClick={runLengthExtension}>Demo Length Extension</button>
          </div>
          
          {leResult && (
             <div className="output-box">
               <p><strong>Status:</strong> {leResult.status}</p>
               <p>{leResult.explanation}</p>
             </div>
          )}
        </div>
      )}
    </div>
  );
}
