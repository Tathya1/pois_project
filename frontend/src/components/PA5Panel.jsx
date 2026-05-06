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
  const [gameSessionId, setGameSessionId] = useState(null);
  const [forgedMessage, setForgedMessage] = useState("");
  const [forgedTag, setForgedTag] = useState("");
  const [forgeryResult, setForgeryResult] = useState(null);

  // For testing length extension
  const [leResult, setLeResult] = useState(null);
  const [leSuffix, setLeSuffix] = useState("&admin=true");
  const [leCompressFn, setLeCompressFn] = useState("xor");
  const [leLoading, setLeLoading] = useState(false);

  const [prfTestQueries, setPrfTestQueries] = useState(100);
  const [prfTestResult, setPrfTestResult] = useState(null);
  const [prfTestLoading, setPrfTestLoading] = useState(false);

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
        body: JSON.stringify({ rounds: gameRounds, variant, includeQueries: true })
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "Game failed");
      setGameResult(data);
      setGameSessionId(data.sessionId || null);
      setForgeryResult(null);
    } catch (e) {
      setError(e.message);
    }
    setGameLoading(false);
  };

  const checkUserForgery = async () => {
    if (!gameSessionId) return;
    setGameLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:5000/pa5/euf-cma-game", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId: gameSessionId,
          forgedMessage,
          forgedTag,
          variant
        })
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "Forgery check failed");
      setGameResult((prev) => ({ ...prev, queries: data.queries }));
      setForgeryResult(data.user_forgery || null);
    } catch (e) {
      setError(e.message);
    }
    setGameLoading(false);
  };

  const runLengthExtension = async () => {
    setLeLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:5000/pa5/length-extension", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          key,
          message,
          suffix: leSuffix,
          compressFn: leCompressFn
        })
      });
      const data = await res.json();
      setLeResult(data);
    } catch (e) {
      setError(e.message);
    }
    setLeLoading(false);
  };

  const runPrfMacPrfTest = async () => {
    setPrfTestLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:5000/pa5/prf-mac-prf-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries: prfTestQueries, messageLen: 8 })
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "PRF test failed");
      setPrfTestResult(data);
    } catch (e) {
      setError(e.message);
    }
    setPrfTestLoading(false);
  };

  const TABS = [
    { id: "auth", label: "MAC & Verify" },
    { id: "game", label: "EUF-CMA Game" },
    { id: "length_ext", label: "Length Extension" },
    { id: "prf_test", label: "PRF Test" }
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

          {gameResult?.queries && (
            <div className="output-box">
              <strong>Oracle queries (message, tag):</strong>
              <ul style={{ marginTop: 8 }}>
                {gameResult.queries.map((q, idx) => (
                  <li key={idx} style={{ marginBottom: 6 }}>
                    <code>{q.messageHex}</code> → <code>{q.tag}</code>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <label>
            Your forged message (text or hex)
            <input value={forgedMessage} onChange={(e) => setForgedMessage(e.target.value)} placeholder="new message" />
          </label>
          <label>
            Your forged tag (hex)
            <input value={forgedTag} onChange={(e) => setForgedTag(e.target.value)} placeholder="tag" />
          </label>

          <div className="pa5-row">
            <button onClick={checkUserForgery} disabled={gameLoading || !gameSessionId}>
              {gameLoading ? "Checking..." : "Check Forgery"}
            </button>
          </div>

          {forgeryResult && (
            <div className={forgeryResult.success ? "pa5-success" : "pa5-error"}>
              <p><strong>Forgery valid:</strong> {forgeryResult.valid ? "Yes" : "No"}</p>
              <p><strong>Was previously queried:</strong> {forgeryResult.was_queried ? "Yes" : "No"}</p>
              <p><strong>EUF-CMA success:</strong> {forgeryResult.success ? "✅ Success" : "❌ Rejected"}</p>
            </div>
          )}
        </div>
      )}

      {activeTab === "length_ext" && (
        <div className="pa5-grid">
          <div className="pa5-info">
            H(k||m) is susceptible to length extension attacks if H is a Merkle-Damgard hash function.
          </div>

          <label>
            Suffix m'
            <input value={leSuffix} onChange={(e) => setLeSuffix(e.target.value)} />
          </label>

          
          
          <div className="pa5-row">
            <button onClick={runLengthExtension} disabled={leLoading}>
              {leLoading ? "Computing..." : "Demo Length Extension"}
            </button>
          </div>
          
          {leResult && (
             <div className="output-box">
               <p><strong>Status:</strong> {leResult.status}</p>
               <p><strong>Original tag t = H(k||m):</strong> {leResult.originalTag}</p>
               <p><strong>Glue padding:</strong> {leResult.gluePaddingHex}</p>
               <p><strong>Forged message (hex):</strong> {leResult.forgedMessageHex}</p>
               <p><strong>Forged tag from t only:</strong> {leResult.forgedTag}</p>
               <p><strong>Server verification:</strong> {leResult.matches ? "✅ matches" : "❌ mismatch"}</p>
               <p className="pa5-info" style={{marginTop: '10px'}}>{leResult.note}</p>
             </div>
          )}
        </div>
      )}

      {activeTab === "prf_test" && (
        <div className="pa5-grid">
          <div className="pa5-info">
            This runs the same frequency-based PRF distinguishing test from PA#2, but on PRF-MAC tags for uniformly random inputs.
          </div>

          <label>
            Queries
            <input
              type="number"
              value={prfTestQueries}
              onChange={(e) => setPrfTestQueries(Number(e.target.value))}
            />
          </label>

          <div className="pa5-row">
            <button onClick={runPrfMacPrfTest} disabled={prfTestLoading}>
              {prfTestLoading ? "Running..." : "Run PRF Distinguishing Test"}
            </button>
          </div>

          {prfTestResult && (
            <div className="output-box">
              <p><strong>Queries:</strong> {prfTestResult.queries}</p>
              <p><strong>PRF-MAC p-value:</strong> {prfTestResult.prf?.p_value?.toFixed(4)}</p>
              <p><strong>PRF-MAC pass:</strong> {prfTestResult.prf?.pass ? "✅ PASS" : "❌ FAIL"}</p>
              <p><strong>Random oracle p-value:</strong> {prfTestResult.rand?.p_value?.toFixed(4)}</p>
              <p><strong>Random oracle pass:</strong> {prfTestResult.rand?.pass ? "✅ PASS" : "❌ FAIL"}</p>
              <p className="pa5-info" style={{ marginTop: "10px" }}>{prfTestResult.conclusion}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
