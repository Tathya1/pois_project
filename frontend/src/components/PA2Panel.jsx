import { useState } from "react";
import "./PA2Panel.css";

export default function PA2Panel() {
  const [key, setKey]     = useState("1a2b3c4d");
  const [x, setX]         = useState("0101");
  const [tree, setTree]   = useState([]);
  const [result, setResult] = useState("");
  const [activeTab, setActiveTab] = useState("ggm"); // 'ggm' | 'aes' | 'distinguish' | 'backward'

  // AES/Comparison state
  const [aesCompareResult, setAesCompareResult] = useState(null);
  const [aesLoading, setAesLoading] = useState(false);

  // Distinguishing game state
  const [distQueries, setDistQueries] = useState(100);
  const [distResult, setDistResult]   = useState(null);
  const [distLoading, setDistLoading] = useState(false);

  // Backward PRG-from-PRF state
  const [bwSeed, setBwSeed]     = useState("123456");
  const [bwNBits, setBwNBits]   = useState(512);
  const [bwResult, setBwResult] = useState(null);

  // ─── GGM PRF ───
  const fetchPRF = async () => {
    try {
      const res  = await fetch("http://localhost:5000/prf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, x }),
      });
      const data = await res.json();
      setTree(data.tree || []);
      setResult(data.result || "");
    } catch { setResult("(API unreachable)"); }
  };

  // ─── AES Comparison ───
  const fetchAESCompare = async () => {
    setAesLoading(true); setAesCompareResult(null);
    try {
      const res = await fetch("http://localhost:5000/prf/aes-compare", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: "test msg", n_queries: 100 }),
      });
      setAesCompareResult(await res.json());
    } catch (e) { setAesCompareResult({ error: String(e) }); }
    setAesLoading(false);
  };

  // ─── Distinguishing game ───
  const runDistinguish = async () => {
    setDistLoading(true);
    setDistResult(null);
    try {
      const res  = await fetch("http://localhost:5000/prf/distinguish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries: distQueries }),
      });
      setDistResult(await res.json());
    } catch (e) { setDistResult({ error: String(e) }); }
    setDistLoading(false);
  };

  // ─── PRG from PRF (backward) ───
  const runBackward = async () => {
    try {
      const res  = await fetch("http://localhost:5000/prg-from-prf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ seed: Number(bwSeed), n_bits: bwNBits }),
      });
      setBwResult(await res.json());
    } catch (e) { setBwResult({ error: String(e) }); }
  };

  // Replace your old computePath with this:
const computePath = (xStr) => {
  // Level 0 is the root (empty string prefix), index 0
  const pathArr = [0]; 
  
  for (let i = 1; i <= xStr.length; i++) {
    // Level 'i' corresponds to the prefix of length 'i'
    // e.g., for "01", Level 1 prefix is "0" (idx 0), Level 2 prefix is "01" (idx 1)
    pathArr.push(parseInt(xStr.slice(0, i), 2));
  }
  return pathArr;
};
  const path = computePath(x);
  const isPathNode = (lvl, idx) => path[lvl] === idx;

  const TABS = [
    { id: "ggm",        label: "GGM PRF (PA#2a)" },
    { id: "aes",        label: "AES PRF (Substitute) Comparison" },
    { id: "distinguish",label: "Distinguishing Game" },
    { id: "backward",   label: "PRG ← PRF (PA#2b)" },
  ];

  return (
    <div className="panel">
      <h3>PA#2 — Pseudorandom Functions</h3>

      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            style={{ fontWeight: activeTab === t.id ? "bold" : "normal" }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── GGM PRF ── */}
      {activeTab === "ggm" && (
        <>
          <label>
            Key (hex)
            <input value={key} onChange={(e) => setKey(e.target.value)} />
          </label>
          <label>
            Query x (bit-string, max 8 bits)
            <input value={x} onChange={(e) => setX(e.target.value.replace(/[^01]/g, "").slice(0, 8))} />
          </label>
          <button onClick={fetchPRF}>Compute F(k, x) + Show Tree</button>

          <div className="tree-container">
            <div className="tree">
              {tree.map((level, i) => (
                <div key={i} className="tree-level">
                  {level.map((node, j) => (
                    <div key={j} className="tree-node"
                      style={{ background: isPathNode(i, j) ? "#3b82f6" : "#1e293b",
                               opacity:   isPathNode(i, j) ? 1 : 0.4 }}>
                      {node.left?.toString(16).slice(0, 6) ?? node.toString(16).slice(0,6)}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>

          <div className="output-box">F(k, x) = {result || "—"}</div>
          <p style={{ fontSize: "0.8rem", color: "#888" }}>
            Blue nodes = path taken for query x. Grey = inactive (not computed for this query).
          </p>
        </>
      )}

      {/* ── AES PRF (OS primitive) ── */}
      {activeTab === "aes" && (
        <>
          <div className="output-box" style={{ fontSize: "0.82rem", color: "#aaa", marginBottom: 12 }}>
            <b>AES-128 as PRF</b>: F_k(x) = AES_k(x) via <code>PyCryptodome</code>. 
            Proves functional identity by replacing GGM in downstream CPA encryption, confirming round-trip correctness and identical passing NIST randomness stats.
          </div>
          
          <button onClick={fetchAESCompare} disabled={aesLoading}>
            {aesLoading ? "Generating bits & running NIST tests..." : "Run Functional Identity Demo"}
          </button>

          {aesCompareResult && !aesCompareResult.error && (
            <div className="stats" style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "15px" }}>
              
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
                {/* GGM Card */}
                <div style={{ background: "#1c0f2e", border: "1.5px solid #7c3aed", borderRadius: 10, padding: 14 }}>
                  <h4 style={{ margin: "0 0 10px 0", color: "#c4b5fd" }}>GGM PRF</h4>
                  <div style={{ fontSize: "0.85em", color: "#ddd" }}>
                    <p><b>CPA Round-Trip:</b> {aesCompareResult.prf_results.ggm.roundtrip_ok ? '✅ pass' : '❌ fail'}</p>
                    <p style={{ marginTop: "4px" }}><b>Raw Encrypted:</b> <code style={{color:"#a78bfa"}}>{aesCompareResult.prf_results.ggm.encrypted.slice(0, 16)}...</code></p>
                    <p><b>Raw Decrypted:</b> <code>{aesCompareResult.prf_results.ggm.decrypted}</code></p>
                    <hr style={{ borderColor: "#7c3aed44", margin: "10px 0" }}/>
                    <p><b>NIST Freq:</b> p = {aesCompareResult.prf_results.ggm.frequency_test.p_value} ({aesCompareResult.prf_results.ggm.frequency_test.pass ? '✅' : '❌'})</p>
                    <p><b>NIST Runs:</b> p = {aesCompareResult.prf_results.ggm.runs_test.p_value} ({aesCompareResult.prf_results.ggm.runs_test.pass ? '✅' : '❌'})</p>
                  </div>
                </div>

                {/* AES Card */}
                <div style={{ background: "#0a1c1a", border: "1.5px solid #0d9488", borderRadius: 10, padding: 14 }}>
                  <h4 style={{ margin: "0 0 10px 0", color: "#5eead4" }}>AES PRF (PyCryptodome)</h4>
                  <div style={{ fontSize: "0.85em", color: "#ccc" }}>
                    <p><b>CPA Round-Trip:</b> {aesCompareResult.prf_results.aes.roundtrip_ok ? '✅ pass' : '❌ fail'}</p>
                    <p style={{ marginTop: "4px" }}><b>Raw Encrypted:</b> <code style={{color:"#5eead4"}}>{aesCompareResult.prf_results.aes.encrypted.slice(0, 16)}...</code></p>
                    <p><b>Raw Decrypted:</b> <code>{aesCompareResult.prf_results.aes.decrypted}</code></p>
                    <hr style={{ borderColor: "#0d948844", margin: "10px 0" }}/>
                    <p><b>NIST Freq:</b> p = {aesCompareResult.prf_results.aes.frequency_test.p_value} ({aesCompareResult.prf_results.aes.frequency_test.pass ? '✅' : '❌'})</p>
                    <p><b>NIST Runs:</b> p = {aesCompareResult.prf_results.aes.runs_test.p_value} ({aesCompareResult.prf_results.aes.runs_test.pass ? '✅' : '❌'})</p>
                  </div>
                </div>
              </div>

              <div style={{ padding: "12px", background: "#1f2937", border: "1px dashed #64748b", borderRadius: "8px", marginTop: "10px" }}>
                <b style={{color: "#e2e8f0"}}>Conclusion:</b> <span style={{color: "#cbd5e1", fontSize: "0.9rem"}}>{aesCompareResult.conclusion}</span>
              </div>
            </div>
          )}
          {aesCompareResult?.error && <p style={{ color: "#ef4444", marginTop: 10 }}>Error: {aesCompareResult.error}</p>}
        </>
      )}

      {/* ── Distinguishing Game ── */}
      {activeTab === "distinguish" && (
        <>
          <div className="output-box" style={{ fontSize: "0.82rem", color: "#aaa", marginBottom: 12 }}>
            Queries GGM PRF and a random oracle on <b>q</b> identical inputs.
            NIST frequency + runs tests confirm no statistical difference — supporting PRF security.
          </div>
          <label>
            Number of queries q
            <input type="number" value={distQueries} min={10} max={1000}
              onChange={(e) => setDistQueries(Number(e.target.value))} />
          </label>
          <button onClick={runDistinguish} disabled={distLoading}>
            {distLoading ? "Running game…" : `Run Distinguishing Game (q=${distQueries})`}
          </button>
          {distResult && !distResult.error && (
            <div className="stats">
              <p><b>PRF</b> frequency: p = {distResult.prf_frequency?.p_value?.toFixed(4)}{" "}
                {distResult.prf_frequency?.pass ? "✅ PASS" : "❌ FAIL"}</p>
              <p><b>Random</b> frequency: p = {distResult.rand_frequency?.p_value?.toFixed(4)}{" "}
                {distResult.rand_frequency?.pass ? "✅ PASS" : "❌ FAIL"}</p>
              <p><b>PRF</b> runs: p = {distResult.prf_runs?.p_value?.toFixed(4)}{" "}
                {distResult.prf_runs?.pass ? "✅ PASS" : "❌ FAIL"}</p>
              <p><b>Random</b> runs: p = {distResult.rand_runs?.p_value?.toFixed(4)}{" "}
                {distResult.rand_runs?.pass ? "✅ PASS" : "❌ FAIL"}</p>
              <p style={{ fontSize: "0.8rem", color: "#888" }}>{distResult.conclusion}</p>
            </div>
          )}
          {distResult?.error && <p style={{ color: "red" }}>Error: {distResult.error}</p>}
        </>
      )}

      {/* ── PRG ← PRF (backward PA#2b) ── */}
      {activeTab === "backward" && (
        <>
          <div className="output-box" style={{ fontSize: "0.82rem", color: "#aaa", marginBottom: 12 }}>
            <b>G(s) = F_s(0ⁿ) ∥ F_s(1ⁿ)</b> — use GGM PRF as a PRG.
            Output passes NIST tests, confirming PRF → PRG backward reduction works.
          </div>
          <label>
            Seed s (integer)
            <input value={bwSeed} onChange={(e) => setBwSeed(e.target.value)} />
          </label>
          <label>
            Output bits: {bwNBits}
            <input type="range" min={64} max={2048} step={64} value={bwNBits}
              onChange={(e) => setBwNBits(Number(e.target.value))} />
          </label>
          <button onClick={runBackward}>Run G(s) = F_s(0ⁿ)‖F_s(1ⁿ)</button>
          {bwResult && !bwResult.error && (
            <div className="stats">
              <p>Sample outputs: {bwResult.sample_outputs?.join(" | ")}</p>
              <p><b>Frequency:</b> p = {bwResult.frequency?.p_value?.toFixed(4)}{" "}
                {bwResult.frequency?.pass ? "✅ PASS" : "❌ FAIL"}</p>
              <p><b>Runs:</b> p = {bwResult.runs?.p_value?.toFixed(4)}{" "}
                {bwResult.runs?.pass ? "✅ PASS" : "❌ FAIL"}</p>
              <p style={{ fontSize: "0.8rem", color: "#888" }}>{bwResult.note}</p>
            </div>
          )}
          {bwResult?.error && <p style={{ color: "red" }}>Error: {bwResult.error}</p>}
        </>
      )}
    </div>
  );
}
