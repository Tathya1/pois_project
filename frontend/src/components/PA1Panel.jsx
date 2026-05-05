import { useState, useEffect } from "react";
import "./PA1Panel.css";

export default function PA1Panel() {
  const [seed, setSeed] = useState("1a2b3c4d5e6f7788");
  const [length, setLength] = useState(64);
  const [bits, setBits] = useState("");
  const [stats, setStats] = useState(null);

  // PA#1b — minimal hardness demo state (supports 1b.md written argument)
  const [owfFromPrgResult, setOwfFromPrgResult] = useState(null);
  const [owfFromPrgLoading, setOwfFromPrgLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("forward"); // 'forward' | 'backward'

  const hexToDecimal = (hex) => {
    try {
      return BigInt("0x" + hex).toString();
    } catch {
      return "123";
    }
  };

  const fetchPRG = async () => {
    try {
      const res = await fetch("http://localhost:5000/prg", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ seed: hexToDecimal(seed), length }),
      });
      const data = await res.json();
      setBits(data.bits || "");
      setStats(null);
    } catch {
      setBits("(API unreachable)");
    }
  };

  const runTests = async () => {
    const res = await fetch("http://localhost:5000/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bits }),
    });
    const data = await res.json();
    setStats(data);
  };

  // PA#1b — minimal inversion hardness demo (supports 1b.md proof)
  const runOwfFromPrg = async () => {
    setOwfFromPrgLoading(true);
    setOwfFromPrgResult(null);
    try {
      const res = await fetch("http://localhost:5000/owf-from-prg", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ n_trials: 5, budget: 10000 }),
      });
      setOwfFromPrgResult(await res.json());
    } catch (e) {
      setOwfFromPrgResult({ error: String(e) });
    }
    setOwfFromPrgLoading(false);
  };

  useEffect(() => { fetchPRG(); }, [seed, length]);

  const bitRatio = bits ? (bits.split("1").length - 1) / bits.length : 0;

  return (
    <div className="panel">
      <h3>PA#1 — OWF + PRG</h3>

      {/* Tab switcher */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button
          onClick={() => setActiveTab("forward")}
          style={{ fontWeight: activeTab === "forward" ? "bold" : "normal" }}
        >
          Forward: OWF → PRG
        </button>
        <button
          onClick={() => setActiveTab("backward")}
          style={{ fontWeight: activeTab === "backward" ? "bold" : "normal" }}
        >
          Backward: PRG → OWF (PA#1b)
        </button>
      </div>

      {/* ──────────────── FORWARD TAB ──────────────── */}
      {activeTab === "forward" && (
        <>
          <label>
            Seed (hex)
            <input value={seed} onChange={(e) => setSeed(e.target.value)} placeholder="Hex seed" />
          </label>

          <label>
            Output length: {length} bits
            <input
              type="range" min="8" max="256" value={length}
              onChange={(e) => setLength(Number(e.target.value))}
            />
          </label>

          <div className="output-box" style={{ fontFamily: "monospace", wordBreak: "break-all" }}>
            {bits || "—"}
          </div>

          <button onClick={runTests}>Run Randomness Tests (NIST SP 800-22)</button>

          {stats && (
            <div className="stats">
              <p>
                <b>Frequency:</b> p = {stats.frequency.p_value.toFixed(4)}{" "}
                {stats.frequency.pass ? "✅ PASS" : "❌ FAIL"}
              </p>
              <p>
                <b>Runs:</b> p = {stats.runs.p_value.toFixed(4)}{" "}
                {stats.runs.pass ? "✅ PASS" : "❌ FAIL"}
              </p>
              <p>
                <b>Serial:</b> p₁ = {stats.serial.p_value1.toFixed(4)}, p₂ = {stats.serial.p_value2.toFixed(4)}{" "}
                {stats.serial.pass ? "✅ PASS" : "❌ FAIL"}
              </p>

              <div className="ratio-bar">
                <div className="ratio-fill" style={{ width: `${bitRatio * 100}%` }} />
              </div>
              <p>1s Ratio: {(bitRatio * 100).toFixed(2)}% (expected ≈ 50%)</p>
            </div>
          )}
        </>
      )}

      {/* ──────────────── BACKWARD TAB ──────────────── */}
      {activeTab === "backward" && (
        <>
          {/* The real deliverable for PA#1b is the written argument in 1b.md */}
          <div className="output-box" style={{ marginBottom: 12, fontSize: "0.85rem", color: "#aaa", lineHeight: 1.7 }}>
            <b>PA#1b Claim:</b> f(s) = G(s) is a one-way function.<br/>
            <b>Proof sketch (reduction to PRG security):</b> Suppose PPT adversary A inverts f
            with non-negligible probability. Build distinguisher D: given y, run A(y)→s′;
            if G(s′)=y output "PRG", else "Random". When y=G(s), A succeeds w/ non-negl →
            D correct. When y uniform, G(s′)≠y w.o.p. (image is small) → D correct.
            D breaks PRG security — contradiction. <b>∴ f is OWF. ∎</b><br/>
            <span style={{color:"#64748b", fontSize:"0.8rem"}}>
              Full formal proof: <code>backend/PA1/1b.md</code>
            </span>
          </div>

          {/* Minimal concrete demo — supports the written argument */}
          <button onClick={runOwfFromPrg} disabled={owfFromPrgLoading}>
            {owfFromPrgLoading ? "Running..." : "Run Hardness Demo (5 seeds × 10,000 guesses)"}
          </button>

          {owfFromPrgResult && !owfFromPrgResult.error && (
            <div className="stats">
              <p>
                <b>Hardness confirmed:</b>{" "}
                {(owfFromPrgResult.hardness_ok ?? owfFromPrgResult.hardness_confirmed)
                  ? "✅ YES — brute-force failed for all seeds"
                  : "⚠️ No (rare collision!)"}
              </p>
              <p style={{ fontSize: "0.82rem", color: "#888" }}>
                Budget: {(owfFromPrgResult.budget ?? owfFromPrgResult.brute_force_budget)?.toLocaleString()} guesses
                out of 2³² = {owfFromPrgResult.seed_space?.toLocaleString()} possible seeds. &nbsp;
                Adversary success: {owfFromPrgResult.success_count ?? owfFromPrgResult.found_count}/
                {owfFromPrgResult.n_trials ?? owfFromPrgResult.n_seeds}
              </p>
              {owfFromPrgResult.results?.map((r, i) => (
                <div key={i} className="output-box" style={{ marginTop: 4, fontSize: "0.8rem" }}>
                  s = {r.s} &nbsp;| y = {(r.y_prefix ?? r.y)?.slice(0, 20)}… &nbsp;|
                  inversion: {(r.inverted ?? r.brute_force_found) ? `⚠️ found at ${r.found_at}` : "❌ not found"}
                </div>
              ))}
              <p style={{ fontSize: "0.8rem", color: "#888", marginTop: 8 }}>
                {owfFromPrgResult.conclusion ?? owfFromPrgResult.argument}
              </p>
            </div>
          )}

          {owfFromPrgResult?.error && (
            <p style={{ color: "#ef4444" }}>Error: {owfFromPrgResult.error}</p>
          )}
        </>
      )}
    </div>
  );
}