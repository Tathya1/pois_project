import { useState, useEffect } from "react";
import "./PA8Panel.css";

const API = "http://localhost:5000";

const get  = async (path)       => { const r = await fetch(`${API}${path}`);               return r.json(); };
const post = async (path, body) => {
  const r = await fetch(`${API}${path}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const d = await r.json();
  if (!r.ok || d.error) throw new Error(d.error || "API error");
  return d;
};

const TABS = [
  { id: "hash",     label: "DLP Hash" },
  { id: "integration", label: "Integration Test" },
  { id: "birthday", label: "Birthday Attack" },
  { id: "security", label: "Security Argument" },
];

// ── DLP Group parameter card ───────────────────────────────────────────────
function GroupCard({ info }) {
  if (!info) return null;
  const fields = [
    { label: "p (safe prime)",  value: info.p },
    { label: "q (subgroup ord)", value: info.q },
    { label: "g (generator)",    value: info.g },
    { label: "h = g^α mod p",    value: info.h },
    { label: "p bits",           value: info.p_bits },
    { label: "q bits",           value: info.q_bits },
    { label: "output bits",      value: info.output_bits },
    { label: "birthday bound",   value: `≈ 2^${info.q_bits/2 | 0} = ${info.birthday_bound}` },
  ];
  return (
    <div className="pa8-group-card">
      {fields.map(f => (
        <div key={f.label} className="pa8-group-field">
          <div className="label">{f.label}</div>
          <div className="value">{f.value}</div>
        </div>
      ))}
    </div>
  );
}

export default function PA8Panel() {
  const [activeTab, setActiveTab] = useState("hash");
  const [group,     setGroup]     = useState(null);
  const [error,     setError]     = useState("");

  // Fetch group info once on mount
  useEffect(() => {
    get("/pa8/group-info")
      .then(d => { if (!d.error) setGroup(d); })
      .catch(() => {});
  }, []);

  // ── Hash tab ───────────────────────────────────────────────────────────
  const [hashMsg,    setHashMsg]    = useState("hello CRHF");
  const [hashResult, setHashResult] = useState(null);
  const [hashLoading, setHashLoading] = useState(false);

  const runHash = async () => {
    setHashLoading(true); setError("");
    try {
      const d = await post("/pa8/trace", { message: hashMsg });
      setHashResult(d);
      if (d.group_info) setGroup(d.group_info);
    } catch (e) { setError(e.message); }
    setHashLoading(false);
  };

  // ── Integration test tab ─────────────────────────────────────────────
  const integrationMessages = [
    "",
    "a",
    "abc",
    "message of length 17",
    "longer message with more bytes for PA8 integration test",
  ];
  const [intResult, setIntResult] = useState(null);
  const [intLoading, setIntLoading] = useState(false);

  const runIntegration = async () => {
    setIntLoading(true); setError("");
    try {
      const digests = await Promise.all(
        integrationMessages.map((message) => post("/pa8/hash", { message }))
      );
      const rows = digests.map((d, i) => ({
        message: integrationMessages[i],
        length: integrationMessages[i].length,
        digest: d.digest,
      }));
      const uniqueCount = new Set(rows.map((r) => r.digest)).size;
      setIntResult({
        rows,
        unique: uniqueCount === rows.length,
      });
    } catch (e) { setError(e.message); }
    setIntLoading(false);
  };

  // ── Birthday attack tab ────────────────────────────────────────────────
  const [maxEv,       setMaxEv]      = useState(5000);
  const [birthResult, setBirthResult] = useState(null);
  const [birthLoading, setBirthLoading] = useState(false);

  const runBirthday = async () => {
    setBirthLoading(true); setError("");
    setBirthResult(null);
    try {
      const d = await post("/pa8/birthday-attack", { max_evaluations: maxEv });
      setBirthResult(d);
    } catch (e) { setError(e.message); }
    setBirthLoading(false);
  };

  // ── Security argument tab ─────────────────────────────────────────────
  const [secArg,      setSecArg]     = useState(null);
  const [activeStep,  setActiveStep] = useState(null);
  const [secLoading,  setSecLoading] = useState(false);

  const loadSecurity = async () => {
    setSecLoading(true); setError("");
    try {
      const d = await get("/pa8/security-argument");
      setSecArg(d);
    } catch (e) { setError(e.message); }
    setSecLoading(false);
  };

  return (
    <div className="panel">
      <h3>PA#8 — DLP-Based Collision-Resistant Hash Function</h3>

      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {TABS.map(t => (
          <button key={t.id}
            onClick={() => { setActiveTab(t.id); setError(""); if (t.id === "security" && !secArg) loadSecurity(); }}
            style={{
              fontWeight: activeTab === t.id ? "bold" : "normal",
              background: activeTab === t.id ? "#581c87" : "#1e293b",
              color: "#e2e8f0", border: "none", borderRadius: 8,
              padding: "8px 14px", cursor: "pointer",
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {error && <p className="pa8-err">⚠ {error}</p>}

      {/* ═══════════ HASH TAB ═══════════ */}
      {activeTab === "hash" && (
        <div className="pa8-grid">
          <div className="pa8-info">
            <b>compress(x, y) = g^x · h^y mod p</b> plugged into Merkle-Damgård.
            Collision resistance reduces to the Discrete Logarithm Problem in Z*_p.
          </div>

          <div style={{ fontWeight: "bold", color: "#94a3b8" }}>DLP Group Parameters</div>
          {group ? <GroupCard info={group} /> : (
            <div style={{ color: "#64748b", fontSize: "0.85rem" }}>Loading group…</div>
          )}

          <label className="pa8-grid">
            Message to hash
            <input value={hashMsg} onChange={e => setHashMsg(e.target.value)} />
          </label>

          <div className="pa8-row">
            <button className="primary" onClick={runHash} disabled={hashLoading}>
              {hashLoading ? "Hashing…" : "Hash with DLP-MD"}
            </button>
          </div>

          {hashResult && (
            <div className="output-box" style={{ fontFamily: "monospace" }}>
              <div><b>Digest:</b> {hashResult.digest}</div>
              <div style={{ marginTop: 6, fontSize: "0.8rem", color: "#64748b" }}>
                {hashResult.n_blocks} compression block{hashResult.n_blocks !== 1 ? "s" : ""} |
                Each block: x=cv (8B), y=block data (8B) →
                compress(x,y) = g^x · h^y mod p
              </div>
              {hashResult.chain && (
                <div style={{ marginTop: 8, fontSize: "0.78rem", color: "#94a3b8" }}>
                  Chain: {hashResult.chain.map((cv, i) => (
                    <span key={i}>
                      {i > 0 && " → "}
                      <span style={{ color: i === 0 ? "#60a5fa" : i === hashResult.chain.length - 1 ? "#fcd34d" : "#a78bfa" }}>
                        {cv.slice(0, 10)}…
                      </span>
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══════════ INTEGRATION TEST TAB ═══════════ */}
      {activeTab === "integration" && (
        <div className="pa8-grid">
          <div className="pa8-info">
            Hash five messages of different lengths and confirm that distinct inputs
            produce distinct digests.
          </div>

          <div className="pa8-row">
            <button className="primary" onClick={runIntegration} disabled={intLoading}>
              {intLoading ? "Running…" : "Run Integration Test"}
            </button>
          </div>

          {intResult && (
            <div className="output-box" style={{ fontFamily: "monospace" }}>
              <div style={{ marginBottom: 8 }}>
                Distinct digests: {intResult.unique ? "YES" : "NO"}
              </div>
              <div style={{ display: "grid", gap: 8 }}>
                {intResult.rows.map((row, i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: 8 }}>
                    <div style={{ color: "#94a3b8" }}>len={row.length}</div>
                    <div>
                      <span style={{ color: "#a78bfa" }}>
                        {row.message === "" ? "(empty)" : row.message}
                      </span>
                      <span style={{ marginLeft: 10, color: "#fcd34d" }}>{row.digest}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══════════ BIRTHDAY ATTACK TAB ═══════════ */}
      {activeTab === "birthday" && (
        <div className="pa8-grid">
          <div className="pa8-info">
            <b>Birthday attack</b> on truncated DLP compress (output_bits bits).
            Expected collisions after ≈ 2^(output_bits/2) random evaluations.
            After finding a collision (x₁,y₁) ≠ (x₂,y₂), we extract α = dlog_g(h)
            proving the collision is cryptographically meaningful.
          </div>

          {group && (
            <div className="output-box" style={{ fontSize: "0.82rem", fontFamily: "monospace" }}>
              Output bits: {group.output_bits} |
              Output space: 2^{group.output_bits} = {Math.pow(2, group.output_bits).toLocaleString()} values |
              Expected evaluations: ≈ 2^{group.output_bits/2} = {group.birthday_bound}
            </div>
          )}

          <label className="pa8-grid">
            Max evaluations budget
            <input type="number" min={100} max={50000} value={maxEv}
              onChange={e => setMaxEv(Number(e.target.value))} />
          </label>

          <div className="pa8-row">
            <button className="attack" onClick={runBirthday} disabled={birthLoading}>
              {birthLoading ? "Searching for collision…" : `Launch Birthday Attack`}
            </button>
          </div>

          {birthLoading && (
            <div className="pa8-birth-wrapper">
              <div style={{ color: "#a78bfa", marginBottom: 8 }}>
                🔍 Hashing random (x, y) pairs, looking for output collision…
              </div>
              <div className="pa8-progress-bar">
                <div className="pa8-progress-fill" style={{ width: "60%" }} />
              </div>
            </div>
          )}

          {birthResult && (
            <div className="pa8-birth-wrapper">
              <div className="pa8-birth-stats">
                <div className="pa8-birth-stat">
                  <div className="num">{birthResult.evaluations?.toLocaleString() ?? "—"}</div>
                  <div className="desc">Evaluations</div>
                </div>
                <div className="pa8-birth-stat">
                  <div className="num">{birthResult.expected?.toLocaleString() ?? "—"}</div>
                  <div className="desc">Birthday bound ≈ 2^(n/2)</div>
                </div>
              </div>

              <div className="pa8-progress-bar">
                <div className="pa8-progress-fill"
                  style={{
                    width: birthResult.success
                      ? `${Math.min((birthResult.evaluations / birthResult.expected) * 50, 100)}%`
                      : "100%",
                    background: birthResult.success
                      ? "linear-gradient(90deg, #7c3aed, #4ade80)"
                      : "linear-gradient(90deg, #7c3aed, #ef4444)",
                  }}
                />
              </div>

              {birthResult.success && birthResult.collision && (
                <div className="pa8-collision-box">
                  <div className="title">✓ Collision Found!</div>
                  <div>
                    (x₁, y₁) = ({birthResult.collision.x1}, {birthResult.collision.y1})
                  </div>
                  <div>
                    (x₂, y₂) = ({birthResult.collision.x2}, {birthResult.collision.y2})
                  </div>
                  <div style={{ marginTop: 6 }}>
                    compress_truncated(x₁,y₁) = compress_truncated(x₂,y₂) =&nbsp;
                    <b style={{ color: "#fcd34d" }}>{birthResult.collision.hash_value}</b>
                  </div>

                  {birthResult.dlog_extraction?.success && (
                    <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid #1e293b" }}>
                      <div style={{ color: "#f87171", fontWeight: "bold" }}>
                        ⚠ Discrete log extracted from collision:
                      </div>
                      <div>α = {birthResult.dlog_extraction.alpha_recovered}</div>
                      <div>g^α mod p = {birthResult.dlog_extraction.h_from_alpha}</div>
                      <div>h original = {birthResult.dlog_extraction.h_original}</div>
                      <div style={{ color: "#4ade80", marginTop: 4 }}>
                        {birthResult.dlog_extraction.alpha_correct
                          ? "✓ g^α = h confirmed — DLP broken by collision!"
                          : "✗ g^α ≠ h (verify code)"}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {!birthResult.success && (
                <div style={{ color: "#facc15", marginTop: 8 }}>
                  ⚠ No collision in {birthResult.evaluations} evaluations. Increase budget.
                </div>
              )}

              <div className="pa8-info" style={{ marginTop: 10, fontSize: "0.8rem" }}>
                {birthResult.explanation}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══════════ SECURITY ARGUMENT TAB ═══════════ */}
      {activeTab === "security" && (
        <div className="pa8-grid">
          <div className="pa8-info">
            Click any step to expand it. The proof shows that any collision finder for
            <code> compress(x,y) = g^x·h^y mod p</code> also solves the Discrete Logarithm Problem.
          </div>

          {secLoading && <div style={{ color: "#64748b" }}>Loading proof…</div>}

          {secArg && (
            <>
              <div style={{
                background: "#1e1b2e", border: "1.5px solid #a855f7",
                borderRadius: 10, padding: 14, fontWeight: "bold", color: "#c4b5fd",
              }}>
                Claim: {secArg.claim}
              </div>

              <div className="pa8-proof-steps">
                {secArg.proof_steps?.map(s => (
                  <div key={s.step}
                    className={`pa8-proof-step ${activeStep === s.step ? "active" : ""}`}
                    onClick={() => setActiveStep(activeStep === s.step ? null : s.step)}>
                    <div className="pa8-step-num">{s.step}</div>
                    <div className="pa8-step-body">
                      <div className="pa8-step-statement">{s.statement}</div>
                      {activeStep === s.step && (
                        <div className="pa8-step-math">{s.math}</div>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <div className="pa8-warn" style={{ fontSize: "0.82rem" }}>
                <b>DLP Hardness:</b> {secArg.dlp_assumption}
              </div>
              <div className="pa8-info" style={{ fontSize: "0.82rem" }}>
                <b>Birthday Lower Bound:</b> {secArg.birthday_lower_bound}
              </div>
            </>
          )}

          {!secArg && !secLoading && (
            <div className="pa8-row">
              <button className="primary" onClick={loadSecurity}>Load Security Argument</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
