import { useState } from "react";
import "./PA13Panel.css";
import "./PA20Panel.css";

const API = "http://localhost:5000";

const post = (path, body) =>
  fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => r.json());

const get = (path) => fetch(API + path).then((r) => r.json());

function Field({ label, value, mono = true }) {
  return (
    <div className="kv-row">
      <span className="kv-label">{label}</span>
      <span className={`kv-value${mono ? " mono" : ""}`}>{value ?? "—"}</span>
    </div>
  );
}
function Badge({ ok, label }) {
  return <span className={`badge ${ok ? "badge-ok" : "badge-fail"}`}>{label}</span>;
}

/* ────────────────────────────────────────────────────────────────────
   Shared gate-trace component
   ──────────────────────────────────────────────────────────────────── */
function GateTrace({ gates }) {
  const [open, setOpen] = useState(false);
  if (!gates || gates.length === 0) return null;
  const andCount  = gates.filter(g => g.type === "AND").length;
  const xorCount  = gates.filter(g => g.type === "XOR").length;
  const notCount  = gates.filter(g => g.type === "NOT").length;
  return (
    <div className="mpc-trace-wrap">
      <button className="trace-toggle" onClick={() => setOpen(o => !o)}>
        {open ? "▲" : "▼"} Circuit trace ({gates.length} gates — {andCount} AND [{andCount} OT calls], {xorCount} XOR, {notCount} NOT)
      </button>
      {open && (
        <div className="mpc-trace">
          {gates.map((g, i) => (
            <div key={i} className={`mpc-gate-row mpc-gate-${g.type.toLowerCase()}`}>
              <span className="gate-type">{g.type}</span>
              <span className="gate-wires">
                {g.in_wires ? `w[${g.in_wires.join(",")}]` : g.in_wire != null ? `w[${g.in_wire}]` : ""}
                {" → w[" + g.out_wire + "]"}
              </span>
              <span className="gate-val">
                {g.in_values ? `${g.in_values.join(g.type === "XOR" ? " ⊕ " : " ∧ ")} = ${g.out_value}` : ""}
                {g.in_value  != null ? `NOT(${g.in_value}) = ${g.out_value}` : ""}
              </span>
              <span className="gate-cost">{g.cost}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 1 — Millionaire's Problem (interactive slider demo)
   ════════════════════════════════════════════════════════════════════ */
function Millionaire() {
  const [x, setX]      = useState(7);
  const [y, setY]      = useState(12);
  const [n, setN]      = useState(4);
  const [bits, setBits] = useState(64);
  const [result, setRes] = useState(null);
  const [busy, setBusy]  = useState(false);
  const [err, setErr]    = useState("");

  const maxVal = (1 << n) - 1;

  const run = async () => {
    setBusy(true); setErr(""); setRes(null);
    try {
      const r = await post("/pa20/millionaire", {
        x: Math.min(x, maxVal), y: Math.min(y, maxVal), n, bits,
      });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const xClamped = Math.min(x, maxVal);
  const yClamped = Math.min(y, maxVal);

  return (
    <div>
      <p className="sub">
        <strong>Millionaire's Problem (Yao 1982):</strong> Alice has wealth{" "}
        <em>x</em>, Bob has wealth <em>y</em>. They want to know who is richer{" "}
        <em>without revealing their actual values</em>.
        The {n}-bit comparison circuit uses AND gates (each an OT call via PA#19)
        and free XOR gates; only the result <em>x &gt; y</em> is revealed.
      </p>

      {/* Sliders */}
      <div className="millionaire-panels">
        <div className="millionaire-party alice-panel">
          <div className="millionaire-party-title">🔒 Alice's Wealth (private)</div>
          <div className="millionaire-value">{xClamped}</div>
          <input
            type="range" min={0} max={maxVal} value={xClamped}
            onChange={e => setX(Number(e.target.value))}
            className="millionaire-slider alice-slider"
          />
          <div className="millionaire-bits">
            Binary: [{" "}
            {Array.from({length: n}, (_, i) => (xClamped >> (n-1-i)) & 1).join(", ")}
            {" "}] (MSB first)
          </div>
        </div>

        <div className="millionaire-vs">VS</div>

        <div className="millionaire-party bob-panel">
          <div className="millionaire-party-title">🔒 Bob's Wealth (private)</div>
          <div className="millionaire-value">{yClamped}</div>
          <input
            type="range" min={0} max={maxVal} value={yClamped}
            onChange={e => setY(Number(e.target.value))}
            className="millionaire-slider bob-slider"
          />
          <div className="millionaire-bits">
            Binary: [{" "}
            {Array.from({length: n}, (_, i) => (yClamped >> (n-1-i)) & 1).join(", ")}
            {" "}] (MSB first)
          </div>
        </div>
      </div>

      {/* Options */}
      <div className="example-row" style={{ marginBottom: 8 }}>
        <span style={{ color: "#64748b", fontSize: 12 }}>Bit-width n:</span>
        {[2, 3, 4].map(v => (
          <button key={v}
            className={`example-btn${n === v ? " active" : ""}`}
            onClick={() => setN(v)}>{v} bits ({1<<v} values)
          </button>
        ))}
      </div>
      <div className="example-row" style={{ marginBottom: 12 }}>
        <span style={{ color: "#64748b", fontSize: 12 }}>OT security:</span>
        {[32, 64].map(b => (
          <button key={b}
            className={`example-btn${bits === b ? " active" : ""}`}
            onClick={() => setBits(b)}>{b}-bit
          </button>
        ))}
      </div>

      <button className="run-btn" onClick={run} disabled={busy} style={{ background: "#8b5cf6" }}>
        {busy ? "Evaluating circuit gate by gate…" : "🤑 Who is richer?"}
      </button>

      {err && <div className="err">{err}</div>}

      {result && (
        <div className="millionaire-result">
          <div className={`millionaire-verdict verdict-${
            result.x_gt_y ? "alice" : xClamped === yClamped ? "equal" : "bob"
          }`}>
            {result.result_text}
          </div>
          <p className="millionaire-privacy">
            ✓ Neither party's actual value was revealed during computation.
          </p>
          <div className="mpc-stats">
            <div className="mpc-stat">
              <span>OT calls (AND)</span>
              <strong>{result.n_ands}</strong>
            </div>
            <div className="mpc-stat">
              <span>Free gates</span>
              <strong>{result.n_free_gates}</strong>
            </div>
            <div className="mpc-stat">
              <span>Total gates</span>
              <strong>{result.gates?.length ?? "—"}</strong>
            </div>
            <div className="mpc-stat">
              <span>Time (ms)</span>
              <strong>{result.time_ms}</strong>
            </div>
          </div>
          <GateTrace gates={result.gates} />
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 2 — n-bit Secure Equality
   ════════════════════════════════════════════════════════════════════ */
function EqualityN() {
  const [x, setX]      = useState(7);
  const [y, setY]      = useState(7);
  const [n, setN]      = useState(4);
  const [bits, setBits] = useState(64);
  const [result, setRes] = useState(null);
  const [busy, setBusy]  = useState(false);
  const [err, setErr]    = useState("");

  const maxVal = (1 << n) - 1;

  const run = async () => {
    setBusy(true); setErr(""); setRes(null);
    try {
      const r = await post("/pa20/equality-n", {
        x: Math.min(x, maxVal), y: Math.min(y, maxVal), n, bits,
      });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const xc = Math.min(x, maxVal), yc = Math.min(y, maxVal);

  return (
    <div>
      <p className="sub">
        <strong>n-bit Secure Equality:</strong> Alice has integer <em>x</em>, Bob
        has <em>y</em>. Securely compute <em>x == y</em> without revealing the values.
        Uses {n > 1 ? n - 1 : 0} AND gate{n > 2 ? "s" : ""} (OT calls) +{" "}
        {n} XOR gates. For n={n}: {n-1} OT call{n !== 2 ? "s" : ""}.
      </p>
      <div className="millionaire-panels">
        <div className="millionaire-party alice-panel">
          <div className="millionaire-party-title">🔒 Alice's x</div>
          <div className="millionaire-value">{xc}</div>
          <input type="range" min={0} max={maxVal} value={xc}
            onChange={e => setX(Number(e.target.value))}
            className="millionaire-slider alice-slider" />
        </div>
        <div className="millionaire-vs">=?</div>
        <div className="millionaire-party bob-panel">
          <div className="millionaire-party-title">🔒 Bob's y</div>
          <div className="millionaire-value">{yc}</div>
          <input type="range" min={0} max={maxVal} value={yc}
            onChange={e => setY(Number(e.target.value))}
            className="millionaire-slider bob-slider" />
        </div>
      </div>
      <div className="example-row" style={{ marginBottom: 12 }}>
        {[2, 3, 4].map(v => (
          <button key={v}
            className={`example-btn${n === v ? " active" : ""}`}
            onClick={() => setN(v)}>{v}-bit</button>
        ))}
      </div>
      <button className="run-btn" onClick={run} disabled={busy} style={{ background: "#8b5cf6" }}>
        {busy ? "Computing…" : "Test x == y Securely"}
      </button>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="millionaire-result">
          <div className={`millionaire-verdict verdict-${result.equal ? "alice" : "bob"}`}>
            {result.result_text}
          </div>
          <div className="mpc-stats">
            <div className="mpc-stat"><span>OT calls</span><strong>{result.n_ands}</strong></div>
            <div className="mpc-stat"><span>Free gates</span><strong>{result.n_free_gates}</strong></div>
            <div className="mpc-stat"><span>Time (ms)</span><strong>{result.time_ms}</strong></div>
          </div>
          <GateTrace gates={result.gates} />
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 3 — n-bit Secure Addition
   ════════════════════════════════════════════════════════════════════ */
function Addition() {
  const [x, setX]      = useState(3);
  const [y, setY]      = useState(5);
  const [n, setN]      = useState(4);
  const [bits, setBits] = useState(64);
  const [result, setRes] = useState(null);
  const [busy, setBusy]  = useState(false);
  const [err, setErr]    = useState("");

  const maxVal = (1 << n) - 1;

  const run = async () => {
    setBusy(true); setErr(""); setRes(null);
    try {
      const r = await post("/pa20/addition", {
        x: Math.min(x, maxVal), y: Math.min(y, maxVal), n, bits,
      });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const xc = Math.min(x, maxVal), yc = Math.min(y, maxVal);
  const expected = (xc + yc) % (1 << n);

  return (
    <div>
      <p className="sub">
        <strong>n-bit Secure Addition:</strong> Alice has <em>x</em>, Bob has{" "}
        <em>y</em>. Securely compute <em>(x + y) mod 2^n</em> using a ripple-carry
        adder circuit. For n={n}: {1 + 3*(n-2)} AND gate{n > 2 ? "s" : ""}
        {" "}(OT calls). Inputs are LSB-first.
      </p>
      <div className="millionaire-panels">
        <div className="millionaire-party alice-panel">
          <div className="millionaire-party-title">🔒 Alice's x</div>
          <div className="millionaire-value">{xc}</div>
          <input type="range" min={0} max={maxVal} value={xc}
            onChange={e => setX(Number(e.target.value))}
            className="millionaire-slider alice-slider" />
        </div>
        <div className="millionaire-vs">+</div>
        <div className="millionaire-party bob-panel">
          <div className="millionaire-party-title">🔒 Bob's y</div>
          <div className="millionaire-value">{yc}</div>
          <input type="range" min={0} max={maxVal} value={yc}
            onChange={e => setY(Number(e.target.value))}
            className="millionaire-slider bob-slider" />
        </div>
        <div className="millionaire-vs">= {expected} <span style={{fontSize:11, color:"#64748b"}}>mod 2^{n}</span></div>
      </div>
      <div className="example-row" style={{ marginBottom: 12 }}>
        {[2, 3, 4].map(v => (
          <button key={v}
            className={`example-btn${n === v ? " active" : ""}`}
            onClick={() => setN(v)}>{v}-bit</button>
        ))}
      </div>
      <button className="run-btn" onClick={run} disabled={busy} style={{ background: "#8b5cf6" }}>
        {busy ? "Computing…" : "Add Securely"}
      </button>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="millionaire-result">
          <div className={`millionaire-verdict verdict-${result.correct ? "alice" : "bob"}`}>
            {result.result_text} <Badge ok={result.correct} label={result.correct ? "✓" : "✗"} />
          </div>
          <div className="mpc-stats">
            <div className="mpc-stat"><span>OT calls</span><strong>{result.n_ands}</strong></div>
            <div className="mpc-stat"><span>Free gates</span><strong>{result.n_free_gates}</strong></div>
            <div className="mpc-stat"><span>Time (ms)</span><strong>{result.time_ms}</strong></div>
          </div>
          <GateTrace gates={result.gates} />
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 4 — Classic demos (inner product, majority, 1-bit equality)
             + Lineage trace
   ════════════════════════════════════════════════════════════════════ */
function ClassicDemos() {
  const [a0, setA0] = useState(1); const [a1, setA1] = useState(0);
  const [b0, setB0] = useState(1); const [b1, setB1] = useState(1);
  const [innerRes, setInnerRes] = useState(null);
  const [lineage, setLineage]   = useState(null);
  const [busy1, setBusy1] = useState(false);
  const [busy2, setBusy2] = useState(false);

  const runInner = async () => {
    setBusy1(true);
    try {
      const r = await post("/pa20/demo-inner-product", { a0, a1, b0, b1, bits: 64 });
      setInnerRes(r);
    } finally { setBusy1(false); }
  };

  const runLineage = async () => {
    setBusy2(true);
    try {
      const r = await get("/pa20/lineage");
      setLineage(r);
    } finally { setBusy2(false); }
  };

  const expected = (a0 & b0) ^ (a1 & b1);

  return (
    <div>
      <h4 style={{ color: "#e2e8f0", marginBottom: 8 }}>2-bit Inner Product</h4>
      <p className="sub">f(a₀,a₁,b₀,b₁) = (a₀ ∧ b₀) ⊕ (a₁ ∧ b₁)</p>
      <div className="mpc-inputs">
        <div className="mpc-party-box">
          <div className="mpc-party-title">Alice</div>
          {[["a₀", a0, setA0], ["a₁", a1, setA1]].map(([label, val, set]) => (
            <div key={label} className="mpc-bit-row">
              <span>{label}</span>
              {[0, 1].map(v => (
                <button key={v} className={`example-btn${val === v ? " active" : ""}`}
                  onClick={() => set(v)}>{v}</button>
              ))}
            </div>
          ))}
        </div>
        <div className="mpc-formula">({a0}∧{b0})⊕({a1}∧{b1}) = <strong>{expected}</strong></div>
        <div className="mpc-party-box">
          <div className="mpc-party-title">Bob</div>
          {[["b₀", b0, setB0], ["b₁", b1, setB1]].map(([label, val, set]) => (
            <div key={label} className="mpc-bit-row">
              <span>{label}</span>
              {[0, 1].map(v => (
                <button key={v} className={`example-btn${val === v ? " active" : ""}`}
                  onClick={() => set(v)}>{v}</button>
              ))}
            </div>
          ))}
        </div>
      </div>
      <button className="run-btn" onClick={runInner} disabled={busy1} style={{ background: "#6366f1" }}>
        {busy1 ? "…" : "Evaluate Securely"}
      </button>
      {innerRes && (
        <div style={{ marginTop: 8 }}>
          <Field label="Output" value={JSON.stringify(innerRes.output)} />
          <Field label="OT calls" value={innerRes.n_ands} />
          <GateTrace gates={innerRes.gates} />
        </div>
      )}

      <hr style={{ borderColor: "#334155", margin: "20px 0" }} />

      <h4 style={{ color: "#e2e8f0", marginBottom: 8 }}>End-to-End Lineage Trace</h4>
      <p className="sub">
        Show that a single AND gate evaluation triggers the full cryptographic
        stack: PA#20 → PA#19 → PA#18 → PA#12 → PA#13.
      </p>
      <button className="run-btn" onClick={runLineage} disabled={busy2} style={{ background: "#0ea5e9" }}>
        {busy2 ? "Running chain…" : "Run Lineage Trace"}
      </button>
      {lineage && (
        <div style={{ marginTop: 12 }}>
          <p className="sub">{lineage.description}</p>
          <Field label="Demo circuit" value={lineage.demo_circuit} mono={false} />
          <Field label="AND gates"    value={lineage.and_gates_evaluated} />
          <Field label="Total time"   value={`${lineage.total_time_ms} ms`} />
          <div style={{ marginTop: 12 }}>
            {lineage.chain?.map((step, i) => (
              <div key={i} className="lineage-step">
                <div className="lineage-layer">{step.layer}</div>
                <div className="lineage-module mono">{step.module}</div>
                <div className="lineage-role">{step.role}</div>
                <div className="lineage-calls">{step.calls}</div>
              </div>
            ))}
          </div>
          <p className="sub" style={{ marginTop: 12, fontStyle: "italic" }}>
            {lineage.security_foundation}
          </p>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   Root panel
   ════════════════════════════════════════════════════════════════════ */
const TABS = [
  { id: "millionaire", label: "🤑 Millionaire's Problem" },
  { id: "equality",    label: "= n-bit Equality" },
  { id: "addition",    label: "+ n-bit Addition" },
  { id: "demos",       label: "⚙ Inner Product / Lineage" },
];

export default function PA20Panel() {
  const [tab, setTab] = useState("millionaire");

  return (
    <div className="panel-root">
      <div className="panel-title">PA#20 — 2-Party Secure MPC (GMW Protocol)</div>
      <p className="panel-desc">
        Evaluate any boolean circuit securely using GMW: XOR gates are free
        (local), AND gates each cost one OT call (PA#19 → PA#18 → PA#12 → PA#13).
        Implements Millionaire's Problem, n-bit Equality, and Ripple-Carry Addition.
      </p>

      {/* Tabs */}
      <div className="tab-row">
        {TABS.map(t => (
          <button key={t.id}
            className={`tab-btn${tab === t.id ? " active" : ""}`}
            onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      <div className="tab-body">
        {tab === "millionaire" && <Millionaire />}
        {tab === "equality"    && <EqualityN />}
        {tab === "addition"    && <Addition />}
        {tab === "demos"       && <ClassicDemos />}
      </div>
    </div>
  );
}
