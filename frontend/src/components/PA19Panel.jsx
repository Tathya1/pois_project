import { useState } from "react";
import "./PA13Panel.css";
import "./PA19Panel.css";

const API = "http://localhost:5000";

const post = (path, body) =>
  fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => r.json());

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

/* ════════════════════════════════════════════════════════════════════
   TAB 1 — Secure AND Demo
   ════════════════════════════════════════════════════════════════════ */
function AndDemo() {
  const [a, setA]       = useState(1);
  const [b, setB]       = useState(1);
  const [bits, setBits] = useState(128);
  const [result, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState("");

  const run = async () => {
    setBusy(true); setErr(""); setRes(null);
    try {
      const r = await post("/pa19/compute", { a, b, bits });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const trace = result?.trace;

  return (
    <div>
      <p className="sub">
        Compute AND(a, b) securely: Alice holds a, Bob holds b. Neither party
        reveals their input during the protocol. Both learn a AND b at the end.
        Implemented using 1-of-2 OT (PA#18): Alice's messages encode r_A and r_A⊕a;
        Bob's OT choice bit = b; output = r_A ⊕ r_B = a AND b.
      </p>
      <div className="and-input-grid">
        <div className="and-party">
          <div className="and-party-label">Alice's bit a</div>
          {[0, 1].map(v => (
            <button key={v} className={`example-btn${a === v ? " active" : ""}`}
              onClick={() => setA(v)}>a = {v}</button>
          ))}
        </div>
        <div className="and-op">AND</div>
        <div className="and-party">
          <div className="and-party-label">Bob's bit b</div>
          {[0, 1].map(v => (
            <button key={v} className={`example-btn${b === v ? " active" : ""}`}
              onClick={() => setB(v)}>b = {v}</button>
          ))}
        </div>
        <div className="and-op">=</div>
        <div className="and-result-preview">{a & b}</div>
      </div>
      <div className="example-row">
        {[64, 128, 256].map(bi => (
          <button key={bi} className={`example-btn${bits === bi ? " active" : ""}`}
            onClick={() => setBits(bi)}>{bi}-bit OT</button>
        ))}
      </div>
      <button className="run-btn" onClick={run} disabled={busy}>
        {busy ? "Running Secure AND…" : "Run Secure AND Protocol"}
      </button>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="result-card">
          <div className="result-headline">
            AND({result.alice_bit}, {result.bob_bit}) = {result.actual_output} &nbsp;
            <Badge ok={result.correct} label={result.correct ? "✓ Correct" : "✗ Error"} />
          </div>
          {trace && (
            <div className="and-trace">
              <div className="and-trace-step">
                <div className="and-step-title">Step 1 — Alice's Share</div>
                <Field label="r_A (Alice's random output share)" value={trace.step1_alice_share?.r_A} />
                <div className="ot-trace-note">{trace.step1_alice_share?.note}</div>
              </div>
              <div className="and-trace-step">
                <div className="and-step-title">Step 2 — OT Messages</div>
                <Field label="m₀ (if Bob=0)" value={trace.step2_alice_ot_messages?.m_0} />
                <Field label="m₁ (if Bob=1)" value={trace.step2_alice_ot_messages?.m_1} />
              </div>
              <div className="and-trace-step">
                <div className="and-step-title">Step 3 — OT Execution</div>
                <Field label="Bob's choice" value={trace.step3_ot_execution?.ot_choice} />
                <Field label="Bob received r_B" value={trace.step3_ot_execution?.bob_received_r_B} />
              </div>
              <div className="and-trace-step">
                <div className="and-step-title">Step 4 — Reconstruct</div>
                <Field label="Alice's share r_A" value={trace.step4_reconstruct?.alice_share_r_A} />
                <Field label="Bob's share r_B"   value={trace.step4_reconstruct?.bob_share_r_B} />
                <Field label="r_A ⊕ r_B = output" value={trace.step4_reconstruct?.output} />
              </div>
            </div>
          )}
          {result.security && (
            <div className="note-box">
              <strong>Alice's view:</strong> {result.security.alice_privacy}<br />
              <strong>Bob's view:</strong> {result.security.bob_privacy}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 2 — Truth Table Verification
   ════════════════════════════════════════════════════════════════════ */
function TruthTable() {
  const [bits, setBits] = useState(128);
  const [rows, setRows] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState("");

  const run = async () => {
    setBusy(true); setErr(""); setRows(null);
    try {
      const r = await post("/pa19/truth-table", { bits });
      if (r.error) throw new Error(r.error);
      setRows(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <p className="sub">
        Run the secure AND protocol for all 4 input combinations (a,b) ∈ {"{{0,1}²}"} and
        verify correctness in each case.
      </p>
      <div className="example-row">
        {[64, 128].map(b => (
          <button key={b} className={`example-btn${bits === b ? " active" : ""}`}
            onClick={() => setBits(b)}>{b}-bit OT</button>
        ))}
      </div>
      <button className="run-btn" onClick={run} disabled={busy}>
        {busy ? "Running 4 OT instances…" : "Verify All 4 Inputs"}
      </button>
      {err && <div className="err">{err}</div>}
      {rows && (
        <div className="result-card">
          <div className="result-headline">
            Truth Table &nbsp;
            <Badge ok={rows.all_correct} label={rows.all_correct ? "✓ All Correct" : "✗ Some Failed"} />
          </div>
          <table className="tt-table">
            <thead>
              <tr><th>a</th><th>b</th><th>Expected</th><th>Computed</th><th>OK?</th></tr>
            </thead>
            <tbody>
              {rows.rows?.map((row, i) => (
                <tr key={i}>
                  <td>{row.a}</td>
                  <td>{row.b}</td>
                  <td>{row.expected}</td>
                  <td>{row.computed}</td>
                  <td><Badge ok={row.correct} label={row.correct ? "✓" : "✗"} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 3 — Privacy Proof
   ════════════════════════════════════════════════════════════════════ */
function PrivacyProof() {
  const [a, setA]       = useState(1);
  const [b, setB]       = useState(0);
  const [bits, setBits] = useState(128);
  const [result, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState("");

  const run = async () => {
    setBusy(true); setErr(""); setRes(null);
    try {
      const r = await post("/pa19/verify-privacy", { a, b, bits });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <p className="sub">
        Privacy analysis: show exactly what each party observes during the protocol
        and why neither can determine the other's private input.
      </p>
      <div className="and-input-grid">
        <div className="and-party">
          <div className="and-party-label">Alice's bit a</div>
          {[0,1].map(v => (
            <button key={v} className={`example-btn${a===v?" active":""}`} onClick={()=>setA(v)}>a={v}</button>
          ))}
        </div>
        <div className="and-op">AND</div>
        <div className="and-party">
          <div className="and-party-label">Bob's bit b</div>
          {[0,1].map(v => (
            <button key={v} className={`example-btn${b===v?" active":""}`} onClick={()=>setB(v)}>b={v}</button>
          ))}
        </div>
      </div>
      <div className="example-row">
        {[64, 128].map(bi => (
          <button key={bi} className={`example-btn${bits===bi?" active":""}`} onClick={()=>setBits(bi)}>{bi}-bit</button>
        ))}
      </div>
      <button className="run-btn" onClick={run} disabled={busy}>
        {busy ? "Analysing…" : "Analyse Privacy"}
      </button>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="result-card">
          <div className="result-headline">
            AND({result.alice_bit}, {result.bob_bit}) = {result.and_result} &nbsp;
            <Badge ok={result.correct} label={result.correct ? "✓ Correct" : "✗ Error"} />
          </div>
          <div className="and-trace">
            <div className="and-trace-step">
              <div className="and-step-title">Alice's View</div>
              <Field label="Her own bit a" value={result.alice_sees?.her_own_bit} />
              <Field label="Her share r_A" value={result.alice_sees?.her_share_r_A} />
              <div className="ot-trace-note">{result.alice_sees?.what_she_knows}</div>
            </div>
            <div className="and-trace-step">
              <div className="and-step-title">Bob's View</div>
              <Field label="His own bit b" value={result.bob_sees?.his_own_bit} />
              <Field label="His share r_B" value={result.bob_sees?.his_share_r_B} />
              <div className="ot-trace-note">{result.bob_sees?.what_he_knows}</div>
            </div>
            <div className="and-trace-step">
              <div className="and-step-title">Reconstruction</div>
              <Field label="Alice's share" value={result.reconstruction?.alice_share} />
              <Field label="Bob's share"   value={result.reconstruction?.bob_share} />
              <Field label="Output"        value={result.reconstruction?.output} />
            </div>
          </div>
          {result.security_proof && (
            <div className="note-box">
              <strong>Privacy:</strong> {result.security_proof.privacy}<br />
              <strong>Correctness:</strong> {result.security_proof.correctness}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 4 — Secure XOR (free gate)
   ════════════════════════════════════════════════════════════════════ */
function SecureXOR() {
  const [a, setA] = useState(1);
  const [b, setB] = useState(0);
  const [result, setRes] = useState(null);
  const [allRuns, setAllRuns] = useState(null);
  const [busy, setBusy]  = useState(false);
  const [err, setErr]    = useState("");

  const run = async () => {
    setBusy(true); setErr(""); setRes(null);
    try {
      const r = await post("/pa19/xor", { a, b });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const runAll = async () => {
    setBusy(true); setErr(""); setAllRuns(null);
    try {
      const r = await post("/pa19/truth-table-xor", {});
      if (r.error) throw new Error(r.error);
      setAllRuns(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const trace = result?.trace;

  return (
    <div>
      <p className="sub">
        <strong>Secure XOR (free gate):</strong> Alice has bit a, Bob has bit b.
        Compute a ⊕ b without revealing inputs. No OT needed — Alice sends a single
        random mask bit r; her share is a⊕r, Bob's share is b⊕r.
        Reconstruction: (a⊕r) ⊕ (b⊕r) = a ⊕ b. <em>Zero public-key operations.</em>
      </p>
      <div className="and-input-grid">
        <div className="and-party">
          <div className="and-party-label">Alice's bit a</div>
          {[0, 1].map(v => (
            <button key={v} className={`example-btn${a === v ? " active" : ""}`}
              onClick={() => setA(v)}>a = {v}</button>
          ))}
        </div>
        <div className="and-op" style={{ color: "#0ea5e9" }}>XOR</div>
        <div className="and-party">
          <div className="and-party-label">Bob's bit b</div>
          {[0, 1].map(v => (
            <button key={v} className={`example-btn${b === v ? " active" : ""}`}
              onClick={() => setB(v)}>b = {v}</button>
          ))}
        </div>
        <div className="and-op" style={{ color: "#0ea5e9" }}>=</div>
        <div className="and-result-preview" style={{ color: "#0ea5e9" }}>{a ^ b}</div>
      </div>
      <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
        <button className="run-btn" onClick={run} disabled={busy} style={{ background: "#0284c7" }}>
          {busy ? "Running…" : "Run Secure XOR"}
        </button>
        <button className="run-btn" onClick={runAll} disabled={busy} style={{ background: "#0284c7" }}>
          {busy ? "…" : "Verify All 4 Inputs"}
        </button>
      </div>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="result-card">
          <div className="result-headline">
            XOR({result.alice_bit}, {result.bob_bit}) = {result.actual_output} &nbsp;
            <Badge ok={result.correct} label={result.correct ? "✓" : "✗"} />
            &nbsp;<span style={{ fontSize: 11, color: "#0ea5e9" }}>OT calls: {result.ot_calls}</span>
          </div>
          {trace && (
            <div className="and-trace">
              <div className="and-trace-step">
                <div className="and-step-title">Step 1 — Alice's Mask</div>
                <Field label="r (random mask)" value={trace.step1_alice_mask?.r} />
                <div className="ot-trace-note">{trace.step1_alice_mask?.note}</div>
              </div>
              <div className="and-trace-step">
                <div className="and-step-title">Step 2 — Secret Shares</div>
                <Field label="Alice's share (a⊕r)" value={trace.step2_shares?.alice_share} />
                <Field label="Bob's share (b⊕r)"   value={trace.step2_shares?.bob_share} />
                <div className="ot-trace-note">{trace.step2_shares?.note}</div>
              </div>
              <div className="and-trace-step">
                <div className="and-step-title">Step 3 — Reconstruct</div>
                <Field label="Output (share⊕share)" value={trace.step3_reconstruct?.output} />
                <div className="ot-trace-note">{trace.step3_reconstruct?.note}</div>
              </div>
            </div>
          )}
          {result.security && (
            <div className="note-box">
              <strong>Alice's privacy:</strong> {result.security.alice_privacy}<br />
              <strong>Bob's privacy:</strong> {result.security.bob_privacy}<br />
              <em>{result.security.no_ot_needed}</em>
            </div>
          )}
        </div>
      )}
      {allRuns && (
        <div className="result-card">
          <div className="result-headline">
            XOR Truth Table &nbsp;
            <Badge ok={allRuns.all_correct} label={allRuns.all_correct ? "✓ All Correct" : "✗ Failed"} />
          </div>
          <table className="tt-table">
            <thead><tr><th>a</th><th>b</th><th>Expected</th><th>Computed</th><th>OK?</th></tr></thead>
            <tbody>
              {allRuns.rows?.map((row, i) => (
                <tr key={i}>
                  <td>{row.a}</td><td>{row.b}</td>
                  <td>{row.expected}</td><td>{row.computed}</td>
                  <td><Badge ok={row.correct} label={row.correct ? "✓" : "✗"} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 5 — Secure NOT (free gate)
   ════════════════════════════════════════════════════════════════════ */
function SecureNOT() {
  const [a, setA]       = useState(1);
  const [result, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState("");

  const run = async () => {
    setBusy(true); setErr(""); setRes(null);
    try {
      const r = await post("/pa19/not", { a });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <p className="sub">
        <strong>Secure NOT (free gate):</strong> Alice locally flips her bit.
        No communication with Bob, no OT call. Alice computes NOT(a) = 1 − a locally.
        Trivially private since zero information is exchanged.
      </p>
      <div className="and-input-grid">
        <div className="and-party">
          <div className="and-party-label">Alice's bit a</div>
          {[0, 1].map(v => (
            <button key={v} className={`example-btn${a === v ? " active" : ""}`}
              onClick={() => setA(v)}>a = {v}</button>
          ))}
        </div>
        <div className="and-op" style={{ color: "#10b981" }}>NOT →</div>
        <div className="and-result-preview" style={{ color: "#10b981" }}>{1 - a}</div>
      </div>
      <button className="run-btn" onClick={run} disabled={busy} style={{ background: "#059669" }}>
        {busy ? "…" : "Run Secure NOT"}
      </button>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="result-card">
          <div className="result-headline">
            NOT({result.alice_bit}) = {result.actual_output} &nbsp;
            <Badge ok={result.correct} label="✓" />
            &nbsp;<span style={{ fontSize: 11, color: "#10b981" }}>OT calls: {result.ot_calls}</span>
          </div>
          <Field label="Input a"     value={result.alice_bit} />
          <Field label="Output NOT(a)" value={result.actual_output} />
          {result.trace?.step1_alice_flips && (
            <div className="note-box">{result.trace.step1_alice_flips.note}</div>
          )}
          {result.security?.no_communication && (
            <div className="note-box">{result.security.no_communication}</div>
          )}
        </div>
      )}
    </div>
  );
}

const TABS = [
  { id: "demo",    label: "Secure AND" },
  { id: "xor",     label: "Secure XOR (free)" },
  { id: "not",     label: "Secure NOT (free)" },
  { id: "truth",   label: "Truth Table" },
  { id: "privacy", label: "Privacy Proof" },
];

export default function PA19Panel() {
  const [tab, setTab] = useState("demo");
  return (
    <div className="panel-root">
      <h2 className="panel-title">PA#19 — Secure AND / XOR / NOT Gates</h2>
      <p className="panel-desc">
        Functionally complete secure gate set: AND costs 1 OT call (PA#18); XOR and NOT
        are free (no OT). Together they can evaluate any boolean function securely — the
        basis of GMW (PA#20).
      </p>
      <div className="pa-tabs">
        {TABS.map(t => (
          <button key={t.id} className={`pa-tab${tab === t.id ? " active" : ""}`}
            onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      {tab === "demo"    && <AndDemo />}
      {tab === "xor"     && <SecureXOR />}
      {tab === "not"     && <SecureNOT />}
      {tab === "truth"   && <TruthTable />}
      {tab === "privacy" && <PrivacyProof />}
    </div>
  );
}
