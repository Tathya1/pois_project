import { useState } from "react";
import "./PA13Panel.css";
import "./PA18Panel.css";

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
const trunc = (s, n = 32) => {
  if (!s) return "—";
  const str = String(s);
  return str.length > n ? str.slice(0, n) + "…" : str;
};

/* ════════════════════════════════════════════════════════════════════
   TAB 1 — Protocol Overview (static explainer)
   ════════════════════════════════════════════════════════════════════ */
function Overview() {
  return (
    <div>
      <p className="sub">
        <strong>Oblivious Transfer (OT)</strong> is a foundational MPC primitive.
        In a 1-of-2 OT: the <em>Sender</em> has two messages (m₀, m₁); the
        <em> Receiver</em> has a choice bit b ∈ {"{0,1}"}. The Receiver obtains
        m_b — and learns nothing about m_{"{1−b}"}. The Sender learns nothing about b.
      </p>
      <div className="ot-steps">
        <div className="ot-step">
          <div className="ot-step-num">1</div>
          <div>
            <strong>Sender setup:</strong> Generate RSA keypair (N, e, d) and two
            random challenges x₀, x₁ ∈ Z_N. Send (N, e, x₀, x₁) to Receiver.
          </div>
        </div>
        <div className="ot-step">
          <div className="ot-step-num">2</div>
          <div>
            <strong>Receiver query:</strong> Pick random k ∈ Z_N.
            Compute v = x_b + k^e mod N. Send v to Sender.
            (Sender cannot determine b from v without inverting RSA.)
          </div>
        </div>
        <div className="ot-step">
          <div className="ot-step-num">3</div>
          <div>
            <strong>Sender response:</strong> Compute k₀ = (v−x₀)^d, k₁ = (v−x₁)^d.
            Exactly one of {"{k₀, k₁}"} equals k. Send (m₀⊕H(k₀), m₁⊕H(k₁)).
          </div>
        </div>
        <div className="ot-step">
          <div className="ot-step-num">4</div>
          <div>
            <strong>Receiver decrypts:</strong> Unmask m_b using H(k). m_{"{1−b}"}
            stays hidden (masked with unknown key k_{"{1−b}"}).
          </div>
        </div>
      </div>
      <div className="note-box">
        <strong>Security:</strong> Receiver privacy relies on RSA one-wayness (OW-CPA);
        sender privacy relies on the fact that Receiver holds exactly one k.
        This is the Even–Goldreich–Lempel (EGL) OT protocol.
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 2 — Interactive Demo: "Play the OT Receiver" (spec-compliant)
   Alice's panel (left, greyed out): holds m0, m1 — hidden from student.
   Bob's panel (right, interactive): student clicks "Choose 0" or "Choose 1."
   ════════════════════════════════════════════════════════════════════ */
function InteractiveDemo() {
  const [m0, setM0]         = useState("Secret message 0");
  const [m1, setM1]         = useState("Secret message 1");
  const [choice, setChoice] = useState(null);   // null = not yet chosen
  const [bits, setBits]     = useState(128);
  const [result, setRes]    = useState(null);
  const [cheat, setCheat]   = useState(null);
  const [busy, setBusy]     = useState(false);
  const [busyCheat, setBusyCheat] = useState(false);
  const [err, setErr]       = useState("");

  const choose = async (b) => {
    setChoice(b); setBusy(true); setErr(""); setRes(null); setCheat(null);
    try {
      const r = await post("/pa18/full-protocol", { m0, m1, choice: b, bits });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const tryCheat = async () => {
    if (result == null) return;
    setBusyCheat(true); setCheat(null);
    try {
      const r = await post("/pa18/cheat-attempt", {
        m0, m1, choice: result.choice, bits,
      });
      setCheat(r);
    } catch (e) { setCheat({ cheat_result: "Error: " + e.message }); }
    finally { setBusyCheat(false); }
  };

  const reset = () => { setChoice(null); setRes(null); setCheat(null); setErr(""); };

  const trace = result?.trace;

  return (
    <div>
      <p className="sub">
        <strong>Play the OT Receiver (Bob).</strong> Alice holds two hidden messages.
        You (Bob) choose which one to receive — without Alice learning your choice,
        and without you learning the other message.
      </p>

      {/* Two-panel layout */}
      <div className="ot-two-panel">

        {/* Alice's panel — greyed out, messages hidden */}
        <div className="ot-panel alice-panel-ot">
          <div className="ot-panel-title">🔒 Alice (Sender)</div>
          <p className="ot-panel-note">Alice holds two secret messages. You cannot see them until the protocol runs.</p>
          <div className="form-row">
            <label style={{ color: "#64748b", fontSize: 12 }}>m₀ (hidden)</label>
            <input className="text-input" value={m0}
              onChange={e => { setM0(e.target.value); reset(); }}
              placeholder="Secret message 0" />
          </div>
          <div className="form-row">
            <label style={{ color: "#64748b", fontSize: 12 }}>m₁ (hidden)</label>
            <input className="text-input" value={m1}
              onChange={e => { setM1(e.target.value); reset(); }}
              placeholder="Secret message 1" />
          </div>
          <div className="example-row" style={{ marginTop: 8 }}>
            {[64, 128].map(b => (
              <button key={b}
                className={`example-btn${bits === b ? " active" : ""}`}
                onClick={() => { setBits(b); reset(); }}>{b}-bit RSA</button>
            ))}
          </div>
        </div>

        {/* Bob's panel — interactive choice */}
        <div className="ot-panel bob-panel-ot">
          <div className="ot-panel-title">🎯 Bob (Receiver — You)</div>
          {result == null ? (
            <>
              <p className="ot-panel-note">
                Which message do you want? <strong>Alice will never learn your choice.</strong>
              </p>
              <div className="ot-choice-btns">
                <button className="run-btn choice-btn choice-0"
                  onClick={() => choose(0)} disabled={busy}>
                  {busy && choice === 0 ? "Running OT…" : "Choose 0 → get m₀"}
                </button>
                <button className="run-btn choice-btn choice-1"
                  onClick={() => choose(1)} disabled={busy}>
                  {busy && choice === 1 ? "Running OT…" : "Choose 1 → get m₁"}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="ot-result-reveal">
                <div className="ot-reveal-label">You chose b = {result.choice}</div>
                <div className="ot-msg-row">
                  <div className="ot-msg-card revealed">
                    <div className="ot-msg-idx">m{result.choice} (revealed)</div>
                    <div className="ot-msg-val">"{result.recovered}"</div>
                  </div>
                  <div className="ot-msg-card hidden-msg">
                    <div className="ot-msg-idx">m{1 - result.choice} (hidden)</div>
                    <div className="ot-msg-val">??</div>
                  </div>
                </div>
                <Badge ok={result.success} label={result.success ? "✓ Correct message received" : "✗ Protocol error"} />
              </div>
              <button className="run-btn" onClick={reset}
                style={{ background: "#475569", marginTop: 8, fontSize: 12 }}>
                Reset
              </button>
            </>
          )}
          {err && <div className="err">{err}</div>}
        </div>
      </div>

      {/* Step log */}
      {trace && (
        <div className="result-card" style={{ marginTop: 12 }}>
          <div className="result-headline">Protocol Message Log</div>
          <div className="ot-trace">
            <div className="ot-trace-step">
              <div className="ot-trace-title">Step 1 — Sender Setup</div>
              <div className="ot-trace-note">{trace.step1_sender_setup?.note}</div>
              <Field label="N (truncated)" value={(trace.step1_sender_setup?.N || "").slice(0, 24) + "…"} />
            </div>
            <div className="ot-trace-step">
              <div className="ot-trace-title">Step 2 — Receiver Query</div>
              <div className="ot-trace-note">{trace.step2_receiver_query?.note}</div>
              <Field label="v (blinded choice)" value={(trace.step2_receiver_query?.v || "").slice(0, 24) + "…"} />
            </div>
            <div className="ot-trace-step">
              <div className="ot-trace-title">Step 3 — Sender Response</div>
              <div className="ot-trace-note">{trace.step3_sender_response?.note}</div>
            </div>
            <div className="ot-trace-step">
              <div className="ot-trace-title">Step 4 — Receiver Decrypts m{result?.choice}</div>
              <div className="ot-trace-note">{trace.step4_receiver_decrypt?.note}</div>
            </div>
          </div>

          {/* Privacy summary */}
          <div className="ot-privacy-summary">
            <div className="ot-privacy-row">
              <span className="ot-privacy-who">What does Alice learn?</span>
              <span className="ot-privacy-ans">Only v (receiver's blinded query). She cannot determine b without inverting RSA.</span>
            </div>
            <div className="ot-privacy-row">
              <span className="ot-privacy-who">What does Bob learn?</span>
              <span className="ot-privacy-ans">Only m{result?.choice}. m{result != null ? 1 - result.choice : "?"} is masked with an unknown key.</span>
            </div>
          </div>

          {/* Cheat attempt */}
          {!cheat && (
            <button className="run-btn" onClick={tryCheat} disabled={busyCheat}
              style={{ background: "#dc2626", marginTop: 12 }}>
              {busyCheat ? "Attempting cheat…" : "🕵️ Cheat Attempt: Try to get m" + (1 - result?.choice)}
            </button>
          )}
          {cheat && (
            <div className="cheat-result">
              <div className="cheat-title">Cheat Attempt — FAILED</div>
              <Field label="Tried to get" value={cheat.cheat_target} mono={false} />
              <Field label="Actually got"  value={`"${cheat.cheat_result}"`} mono={false} />
              <Badge ok={false} label="✗ Cheat failed — m_{1-b} is computationally hidden" />
              <div className="ot-trace-note" style={{ marginTop: 6 }}>{cheat.explanation}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 3 — Step-by-step Manual
   ════════════════════════════════════════════════════════════════════ */
function StepByStep() {
  const [bits, setBits]   = useState(128);
  const [setup, setSetup] = useState(null);
  const [query, setQuery] = useState(null);
  const [resp, setResp]   = useState(null);
  const [dec, setDec]     = useState(null);
  const [choice, setChoice] = useState(0);
  const [m0, setM0] = useState("Hello");
  const [m1, setM1] = useState("World");
  const [busy, setBusy]   = useState(false);
  const [err, setErr]     = useState("");

  const step1 = async () => {
    setBusy(true); setErr(""); setSetup(null); setQuery(null); setResp(null); setDec(null);
    try {
      const r = await post("/pa18/sender-setup", { bits });
      if (r.error) throw new Error(r.error);
      setSetup(r);
    } catch(e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const step2 = async () => {
    if (!setup) return;
    setBusy(true); setErr(""); setQuery(null); setResp(null); setDec(null);
    try {
      const r = await post("/pa18/receiver-query", {
        N: setup.N, e: setup.e, x0: setup.x0, x1: setup.x1, choice,
      });
      if (r.error) throw new Error(r.error);
      setQuery(r);
    } catch(e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const step3 = async () => {
    if (!setup || !query) return;
    setBusy(true); setErr(""); setResp(null); setDec(null);
    try {
      const r = await post("/pa18/sender-respond", {
        N: setup.N, d: setup.d, x0: setup.x0, x1: setup.x1,
        v: query.v,
        m0_hex: Array.from(new TextEncoder().encode(m0)).map(b => b.toString(16).padStart(2,"0")).join(""),
        m1_hex: Array.from(new TextEncoder().encode(m1)).map(b => b.toString(16).padStart(2,"0")).join(""),
      });
      if (r.error) throw new Error(r.error);
      setResp(r);
    } catch(e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const step4 = async () => {
    if (!query || !resp) return;
    setBusy(true); setErr(""); setDec(null);
    try {
      const r = await post("/pa18/receiver-decrypt", {
        choice, k: query.k, m0_enc_hex: resp.m0_enc_hex, m1_enc_hex: resp.m1_enc_hex,
      });
      if (r.error) throw new Error(r.error);
      setDec(r);
    } catch(e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <p className="sub">Walk through the four OT steps manually.</p>
      <div className="form-row">
        <label>m₀</label>
        <input className="text-input" value={m0} onChange={e => setM0(e.target.value)} />
      </div>
      <div className="form-row">
        <label>m₁</label>
        <input className="text-input" value={m1} onChange={e => setM1(e.target.value)} />
      </div>
      <div className="form-row">
        <label>Choice b</label>
        <div className="example-row">
          {[0,1].map(c => (
            <button key={c} className={`example-btn${choice===c?" active":""}`} onClick={()=>setChoice(c)}>b={c}</button>
          ))}
        </div>
      </div>
      <div className="example-row">
        {[64, 128].map(b => (
          <button key={b} className={`example-btn${bits===b?" active":""}`} onClick={()=>setBits(b)}>{b}-bit</button>
        ))}
      </div>
      <div className="ot-steps-row">
        <button className="run-btn" onClick={step1} disabled={busy}>Step 1: Sender Setup</button>
        <button className="run-btn" onClick={step2} disabled={busy || !setup}>Step 2: Receiver Query</button>
        <button className="run-btn" onClick={step3} disabled={busy || !query}>Step 3: Sender Respond</button>
        <button className="run-btn" onClick={step4} disabled={busy || !resp}>Step 4: Decrypt</button>
      </div>
      {err && <div className="err">{err}</div>}
      {setup && (
        <div className="result-card">
          <div className="eg-section-title">Step 1 — Sender Setup</div>
          <Field label="N" value={trunc(setup.N)} />
          <Field label="e" value={setup.e} />
          <Field label="x₀" value={trunc(setup.x0)} />
          <Field label="x₁" value={trunc(setup.x1)} />
        </div>
      )}
      {query && (
        <div className="result-card">
          <div className="eg-section-title">Step 2 — Receiver Query</div>
          <Field label="v (blinded choice)" value={trunc(query.v)} />
          <Field label="k (receiver secret)" value={trunc(query.k)} />
        </div>
      )}
      {resp && (
        <div className="result-card">
          <div className="eg-section-title">Step 3 — Sender Response</div>
          <Field label="m₀_enc" value={trunc(resp.m0_enc_hex)} />
          <Field label="m₁_enc" value={trunc(resp.m1_enc_hex)} />
          <Field label="k₀ (sender)" value={trunc(resp.k0)} />
          <Field label="k₁ (sender)" value={trunc(resp.k1)} />
        </div>
      )}
      {dec && (
        <div className="result-card">
          <div className="eg-section-title">Step 4 — Receiver Decrypts</div>
          <Field label="Recovered m_b" value={dec.message_text} mono={false} />
          <Badge ok={dec.message_text === (choice === 0 ? m0 : m1)}
            label={dec.message_text === (choice === 0 ? m0 : m1) ? "✓ Correct message" : "✗ Mismatch"} />
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 4 — Correctness Test
   ════════════════════════════════════════════════════════════════════ */
function CorrectnessTest() {
  const [trials, setTrials] = useState(100);
  const [bits, setBits] = useState(64);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const runTest = async () => {
    setBusy(true);
    setErr("");
    setResult(null);
    try {
      const r = await post("/pa18/bulk-test", { trials, bits });
      if (r.error) throw new Error(r.error);
      setResult(r);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <p className="sub">
        Run multiple trials of the OT protocol with random inputs to verify its correctness.
      </p>
      <div className="form-row">
        <label>Number of Trials</label>
        <input
          className="text-input"
          type="number"
          value={trials}
          onChange={(e) => setTrials(parseInt(e.target.value, 10))}
        />
      </div>
      <div className="form-row">
        <label>RSA Bit-length</label>
        <div className="example-row">
          {[64, 128].map((b) => (
            <button
              key={b}
              className={`example-btn${bits === b ? " active" : ""}`}
              onClick={() => setBits(b)}
            >
              {b}-bit
            </button>
          ))}
        </div>
      </div>
      <button className="run-btn" onClick={runTest} disabled={busy}>
        {busy ? "Running Tests…" : `Run ${trials} Trials`}
      </button>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="result-card">
          <div className="result-headline">Test Results</div>
          <Field label="Trials" value={result.trials} mono={false} />
          <Field label="Successes" value={result.successes} mono={false} />
          <Field label="Failures" value={result.failures} mono={false} />
          <Field label="Success Rate" value={`${result.success_rate}%`} mono={false} />
          <Badge
            ok={result.failures === 0}
            label={result.failures === 0 ? "✓ All tests passed" : "✗ Some tests failed"}
          />
        </div>
      )}
    </div>
  );
}

const TABS = [
  { id: "overview", label: "Protocol Overview" },
  { id: "demo",     label: "Interactive Demo" },
  { id: "steps",    label: "Step by Step" },
  { id: "correctness", label: "Correctness Test" },
];

export default function PA18Panel() {
  const [tab, setTab] = useState("overview");
  return (
    <div className="panel-root">
      <h2 className="panel-title">PA#18 — 1-of-2 Oblivious Transfer</h2>
      <p className="panel-desc">
        Foundational MPC primitive: Receiver obtains one of two Sender messages without
        revealing their choice. Sender learns nothing about which message was chosen.
        Built on PA#12 (RSA). Based on the Even–Goldreich–Lempel protocol.
      </p>
      <div className="pa-tabs">
        {TABS.map(t => (
          <button key={t.id} className={`pa-tab${tab === t.id ? " active" : ""}`}
            onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      {tab === "overview" && <Overview />}
      {tab === "demo"     && <InteractiveDemo />}
      {tab === "steps"    && <StepByStep />}
      {tab === "correctness" && <CorrectnessTest />}
    </div>
  );
}
