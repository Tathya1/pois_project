import { useState } from "react";
import "./PA13Panel.css";
import "./PA11Panel.css";

const API = "http://localhost:5000";

/* ── tiny helpers ────────────────────────────────────────────────────── */
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

/* ── truncate large hex strings for display ─────────────────────────── */
const truncHex = (s, n = 40) => {
  if (!s) return "—";
  const h = typeof s === "string" ? s : s.toString(16);
  return h.length > n ? h.slice(0, n) + "…" : h;
};

/* ════════════════════════════════════════════════════════════════════════
   TAB 1 — Live DH Exchange (Alice + Bob panels, optional Eve MITM)
   ════════════════════════════════════════════════════════════════════════ */
function LiveExchange() {
  const [bits, setBits] = useState(32);
  const [params, setParams] = useState(null);
  const [alicePriv, setAlicePriv] = useState("");
  const [bobPriv, setBobPriv] = useState("");
  const [alicePub, setAlicePub] = useState(null);
  const [bobPub, setBobPub] = useState(null);
  const [kAlice, setKAlice] = useState(null);
  const [kBob, setKBob] = useState(null);
  const [mitm, setMitm] = useState(false);
  const [evePub, setEvePub] = useState(null);
  const [kAE, setKAE] = useState(null);
  const [kBE, setKBE] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const genParams = async () => {
    setLoading(true); setErr("");
    try {
      const d = await post("/pa11/params", { bits });
      setParams(d);
      setAlicePriv(""); setBobPriv("");
      setAlicePub(null); setBobPub(null);
      setKAlice(null); setKBob(null);
      setEvePub(null); setKAE(null); setKBE(null);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const doExchange = async () => {
    if (!params) return;
    setLoading(true); setErr("");
    try {
      const pp = { p: params.p, q: params.q, g: params.g };

      // Step 1
      const aPrivInput = alicePriv.trim() ? alicePriv.trim() : undefined;
      const bPrivInput = bobPriv.trim()   ? bobPriv.trim()   : undefined;

      const [a1, b1] = await Promise.all([
        post("/pa11/alice-step1", { ...pp, ...(aPrivInput ? { a: aPrivInput } : {}) }),
        post("/pa11/bob-step1",   { ...pp, ...(bPrivInput ? { b: bPrivInput } : {}) }),
      ]);

      setAlicePub(a1.public); setBobPub(b1.public);
      setAlicePriv(a1.private); setBobPriv(b1.private);

      if (mitm) {
        // MITM: Eve intercepts A and B, substitutes her own
        const mData = await post("/pa11/mitm", {
          ...pp, alice_public: a1.public, bob_public: b1.public,
        });
        setEvePub(mData.eve_public);
        setKAE(mData.key_alice_eve ?? mData.K_alice_eve);
        setKBE(mData.key_bob_eve   ?? mData.K_bob_eve);
        // Alice and Bob each compute with Eve's public (Eve intercepts)
        const [a2, b2] = await Promise.all([
          post("/pa11/alice-step2", { ...pp, a: a1.private, B: mData.eve_public }),
          post("/pa11/bob-step2",   { ...pp, b: b1.private, A: mData.eve_public }),
        ]);
        setKAlice(a2.shared_secret); setKBob(b2.shared_secret);
      } else {
        // Honest exchange
        const [a2, b2] = await Promise.all([
          post("/pa11/alice-step2", { ...pp, a: a1.private, B: b1.public }),
          post("/pa11/bob-step2",   { ...pp, b: b1.private, A: a1.public }),
        ]);
        setKAlice(a2.shared_secret); setKBob(b2.shared_secret);
        setEvePub(null); setKAE(null); setKBE(null);
      }
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const match = kAlice && kBob && kAlice === kBob && !mitm;

  return (
    <div>
      <p className="sub">
        Two parties establish a shared secret over a public channel. Public parameters
        (p, q, g) are shared openly. Only g<sup>a</sup> and g<sup>b</sup> are exchanged —
        computing g<sup>ab</sup> from these alone requires solving the CDH problem.
      </p>

      {/* Controls */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
        <div>
          <label>Bit size (safe prime p ≈ 2<sup>bits</sup>)</label>
          <input
            type="range" min={16} max={64} step={8} value={bits}
            onChange={(e) => setBits(+e.target.value)}
            style={{ display: "block", width: 160 }}
          />
          <span className="sub" style={{ fontSize: 12 }}>bits = {bits}</span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end", gap: 6 }}>
          <button onClick={genParams} disabled={loading}>
            {loading ? "Generating…" : "Generate Params"}
          </button>
          <label className="eve-toggle" style={{ marginBottom: 0 }}>
            <input type="checkbox" checked={mitm} onChange={(e) => setMitm(e.target.checked)} />
            Enable Eve (MITM)
          </label>
        </div>
      </div>

      {/* Group params */}
      {params && (
        <div className="result-card" style={{ marginBottom: 14 }}>
          <div className="result-headline">
            <strong>Public Parameters</strong>
            <Badge ok label="p = 2q+1  (safe prime)" />
          </div>
          <Field label="p (modulus)" value={truncHex(params.p)} />
          <Field label="q (group order)" value={truncHex(params.q)} />
          <Field label="g (generator)" value={truncHex(params.g)} />
          <div className="note-box" style={{ marginTop: 8 }}>
            g<sup>q</sup> ≡ 1 (mod p) — generator of the prime-order-q subgroup of Z*<sub>p</sub>
          </div>
        </div>
      )}

      {/* Alice / Bob input */}
      {params && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <div style={{ flex: "1 1 200px" }}>
              <label>Alice's private exponent a (leave blank to randomise)</label>
              <input
                type="text" value={alicePriv}
                onChange={(e) => setAlicePriv(e.target.value)}
                placeholder="random"
                style={{ fontFamily: "monospace", width: "100%" }}
              />
            </div>
            <div style={{ flex: "1 1 200px" }}>
              <label>Bob's private exponent b (leave blank to randomise)</label>
              <input
                type="text" value={bobPriv}
                onChange={(e) => setBobPriv(e.target.value)}
                placeholder="random"
                style={{ fontFamily: "monospace", width: "100%" }}
              />
            </div>
          </div>
          <button onClick={doExchange} disabled={loading} style={{ marginTop: 10 }}>
            {loading ? "Exchanging…" : "Exchange →"}
          </button>
        </div>
      )}

      {err && <div className="err">{err}</div>}

      {/* MITM warning */}
      {mitm && kAlice && (
        <div className="mitm-banner">
          ⚠ MITM active — Eve intercepted the exchange. Alice and Bob each share a
          secret with Eve, not with each other. Basic DH is not authenticated!
        </div>
      )}

      {/* Result grid */}
      {alicePub && bobPub && (
        <div className="dh-grid">
          {/* Alice */}
          <div className="dh-party alice">
            <h3>Alice</h3>
            <Field label="private a" value={truncHex(alicePriv)} />
            <Field label="public A = g^a mod p" value={truncHex(alicePub)} />
            {kAlice && (
              <div className={`shared-secret-box${mitm ? " mismatch" : " match"}`}
                   style={{ marginTop: 10 }}>
                <div className="label">K = {mitm ? "B'^a" : "B^a"} mod p</div>
                <div className="value">{truncHex(kAlice)}</div>
              </div>
            )}
          </div>

          {/* Eve (only if MITM) */}
          {mitm && evePub && (
            <div className="dh-party eve">
              <h3>Eve (MITM)</h3>
              <Field label="public E = g^e mod p" value={truncHex(evePub)} />
              <div className={`shared-secret-box mismatch`} style={{ marginTop: 10 }}>
                <div className="label">K_AE (with Alice)</div>
                <div className="value">{truncHex(kAE)}</div>
              </div>
              <div className={`shared-secret-box mismatch`} style={{ marginTop: 6 }}>
                <div className="label">K_BE (with Bob)</div>
                <div className="value">{truncHex(kBE)}</div>
              </div>
              <p className="sub" style={{ marginTop: 8, fontSize: 12 }}>
                Eve can now decrypt all traffic between Alice and Bob.
              </p>
            </div>
          )}

          {/* Bob */}
          <div className="dh-party bob">
            <h3>Bob</h3>
            <Field label="private b" value={truncHex(bobPriv)} />
            <Field label="public B = g^b mod p" value={truncHex(bobPub)} />
            {kBob && (
              <div className={`shared-secret-box${mitm ? " mismatch" : " match"}`}
                   style={{ marginTop: 10 }}>
                <div className="label">K = {mitm ? "A'^b" : "A^b"} mod p</div>
                <div className="value">{truncHex(kBob)}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Shared secret confirmation */}
      {kAlice && kBob && !mitm && (
        <div className={`shared-secret-box ${match ? "match" : "mismatch"}`}
             style={{ marginTop: 14 }}>
          <div className="label">Shared Secret K = g<sup>ab</sup> mod p</div>
          <div className="value">{truncHex(kAlice)}</div>
          <div style={{ marginTop: 6 }}>
            <Badge ok={match} label={match ? "K_alice == K_bob ✓" : "MISMATCH ✗"} />
          </div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   TAB 2 — Step-by-Step Protocol Walkthrough
   ════════════════════════════════════════════════════════════════════════ */
function StepByStep() {
  const [bits, setBits] = useState(32);
  const [params, setParams] = useState(null);
  const [step, setStep] = useState(0);
  const [a1, setA1] = useState(null);
  const [b1, setB1] = useState(null);
  const [a2, setA2] = useState(null);
  const [b2, setB2] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const reset = () => { setParams(null); setStep(0); setA1(null); setB1(null); setA2(null); setB2(null); };

  const step0 = async () => {
    setLoading(true); setErr("");
    try {
      const d = await post("/pa11/params", { bits });
      setParams(d); setStep(1);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const step1 = async () => {
    setLoading(true); setErr("");
    try {
      const pp = { p: params.p, q: params.q, g: params.g };
      const [ad, bd] = await Promise.all([
        post("/pa11/alice-step1", pp), post("/pa11/bob-step1", pp),
      ]);
      setA1(ad); setB1(bd); setStep(2);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const step2 = async () => {
    setLoading(true); setErr("");
    try {
      const pp = { p: params.p, q: params.q, g: params.g };
      const [ad, bd] = await Promise.all([
        post("/pa11/alice-step2", { ...pp, a: a1.private, B: b1.public }),
        post("/pa11/bob-step2",   { ...pp, b: b1.private, A: a1.public }),
      ]);
      setA2(ad); setB2(bd); setStep(3);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  return (
    <div>
      <p className="sub">
        Walk through the Diffie-Hellman protocol one step at a time to see exactly
        what information is public vs. private at each stage.
      </p>

      {/* Step 0 */}
      <div className="step-card">
        <h4>Step 0 — Agree on public parameters</h4>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <div>
            <label>Bit size</label>
            <input type="range" min={16} max={64} step={8} value={bits}
              onChange={(e) => { setBits(+e.target.value); reset(); }}
              style={{ display: "block", width: 140 }} />
            <span className="sub" style={{ fontSize: 12 }}>bits = {bits}</span>
          </div>
          <button onClick={step0} disabled={loading || step > 0}>Generate safe prime p, q, g</button>
          {step > 0 && <Badge ok label="Done" />}
        </div>
        {params && (
          <div className="step-values" style={{ marginTop: 8 }}>
            <Field label="p" value={truncHex(params.p)} />
            <Field label="q" value={truncHex(params.q)} />
            <Field label="g" value={truncHex(params.g)} />
          </div>
        )}
      </div>

      {/* Step 1 */}
      {step >= 1 && (
        <div className="step-card">
          <h4>Step 1 — Each party samples a private exponent and computes a public key</h4>
          <button onClick={step1} disabled={loading || step > 1}>
            Alice samples a; Bob samples b
          </button>
          {step > 1 && <Badge ok label="Done" />}
          {a1 && b1 && (
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginTop: 10 }}>
              <div style={{ flex: "1 1 180px" }}>
                <p className="sub" style={{ fontSize: 12, color: "#a78bfa" }}>Alice</p>
                <Field label="private a (secret!)" value={truncHex(a1.private)} />
                <Field label="public A = g^a mod p" value={truncHex(a1.public)} />
              </div>
              <div style={{ flex: "1 1 180px" }}>
                <p className="sub" style={{ fontSize: 12, color: "#60a5fa" }}>Bob</p>
                <Field label="private b (secret!)" value={truncHex(b1.private)} />
                <Field label="public B = g^b mod p" value={truncHex(b1.public)} />
              </div>
            </div>
          )}
          {a1 && b1 && (
            <div className="note-box" style={{ marginTop: 8 }}>
              Alice sends A to Bob. Bob sends B to Alice. Eve sees A, B, g, p — but
              she cannot compute g<sup>ab</sup> from these (CDH assumption).
            </div>
          )}
        </div>
      )}

      {/* Step 2 */}
      {step >= 2 && (
        <div className="step-card">
          <h4>Step 2 — Each party computes the shared secret</h4>
          <button onClick={step2} disabled={loading || step > 2}>
            Alice: K = B^a mod p &nbsp;|&nbsp; Bob: K = A^b mod p
          </button>
          {step > 2 && <Badge ok label="Done" />}
          {a2 && b2 && (
            <div style={{ marginTop: 10 }}>
              <Field label="K (Alice computed B^a mod p)" value={truncHex(a2.shared_secret)} />
              <Field label="K (Bob computed A^b mod p)"   value={truncHex(b2.shared_secret)} />
              <div className={`shared-secret-box ${a2.shared_secret === b2.shared_secret ? "match" : "mismatch"}`}
                   style={{ marginTop: 10 }}>
                <div className="label">K_alice == K_bob?</div>
                <div className="value">{a2.shared_secret === b2.shared_secret ? "✓ Match — K = g^ab" : "✗ Mismatch"}</div>
              </div>
            </div>
          )}
        </div>
      )}

      {err && <div className="err">{err}</div>}

      {step > 0 && (
        <button style={{ marginTop: 10, background: "#334155", color: "#94a3b8" }}
                onClick={reset}>Reset</button>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   TAB 3 — CDH Hardness Demo (toy brute-force)
   ════════════════════════════════════════════════════════════════════════ */
function CDHDemo() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const runDemo = async () => {
    setLoading(true); setErr(""); setResult(null);
    try {
      // Generate tiny 16-bit params, do exchange, show public keys only
      const pd = await post("/pa11/params", { bits: 16 });
      const pp = { p: pd.p, q: pd.q, g: pd.g };
      const [ad, bd] = await Promise.all([
        post("/pa11/alice-step1", pp), post("/pa11/bob-step1", pp),
      ]);
      // Now simulate brute-force DL (done server-side via exchange metadata)
      const xd = await post("/pa11/exchange", { ...pp });
      setResult({ params: pd, alice: ad, bob: bd, exchange: xd });
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  return (
    <div>
      <p className="sub">
        The security of DH rests on the <strong>Computational Diffie-Hellman (CDH)</strong>{" "}
        problem: given g<sup>a</sup> mod p and g<sup>b</sup> mod p, computing g<sup>ab</sup>{" "}
        requires knowing either a or b. For small parameters (q ≈ 2<sup>16</sup>) an attacker
        can brute-force the discrete logarithm. For q ≈ 2<sup>256</sup> it is infeasible.
      </p>

      <button onClick={runDemo} disabled={loading}>
        {loading ? "Running…" : "Run CDH Demo (16-bit toy params)"}
      </button>

      {err && <div className="err">{err}</div>}

      {result && (
        <div className="result-card">
          <div className="result-headline">
            <strong>Toy DH Parameters</strong>
            <Badge ok label="16-bit safe prime" />
          </div>
          <Field label="p (modulus)" value={result.params.p} />
          <Field label="q (group order)" value={result.params.q} />
          <Field label="g (generator)" value={result.params.g} />

          <div style={{ marginTop: 12, display: "flex", gap: 12, flexWrap: "wrap" }}>
            <div style={{ flex: "1 1 160px" }}>
              <p className="sub" style={{ fontSize: 12, color: "#a78bfa" }}>Alice (public only)</p>
              <Field label="A = g^a mod p" value={result.alice.public} />
            </div>
            <div style={{ flex: "1 1 160px" }}>
              <p className="sub" style={{ fontSize: 12, color: "#60a5fa" }}>Bob (public only)</p>
              <Field label="B = g^b mod p" value={result.bob.public} />
            </div>
          </div>

          <div className="note-box" style={{ marginTop: 12 }}>
            <strong>CDH Challenge:</strong> Given g={result.params.g}, A={result.alice.public},
            B={result.bob.public} and p={result.params.p} — can you compute g<sup>ab</sup> mod p
            without knowing a or b?
            <br /><br />
            For 16-bit q, brute-force runs in milliseconds (at most q iterations).
            For 256-bit q this would take longer than the age of the universe.
          </div>

          <div className={`shared-secret-box match`} style={{ marginTop: 12 }}>
            <div className="label">Shared Secret K = g<sup>ab</sup> mod p (honest exchange)</div>
            <div className="value">{result.exchange.shared_secret}</div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   Root component
   ════════════════════════════════════════════════════════════════════════ */
const TABS = [
  { key: "exchange", label: "Live Exchange" },
  { key: "stepbystep", label: "Step by Step" },
  { key: "cdh", label: "CDH Hardness" },
];

export default function PA11Panel() {
  const [tab, setTab] = useState("exchange");

  return (
    <div>
      <h2 style={{ marginBottom: 4, color: "#e2e8f0" }}>PA#11 — Diffie-Hellman Key Exchange</h2>
      <p className="sub">
        Establish a shared secret over a completely public (eavesdropped) channel using the
        hardness of the CDH problem in the prime-order-q subgroup of Z*<sub>p</sub>.
      </p>

      <div className="pa-tabs">
        {TABS.map((t) => (
          <button key={t.key} className={`pa-tab${tab === t.key ? " active" : ""}`}
                  onClick={() => setTab(t.key)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "exchange"  && <LiveExchange />}
      {tab === "stepbystep" && <StepByStep />}
      {tab === "cdh"       && <CDHDemo />}
    </div>
  );
}
