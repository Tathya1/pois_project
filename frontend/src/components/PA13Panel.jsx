import { useState } from "react";
import "./PA13Panel.css";

const API = "http://localhost:5000";

/* ─── tiny helpers ─────────────────────────────────────────────── */
const Badge = ({ ok, label }) => (
  <span className={`badge ${ok ? "badge-ok" : "badge-fail"}`}>{label}</span>
);

const Field = ({ label, value, mono = true }) => (
  <div className="kv-row">
    <span className="kv-label">{label}</span>
    <span className={mono ? "kv-value mono" : "kv-value"}>{value}</span>
  </div>
);

/* ─── pre-loaded examples ───────────────────────────────────────── */
const EXAMPLES = [
  { label: "2 (prime)",        n: "2" },
  { label: "17 (prime)",       n: "17" },
  { label: "561 (Carmichael)", n: "561" },
  { label: "1729 (Carmichael)",n: "1729" },
  { label: "2147483647 (Mersenne prime)", n: "2147483647" },
  { label: "1000000007 (prime)",          n: "1000000007" },
];

export default function PA13Panel() {
  /* ── Test tab ── */
  const [n,       setN]       = useState("561");
  const [rounds,  setRounds]  = useState(40);
  const [testRes, setTestRes] = useState(null);
  const [testErr, setTestErr] = useState("");
  const [testing, setTesting] = useState(false);

  /* ── Gen tab ── */
  const [bits,   setBits]   = useState(64);
  const [genRes, setGenRes] = useState(null);
  const [genErr, setGenErr] = useState("");
  const [genBusy, setGenBusy] = useState(false);

  /* ── Benchmark tab ── */
  const [benchTrials, setBenchTrials] = useState(3);
  const [benchRes, setBenchRes] = useState(null);
  const [benchErr, setBenchErr] = useState("");
  const [benchBusy, setBenchBusy] = useState(false);

  /* ── Carmichael tab ── */
  const [carmRes, setCarmRes] = useState(null);
  const [carmErr, setCarmErr] = useState("");

  /* ── active tab ── */
  const [tab, setTab] = useState("test");

  /* ────────────────────── API calls ──────────────────────────── */
  const runTest = async (nOverride) => {
    setTesting(true);
    setTestErr("");
    setTestRes(null);
    try {
      const res  = await fetch(`${API}/pa13/test`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ n: nOverride ?? n, rounds }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setTestRes(data);
    } catch (e) {
      setTestErr(e.message);
    } finally {
      setTesting(false);
    }
  };

  const runGen = async () => {
    setGenBusy(true);
    setGenErr("");
    setGenRes(null);
    try {
      const res  = await fetch(`${API}/pa13/gen`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ bits }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setGenRes(data);
    } catch (e) {
      setGenErr(e.message);
    } finally {
      setGenBusy(false);
    }
  };

  const runCarmichael = async () => {
    setCarmErr("");
    setCarmRes(null);
    try {
      const res  = await fetch(`${API}/pa13/carmichael-demo`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setCarmRes(data);
    } catch (e) {
      setCarmErr(e.message);
    }
  };

  const runBenchmark = async () => {
    setBenchBusy(true);
    setBenchErr("");
    setBenchRes(null);
    try {
      const res = await fetch(`${API}/pa13/benchmark`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ trials: benchTrials }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setBenchRes(data);
    } catch (e) {
      setBenchErr(e.message);
    } finally {
      setBenchBusy(false);
    }
  };

  /* ────────────────────── Render ──────────────────────────────── */
  return (
    <div className="panel">
      <h3>PA #13 — Miller-Rabin Primality Testing</h3>

      {/* ── Tab switcher ── */}
      <div className="pa-tabs">
  {["test", "gen", "carmichael", "benchmark"].map((t) => (
          <button
            key={t}
            className={`pa-tab ${tab === t ? "active" : ""}`}
            onClick={() => setTab(t)}
          >
            {t === "test"       ? "Primality Tester"
           : t === "gen"        ? "Prime Generator"
           : t === "carmichael" ? "Carmichael Demo"
           :                      "Benchmark"}
          </button>
        ))}
      </div>

      {/* ════════════════ TAB: PRIMALITY TEST ════════════════ */}
      {tab === "test" && (
        <div>
          <p className="sub">
            Tests whether a number is (probably) prime using the Miller-Rabin
            probabilistic test. Error probability ≤ 4<sup>-k</sup>.
          </p>

          {/* Pre-loaded examples */}
          <div className="example-row">
            {EXAMPLES.map((ex) => (
              <button
                key={ex.n}
                className="example-btn"
                onClick={() => { setN(ex.n); runTest(ex.n); }}
              >
                {ex.label}
              </button>
            ))}
          </div>

          <label>Integer n</label>
          <input value={n} onChange={(e) => setN(e.target.value)} placeholder="e.g. 561" />

          <label>Rounds k = {rounds}  (error ≤ 4<sup>-{rounds}</sup> ≈ 10<sup>-{Math.floor(rounds * 0.6)}</sup>)</label>
          <input
            type="range" min="1" max="100" value={rounds}
            onChange={(e) => setRounds(Number(e.target.value))}
          />

          <button onClick={() => runTest()} disabled={testing}>
            {testing ? "Testing…" : "Run Miller-Rabin"}
          </button>

          {testErr && <p className="err">{testErr}</p>}

          {testRes && (
            <div className="result-card">
              <div className="result-headline">
                <span className="mono big">{testRes.n}</span>
                <Badge
                  ok={testRes.probably_prime}
                  label={testRes.result}
                />
              </div>

              <Field label="Rounds"       value={testRes.rounds} mono={false} />
              <Field label="Time"         value={`${testRes.time_ms} ms`} mono={false} />

              {testRes.fermat_pass !== null && (
                <div className="kv-row">
                  <span className="kv-label">Fermat test (base 2)</span>
                  <Badge ok={testRes.fermat_pass} label={testRes.fermat_pass ? "PASS" : "FAIL"} />
                </div>
              )}

              {testRes.note && (
                <div className="note-box">
                  <span className="note-icon">⚠️</span> {testRes.note}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ════════════════ TAB: PRIME GENERATOR ════════════════ */}
      {tab === "gen" && (
        <div>
          <p className="sub">
            Generates a random probable prime of the requested bit length.
            By the Prime Number Theorem, ~{Math.ceil(bits * 0.693)} candidates
            are tested on average before finding one.
          </p>

          <label>Bit length: {bits}</label>
          <input
            type="range" min="8" max="512" value={bits}
            onChange={(e) => setBits(Number(e.target.value))}
          />

          <button onClick={runGen} disabled={genBusy}>
            {genBusy ? "Generating…" : `Generate ${bits}-bit Prime`}
          </button>

          {genErr && <p className="err">{genErr}</p>}

          {genRes && (
            <div className="result-card">
              <Field label="Bit length"     value={genRes.bits}      mono={false} />
              <Field label="Time"           value={`${genRes.time_ms} ms`} mono={false} />
              <Field label="Rounds"         value={genRes.rounds} mono={false} />
              <Field label="Verified"       value={genRes.verified ? "Yes" : "No"} mono={false} />
              <label className="small-label">Decimal</label>
              <div className="output-box">{genRes.prime}</div>
              <label className="small-label">Hex</label>
              <div className="output-box">{genRes.prime_hex}</div>
            </div>
          )}
        </div>
      )}

      {/* ════════════════ TAB: BENCHMARK ════════════════ */}
      {tab === "benchmark" && (
        <div>
          <p className="sub">
            Measures the average number of random candidates sampled before
            finding a prime. This is compared to the Prime Number Theorem
            prediction of ln(n) candidates. Larger sizes may take longer.
          </p>

          <label>Trials per bit-size: {benchTrials}</label>
          <input
            type="range" min="1" max="5" value={benchTrials}
            onChange={(e) => setBenchTrials(Number(e.target.value))}
          />

          <button onClick={runBenchmark} disabled={benchBusy}>
            {benchBusy ? "Benchmarking…" : "Run Benchmark"}
          </button>

          {benchErr && <p className="err">{benchErr}</p>}

          {benchRes && (
            <div className="result-card">
              <Field label="Rounds" value={benchRes.rounds} mono={false} />
              <Field label="Trials" value={benchRes.trials} mono={false} />

              <div className="bench-table">
                <div className="bench-header">
                  <span>Bits</span>
                  <span>Avg candidates</span>
                  <span>ln(n)</span>
                  <span>Ratio</span>
                </div>
                {benchRes.results.map((row) => (
                  <div className="bench-row" key={row.bits}>
                    <span>{row.bits}</span>
                    <span>{row.avg_candidates}</span>
                    <span>{row.theoretical_ln_n}</span>
                    <span>{row.ratio}</span>
                  </div>
                ))}
              </div>
              <div className="bench-note">Ratio = avg / ln(n)</div>
            </div>
          )}
        </div>
      )}

      {/* ════════════════ TAB: CARMICHAEL DEMO ════════════════ */}
      {tab === "carmichael" && (
        <div>
          <p className="sub">
            561 = 3 × 11 × 17 is the smallest <em>Carmichael number</em>.
            It passes the naive Fermat primality test (2<sup>560</sup> ≡ 1 mod 561)
            but is correctly rejected by Miller-Rabin.
          </p>

          <button onClick={runCarmichael}>Run Demo (n = 561)</button>

          {carmErr && <p className="err">{carmErr}</p>}

          {carmRes && (
            <div className="result-card">
              <div className="result-headline">
                <span className="mono big">561</span>
                <Badge ok={false} label="COMPOSITE" />
              </div>

              <Field label="Factorisation"      value={carmRes.factorization}            mono={false} />
              <Field label="Actually prime?"    value={carmRes.is_actually_prime ? "Yes" : "No"} mono={false} />

              <div className="kv-row">
                <span className="kv-label">Fermat test (base 2)</span>
                <Badge ok={carmRes.fermat_test_base2}
                       label={carmRes.fermat_test_base2 ? "PASS (fooled!)" : "FAIL"} />
              </div>

              <div className="kv-row">
                <span className="kv-label">Miller-Rabin result</span>
                <Badge ok={carmRes.correctly_rejected}
                       label={carmRes.miller_rabin_result} />
              </div>

              <div className="note-box">{carmRes.explanation}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
