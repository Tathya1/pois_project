import { useState, useEffect, useRef, useCallback } from "react";
import "./PA4Panel.css";

/* ══════════════════════════════════════════════════════════════
   BACKEND API HELPERS (Python does all crypto)
   ══════════════════════════════════════════════════════════════ */
const API = "http://localhost:5000/pa4";

async function apiPost(path, payload) {
  const res = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data?.error || "Request failed");
  }
  return data;
}

async function fetchTrace(mode, key, message) {
  const data = await apiPost("/trace", { mode, key, message });
  const blocks = (data.blocks || []).map((b) => {
    if (mode === "CBC") {
      return { plain: b.plain, prev: b.prev, xorVal: b.xor, cipher: b.cipher };
    }
    if (mode === "OFB") {
      return { plain: b.plain, stateIn: b.stateIn, ks: b.keystream, cipher: b.cipher };
    }
    return { plain: b.plain, counter: b.counter, ks: b.keystream, cipher: b.cipher };
  });
  return { ...data, blocks };
}

async function fetchFlipBit(mode, key, message, blockIndex, bitIndex) {
  const data = await apiPost("/flip-bit", { mode, key, message, blockIndex, bitIndex });
  return {
    corrupted: data.corruptedPlaintextBlocks,
    origBlocks: data.originalPlainBlocks,
    recvBlocks: data.corruptedPlainBlocks,
    ciphertext: data.ciphertext,
    tampered: data.tamperedCiphertext,
  };
}

async function fetchCbcAttack(key, messageA, messageB) {
  const data = await apiPost("/attack/cbc-iv-reuse", { key, messageA, messageB });
  return {
    iv: data.iv,
    pA: data.plainBlocksA,
    pB: data.plainBlocksB,
    cA: data.cipherBlocksA,
    cB: data.cipherBlocksB,
    matchPlain: data.matchingPlainBlocks,
    matchCipher: data.matchingCipherBlocks,
  };
}

async function fetchOfbAttack(key, messageA, messageB) {
  const data = await apiPost("/attack/ofb-keystream-reuse", { key, messageA, messageB });
  return {
    iv: data.iv,
    cA: data.cipherA,
    cB: data.cipherB,
    cxor: data.cipherXor,
    pxor: data.plainXor,
    match: data.xorsMatch,
  };
}

async function fetchTests(mode, key) {
  const data = await apiPost("/tests", { mode, key });
  return data.results || [];
}

/* ══════════════════════════════════════════════════════════════
   TINY COMPONENTS
   ══════════════════════════════════════════════════════════════ */

function HexBox({ label, value, type = "neutral", visible = true, corrupted = false }) {
  const classes = [
    "pa4-hex-box",
    `pa4-hex-${type}`,
    visible ? "is-visible" : "is-hidden",
  ];
  if (corrupted) classes.push("pa4-hex-corrupt");
  return (
    <div className="pa4-hex">
      <div className="pa4-hex-label">{label}</div>
      <div className={classes.join(" ")}>
        {value || "—"}
      </div>
    </div>
  );
}

function Arrow({ label, sub, visible = true }) {
  return (
    <div className={`pa4-arrow ${visible ? "" : "is-hidden"}`}>
      <div>↓</div>
      {label && <div className="pa4-arrow-label">{label}</div>}
      {sub && <div className="pa4-arrow-sub">{sub}</div>}
      <div>↓</div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   ANIMATION SECTION
   ══════════════════════════════════════════════════════════════ */
function AnimSection({ mode, keyStr, message }) {
  const [trace,    setTrace]   = useState(null);
  const [step,     setStep]    = useState(0);
  const [playing,  setPlaying] = useState(false);
  const [error,    setError]   = useState("");
  const timerRef = useRef(null);

  // Steps: CBC/OFB = 3 sub-steps per block × 3 blocks = 9; CTR = 3 (all parallel)
  const maxStep = mode === "CTR" ? 3 : 9;

  const refresh = useCallback(async () => {
    try {
      setError("");
      setTrace(null);
      const data = await fetchTrace(mode, keyStr, message);
      setTrace(data);
      setStep(0);
      setPlaying(false);
    } catch (e) {
      setError(e.message);
    }
  }, [mode, keyStr, message]);

  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    if (!playing) { clearInterval(timerRef.current); return; }
    timerRef.current = setInterval(() => {
      setStep(s => { if(s>=maxStep){setPlaying(false);return s;} return s+1; });
    }, 700);
    return () => clearInterval(timerRef.current);
  }, [playing, maxStep]);

  // vis(blockIdx, subStep) → is this element visible yet?
  // CBC/OFB: sequential — block i starts at step i*3+1
  // CTR: parallel — all blocks share same sub-step clock
  const vis = (bi, sub) => mode === "CTR" ? step > sub : step >= bi*3 + sub + 1;

  if (error) return <div className="pa4-error">{error}</div>;
  if (!trace) return <div className="pa4-muted">Computing…</div>;
  const { blocks } = trace;

  return (
    <div>
      {/* IV / nonce header */}
      <div className="pa4-meta">
        {trace.iv ? `IV = ${trace.iv}` : `nonce = ${trace.nonce}`}
      </div>

      {/* Block flow */}
      <div className="pa4-block-flow">
        {blocks.map((b, bi) => (
          <div key={bi} className="pa4-block-wrap">
            {/* Chain arrow for CBC (C_{i-1} feeds into XOR of block i) */}
            {mode === "CBC" && bi > 0 && (
              <div className={`pa4-chain-arrow ${vis(bi, 0) ? "active" : ""}`}>→</div>
            )}
            {/* OFB chaining arrow (state flows forward) */}
            {mode === "OFB" && bi > 0 && (
              <div className={`pa4-chain-arrow ${vis(bi, 0) ? "active" : ""}`}>→</div>
            )}

            <div className="pa4-block-card">
              <div className="pa4-block-header">
                Block {bi} {mode === "CTR" ? "⟦∥⟧" : ""}
              </div>

              {mode === "CBC" && (<>
                <HexBox label={`P[${bi}]`}          value={b.plain}  type="plain"  visible={vis(bi,0)} />
                <Arrow  label={`⊕ ${bi===0?"IV":`C[${bi-1}]`}`} visible={vis(bi,1)} />
                <HexBox label="after XOR"            value={b.xorVal} type="xor"   visible={vis(bi,1)} />
                <Arrow  label="E_k"                  visible={vis(bi,2)} />
                <HexBox label={`C[${bi}]`}           value={b.cipher} type="cipher" visible={vis(bi,2)} />
              </>)}

              {mode === "OFB" && (<>
                <HexBox label={bi===0?"IV":`KS[${bi-1}]`} value={b.stateIn} type="iv"   visible={vis(bi,0)} />
                <Arrow  label="E_k"                        visible={vis(bi,1)} />
                <HexBox label={`KS[${bi}]`}                value={b.ks}      type="ks"    visible={vis(bi,1)} />
                <Arrow  label={`⊕ P[${bi}]`}               visible={vis(bi,2)} />
                <HexBox label={`C[${bi}]`}                 value={b.cipher}  type="cipher" visible={vis(bi,2)} />
              </>)}

              {mode === "CTR" && (<>
                <HexBox label={`CTR[${bi}] = nonce+${bi}`} value={b.counter} type="counter" visible={vis(bi,0)} />
                <Arrow  label="E_k"                         visible={vis(bi,1)} />
                <HexBox label={`KS[${bi}]`}                 value={b.ks}     type="ks"      visible={vis(bi,1)} />
                <Arrow  label={`⊕ P[${bi}]`}                visible={vis(bi,2)} />
                <HexBox label={`C[${bi}]`}                  value={b.cipher} type="cipher"  visible={vis(bi,2)} />
              </>)}
            </div>
          </div>
        ))}
      </div>

      {/* Playback controls */}
      <div className="pa4-controls">
        <button className="pa4-button" onClick={refresh}>↺ New</button>
        <button
          className={`pa4-button ${playing ? "is-active" : ""}`}
          onClick={() => setPlaying(p => !p)}
        >{playing ? "⏸ Pause" : "▶ Play"}</button>
        <button className="pa4-button" onClick={() => setStep(s=>Math.max(0,s-1))}>◀ Step</button>
        <button className="pa4-button" onClick={() => setStep(s=>Math.min(maxStep,s+1))}>Step ▶</button>
        <button className="pa4-button" onClick={() => { setStep(0); setPlaying(false); }}>⏮ Reset</button>
        <span className="pa4-step-counter">step {step} / {maxStep}</span>
      </div>

      {/* Mode hint */}
      <div className={`pa4-info pa4-info--${mode.toLowerCase()}`}>
        {mode === "CBC" && "🔗 CBC — chaining: C[i-1] XORed into P[i] before encryption. Strictly sequential."}
        {mode === "OFB" && "🔑 OFB — keystream is independent of plaintext; can be precomputed before M is known."}
        {mode === "CTR" && "⚡ CTR — counters are independent: all blocks can encrypt in parallel simultaneously."}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   FLIP-BIT SECTION
   ══════════════════════════════════════════════════════════════ */
function correctPattern(mode, flipped, corrupted) {
  if (mode === "CBC") {
    const exp = [flipped, flipped+1].filter(i=>i<3).sort();
    return JSON.stringify([...corrupted].sort()) === JSON.stringify(exp);
  }
  return corrupted.length===1 && corrupted[0]===flipped;
}

function FlipSection({ mode, keyStr, message }) {
  const [result,   setResult]   = useState(null);
  const [selected, setSelected] = useState(null);
  const [error,    setError]    = useState("");

  const runFlip = async (bi) => {
    try {
      setError("");
      const r = await fetchFlipBit(mode, keyStr, message, bi, 0);
      setResult({ ...r, flippedBlock: bi });
      setSelected(bi);
    } catch(e) { setError(e.message); }
  };

  const expected = { CBC:"C[i] corrupt → P[i] garbled + P[i+1] fully corrupted", OFB:"Only P[i] flipped (same bit)", CTR:"Only P[i] flipped (same bit)" }[mode];

  return (
    <div>
      <div className="pa4-hint">
        Click a ciphertext block to flip bit 0. Observe which plaintext blocks are corrupted.
      </div>
      <div className="pa4-row">
        {[0,1,2].map(bi => (
          <button
            key={bi}
            className={`pa4-button ${selected===bi ? "is-active" : ""}`}
            onClick={() => runFlip(bi)}
          >✎ Flip C[{bi}] bit 0</button>
        ))}
      </div>
      {error && <div className="pa4-error">{error}</div>}

      {result && (<>
        <div className="pa4-hint">
          Expected: <span className="pa4-hint-strong">{expected}</span>
        </div>
        <div className="pa4-card-row">
          {[0,1,2].map(bi => {
            const isCorrupted = result.corrupted.includes(bi);
            const isFlipped   = bi === result.flippedBlock;
            return (
              <div key={bi} className={`pa4-block-card ${isCorrupted ? "is-corrupt" : ""} ${isFlipped ? "is-flipped" : ""}`}>
                <div className="pa4-block-header">
                  Block {bi} {isFlipped?"✎":isCorrupted?"✗ corrupt":"✓ intact"}
                </div>
                <HexBox label="original P[i]"      value={result.origBlocks[bi]} type="plain"  visible={true} />
                <HexBox label="decrypted (tampered)" value={result.recvBlocks[bi]} type={isCorrupted?"corrupt":"plain"} visible={true} corrupted={isCorrupted} />
              </div>
            );
          })}
        </div>
        <div className={`pa4-status ${correctPattern(mode,result.flippedBlock,result.corrupted) ? "is-success" : "is-error"}`}>
          {correctPattern(mode,result.flippedBlock,result.corrupted) ? "✅" : "⚠️"} Corrupted blocks: [{result.corrupted.join(", ") || "none"}] — {correctPattern(mode,result.flippedBlock,result.corrupted) ? "pattern correct" : "unexpected pattern"}
        </div>
      </>)}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   ATTACK DEMOS SECTION
   ══════════════════════════════════════════════════════════════ */
function AttackSection({ keyStr }) {
  const [mA,  setMA]  = useState("AAAAAAAABBBBBBBB");
  const [mB,  setMB]  = useState("AAAAAAAACCCCCCCC");
  const [cbc, setCbc] = useState(null);
  const [ofb, setOfb] = useState(null);
  const [err, setErr] = useState("");

  const run = async () => {
    try {
      setErr("");
      const [cbcRes, ofbRes] = await Promise.all([
        fetchCbcAttack(keyStr, mA, mB),
        fetchOfbAttack(keyStr, mA, mB),
      ]);
      setCbc(cbcRes);
      setOfb(ofbRes);
    } catch(e) { setErr(e.message); }
  };

  return (
    <div>
      <div className="pa4-row">
        <label className="pa4-field">
          <span>Message A</span>
          <input value={mA} onChange={e=>setMA(e.target.value)} />
        </label>
        <label className="pa4-field">
          <span>Message B</span>
          <input value={mB} onChange={e=>setMB(e.target.value)} />
        </label>
        <button className="pa4-button" onClick={run}>▶ Run attacks</button>
      </div>
      {err && <div className="pa4-error">{err}</div>}

      {cbc && (
        <div className="pa4-attack-section">
          <div className="pa4-attack-title">CBC IV-REUSE ATTACK</div>
          <div className="pa4-hint">
            Both messages encrypted with the <strong className="pa4-hint-strong">same IV = {cbc.iv}</strong>. Equal plaintext blocks under same chaining context → equal ciphertext blocks (information leak).
          </div>
          <div className="pa4-attack-grid">
            {cbc.cA.map((cHex,i) => {
              const isMatchC = cbc.matchCipher.includes(i);
              const isMatchP = cbc.matchPlain.includes(i);
              return (
                <div key={i} className={`pa4-block-card ${isMatchC ? "is-corrupt" : ""}`}>
                  <div className="pa4-block-header">Block {i}</div>
                  <HexBox label={`PA[${i}]`} value={cbc.pA[i]} type={isMatchP?"xor":"plain"} visible={true} />
                  <HexBox label={`PB[${i}]`} value={cbc.pB[i]} type={isMatchP?"xor":"plain"} visible={true} />
                  <div className="pa4-spacer" />
                  <HexBox label={`CA[${i}]`} value={cHex}       type="cipher"  visible={true} />
                  <HexBox label={`CB[${i}]`} value={cbc.cB[i]}  type="cipher"  visible={true} corrupted={isMatchC} />
                  {isMatchC && (
                    <div className="pa4-alert">⚠ CA[{i}] = CB[{i}] → leak!</div>
                  )}
                </div>
              );
            })}
          </div>
          <div className={`pa4-status ${cbc.matchCipher.length > 0 ? "is-error" : "is-success"}`}>
            {cbc.matchCipher.length>0
              ? `🚨 Ciphertext blocks [${cbc.matchCipher.join(", ")}] match → confirms equal plaintext blocks`
              : "✅ No matching ciphertext blocks (plaintext blocks all differ)"}
          </div>
        </div>
      )}

      {ofb && (
        <div className="pa4-attack-section">
          <div className="pa4-attack-title">OFB KEYSTREAM-REUSE ATTACK</div>
          <div className="pa4-hint">
            Same IV → same keystream KS.
            <span className="pa4-hint-strong"> C₁ ⊕ C₂ = (M₁⊕KS) ⊕ (M₂⊕KS) = M₁ ⊕ M₂</span> — keystream cancels out.
          </div>
          <div className="pa4-attack-xor">
            <div>
              <HexBox label="C₁ ⊕ C₂" value={ofb.cxor} type="ks"  visible={true} />
            </div>
            <div className={`pa4-xor-symbol ${ofb.match ? "is-success" : "is-error"}`}>
              {ofb.match ? "=" : "≠"}
            </div>
            <div>
              <HexBox label="M₁ ⊕ M₂" value={ofb.pxor} type="xor" visible={true} />
            </div>
          </div>
          <div className={`pa4-status ${ofb.match ? "is-error" : "is-success"}`}>
            {ofb.match
              ? "🚨 XORs match! Keystream eliminated — attacker recovers M₁ ⊕ M₂ directly"
              : "❌ Mismatch (unexpected — check implementation)"}
          </div>
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   CORRECTNESS TEST SECTION
   ══════════════════════════════════════════════════════════════ */
function TestSection({ mode, keyStr }) {
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    try {
      setError("");
      const data = await fetchTests(mode, keyStr);
      setResults(data);
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div>
      <div className="pa4-hint">
        Verifies Dec(k, Enc(k, M)) = M for three message lengths.
      </div>
      <button className="pa4-button" onClick={run}>▶ Run correctness tests</button>
      {error && <div className="pa4-error">{error}</div>}
      {results && (
        <div className="pa4-test-list">
          {results.map((r,i) => (
            <div key={i} className={`pa4-test-row ${r.pass ? "is-success" : "is-error"}`}>
              <div className="pa4-test-title">
                {r.pass?"✅":"❌"} {r.label}
              </div>
              {r.error && <div className="pa4-error-text">Error: {r.error}</div>}
              {!r.error && <>
                <div className="pa4-muted">original: <span className="pa4-value-accent">{r.orig}</span></div>
                <div className="pa4-muted">decrypted: <span className={r.pass ? "pa4-value-success" : "pa4-value-error"}>{r.dec}</span></div>
              </>}
            </div>
          ))}
          <div className={`pa4-status ${results.every(r=>r.pass) ? "is-success" : "is-error"}`}>
            {results.every(r=>r.pass)
              ? `✅ All ${results.length} tests passed for ${mode} mode`
              : `❌ Some tests failed — check key/message inputs`}
          </div>
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   MAIN PANEL
   ══════════════════════════════════════════════════════════════ */
export default function PA4Panel() {
  const [mode,    setMode]    = useState("CBC");
  const [keyStr,  setKeyStr]  = useState("1a2b3c4d");
  const [message, setMessage] = useState("message0message1message2");

  const [encResult, setEncResult] = useState(null);
  const [decResult, setDecResult] = useState(null);
  const [error,     setError]     = useState("");

  const onTabChange = m => {
    setMode(m);
    setEncResult(null);
    setDecResult(null);
    setError("");
  };

  const doEncrypt = async () => {
    try {
      setError("");
      const e = await apiPost("/encrypt", { mode, key: keyStr, message });
      setEncResult({
        mode: e.mode,
        ciphertext: e.ciphertext,
        iv: e.iv,
        nonce: e.nonce,
      });
      setDecResult(null);
    } catch(e) { setError(e.message); }
  };

  const doDecrypt = async () => {
    if (!encResult) { setError("Encrypt first."); return; }
    try {
      setError("");
      const data = await apiPost("/decrypt", {
        mode,
        key: keyStr,
        ciphertext: encResult.ciphertext,
        iv: encResult.iv,
        nonce: encResult.nonce,
      });
      setDecResult({ text: data.message, hex: data.messageHex });
    } catch(e) { setError(e.message); }
  };

  return (
    <div className="panel pa4-panel">
      <div>
        <h3>PA#4 — Block Cipher Modes</h3>
        <p className="pa4-subtitle">CBC · OFB · CTR · Feistel-PRP(6-round) · 8-byte blocks · PKCS#7</p>
      </div>

      <div className="pa4-tabs">
        {["CBC","OFB","CTR"].map(m => (
          <button
            key={m}
            className={`pa4-tab ${m===mode?"active":""}`}
            onClick={() => onTabChange(m)}
          >{m}</button>
        ))}
      </div>

      <div className="pa4-row">
        <label className="pa4-field">
          <span>Key (hex or int)</span>
          <input value={keyStr} onChange={e=>setKeyStr(e.target.value)} />
        </label>
        <label className="pa4-field">
          <span>Message (UTF-8)</span>
          <input value={message} onChange={e=>setMessage(e.target.value)} />
        </label>
        <button className="pa4-button" onClick={doEncrypt}>Encrypt</button>
        <button className="pa4-button" onClick={doDecrypt}>Decrypt</button>
      </div>

      {error && <div className="pa4-error">{error}</div>}

      {encResult && (
        <div className="pa4-output">
          <div className="pa4-output-row"><span className="pa4-output-key">mode</span><span className="pa4-output-val">{encResult.mode}</span></div>
          {encResult.iv    && <div className="pa4-output-row"><span className="pa4-output-key">iv</span>   <span className="pa4-output-val pa4-value-accent">{encResult.iv}</span></div>}
          {encResult.nonce && <div className="pa4-output-row"><span className="pa4-output-key">nonce</span><span className="pa4-output-val pa4-value-accent">{encResult.nonce}</span></div>}
          <div className="pa4-output-row"><span className="pa4-output-key">ciphertext</span><span className="pa4-output-val pa4-value-success">{encResult.ciphertext}</span></div>
        </div>
      )}

      {decResult && (
        <div className="pa4-output pa4-output-success">
          <div className="pa4-output-row"><span className="pa4-output-key">plaintext</span><span className="pa4-output-val pa4-value-success">{decResult.text}</span></div>
          <div className="pa4-output-row"><span className="pa4-output-key">hex</span>      <span className="pa4-output-val pa4-value-accent">{decResult.hex}</span></div>
        </div>
      )}

      <div className="pa4-section">
        <div className="pa4-section-title">{mode} Encryption Flow — 3 Blocks</div>
        <AnimSection key={mode} mode={mode} keyStr={keyStr} message={message} />
      </div>

      <div className="pa4-section">
        <div className="pa4-section-title">Bit-Flip Error Propagation</div>
        <FlipSection key={`flip-${mode}`} mode={mode} keyStr={keyStr} message={message} />
      </div>

      <div className="pa4-section">
        <div className="pa4-section-title">Attack Demonstrations</div>
        <AttackSection keyStr={keyStr} />
      </div>

      <div className="pa4-section">
        <div className="pa4-section-title">Correctness Tests — Dec(k, Enc(k, M)) = M</div>
        <TestSection key={mode} mode={mode} keyStr={keyStr} />
      </div>
    </div>
  );
}