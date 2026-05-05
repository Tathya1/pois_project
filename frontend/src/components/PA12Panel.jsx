import { useState } from "react";
import "./PA13Panel.css";
import "./PA12Panel.css";

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

const trunc = (s, n = 48) => {
  if (!s) return "—";
  const str = String(s);
  return str.length > n ? str.slice(0, n) + "…" : str;
};

const toHex = (s) => {
  try { return BigInt(s).toString(16); } catch { return s; }
};

/* ════════════════════════════════════════════════════════════════════════
   TAB 1 — Key Generation
   ════════════════════════════════════════════════════════════════════════ */
function KeyGen() {
  const [bits, setBits] = useState(512);
  const [keys, setKeys] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const gen = async () => {
    setLoading(true); setErr("");
    try {
      const d = await post("/pa12/keygen", { bits });
      setKeys(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const keyItems = keys ? [
    ["N (modulus)", trunc(toHex(keys.N), 80)],
    ["e (public exponent)", keys.e],
    ["d (private exponent)", trunc(toHex(keys.d), 80)],
    ["p (prime 1)", trunc(toHex(keys.p), 60)],
    ["q (prime 2)", trunc(toHex(keys.q), 60)],
    ["dp = d mod (p−1)", trunc(toHex(keys.dp), 60)],
    ["dq = d mod (q−1)", trunc(toHex(keys.dq), 60)],
    ["q_inv = q⁻¹ mod p", trunc(toHex(keys.q_inv), 60)],
  ] : [];

  return (
    <div>
      <p className="sub">
        RSA key generation: choose two large primes p, q (via PA#13 Miller-Rabin),
        compute N=pq, φ(N)=(p−1)(q−1), e=65537, d=e⁻¹ mod φ(N). The CRT parameters
        dp, dq, q_inv enable fast Garner decryption used in PA#14.
      </p>

      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 14 }}>
        <div>
          <label>Key size (bits)</label>
          <select value={bits} onChange={(e) => setBits(+e.target.value)}
                  style={{ display: "block", marginTop: 4 }}>
            {[256, 512, 1024].map((b) => <option key={b} value={b}>{b} bits</option>)}
          </select>
        </div>
        <button onClick={gen} disabled={loading}>
          {loading ? "Generating…" : "Generate RSA Key"}
        </button>
      </div>

      {err && <div className="err">{err}</div>}

      {keys && (
        <div className="result-card">
          <div className="result-headline">
            <strong>{bits}-bit RSA Keypair</strong>
            <Badge ok label={`N = p·q, e=65537`} />
          </div>
          {keyItems.map(([label, value]) => (
            <Field key={label} label={label} value={value} />
          ))}
          <div className="note-box" style={{ marginTop: 8 }}>
            <strong>Public key:</strong> (N, e) — share openly.&nbsp;
            <strong>Private key:</strong> (N, d) — keep secret.&nbsp;
            The hardness of factoring N = p·q protects d.
          </div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   TAB 2 — Determinism Attack
   Spec: "Student types a short message (e.g., 'yes' or 'no'), click
          'Encrypt twice'. Both ciphertexts shown — identical (red banner)
          for textbook, differ each time (green banner) for PKCS#1 v1.5."
   ════════════════════════════════════════════════════════════════════════ */
function DeterminismAttack() {
  const [bits] = useState(512);
  const [keys, setKeys] = useState(null);
  const [msg, setMsg] = useState("yes");
  const [mode, setMode] = useState("textbook"); // "textbook" | "pkcs15"
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const ensureKeys = async () => {
    if (keys) return keys;
    const d = await post("/pa12/keygen", { bits });
    setKeys(d); return d;
  };

  const encryptTwice = async () => {
    setLoading(true); setErr(""); setResult(null);
    try {
      const k = await ensureKeys();
      const msgHex = Array.from(new TextEncoder().encode(msg))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const d = await post("/pa12/attack/determinism", {
        N: k.N, e: k.e, message_hex: msgHex,
      });
      setResult({ ...d, msgHex });
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const tb = result?.textbook;
  const pk = result?.pkcs15;
  const showMode = mode === "textbook" ? tb : pk;
  const isIdentical = showMode?.identical;

  return (
    <div>
      <p className="sub">
        Textbook RSA is <strong>deterministic</strong> — encrypting the same message
        twice always produces identical ciphertexts. This immediately breaks CPA security.
        PKCS#1 v1.5 injects random bytes (PS) to prevent this.
      </p>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
        <div style={{ flex: "1 1 180px" }}>
          <label>Message (simulate a vote)</label>
          <input type="text" value={msg} onChange={(e) => setMsg(e.target.value)}
                 placeholder="yes / no / vote_a" />
        </div>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end", gap: 6 }}>
          <button onClick={encryptTwice} disabled={loading}>
            {loading ? "Encrypting…" : "Encrypt Twice"}
          </button>
          {!keys && <span className="sub" style={{ fontSize: 11 }}>Will generate 512-bit key first</span>}
        </div>
      </div>

      {/* Mode toggle */}
      {result && (
        <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
          <button
            className={`pa-tab${mode === "textbook" ? " active" : ""}`}
            onClick={() => setMode("textbook")}
          >Textbook RSA</button>
          <button
            className={`pa-tab${mode === "pkcs15" ? " active" : ""}`}
            onClick={() => setMode("pkcs15")}
          >PKCS#1 v1.5</button>
        </div>
      )}

      {err && <div className="err">{err}</div>}

      {result && showMode && (
        <>
          <div className={`det-banner ${isIdentical ? "danger" : "safe"}`}>
            {isIdentical
              ? `🔴 Both ciphertexts are IDENTICAL — plaintext leaked! (${mode === "textbook" ? "Textbook RSA" : "PKCS#1 v1.5"})`
              : `🟢 Ciphertexts DIFFER each time — randomness protects the message. (${mode === "textbook" ? "Textbook RSA" : "PKCS#1 v1.5"})`}
          </div>

          <div className="rsa-det-grid">
            <div className="ct-box">
              <div className="ct-label">Ciphertext 1</div>
              <div className="ct-value">{trunc(toHex(showMode.c1), 120)}</div>
            </div>
            <div className="ct-box">
              <div className="ct-label">Ciphertext 2</div>
              <div className="ct-value">{trunc(toHex(showMode.c2), 120)}</div>
            </div>
          </div>

          {/* Show PS bytes for PKCS#1 mode */}
          {mode === "pkcs15" && (pk?.ps1_hex || pk?.ps_bytes_1) && (
            <div className="result-card" style={{ marginTop: 14 }}>
              <strong style={{ fontSize: 13, color: "#94a3b8" }}>Random PS bytes (differ each time)</strong>
              <div style={{ marginTop: 8 }}>
                <p className="sub" style={{ fontSize: 12 }}>Encryption 1 PS:</p>
                <div className="ps-bytes">
                  {(pk.ps1_hex || pk.ps_bytes_1 || "").match(/.{2}/g)?.map((b, i) => (
                    <span key={i} className="ps-byte">{b}</span>
                  ))}
                </div>
              </div>
              {(pk?.ps2_hex || pk?.ps_bytes_2) && (
                <div style={{ marginTop: 8 }}>
                  <p className="sub" style={{ fontSize: 12 }}>Encryption 2 PS:</p>
                  <div className="ps-bytes">
                    {(pk.ps2_hex || pk.ps_bytes_2 || "").match(/.{2}/g)?.map((b, i) => (
                      <span key={i} className="ps-byte">{b}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="note-box" style={{ marginTop: 12 }}>
            {mode === "textbook"
              ? "An attacker can encrypt a list of candidate messages and compare ciphertexts — trivially breaking confidentiality for small message spaces (e.g., election votes)."
              : "PKCS#1 v1.5 appends ≥8 random nonzero bytes (PS) before each encryption. Even for the same message, Eve sees different ciphertexts and cannot confirm the plaintext."}
          </div>
        </>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   TAB 3 — PKCS#1 v1.5 Inspector
   ════════════════════════════════════════════════════════════════════════ */
function PKCS15Inspector() {
  const [bits] = useState(512);
  const [keys, setKeys] = useState(null);
  const [msgText, setMsgText] = useState("Hello");
  const [encResult, setEncResult] = useState(null);
  const [decResult, setDecResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const ensureKeys = async () => {
    if (keys) return keys;
    const d = await post("/pa12/keygen", { bits });
    setKeys(d); return d;
  };

  const toHexMsg = (s) =>
    Array.from(new TextEncoder().encode(s))
      .map((b) => b.toString(16).padStart(2, "0")).join("");

  const encrypt = async () => {
    setLoading(true); setErr(""); setEncResult(null); setDecResult(null);
    try {
      const k = await ensureKeys();
      const d = await post("/pa12/pkcs15/encrypt", {
        N: k.N, e: k.e, message_hex: toHexMsg(msgText),
      });
      setEncResult(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const decrypt = async () => {
    if (!encResult || !keys) return;
    setLoading(true); setErr("");
    try {
      const d = await post("/pa12/pkcs15/decrypt", {
        N: keys.N, d: keys.d, c: encResult.c,
      });
      setDecResult(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  // Parse EM bytes for structure visualisation
  const em = encResult?.em_hex;
  let emParsed = null;
  if (em && em.length >= 6) {
    const bytes = em.match(/.{2}/g) || [];
    const sepIdx = bytes.findIndex((b, i) => i > 1 && b === "00");
    if (sepIdx > 1) {
      emParsed = {
        b00: bytes[0],
        b02: bytes[1],
        ps: bytes.slice(2, sepIdx),
        sep: bytes[sepIdx],
        msg: bytes.slice(sepIdx + 1),
      };
    }
  }

  return (
    <div>
      <p className="sub">
        PKCS#1 v1.5 wraps the message in a structured envelope before encryption:
        EM = 0x00 ‖ 0x02 ‖ PS (≥8 random nonzero bytes) ‖ 0x00 ‖ message.
        Inspect the padding structure in detail here.
      </p>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
        <div style={{ flex: "1 1 200px" }}>
          <label>Plaintext message</label>
          <input type="text" value={msgText} onChange={(e) => setMsgText(e.target.value)} />
        </div>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end", gap: 6 }}>
          <button onClick={encrypt} disabled={loading}>
            {loading ? "Working…" : "Pad & Encrypt"}
          </button>
        </div>
      </div>

      {err && <div className="err">{err}</div>}

      {encResult && (
        <div className="result-card">
          <div className="result-headline">
            <strong>Encrypted Message</strong>
            <Badge ok label="PKCS#1 v1.5 Type-02" />
          </div>
          <Field label="Original (hex)" value={toHexMsg(msgText)} />
          <Field label="Ciphertext C" value={trunc(toHex(encResult.c), 80)} />

          {emParsed && (
            <>
              <div style={{ marginTop: 12, marginBottom: 6 }}>
                <span className="kv-label">Padded message EM structure (k = {em.length / 2} bytes):</span>
              </div>
              <div className="pkcs-structure">
                <div className="pkcs-seg byte00">00<br /><span style={{ fontSize: 9, opacity: .7 }}>lead</span></div>
                <div className="pkcs-seg byte02">02<br /><span style={{ fontSize: 9, opacity: .7 }}>type</span></div>
                <div className="pkcs-seg ps-seg">
                  PS ({emParsed.ps.length} random bytes)<br />
                  <span style={{ fontSize: 9, opacity: .7 }}>nonzero, random</span>
                </div>
                <div className="pkcs-seg sep">00<br /><span style={{ fontSize: 9, opacity: .7 }}>sep</span></div>
                <div className="pkcs-seg msg-seg">
                  "{msgText}"<br />
                  <span style={{ fontSize: 9, opacity: .7 }}>{emParsed.msg.length} bytes</span>
                </div>
              </div>

              {/* PS bytes visualisation */}
              <div style={{ marginTop: 10 }}>
                <p className="sub" style={{ fontSize: 12 }}>
                  PS bytes ({emParsed.ps.length} bytes, all nonzero):
                </p>
                <div className="ps-bytes">
                  {emParsed.ps.map((b, i) => (
                    <span key={i} className="ps-byte">{b}</span>
                  ))}
                </div>
              </div>
            </>
          )}

          <div style={{ marginTop: 12 }}>
            <button onClick={decrypt} disabled={loading || !encResult}>
              {loading ? "Decrypting…" : "Decrypt & Verify"}
            </button>
          </div>

          {decResult && (
            <div style={{ marginTop: 10 }}>
              <Field label="Recovered message (hex)" value={decResult.message_hex} />
              <Field label="Recovered message (text)"
                     value={decResult.message_hex
                       ? (() => {
                           try {
                             return new TextDecoder().decode(
                               Uint8Array.from(decResult.message_hex.match(/.{2}/g), (b) => parseInt(b, 16))
                             );
                           } catch { return "—"; }
                         })()
                       : "—"}
                     mono={false} />
              <div className={`shared-secret-box match`} style={{ marginTop: 8 }}>
                <div className="label">Padding validation</div>
                <div className="value">
                  {decResult.valid_padding !== false ? "✓ Valid PKCS#1 v1.5 padding" : "✗ Invalid padding (⊥)"}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="note-box" style={{ marginTop: 14 }}>
        Even though the plaintext is the same, re-encrypting produces different EM
        (and therefore a different ciphertext) each time. This is what makes
        PKCS#1 v1.5 IND-CPA secure — unlike textbook RSA.
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   TAB 4 — Bleichenbacher Padding Oracle
   ════════════════════════════════════════════════════════════════════════ */
function Bleichenbacher() {
  const [bits] = useState(512);
  const [keys, setKeys] = useState(null);
  const [msgText, setMsgText] = useState("Secret");
  const [ciphertext, setCiphertext] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const toHexMsg = (s) =>
    Array.from(new TextEncoder().encode(s))
      .map((b) => b.toString(16).padStart(2, "0")).join("");

  const setup = async () => {
    setLoading(true); setErr("");
    try {
      const k = await post("/pa12/keygen", { bits });
      setKeys(k);
      const enc = await post("/pa12/pkcs15/encrypt", {
        N: k.N, e: k.e, message_hex: toHexMsg(msgText),
      });
      setCiphertext(enc.c);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const runAttack = async () => {
    if (!keys || !ciphertext) return;
    setLoading(true); setErr(""); setResult(null);
    try {
      const d = await post("/pa12/attack/bleichenbacher", {
        N: keys.N, d: keys.d, c: ciphertext, e: keys.e,
      });
      setResult(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  return (
    <div>
      <p className="sub">
        Bleichenbacher (1998) showed that a <strong>padding oracle</strong> — a service that
        reveals whether a ciphertext decrypts to valid PKCS#1 v1.5 format — can recover
        any RSA plaintext with ≈2<sup>20</sup> adaptive queries. This is a CCA2 attack.
        PKCS#1 v1.5 is IND-CPA secure but <em>not</em> IND-CCA2 secure.
      </p>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
        <div style={{ flex: "1 1 200px" }}>
          <label>Target plaintext to encrypt then recover</label>
          <input type="text" value={msgText} onChange={(e) => setMsgText(e.target.value)} />
        </div>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end", gap: 6 }}>
          <button onClick={setup} disabled={loading}>
            {loading ? "Working…" : "1. Setup (keygen + encrypt)"}
          </button>
        </div>
      </div>

      {keys && ciphertext && (
        <div className="result-card" style={{ marginBottom: 14 }}>
          <Field label="Target ciphertext C" value={trunc(toHex(ciphertext), 80)} />
          <div className="note-box" style={{ marginTop: 8 }}>
            The attacker has: public key (N, e) and the ciphertext C.
            They also have access to a <strong>padding oracle</strong> that returns
            whether Dec(c) has valid PKCS#1 v1.5 structure — nothing else.
          </div>
          <button onClick={runAttack} disabled={loading} style={{ marginTop: 10 }}>
            {loading ? "Attacking (may take a moment)…" : "2. Run Bleichenbacher Attack"}
          </button>
        </div>
      )}

      {err && <div className="err">{err}</div>}

      {result && (
        <div className="result-card">
          <div className="result-headline">
            <strong>Attack Result</strong>
            <Badge ok={!!result.recovered_plaintext_hex} label="CCA2 Demo" />
          </div>

          {result.oracle_queries != null && (
            <Field label="Oracle queries made"
                   value={Array.isArray(result.oracle_queries)
                     ? result.oracle_queries.length.toString()
                     : typeof result.oracle_queries === "number"
                       ? result.oracle_queries.toLocaleString()
                       : String(result.oracle_queries)} />
          )}
          {result.recovered_plaintext_hex && (
            <>
              <Field label="Recovered plaintext (hex)" value={result.recovered_plaintext_hex} />
              <Field label="Recovered plaintext (text)"
                     value={(() => {
                       try {
                         return new TextDecoder().decode(
                           Uint8Array.from(
                             result.recovered_plaintext_hex.match(/.{2}/g),
                             (b) => parseInt(b, 16)
                           )
                         );
                       } catch { return "—"; }
                     })()}
                     mono={false} />
            </>
          )}
          {result.explanation && (
            <div className="note-box" style={{ marginTop: 8 }}>{result.explanation}</div>
          )}
          <div className="note-box" style={{ marginTop: 8 }}>
            <strong>Lesson:</strong> Never expose a PKCS#1 v1.5 padding oracle in production.
            The modern secure alternative is <strong>OAEP</strong> (PA#17), which is
            IND-CCA2 secure in the random oracle model.
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
  { key: "keygen",   label: "Key Generation" },
  { key: "attack",   label: "Determinism Attack" },
  { key: "pkcs15",   label: "PKCS#1 v1.5 Inspector" },
  { key: "bb",       label: "Bleichenbacher" },
];

export default function PA12Panel() {
  const [tab, setTab] = useState("keygen");

  return (
    <div>
      <h2 style={{ marginBottom: 4, color: "#e2e8f0" }}>PA#12 — Textbook RSA + PKCS#1 v1.5</h2>
      <p className="sub">
        RSA public-key cryptosystem: encrypt with public key, decrypt with private key.
        Textbook RSA is deterministic (not CPA-secure). PKCS#1 v1.5 adds randomness.
      </p>

      <div className="pa-tabs">
        {TABS.map((t) => (
          <button key={t.key} className={`pa-tab${tab === t.key ? " active" : ""}`}
                  onClick={() => setTab(t.key)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "keygen" && <KeyGen />}
      {tab === "attack" && <DeterminismAttack />}
      {tab === "pkcs15" && <PKCS15Inspector />}
      {tab === "bb"     && <Bleichenbacher />}
    </div>
  );
}
