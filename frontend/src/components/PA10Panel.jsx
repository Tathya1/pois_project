import { useMemo, useState } from "react";
import "./PA10Panel.css";

const API = "http://localhost:5000";

const post = async (path, body) => {
  const response = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(data.error || "API error");
  }
  return data;
};

const formatNumber = (value) => {
  if (typeof value !== "number") return String(value);
  if (Math.abs(value) >= 1e6) return value.toExponential(3);
  return value.toLocaleString(undefined, { maximumFractionDigits: 6 });
};

function flipHexBit(hex) {
  if (!hex || hex.length < 2) return hex;
  const head = hex.slice(0, -2);
  const tail = hex.slice(-2);
  const byte = parseInt(tail, 16);
  if (Number.isNaN(byte)) return hex;
  const flipped = (byte ^ 0x01).toString(16).padStart(2, "0");
  return `${head}${flipped}`;
}

export default function PA10Panel() {
  const [activeTab, setActiveTab] = useState("hmac");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [hashType, setHashType] = useState("dlp");

  const [hmacKey, setHmacKey] = useState("1a2b3c4d");
  const [hmacMsg, setHmacMsg] = useState("hello world");
  const [tagInput, setTagInput] = useState("");
  const [hmacTag, setHmacTag] = useState("");
  const [verifyResult, setVerifyResult] = useState(null);

  const [extSuffix, setExtSuffix] = useState("&admin=true");
  const [guessKeyLen, setGuessKeyLen] = useState(4);
  const [extResult, setExtResult] = useState(null);

  const [keyE, setKeyE] = useState("1a2b3c4d");
  const [keyM, setKeyM] = useState("0f0e0d0c0b0a0908");
  const [ethMessage, setEthMessage] = useState("confidential payload");
  const [ethPacket, setEthPacket] = useState({ r: "", c: "", tag: "" });
  const [ethDecResult, setEthDecResult] = useState(null);

  const [eufRounds, setEufRounds] = useState(20);
  const [eufQueries, setEufQueries] = useState(50);
  const [eufResult, setEufResult] = useState(null);

  const [ccaRounds, setCcaRounds] = useState(40);
  const [ccaCompare, setCcaCompare] = useState(null);

  const [timingIterations, setTimingIterations] = useState(12000);
  const [timingResult, setTimingResult] = useState(null);

  const [machashMessages, setMachashMessages] = useState("m0,m1,m2,m3,m4");
  const [machashResult, setMachashResult] = useState(null);

  const run = async (task) => {
    setLoading(true);
    setError("");
    try {
      await task();
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  const runHmac = async () => {
    await run(async () => {
      const result = await post("/pa10/hmac", {
        key: hmacKey,
        message: hmacMsg,
        hashType,
      });
      setHmacTag(result.tag);
      setTagInput(result.tag);
      setVerifyResult(null);
    });
  };

  const runVerify = async () => {
    await run(async () => {
      const result = await post("/pa10/hmac/verify", {
        key: hmacKey,
        message: hmacMsg,
        tag: tagInput,
        hashType,
      });
      setVerifyResult(result);
    });
  };

  const runLengthExtension = async () => {
    await run(async () => {
      const result = await post("/pa10/length-extension", {
        key: hmacKey,
        message: hmacMsg,
        suffix: extSuffix,
        guessKeyLen,
        hashType,
      });
      setExtResult(result);
    });
  };

  const runEncrypt = async () => {
    await run(async () => {
      const result = await post("/pa10/eth/enc", {
        keyE,
        keyM,
        message: ethMessage,
        hashType,
      });
      setEthPacket({ r: result.r, c: result.c, tag: result.tag });
      setEthDecResult(null);
    });
  };

  const runDecrypt = async () => {
    await run(async () => {
      const result = await post("/pa10/eth/dec", {
        keyE,
        keyM,
        r: ethPacket.r,
        c: ethPacket.c,
        tag: ethPacket.tag,
        hashType,
      });
      setEthDecResult(result);
    });
  };

  const runEufCma = async () => {
    await run(async () => {
      const result = await post("/pa10/euf-cma", {
        rounds: eufRounds,
        queries: eufQueries,
        hashType,
      });
      setEufResult(result);
    });
  };

  const runCompareCca = async () => {
    await run(async () => {
      const result = await post("/pa10/compare-pa6", {
        rounds: ccaRounds,
        hashType,
      });
      setCcaCompare(result);
    });
  };

  const runTiming = async () => {
    await run(async () => {
      const result = await post("/pa10/timing", { iterations: timingIterations });
      setTimingResult(result);
    });
  };

  const runMachash = async () => {
    await run(async () => {
      const parsed = machashMessages
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);

      const result = await post("/pa10/machash", {
        messages: parsed,
        hashType,
      });
      setMachashResult(result);
    });
  };

  const timingObservation = useMemo(() => {
    if (!timingResult) return "";

    const naive = Math.abs(timingResult.naiveDeltaNs);
    const secure = Math.abs(timingResult.secureDeltaNs);

    if (secure < naive) {
      return "Constant-time comparison shows lower timing skew than naive early-exit comparison.";
    }
    return "Measured timing skew is noisy; rerun with higher iterations to separate naive vs constant-time behavior.";
  }, [timingResult]);

  return (
    <div className="panel pa10-shell">
      <h3>PA#10 - HMAC and Encrypt-then-HMAC</h3>

      <div className="pa10-hash-toggle">
        <span>Underlying hash</span>
        <button
          className={hashType === "dlp" ? "active" : ""}
          onClick={() => setHashType("dlp")}
        >
          PA8 DLP Hash
        </button>
        <button
          className={hashType === "sha256" ? "active" : ""}
          onClick={() => setHashType("sha256")}
        >
          SHA-256 Placeholder
        </button>
      </div>

      <div className="pa10-tabs">
        {[
          ["hmac", "HMAC"],
          ["extension", "Length Extension"],
          ["eth", "EtH Enc/Dec"],
          ["euf", "EUF-CMA"],
          ["cca", "CCA2 + PA6 Compare"],
          ["timing", "Constant-Time"],
          ["machash", "MAC=>CRHF"],
        ].map(([id, label]) => (
          <button key={id} onClick={() => setActiveTab(id)} className={activeTab === id ? "active" : ""}>
            {label}
          </button>
        ))}
      </div>

      {error && <p className="pa10-error">{error}</p>}

      {activeTab === "hmac" && (
        <section className="pa10-section">
          <p className="pa10-lead">
            Interface requirement: HMAC(k,m) -&gt; tag and HMAC Verify(k,m,t) -&gt; bool.
          </p>

          <div className="pa10-grid-3">
            <label>
              Key
              <input value={hmacKey} onChange={(event) => setHmacKey(event.target.value)} />
            </label>
            <label>
              Message
              <input value={hmacMsg} onChange={(event) => setHmacMsg(event.target.value)} />
            </label>
            <label>
              Tag to verify
              <input value={tagInput} onChange={(event) => setTagInput(event.target.value)} />
            </label>
          </div>

          <div className="pa10-actions">
            <button onClick={runHmac} disabled={loading} className="pa10-primary">
              {loading ? "Running..." : "Generate HMAC"}
            </button>
            <button onClick={runVerify} disabled={loading}>
              Verify Tag
            </button>
          </div>

          {hmacTag && <p className="pa10-mono">Generated tag: {hmacTag}</p>}
          {verifyResult && <p>Verification result: {verifyResult.valid ? "Valid" : "Invalid"}</p>}
        </section>
      )}

      {activeTab === "extension" && (
        <section className="pa10-section">
          <p className="pa10-lead">
            Side-by-side demo: naive MAC H(k||m) is forgeable via length extension, HMAC is not.
          </p>

          <div className="pa10-grid-4">
            <label>
              Key
              <input value={hmacKey} onChange={(event) => setHmacKey(event.target.value)} />
            </label>
            <label>
              Message
              <input value={hmacMsg} onChange={(event) => setHmacMsg(event.target.value)} />
            </label>
            <label>
              Suffix m'
              <input value={extSuffix} onChange={(event) => setExtSuffix(event.target.value)} />
            </label>
            <label>
              Guessed |k|
              <input
                type="number"
                min="0"
                value={guessKeyLen}
                onChange={(event) => setGuessKeyLen(Number(event.target.value))}
              />
            </label>
          </div>

          <button onClick={runLengthExtension} disabled={loading} className="pa10-primary">
            {loading ? "Running..." : "Attempt Length Extension"}
          </button>

          {extResult && (
            <div className="pa10-columns">
              <div className="pa10-card broken">
                <h4>Broken: naive H(k||m)</h4>
                <p>Forgery succeeded: {String(extResult.naiveForgerySucceeded)}</p>
                <p className="pa10-mono">Original tag: {extResult.naiveTag}</p>
                <p className="pa10-mono">Forged tag: {extResult.forgedTag}</p>
              </div>

              <div className="pa10-card secure">
                <h4>Secure: HMAC(k,m)</h4>
                <p>Forgery succeeded: {String(extResult.hmacForgerySucceeded)}</p>
                <p className="pa10-mono">Original HMAC: {extResult.hmacTag}</p>
                <p className="pa10-mono">Real HMAC on forged msg: {extResult.actualHmacForForgedMessage}</p>
              </div>

              <details className="pa10-details">
                <summary>Forgery internals</summary>
                <p className="pa10-mono">Glue padding: {extResult.gluePaddingHex}</p>
                <p className="pa10-mono">Forged message hex: {extResult.forgedMessageHex}</p>
              </details>
            </div>
          )}
        </section>
      )}

      {activeTab === "eth" && (
        <section className="pa10-section">
          <p className="pa10-lead">
            Interface requirement: EtH Enc(kE,kM,m) and EtH Dec(kE,kM,c,t), with verify-before-decrypt.
          </p>

          <div className="pa10-grid-3">
            <label>
              kE
              <input value={keyE} onChange={(event) => setKeyE(event.target.value)} />
            </label>
            <label>
              kM
              <input value={keyM} onChange={(event) => setKeyM(event.target.value)} />
            </label>
            <label>
              Message
              <input value={ethMessage} onChange={(event) => setEthMessage(event.target.value)} />
            </label>
          </div>

          <div className="pa10-actions">
            <button onClick={runEncrypt} disabled={loading} className="pa10-primary">
              {loading ? "Running..." : "Encrypt + Tag"}
            </button>
            <button onClick={runDecrypt} disabled={loading}>
              Verify + Decrypt
            </button>
            <button
              onClick={() => setEthPacket((prev) => ({ ...prev, tag: flipHexBit(prev.tag) }))}
              disabled={!ethPacket.tag}
            >
              Tamper tag bit
            </button>
          </div>

          <div className="pa10-grid-3">
            <label>
              r
              <input value={ethPacket.r} onChange={(event) => setEthPacket((prev) => ({ ...prev, r: event.target.value }))} />
            </label>
            <label>
              c
              <input value={ethPacket.c} onChange={(event) => setEthPacket((prev) => ({ ...prev, c: event.target.value }))} />
            </label>
            <label>
              tag
              <input value={ethPacket.tag} onChange={(event) => setEthPacket((prev) => ({ ...prev, tag: event.target.value }))} />
            </label>
          </div>

          {ethDecResult && (
            <p>
              Decryption: {ethDecResult.valid ? `valid, message = ${ethDecResult.message}` : "rejected (tampered or invalid tag)"}
            </p>
          )}
        </section>
      )}

      {activeTab === "euf" && (
        <section className="pa10-section">
          <p className="pa10-lead">
            CRHF=&gt;MAC check: EUF-CMA simulation after oracle queries; forging on fresh message should remain negligible.
          </p>

          <div className="pa10-inline-controls">
            <label>
              Rounds
              <input
                type="number"
                min="1"
                value={eufRounds}
                onChange={(event) => setEufRounds(Number(event.target.value))}
              />
            </label>
            <label>
              Oracle queries
              <input
                type="number"
                min="1"
                value={eufQueries}
                onChange={(event) => setEufQueries(Number(event.target.value))}
              />
            </label>
            <button onClick={runEufCma} disabled={loading} className="pa10-primary">
              {loading ? "Running..." : "Run EUF-CMA"}
            </button>
          </div>

          {eufResult && (
            <div className="pa10-metrics">
              <div>
                <span>Forge success rate</span>
                <strong>{formatNumber(eufResult.forgeSuccessRate)}</strong>
              </div>
              <div>
                <span>Rounds</span>
                <strong>{eufResult.rounds}</strong>
              </div>
              <div>
                <span>Queries</span>
                <strong>{eufResult.oracleQueries}</strong>
              </div>
              <div>
                <span>Tag bytes</span>
                <strong>{eufResult.tagBytes}</strong>
              </div>
            </div>
          )}
        </section>
      )}

      {activeTab === "cca" && (
        <section className="pa10-section">
          <p className="pa10-lead">
            CCA2 requirement: compare EtH-HMAC with PA6 PRF-MAC scheme on tamper rejection, advantage, tag size,
            and runtime cost.
          </p>

          <div className="pa10-inline-controls">
            <label>
              Rounds
              <input
                type="number"
                min="1"
                value={ccaRounds}
                onChange={(event) => setCcaRounds(Number(event.target.value))}
              />
            </label>
            <button onClick={runCompareCca} disabled={loading} className="pa10-primary">
              {loading ? "Running..." : "Run CCA2 + Compare"}
            </button>
          </div>

          {ccaCompare && (
            <div className="pa10-columns">
              <div className="pa10-card secure">
                <h4>PA10 EtH-HMAC</h4>
                <p>Advantage: {formatNumber(ccaCompare.hmacScheme.advantage)}</p>
                <p>Tamper reject rate: {formatNumber(ccaCompare.hmacScheme.tamperRejectRate)}</p>
                <p>Tag bytes: {ccaCompare.hmacScheme.tagBytes}</p>
                <p>Avg enc ms: {formatNumber(ccaCompare.hmacScheme.avgEncryptMs)}</p>
                <p>Avg dec ms: {formatNumber(ccaCompare.hmacScheme.avgDecryptMs)}</p>
              </div>

              <div className="pa10-card">
                <h4>PA6 PRF-MAC EtM</h4>
                <p>Advantage: {formatNumber(ccaCompare.pa6PrfMacScheme.advantage)}</p>
                <p>Tamper reject rate: {formatNumber(ccaCompare.pa6PrfMacScheme.tamperRejectRate)}</p>
                <p>Tag bytes: {ccaCompare.pa6PrfMacScheme.tagBytes}</p>
                <p>Avg enc ms: {formatNumber(ccaCompare.pa6PrfMacScheme.avgEncryptMs)}</p>
                <p>Avg dec ms: {formatNumber(ccaCompare.pa6PrfMacScheme.avgDecryptMs)}</p>
              </div>

              <div className="pa10-card">
                <h4>Comparison</h4>
                <p>Tag size delta bytes: {formatNumber(ccaCompare.comparison.tagSizeDeltaBytes)}</p>
                <p>Encrypt cost ratio (HMAC/PA6): {formatNumber(ccaCompare.comparison.encryptCostRatioHmacToPa6)}</p>
                <p>Decrypt cost ratio (HMAC/PA6): {formatNumber(ccaCompare.comparison.decryptCostRatioHmacToPa6)}</p>
              </div>
            </div>
          )}
        </section>
      )}

      {activeTab === "timing" && (
        <section className="pa10-section">
          <p className="pa10-lead">
            Constant-time check: compare naive early-exit tag comparison versus XOR-accumulating secure comparison.
          </p>

          <div className="pa10-inline-controls">
            <label>
              Iterations
              <input
                type="number"
                min="1000"
                value={timingIterations}
                onChange={(event) => setTimingIterations(Number(event.target.value))}
              />
            </label>
            <button onClick={runTiming} disabled={loading} className="pa10-primary">
              {loading ? "Running..." : "Run Timing Demo"}
            </button>
          </div>

          {timingResult && (
            <>
              <div className="pa10-metrics">
                <div>
                  <span>Naive delta ns</span>
                  <strong>{formatNumber(timingResult.naiveDeltaNs)}</strong>
                </div>
                <div>
                  <span>Secure delta ns</span>
                  <strong>{formatNumber(timingResult.secureDeltaNs)}</strong>
                </div>
                <div>
                  <span>Naive late ns</span>
                  <strong>{formatNumber(timingResult.naiveLateNs)}</strong>
                </div>
                <div>
                  <span>Secure late ns</span>
                  <strong>{formatNumber(timingResult.secureLateNs)}</strong>
                </div>
              </div>
              <p>{timingObservation}</p>
            </>
          )}
        </section>
      )}

      {activeTab === "machash" && (
        <section className="pa10-section">
          <p className="pa10-lead">
            MAC=&gt;CRHF requirement: build MAC Hash with h'(cv,block) = HMAC_k(cv||block) and present the
            reduction argument.
          </p>

          <div className="pa10-inline-controls">
            <label>
              Messages (comma-separated)
              <input
                value={machashMessages}
                onChange={(event) => setMachashMessages(event.target.value)}
              />
            </label>
            <button onClick={runMachash} disabled={loading} className="pa10-primary">
              {loading ? "Running..." : "Compute MAC Hash"}
            </button>
          </div>

          {machashResult && (
            <div className="pa10-columns">
              <div className="pa10-card">
                <h4>Digests</h4>
                {machashResult.results.map((row) => (
                  <p key={row.message} className="pa10-mono">
                    {row.message}: {row.digest}
                  </p>
                ))}
                <p>All distinct: {String(machashResult.allDistinct)}</p>
              </div>

              <div className="pa10-card secure">
                <h4>Reduction sketch</h4>
                <ol>
                  {machashResult.reduction.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
                <p>{machashResult.note}</p>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
