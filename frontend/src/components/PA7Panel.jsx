import { useState, useCallback } from "react";
import "./PA7Panel.css";

const API = "http://localhost:5000";
const BLOCK_SIZE = 8;
const HASH_SIZE = 4;

const post = async (path, body) => {
  const res  = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error || "API error");
  return data;
};

const TABS = [
  { id: "trace",     label: "MD Hash + Chain" },
  { id: "collision", label: "Collision Demo" },
];

const normalizeHex = (hex) => hex.replace(/\s+/g, "").toLowerCase();
const isValidHex = (hex) => /^[0-9a-f]*$/i.test(hex) && hex.length % 2 === 0;

const hexToBytes = (hex) => {
  const clean = normalizeHex(hex);
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

const bytesToHex = (bytes) =>
  Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");

const xorCompress = (cvBytes, blockBytes) => {
  const n = cvBytes.length;
  const folded = new Uint8Array(n);
  for (let i = 0; i < blockBytes.length; i += n) {
    for (let j = 0; j < n; j += 1) {
      folded[j] ^= blockBytes[i + j] || 0;
    }
  }
  const out = new Uint8Array(n);
  for (let j = 0; j < n; j += 1) {
    out[j] = cvBytes[j] ^ folded[j];
  }
  return out;
};

const recomputeChainFrom = (blocks, startIndex, chain) => {
  const newChain = [...chain];
  let cv;
  if (startIndex <= 0 || !newChain[startIndex]) {
    cv = new Uint8Array(HASH_SIZE);
    newChain[0] = bytesToHex(cv);
    startIndex = 0;
  } else {
    cv = hexToBytes(newChain[startIndex]);
  }

  for (let i = startIndex; i < blocks.length; i += 1) {
    const blockBytes = hexToBytes(blocks[i]);
    cv = xorCompress(cv, blockBytes);
    newChain[i + 1] = bytesToHex(cv);
  }

  return newChain;
};

// ── Chain visualization component ─────────────────────────────────────────
function ChainViz({ chain, blocks }) {
  if (!chain || chain.length === 0) return null;
  return (
    <div className="pa7-chain">
      {chain.map((cv, i) => {
        const isIV     = i === 0;
        const isDigest = i === chain.length - 1;
        const blockHex = blocks && blocks[i - 1] ? blocks[i - 1].hex : null;
        return (
          <div key={i} className="pa7-chain-node" style={{ display: "flex", alignItems: "center" }}>
            {i > 0 && (
              <div className="pa7-chain-arrow">
                {blockHex && (
                  <div className="pa7-arrow-block" title={blockHex}>
                    B{i - 1}: {blockHex.slice(0, 8)}…
                  </div>
                )}
                <div className="pa7-arrow-line" />
              </div>
            )}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
              <div className={`pa7-state-box ${isIV ? "iv" : isDigest ? "digest" : "mid"}`}>
                {cv.slice(0, 16)}…
              </div>
              <div className="pa7-state-label">
                {isIV ? "IV" : isDigest ? "Digest" : `h${i}`}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Block grid with padding annotations ──────────────────────────────────
function BlockGrid({ blocks, paddingInfo, blockSize, onEditBlock, blockEditError }) {
  if (!blocks || blocks.length === 0) return null;
  return (
    <div>
      <div className="pa7-legend">
        <div className="pa7-legend-item">
          <div className="pa7-legend-dot" style={{ background: "#3b82f6" }} /> Data bytes
        </div>
        <div className="pa7-legend-item">
          <div className="pa7-legend-dot" style={{ background: "#f59e0b" }} /> Padding/length
        </div>
        <div className="pa7-legend-item">
          <div className="pa7-legend-dot" style={{ background: "#16a34a" }} /> Pure padding block
        </div>
      </div>
      <div className="pa7-blocks-grid">
        {blocks.map((blk, i) => {
          const cls = blk.has_data && !blk.has_pad ? "data"
                    : blk.has_data                  ? "mixed"
                    : "pad";
          return (
            <div key={i} className={`pa7-block-card ${cls}`}>
              <div style={{ fontWeight: "bold", color: "#94a3b8", marginBottom: 4 }}>
                Block {i}{blk.has_data ? " (data" : " ("}
                {blk.has_pad ? "+pad" : ""}{blk.has_length ? "+length" : ""}
                {")"}
              </div>
              <div className="pa7-block-hex">{blk.hex}</div>
              <label style={{ display: "grid", gap: 4, marginTop: 8 }}>
                <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>
                  Edit block hex ({blockSize}B)
                </span>
                <input
                  value={blk.hex}
                  onChange={(e) => onEditBlock(i, e.target.value)}
                  style={{ fontFamily: "monospace", fontSize: "0.75rem" }}
                />
              </label>
            </div>
          );
        })}
      </div>
      {blockEditError && (
        <div className="pa7-info" style={{ marginTop: 10, fontSize: "0.78rem", color: "#fca5a5" }}>
          {blockEditError}
        </div>
      )}
      {paddingInfo && (
        <div className="pa7-info" style={{ marginTop: 10, fontSize: "0.8rem" }}>
          Original: {paddingInfo.original_bytes}B ({paddingInfo.original_bits} bits) →
          Padded: {paddingInfo.padded_bytes}B |
          0x80 at byte {paddingInfo.marker_byte_pos} |
          64-bit length at byte {paddingInfo.length_field_pos}
        </div>
      )}
    </div>
  );
}

export default function PA7Panel() {
  const [activeTab, setActiveTab] = useState("trace");
  const [error, setError]         = useState("");

  // ── Trace tab ──────────────────────────────────────────────────────────
  const [msg,         setMsg]        = useState("hello world");
  const [compressFn,  setCompressFn] = useState("xor");
  const [asHex,       setAsHex]      = useState(false);
  const [traceResult, setTraceResult] = useState(null);
  const [traceBlocks, setTraceBlocks] = useState([]);
  const [traceChain,  setTraceChain]  = useState([]);
  const [blockEditError, setBlockEditError] = useState("");
  const [loading,     setLoading]    = useState(false);
  const expectedBlockHexLen = BLOCK_SIZE * 2;

  const runTrace = async () => {
    setLoading(true); setError("");
    try {
      const data = await post("/pa7/trace", { message: msg, compressFn, asHex });
      setTraceResult(data);
      setTraceBlocks(data.blocks || []);
      setTraceChain(data.chain || []);
      setBlockEditError("");
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const handleEditBlock = (index, value) => {
    const nextBlocks = traceBlocks.map((blk, i) =>
      i === index ? { ...blk, hex: normalizeHex(value) } : blk
    );
    setTraceBlocks(nextBlocks);

    const hex = normalizeHex(value);
    if (!isValidHex(hex) || hex.length !== expectedBlockHexLen) {
      setBlockEditError(`Each block must be exactly ${BLOCK_SIZE} bytes (${BLOCK_SIZE * 2} hex chars).`);
      return;
    }

    setBlockEditError("");
    const blockHexes = nextBlocks.map((blk) => blk.hex);
    setTraceChain((prev) => recomputeChainFrom(blockHexes, index, prev || []));
  };


  // ── Collision tab ──────────────────────────────────────────────────────
  const [suffix,      setSuffix]    = useState("any_suffix_works");
  const [collResult,  setCollResult] = useState(null);
  const [collLoading, setCollLoading] = useState(false);

  const runCollision = async () => {
    setCollLoading(true); setError("");
    try {
      const data = await post("/pa7/collision-demo", { compressFn: "xor", suffix });
      setCollResult(data);
    } catch (e) { setError(e.message); }
    setCollLoading(false);
  };

  return (
    <div className="panel">
      <h3>PA#7 — Merkle-Damgård Hash Transform</h3>

      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => { setActiveTab(t.id); setError(""); }}
            style={{
              fontWeight: activeTab === t.id ? "bold" : "normal",
              background: activeTab === t.id ? "#1e40af" : "#1e293b",
              color: "#e2e8f0", border: "none", borderRadius: 8,
              padding: "8px 14px", cursor: "pointer",
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {error && <p className="pa7-err">⚠ {error}</p>}

      {/* ═══ TRACE TAB ═══ */}
      {activeTab === "trace" && (
        <div className="pa7-grid">
          <div className="pa7-info">
            <b>Merkle-Damgård</b>: H(M) = f(f(f(IV, B₀), B₁), …, Bₙ) where B₀…Bₙ are blocks
            of padded M. The chain below shows each chaining value after each compression round.
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <label className="pa7-grid">
              Message
              <input value={msg} onChange={e => setMsg(e.target.value)} />
            </label>
            <label className="pa7-grid">
              Compress function
              <select value={compressFn} onChange={e => setCompressFn(e.target.value)}>
                <option value="xor">XOR Compress (trivially broken)</option>
              </select>
            </label>
          </div>

          <label className="pa7-grid" style={{ marginTop: 8 }}>
            <span>Interpret message as hex</span>
            <input
              type="checkbox"
              checked={asHex}
              onChange={(e) => setAsHex(e.target.checked)}
            />
          </label>

          <div className="pa7-row">
            <button onClick={runTrace} disabled={loading}>
              {loading ? "Computing…" : "Hash + Show Chain"}
            </button>
          </div>

          {traceResult && (
            <>
              <div className="output-box" style={{ fontFamily: "monospace" }}>
                <b>Digest:</b> {(traceChain && traceChain.length > 0) ? traceChain[traceChain.length - 1] : traceResult.digest} &nbsp;|&nbsp;
                <b>Blocks:</b> {traceResult.n_blocks} &nbsp;|&nbsp;
                <b>Padded:</b> {traceResult.padding_info.padded_bytes}B
              </div>

              <div style={{ marginTop: 6, marginBottom: 2, fontWeight: "bold", color: "#94a3b8" }}>
                Chain Visualization
              </div>
              <ChainViz chain={traceChain} blocks={traceBlocks} />

              <div style={{ marginTop: 6, fontWeight: "bold", color: "#94a3b8" }}>
                Block Breakdown (with padding)
              </div>
              <BlockGrid
                blocks={traceBlocks}
                paddingInfo={traceResult.padding_info}
                blockSize={BLOCK_SIZE}
                onEditBlock={handleEditBlock}
                blockEditError={blockEditError}
              />
            </>
          )}
        </div>
      )}

      {/* ═══ COLLISION TAB ═══ */}
      {activeTab === "collision" && (
        <div className="pa7-grid">
          <div className="pa7-info">
            <b>Theorem:</b> A collision in compress propagates to a full MD collision.
            <br />
            XOR compress lets us construct B₁ ≠ B₂ with compress(IV, B₁) = compress(IV, B₂) = IV.
            Then for <em>any</em> suffix S: H(B₁ ‖ S) = H(B₂ ‖ S).
          </div>

          <label className="pa7-grid">
            Suffix S (any string — demonstrates the "for any suffix" property)
            <input value={suffix} onChange={e => setSuffix(e.target.value)} />
          </label>

          <div className="pa7-row">
            <button onClick={runCollision} disabled={collLoading}>
              {collLoading ? "Running…" : "Construct Collision + Propagate"}
            </button>
          </div>

          {collResult && collResult.found && (
            <>
              {/* Compress collision highlight */}
              <div style={{
                background: "#1a0a0a", border: "1.5px solid #ef4444",
                borderRadius: 10, padding: 14, marginTop: 8
              }}>
                <div style={{ fontWeight: "bold", color: "#f87171", marginBottom: 8 }}>
                  Step 1 — Compress Collision (Round 1)
                </div>
                <div style={{ fontFamily: "monospace", fontSize: "0.82rem", lineHeight: 1.8 }}>
                  <div>B₁ = <span style={{ color: "#a855f7" }}>{collResult.compress_collision.block1_hex}</span></div>
                  <div>B₂ = <span style={{ color: "#22c55e" }}>{collResult.compress_collision.block2_hex}</span></div>
                  <div style={{ marginTop: 6 }}>
                    compress(IV, B₁) = compress(IV, B₂) = <b style={{ color: "#fcd34d" }}>
                      {collResult.compress_collision.compress_output}
                    </b>
                  </div>
                  <div>Blocks equal: <b style={{ color: collResult.compress_collision.blocks_equal ? "#ef4444" : "#4ade80" }}>
                    {collResult.compress_collision.blocks_equal ? "YES (bug!)" : "NO (genuine collision)"}
                  </b>
                  </div>
                </div>
              </div>

              {/* MD collision split panel */}
              <div style={{ fontWeight: "bold", color: "#94a3b8", marginTop: 10 }}>
                Step 2 — Full MD Collision (suffix: "{suffix}")
              </div>

              <div className="pa7-collision-split">
                <div className="pa7-collision-side path1">
                  <div style={{ fontWeight: "bold", color: "#c084fc", marginBottom: 8 }}>
                    M₁ = B₁ ‖ S
                  </div>
                  <ChainViz
                    chain={collResult.trace1?.chain?.slice(0, 3)}
                    blocks={collResult.trace1?.blocks?.slice(0, 2)}
                  />
                  <div className="pa7-block-hex" style={{ fontSize: "0.75rem", marginTop: 6 }}>
                    Hash: <b>{collResult.hash1}</b>
                  </div>
                </div>

                <div className="pa7-collision-side path2">
                  <div style={{ fontWeight: "bold", color: "#4ade80", marginBottom: 8 }}>
                    M₂ = B₂ ‖ S
                  </div>
                  <ChainViz
                    chain={collResult.trace2?.chain?.slice(0, 3)}
                    blocks={collResult.trace2?.blocks?.slice(0, 2)}
                  />
                  <div className="pa7-block-hex" style={{ fontSize: "0.75rem", marginTop: 6 }}>
                    Hash: <b>{collResult.hash2}</b>
                  </div>
                </div>
              </div>

              <div className="pa7-collision-convergence">
                {collResult.full_collision
                  ? `✓ FULL MD COLLISION CONFIRMED: H(B₁‖S) = H(B₂‖S) = ${collResult.hash1}`
                  : "✗ Collision did NOT propagate (unexpected — check compress_fn logic)"}
              </div>

              <div className="pa7-info" style={{ fontSize: "0.8rem" }}>
                {collResult.explanation}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
