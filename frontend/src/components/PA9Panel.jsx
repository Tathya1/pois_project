import { useEffect, useMemo, useState } from "react";
import "./PA9Panel.css";

const API = "http://localhost:5000";
const DEMO_BITS = [8, 10, 12, 14, 16];

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
  if (Math.abs(value) >= 1e12) return value.toExponential(3);
  if (Math.abs(value) >= 1e6) return value.toLocaleString(undefined, { maximumFractionDigits: 0 });
  return value.toLocaleString(undefined, { maximumFractionDigits: 4 });
};

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

function XYChart({ series, yMin = null, yMax = null, width = 720, height = 280, markerX = null }) {
  const allPoints = series.flatMap((line) => line.points);
  if (!allPoints.length) return null;

  const minX = Math.min(...allPoints.map((p) => p.x));
  const maxX = Math.max(...allPoints.map((p) => p.x));

  const computedYMin = yMin !== null ? yMin : Math.min(...allPoints.map((p) => p.y));
  const computedYMax = yMax !== null ? yMax : Math.max(...allPoints.map((p) => p.y));
  const safeYMax = computedYMax === computedYMin ? computedYMin + 1 : computedYMax;

  const pad = { left: 52, right: 20, top: 14, bottom: 34 };
  const w = width - pad.left - pad.right;
  const h = height - pad.top - pad.bottom;

  const xScale = (x) => pad.left + ((x - minX) / Math.max(1, maxX - minX)) * w;
  const yScale = (y) => pad.top + (1 - (y - computedYMin) / Math.max(1e-12, safeYMax - computedYMin)) * h;

  const ticksY = 5;
  const yGrid = Array.from({ length: ticksY + 1 }, (_, i) => {
    const ratio = i / ticksY;
    const value = safeYMax - ratio * (safeYMax - computedYMin);
    return { value, y: yScale(value) };
  });

  return (
    <div className="pa9-chart-wrap">
      <svg viewBox={`0 0 ${width} ${height}`} className="pa9-chart" role="img" aria-label="Plot">
        <rect x="0" y="0" width={width} height={height} fill="#020617" rx="10" />

        {yGrid.map((tick, idx) => (
          <g key={idx}>
            <line x1={pad.left} x2={width - pad.right} y1={tick.y} y2={tick.y} stroke="#1f2937" strokeWidth="1" />
            <text x={pad.left - 8} y={tick.y + 4} textAnchor="end" fill="#94a3b8" fontSize="10">
              {formatNumber(tick.value)}
            </text>
          </g>
        ))}

        <line x1={pad.left} x2={pad.left} y1={pad.top} y2={height - pad.bottom} stroke="#475569" strokeWidth="1.2" />
        <line
          x1={pad.left}
          x2={width - pad.right}
          y1={height - pad.bottom}
          y2={height - pad.bottom}
          stroke="#475569"
          strokeWidth="1.2"
        />

        {markerX !== null && markerX >= minX && markerX <= maxX && (
          <line
            x1={xScale(markerX)}
            x2={xScale(markerX)}
            y1={pad.top}
            y2={height - pad.bottom}
            stroke="#fbbf24"
            strokeDasharray="5 4"
            strokeWidth="1.4"
          />
        )}

        {series.map((line) => {
          const d = line.points
            .map((p, idx) => `${idx === 0 ? "M" : "L"}${xScale(p.x)} ${yScale(p.y)}`)
            .join(" ");

          return <path key={line.name} d={d} fill="none" stroke={line.color} strokeWidth="2" />;
        })}
      </svg>

      <div className="pa9-chart-legend">
        {series.map((line) => (
          <span key={line.name}>
            <i style={{ background: line.color }} />
            {line.name}
          </span>
        ))}
        {markerX !== null && <span className="marker-note">Expected marker: {formatNumber(markerX)}</span>}
      </div>
    </div>
  );
}

export default function PA9Panel() {
  const [activeTab, setActiveTab] = useState("live");
  const [error, setError] = useState("");

  const [nBits, setNBits] = useState(12);
  const [method, setMethod] = useState("naive");
  const [hashType, setHashType] = useState("toy");
  const [loading, setLoading] = useState(false);

  const [liveResult, setLiveResult] = useState(null);
  const [animatedCount, setAnimatedCount] = useState(0);

  const [toyTrials, setToyTrials] = useState(25);
  const [toyStudy, setToyStudy] = useState(null);

  const [dlpResult, setDlpResult] = useState(null);
  const [dlpMethod, setDlpMethod] = useState("naive");

  const [gridMethod, setGridMethod] = useState("naive");
  const [gridHashType, setGridHashType] = useState("toy");
  const [gridTrials, setGridTrials] = useState(100);
  const [gridData, setGridData] = useState(null);
  const [gridSelectedBits, setGridSelectedBits] = useState(8);

  const [hashRate, setHashRate] = useState("1000000000");
  const [contextData, setContextData] = useState(null);

  useEffect(() => {
    if (!liveResult?.found) {
      setAnimatedCount(0);
      return;
    }

    let frame = 0;
    const target = Number(liveResult.evaluations || 0);
    const startTime = performance.now();

    const tick = (now) => {
      const elapsed = now - startTime;
      const duration = 1200;
      const ratio = clamp(elapsed / duration, 0, 1);
      const eased = 1 - Math.pow(1 - ratio, 3);
      setAnimatedCount(Math.round(target * eased));

      if (ratio < 1) {
        frame = requestAnimationFrame(tick);
      }
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [liveResult]);

  const runLiveAttack = async () => {
    setLoading(true);
    setError("");
    setLiveResult(null);
    setAnimatedCount(0);

    try {
      const result = await post("/pa9/attack", {
        nBits,
        method,
        hashType,
        track: true,
        historyStep: 1,
      });
      setLiveResult(result);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  };

  const runToyStudy = async () => {
    setLoading(true);
    setError("");
    setToyStudy(null);

    try {
      const result = await post("/pa9/toy-study", { trialsPerPoint: toyTrials });
      setToyStudy(result);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  };

  const runDlpAttack = async () => {
    setLoading(true);
    setError("");
    setDlpResult(null);

    try {
      const result = await post("/pa9/dlp-truncated", { nBits: 16, method: dlpMethod });
      setDlpResult(result);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  };

  const runEmpiricalGrid = async () => {
    setLoading(true);
    setError("");
    setGridData(null);

    try {
      const result = await post("/pa9/empirical-grid", {
        hashType: gridHashType,
        method: gridMethod,
        trials: gridTrials,
        nValues: DEMO_BITS,
      });
      setGridData(result);
      setGridSelectedBits(DEMO_BITS[0]);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  };

  const runContext = async () => {
    setLoading(true);
    setError("");

    try {
      const result = await post("/pa9/context", { hashRate: Number(hashRate) });
      setContextData(result);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  };

  const liveChartSeries = useMemo(() => {
    if (!liveResult?.liveTrace?.points) return [];

    const points = liveResult.liveTrace.points;
    return [
      {
        name: "Theoretical P(collision by k)",
        color: "#22d3ee",
        points: points.map((p) => ({ x: p.k, y: p.theoretical })),
      },
      {
        name: "Empirical (single run)",
        color: "#f97316",
        points: points.map((p) => ({ x: p.k, y: p.empirical })),
      },
    ];
  }, [liveResult]);

  const toyPlotSeries = useMemo(() => {
    if (!toyStudy?.plot) return [];

    const byMethod = {};
    for (const row of toyStudy.plot) {
      if (!byMethod[row.method]) byMethod[row.method] = [];
      byMethod[row.method].push({ x: row.nBits, y: row.measured });
    }

    return [
      {
        name: "Expected 2^(n/2)",
        color: "#22d3ee",
        points: DEMO_BITS.filter((n) => [8, 12, 16].includes(n)).map((n) => ({ x: n, y: 2 ** (n / 2) })),
      },
      {
        name: "Naive mean evals",
        color: "#f97316",
        points: (byMethod.naive || []).sort((a, b) => a.x - b.x),
      },
      {
        name: "Floyd mean evals",
        color: "#a78bfa",
        points: (byMethod.floyd || []).sort((a, b) => a.x - b.x),
      },
    ];
  }, [toyStudy]);

  const selectedGridCurve = useMemo(() => {
    if (!gridData?.rows) return null;
    return gridData.rows.find((r) => r.nBits === Number(gridSelectedBits)) || null;
  }, [gridData, gridSelectedBits]);

  const gridCurveSeries = useMemo(() => {
    if (!selectedGridCurve?.curve?.points) return [];
    const points = selectedGridCurve.curve.points;

    return [
      {
        name: "Theoretical",
        color: "#22d3ee",
        points: points.map((p) => ({ x: p.k, y: p.theoretical })),
      },
      {
        name: "Empirical CDF",
        color: "#f97316",
        points: points.map((p) => ({ x: p.k, y: p.empirical })),
      },
    ];
  }, [selectedGridCurve]);

  return (
    <div className="panel pa9-shell">
      <h3>PA#9 - Birthday Attack Collision Finding</h3>

      <div className="pa9-tabs">
        {[
          ["live", "Live Demo"],
          ["toy", "Toy n=8/12/16"],
          ["dlp", "Truncated DLP n=16"],
          ["grid", "100-Trial Grid"],
          ["context", "MD5/SHA-1 Context"],
        ].map(([id, label]) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={activeTab === id ? "active" : ""}
          >
            {label}
          </button>
        ))}
      </div>

      {error && <p className="pa9-error">{error}</p>}

      {activeTab === "live" && (
        <section className="pa9-section">
          <p className="pa9-lead">
            Run a collision attack with n in {`{8,10,12,14,16}`} and watch empirical behavior against the
            birthday bound.
          </p>

          <div className="pa9-grid-3">
            <label>
              n bits (slider)
              <input
                type="range"
                min="8"
                max="16"
                step="2"
                value={nBits}
                onChange={(event) => setNBits(Number(event.target.value))}
              />
              <span className="pa9-value">{nBits}</span>
            </label>

            <label>
              Method
              <select value={method} onChange={(event) => setMethod(event.target.value)}>
                <option value="naive">Naive dictionary attack</option>
                <option value="floyd">Floyd cycle detection</option>
              </select>
            </label>

            <label>
              Hash function
              <select value={hashType} onChange={(event) => setHashType(event.target.value)}>
                <option value="toy">Toy hash</option>
                <option value="dlp">PA8 DLP hash</option>
                <option value="dlp-toy">DLP toy variant</option>
              </select>
            </label>
          </div>

          <button onClick={runLiveAttack} disabled={loading} className="pa9-primary">
            {loading ? "Running..." : "Run Attack"}
          </button>

          {liveResult && (
            <div className="pa9-card-stack">
              <div className="pa9-metrics">
                <div>
                  <span>Live counter</span>
                  <strong>{formatNumber(animatedCount)}</strong>
                </div>
                <div>
                  <span>Expected 2^(n/2)</span>
                  <strong>{formatNumber(liveResult.expected)}</strong>
                </div>
                <div>
                  <span>Ratio eval/expected</span>
                  <strong>{formatNumber(liveResult.ratio)}</strong>
                </div>
                <div>
                  <span>Status</span>
                  <strong>{liveResult.found ? "Collision found" : "Not found"}</strong>
                </div>
              </div>

              {liveChartSeries.length > 0 && (
                <XYChart
                  series={liveChartSeries}
                  yMin={0}
                  yMax={1}
                  markerX={liveResult.expected}
                />
              )}

              {liveResult.found && (
                <div className="pa9-json-grid">
                  <div>
                    <h4>Collision pair</h4>
                    <p>x1: {liveResult.x1}</p>
                    <p>x2: {liveResult.x2}</p>
                    <p>H(x1)=H(x2): {liveResult.digest}</p>
                  </div>
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {activeTab === "toy" && (
        <section className="pa9-section">
          <p className="pa9-lead">
            Requirement check: run both naive and Floyd attacks on toy hash for n = 8, 12, 16.
          </p>

          <div className="pa9-inline-controls">
            <label>
              Trials per point
              <input
                type="number"
                min="1"
                value={toyTrials}
                onChange={(event) => setToyTrials(Number(event.target.value))}
              />
            </label>
            <button onClick={runToyStudy} disabled={loading} className="pa9-primary">
              {loading ? "Running..." : "Run Toy Benchmark"}
            </button>
          </div>

          {toyStudy?.rows && (
            <>
              <div className="pa9-table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Method</th>
                      <th>n</th>
                      <th>Mean eval</th>
                      <th>Expected</th>
                      <th>Ratio</th>
                    </tr>
                  </thead>
                  <tbody>
                    {toyStudy.rows.map((row) => (
                      <tr key={`${row.method}-${row.nBits}`}>
                        <td>{row.method}</td>
                        <td>{row.nBits}</td>
                        <td>{formatNumber(row.meanEvaluations)}</td>
                        <td>{formatNumber(row.expected)}</td>
                        <td>{formatNumber(row.ratio)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <XYChart series={toyPlotSeries} markerX={null} />
            </>
          )}
        </section>
      )}

      {activeTab === "dlp" && (
        <section className="pa9-section">
          <p className="pa9-lead">
            Requirement check: attack PA8 DLP hash truncated to n = 16 bits and report colliding inputs,
            evaluations, and ratio.
          </p>

          <div className="pa9-inline-controls">
            <label>
              Method
              <select value={dlpMethod} onChange={(event) => setDlpMethod(event.target.value)}>
                <option value="naive">Naive dictionary</option>
                <option value="floyd">Floyd cycle finding</option>
              </select>
            </label>
            <button onClick={runDlpAttack} disabled={loading} className="pa9-primary">
              {loading ? "Running..." : "Run Truncated DLP Attack"}
            </button>
          </div>

          {dlpResult && (
            <div className="pa9-card-stack">
              <div className="pa9-metrics">
                <div>
                  <span>Evaluations</span>
                  <strong>{formatNumber(dlpResult.evaluations)}</strong>
                </div>
                <div>
                  <span>Expected</span>
                  <strong>{formatNumber(dlpResult.expected)}</strong>
                </div>
                <div>
                  <span>Ratio</span>
                  <strong>{formatNumber(dlpResult.ratio)}</strong>
                </div>
                <div>
                  <span>Status</span>
                  <strong>{dlpResult.found ? "Collision found" : "Not found"}</strong>
                </div>
              </div>

              {dlpResult.found && (
                <div className="pa9-json-grid">
                  <div>
                    <h4>Collision pair (hex)</h4>
                    <p>x1: {dlpResult.x1}</p>
                    <p>x2: {dlpResult.x2}</p>
                    <p>Digest: {dlpResult.digest}</p>
                  </div>
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {activeTab === "grid" && (
        <section className="pa9-section">
          <p className="pa9-lead">
            Requirement check: run independent trials for n in {`{8,10,12,14,16}`} and compare empirical CDF
            with theoretical 1 - exp(-k(k-1)/2^(n+1)).
          </p>

          <div className="pa9-grid-3">
            <label>
              Hash
              <select value={gridHashType} onChange={(event) => setGridHashType(event.target.value)}>
                <option value="toy">Toy</option>
                <option value="dlp">DLP</option>
              </select>
            </label>

            <label>
              Method
              <select value={gridMethod} onChange={(event) => setGridMethod(event.target.value)}>
                <option value="naive">Naive</option>
                <option value="floyd">Floyd</option>
              </select>
            </label>

            <label>
              Trials
              <input
                type="number"
                min="1"
                value={gridTrials}
                onChange={(event) => setGridTrials(Number(event.target.value))}
              />
            </label>
          </div>

          <button onClick={runEmpiricalGrid} disabled={loading} className="pa9-primary">
            {loading ? "Running..." : "Run Empirical Grid"}
          </button>

          {gridData?.rows && (
            <>
              <div className="pa9-table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>n</th>
                      <th>Mean eval</th>
                      <th>Expected</th>
                      <th>Ratio</th>
                      <th>StdDev</th>
                    </tr>
                  </thead>
                  <tbody>
                    {gridData.rows.map((row) => (
                      <tr key={row.nBits}>
                        <td>{row.nBits}</td>
                        <td>{formatNumber(row.stats.mean)}</td>
                        <td>{formatNumber(row.stats.expected)}</td>
                        <td>{formatNumber(row.stats.ratioMean)}</td>
                        <td>{formatNumber(row.stats.stddev)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <label className="pa9-curve-picker">
                Curve for n =
                <select
                  value={gridSelectedBits}
                  onChange={(event) => setGridSelectedBits(Number(event.target.value))}
                >
                  {gridData.rows.map((row) => (
                    <option key={row.nBits} value={row.nBits}>
                      {row.nBits}
                    </option>
                  ))}
                </select>
              </label>

              {selectedGridCurve && (
                <XYChart
                  series={gridCurveSeries}
                  yMin={0}
                  yMax={1}
                  markerX={selectedGridCurve.curve.expected}
                />
              )}
            </>
          )}
        </section>
      )}

      {activeTab === "context" && (
        <section className="pa9-section">
          <p className="pa9-lead">
            Requirement check: contextualize collision work factors for MD5 (128-bit) and SHA-1 (160-bit).
          </p>

          <div className="pa9-inline-controls">
            <label>
              Hashes per second
              <input value={hashRate} onChange={(event) => setHashRate(event.target.value)} />
            </label>
            <button onClick={runContext} disabled={loading} className="pa9-primary">
              {loading ? "Running..." : "Compute Context"}
            </button>
          </div>

          {contextData?.rows && (
            <div className="pa9-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Hash</th>
                    <th>n</th>
                    <th>2^(n/2)</th>
                    <th>Seconds at rate</th>
                    <th>Years at rate</th>
                  </tr>
                </thead>
                <tbody>
                  {contextData.rows.map((row) => (
                    <tr key={row.hash}>
                      <td>{row.hash}</td>
                      <td>{row.nBits}</td>
                      <td>{formatNumber(row.work)}</td>
                      <td>{formatNumber(row.secondsAtGivenRate)}</td>
                      <td>{formatNumber(row.yearsAtGivenRate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
