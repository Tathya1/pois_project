import { useState } from "react";
import "./PA3Panel.css";

export default function PA3Panel() {
  const [m0, setM0] = useState("message0");
  const [m1, setM1] = useState("message1");
  const [reuseNonce, setReuseNonce] = useState(false);
  const [sessionId, setSessionId] = useState("");

  const [challenge, setChallenge] = useState(null);
  const [oracle0, setOracle0] = useState(null);
  const [oracle1, setOracle1] = useState(null);
  const [error, setError] = useState("");

  const [rounds, setRounds] = useState(0);
  const [wins, setWins] = useState(0);
  const [lastResult, setLastResult] = useState("");
  const [simulateResult, setSimulateResult] = useState(null);
  const [autoResult, setAutoResult] = useState(null);

  const resetGame = () => {
    setChallenge(null);
    setOracle0(null);
    setOracle1(null);
    setRounds(0);
    setWins(0);
    setLastResult("");
    setError("");
  };

  const ensureEqualLength = () => {
    if (m0.length !== m1.length) {
      setError("m0 and m1 must have equal length.");
      return false;
    }
    setError("");
    return true;
  };

  const fetchChallenge = async () => {
    if (!ensureEqualLength()) return;

    try {
      const res = await fetch("http://localhost:5000/cpa/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          m0,
          m1,
          reuseNonce,
          sessionId: sessionId || null,
        }),
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        setError(data.error || "Failed to create challenge.");
        return;
      }

      setError("");
      setSessionId(data.sessionId);
      setChallenge({ r: data.r, c: data.c });
      setLastResult("");
    } catch (err) {
      setError("Unable to reach the CPA server.");
    }
  };

  const guess = async (value) => {
    if (!sessionId) {
      setError("Start a challenge before guessing.");
      return;
    }
    try {
      const res = await fetch("http://localhost:5000/cpa/guess", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId, guess: value }),
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        setError(data.error || "Guess failed.");
        return;
      }

      const nextRounds = rounds + 1;
      const nextWins = wins + (data.correct ? 1 : 0);
      setRounds(nextRounds);
      setWins(nextWins);
      setError("");
      setLastResult(
        data.correct ? `✅ Correct (b = ${data.b})` : `❌ Wrong (b = ${data.b})`,
      );
    } catch (err) {
      setError("Unable to reach the CPA server.");
    }
  };

  const fetchOracle = async (message, setter) => {
    if (!sessionId) {
      setError("Start a challenge first so the oracle has a session.");
      return;
    }
    try {
      const res = await fetch("http://localhost:5000/cpa/oracle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId, message }),
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        setError(data.error || "Oracle encryption failed.");
        return;
      }

      setError("");
      setter({ r: data.r, c: data.c });
    } catch (err) {
      setError("Unable to reach the CPA server.");
    }
  };

  const simulateDummy = async () => {
    try {
      const res = await fetch("http://localhost:5000/cpa/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rounds: 20, oracleQueries: 50 }),
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        setError(data.error || "Simulation failed.");
        return;
      }
      setError("");
      setSimulateResult(data);
    } catch (err) {
      setError("Unable to reach the CPA server.");
    }
  };

  const runAutoRounds = async () => {
    try {
      const res = await fetch("http://localhost:5000/cpa/rounds", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rounds: 20, reuseNonce }),
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        setError(data.error || "Auto-run failed.");
        return;
      }
      setError("");
      setAutoResult(data);
    } catch (err) {
      setError("Unable to reach the CPA server.");
    }
  };

  const winRate = rounds ? wins / rounds : 0;
  const advantage = Math.abs(winRate - 0.5) * 2;

  return (
    <div className="panel">
      <h3>IND-CPA Game (PA#3)</h3>

      <div className="cpa-grid">
        <label>
          m0
          <input value={m0} onChange={(e) => setM0(e.target.value)} />
        </label>

        <label>
          m1
          <input value={m1} onChange={(e) => setM1(e.target.value)} />
        </label>

        <label className="cpa-toggle">
          <span>Reuse nonce (broken)</span>

          <div className="switch">
            <input
              type="checkbox"
              checked={reuseNonce}
              onChange={(e) => setReuseNonce(e.target.checked)}
            />
            <span className="slider"></span>
          </div>
        </label>

        <div className="cpa-row">
          <button onClick={fetchChallenge}>Encrypt Challenge</button>
          <button onClick={resetGame}>Reset</button>
        </div>

        {error && <p className="cpa-error">{error}</p>}

        {challenge && (
          <div className="output-box">
            <div>r = {challenge.r}</div>
            <div>c = {challenge.c}</div>
          </div>
        )}

        <div className="cpa-row">
          <button onClick={() => guess(0)}>Guess b = 0</button>
          <button onClick={() => guess(1)}>Guess b = 1</button>
        </div>

        {lastResult && <p className="cpa-result">{lastResult}</p>}

        <div className="cpa-stats">
          <div>Rounds: {rounds}</div>
          <div>Wins: {wins}</div>
          <div>Advantage: {advantage.toFixed(3)}</div>
        </div>

        <div className="cpa-row">
          <button onClick={() => fetchOracle(m0, setOracle0)}>
            Oracle Encrypt m0
          </button>
          <button onClick={() => fetchOracle(m1, setOracle1)}>
            Oracle Encrypt m1
          </button>
        </div>

        {oracle0 && (
          <div className="output-box">
            <div>Oracle m0: r = {oracle0.r}</div>
            <div>c = {oracle0.c}</div>
          </div>
        )}

        {oracle1 && (
          <div className="output-box">
            <div>Oracle m1: r = {oracle1.r}</div>
            <div>c = {oracle1.c}</div>
          </div>
        )}

        <div className="cpa-row">
          <button onClick={simulateDummy}>
            Simulate Dummy Adversary (50 oracle queries)
          </button>
          <button onClick={runAutoRounds}>Auto-run 20 Rounds</button>
        </div>

        {simulateResult && (
          <div className="output-box">
            Dummy advantage: {simulateResult.advantage.toFixed(3)}
          </div>
        )}

        {autoResult && (
          <div className="output-box">
            Auto advantage: {autoResult.advantage.toFixed(3)}
          </div>
        )}
      </div>
    </div>
  );
}
