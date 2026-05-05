import React, { useState } from 'react';
import './PA0Panel.css';

const PRIMITIVES = [
  { key: "OWF", pa: "PA1" },
  { key: "PRG", pa: "PA1" },
  { key: "PRF", pa: "PA2" },
  { key: "CPA-PKC", pa: "PA3" },
  { key: "CPA-SKE", pa: "PA3" },
  { key: "Modes", pa: "PA4" },
  { key: "MAC", pa: "PA5" },
  { key: "CCA-SKE", pa: "PA6" },
  { key: "MD", pa: "PA7" },
  { key: "CRHF", pa: "PA8" },
  { key: "Collision", pa: "PA9" },
  { key: "HMAC", pa: "PA10" },
];

const REDUCTIONS = {
  "PRG-OWF": { pa: "PA1", proof: "If you can break OWF, you can break PRG." },
  "PRF-PRG": { pa: "PA2", proof: "If you can distinguish PRF from random, you can distinguish PRG from random." },
  "CPA-SKE-PRF": { pa: "PA3", proof: "If you can break CPA-SKE, you can distinguish PRF." },
  "MAC-PRF": { pa: "PA5", proof: "If you can forge a MAC tag, you can distinguish the PRF." },
  "CCA-SKE-CPA-SKE": { pa: "PA6", proof: "If you can break CCA-SKE, you can break CPA-SKE." },
  "CRHF-OWF": { pa: "PA8", proof: "If you can find a collision in CRHF, you can break OWF." },
  "HMAC-CRHF": { pa: "PA10", proof: "If you can break HMAC, you can find a collision in CRHF." },
};

const PA0Panel = () => {
  const [foundation, setFoundation] = useState('AES');
  const [source, setSource] = useState('PRG');
  const [target, setTarget] = useState('OWF');
  const [bidirectional, setBidirectional] = useState(false);

  const getReductionPath = (src, tgt) => {
    const pathKey = `${src}-${tgt}`;
    if (REDUCTIONS[pathKey]) {
      return REDUCTIONS[pathKey];
    }
    return null;
  };

  const path = getReductionPath(source, target);

  return (
    <div className="pa0-panel">
      <div className="controls">
        <div className="foundation-toggle">
          <span>Foundation:</span>
          <button onClick={() => setFoundation('AES')} className={foundation === 'AES' ? 'active' : ''}>AES</button>
          <button onClick={() => setFoundation('DLP')} className={foundation === 'DLP' ? 'active' : ''}>DLP</button>
        </div>
        <div className="bidirectional-toggle">
          <label>
            <input type="checkbox" checked={bidirectional} onChange={() => setBidirectional(!bidirectional)} />
            Forward (A → B) / Backward (B → A)
          </label>
        </div>
      </div>

      <div className="panels">
        <div className="panel">
          <h3>Build Panel</h3>
          <p>Given a Foundation and a target source primitive A,
compute and display the full chain Foundation → A, showing each intermediate value.</p>
          <p><strong>Foundation:</strong> {foundation}</p>
          <div className="primitive-selector">
            <label>Source Primitive (A):</label>
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              {PRIMITIVES.map(p => <option key={p.key} value={p.key}>{p.key}</option>)}
            </select>
          </div>
          <div className="computation-steps">
            <p><i>Not implemented yet (due: PA#{PRIMITIVES.find(p => p.key === source)?.pa})</i></p>
          </div>
        </div>

        <div className="panel">
          <h3>Reduce Panel</h3>
          <p>Given the concrete instance of A produced by Column 1 and a target primitive B, compute and display the reduction A → B step by step.</p>
          <div className="primitive-selector">
            <label>Target Primitive (B):</label>
            <select value={target} onChange={(e) => setTarget(e.target.value)}>
              {PRIMITIVES.map(p => <option key={p.key} value={p.key}>{p.key}</option>)}
            </select>
          </div>
          <div className="computation-steps">
            {path ? (
              <p><i>Not implemented yet (due: PA#{path.pa})</i></p>
            ) : (
              <p className="error-message">No direct path exists in this direction. Try the bidirectional toggle.</p>
            )}
          </div>
        </div>
      </div>

      <div className="proof-summary">
        <h3>Proof Summary</h3>
        {path ? (
          <div>
            <p><strong>Reduction:</strong> {source} → {target}</p>
            <p><strong>Theorem:</strong> {path.proof}</p>
            <p><strong>PA Implemention:</strong> PA#{path.pa}</p>
          </div>
        ) : (
          <p>Select a valid reduction path.</p>
        )}
      </div>
    </div>
  );
};

export default PA0Panel;
