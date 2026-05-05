export default function ReducePanel() {
  return (
    <div className="panel">
      <h3>Reduce A → B</h3>

      <select>
        <option>PRF</option>
        <option>MAC</option>
      </select>

      <input placeholder="Enter query/message" />

      <div className="output-box">
        GGM: G1(G0(k)) <br />
        Output: 88d4...
      </div>
    </div>
  );
}