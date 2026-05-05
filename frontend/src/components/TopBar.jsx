import "./TopBar.css";

export default function TopBar({ foundation, setFoundation }) {
  return (
    <div className="topbar">
      <h2>Minicrypt Explorer</h2>

      <div>
        <button onClick={() => setFoundation("AES")}>
          AES
        </button>
        <button onClick={() => setFoundation("DLP")}>
          DLP
        </button>
      </div>
    </div>
  );
}