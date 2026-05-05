import { useState } from "react";
import PA0Panel from "./components/PA0Panel";
import PA1Panel  from "./components/PA1Panel";
import PA2Panel  from "./components/PA2Panel";
import PA3Panel  from "./components/PA3Panel";
import PA4Panel  from "./components/PA4Panel";
import PA5Panel  from "./components/PA5Panel";
import PA6Panel  from "./components/PA6Panel";
import PA7Panel  from "./components/PA7Panel";
import PA8Panel  from "./components/PA8Panel";
import PA9Panel  from "./components/PA9Panel";
import PA10Panel from "./components/PA10Panel";
import PA11Panel from "./components/PA11Panel";
import PA12Panel from "./components/PA12Panel";
import PA13Panel from "./components/PA13Panel";
import PA14Panel from "./components/PA14Panel";
import PA15Panel from "./components/PA15Panel";
import PA16Panel from "./components/PA16Panel";
import PA17Panel from "./components/PA17Panel";
import PA18Panel from "./components/PA18Panel";
import PA19Panel from "./components/PA19Panel";
import PA20Panel from "./components/PA20Panel";

const NAV = [
  { key: "PA0",  label: "Reductions (PA#0)", group: "minicrypt" },
  { key: "PA1",  label: "PRG (PA#1)",        group: "minicrypt" },
  { key: "PA2",  label: "PRF (PA#2)",        group: "minicrypt" },
  { key: "PA3",  label: "CPA (PA#3)",        group: "minicrypt" },
  { key: "PA4",  label: "Modes (PA#4)",      group: "minicrypt" },
  { key: "PA5",  label: "MAC (PA#5)",        group: "minicrypt" },
  { key: "PA6",  label: "CCA (PA#6)",        group: "minicrypt" },
  { key: "PA7",  label: "MD Hash (PA#7)",    group: "minicrypt" },
  { key: "PA8",  label: "CRHF (PA#8)",       group: "minicrypt" },
  { key: "PA9",  label: "Collision (PA#9)",  group: "minicrypt" },
  { key: "PA10", label: "HMAC (PA#10)",      group: "minicrypt" },
  { key: "PA13", label: "Primality (PA#13)", group: "cryptomania" },
  { key: "PA14", label: "CRT (PA#14)",       group: "cryptomania" },
  { key: "PA11", label: "DH (PA#11)",        group: "cryptomania" },
  { key: "PA12", label: "RSA (PA#12)",       group: "cryptomania" },
  { key: "PA15", label: "Signatures (PA#15)",group: "cryptomania" },
  { key: "PA16", label: "ElGamal (PA#16)",   group: "cryptomania" },
  { key: "PA17", label: "CCA PKC (PA#17)",   group: "cryptomania" },
  { key: "PA18", label: "OT (PA#18)",        group: "mpc" },
  { key: "PA19", label: "AND Gate (PA#19)",  group: "mpc" },
  { key: "PA20", label: "MPC (PA#20)",       group: "mpc" },
];

const GROUP_COLORS = {
  minicrypt:   "#0ea5e9",
  cryptomania: "#6366f1",
  mpc:         "#8b5cf6",
};

function App() {
  const [view, setView] = useState("PA1");

  return (
    <div className="container">

      {/* Navigation */}
      <div style={{ marginBottom: "20px", display: "flex", flexWrap: "wrap", gap: 6 }}>
        {NAV.map(({ key, label, group }) => (
          <button
            key={key}
            onClick={() => setView(key)}
            style={{
              background: view === key
                ? (GROUP_COLORS[group] ?? "#6366f1")
                : "#1e293b",
              color: view === key ? "#fff" : "#94a3b8",
              border: `1px solid ${view === key ? "transparent" : "#334155"}`,
              borderRadius: 6,
              padding: "6px 14px",
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Panels */}
      {view === "PA1"  && <PA1Panel />}
      {view === "PA2"  && <PA2Panel />}
      {view === "PA3"  && <PA3Panel />}
      {view === "PA4"  && <PA4Panel />}
      {view === "PA5"  && <PA5Panel />}
      {view === "PA6"  && <PA6Panel />}
      {view === "PA7"  && <PA7Panel />}
      {view === "PA8"  && <PA8Panel />}
      {view === "PA9"  && <PA9Panel />}
      {view === "PA10" && <PA10Panel />}
      {view === "PA11" && <PA11Panel />}
      {view === "PA12" && <PA12Panel />}
      {view === "PA13" && <PA13Panel />}
      {view === "PA14" && <PA14Panel />}
      {view === "PA15" && <PA15Panel />}
      {view === "PA16" && <PA16Panel />}
      {view === "PA17" && <PA17Panel />}
      {view === "PA18" && <PA18Panel />}
      {view === "PA19" && <PA19Panel />}
      {view === "PA20" && <PA20Panel />}
      {view === "PA0"  && <PA0Panel />}

    </div>
  );
}

export default App;