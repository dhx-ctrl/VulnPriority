import React from "react";
import { useTheme } from "../../context/AppContext.jsx";

export default function ScannerPill({ scanner }) {
  const { dark } = useTheme();
  const color =
    scanner === "DAST" ? "#9b6bff" : scanner === "SAST" ? "#4f7df3" : "#25a36b";

  return (
    <span
      style={{
        display: "inline-flex",
        justifyContent: "center",
        minWidth: 48,
        padding: "4px 8px",
        borderRadius: 8,
        background: color + (dark ? "1e" : "12"),
        color,
        fontSize: 11,
        fontWeight: 800,
        border: `1px solid ${color}${dark ? "30" : "20"}`,
      }}
    >
      {scanner || "SCA"}
    </span>
  );
}
