import React from "react";
import { useTheme } from "../../context/AppContext.jsx";

export default function PriorityPill({ tier }) {
  const { dark } = useTheme();
  const label = tier || "Backlog";
  const color =
    label === "Review First"
      ? "#e0364c"
      : label === "Review Soon"
        ? "#ef7a3c"
        : label === "Severity Watch"
          ? "#d6a312"
          : "#64748b";

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        minWidth: 92,
        padding: "5px 8px",
        borderRadius: 999,
        background: color + (dark ? "22" : "15"),
        color,
        border: `1px solid ${color}${dark ? "33" : "25"}`,
        fontSize: 10.5,
        fontWeight: 900,
        letterSpacing: "0.01em",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}
