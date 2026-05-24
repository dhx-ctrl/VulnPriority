import React from "react";
import { useTheme } from "../../context/AppContext.jsx";

const RISK_COLORS = {
  High: "#e0364c",
  Medium: "#d6a312",
  Low: "#25a36b",
};

export default function RiskPill({ category }) {
  const { dark } = useTheme();
  const risk = category || "Low";
  const color = RISK_COLORS[risk] || RISK_COLORS.Low;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        minWidth: 84,
        padding: "5px 10px",
        borderRadius: 999,
        background: color + (dark ? "22" : "15"),
        color,
        border: `1px solid ${color}${dark ? "33" : "25"}`,
        fontSize: 11,
        fontWeight: 800,
        letterSpacing: "0.02em",
      }}
    >
      {`${risk} Risk`}
    </span>
  );
}
