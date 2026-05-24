import React from "react";
import { useTheme } from "../../context/AppContext.jsx";
import { cardColors } from "./GlassCard.jsx";

export default function EmptyPanel({ text }) {
  const { dark } = useTheme();
  const c = cardColors(dark);

  return (
    <div
      style={{
        minHeight: 170,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        textAlign: "center",
        color: c.sub,
        fontSize: 13,
        border: `1px dashed ${c.border}`,
        borderRadius: 14,
        background: dark ? "rgba(255,255,255,0.015)" : "rgba(15,23,42,0.015)",
        padding: 20,
      }}
    >
      {text}
    </div>
  );
}
