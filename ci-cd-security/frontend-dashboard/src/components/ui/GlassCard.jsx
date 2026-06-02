import React from "react";
import { useTheme } from "../../context/AppContext.jsx";

export function cardColors(dark) {
  return {
    text: dark ? "#e6ecf5" : "#0b1220",
    sub: dark ? "#98a8c0" : "#64748b",
    muted: dark ? "#5b6e8c" : "#8493a8",
    bg: dark ? "#0f1626" : "#ffffff",
    bg2: dark ? "#131c30" : "#fafbfd",
    border: dark ? "rgba(255,255,255,0.07)" : "rgba(15,23,42,0.08)",
    softBorder: dark ? "rgba(255,255,255,0.04)" : "rgba(15,23,42,0.05)",
    shadow: dark
      ? "0 12px 28px -18px rgba(0,0,0,0.75)"
      : "0 10px 28px -18px rgba(15,23,42,0.22)",
  };
}

export function GlassCard({ children, style, hover = false, delay = 0 }) {
  const { dark } = useTheme();
  const c = cardColors(dark);

  return (
    <div
      className={hover ? "card-in lift" : "card-in"}
      style={{
        animationDelay: `${delay}ms`,
        borderRadius: 16,
        padding: 22,
        background: c.bg,
        border: `1px solid ${c.border}`,
        boxShadow: c.shadow,
        transition: "all 0.22s ease",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

export default GlassCard;
