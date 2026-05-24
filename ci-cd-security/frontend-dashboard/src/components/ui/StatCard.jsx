import React from "react";
import { useTheme } from "../../context/AppContext.jsx";
import GlassCard, { cardColors } from "./GlassCard.jsx";

const BRAND_BLUE = "#4f7df3";

export default function StatCard({
  label,
  value,
  sub,
  accent = BRAND_BLUE,
  icon,
  delay = 0,
}) {
  const { dark } = useTheme();
  const c = cardColors(dark);

  return (
    <GlassCard
      hover={true}
      delay={delay}
      style={{
        padding: 18,
        position: "relative",
        overflow: "hidden",
        minHeight: 128,
      }}
    >
      <div
        style={{
          position: "absolute",
          top: -36,
          right: -36,
          width: 128,
          height: 128,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${accent}24, transparent 70%)`,
          pointerEvents: "none",
        }}
      />

      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          marginBottom: 16,
          position: "relative",
        }}
      >
        <div
          style={{
            fontSize: 11,
            fontWeight: 800,
            color: c.sub,
            textTransform: "uppercase",
            letterSpacing: "0.08em",
          }}
        >
          {label}
        </div>

        <div
          style={{
            width: 34,
            height: 34,
            borderRadius: 10,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: accent + (dark ? "22" : "14"),
            color: accent,
            fontSize: 16,
            fontWeight: 800,
          }}
        >
          {icon || "•"}
        </div>
      </div>

      <div
        className="num"
        style={{
          fontSize: 31,
          fontWeight: 800,
          color: c.text,
          lineHeight: 1,
          letterSpacing: "-0.035em",
          position: "relative",
        }}
      >
        {value}
      </div>

      {sub && (
        <div
          style={{
            fontSize: 12,
            color: c.sub,
            marginTop: 9,
            fontWeight: 500,
            position: "relative",
          }}
        >
          {sub}
        </div>
      )}
    </GlassCard>
  );
}
