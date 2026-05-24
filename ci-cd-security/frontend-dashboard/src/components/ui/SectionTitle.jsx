import React from "react";
import { useTheme } from "../../context/AppContext.jsx";
import { cardColors } from "./GlassCard.jsx";

export default function SectionTitle({ title, subtitle, right }) {
  const { dark } = useTheme();
  const c = cardColors(dark);

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "flex-start",
        gap: 14,
        marginBottom: 18,
      }}
    >
      <div>
        <h3 style={{ fontSize: 15, fontWeight: 800, color: c.text, margin: 0 }}>
          {title}
        </h3>

        {subtitle && (
          <p
            style={{
              fontSize: 12,
              color: c.sub,
              margin: "5px 0 0",
              lineHeight: 1.45,
            }}
          >
            {subtitle}
          </p>
        )}
      </div>

      {right || null}
    </div>
  );
}
