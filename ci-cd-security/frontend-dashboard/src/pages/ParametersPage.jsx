import React, { useEffect, useState } from "react";
import { useSettings, useTheme } from "../context/AppContext.jsx";
import { GlassCard } from "./DashboardPage.jsx";
import { apiClient } from "../services/api-client.js";

// Parameters Page — read-only model configuration + UI preferences.
// Model thresholds are loaded from backend metadata, not changed here.

function ParametersPage() {
  const { dark, toggle } = useTheme();
  const { settings, update } = useSettings();

  const [health, setHealth] = useState(null);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .getHealth()
      .then((h) => {
        if (!cancelled) setHealth(h);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const t = dark ? "#e2e8f0" : "#1e293b";
  const sub = dark ? "#94a3b8" : "#64748b";
  const border = dark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)";
  const inputBg = dark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.02)";

  const singleModel =
    health?.models?.single ||
    health?.models?.primary ||
    health?.model ||
    {};
  const modelName =
    singleModel.model ||
    health?.model_version ||
    health?.binary_model ||
    "XGBoost stacked ensemble (v4)";

  const threshold = Number(singleModel.threshold ?? health?.threshold ?? 0.386);
  const thresholdText = Number.isFinite(threshold) ? threshold.toFixed(4) : "metadata";

  const featureCount = Array.isArray(singleModel.features)
    ? singleModel.features.length
    : Array.isArray(health?.features)
      ? health.features.length
      : Array.isArray(health?.binary_features)
        ? health.binary_features.length
        : "metadata";

  function Section({ title, subtitle, children }) {
    return (
      <GlassCard style={{ marginBottom: 0 }}>
        <h3 style={{ fontSize: 16, fontWeight: 800, color: t, margin: "0 0 4px" }}>
          {title}
        </h3>

        {subtitle && (
          <p style={{ fontSize: 12, color: sub, margin: "0 0 18px", lineHeight: 1.5 }}>
            {subtitle}
          </p>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>{children}</div>
      </GlassCard>
    );
  }

  function Toggle({ label, desc, checked, onChange }) {
    return (
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16 }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: t }}>{label}</div>
          {desc && <div style={{ fontSize: 12, color: sub, marginTop: 4, lineHeight: 1.4 }}>{desc}</div>}
        </div>

        <button
          onClick={() => onChange(!checked)}
          style={{
            width: 44,
            height: 24,
            borderRadius: 12,
            border: "none",
            cursor: "pointer",
            flexShrink: 0,
            background: checked ? "#3884f4" : dark ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.1)",
            position: "relative",
            transition: "background 0.2s",
          }}
        >
          <span
            style={{
              position: "absolute",
              top: 3,
              left: checked ? 23 : 3,
              width: 18,
              height: 18,
              borderRadius: "50%",
              background: "#fff",
              transition: "left 0.2s",
              boxShadow: "0 1px 3px rgba(0,0,0,0.25)",
            }}
          />
        </button>
      </div>
    );
  }

  function InfoRow({ label, value, note }) {
    return (
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr auto",
          gap: 16,
          padding: "10px 0",
          borderBottom: `1px solid ${border}`,
        }}
      >
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: t }}>{label}</div>
          {note && <div style={{ fontSize: 12, color: sub, marginTop: 3, lineHeight: 1.4 }}>{note}</div>}
        </div>
        <div className="num" style={{ fontSize: 13, fontWeight: 850, color: t, textAlign: "right" }}>
          {value}
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20, maxWidth: 980 }}>
      <div>
        <h1 style={{ fontSize: 24, fontWeight: 850, color: t, margin: "0 0 4px" }}>Parameters</h1>
        <p style={{ fontSize: 14, color: sub, margin: 0, lineHeight: 1.5 }}>
          Read-only backend model configuration and local dashboard preferences.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 0.8fr", gap: 18 }}>
        <Section
          title="Single v4 AI Model"
          subtitle="The backend now loads one production model. It returns probability, score, label, decision, and confidence."
        >
          <InfoRow label="Model" value={modelName} note="Loaded from /api/health/." />
          <InfoRow label="Decision threshold" value={thresholdText} note="Default F1 operating point from metadata." />
          <InfoRow label="Feature columns" value={featureCount} note="Count read from feature_columns.json." />
          <InfoRow label="Primary sort key" value="ai_probability" note="Use full-precision probability for queue ordering." />
          <InfoRow label="Display score" value="ai_risk_score" note="Rounded 0–100 display value." />
          <InfoRow label="Confidence" value="ai_confidence" note="High / Medium / Low." />
        </Section>

        <Section title="Dashboard Preferences" subtitle="Local UI settings saved in your browser.">
          <Toggle
            label="Dark mode"
            desc="Switch between light and dark dashboard themes."
            checked={dark}
            onChange={toggle}
          />

          <Toggle
            label="Compact tables"
            desc="Reduce row spacing in findings-heavy views."
            checked={Boolean(settings.compactTables)}
            onChange={(value) => update({ compactTables: value })}
          />

          <Toggle
            label="Animated background"
            desc="Enable subtle login/dashboard background animation."
            checked={Boolean(settings.playful)}
            onChange={(value) => update({ playful: value })}
          />
        </Section>
      </div>

      <Section title="API / Backend Status" subtitle="Connection and authentication information.">
        <InfoRow label="Backend status" value={health?.status || "unknown"} />
        <InfoRow label="Database" value={health?.db || "metadata"} />
        <InfoRow label="Auth header" value={health?.auth?.header || "X-API-Key"} />
        <InfoRow label="Protected endpoints" value={health?.auth?.protected_endpoints_require_api_key ? "enabled" : "metadata"} />
      </Section>
    </div>
  );
}

export default ParametersPage;
