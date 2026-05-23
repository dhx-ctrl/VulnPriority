// Model Insights Page — single v4 AI model explanation
import React, { useEffect, useMemo, useState } from "react";
import {
  Bar as B2,
  BarChart as BC2,
  CartesianGrid as CG2,
  ResponsiveContainer as RC2,
  Tooltip as TT2,
  XAxis as XA2,
  YAxis as YA2,
} from "recharts";
import { useTheme } from "../context/AppContext.jsx";
import { apiClient } from "../services/api-client.js";
import { GlassCard } from "./DashboardPage.jsx";

function MetricRow({ label, value, note, accent }) {
  const { dark } = useTheme();
  const text = dark ? "#e2e8f0" : "#1e293b";
  const sub = dark ? "#94a3b8" : "#64748b";

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "1fr auto",
        gap: 12,
        padding: "10px 0",
        borderBottom: `1px solid ${dark ? "rgba(255,255,255,0.045)" : "rgba(15,23,42,0.055)"}`,
      }}
    >
      <div>
        <div style={{ fontSize: 13, color: sub, fontWeight: 700 }}>{label}</div>
        {note && (
          <div style={{ fontSize: 11, color: sub, opacity: 0.82, marginTop: 3, lineHeight: 1.35 }}>
            {note}
          </div>
        )}
      </div>
      <span className="num" style={{ fontSize: 14, fontWeight: 850, color: accent || text, textAlign: "right" }}>
        {value}
      </span>
    </div>
  );
}

function MiniBadge({ children, color = "#3884f4" }) {
  const { dark } = useTheme();
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "5px 9px",
        borderRadius: 999,
        background: color + (dark ? "22" : "12"),
        color,
        border: `1px solid ${color}${dark ? "34" : "22"}`,
        fontSize: 11,
        fontWeight: 800,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function InfoBox({ title, children, color = "#3884f4" }) {
  const { dark } = useTheme();
  const text = dark ? "#e2e8f0" : "#1e293b";
  return (
    <div
      style={{
        padding: 14,
        borderRadius: 12,
        background: color + (dark ? "18" : "08"),
        border: `1px solid ${color}${dark ? "30" : "18"}`,
      }}
    >
      <div style={{ fontSize: 13, fontWeight: 850, color, marginBottom: 7 }}>
        {title}
      </div>
      <div style={{ fontSize: 12.5, color: text, lineHeight: 1.55 }}>{children}</div>
    </div>
  );
}

function ConfusionMatrixV4() {
  const { dark } = useTheme();
  const sub = dark ? "#94a3b8" : "#64748b";

  const cells = [
    { label: "TN", value: 1128, row: 0, col: 0, color: "#22c55e", text: "Correctly left low-risk" },
    { label: "FP", value: 56, row: 0, col: 1, color: "#f97316", text: "Low-risk flagged high" },
    { label: "FN", value: 93, row: 1, col: 0, color: "#ef4444", text: "High-risk missed" },
    { label: "TP", value: 137, row: 1, col: 1, color: "#3884f4", text: "Correctly flagged high" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
      <div style={{ display: "flex", gap: 4, fontSize: 11, color: sub, marginBottom: 4 }}>
        <span style={{ width: 82 }} />
        <span style={{ width: 130, textAlign: "center" }}>Predicted Low</span>
        <span style={{ width: 130, textAlign: "center" }}>Predicted High</span>
      </div>

      {["Actual Low", "Actual High"].map((rowLabel, ri) => (
        <div key={rowLabel} style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <span style={{ width: 82, fontSize: 11, color: sub, textAlign: "right", paddingRight: 8 }}>
            {rowLabel}
          </span>
          {cells
            .filter((c) => c.row === ri)
            .map((c) => (
              <div
                key={c.label}
                style={{
                  width: 130,
                  minHeight: 86,
                  borderRadius: 10,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 4,
                  background: c.color + (dark ? "18" : "10"),
                  border: `1px solid ${c.color}${dark ? "30" : "22"}`,
                }}
              >
                <div style={{ fontSize: 12, fontWeight: 850, color: c.color }}>{c.label}</div>
                <div className="num" style={{ fontSize: 23, fontWeight: 900, color: c.color }}>{c.value}</div>
                <div style={{ fontSize: 10.5, color: sub, textAlign: "center", padding: "0 8px" }}>{c.text}</div>
              </div>
            ))}
        </div>
      ))}
    </div>
  );
}

function ModelInsightsPage() {
  const { dark } = useTheme();
  const [health, setHealth] = useState(null);

  useEffect(() => {
    let cancelled = false;
    apiClient.getHealth().then((h) => {
      if (!cancelled) setHealth(h);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const t = dark ? "#e2e8f0" : "#1e293b";
  const sub = dark ? "#94a3b8" : "#64748b";
  const border = dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.05)";

  const model =
    health?.models?.single ||
    health?.models?.primary ||
    health?.model ||
    {};
  const modelName =
    model.model ||
    health?.model_version ||
    health?.binary_model ||
    "XGBoost stacked ensemble (v4)";
  const threshold = Number(model.threshold ?? health?.threshold ?? 0.386);
  const features = Array.isArray(model.features)
    ? model.features.length
    : Array.isArray(health?.features)
      ? health.features.length
      : Array.isArray(health?.binary_features)
        ? health.binary_features.length
        : 51;

  const featureData = useMemo(() => [
    { name: "Text / metadata", value: 18 },
    { name: "Package", value: 4 },
    { name: "CWE", value: 3 },
    { name: "Scanner", value: 3 },
    { name: "Dates / counts", value: 23 },
  ], []);

  const tooltipStyle = {
    background: dark ? "#101827" : "#ffffff",
    border: `1px solid ${border}`,
    borderRadius: 10,
    fontSize: 12,
    color: t,
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22, maxWidth: 1120 }}>
      <div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
          <MiniBadge>Single v4 model</MiniBadge>
          <MiniBadge color="#22c55e">Scanner severity preserved</MiniBadge>
          <MiniBadge color="#9b6bff">Threshold {Number.isFinite(threshold) ? threshold.toFixed(3) : "metadata"}</MiniBadge>
        </div>

        <h1 style={{ fontSize: 24, fontWeight: 850, color: t, margin: "0 0 4px" }}>
          Model Insights
        </h1>
        <p style={{ fontSize: 14, color: sub, margin: 0, lineHeight: 1.55 }}>
          The dashboard now uses one v4 stacked model for vulnerability prioritization. It outputs probability,
          risk score, risk label, decision, and confidence. DefectDojo/scanner severity remains a separate field.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 14 }}>
        <GlassCard>
          <MetricRow label="Model" value={modelName} note="Loaded from the backend health endpoint." />
          <MetricRow label="Features" value={features} note="Feature count from feature_columns.json." />
          <MetricRow label="Decision threshold" value={Number.isFinite(threshold) ? threshold.toFixed(3) : "metadata"} note="Default F1 operating point." />
        </GlassCard>

        <GlassCard>
          <MetricRow label="Precision" value="0.7098" accent="#22c55e" note="Held-out test set." />
          <MetricRow label="Recall" value="0.5957" accent="#3884f4" note="Held-out test set." />
          <MetricRow label="F1" value="0.6478" accent="#9b6bff" note="Balanced default threshold." />
        </GlassCard>

        <GlassCard>
          <MetricRow label="ROC-AUC" value="0.9056" accent="#3884f4" note="Ranking quality over all thresholds." />
          <MetricRow label="AUC-PR" value="0.7387" accent="#f97316" note="More meaningful with class imbalance." />
          <MetricRow label="Accuracy" value="0.8946" accent="#22c55e" note="Held-out test set." />
        </GlassCard>

        <GlassCard>
          <MetricRow label="Primary sort key" value="ai_probability" note="Use this for queue ordering." />
          <MetricRow label="Display score" value="ai_risk_score" note="Rounded 0–100 value." />
          <MetricRow label="Confidence" value="ai_confidence" note="High / Medium / Low." />
        </GlassCard>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.05fr 0.95fr", gap: 18 }}>
        <GlassCard>
          <h3 style={{ fontSize: 16, fontWeight: 850, color: t, margin: "0 0 14px" }}>
            Test Confusion Matrix
          </h3>
          <ConfusionMatrixV4 />
        </GlassCard>

        <GlassCard>
          <h3 style={{ fontSize: 16, fontWeight: 850, color: t, margin: "0 0 14px" }}>
            Feature Groups
          </h3>
          <RC2 width="100%" height={245}>
            <BC2 data={featureData} margin={{ top: 8, right: 12, bottom: 4, left: -18 }}>
              <CG2 strokeDasharray="3 3" stroke={border} />
              <XA2 dataKey="name" tick={{ fill: sub, fontSize: 11 }} axisLine={false} tickLine={false} />
              <YA2 tick={{ fill: sub, fontSize: 11 }} axisLine={false} tickLine={false} />
              <TT2 contentStyle={tooltipStyle} />
              <B2 dataKey="value" fill="#3884f4" radius={[6, 6, 0, 0]} />
            </BC2>
          </RC2>
        </GlassCard>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 14 }}>
        <InfoBox title="What the model predicts">
          It predicts whether a vulnerability should be treated as high priority based on exploit-likelihood signals,
          metadata, scanner source, CWE family, package context, and text-derived indicators.
        </InfoBox>

        <InfoBox title="What the model does not replace" color="#f97316">
          Scanner severity, CVSS, and analyst judgment are still visible. The AI score is a prioritization layer, not a
          replacement for the original scanner finding.
        </InfoBox>

        <InfoBox title="How to read confidence" color="#9b6bff">
          High means the probability is far from the decision boundary. Low means the case is near the threshold and
          should be manually checked.
        </InfoBox>
      </div>
    </div>
  );
}

export default ModelInsightsPage;
