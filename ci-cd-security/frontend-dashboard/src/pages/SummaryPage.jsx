// Summary Page — simple explanation of scanners, single AI model, and dashboard triage logic
import React from "react";
import { useTheme } from "../context/AppContext.jsx";

function SummaryPage() {
  const { dark } = useTheme();

  const t = dark ? "#e2e8f0" : "#1e293b";
  const sub = dark ? "#94a3b8" : "#64748b";
  const border = dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.05)";
  const raisedBg = dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.02)";
  const accentDim = dark ? "rgba(56,132,244,0.10)" : "rgba(56,132,244,0.06)";
  const accentBorder = dark ? "rgba(56,132,244,0.20)" : "rgba(56,132,244,0.15)";

  const colors = {
    red: "#ef4444",
    amber: "#f97316",
    blue: "#3884f4",
    green: "#22c55e",
    purple: "#9b6bff",
    gray: "#64748b",
  };

  function SectionTitle({ children }) {
    return (
      <h2 style={{ fontSize: 17, fontWeight: 800, color: t, margin: "0 0 12px" }}>
        {children}
      </h2>
    );
  }

  function DefCard({ title, badge, color = "#3884f4", children }) {
    return (
      <div style={{ background: raisedBg, border: `1px solid ${border}`, borderRadius: 12, padding: "16px 18px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: t }}>{title}</div>
          {badge && (
            <span
              style={{
                fontSize: 11,
                fontWeight: 750,
                padding: "2px 8px",
                borderRadius: 999,
                background: color + (dark ? "22" : "12"),
                color,
                border: `1px solid ${color}${dark ? "34" : "22"}`,
                whiteSpace: "nowrap",
              }}
            >
              {badge}
            </span>
          )}
        </div>
        <div style={{ fontSize: 13, color: sub, lineHeight: 1.62 }}>{children}</div>
      </div>
    );
  }

  function RuleBox({ children }) {
    return (
      <div
        style={{
          padding: "14px 18px",
          background: accentDim,
          border: `1px solid ${accentBorder}`,
          borderRadius: 12,
          fontSize: 13,
          lineHeight: 1.6,
          color: sub,
        }}
      >
        {children}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 28, maxWidth: 930 }}>
      <div>
        <h1 style={{ fontSize: 24, fontWeight: 850, color: t, margin: "0 0 4px", letterSpacing: "-0.02em" }}>
          Summary
        </h1>
        <p style={{ fontSize: 14, color: sub, margin: 0, lineHeight: 1.55 }}>
          VulnPriority imports scanner findings from DefectDojo, preserves the original scanner severity, and adds
          one v4 AI prioritization score for triage.
        </p>
      </div>

      <section>
        <SectionTitle>1. What the dashboard shows</SectionTitle>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 12 }}>
          <DefCard title="Scanner Severity" badge="Original" color={colors.amber}>
            Critical, High, Medium, and Low come from the scanner or DefectDojo. The AI does not rewrite this field.
          </DefCard>

          <DefCard title="AI Risk Score" badge="v4 model" color={colors.blue}>
            The single model returns <b>ai_probability</b>, <b>ai_risk_score</b>, <b>ai_risk_label</b>,
            <b> ai_decision</b>, and <b>ai_confidence</b>.
          </DefCard>

          <DefCard title="Review Priority" badge="Queue" color={colors.red}>
            Review First, Review Soon, Severity Watch, and Backlog are dashboard triage labels derived from the AI score
            and scanner severity.
          </DefCard>
        </div>
      </section>

      <section>
        <SectionTitle>2. Single-model AI workflow</SectionTitle>
        <RuleBox>
          The backend uses one XGBoost stacked ensemble v4 model. It replaces the previous two-model setup. The model is
          used for exploit-likelihood prioritization, while DefectDojo/scanner severity remains visible as separate
          evidence for the analyst.
        </RuleBox>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, minmax(0, 1fr))", gap: 10, marginTop: 12 }}>
          {[
            ["Precision", "0.7098", colors.green],
            ["Recall", "0.5957", colors.blue],
            ["F1", "0.6478", colors.purple],
            ["ROC-AUC", "0.9056", colors.blue],
            ["AUC-PR", "0.7387", colors.amber],
          ].map(([label, value, color]) => (
            <div
              key={label}
              style={{
                padding: "12px 14px",
                borderRadius: 12,
                border: `1px solid ${color}${dark ? "30" : "18"}`,
                background: color + (dark ? "14" : "08"),
              }}
            >
              <div style={{ fontSize: 11, color: sub, fontWeight: 800, textTransform: "uppercase" }}>{label}</div>
              <div className="num" style={{ fontSize: 22, color, fontWeight: 900, marginTop: 4 }}>{value}</div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionTitle>3. How to interpret the fields</SectionTitle>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <DefCard title="ai_probability" badge="Sort key" color={colors.blue}>
            This is the full-precision model probability. The findings table and queue should sort by it in descending
            order.
          </DefCard>

          <DefCard title="ai_risk_score" badge="Display" color={colors.purple}>
            This is the rounded 0–100 display score. It is easier to read but less precise than the probability.
          </DefCard>

          <DefCard title="ai_decision" badge="Boolean" color={colors.red}>
            True means the model predicts the finding should be treated as high risk according to the selected threshold.
          </DefCard>

          <DefCard title="ai_confidence" badge="Analyst cue" color={colors.amber}>
            High means far from the boundary; Low means borderline and should be checked carefully.
          </DefCard>
        </div>
      </section>

      <section>
        <SectionTitle>4. Practical triage rule</SectionTitle>
        <RuleBox>
          Start with <b>Review First</b> findings, especially when the AI score is high and the scanner severity is also
          High or Critical. Treat <b>Low</b> confidence as a prompt for manual review rather than automatic acceptance.
        </RuleBox>
      </section>
    </div>
  );
}

export default SummaryPage;
