// Findings Page — single-model AI risk table, real backend data only
import React, { useState, useMemo, useEffect, useRef } from "react";
import { useTheme } from "../context/AppContext.jsx";
import { useData } from "../context/DataContext.jsx";
import { GlassCard } from "./DashboardPage.jsx";
function _num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function _maybeScore(v) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
const OPERATIONAL_PRIORITY = {
  REVIEW_FIRST_MIN: 20,
  REVIEW_SOON_MIN: 10,
};
function _rankScore(f) {
  return _num(f.ai_risk_score ?? f.risk_score ?? f.operational_rank_score, 0);
}
function _priorityWeight(priority) {
  if (priority === "Review First") return 4;
  if (priority === "Review Soon") return 3;
  if (priority === "Severity Watch") return 2;
  return 1;
}
function _priorityFromFinding(f) {
  if (f.priority_tier) return f.priority_tier;
  const rankScore = _rankScore(f);
  const aiFlag = Boolean(f.ai_decision ?? f.is_high_risk ?? f.operational_is_high_risk ?? f.clean_is_high_risk);
  const opAlert = Boolean(f.operational_is_high_risk ?? f.is_high_risk);
  const sev = String(f.scanner_severity || f.severity || "").toLowerCase();
  if (opAlert || rankScore >= OPERATIONAL_PRIORITY.REVIEW_FIRST_MIN) {
    return "Review First";
  }
  if (aiFlag || rankScore >= OPERATIONAL_PRIORITY.REVIEW_SOON_MIN) {
    return "Review Soon";
  }
  if (sev === "critical" || sev === "high") {
    return "Severity Watch";
  }
  return "Backlog";
}
function HoverText({
  text,
  children,
  style = {},
  mono = false,
  maxWidth = "100%",
}) {
  const timerRef = useRef(null);
  const tooltipRef = useRef(null);
  const value =
    text === undefined || text === null || text === "" ? "N/A" : String(text);
  const display =
    children !== undefined && children !== null ? children : value;
  const removeTooltip = () => {
    window.clearTimeout(timerRef.current);
    if (tooltipRef.current) {
      tooltipRef.current.remove();
      tooltipRef.current = null;
    }
  };
  const createTooltip = (targetEl) => {
    removeTooltip();
    const rect = targetEl.getBoundingClientRect();
    const tooltip = document.createElement("div");
    tooltip.textContent = value;
    tooltip.style.position = "fixed";
    tooltip.style.zIndex = "999999";
    tooltip.style.maxWidth = "320px";
    tooltip.style.padding = "8px 10px";
    tooltip.style.borderRadius = "10px";
    tooltip.style.background = "rgba(15,23,42,0.97)";
    tooltip.style.color = "#f8fafc";
    tooltip.style.border = "1px solid rgba(148,163,184,0.22)";
    tooltip.style.boxShadow = "0 14px 34px rgba(0,0,0,0.28)";
    tooltip.style.fontSize = "11px";
    tooltip.style.fontWeight = "650";
    tooltip.style.lineHeight = "1.35";
    tooltip.style.whiteSpace = "normal";
    tooltip.style.wordBreak = "break-word";
    tooltip.style.pointerEvents = "none";
    tooltip.style.opacity = "0";
    tooltip.style.transition = "opacity 0.12s ease, transform 0.12s ease";
    tooltip.style.transform = "translateY(3px)";
    document.body.appendChild(tooltip);
    const tipRect = tooltip.getBoundingClientRect();
    let left = rect.left;
    let top = rect.top - tipRect.height - 8;
    if (top < 8) top = rect.bottom + 8;
    if (left + tipRect.width > window.innerWidth - 8)
      left = window.innerWidth - tipRect.width - 8;
    if (left < 8) left = 8;
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
    requestAnimationFrame(() => {
      tooltip.style.opacity = "1";
      tooltip.style.transform = "translateY(0)";
    });
    tooltipRef.current = tooltip;
  };
  const showTip = (e) => {
    const targetEl = e.currentTarget;
    window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(() => createTooltip(targetEl), 300);
  };
  const hideTip = () => removeTooltip();
  useEffect(() => {
    return () => removeTooltip();
  }, []);
  return (
    <span
      onMouseEnter={showTip}
      onMouseLeave={hideTip}
      style={{
        display: "inline-block",
        width: "100%",
        maxWidth,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
        verticalAlign: "middle",
        fontFamily: mono
          ? "JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace"
          : undefined,
        cursor: value && value !== "N/A" ? "default" : "inherit",
        ...style,
      }}
    >
      {display}
    </span>
  );
}
function SevBadge({ severity }) {
  const colors = {
    Critical: "#ef4444",
    High: "#f97316",
    Medium: "#eab308",
    Low: "#22c55e",
  };
  const sev = severity || "Medium";
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        minWidth: 50,
        fontSize: 10,
        fontWeight: 800,
        padding: "3px 8px",
        borderRadius: 7,
        background: (colors[sev] || "#64748b") + "18",
        color: colors[sev] || "#64748b",
        lineHeight: 1,
      }}
    >
      {sev}
    </span>
  );
}
function ScanBadge({ type }) {
  const colors = {
    SAST: "#2563eb",
    SCA: "#06b6d4",
    DAST: "#f97316",
  };
  const label = type || "SCA";
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        minWidth: 44,
        fontSize: 10,
        fontWeight: 800,
        padding: "3px 7px",
        borderRadius: 7,
        background: (colors[label] || "#3884f4") + "15",
        color: colors[label] || "#3884f4",
        lineHeight: 1,
        letterSpacing: "0.02em",
      }}
    >
      {label}
    </span>
  );
}
function RiskBadge({ category }) {
  const { dark } = useTheme();
  const raw = String(category || "Low")
    .replace(/\s*Risk$/i, "")
    .trim();
  const risk = raw === "Critical" ? "High" : raw || "Low";
  const colors = {
    High: "#ef4444",
    Medium: "#eab308",
    Low: "#64748b",
  };
  const color = colors[risk] || colors.Low;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        minWidth: 50,
        fontSize: 10,
        fontWeight: 800,
        padding: "3px 8px",
        borderRadius: 7,
        background: color + (dark ? "20" : "14"),
        color,
        lineHeight: 1,
      }}
    >
      {risk}
    </span>
  );
}
function PriorityBadge({ priority }) {
  const { dark } = useTheme();
  const label = priority || "Backlog";
  const colors = {
    "Review First": "#ef4444",
    "Review Soon": "#f97316",
    "Severity Watch": "#eab308",
    Backlog: "#64748b",
  };
  const color = colors[label] || "#64748b";
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        maxWidth: "100%",
        fontSize: 10,
        fontWeight: 850,
        padding: "3px 8px",
        borderRadius: 7,
        background: color + (dark ? "22" : "14"),
        color,
        lineHeight: 1,
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}
function FindingsPage() {
  const { dark } = useTheme();
  const { findings } = useData();
  const allFindings = Array.isArray(findings) ? findings : [];
  const textColor = dark ? "#e2e8f0" : "#1e293b";
  const subColor = dark ? "#94a3b8" : "#64748b";
  const mutedColor = dark ? "#64748b" : "#94a3b8";
  const borderColor = dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.05)";
  const rowBgHover = dark ? "rgba(56,132,244,0.055)" : "rgba(56,132,244,0.035)";
  const [search, setSearch] = useState("");
  const [prodFilter, setProdFilter] = useState("All");
  const [scanFilter, setScanFilter] = useState("All");
  const [sevFilter, setSevFilter] = useState("All");
  const [highRiskOnly, setHighRiskOnly] = useState(false);
  const [page, setPage] = useState(0);
  const perPage = 30;
  const productOptions = useMemo(() => {
    const set = new Set();
    allFindings.forEach((f) => {
      if (f.product) set.add(f.product);
    });
    return ["All", ...[...set].sort()];
  }, [allFindings]);
  const scannerOptions = useMemo(() => {
    const set = new Set();
    allFindings.forEach((f) => {
      if (f.scanner_type) set.add(f.scanner_type);
    });
    return ["All", ...[...set].sort()];
  }, [allFindings]);
  const filtered = useMemo(() => {
    let data = allFindings;
    if (prodFilter !== "All")
      data = data.filter((f) => f.product === prodFilter);
    if (scanFilter !== "All")
      data = data.filter((f) => f.scanner_type === scanFilter);
    if (sevFilter !== "All")
      data = data.filter((f) => f.severity === sevFilter);
    if (highRiskOnly) {
      data = data.filter((f) => _priorityFromFinding(f) === "Review First");
    }
    if (search) {
      const s = search.toLowerCase();
      data = data.filter(
        (f) =>
          (f.cve_id || "").toLowerCase().includes(s) ||
          (f.title || "").toLowerCase().includes(s) ||
          (f.package_name || "").toLowerCase().includes(s) ||
          (f.file_path || "").toLowerCase().includes(s),
      );
    }
    return [...data].sort((a, b) => {
      const priorityDiff =
        _priorityWeight(_priorityFromFinding(b)) -
        _priorityWeight(_priorityFromFinding(a));
      if (priorityDiff !== 0) return priorityDiff;
      const bRank = _rankScore(b);
      const aRank = _rankScore(a);
      if (bRank !== aRank) return bRank - aRank;
      if (Boolean(b.AI_is_high_risk) !== Boolean(a.AI_is_high_risk)) {
        return Boolean(b.AI_is_high_risk) ? 1 : -1;
      }
      return _num(b.cvss_score, 0) - _num(a.cvss_score, 0);
    });
  }, [allFindings, search, prodFilter, scanFilter, sevFilter, highRiskOnly]);
  const paged = filtered.slice(page * perPage, (page + 1) * perPage);
  const totalPages = Math.max(1, Math.ceil(filtered.length / perPage));
  const selectStyle = {
    padding: "8px 12px",
    borderRadius: 10,
    border: `1px solid ${borderColor}`,
    fontSize: 13,
    background: dark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.02)",
    color: textColor,
    outline: "none",
  };
  const thStyle = {
    padding: "9px 10px",
    textAlign: "left",
    fontWeight: 850,
    color: subColor,
    fontSize: 9.5,
    textTransform: "uppercase",
    letterSpacing: "0.055em",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    borderBottom: `1px solid ${borderColor}`,
  };
  const tdBase = {
    padding: "7px 10px",
    verticalAlign: "middle",
    borderBottom: `1px solid ${borderColor}`,
    lineHeight: 1.18,
    height: 42,
  };
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 18,
      }}
    >
      <div>
        <h1
          style={{
            fontSize: 24,
            fontWeight: 800,
            color: textColor,
            margin: 0,
          }}
        >
          Findings
        </h1>
        <p
          style={{
            fontSize: 13,
            color: subColor,
            margin: "6px 0 0",
            lineHeight: 1.45,
          }}
        >
          All findings stay visible. The single v4 AI score sorts the queue; confidence highlights borderline predictions.
        </p>
      </div>
      <GlassCard style={{ padding: 14, borderLeft: "4px solid #3884f4" }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
            gap: 12,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                fontWeight: 800,
                color: subColor,
                textTransform: "uppercase",
                letterSpacing: "0.07em",
              }}
            >
              AI /100
            </div>
            <div
              style={{
                fontSize: 13,
                color: textColor,
                marginTop: 4,
                lineHeight: 1.4,
              }}
            >
              Single v4 model score used to order the review queue.
            </div>
          </div>
          <div>
            <div
              style={{
                fontSize: 11,
                fontWeight: 800,
                color: subColor,
                textTransform: "uppercase",
                letterSpacing: "0.07em",
              }}
            >
              Confidence
            </div>
            <div
              style={{
                fontSize: 13,
                color: textColor,
                marginTop: 4,
                lineHeight: 1.4,
              }}
            >
              Model confidence around the decision threshold.
            </div>
          </div>
          <div>
            <div
              style={{
                fontSize: 11,
                fontWeight: 800,
                color: subColor,
                textTransform: "uppercase",
                letterSpacing: "0.07em",
              }}
            >
              Scanner Severity
            </div>
            <div
              style={{
                fontSize: 13,
                color: textColor,
                marginTop: 4,
                lineHeight: 1.4,
              }}
            >
              Original DefectDojo/scanner severity, kept separate from AI
              priority.
            </div>
          </div>
        </div>
      </GlassCard>
      <GlassCard style={{ padding: 16 }}>
        <div
          style={{
            display: "flex",
            gap: 12,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <input
            placeholder="Search CVE, package, file, title..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            style={{
              ...selectStyle,
              flex: "1 1 200px",
              minWidth: 200,
            }}
          />
          <select
            value={prodFilter}
            onChange={(e) => {
              setProdFilter(e.target.value);
              setPage(0);
            }}
            style={selectStyle}
          >
            {productOptions.map((p) => (
              <option key={p} value={p}>
                {p === "All" ? "All Products" : p}
              </option>
            ))}
          </select>
          <select
            value={scanFilter}
            onChange={(e) => {
              setScanFilter(e.target.value);
              setPage(0);
            }}
            style={selectStyle}
          >
            {scannerOptions.map((s) => (
              <option key={s} value={s}>
                {s === "All" ? "All Scanners" : s}
              </option>
            ))}
          </select>
          <select
            value={sevFilter}
            onChange={(e) => {
              setSevFilter(e.target.value);
              setPage(0);
            }}
            style={selectStyle}
          >
            <option value="All">All Severities</option>
            {["Critical", "High", "Medium", "Low"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              fontSize: 13,
              color: subColor,
              cursor: "pointer",
            }}
          >
            <input
              type="checkbox"
              checked={highRiskOnly}
              onChange={(e) => {
                setHighRiskOnly(e.target.checked);
                setPage(0);
              }}
            />
            Review First only
          </label>
          <span
            style={{
              fontSize: 12,
              color: subColor,
              marginLeft: "auto",
            }}
          >{`${filtered.length} results`}</span>
        </div>
      </GlassCard>
      <GlassCard
        style={{
          padding: 0,
          overflow: "hidden",
        }}
      >
        <div style={{ overflowX: "auto" }}>
          <table
            style={{
              width: "100%",
              minWidth: 1260,
              borderCollapse: "collapse",
              tableLayout: "fixed",
              fontSize: 12,
            }}
          >
            <colgroup>
              <col style={{ width: 86 }} />
              <col style={{ width: 205 }} />
              <col style={{ width: 145 }} />
              <col style={{ width: 145 }} />
              <col style={{ width: 64 }} />
              <col style={{ width: 80 }} />
              <col style={{ width: 56 }} />
              <col style={{ width: 82 }} />
              <col style={{ width: 82 }} />
              <col style={{ width: 116 }} />
              <col style={{ width: 175 }} />
            </colgroup>
            <thead>
              <tr>
                {[
                  "Product",
                  "Finding",
                  "Package",
                  "File",
                  "Scan",
                  "Severity",
                  "CVSS",
                  "AI /100",
                  "Confidence",
                  "Priority",
                  "Action",
                ].map((h) => (
                  <th key={h} style={thStyle}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {paged.length === 0 && (
                <tr>
                  <td
                    colSpan={11}
                    style={{
                      textAlign: "center",
                      padding: "34px 24px",
                      color: subColor,
                      fontSize: 14,
                    }}
                  >
                    No findings match your filters.
                  </td>
                </tr>
              )}
              {paged.map((f) => {
                const rankScore = _rankScore(f);
                const confidenceScore = _maybeScore(f.ai_risk_score ?? f.risk_score ?? f.AI_ai_score);
                const cvss = _num(f.cvss_score, 0);
                const priority = _priorityFromFinding(f);
                const rankColor =
                  rankScore >= OPERATIONAL_PRIORITY.REVIEW_FIRST_MIN
                    ? "#ef4444"
                    : rankScore >= OPERATIONAL_PRIORITY.REVIEW_SOON_MIN
                      ? "#f97316"
                      : rankScore >= 5
                        ? "#eab308"
                        : textColor;
                const confidenceColor =
                  confidenceScore === null
                    ? mutedColor
                    : confidenceScore >= 70
                      ? "#ef4444"
                      : confidenceScore >= 40
                        ? "#f97316"
                        : textColor;
                return (
                  <tr
                    key={f.id}
                    className="tr-hover"
                    style={{
                      transition: "background 0.15s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = rowBgHover;
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "transparent";
                    }}
                  >
                    <td
                      style={{
                        ...tdBase,
                        fontWeight: 700,
                        color: textColor,
                      }}
                    >
                      <HoverText
                        text={f.product || "Unknown"}
                        maxWidth="100%"
                      />
                    </td>
                    <td style={tdBase}>
                      <HoverText
                        text={f.title || f.cve_id || "Finding"}
                        maxWidth="100%"
                        style={{
                          fontWeight: 700,
                          color: textColor,
                          fontSize: 12,
                        }}
                      />
                      <div style={{ height: 2 }} />
                      <HoverText
                        text={f.cve_id || "No CVE"}
                        maxWidth="100%"
                        mono={true}
                        style={{
                          fontSize: 10,
                          color: subColor,
                        }}
                      />
                    </td>
                    <td
                      style={{
                        ...tdBase,
                        color: subColor,
                      }}
                    >
                      <HoverText
                        text={f.package_name || "N/A"}
                        maxWidth="100%"
                      />
                    </td>
                    <td
                      style={{
                        ...tdBase,
                        color: subColor,
                      }}
                    >
                      <HoverText
                        text={f.file_path || "N/A"}
                        mono={true}
                        maxWidth="100%"
                        style={{
                          fontSize: 10.5,
                        }}
                      />
                    </td>
                    <td style={tdBase}>
                      <ScanBadge type={f.scanner_type} />
                    </td>
                    <td style={tdBase}>
                      <SevBadge severity={f.severity} />
                    </td>
                    <td
                      style={{
                        ...tdBase,
                        fontWeight: 800,
                        color: textColor,
                      }}
                    >
                      {cvss.toFixed(1)}
                    </td>
                    <td
                      style={{
                        ...tdBase,
                        fontWeight: 900,
                        color: rankColor,
                      }}
                    >
                      {rankScore.toFixed(1)}
                    </td>
                    <td
                      style={{
                        ...tdBase,
                        fontWeight: 900,
                        color: confidenceColor,
                      }}
                    >
                      {f.ai_confidence || (confidenceScore === null ? "—" : confidenceScore.toFixed(1))}
                    </td>
                    <td style={tdBase}>
                      <PriorityBadge priority={priority} />
                    </td>
                    <td
                      style={{
                        ...tdBase,
                        color: subColor,
                      }}
                    >
                      <HoverText
                        text={
                          f.next_action ||
                          f.fix_recommendation ||
                          "Review according to AI risk, AI AI flag, CVSS, and scanner severity"
                        }
                        maxWidth="100%"
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "11px 16px",
            borderTop: `1px solid ${borderColor}`,
          }}
        >
          <span
            style={{
              fontSize: 12,
              color: subColor,
            }}
          >{`Page ${page + 1} of ${totalPages}`}</span>
          <div
            style={{
              display: "flex",
              gap: 8,
            }}
          >
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              style={{
                padding: "6px 13px",
                borderRadius: 8,
                border: `1px solid ${borderColor}`,
                background: "transparent",
                color: textColor,
                cursor: page === 0 ? "not-allowed" : "pointer",
                fontSize: 13,
                opacity: page === 0 ? 0.4 : 1,
              }}
            >
              ← Prev
            </button>
            <button
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              style={{
                padding: "6px 13px",
                borderRadius: 8,
                border: `1px solid ${borderColor}`,
                background: "transparent",
                color: textColor,
                cursor: page >= totalPages - 1 ? "not-allowed" : "pointer",
                fontSize: 13,
                opacity: page >= totalPages - 1 ? 0.4 : 1,
              }}
            >
              Next →
            </button>
          </div>
        </div>
      </GlassCard>
    </div>
  );
}
export { SevBadge, ScanBadge, HoverText };
export default FindingsPage;
