// Dashboard Page — polished visual refresh, current backend-safe logic preserved
import React, { useState, useEffect, useMemo } from 'react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { useTheme } from '../context/AppContext.jsx';
import { useData } from '../context/DataContext.jsx';
import { apiClient } from '../services/api-client.js';

const SEV_COLORS = { Critical: '#e0364c', High: '#ef7a3c', Medium: '#d6a312', Low: '#25a36b' };
const RISK_COLORS = { High: '#e0364c', Medium: '#d6a312', Low: '#25a36b' };
const BRAND_BLUE = '#4f7df3';

function _safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeRiskCategory(f) {
  const raw = String(f.risk_category || '').replace(/\s*Risk$/i, '').trim();
  if (raw === 'Critical' || raw === 'High') return 'High';
  if (raw === 'Medium') return 'Medium';
  if (raw === 'Low') return 'Low';
  const score = _safeNumber(f.risk_score);
  if (score >= 70) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

function cleanFlagged(f) {
  return Boolean(f.clean_is_high_risk);
}

function operationalScore(f) {
  return _safeNumber(f.operational_rank_score ?? f.risk_score, 0);
}

function scannerSeverityRank(f) {
  const s = String(f.severity || f.scanner_severity || f.defectdojo_severity || '').trim().toLowerCase();
  if (s === 'critical') return 4;
  if (s === 'high') return 3;
  if (s === 'medium') return 2;
  if (s === 'low') return 1;
  return 0;
}

function dashboardPriorityTier(f) {
  const score = operationalScore(f);

  if (Boolean(f.operational_is_high_risk) || score >= 70) {
    return 'Review First';
  }

  if (score >= 30 || cleanFlagged(f)) {
    return 'Review Soon';
  }

  if (scannerSeverityRank(f) >= 3) {
    return 'Severity Watch';
  }

  return 'Backlog';
}

function priorityRank(f) {
  const tier = dashboardPriorityTier(f);
  if (tier === 'Review First') return 4;
  if (tier === 'Review Soon') return 3;
  if (tier === 'Severity Watch') return 2;
  return 1;
}

function cardColors(dark) {
  return {
    text: dark ? '#e6ecf5' : '#0b1220',
    sub: dark ? '#98a8c0' : '#64748b',
    muted: dark ? '#5b6e8c' : '#8493a8',
    bg: dark ? '#0f1626' : '#ffffff',
    bg2: dark ? '#131c30' : '#fafbfd',
    border: dark ? 'rgba(255,255,255,0.07)' : 'rgba(15,23,42,0.08)',
    softBorder: dark ? 'rgba(255,255,255,0.04)' : 'rgba(15,23,42,0.05)',
    shadow: dark ? '0 12px 28px -18px rgba(0,0,0,0.75)' : '0 10px 28px -18px rgba(15,23,42,0.22)',
  };
}

function GlassCard({ children, style, hover = false, delay = 0 }) {
  const { dark } = useTheme();
  const c = cardColors(dark);
  return React.createElement('div', {
    className: hover ? 'card-in lift' : 'card-in',
    style: {
      animationDelay: `${delay}ms`,
      borderRadius: 16,
      padding: 22,
      background: c.bg,
      border: `1px solid ${c.border}`,
      boxShadow: c.shadow,
      transition: 'all 0.22s ease',
      ...style,
    },
  }, children);
}

function SectionTitle({ title, subtitle, right }) {
  const { dark } = useTheme();
  const c = cardColors(dark);
  return React.createElement('div', {
    style: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 14, marginBottom: 18 },
  },
    React.createElement('div', null,
      React.createElement('h3', { style: { fontSize: 15, fontWeight: 800, color: c.text, margin: 0 } }, title),
      subtitle && React.createElement('p', { style: { fontSize: 12, color: c.sub, margin: '5px 0 0', lineHeight: 1.45 } }, subtitle),
    ),
    right || null,
  );
}

function StatCard({ label, value, sub, accent = BRAND_BLUE, icon, delay = 0 }) {
  const { dark } = useTheme();
  const c = cardColors(dark);
  return React.createElement(GlassCard, { hover: true, delay, style: { padding: 18, position: 'relative', overflow: 'hidden', minHeight: 128 } },
    React.createElement('div', {
      style: {
        position: 'absolute', top: -36, right: -36, width: 128, height: 128, borderRadius: '50%',
        background: `radial-gradient(circle, ${accent}24, transparent 70%)`, pointerEvents: 'none',
      },
    }),
    React.createElement('div', { style: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16, position: 'relative' } },
      React.createElement('div', { style: { fontSize: 11, fontWeight: 800, color: c.sub, textTransform: 'uppercase', letterSpacing: '0.08em' } }, label),
      React.createElement('div', {
        style: {
          width: 34, height: 34, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: accent + (dark ? '22' : '14'), color: accent, fontSize: 16, fontWeight: 800,
        },
      }, icon || '•'),
    ),
    React.createElement('div', { className: 'num', style: { fontSize: 31, fontWeight: 800, color: c.text, lineHeight: 1, letterSpacing: '-0.035em', position: 'relative' } }, value),
    sub && React.createElement('div', { style: { fontSize: 12, color: c.sub, marginTop: 9, fontWeight: 500, position: 'relative' } }, sub),
  );
}

function RiskPill({ category }) {
  const { dark } = useTheme();
  const risk = category || 'Low';
  const color = RISK_COLORS[risk] || RISK_COLORS.Low;
  return React.createElement('span', {
    style: {
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      minWidth: 84, padding: '5px 10px', borderRadius: 999,
      background: color + (dark ? '22' : '15'), color,
      border: `1px solid ${color}${dark ? '33' : '25'}`,
      fontSize: 11, fontWeight: 800, letterSpacing: '0.02em',
    },
  }, `${risk} Risk`);
}

function ScannerPill({ scanner }) {
  const { dark } = useTheme();
  const color = scanner === 'DAST' ? '#9b6bff' : scanner === 'SAST' ? '#4f7df3' : '#25a36b';
  return React.createElement('span', {
    style: {
      display: 'inline-flex', justifyContent: 'center', minWidth: 48,
      padding: '4px 8px', borderRadius: 8,
      background: color + (dark ? '1e' : '12'), color,
      fontSize: 11, fontWeight: 800,
      border: `1px solid ${color}${dark ? '30' : '20'}`,
    },
  }, scanner || 'SCA');
}

function PriorityPill({ tier }) {
  const { dark } = useTheme();
  const label = tier || 'Backlog';
  const color = label === 'Review First' ? '#e0364c'
    : label === 'Review Soon' ? '#ef7a3c'
    : label === 'Severity Watch' ? '#d6a312'
    : '#64748b';

  return React.createElement('span', {
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      minWidth: 92,
      padding: '5px 8px',
      borderRadius: 999,
      background: color + (dark ? '22' : '15'),
      color,
      border: `1px solid ${color}${dark ? '33' : '25'}`,
      fontSize: 10.5,
      fontWeight: 900,
      letterSpacing: '0.01em',
      whiteSpace: 'nowrap',
    },
  }, label);
}

function EmptyPanel({ text }) {
  const { dark } = useTheme();
  const c = cardColors(dark);
  return React.createElement('div', {
    style: {
      minHeight: 170, display: 'flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center',
      color: c.sub, fontSize: 13, border: `1px dashed ${c.border}`, borderRadius: 14,
      background: dark ? 'rgba(255,255,255,0.015)' : 'rgba(15,23,42,0.015)', padding: 20,
    },
  }, text);
}

function DashboardPage() {
  const { dark } = useTheme();
  const c = cardColors(dark);
  const { findings, trends: trendRows } = useData();
  const trendsRaw = Array.isArray(trendRows) ? trendRows : [];
  const [health, setHealth] = useState(null);

  useEffect(() => {
    let cancelled = false;
    apiClient.getHealth().then(h => { if (!cancelled) setHealth(h); }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const total = findings.length;

  const sev = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    findings.forEach(f => {
      const s = f.scanner_severity || f.defectdojo_severity || f.predicted_severity || 'Medium';
      if (counts[s] !== undefined) counts[s] += 1;
    });
    return counts;
  }, [findings]);

  const scannerCounts = useMemo(() => {
    const counts = { SCA: 0, SAST: 0, DAST: 0 };
    findings.forEach(f => {
      const s = f.scanner_type || 'SCA';
      counts[s] = (counts[s] || 0) + 1;
    });
    return counts;
  }, [findings]);

  const reviewFirst = findings.filter(f => dashboardPriorityTier(f) === 'Review First').length;

  const cleanFlags = findings.filter(cleanFlagged).length;

  const avgRisk = total > 0
    ? (findings.reduce((a, f) => a + operationalScore(f), 0) / total).toFixed(1)
    : '0.0';

  const fixNow = useMemo(() => {
    const sorted = [...findings].sort((a, b) => {
      const tierDiff = priorityRank(b) - priorityRank(a);
      if (tierDiff !== 0) return tierDiff;

      const cleanDiff = Number(Boolean(b.clean_is_high_risk)) - Number(Boolean(a.clean_is_high_risk));
      if (cleanDiff !== 0) return cleanDiff;

      return operationalScore(b) - operationalScore(a);
    });
    return sorted.slice(0, 8);
  }, [findings]);

  const donutData = Object.entries(sev).map(([name, value]) => ({ name, value })).filter(d => d.value > 0);

  const barData = useMemo(() => {
    const byProduct = {};
    findings.forEach(f => {
      const p = f.product || 'Unknown';
      const s = f.scanner_severity || f.defectdojo_severity || f.predicted_severity || 'Medium';
      if (!byProduct[p]) byProduct[p] = { name: p, Critical: 0, High: 0, Medium: 0, Low: 0 };
      if (byProduct[p][s] !== undefined) byProduct[p][s] += 1;
    });
    return Object.values(byProduct).sort((a, b) => {
      const ta = a.Critical + a.High + a.Medium + a.Low;
      const tb = b.Critical + b.High + b.Medium + b.Low;
      return tb - ta;
    }).slice(0, 8);
  }, [findings]);

  const trends = useMemo(() => trendsRaw.map(r => ({
    date: r.date,
    critical: r.critical ?? r.Critical ?? 0,
    high: r.high ?? r.High ?? 0,
    medium: r.medium ?? r.Medium ?? 0,
    low: r.low ?? r.Low ?? 0,
  })), [trendsRaw]);

  const tooltipStyle = {
    background: dark ? '#101827' : '#ffffff',
    border: `1px solid ${c.border}`,
    borderRadius: 12,
    fontSize: 12,
    boxShadow: c.shadow,
    color: c.text,
  };

  const cleanModel = health?.models?.clean || {};
  const rankerModel = health?.models?.operational_ranker || {};
  const rankerName = rankerModel.model || health?.binary_model || 'EPSS operational ranker';
  const cleanName = cleanModel.model || 'Leakage-safe clean model';

  const rankerThreshold = rankerModel.threshold ?? health?.threshold;
  const rankerThresholdDisplay = Number.isFinite(Number(rankerThreshold)) ? Number(rankerThreshold).toFixed(4) : 'metadata';
  const cleanThresholdDisplay = Number.isFinite(Number(cleanModel.threshold)) ? Number(cleanModel.threshold).toFixed(4) : 'metadata';

  const rankerFeatureCount = Array.isArray(rankerModel.features)
    ? rankerModel.features.length
    : Array.isArray(health?.binary_features) ? health.binary_features.length : 'metadata';

  const cleanFeatureCount = Array.isArray(cleanModel.features) ? cleanModel.features.length : 'metadata';
  
  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 22 } },
    React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 16 } },
      React.createElement('div', null,
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 9, marginBottom: 8 } },
          React.createElement('span', { className: 'pulse-dot', style: { width: 8, height: 8, borderRadius: '50%', background: '#16a571' } }),
          React.createElement('span', { style: { fontSize: 11, color: c.sub, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.08em' } }, 'Live local DevSecOps dashboard'),
        ),
        React.createElement('h1', { style: { fontSize: 28, fontWeight: 800, color: c.text, margin: 0, letterSpacing: '-0.035em' } }, 'Dashboard'),
        React.createElement('p', { style: { fontSize: 14, color: c.sub, margin: '6px 0 0' } }, 'AI-prioritized vulnerability overview from DefectDojo, Semgrep, Trivy, and ZAP.'),
      ),
      React.createElement('div', { style: { display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' } },
        ['SCA', 'SAST', 'DAST'].map(s => React.createElement('div', {
          key: s,
          style: {
            padding: '7px 10px', borderRadius: 999, border: `1px solid ${c.border}`,
            background: c.bg, color: c.sub, fontSize: 12, fontWeight: 700,
          },
        }, `${s}: `, React.createElement('span', { className: 'num', style: { color: c.text } }, scannerCounts[s] || 0))),
      ),
    ),

    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 14 } },
      React.createElement(StatCard, { label: 'Total Findings', value: total, sub: 'Stored local findings', accent: BRAND_BLUE, icon: '↻', delay: 0 }),
      React.createElement(StatCard, { label: 'Review First', value: reviewFirst, sub: 'Top operational priority', accent: '#e0364c', icon: '!', delay: 45 }),
      React.createElement(StatCard, { label: 'Clean AI Flags', value: cleanFlags, sub: 'Strict leakage-safe alerts', accent: '#9b6bff', icon: '✓', delay: 90 }),
      React.createElement(StatCard, { label: 'Avg Rank Score', value: avgRisk, sub: 'Operational score /100', accent: '#25a36b', icon: '↗', delay: 135 }),
    ),

    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: 'minmax(320px, 0.85fr) minmax(380px, 1.15fr)', gap: 18 } },
      React.createElement(GlassCard, { delay: 80, style: { minHeight: 330 } },
        React.createElement(SectionTitle, { title: 'Scanner Severity Distribution', subtitle: 'Original scanner / DefectDojo severity. This is separate from AI priority.' }),
        donutData.length === 0 ? React.createElement(EmptyPanel, { text: 'No severity data yet. Sync a DefectDojo product first.' }) :
          React.createElement(ResponsiveContainer, { width: '100%', height: 235 },
            React.createElement(PieChart, null,
              React.createElement(Pie, { data: donutData, cx: '50%', cy: '50%', innerRadius: 62, outerRadius: 92, paddingAngle: 4, dataKey: 'value', stroke: 'none' },
                donutData.map(d => React.createElement(Cell, { key: d.name, fill: SEV_COLORS[d.name] })),
              ),
              React.createElement(Tooltip, { contentStyle: tooltipStyle }),
              React.createElement(Legend, { wrapperStyle: { fontSize: 12, color: c.sub } }),
            ),
          ),
      ),

      React.createElement(GlassCard, { delay: 120, style: { minHeight: 330 } },
        React.createElement(SectionTitle, { title: 'Findings by Product', subtitle: 'Real synced product names, grouped dynamically.' }),
        barData.length === 0 ? React.createElement(EmptyPanel, { text: 'No product data yet. Use the Sync page to fetch findings.' }) :
          React.createElement(ResponsiveContainer, { width: '100%', height: 235 },
            React.createElement(BarChart, { data: barData, margin: { top: 8, right: 8, bottom: 0, left: -16 } },
              React.createElement(CartesianGrid, { strokeDasharray: '3 3', stroke: c.softBorder }),
              React.createElement(XAxis, { dataKey: 'name', tick: { fill: c.sub, fontSize: 11 }, axisLine: false, tickLine: false }),
              React.createElement(YAxis, { tick: { fill: c.sub, fontSize: 11 }, axisLine: false, tickLine: false }),
              React.createElement(Tooltip, { contentStyle: tooltipStyle }),
              Object.keys(SEV_COLORS).map(s => React.createElement(Bar, { key: s, dataKey: s, fill: SEV_COLORS[s], radius: [5, 5, 0, 0], stackId: 'a' })),
            ),
          ),
      ),
    ),

    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: 'minmax(420px, 1.2fr) minmax(300px, 0.8fr)', gap: 18 } },
      React.createElement(GlassCard, { delay: 160, style: { minHeight: 330 } },
        React.createElement(SectionTitle, { title: 'Findings Trend', subtitle: 'Weekly severity movement from backend trend endpoint.' }),
        trends.length === 0 ? React.createElement(EmptyPanel, { text: 'No trend data available yet.' }) :
          React.createElement(ResponsiveContainer, { width: '100%', height: 235 },
            React.createElement(AreaChart, { data: trends, margin: { top: 8, right: 12, bottom: 0, left: -16 } },
              React.createElement('defs', null,
                Object.keys(SEV_COLORS).map(s => React.createElement('linearGradient', { key: s, id: `grad${s}`, x1: '0', y1: '0', x2: '0', y2: '1' },
                  React.createElement('stop', { offset: '5%', stopColor: SEV_COLORS[s], stopOpacity: 0.22 }),
                  React.createElement('stop', { offset: '95%', stopColor: SEV_COLORS[s], stopOpacity: 0.02 }),
                )),
              ),
              React.createElement(CartesianGrid, { strokeDasharray: '3 3', stroke: c.softBorder }),
              React.createElement(XAxis, { dataKey: 'date', tick: { fill: c.sub, fontSize: 11 }, axisLine: false, tickLine: false }),
              React.createElement(YAxis, { tick: { fill: c.sub, fontSize: 11 }, axisLine: false, tickLine: false }),
              React.createElement(Tooltip, { contentStyle: tooltipStyle }),
              Object.keys(SEV_COLORS).map(s => React.createElement(Area, { key: s, type: 'monotone', dataKey: s.toLowerCase(), stroke: SEV_COLORS[s], fill: `url(#grad${s})`, strokeWidth: 2, dot: false })),
            ),
          ),
      ),

      React.createElement(GlassCard, { delay: 200, style: { minHeight: 330 } },
        React.createElement(SectionTitle, { title: 'Dual AI Model Status', subtitle: 'Operational ranker sorts the queue; clean model is a strict confidence signal.' }),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 12 } },
          React.createElement('div', { style: { padding: 14, borderRadius: 12, background: dark ? 'rgba(79,125,243,0.10)' : 'rgba(79,125,243,0.06)', border: `1px solid ${dark ? 'rgba(79,125,243,0.22)' : 'rgba(79,125,243,0.14)'}` } },
            React.createElement('div', { style: { fontSize: 13, fontWeight: 800, color: BRAND_BLUE, marginBottom: 9 } }, 'Operational Ranker'),
            [['Model', rankerName], ['Use', 'Main sorting score'], ['Threshold', rankerThresholdDisplay], ['Features', rankerFeatureCount]].map(([k, v]) =>
              React.createElement('div', { key: k, style: { display: 'flex', justifyContent: 'space-between', gap: 10, fontSize: 12, padding: '4px 0', color: c.text } },
                React.createElement('span', { style: { color: c.sub } }, k),
                React.createElement('span', { className: 'num', style: { fontWeight: 800, textAlign: 'right', maxWidth: 170, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, String(v)),
              )
            ),
          ),
          React.createElement('div', { style: { padding: 14, borderRadius: 12, background: dark ? 'rgba(155,107,255,0.10)' : 'rgba(155,107,255,0.06)', border: `1px solid ${dark ? 'rgba(155,107,255,0.22)' : 'rgba(155,107,255,0.14)'}` } },
            React.createElement('div', { style: { fontSize: 13, fontWeight: 800, color: '#9b6bff', marginBottom: 9 } }, 'Clean Leakage-Safe Model'),
            [['Model', cleanName], ['Use', 'Strict confidence flag'], ['Threshold', cleanThresholdDisplay], ['Features', cleanFeatureCount]].map(([k, v]) =>
              React.createElement('div', { key: k, style: { display: 'flex', justifyContent: 'space-between', gap: 10, fontSize: 12, padding: '4px 0', color: c.text } },
                React.createElement('span', { style: { color: c.sub } }, k),
                React.createElement('span', { style: { fontWeight: 800, textAlign: 'right', maxWidth: 170, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, String(v)),
              )
            ),
          ),
        ),
      ),
    ),

    React.createElement(GlassCard, { delay: 240 },
      React.createElement(SectionTitle, {
        title: 'Review Queue — Operational Ranking',
        subtitle: 'Sorted by priority tier, clean AI flag, then operational rank score. Scanner severity stays visible for context.',
        right: React.createElement('span', { style: { fontSize: 11, padding: '5px 10px', borderRadius: 999, background: 'rgba(224,54,76,0.12)', color: '#e0364c', fontWeight: 800 } }, `${fixNow.length} items`),
      }),
      fixNow.length === 0
        ? React.createElement(EmptyPanel, { text: 'No findings yet. Run a product sync to populate the priority list.' })
        : React.createElement('div', { style: { overflowX: 'auto' } },
            React.createElement('div', {
              style: {
                display: 'grid', gridTemplateColumns: '130px minmax(260px,1fr) 104px 80px 88px 72px', gap: 12,
                padding: '0 16px 10px', color: c.muted, fontSize: 10, fontWeight: 900, textTransform: 'uppercase', letterSpacing: '0.08em', minWidth: 780,
              },
            },
              React.createElement('div', null, 'Product'),
              React.createElement('div', null, 'Finding'),
              React.createElement('div', { style: { textAlign: 'center' } }, 'Priority'),
              React.createElement('div', { style: { textAlign: 'center' } }, 'Scanner'),
              React.createElement('div', { style: { textAlign: 'right' } }, 'Rank /100'),
              React.createElement('div', { style: { textAlign: 'right' } }, 'CVSS'),
            ),
            React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 9, minWidth: 760 } },
              fixNow.map((f, idx) => {
                const risk = normalizeRiskCategory(f);
                const riskScore = _safeNumber(f.risk_score);
                const cvss = _safeNumber(f.cvss_score);
                const severity = f.scanner_severity || f.defectdojo_severity || f.predicted_severity || 'Medium';
                const sevColor = SEV_COLORS[severity] || SEV_COLORS.Medium;
                return React.createElement('div', {
                  key: f.id || idx,
                  className: 'tr-hover',
                  style: {
                    display: 'grid', gridTemplateColumns: '130px minmax(260px,1fr) 104px 80px 88px 72px', alignItems: 'center', gap: 12,
                    padding: '13px 16px', borderRadius: 13,
                    background: dark ? 'rgba(255,255,255,0.025)' : '#ffffff',
                    border: `1px solid ${c.softBorder}`,
                    boxShadow: dark ? 'none' : '0 1px 2px rgba(15,23,42,0.035)',
                  },
                },
                  React.createElement('div', { style: { minWidth: 0 } },
                    React.createElement('div', { style: { fontSize: 12, fontWeight: 800, color: c.text, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, f.product || 'Unknown'),
                    React.createElement('div', { style: { fontSize: 10, color: c.muted, marginTop: 3 } }, f.source || 'defectdojo'),
                  ),
                  React.createElement('div', { style: { minWidth: 0 } },
                    React.createElement('div', { style: { fontSize: 13, fontWeight: 800, color: c.text, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, f.title || f.cve_id || 'Finding'),
                    React.createElement('div', { style: { fontSize: 11, color: c.sub, marginTop: 4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } },
                      `${f.cve_id || 'No CVE'} · ${f.package_name || 'N/A'} · `,
                      React.createElement('span', { style: { color: sevColor, fontWeight: 800 } }, `Scanner severity: ${severity}`),
                    ),
                  ),
                  React.createElement('div', { style: { textAlign: 'center' } }, React.createElement(PriorityPill, { tier: dashboardPriorityTier(f) })),
                  React.createElement('div', { style: { textAlign: 'center' } }, React.createElement(ScannerPill, { scanner: f.scanner_type || 'SCA' })),
                  React.createElement('div', { style: { textAlign: 'right' } },
                    React.createElement('div', { className: 'num', style: { fontSize: 17, fontWeight: 900, color: RISK_COLORS[risk] || RISK_COLORS.Low } }, riskScore.toFixed(1)),
                    React.createElement('div', { style: { fontSize: 10, color: c.muted, marginTop: 2 } }, '/100'),
                  ),
                  React.createElement('div', { style: { textAlign: 'right' } },
                    React.createElement('div', { className: 'num', style: { fontSize: 13, fontWeight: 800, color: c.text } }, cvss.toFixed(1)),
                    React.createElement('div', { style: { fontSize: 10, color: c.muted, marginTop: 2 } }, 'scanner'),
                  ),
                );
              }),
            ),
          ),
    ),
  );
}

export { GlassCard, StatCard, SEV_COLORS };
export default DashboardPage;