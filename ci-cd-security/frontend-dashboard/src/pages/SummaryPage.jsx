// Summary Page — simple explanation of scanners, dual AI models, and dashboard triage logic
import React from 'react';
import { useTheme } from '../context/AppContext.jsx';

function SummaryPage() {
  const { dark } = useTheme();

  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';
  const border = dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)';
  const raisedBg = dark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)';
  const accentDim = dark ? 'rgba(56,132,244,0.10)' : 'rgba(56,132,244,0.06)';
  const accentBorder = dark ? 'rgba(56,132,244,0.20)' : 'rgba(56,132,244,0.15)';

  const sevColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    blue: '#3884f4',
    purple: '#9b6bff',
    gray: '#64748b',
  };

  const sevBg = s => (sevColors[s] || '#64748b') + (dark ? '16' : '10');

  function SectionTitle({ children }) {
    return (
      <h2 style={{ fontSize: 17, fontWeight: 800, color: t, margin: '0 0 12px' }}>
        {children}
      </h2>
    );
  }

  function DefCard({ title, badge, color = '#3884f4', children }) {
    return (
      <div
        style={{
          background: raisedBg,
          border: `1px solid ${border}`,
          borderRadius: 12,
          padding: '16px 18px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: t }}>{title}</div>

          {badge && (
            <span
              style={{
                fontSize: 11,
                fontWeight: 750,
                padding: '2px 8px',
                borderRadius: 999,
                background: color + (dark ? '22' : '12'),
                color,
                border: `1px solid ${color}${dark ? '34' : '22'}`,
                whiteSpace: 'nowrap',
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
          padding: '14px 18px',
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 28, maxWidth: 900 }}>
      <div>
        <h1
          style={{
            fontSize: 24,
            fontWeight: 850,
            color: t,
            margin: '0 0 4px',
            letterSpacing: '-0.02em',
          }}
        >
          Summary
        </h1>

        <p style={{ fontSize: 14, color: sub, margin: 0, lineHeight: 1.55 }}>
          What each scanner does, what the two AI scores mean, and how to use the dashboard without confusing scanner severity with priority.
        </p>
      </div>

      <div>
        <SectionTitle>1. Scanner layer: detection</SectionTitle>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <DefCard title="Semgrep" badge="SAST" color="#3884f4">
            Static code analysis. It finds risky code patterns before the application runs.
          </DefCard>

          <DefCard title="Trivy" badge="SCA" color="#06b6d4">
            Dependency and container scanning. It finds vulnerable packages, libraries, and images.
          </DefCard>

          <DefCard title="OWASP ZAP" badge="DAST" color="#f97316">
            Dynamic web testing. It checks the running application through real HTTP requests.
          </DefCard>

          <DefCard title="DefectDojo" badge="hub" color="#9b6bff">
            Stores findings from all tools so the dashboard can sync, score, and display them in one place.
          </DefCard>
        </div>
      </div>

      <div>
        <SectionTitle>2. AI layer: prioritization</SectionTitle>

        <p style={{ fontSize: 14, color: sub, lineHeight: 1.7, marginBottom: 10 }}>
          The AI does not replace Semgrep, Trivy, ZAP, DefectDojo, CVSS, or analyst review. It adds a triage layer: which findings should be reviewed first.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <DefCard title="Operational EPSS Ranker" badge="Rank /100" color="#3884f4">
            This is the main dashboard sorting model. It produces the operational rank score used to order the review queue. Higher score means the finding should be reviewed earlier.
          </DefCard>

          <DefCard title="Clean Leakage-Safe Model" badge="Clean /100" color="#22c55e">
            This is the strict scientific confidence model. It avoids direct label signals such as EPSS score, CVSS score, scanner severity, raw IDs, exploit references, source metadata, and CVSS subcomponents.
          </DefCard>
        </div>
      </div>

      <div>
        <SectionTitle>3. Scanner severity vs AI priority</SectionTitle>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
          <DefCard title="Scanner Severity" color="#f97316">
            Original severity from the scanner or DefectDojo. It describes technical impact using scanner rules or CVSS-style reasoning.
          </DefCard>

          <DefCard title="AI Priority" color="#3884f4">
            Operational review priority from the AI ranker. It answers a different question: how early should this finding appear in the remediation queue?
          </DefCard>
        </div>

        <RuleBox>
          <strong style={{ color: t }}>Rule of thumb: </strong>
          use scanner severity and CVSS to understand impact. Use <strong style={{ color: t }}>Rank /100</strong> to sort the queue. Use <strong style={{ color: t }}>Clean /100</strong> as a secondary confidence signal.
        </RuleBox>
      </div>

      <div>
        <SectionTitle>4. Priority labels</SectionTitle>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {[
            {
              sev: 'critical',
              label: 'Review First',
              desc: 'Operational alert is true or Rank /100 is at least 70. These should be checked first.',
            },
            {
              sev: 'high',
              label: 'Review Soon',
              desc: 'Rank /100 is at least 30, or the clean model also flags the finding.',
            },
            {
              sev: 'medium',
              label: 'Severity Watch',
              desc: 'Scanner says High/Critical, but operational AI rank is low. Keep visible, but do not treat as AI emergency.',
            },
            {
              sev: 'gray',
              label: 'Backlog',
              desc: 'Lower operational priority. Track, monitor, or fix later depending on project context.',
            },
          ].map(s => (
            <div
              key={s.label}
              style={{
                background: sevBg(s.sev),
                borderRadius: 10,
                padding: '12px 16px',
                display: 'flex',
                gap: 10,
                alignItems: 'center',
              }}
            >
              <span
                style={{
                  fontSize: 11,
                  fontWeight: 800,
                  padding: '3px 10px',
                  borderRadius: 6,
                  background: (sevColors[s.sev] || sevColors.gray) + '20',
                  color: sevColors[s.sev] || sevColors.gray,
                  textTransform: 'uppercase',
                  flexShrink: 0,
                  whiteSpace: 'nowrap',
                }}
              >
                {s.label}
              </span>

              <span
                style={{
                  fontSize: 13,
                  fontWeight: 650,
                  color: sub,
                  lineHeight: 1.4,
                }}
              >
                {s.desc}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <SectionTitle>5. How to use the dashboard</SectionTitle>

        <p style={{ fontSize: 14, color: sub, lineHeight: 1.7, marginBottom: 10 }}>
          Start with the Dashboard <strong style={{ color: t }}>Review Queue</strong>. It is sorted by priority tier and operational rank score, so the highest-priority findings appear first.
        </p>

        <p style={{ fontSize: 14, color: sub, lineHeight: 1.7, marginBottom: 10 }}>
          Then open the Findings table. Compare <strong style={{ color: t }}>Severity</strong>, <strong style={{ color: t }}>CVSS</strong>, <strong style={{ color: t }}>Rank /100</strong>, and <strong style={{ color: t }}>Clean /100</strong>. A High scanner severity finding is not automatically the first item to fix if the operational rank score is low.
        </p>

        <p style={{ fontSize: 14, color: sub, lineHeight: 1.7 }}>
          Use Scan History for product-level overview. A product with medium or high average rank score should be marked for review, even if the strict operational alert threshold is not triggered.
        </p>
      </div>

      <div>
        <SectionTitle>6. Important limitation</SectionTitle>

        <RuleBox>
          The AI score is not a vulnerability detector. The scanners detect findings. The AI only helps prioritize them. Human review is still required, especially for business-critical systems, internet-facing services, authentication issues, and findings with uncertain exploitability.
        </RuleBox>
      </div>
    </div>
  );
}

export default SummaryPage;