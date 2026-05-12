// Summary Page — Overview of scanners, AI model, and severity meanings

function SummaryPage() {
  const { dark } = useTheme();
  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';
  const muted = dark ? '#4a5d78' : '#8898b0';
  const border = dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)';
  const raisedBg = dark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)';
  const accentDim = dark ? 'rgba(56,132,244,0.10)' : 'rgba(56,132,244,0.06)';
  const accentBorder = dark ? 'rgba(56,132,244,0.20)' : 'rgba(56,132,244,0.15)';

  const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
  const sevBg = s => (sevColors[s] || '#64748b') + (dark ? '15' : '10');

  function SectionTitle({ children }) {
    return React.createElement('h2', { style: { fontSize: 17, fontWeight: 700, color: t, margin: '0 0 12px' } }, children);
  }

  function DefCard({ title, badge, children }) {
    return React.createElement('div', {
      style: { background: raisedBg, border: `1px solid ${border}`, borderRadius: 10, padding: '16px 18px' },
    },
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 } },
        React.createElement('div', { style: { fontSize: 13, fontWeight: 700, color: t } }, title),
        badge && React.createElement('span', {
          style: { fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 6, background: accentDim, color: '#3884f4', border: `1px solid ${accentBorder}` },
        }, badge),
      ),
      React.createElement('div', { style: { fontSize: 13, color: sub, lineHeight: 1.6 } }, children),
    );
  }

  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 28, maxWidth: 760 } },
    React.createElement('div', null,
      React.createElement('h1', { style: { fontSize: 24, fontWeight: 800, color: t, margin: '0 0 4px', letterSpacing: '-0.02em' } }, 'Summary'),
      React.createElement('p', { style: { fontSize: 14, color: sub, margin: 0 } }, 'How VulnPriority AI works — scanners, models, and what the scores mean'),
    ),

    // The Scanners
    React.createElement('div', null,
      React.createElement(SectionTitle, null, 'The Scanners'),
      React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 } },
        React.createElement(DefCard, { title: 'Semgrep', badge: 'SAST' },
          'Scans your source code for insecure patterns — hardcoded secrets, injection vulnerabilities, unsafe API calls. Runs without executing your code.',
        ),
        React.createElement(DefCard, { title: 'Trivy', badge: 'SCA' },
          'Checks your dependencies, containers, and config files against known vulnerability databases. Finds outdated packages and misconfigurations.',
        ),
        React.createElement(DefCard, { title: 'OWASP ZAP', badge: 'DAST' },
          'Probes your running application for web vulnerabilities — XSS, SQL injection, insecure headers — by sending real HTTP requests.',
        ),
        React.createElement(DefCard, { title: 'DefectDojo' },
          'Aggregates findings from all three scanners into one place. Without it you\'d have three separate reports to manually merge and de-duplicate every scan cycle.',
        ),
      ),
    ),

    // The AI Model
    React.createElement('div', null,
      React.createElement(SectionTitle, null, 'The AI Model'),
      React.createElement('p', { style: { fontSize: 14, color: sub, lineHeight: 1.7, marginBottom: 10 } },
        'Scanners assign severity based on rules. The AI re-ranks findings based on exploit likelihood and real-world risk — so you fix the ones that actually matter first, not just the ones with the highest CVSS score.',
      ),
      React.createElement('p', { style: { fontSize: 14, color: sub, lineHeight: 1.7 } },
        'A finding that scores 9.8 on CVSS but targets a code path that\'s never reachable in your application is less urgent than a 6.5 that\'s actively exploitable in your CI pipeline. The AI understands the difference.',
      ),
    ),

    // Severity vs AI Risk Score
    React.createElement('div', null,
      React.createElement(SectionTitle, null, 'Severity vs AI Risk Score'),
      React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 } },
        React.createElement(DefCard, { title: 'Scanner Severity' },
          'Based on the vulnerability\'s theoretical worst-case impact. Assigned by the scanner using CVSS rules. Doesn\'t know your specific environment.',
        ),
        React.createElement(DefCard, { title: 'AI Risk Score' },
          'Based on how likely this specific finding is to be exploited in your context. Considers exploit availability, reachability, and historical patterns.',
        ),
      ),
      React.createElement('div', {
        style: {
          padding: '14px 18px', background: accentDim, border: `1px solid ${accentBorder}`,
          borderRadius: 10, fontSize: 13, lineHeight: 1.6, color: sub,
        },
      },
        React.createElement('strong', { style: { color: t } }, 'Rule of thumb: '),
        'A Medium severity finding with a high AI risk score should be fixed before a High severity finding with a low AI risk score.',
      ),
    ),

    // Severity Levels
    React.createElement('div', null,
      React.createElement(SectionTitle, null, 'Severity Levels — What They Mean for You'),
      React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 } },
        [
          { sev: 'critical', label: 'Critical', desc: 'Fix today. Stop what you\'re doing.' },
          { sev: 'high', label: 'High', desc: 'Fix this sprint. Don\'t ship over it.' },
          { sev: 'medium', label: 'Medium', desc: 'Fix in your next maintenance window.' },
          { sev: 'low', label: 'Low', desc: 'Track it. Fix it when convenient.' },
        ].map(s =>
          React.createElement('div', {
            key: s.sev,
            style: {
              background: sevBg(s.sev), borderRadius: 10, padding: '12px 16px',
              display: 'flex', gap: 10, alignItems: 'center',
            },
          },
            React.createElement('span', {
              style: { fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 6, background: sevColors[s.sev] + '20', color: sevColors[s.sev], textTransform: 'uppercase', flexShrink: 0 },
            }, s.label),
            React.createElement('span', { style: { fontSize: 13, fontWeight: 600, color: sevColors[s.sev] } }, s.desc),
          ),
        ),
      ),
    ),

    // Where to Start
    React.createElement('div', null,
      React.createElement(SectionTitle, null, 'Where to Start'),
      React.createElement('p', { style: { fontSize: 14, color: sub, lineHeight: 1.7, marginBottom: 10 } },
        'Open the ',
        React.createElement('strong', { style: { color: t } }, 'Fix Now'),
        ' list on the Dashboard. It shows the findings with the highest AI risk scores that have an available fix right now.',
      ),
      React.createElement('p', { style: { fontSize: 14, color: sub, lineHeight: 1.7, marginBottom: 10 } },
        'Then work through the ',
        React.createElement('strong', { style: { color: t } }, 'Findings'),
        ' table filtered to Critical and High, sorted by AI risk score descending. That order is your roadmap.',
      ),
      React.createElement('p', { style: { fontSize: 14, color: sub, lineHeight: 1.7 } },
        'Use the ',
        React.createElement('strong', { style: { color: t } }, 'Scan History'),
        ' to track whether new issues are being introduced between sprints, and the ',
        React.createElement('strong', { style: { color: t } }, 'Parameters'),
        ' page to tune when builds get blocked vs. warned.',
      ),
    ),
  );
}

Object.assign(window, { SummaryPage });
