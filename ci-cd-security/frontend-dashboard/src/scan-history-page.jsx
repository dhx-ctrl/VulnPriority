// Scan History Page — groups real findings by product + date into scan-run rows.
const { useState, useMemo } = React;

// Build synthetic "scan run" records by grouping cached findings.
// Falls back to MOCK_SCAN_HISTORY when no real findings have been loaded yet.
function buildScanHistory(findings) {
  if (!findings || findings.length === 0) return window.MOCK_SCAN_HISTORY;

  // Group key: YYYY-MM-DD __ product __ source
  // This way, when there are multiple products (JuiceShop / DVWA) they show
  // up as separate rows even if synced on the same day.
  const groups = {};
  findings.forEach(f => {
    const day      = (f.created_at || '').slice(0, 10) || 'Unknown';
    const product  = f.product || (f.source === 'api' ? 'Manual' : 'DefectDojo');
    const source   = f.source  || 'api';
    const key      = `${day}__${product}__${source}`;
    if (!groups[key]) groups[key] = { day, product, source, items: [] };
    groups[key].items.push(f);
  });

  return Object.values(groups)
    .sort((a, b) => b.day.localeCompare(a.day))
    .map((g, i) => {
      const items   = g.items;
      const sev     = { critical: 0, high: 0, medium: 0, low: 0 };
      const toolSet = new Set();
      let highRisk  = 0;

      items.forEach(f => {
        // Severity column reflects predicted_severity (multiclass model output)
        const s = (f.severity || f.predicted_severity || 'medium').toLowerCase();
        if (sev[s] !== undefined) sev[s]++;

        // High-risk flag comes exclusively from the binary model threshold (0.3819)
        // NOT from risk_category or risk_score bands
        if (f.is_high_risk) highRisk++;

        if (f.scanner_type) toolSet.add(f.scanner_type);
      });

      // ── Product AI Score: average of top-10 highest risk_score findings ──
      // Using only the tail end of the distribution gives a more meaningful
      // "worst-case" signal per scan group than a simple mean across all findings
      // (which would be dragged down by the many low-score items in every batch).
      const sorted = [...items].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
      const top10  = sorted.slice(0, Math.min(10, sorted.length));
      const aiScore = top10.length
        ? top10.reduce((sum, f) => sum + (f.risk_score || 0), 0) / top10.length
        : 0;

      // ── Status: driven by is_high_risk count only ─────────────────────────
      // is_high_risk is the real production alert flag from the binary model.
      // risk_category (score band) and risk_score are NOT used for gate logic.
      //   >= 10 high-risk findings → Block
      //   >= 1  high-risk finding  → Warn
      //      0  high-risk findings → Pass
      const status = highRisk >= 10 ? 'Block' : highRisk >= 1 ? 'Warn' : 'Pass';

      // Engagement label varies by source so users can tell at a glance how
      // findings entered the system.
      const engagement = g.source === 'defectdojo'
        ? 'DefectDojo Sync'
        : g.source === 'api'
          ? 'API Submission'
          : 'Manual Entry';

      return {
        id:                i + 1,
        product:           g.product,
        engagement:        engagement,
        tools:             toolSet.size ? [...toolSet] : ['Unknown'],
        commit:            '—',
        branch:            'main',
        date:              g.day + 'T00:00:00Z',
        duration:          '—',
        findings_imported: items.length,
        critical_count:    sev.critical,
        high_risk_flagged: highRisk,
        ai_risk_score:     Math.round(aiScore * 10) / 10,
        status:            status,
        severity:          sev,
      };
    });
}

function ScanHistoryPage() {
  const { dark } = useTheme();
  const t        = dark ? '#e2e8f0' : '#1e293b';
  const sub      = dark ? '#94a3b8' : '#64748b';
  const muted    = dark ? '#4a5d78' : '#8898b0';
  const border   = dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)';
  const raisedBg = dark ? '#1a2234' : '#f4f6fa';

  const statusColors = { Pass: '#22c55e', Warn: '#f97316', Block: '#ef4444' };
  const sevColors    = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

  const scans = useMemo(
    () => buildScanHistory(window._cachedFindings),
    [],
  );

  const [branchFilter, setBranchFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [toolFilter,   setToolFilter]   = useState('all');
  const [expandedRow,  setExpandedRow]  = useState(null);

  const branches = useMemo(() => [...new Set(scans.map(s => s.branch))], [scans]);

  // Tool filter options computed from real data so the dropdown reflects what
  // the backend actually has (e.g. only "SCA" if every Trivy run is SCA).
  const toolOptions = useMemo(() => {
    const set = new Set();
    scans.forEach(s => s.tools.forEach(tt => set.add(tt)));
    return ['all', ...[...set].sort()];
  }, [scans]);

  const filtered = useMemo(() => {
    return scans.filter(s => {
      if (branchFilter !== 'all' && s.branch                 !== branchFilter) return false;
      if (statusFilter !== 'all' && s.status.toLowerCase()   !== statusFilter) return false;
      if (toolFilter   !== 'all' && !s.tools.includes(toolFilter))             return false;
      return true;
    });
  }, [scans, branchFilter, statusFilter, toolFilter]);

  function timeAgo(dateStr) {
    const s = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
    if (s < 60)    return s + 's ago';
    if (s < 3600)  return Math.floor(s / 60)    + 'm ago';
    if (s < 86400) return Math.floor(s / 3600)  + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  // Color the AI score display using the same bands as risk_category:
  // High 70–100 → red, Medium 30–69 → orange, Low 0–29 → green
  function scoreColor(n) {
    if (n >= 70) return '#ef4444';
    if (n >= 30) return '#f97316';
    return '#22c55e';
  }

  const selectStyle = {
    padding: '8px 12px', borderRadius: 8, border: `1px solid ${border}`, fontSize: 13,
    background: dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)', color: t, outline: 'none',
    cursor: 'pointer',
  };

  const thStyle = {
    padding: '10px 12px', textAlign: 'left', fontWeight: 700, color: muted,
    fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em', whiteSpace: 'nowrap',
    borderBottom: `1px solid ${border}`,
  };
  const tdStyle = { padding: '10px 12px', fontSize: 13, verticalAlign: 'middle' };

  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 20 } },
    React.createElement('div', null,
      React.createElement('h1', { style: { fontSize: 24, fontWeight: 800, color: t, margin: '0 0 4px', letterSpacing: '-0.02em' } }, 'Scan History'),
      React.createElement('p', { style: { fontSize: 14, color: sub, margin: 0 } }, 'CI/CD security scan timeline with severity breakdowns'),
    ),
    // Filters
    React.createElement(GlassCard, { style: { padding: 16 } },
      React.createElement('div', { style: { display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' } },
        React.createElement('select', { value: branchFilter, onChange: e => setBranchFilter(e.target.value), style: selectStyle },
          React.createElement('option', { value: 'all' }, 'All Branches'),
          branches.map(b => React.createElement('option', { key: b, value: b }, b)),
        ),
        React.createElement('select', { value: statusFilter, onChange: e => setStatusFilter(e.target.value), style: selectStyle },
          React.createElement('option', { value: 'all' }, 'All Statuses'),
          React.createElement('option', { value: 'pass'  }, 'Pass'),
          React.createElement('option', { value: 'warn'  }, 'Warn'),
          React.createElement('option', { value: 'block' }, 'Block'),
        ),
        React.createElement('select', { value: toolFilter, onChange: e => setToolFilter(e.target.value), style: selectStyle },
          toolOptions.map(o =>
            React.createElement('option', { key: o, value: o }, o === 'all' ? 'All Tools' : o),
          ),
        ),
        React.createElement('span', { style: { marginLeft: 'auto', fontSize: 12, color: muted } }, filtered.length + ' scans'),
      ),
    ),
    // Table
    React.createElement(GlassCard, { style: { padding: 0, overflow: 'hidden' } },
      React.createElement('div', { style: { overflowX: 'auto' } },
        React.createElement('table', { style: { width: '100%', borderCollapse: 'collapse' } },
          React.createElement('thead', null,
            React.createElement('tr', null,
              ['Product', 'Engagement', 'Commit', 'Branch', 'Scanned', 'Tools', 'Findings', 'High-Risk', 'AI Score', 'Status'].map(h =>
                React.createElement('th', { key: h, style: thStyle }, h),
              ),
            ),
          ),
          React.createElement('tbody', null,
            filtered.length === 0 && React.createElement('tr', null,
              React.createElement('td', { colSpan: 10, style: { textAlign: 'center', padding: '40px 24px', color: muted, fontSize: 14 } }, 'No scans match your filters.'),
            ),
            filtered.map(s => {
              const sc         = statusColors[s.status] || '#64748b';
              const isExpanded = expandedRow === s.id;
              return React.createElement(React.Fragment, { key: s.id },
                React.createElement('tr', {
                  onClick: () => setExpandedRow(isExpanded ? null : s.id),
                  style: { borderBottom: isExpanded ? 'none' : `1px solid ${border}`, cursor: 'pointer', transition: 'background 0.15s' },
                },
                  React.createElement('td', { style: { ...tdStyle, fontWeight: 600, color: t } }, s.product),
                  React.createElement('td', { style: { ...tdStyle, fontSize: 12, color: sub } }, s.engagement),
                  React.createElement('td', { style: tdStyle },
                    React.createElement('span', { style: { fontFamily: 'monospace', fontSize: 12, color: '#3884f4' } }, s.commit),
                  ),
                  React.createElement('td', { style: { ...tdStyle, fontFamily: 'monospace', fontSize: 12, color: sub } }, s.branch),
                  React.createElement('td', { style: { ...tdStyle, fontSize: 12, color: muted } }, timeAgo(s.date)),
                  React.createElement('td', { style: tdStyle },
                    React.createElement('div', { style: { display: 'flex', gap: 4, flexWrap: 'wrap' } },
                      s.tools.map(tool =>
                        React.createElement('span', {
                          key: tool,
                          style: { fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 6, background: 'rgba(56,132,244,0.10)', color: '#3884f4', border: '1px solid rgba(56,132,244,0.20)' },
                        }, tool),
                      ),
                    ),
                  ),
                  React.createElement('td', { style: { ...tdStyle, fontFamily: 'monospace', fontWeight: 600, color: t } }, s.findings_imported),
                  React.createElement('td', { style: tdStyle },
                    React.createElement('span', {
                      style: { fontFamily: 'monospace', fontWeight: 700, color: s.high_risk_flagged > 0 ? '#ef4444' : muted },
                    }, s.high_risk_flagged),
                  ),
                  React.createElement('td', { style: tdStyle },
                    React.createElement('span', { style: { fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: scoreColor(s.ai_risk_score) } }, s.ai_risk_score),
                  ),
                  React.createElement('td', { style: tdStyle },
                    React.createElement('span', {
                      style: { fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 6, background: sc + '18', color: sc },
                    }, s.status),
                  ),
                ),
                // Expanded detail row
                isExpanded && React.createElement('tr', null,
                  React.createElement('td', { colSpan: 10, style: { padding: 0 } },
                    React.createElement('div', {
                      style: {
                        background: raisedBg, borderTop: `1px solid ${border}`, borderBottom: `1px solid ${border}`,
                        padding: '16px 16px 16px 48px',
                      },
                    },
                      React.createElement('div', { style: { display: 'flex', gap: 32, flexWrap: 'wrap' } },
                        React.createElement('div', null,
                          React.createElement('div', { style: { fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', color: muted, marginBottom: 4 } }, 'Full Date'),
                          React.createElement('div', { style: { fontFamily: 'monospace', fontSize: 12, color: t } },
                            new Date(s.date).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
                          ),
                        ),
                        React.createElement('div', null,
                          React.createElement('div', { style: { fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', color: muted, marginBottom: 4 } }, 'Duration'),
                          React.createElement('div', { style: { fontFamily: 'monospace', fontSize: 12, color: t } }, s.duration),
                        ),
                        React.createElement('div', null,
                          React.createElement('div', { style: { fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', color: muted, marginBottom: 4 } }, 'Severity Breakdown'),
                          React.createElement('div', { style: { display: 'flex', gap: 14, marginTop: 4 } },
                            React.createElement('span', { style: { fontSize: 12 } },
                              React.createElement('span', { style: { color: sevColors.critical, fontWeight: 700 } }, s.severity.critical),
                              React.createElement('span', { style: { color: muted, marginLeft: 3 } }, 'crit'),
                            ),
                            React.createElement('span', { style: { fontSize: 12 } },
                              React.createElement('span', { style: { color: sevColors.high, fontWeight: 700 } }, s.severity.high),
                              React.createElement('span', { style: { color: muted, marginLeft: 3 } }, 'high'),
                            ),
                            React.createElement('span', { style: { fontSize: 12 } },
                              React.createElement('span', { style: { color: sevColors.medium, fontWeight: 700 } }, s.severity.medium),
                              React.createElement('span', { style: { color: muted, marginLeft: 3 } }, 'med'),
                            ),
                            React.createElement('span', { style: { fontSize: 12 } },
                              React.createElement('span', { style: { color: sevColors.low, fontWeight: 700 } }, s.severity.low),
                              React.createElement('span', { style: { color: muted, marginLeft: 3 } }, 'low'),
                            ),
                          ),
                          React.createElement('div', {
                            style: { display: 'flex', gap: 2, height: 6, borderRadius: 3, overflow: 'hidden', marginTop: 8, width: 200 },
                          },
                            (() => {
                              const sv    = s.severity;
                              const total = sv.critical + sv.high + sv.medium + sv.low;
                              const pct   = (v) => total ? ((v / total) * 100).toFixed(1) + '%' : '0%';
                              return [
                                React.createElement('div', { key: 'c', style: { width: pct(sv.critical), background: sevColors.critical, borderRadius: '3px 0 0 3px' } }),
                                React.createElement('div', { key: 'h', style: { width: pct(sv.high),     background: sevColors.high } }),
                                React.createElement('div', { key: 'm', style: { width: pct(sv.medium),   background: sevColors.medium } }),
                                React.createElement('div', { key: 'l', style: { width: pct(sv.low),      background: sevColors.low,    borderRadius: '0 3px 3px 0' } }),
                              ];
                            })(),
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              );
            }),
          ),
        ),
      ),
    ),
  );
}

Object.assign(window, { ScanHistoryPage });