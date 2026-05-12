// Findings Page — compact rows + modern hover tooltips, real backend data only
const { useState, useMemo, useEffect, useRef } = React;

function _num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function HoverText({ text, children, style = {}, mono = false, maxWidth = '100%' }) {
  const timerRef = useRef(null);
  const tooltipRef = useRef(null);

  const value = text === undefined || text === null || text === '' ? 'N/A' : String(text);
  const display = children !== undefined && children !== null ? children : value;

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

    const tooltip = document.createElement('div');
    tooltip.textContent = value;

    tooltip.style.position = 'fixed';
    tooltip.style.zIndex = '999999';
    tooltip.style.maxWidth = '320px';
    tooltip.style.padding = '8px 10px';
    tooltip.style.borderRadius = '10px';
    tooltip.style.background = 'rgba(15,23,42,0.97)';
    tooltip.style.color = '#f8fafc';
    tooltip.style.border = '1px solid rgba(148,163,184,0.22)';
    tooltip.style.boxShadow = '0 14px 34px rgba(0,0,0,0.28)';
    tooltip.style.fontSize = '11px';
    tooltip.style.fontWeight = '650';
    tooltip.style.lineHeight = '1.35';
    tooltip.style.whiteSpace = 'normal';
    tooltip.style.wordBreak = 'break-word';
    tooltip.style.pointerEvents = 'none';
    tooltip.style.opacity = '0';
    tooltip.style.transition = 'opacity 0.12s ease, transform 0.12s ease';
    tooltip.style.transform = 'translateY(3px)';

    document.body.appendChild(tooltip);

    const tipRect = tooltip.getBoundingClientRect();

    // Default: directly above the hovered text
    let left = rect.left;
    let top = rect.top - tipRect.height - 8;

    // If not enough space above, put it below the hovered text
    if (top < 8) {
      top = rect.bottom + 8;
    }

    // If it goes outside right edge, move it left
    if (left + tipRect.width > window.innerWidth - 8) {
      left = window.innerWidth - tipRect.width - 8;
    }

    // If it goes outside left edge, clamp it
    if (left < 8) {
      left = 8;
    }

    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;

    requestAnimationFrame(() => {
      tooltip.style.opacity = '1';
      tooltip.style.transform = 'translateY(0)';
    });

    tooltipRef.current = tooltip;
  };

  const showTip = (e) => {
    const targetEl = e.currentTarget;

    window.clearTimeout(timerRef.current);

    timerRef.current = window.setTimeout(() => {
      createTooltip(targetEl);
    }, 300);
  };

  const hideTip = () => {
    removeTooltip();
  };

  useEffect(() => {
    return () => removeTooltip();
  }, []);

  return React.createElement('span', {
    onMouseEnter: showTip,
    onMouseLeave: hideTip,
    style: {
      display: 'inline-block',
      width: '100%',
      maxWidth,
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap',
      verticalAlign: 'middle',
      fontFamily: mono
        ? 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace'
        : undefined,
      cursor: value && value !== 'N/A' ? 'default' : 'inherit',
      ...style,
    },
  }, display);
}

function SevBadge({ severity }) {
  const colors = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#22c55e',
  };

  const sev = severity || 'Medium';

  return React.createElement('span', {
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      minWidth: 50,
      fontSize: 10,
      fontWeight: 800,
      padding: '3px 8px',
      borderRadius: 7,
      background: (colors[sev] || '#64748b') + '18',
      color: colors[sev] || '#64748b',
      lineHeight: 1,
    },
  }, sev);
}

function ScanBadge({ type }) {
  const colors = {
    SAST: '#2563eb',
    SCA: '#06b6d4',
    DAST: '#f97316',
  };

  const label = type || 'SCA';

  return React.createElement('span', {
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      minWidth: 44,
      fontSize: 10,
      fontWeight: 800,
      padding: '3px 7px',
      borderRadius: 7,
      background: (colors[label] || '#3884f4') + '15',
      color: colors[label] || '#3884f4',
      lineHeight: 1,
      letterSpacing: '0.02em',
    },
  }, label);
}

function RiskBadge({ category }) {
  const { dark } = useTheme();

  const raw = String(category || 'Low').replace(/\s*Risk$/i, '').trim();
  const risk = raw === 'Critical' ? 'High' : raw || 'Low';

  const colors = {
    High: '#ef4444',
    Medium: '#eab308',
    Low: '#64748b',
  };

  const color = colors[risk] || colors.Low;

  return React.createElement('span', {
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      minWidth: 50,
      fontSize: 10,
      fontWeight: 800,
      padding: '3px 8px',
      borderRadius: 7,
      background: color + (dark ? '20' : '14'),
      color,
      lineHeight: 1,
    },
  }, risk);
}

function FindingsPage() {
  const { dark } = useTheme();

  const textColor   = dark ? '#e2e8f0' : '#1e293b';
  const subColor    = dark ? '#94a3b8' : '#64748b';
  const mutedColor  = dark ? '#64748b' : '#94a3b8';
  const borderColor = dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)';
  const rowBgHover  = dark ? 'rgba(56,132,244,0.055)' : 'rgba(56,132,244,0.035)';

  const [allFindings, setAllFindings] = useState(window._cachedFindings || []);

  const [search,       setSearch]       = useState('');
  const [prodFilter,   setProdFilter]   = useState('All');
  const [scanFilter,   setScanFilter]   = useState('All');
  const [sevFilter,    setSevFilter]    = useState('All');
  const [highRiskOnly, setHighRiskOnly] = useState(false);
  const [page,         setPage]         = useState(0);

  const perPage = 30;

  useEffect(() => {
    setAllFindings(window._cachedFindings || []);
  }, []);

  const productOptions = useMemo(() => {
    const set = new Set();
    allFindings.forEach(f => {
      if (f.product) set.add(f.product);
    });
    return ['All', ...[...set].sort()];
  }, [allFindings]);

  const scannerOptions = useMemo(() => {
    const set = new Set();
    allFindings.forEach(f => {
      if (f.scanner_type) set.add(f.scanner_type);
    });
    return ['All', ...[...set].sort()];
  }, [allFindings]);

  const filtered = useMemo(() => {
    let data = allFindings;

    if (prodFilter !== 'All') data = data.filter(f => f.product === prodFilter);
    if (scanFilter !== 'All') data = data.filter(f => f.scanner_type === scanFilter);
    if (sevFilter  !== 'All') data = data.filter(f => f.severity === sevFilter);
    if (highRiskOnly) data = data.filter(f => f.is_high_risk);

    if (search) {
      const s = search.toLowerCase();
      data = data.filter(f =>
        (f.cve_id       || '').toLowerCase().includes(s) ||
        (f.title        || '').toLowerCase().includes(s) ||
        (f.package_name || '').toLowerCase().includes(s) ||
        (f.file_path    || '').toLowerCase().includes(s)
      );
    }

    return data;
  }, [allFindings, search, prodFilter, scanFilter, sevFilter, highRiskOnly]);

  const paged = filtered.slice(page * perPage, (page + 1) * perPage);
  const totalPages = Math.max(1, Math.ceil(filtered.length / perPage));

  const selectStyle = {
    padding: '8px 12px',
    borderRadius: 10,
    border: `1px solid ${borderColor}`,
    fontSize: 13,
    background: dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)',
    color: textColor,
    outline: 'none',
  };

  const thStyle = {
    padding: '9px 12px',
    textAlign: 'left',
    fontWeight: 800,
    color: subColor,
    fontSize: 10,
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    whiteSpace: 'nowrap',
    borderBottom: `1px solid ${borderColor}`,
  };

  const tdBase = {
    padding: '7px 12px',
    verticalAlign: 'middle',
    borderBottom: `1px solid ${borderColor}`,
    lineHeight: 1.18,
    height: 42,
  };

  return React.createElement('div', {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: 18,
    },
  },

    React.createElement('h1', {
      style: {
        fontSize: 24,
        fontWeight: 800,
        color: textColor,
        margin: 0,
      },
    }, 'Findings'),

    React.createElement(GlassCard, { style: { padding: 16 } },
      React.createElement('div', {
        style: {
          display: 'flex',
          gap: 12,
          flexWrap: 'wrap',
          alignItems: 'center',
        },
      },

        React.createElement('input', {
          placeholder: 'Search CVE, package, file, title...',
          value: search,
          onChange: e => {
            setSearch(e.target.value);
            setPage(0);
          },
          style: {
            ...selectStyle,
            flex: '1 1 200px',
            minWidth: 200,
          },
        }),

        React.createElement('select', {
          value: prodFilter,
          onChange: e => {
            setProdFilter(e.target.value);
            setPage(0);
          },
          style: selectStyle,
        },
          productOptions.map(p =>
            React.createElement('option', { key: p, value: p },
              p === 'All' ? 'All Products' : p,
            ),
          ),
        ),

        React.createElement('select', {
          value: scanFilter,
          onChange: e => {
            setScanFilter(e.target.value);
            setPage(0);
          },
          style: selectStyle,
        },
          scannerOptions.map(s =>
            React.createElement('option', { key: s, value: s },
              s === 'All' ? 'All Scanners' : s,
            ),
          ),
        ),

        React.createElement('select', {
          value: sevFilter,
          onChange: e => {
            setSevFilter(e.target.value);
            setPage(0);
          },
          style: selectStyle,
        },
          React.createElement('option', { value: 'All' }, 'All Severities'),
          ...['Critical', 'High', 'Medium', 'Low'].map(s =>
            React.createElement('option', { key: s, value: s }, s),
          ),
        ),

        React.createElement('label', {
          style: {
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 13,
            color: subColor,
            cursor: 'pointer',
          },
        },
          React.createElement('input', {
            type: 'checkbox',
            checked: highRiskOnly,
            onChange: e => {
              setHighRiskOnly(e.target.checked);
              setPage(0);
            },
          }),
          'High-risk only',
        ),

        React.createElement('span', {
          style: {
            fontSize: 12,
            color: subColor,
            marginLeft: 'auto',
          },
        }, `${filtered.length} results`),
      ),
    ),

    React.createElement(GlassCard, {
      style: {
        padding: 0,
        overflow: 'hidden',
      },
    },

      React.createElement('div', { style: { overflowX: 'auto' } },
        React.createElement('table', {
          style: {
            width: '100%',
            minWidth: 1280,
            borderCollapse: 'collapse',
            tableLayout: 'fixed',
            fontSize: 12,
          },
        },

          React.createElement('colgroup', null,
            React.createElement('col', { style: { width: 92 } }),
            React.createElement('col', { style: { width: 205 } }),
            React.createElement('col', { style: { width: 150 } }),
            React.createElement('col', { style: { width: 150 } }),
            React.createElement('col', { style: { width: 86 } }),
            React.createElement('col', { style: { width: 132 } }),
            React.createElement('col', { style: { width: 64 } }),
            React.createElement('col', { style: { width: 82 } }),
            React.createElement('col', { style: { width: 92 } }),
            React.createElement('col', { style: { width: 74 } }),
            React.createElement('col', { style: { width: 150 } }),
          ),

          React.createElement('thead', null,
            React.createElement('tr', null,
              [
                'Product',
                'Finding / CVE',
                'Package',
                'File',
                'Scanner',
                'Predicted Severity',
                'CVSS',
                'AI Risk',
                'AI Score',
                'Flagged',
                'Fix',
              ].map(h =>
                React.createElement('th', { key: h, style: thStyle }, h),
              ),
            ),
          ),

          React.createElement('tbody', null,

            paged.length === 0 && React.createElement('tr', null,
              React.createElement('td', {
                colSpan: 11,
                style: {
                  textAlign: 'center',
                  padding: '34px 24px',
                  color: subColor,
                  fontSize: 14,
                },
              }, 'No findings match your filters.'),
            ),

            paged.map(f => {
              const score = _num(f.risk_score);
              const cvss = _num(f.cvss_score);

              const riskCategory =
                f.risk_category ||
                (score >= 70 ? 'High' : score >= 30 ? 'Medium' : 'Low');

              const scoreColor =
                score >= 80 ? '#ef4444' :
                score >= 60 ? '#f97316' :
                textColor;

              return React.createElement('tr', {
                key: f.id,
                className: 'tr-hover',
                style: {
                  transition: 'background 0.15s',
                },
                onMouseEnter: e => {
                  e.currentTarget.style.background = rowBgHover;
                },
                onMouseLeave: e => {
                  e.currentTarget.style.background = 'transparent';
                },
              },

                React.createElement('td', {
                  style: {
                    ...tdBase,
                    fontWeight: 700,
                    color: textColor,
                  },
                },
                  React.createElement(HoverText, {
                    text: f.product || 'Unknown',
                    maxWidth: '100%',
                  }),
                ),

                React.createElement('td', { style: tdBase },
                  React.createElement(HoverText, {
                    text: f.title || f.cve_id || 'Finding',
                    maxWidth: '100%',
                    style: {
                      fontWeight: 700,
                      color: textColor,
                      fontSize: 12,
                    },
                  }),

                  React.createElement('div', { style: { height: 2 } }),

                  React.createElement(HoverText, {
                    text: f.cve_id || 'No CVE',
                    maxWidth: '100%',
                    mono: true,
                    style: {
                      fontSize: 10,
                      color: subColor,
                    },
                  }),
                ),

                React.createElement('td', {
                  style: {
                    ...tdBase,
                    color: subColor,
                  },
                },
                  React.createElement(HoverText, {
                    text: f.package_name || 'N/A',
                    maxWidth: '100%',
                  }),
                ),

                React.createElement('td', {
                  style: {
                    ...tdBase,
                    color: subColor,
                  },
                },
                  React.createElement(HoverText, {
                    text: f.file_path || 'N/A',
                    mono: true,
                    maxWidth: '100%',
                    style: {
                      fontSize: 10.5,
                    },
                  }),
                ),

                React.createElement('td', { style: tdBase },
                  React.createElement(ScanBadge, { type: f.scanner_type }),
                ),

                React.createElement('td', { style: tdBase },
                  React.createElement(SevBadge, { severity: f.severity }),
                ),

                React.createElement('td', {
                  style: {
                    ...tdBase,
                    fontWeight: 800,
                    color: textColor,
                  },
                }, cvss.toFixed(1)),

                React.createElement('td', { style: tdBase },
                  React.createElement(RiskBadge, { category: riskCategory }),
                ),

                React.createElement('td', {
                  style: {
                    ...tdBase,
                    fontWeight: 900,
                    color: scoreColor,
                  },
                }, score.toFixed(1)),

                React.createElement('td', { style: tdBase },
                  f.is_high_risk
                    ? React.createElement('span', {
                        style: {
                          fontSize: 10,
                          fontWeight: 800,
                          padding: '3px 7px',
                          borderRadius: 7,
                          background: 'rgba(244,63,94,0.12)',
                          color: '#ef4444',
                        },
                      }, 'Yes')
                    : React.createElement('span', {
                        style: {
                          fontSize: 12,
                          color: mutedColor,
                        },
                      }, '—'),
                ),

                React.createElement('td', {
                  style: {
                    ...tdBase,
                    color: subColor,
                  },
                },
                  React.createElement(HoverText, {
                    text: f.fix_recommendation || 'Review and remediate based on AI risk score',
                    maxWidth: '100%',
                  }),
                ),
              );
            }),
          ),
        ),
      ),

      React.createElement('div', {
        style: {
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '11px 16px',
          borderTop: `1px solid ${borderColor}`,
        },
      },

        React.createElement('span', {
          style: {
            fontSize: 12,
            color: subColor,
          },
        }, `Page ${page + 1} of ${totalPages}`),

        React.createElement('div', {
          style: {
            display: 'flex',
            gap: 8,
          },
        },

          React.createElement('button', {
            disabled: page === 0,
            onClick: () => setPage(p => Math.max(0, p - 1)),
            style: {
              padding: '6px 13px',
              borderRadius: 8,
              border: `1px solid ${borderColor}`,
              background: 'transparent',
              color: textColor,
              cursor: page === 0 ? 'not-allowed' : 'pointer',
              fontSize: 13,
              opacity: page === 0 ? 0.4 : 1,
            },
          }, '← Prev'),

          React.createElement('button', {
            disabled: page >= totalPages - 1,
            onClick: () => setPage(p => Math.min(totalPages - 1, p + 1)),
            style: {
              padding: '6px 13px',
              borderRadius: 8,
              border: `1px solid ${borderColor}`,
              background: 'transparent',
              color: textColor,
              cursor: page >= totalPages - 1 ? 'not-allowed' : 'pointer',
              fontSize: 13,
              opacity: page >= totalPages - 1 ? 0.4 : 1,
            },
          }, 'Next →'),
        ),
      ),
    ),
  );
}

Object.assign(window, {
  FindingsPage,
  SevBadge,
  ScanBadge,
  HoverText,
});