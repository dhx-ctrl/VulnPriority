// Model Insights Page — dual-model explanation:
// 1) Clean leakage-safe model = strict scientific confidence signal
// 2) EPSS operational ranker = primary dashboard sorting / review-queue model

import React from 'react';
import {
  Bar as B2,
  BarChart as BC2,
  CartesianGrid as CG2,
  ResponsiveContainer as RC2,
  Tooltip as TT2,
  XAxis as XA2,
  YAxis as YA2,
} from 'recharts';
import { useTheme } from '../context/AppContext.jsx';
import { apiClient } from '../services/api-client.js';
import { GlassCard } from './DashboardPage.jsx';

function MetricRow({ label, value, accent, note }) {
  const { dark } = useTheme();
  const text = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';

  return React.createElement('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: '1fr auto',
      gap: 12,
      padding: '9px 0',
      borderBottom: `1px solid ${dark ? 'rgba(255,255,255,0.045)' : 'rgba(15,23,42,0.055)'}`,
    },
  },
    React.createElement('div', null,
      React.createElement('div', {
        style: {
          fontSize: 13,
          color: sub,
          fontWeight: 650,
        },
      }, label),

      note && React.createElement('div', {
        style: {
          fontSize: 11,
          color: sub,
          opacity: 0.82,
          marginTop: 3,
          lineHeight: 1.35,
        },
      }, note),
    ),

    React.createElement('span', {
      className: 'num',
      style: {
        fontSize: 14,
        fontWeight: 850,
        color: accent || text,
        textAlign: 'right',
      },
    }, value),
  );
}

function MiniBadge({ children, color = '#3884f4' }) {
  const { dark } = useTheme();

  return React.createElement('span', {
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      padding: '5px 9px',
      borderRadius: 999,
      background: color + (dark ? '22' : '12'),
      color,
      border: `1px solid ${color}${dark ? '34' : '22'}`,
      fontSize: 11,
      fontWeight: 800,
      whiteSpace: 'nowrap',
    },
  }, children);
}

function InfoBox({ title, children, color = '#3884f4' }) {
  const { dark } = useTheme();
  const text = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';

  return React.createElement('div', {
    style: {
      padding: 14,
      borderRadius: 12,
      background: color + (dark ? '18' : '08'),
      border: `1px solid ${color}${dark ? '30' : '18'}`,
    },
  },
    React.createElement('div', {
      style: {
        fontSize: 13,
        fontWeight: 850,
        color,
        marginBottom: 7,
      },
    }, title),

    React.createElement('div', {
      style: {
        fontSize: 12.5,
        color: text,
        lineHeight: 1.55,
      },
    }, children),
  );
}

function ConfusionMatrixClean() {
  const { dark } = useTheme();
  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';

  const cells = [
    {
      label: 'TN',
      value: 1127,
      row: 0,
      col: 0,
      color: '#22c55e',
      text: 'Correctly left low-priority',
    },
    {
      label: 'FP',
      value: 34,
      row: 0,
      col: 1,
      color: '#f97316',
      text: 'Low-risk flagged high',
    },
    {
      label: 'FN',
      value: 107,
      row: 1,
      col: 0,
      color: '#ef4444',
      text: 'High-risk missed',
    },
    {
      label: 'TP',
      value: 115,
      row: 1,
      col: 1,
      color: '#3884f4',
      text: 'Correctly flagged high',
    },
  ];

  return React.createElement('div', {
    style: {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: 8,
    },
  },
    React.createElement('div', {
      style: {
        display: 'flex',
        gap: 4,
        fontSize: 11,
        color: sub,
        marginBottom: 4,
      },
    },
      React.createElement('span', { style: { width: 82 } }),
      React.createElement('span', { style: { width: 130, textAlign: 'center' } }, 'Predicted Low'),
      React.createElement('span', { style: { width: 130, textAlign: 'center' } }, 'Predicted High'),
    ),

    ['Actual Low', 'Actual High'].map((rowLabel, ri) =>
      React.createElement('div', {
        key: ri,
        style: {
          display: 'flex',
          gap: 4,
          alignItems: 'center',
        },
      },
        React.createElement('span', {
          style: {
            width: 82,
            fontSize: 11,
            color: sub,
            textAlign: 'right',
            paddingRight: 8,
          },
        }, rowLabel),

        cells.filter(c => c.row === ri).map(c =>
          React.createElement('div', {
            key: c.label,
            style: {
              width: 130,
              minHeight: 86,
              borderRadius: 10,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 4,
              background: c.color + (dark ? '18' : '10'),
              border: `1px solid ${c.color}30`,
              padding: 8,
            },
          },
            React.createElement('span', {
              style: {
                fontSize: 11,
                fontWeight: 800,
                color: c.color,
              },
            }, c.label),

            React.createElement('span', {
              className: 'num',
              style: {
                fontSize: 24,
                fontWeight: 900,
                color: t,
              },
            }, c.value),

            React.createElement('span', {
              style: {
                fontSize: 10,
                color: sub,
                textAlign: 'center',
                lineHeight: 1.25,
              },
            }, c.text),
          ),
        ),
      ),
    ),
  );
}

function ModelInsightsPage() {
  const { dark } = useTheme();

  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';
  const border = dark ? 'rgba(255,255,255,0.06)' : 'rgba(15,23,42,0.07)';
  const chartText = dark ? '#94a3b8' : '#64748b';

  const [health, setHealth] = React.useState(null);

  React.useEffect(() => {
    let cancelled = false;

    apiClient.getHealth()
      .then(h => {
        if (!cancelled) setHealth(h);
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, []);

  const cleanModel = health?.models?.clean || {};
  const rankerModel = health?.models?.operational_ranker || {};

  const cleanThreshold = Number(cleanModel.threshold);
  const rankerThreshold = Number(rankerModel.threshold ?? health?.threshold);

  const cleanThresholdText = Number.isFinite(cleanThreshold)
    ? cleanThreshold.toFixed(4)
    : 'metadata';

  const rankerThresholdText = Number.isFinite(rankerThreshold)
    ? rankerThreshold.toFixed(4)
    : 'metadata';

  const cleanFeatureCount = Array.isArray(cleanModel.features)
    ? cleanModel.features.length
    : 26;

  const rankerFeatureCount = Array.isArray(rankerModel.features)
    ? rankerModel.features.length
    : Array.isArray(health?.binary_features)
      ? health.binary_features.length
      : 33;

  const rankerName =
    rankerModel.model ||
    health?.binary_model ||
    'EPSS operational ranker';

  const cleanName =
    cleanModel.model ||
    'XGBoost leakage-safe binary classifier';

  const rankingComparison = [
    { metric: 'AUCPR', ai: 0.265, cvss: 0.118 },
    { metric: 'ROC-AUC', ai: 0.827, cvss: 0.618 },
    { metric: 'NDCG', ai: 0.712, cvss: 0.606 },
  ];

  const ablationData = [
    { test: 'baseline', aucpr: 0.739, roc: 0.896 },
    { test: 'no source', aucpr: 0.740, roc: 0.897 },
    { test: 'no CVSS parts', aucpr: 0.735, roc: 0.891 },
    { test: 'final minimal', aucpr: 0.717, roc: 0.888 },
  ];

  return React.createElement('div', {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: 24,
    },
  },

    React.createElement('div', null,
      React.createElement('h1', {
        style: {
          fontSize: 24,
          fontWeight: 850,
          color: t,
          margin: '0 0 4px',
        },
      }, 'AI Insights'),

      React.createElement('p', {
        style: {
          fontSize: 14,
          color: sub,
          margin: 0,
          lineHeight: 1.55,
        },
      },
        'The dashboard uses two XGBoost models: an operational EPSS ranker for sorting the review queue, and a clean leakage-safe model as a stricter confidence signal.',
      ),
    ),

    React.createElement('div', {
      style: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(330px, 1fr))',
        gap: 20,
      },
    },

      React.createElement(GlassCard, null,
        React.createElement('div', {
          style: {
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: 12,
            marginBottom: 16,
          },
        },
          React.createElement('div', null,
            React.createElement('div', {
              style: {
                fontSize: 16,
                fontWeight: 850,
                color: t,
              },
            }, 'Operational EPSS Ranker'),

            React.createElement('div', {
              style: {
                fontSize: 12,
                color: sub,
                marginTop: 3,
              },
            }, `${rankerName} · ${rankerFeatureCount} features`),
          ),

          React.createElement(MiniBadge, { color: '#3884f4' }, 'main sorting model'),
        ),

        React.createElement('p', {
          style: {
            fontSize: 13,
            color: sub,
            margin: '0 0 14px',
            lineHeight: 1.55,
          },
        },
          'This model is used to order the analyst review queue. It was trained with EPSS-only labels, so CVSS can be used as an input feature without circularly copying the label.',
        ),

        React.createElement(MetricRow, {
          label: 'Test AUCPR',
          value: '0.265',
          accent: '#3884f4',
          note: 'Ranking quality for EPSS-positive findings.',
        }),

        React.createElement(MetricRow, {
          label: 'Test ROC-AUC',
          value: '0.827',
          accent: '#3884f4',
          note: 'Ability to separate EPSS-positive from EPSS-negative findings.',
        }),

        React.createElement(MetricRow, {
          label: 'NDCG',
          value: '0.712',
          note: 'Measures how good the ordering is near the top of the queue.',
        }),

        React.createElement(MetricRow, {
          label: 'Findings needed for 80% coverage',
          value: '389',
          accent: '#22c55e',
          note: 'CVSS needed 733 findings for the same EPSS-positive coverage.',
        }),

        React.createElement(MetricRow, {
          label: 'Workload reduction vs CVSS',
          value: '46.9%',
          accent: '#22c55e',
          note: 'Fewer findings reviewed to cover 80% of EPSS-positive items.',
        }),

        React.createElement(MetricRow, {
          label: 'Strict threshold',
          value: rankerThresholdText,
          note: 'Used only for the operational alert flag. The dashboard still sorts by the full rank score.',
        }),
      ),

      React.createElement(GlassCard, null,
        React.createElement('div', {
          style: {
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: 12,
            marginBottom: 16,
          },
        },
          React.createElement('div', null,
            React.createElement('div', {
              style: {
                fontSize: 16,
                fontWeight: 850,
                color: t,
              },
            }, 'Clean Leakage-Safe Model'),

            React.createElement('div', {
              style: {
                fontSize: 12,
                color: sub,
                marginTop: 3,
              },
            }, `${cleanName} · ${cleanFeatureCount} minimal features`),
          ),

          React.createElement(MiniBadge, { color: '#22c55e' }, 'strict confidence signal'),
        ),

        React.createElement('p', {
          style: {
            fontSize: 13,
            color: sub,
            margin: '0 0 14px',
            lineHeight: 1.55,
          },
        },
          'This model is kept as the scientifically defensible baseline. EPSS, CVSS score, severity, raw advisory IDs, source metadata, exploit references, and CVSS subcomponents were removed from its inputs.',
        ),

        React.createElement(MetricRow, {
          label: 'Precision',
          value: '0.772',
          accent: '#22c55e',
          note: 'When the clean model flags High Risk, it is correct about 77% of the time.',
        }),

        React.createElement(MetricRow, {
          label: 'Recall',
          value: '0.518',
          accent: '#f97316',
          note: 'Strict mode catches about half of true high-risk items, so it is not used as a hard gate.',
        }),

        React.createElement(MetricRow, {
          label: 'F1-score',
          value: '0.620',
        }),

        React.createElement(MetricRow, {
          label: 'AUCPR',
          value: '0.717',
        }),

        React.createElement(MetricRow, {
          label: 'ROC-AUC',
          value: '0.888',
        }),

        React.createElement(MetricRow, {
          label: 'Decision threshold',
          value: cleanThresholdText,
          note: 'Used for the clean confidence flag, not for hiding findings.',
        }),
      ),
    ),

    React.createElement('div', {
      style: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(330px, 1fr))',
        gap: 20,
      },
    },

      React.createElement(GlassCard, null,
        React.createElement('h3', {
          style: {
            fontSize: 15,
            fontWeight: 800,
            color: t,
            margin: '0 0 14px',
          },
        }, 'How the dashboard uses both models'),

        React.createElement('div', {
          style: {
            display: 'grid',
            gap: 10,
          },
        },
          React.createElement(InfoBox, { title: 'Rank /100', color: '#3884f4' },
            'The operational EPSS ranker score. This is the main score used to sort the review queue. A higher score means the finding should be reviewed earlier.',
          ),

          React.createElement(InfoBox, { title: 'Clean /100', color: '#22c55e' },
            'The clean leakage-safe model score. It is shown as a secondary confidence signal and is not used to hide lower-scoring findings.',
          ),

          React.createElement(InfoBox, { title: 'Scanner Severity', color: '#f97316' },
            'The original severity from DefectDojo or the scanner. It remains visible because scanner severity and AI priority answer different questions.',
          ),

          React.createElement(InfoBox, { title: 'Priority label', color: '#e0364c' },
            'Review First means the operational rank score is high enough for immediate queue priority. Review Soon and Severity Watch keep important findings visible without pretending every scanner-high item is an AI emergency.',
          ),
        ),
      ),

      React.createElement(GlassCard, null,
        React.createElement('h3', {
          style: {
            fontSize: 15,
            fontWeight: 800,
            color: t,
            margin: '0 0 14px',
          },
        }, 'AI Ranker vs CVSS Ranking'),

        React.createElement(RC2, { width: '100%', height: 240 },
          React.createElement(BC2, {
            data: rankingComparison,
            margin: {
              top: 8,
              right: 8,
              bottom: 0,
              left: -12,
            },
          },
            React.createElement(CG2, {
              strokeDasharray: '3 3',
              stroke: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)',
            }),

            React.createElement(XA2, {
              dataKey: 'metric',
              tick: {
                fill: chartText,
                fontSize: 11,
              },
              axisLine: false,
              tickLine: false,
            }),

            React.createElement(YA2, {
              domain: [0, 1],
              tick: {
                fill: chartText,
                fontSize: 11,
              },
              axisLine: false,
              tickLine: false,
            }),

            React.createElement(TT2, {
              contentStyle: {
                background: dark ? '#1a2332' : '#fff',
                border: 'none',
                borderRadius: 8,
                fontSize: 13,
              },
            }),

            React.createElement(B2, {
              dataKey: 'ai',
              name: 'AI Ranker',
              fill: '#3884f4',
              radius: [6, 6, 0, 0],
            }),

            React.createElement(B2, {
              dataKey: 'cvss',
              name: 'CVSS',
              fill: '#f97316',
              radius: [6, 6, 0, 0],
            }),
          ),
        ),

        React.createElement('p', {
          style: {
            fontSize: 12,
            color: sub,
            marginTop: 12,
            lineHeight: 1.5,
          },
        },
          'On the held-out EPSS ranking test, the AI ranker outperformed CVSS on AUCPR, ROC-AUC, and NDCG. It also required fewer findings to be reviewed to cover 80% of EPSS-positive cases.',
        ),
      ),
    ),

    React.createElement('div', {
      style: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
        gap: 20,
      },
    },

      React.createElement(GlassCard, null,
        React.createElement('h3', {
          style: {
            fontSize: 15,
            fontWeight: 800,
            color: t,
            margin: '0 0 18px',
          },
        }, 'Clean Model — Confusion Matrix'),

        React.createElement(ConfusionMatrixClean, null),

        React.createElement('p', {
          style: {
            fontSize: 12,
            color: sub,
            marginTop: 14,
            lineHeight: 1.5,
          },
        },
          'The clean model is strict: it keeps false positives low, but misses some true positives. For that reason, the dashboard does not use it as a hard gate.',
        ),
      ),

      React.createElement(GlassCard, null,
        React.createElement('h3', {
          style: {
            fontSize: 15,
            fontWeight: 800,
            color: t,
            margin: '0 0 16px',
          },
        }, 'Clean Model Ablation Check'),

        React.createElement(RC2, { width: '100%', height: 230 },
          React.createElement(BC2, {
            data: ablationData,
            margin: {
              top: 8,
              right: 8,
              bottom: 0,
              left: -12,
            },
          },
            React.createElement(CG2, {
              strokeDasharray: '3 3',
              stroke: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)',
            }),

            React.createElement(XA2, {
              dataKey: 'test',
              tick: {
                fill: chartText,
                fontSize: 11,
              },
              axisLine: false,
              tickLine: false,
            }),

            React.createElement(YA2, {
              domain: [0.65, 0.92],
              tick: {
                fill: chartText,
                fontSize: 11,
              },
              axisLine: false,
              tickLine: false,
            }),

            React.createElement(TT2, {
              contentStyle: {
                background: dark ? '#1a2332' : '#fff',
                border: 'none',
                borderRadius: 8,
                fontSize: 13,
              },
            }),

            React.createElement(B2, {
              dataKey: 'aucpr',
              name: 'AUCPR',
              fill: '#3884f4',
              radius: [6, 6, 0, 0],
            }),

            React.createElement(B2, {
              dataKey: 'roc',
              name: 'ROC-AUC',
              fill: '#22c55e',
              radius: [6, 6, 0, 0],
            }),
          ),
        ),

        React.createElement('p', {
          style: {
            fontSize: 12,
            color: sub,
            marginTop: 12,
            lineHeight: 1.5,
          },
        },
          'Removing source metadata and CVSS subcomponents did not collapse the clean model, which supports that it is not only copying source bias or CVSS logic.',
        ),
      ),
    ),

    React.createElement(GlassCard, null,
      React.createElement('h3', {
        style: {
          fontSize: 15,
          fontWeight: 800,
          color: t,
          margin: '0 0 12px',
        },
      }, 'Important limitation'),

      React.createElement('div', {
        style: {
          padding: 14,
          borderRadius: 12,
          border: `1px solid ${border}`,
          background: dark ? 'rgba(255,255,255,0.025)' : 'rgba(15,23,42,0.02)',
          color: sub,
          fontSize: 13,
          lineHeight: 1.6,
        },
      },
        'The AI score is not a vulnerability detector and does not replace SAST, SCA, DAST, CVSS, or analyst review. Scanner findings remain the source of detection. The AI models only help prioritize which findings should be reviewed first.',
      ),
    ),
  );
}

export default ModelInsightsPage;