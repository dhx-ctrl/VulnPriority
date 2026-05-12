// Model Insights Page
const { ResponsiveContainer: RC2, BarChart: BC2, Bar: B2, XAxis: XA2, YAxis: YA2, Tooltip: TT2, CartesianGrid: CG2, LineChart: LC2, Line: L2 } = Recharts;

function ConfusionMatrix() {
  const { dark } = useTheme();
  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';
  const cells = [
    { label: 'TN', value: 529, row: 0, col: 0, color: '#22c55e' },
    { label: 'FP', value: 293, row: 0, col: 1, color: '#f97316' },
    { label: 'FN', value: 29, row: 1, col: 0, color: '#ef4444' },
    { label: 'TP', value: 158, row: 1, col: 1, color: '#3884f4' },
  ];
  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 } },
    React.createElement('div', { style: { display: 'flex', gap: 4, fontSize: 11, color: sub, marginBottom: 4 } },
      React.createElement('span', { style: { width: 80 } }),
      React.createElement('span', { style: { width: 120, textAlign: 'center' } }, 'Predicted Low'),
      React.createElement('span', { style: { width: 120, textAlign: 'center' } }, 'Predicted High'),
    ),
    ['Actual Low', 'Actual High'].map((rowLabel, ri) =>
      React.createElement('div', { key: ri, style: { display: 'flex', gap: 4, alignItems: 'center' } },
        React.createElement('span', { style: { width: 80, fontSize: 11, color: sub, textAlign: 'right', paddingRight: 8 } }, rowLabel),
        cells.filter(c => c.row === ri).map(c =>
          React.createElement('div', {
            key: c.label,
            style: {
              width: 120, height: 80, borderRadius: 8, display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center', gap: 4,
              background: c.color + (dark ? '18' : '10'), border: `1px solid ${c.color}30`,
            },
          },
            React.createElement('span', { style: { fontSize: 11, fontWeight: 700, color: c.color } }, c.label),
            React.createElement('span', { style: { fontSize: 24, fontWeight: 800, color: t } }, c.value),
          )
        ),
      )
    ),
  );
}

function MetricRow({ label, value, accent }) {
  const { dark } = useTheme();
  return React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: `1px solid ${dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.04)'}` } },
    React.createElement('span', { style: { fontSize: 13, color: dark ? '#94a3b8' : '#64748b' } }, label),
    React.createElement('span', { style: { fontSize: 14, fontWeight: 700, color: accent || (dark ? '#e2e8f0' : '#1e293b') } }, value),
  );
}

function ModelInsightsPage() {
  const { dark } = useTheme();
  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';

  const learningData = [
    { pct: '20%', auc: 0.788 }, { pct: '40%', auc: 0.801 }, { pct: '60%', auc: 0.812 },
    { pct: '80%', auc: 0.820 }, { pct: '100%', auc: 0.824 },
  ];
  const chartText = dark ? '#94a3b8' : '#64748b';

  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 24 } },
    React.createElement('div', null,
      React.createElement('h1', { style: { fontSize: 24, fontWeight: 800, color: t, margin: '0 0 4px' } }, 'Model Insights'),
      React.createElement('p', { style: { fontSize: 14, color: sub, margin: 0 } }, 'AI model performance metrics and evaluation'),
    ),
    // Model cards
    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 20 } },
      // Binary
      React.createElement(GlassCard, null,
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 } },
          React.createElement('div', { style: { width: 40, height: 40, borderRadius: 8, background: 'linear-gradient(135deg, #3884f4, #3884f4)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 18 } }, '⊘'),
          React.createElement('div', null,
            React.createElement('div', { style: { fontSize: 16, fontWeight: 700, color: t } }, 'Binary Classifier'),
            React.createElement('div', { style: { fontSize: 12, color: sub } }, 'XGBoost v3.0'),
          ),
        ),
        React.createElement('p', { style: { fontSize: 13, color: sub, margin: '0 0 14px', lineHeight: 1.5 } }, 'Predicts exploit likelihood using EPSS data. Findings with EPSS ≥ 0.01 are labeled as High Risk. The model outputs a probability, thresholded at 0.3819 to flag high-risk items.'),
        React.createElement(MetricRow, { label: 'ROC-AUC', value: '0.8248', accent: '#3884f4' }),
        React.createElement(MetricRow, { label: 'PR-AUC', value: '0.5104' }),
        React.createElement(MetricRow, { label: 'False Negative Rate', value: '15.5%', accent: '#f97316' }),
        React.createElement(MetricRow, { label: 'Decision Threshold', value: '0.3819' }),
        React.createElement(MetricRow, { label: 'Features Used', value: '12' }),
      ),
      // Multiclass
      React.createElement(GlassCard, null,
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 } },
          React.createElement('div', { style: { width: 40, height: 40, borderRadius: 8, background: 'linear-gradient(135deg, #2563eb, #60a5fa)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 18 } }, '◈'),
          React.createElement('div', null,
            React.createElement('div', { style: { fontSize: 16, fontWeight: 700, color: t } }, 'Multiclass Classifier'),
            React.createElement('div', { style: { fontSize: 12, color: sub } }, 'XGBoost v3.0 Multi'),
          ),
        ),
        React.createElement('p', { style: { fontSize: 13, color: sub, margin: '0 0 14px', lineHeight: 1.5 } }, 'Predicts vulnerability severity into four classes: Critical, High, Medium, and Low. Used alongside the binary model to provide a complete risk assessment for each finding.'),
        React.createElement(MetricRow, { label: 'Accuracy', value: '0.96', accent: '#22c55e' }),
        React.createElement(MetricRow, { label: 'Macro F1-Score', value: '0.9430', accent: '#22c55e' }),
        React.createElement(MetricRow, { label: 'Features Used', value: '13' }),
      ),
    ),
    // Confusion Matrix
    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 20 } },
      React.createElement(GlassCard, null,
        React.createElement('h3', { style: { fontSize: 15, fontWeight: 700, color: t, margin: '0 0 20px' } }, 'Binary Model — Confusion Matrix'),
        React.createElement(ConfusionMatrix, null),
        React.createElement('p', { style: { fontSize: 12, color: sub, marginTop: 14, lineHeight: 1.5 } }, 'Out of 1,009 test samples: 529 true negatives, 158 true positives, 293 false positives, and only 29 false negatives. The low FN count means the model rarely misses truly high-risk vulnerabilities.'),
      ),
      // Learning curve
      React.createElement(GlassCard, null,
        React.createElement('h3', { style: { fontSize: 15, fontWeight: 700, color: t, margin: '0 0 16px' } }, 'Learning Curve'),
        React.createElement(RC2, { width: '100%', height: 220 },
          React.createElement(LC2, { data: learningData },
            React.createElement(CG2, { strokeDasharray: '3 3', stroke: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)' }),
            React.createElement(XA2, { dataKey: 'pct', tick: { fill: chartText, fontSize: 12 }, axisLine: false, label: { value: 'Training Data', position: 'insideBottom', offset: -5, fill: chartText, fontSize: 11 } }),
            React.createElement(YA2, { domain: [0.75, 0.85], tick: { fill: chartText, fontSize: 12 }, axisLine: false, label: { value: 'ROC-AUC', angle: -90, position: 'insideLeft', fill: chartText, fontSize: 11 } }),
            React.createElement(TT2, { contentStyle: { background: dark ? '#1a2332' : '#fff', border: 'none', borderRadius: 8, fontSize: 13 } }),
            React.createElement(L2, { type: 'monotone', dataKey: 'auc', stroke: '#3884f4', strokeWidth: 3, dot: { fill: '#3884f4', r: 5 } }),
          ),
        ),
        React.createElement('p', { style: { fontSize: 12, color: sub, marginTop: 12, lineHeight: 1.5 } }, 'Model performance improved steadily as training data increased from 20% to 100%, rising from 0.788 to 0.824 ROC-AUC. This demonstrates that more training data reduces missed high-risk CVEs and improves robustness.'),
      ),
    ),
  );
}

Object.assign(window, { ModelInsightsPage });
