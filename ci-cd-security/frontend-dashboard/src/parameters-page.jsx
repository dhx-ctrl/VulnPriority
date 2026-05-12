// Parameters Page

function ParametersPage() {
  const { dark, toggle } = useTheme();
  const { settings, update } = useSettings();
  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';
  const border = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
  const inputBg = dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)';

  const sliderStyle = { width: '100%', accentColor: '#3884f4' };
  const labelStyle = { fontSize: 13, fontWeight: 600, color: t, marginBottom: 6, display: 'block' };
  const descStyle = { fontSize: 12, color: sub, marginTop: 4 };

  function Section({ title, children }) {
    return React.createElement(GlassCard, { style: { marginBottom: 0 } },
      React.createElement('h3', { style: { fontSize: 16, fontWeight: 700, color: t, margin: '0 0 18px' } }, title),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 20 } }, children),
    );
  }

  function Toggle({ label, desc, checked, onChange }) {
    return React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 } },
      React.createElement('div', null,
        React.createElement('div', { style: { fontSize: 13, fontWeight: 600, color: t } }, label),
        desc && React.createElement('div', { style: descStyle }, desc),
      ),
      React.createElement('button', {
        onClick: () => onChange(!checked),
        style: {
          width: 44, height: 24, borderRadius: 12, border: 'none', cursor: 'pointer', flexShrink: 0,
          background: checked ? '#3884f4' : (dark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.1)'),
          position: 'relative', transition: 'background 0.2s',
        },
      },
        React.createElement('div', { style: { width: 18, height: 18, borderRadius: '50%', background: '#fff', position: 'absolute', top: 3, left: checked ? 23 : 3, transition: 'left 0.2s', boxShadow: '0 1px 3px rgba(0,0,0,0.2)' } }),
      ),
    );
  }

  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 720 } },
    React.createElement('h1', { style: { fontSize: 24, fontWeight: 800, color: t, margin: 0 } }, 'Parameters'),
    // AI Thresholds
    React.createElement(Section, { title: 'AI Risk Thresholds' },
      React.createElement('div', null,
        React.createElement('label', { style: labelStyle }, `High-Risk Threshold: ${settings.highRiskThreshold}`),
        React.createElement('input', { type: 'range', min: 50, max: 100, value: settings.highRiskThreshold, onChange: e => update('highRiskThreshold', +e.target.value), style: sliderStyle }),
        React.createElement('div', { style: descStyle }, 'Findings with AI risk score above this value are flagged as high-risk'),
      ),
      React.createElement('div', null,
        React.createElement('label', { style: labelStyle }, `Build Block Threshold: ${settings.blockThreshold}`),
        React.createElement('input', { type: 'range', min: 60, max: 100, value: settings.blockThreshold, onChange: e => update('blockThreshold', +e.target.value), style: sliderStyle }),
        React.createElement('div', { style: descStyle }, 'CI/CD builds are blocked when any finding exceeds this score'),
      ),
    ),
    // Filtering
    React.createElement(Section, { title: 'Display Filters' },
      React.createElement(Toggle, { label: 'Show only high-risk findings', desc: 'Hide findings below the high-risk threshold', checked: settings.showHighRiskOnly, onChange: v => update('showHighRiskOnly', v) }),
      React.createElement(Toggle, { label: 'Hide low severity', desc: 'Filter out Low severity findings from all views', checked: settings.hideLowSev, onChange: v => update('hideLowSev', v) }),
      React.createElement(Toggle, { label: 'Show only fixable issues', desc: 'Display findings that have a known patched version', checked: settings.showFixableOnly, onChange: v => update('showFixableOnly', v) }),
    ),
    // Default product
    React.createElement(Section, { title: 'Defaults' },
      React.createElement('div', null,
        React.createElement('label', { style: labelStyle }, 'Default Product'),
        React.createElement('select', {
          value: settings.defaultProduct, onChange: e => update('defaultProduct', e.target.value),
          style: { padding: '10px 14px', borderRadius: 10, border: `1px solid ${border}`, background: inputBg, color: t, fontSize: 13, outline: 'none', width: '100%' },
        },
          React.createElement('option', { value: 'All' }, 'All Products'),
          React.createElement('option', { value: 'JuiceShop' }, 'JuiceShop'),
          React.createElement('option', { value: 'DVWA' }, 'DVWA'),
        ),
      ),
    ),
    // Notifications & Theme
    React.createElement(Section, { title: 'Preferences' },
      React.createElement(Toggle, { label: 'Notifications', desc: 'Show alerts for new critical and high-risk findings', checked: settings.notifications, onChange: v => update('notifications', v) }),
      React.createElement(Toggle, { label: 'Dark Mode', desc: 'Switch between light and dark theme', checked: dark, onChange: () => toggle() }),
    ),
  );
}

Object.assign(window, { ParametersPage });
