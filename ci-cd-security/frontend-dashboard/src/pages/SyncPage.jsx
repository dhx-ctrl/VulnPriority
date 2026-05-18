import React, { useState, useMemo } from 'react';
import { useTheme } from '../context/AppContext.jsx';
import { useData } from '../context/DataContext.jsx';
import { apiClient, USE_MOCK_DATA } from '../services/api-client.js';
import { MOCK_SEVERITY_BREAKDOWN, MOCK_SYNC_STATUS } from '../data/mock-data.js';
import { GlassCard } from './DashboardPage.jsx';
import { NavIcon } from '../components/Layout.jsx';
// Sync Page — DefectDojo sync that refreshes the in-memory cache when done.


function SyncPage() {
  const { dark } = useTheme();
  const { findings, refreshData } = useData();
  const t       = dark ? '#e2e8f0' : '#1e293b';
  const sub     = dark ? '#94a3b8' : '#64748b';
  const muted   = dark ? '#4a5d78' : '#8898b0';
  const border  = dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)';
  const inputBg = dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)';

  // Product selector state
  const [products,          setProducts]          = useState([]);
  const [productsLoading,   setProductsLoading]   = useState(false);
  const [productsError,     setProductsError]     = useState('');
  const [selectedProductId, setSelectedProductId] = useState(null);
  const [productName,       setProductName]       = useState('');

  const [limit,      setLimit]      = useState(500);
  const [activeOnly, setActiveOnly] = useState(true);
  const [syncState,  setSyncState]  = useState('idle');   // idle | syncing | done | error
  const [stepIndex,  setStepIndex]  = useState(0);
  const [result,     setResult]     = useState(null);
  const [syncTime,   setSyncTime]   = useState(null);
  const [error,      setError]      = useState('');

  const steps = [
    'Connecting to DefectDojo…',
    'Fetching findings…',
    'Running dual AI scoring…',
    'Storing ranked results…',
    'Refreshing dashboard…',
  ];

  const handleFetchProducts = async () => {
    setProductsLoading(true);
    setProductsError('');
    try {
      const list = await apiClient.getProducts();
      setProducts(list);
      if (list.length === 0) {
        setProductsError('No products returned from backend.');
      } else if (!selectedProductId && !productName.trim()) {
        // Auto-select the first product
        setSelectedProductId(list[0].id);
        setProductName(list[0].name);
      }
    } catch (e) {
      setProductsError('Failed to fetch products. Check backend connection.');
    } finally {
      setProductsLoading(false);
    }
  };

  const handleSelectProduct = (p) => {
    setSelectedProductId(p.id);
    setProductName(p.name);
  };

  const handleSync = async () => {
    // Validate: need either a selected product ID or a manually typed name
    if (!selectedProductId && !productName.trim()) {
      setSyncState('error');
      setError('Fetch or enter a DefectDojo product first.');
      return;
    }

    setSyncState('syncing');
    setStepIndex(0);
    setResult(null);
    setError('');

    // Build payload
    const payload = selectedProductId
      ? { product_id: selectedProductId, limit: Number(limit), active_only: activeOnly }
      : { product_name: productName.trim(), limit: Number(limit), active_only: activeOnly };

    if (USE_MOCK_DATA) {
      // Step-by-step animation when running against the mock data
      let step = 0;
      const advance = () => {
        step++;
        setStepIndex(step);
        if (step < steps.length - 1) {
          setTimeout(advance, 600 + Math.random() * 400);
        } else {
          setSyncState('done');
          setResult(MOCK_SYNC_STATUS);
          setSyncTime(new Date());
        }
      };
      setTimeout(advance, 700);
      return;
    }

    // Real backend flow:
    //  1) POST /api/sync-defectdojo/  (this can take many seconds for large products)
    //  2) Refresh the in-memory cache so all dashboard pages see the new findings
    try {
      // Step 1 + 2 + 3 happen server-side in a single request.
      // We bump the visible step so the user sees progress.
      setStepIndex(1);
      const data = await apiClient.syncDefectDojo(payload);

      // Backend response shape -> dashboard's expected shape
      // Backend returns: { product_id, total_fetched, scored, stored, skipped_on_error, high_risk_flagged, severity_breakdown, errors, note }
      const formatted = {
        status:             'Success',
        lastSync:           new Date().toISOString(),
        product_id:         data.product_id ?? selectedProductId,
        product_name:       productName.trim(),
        total_fetched:      data.total_fetched      ?? 0,
        scored:             data.scored             ?? 0,
        stored:             data.stored             ?? 0,
        skipped_on_error:   data.skipped_on_error   ?? 0,
        high_risk_flagged:  data.high_risk_flagged  ?? 0,
        severity_breakdown: data.severity_breakdown ?? null,
      };

      setStepIndex(3);
      setResult(formatted);

      // Step 4 — refresh cache so Dashboard / Findings / Scan History
      // immediately reflect the new data without a full page reload.
      setStepIndex(4);
      await refreshData();

      setStepIndex(steps.length);
      setSyncState('done');
      setSyncTime(new Date());
    } catch (e) {
      setSyncState('error');
      setError(e.message || 'Sync failed. Check backend connection.');
    }
  };

  // Severity breakdown — prefer the live result, then real cached findings,
  // and only fall back to mock when nothing real is available.
  const sev = useMemo(() => {
    // Prefer the breakdown returned by the most recent sync
    if (result && result.severity_breakdown) return result.severity_breakdown;

    // Otherwise compute from currently cached findings
    const src = findings;
    if (!src || src.length === 0) return MOCK_SEVERITY_BREAKDOWN;
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    src.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
    return counts;
  }, [result, findings]);

  const inputStyle = {
    width: '100%', padding: '10px 14px', borderRadius: 8, border: `1px solid ${border}`,
    background: inputBg, color: t, fontSize: 13, outline: 'none', boxSizing: 'border-box',
  };
  const labelStyle = { display: 'block', fontSize: 12, color: sub, marginBottom: 6 };

  // Helper text showing available products inline
  const productsHelperText = products.length > 0
    ? 'Available: ' + products.map(p => `${p.name} (ID ${p.id})`).join(', ')
    : null;

  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 20 } },
    React.createElement('div', null,
      React.createElement('h1', { style: { fontSize: 24, fontWeight: 800, color: t, margin: '0 0 4px', letterSpacing: '-0.02em' } }, 'Sync'),
      React.createElement('p', { style: { fontSize: 14, color: sub, margin: 0 } }, 'Sync findings from DefectDojo and score them with both AI models'),
    ),

    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '380px 1fr', gap: 20, alignItems: 'start' } },
      // Left: config form
      React.createElement(GlassCard, null,
        React.createElement('h3', { style: { fontSize: 15, fontWeight: 700, color: t, margin: '0 0 18px' } }, 'Sync Configuration'),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 16 } },

          // ── Product selector ────────────────────────────────────────────────
          React.createElement('div', null,
            React.createElement('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 } },
              React.createElement('label', { style: { ...labelStyle, marginBottom: 0 } }, 'Product'),
              React.createElement('button', {
                onClick: handleFetchProducts,
                disabled: productsLoading,
                style: {
                  padding: '4px 10px', borderRadius: 6, border: `1px solid ${border}`,
                  background: 'transparent', color: sub, fontSize: 11, cursor: 'pointer',
                  opacity: productsLoading ? 0.6 : 1, whiteSpace: 'nowrap',
                },
              }, productsLoading ? 'Loading…' : 'Fetch Product Names'),
            ),

            // Text input — editable, also updated by clicking a product chip
            React.createElement('input', {
              type: 'text',
              value: productName,
              placeholder: 'Type a name or fetch from backend…',
              onChange: e => {
                setProductName(e.target.value);
                // Deselect ID when the user edits manually
                setSelectedProductId(null);
              },
              style: inputStyle,
            }),

            // Helper text + product chips (shown once products are loaded)
            products.length > 0
              ? React.createElement('div', { style: { marginTop: 6 } },
                  React.createElement('div', { style: { fontSize: 11, color: muted, marginBottom: 6 } }, productsHelperText),
                  React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 4 } },
                    products.map(p =>
                      React.createElement('button', {
                        key: p.id,
                        onClick: () => handleSelectProduct(p),
                        style: {
                          padding: '3px 8px', borderRadius: 5, fontSize: 11, cursor: 'pointer',
                          border: `1px solid ${selectedProductId === p.id ? '#3884f4' : border}`,
                          background: selectedProductId === p.id
                            ? (dark ? 'rgba(56,132,244,0.18)' : 'rgba(56,132,244,0.10)')
                            : 'transparent',
                          color: selectedProductId === p.id ? '#3884f4' : sub,
                          transition: 'all 0.15s',
                        },
                      }, `${p.name} (${p.id})`),
                    ),
                  ),
                )
              : React.createElement('div', { style: { fontSize: 11, color: muted, marginTop: 4 } },
                  productsError
                    ? React.createElement('span', { style: { color: '#ef4444' } }, productsError)
                    : 'Click "Fetch Product Names" to load available products',
                ),
          ),

          // ── Limit ───────────────────────────────────────────────────────────
          React.createElement('div', null,
            React.createElement('label', { style: labelStyle }, 'Limit'),
            React.createElement('input', { type: 'number', value: limit, onChange: e => setLimit(+e.target.value), style: inputStyle }),
            React.createElement('div', { style: { fontSize: 11, color: muted, marginTop: 4 } }, 'Max findings to fetch per sync'),
          ),

          // ── Active only ─────────────────────────────────────────────────────
          React.createElement('div', null,
            React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13, color: sub } },
              React.createElement('input', { type: 'checkbox', checked: activeOnly, onChange: e => setActiveOnly(e.target.checked), style: { accentColor: '#3884f4' } }),
              'Active engagements only',
            ),
            React.createElement('div', { style: { fontSize: 11, color: muted, marginTop: 4, paddingLeft: 24 } }, 'Skip closed or archived engagements'),
          ),

          React.createElement('button', {
            onClick: handleSync,
            disabled: syncState === 'syncing',
            style: {
              width: '100%', padding: '12px', borderRadius: 8, border: 'none', cursor: 'pointer',
              background: 'linear-gradient(135deg, #3884f4, #2563eb)', color: '#fff',
              fontSize: 14, fontWeight: 600, transition: 'all 0.3s', marginTop: 4,
              opacity: syncState === 'syncing' ? 0.7 : 1,
            },
          }, syncState === 'syncing' ? 'Syncing…' : 'Sync Now'),
        ),

        // Progress steps
        syncState === 'syncing' && React.createElement('div', { style: { marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 } },
          React.createElement('div', { style: { height: 2, background: border, borderRadius: 1, overflow: 'hidden', marginBottom: 8 } },
            React.createElement('div', { style: { height: '100%', background: '#3884f4', width: `${Math.min(100, (stepIndex / (steps.length - 1)) * 100)}%`, transition: 'width 0.4s ease', borderRadius: 1 } }),
          ),
          steps.map((s, i) =>
            React.createElement('div', { key: i, style: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 } },
              React.createElement('div', {
                style: {
                  width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                  background: i < stepIndex ? '#22c55e' : i === stepIndex ? '#3884f4' : (dark ? '#2a3d5a' : '#c8d0e4'),
                },
              }),
              React.createElement('span', {
                style: { color: i < stepIndex ? '#22c55e' : i === stepIndex ? t : muted },
              }, s),
            ),
          ),
        ),
      ),

      // Right: Results / idle / error states
      React.createElement('div', null,
        result && React.createElement(GlassCard, null,
          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 } },
            React.createElement('div', { style: { width: 10, height: 10, borderRadius: '50%', background: '#22c55e' } }),
            React.createElement('span', { style: { fontSize: 20, fontWeight: 700, color: '#22c55e' } }, 'Sync Successful'),
          ),
          // Product info
          result.product_name && React.createElement('div', {
            style: { fontSize: 13, color: sub, marginBottom: 14 },
          }, 'Product: ',
            React.createElement('span', { style: { color: t, fontWeight: 600 } },
              result.product_name + (result.product_id ? ` (ID ${result.product_id})` : '')
            ),
          ),
          // Stats grid
          React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 18 } },
            [
              { label: 'Total Fetched',    val: result.total_fetched },
              { label: 'Scored',           val: result.scored },
              { label: 'Stored',           val: result.stored },
              { label: 'Skipped on Error', val: result.skipped_on_error },
              { label: 'Strict Op. Alerts', val: result.high_risk_flagged, highlight: true },
            ].map(({ label, val, highlight }) =>
              React.createElement('div', {
                key: label,
                style: {
                  background: dark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)',
                  border: `1px solid ${border}`, borderRadius: 8, padding: '12px 16px',
                },
              },
                React.createElement('div', { style: { fontSize: 22, fontWeight: 700, color: highlight ? '#ef4444' : t } }, val),
                React.createElement('div', { style: { fontSize: 11, color: muted, marginTop: 2 } }, label),
              ),
            ),
          ),
          // Severity breakdown
          React.createElement('div', null,
            React.createElement('div', { style: { fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: muted, marginBottom: 8 } }, 'Severity Breakdown'),
            React.createElement('div', { style: { display: 'flex', gap: 2, height: 10, borderRadius: 5, overflow: 'hidden', marginBottom: 8 } },
              [
                { v: sev.Critical || 0, c: '#ef4444' },
                { v: sev.High     || 0, c: '#f97316' },
                { v: sev.Medium   || 0, c: '#eab308' },
                { v: sev.Low      || 0, c: '#22c55e' },
              ].map(({ v, c }, i) =>
                React.createElement('div', { key: i, style: { flex: v, background: c, borderRadius: i === 0 ? '4px 0 0 4px' : i === 3 ? '0 4px 4px 0' : 0 } }),
              ),
            ),
            React.createElement('div', { style: { display: 'flex', gap: 16, fontSize: 12 } },
              [
                { label: 'Critical', val: sev.Critical || 0, c: '#ef4444' },
                { label: 'High',     val: sev.High     || 0, c: '#f97316' },
                { label: 'Medium',   val: sev.Medium   || 0, c: '#eab308' },
                { label: 'Low',      val: sev.Low      || 0, c: '#22c55e' },
              ].map(({ label, val, c }) =>
                React.createElement('span', { key: label },
                  React.createElement('span', { style: { color: c, fontWeight: 700 } }, val),
                  React.createElement('span', { style: { color: muted, marginLeft: 4 } }, label),
                ),
              ),
            ),
          ),
          syncTime && React.createElement('div', {
            style: { marginTop: 16, fontSize: 11, color: muted, fontFamily: 'monospace' },
          }, 'Synced at ' + syncTime.toISOString().replace('T', ' ').slice(0, 19) + ' UTC'),
          // Hint
          React.createElement('div', {
            style: { marginTop: 12, padding: '10px 14px', borderRadius: 6, background: dark ? 'rgba(56,132,244,0.08)' : 'rgba(56,132,244,0.05)', fontSize: 12, color: sub },
          }, 'Dashboard, Findings and Scan History have been refreshed with dual-model scores. Use Rank /100 for queue priority and Clean /100 as the strict confidence signal.'),
        ),
        // Idle
        syncState === 'idle' && !result && React.createElement(GlassCard, {
          style: { display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 200 },
        },
          React.createElement(NavIcon, { name: 'sync', size: 32 }),
          React.createElement('div', { style: { fontSize: 14, color: muted, marginTop: 12 } }, 'Configure and run a sync to score findings with both AI models'),
        ),
        // Error
        syncState === 'error' && React.createElement(GlassCard, {
          style: { display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 200, gap: 8 },
        },
          React.createElement('div', { style: { fontSize: 14, color: '#ef4444', fontWeight: 600 } }, 'Sync failed'),
          React.createElement('div', { style: { fontSize: 12, color: sub, textAlign: 'center', maxWidth: 360, padding: '0 16px' } }, error || 'Check backend connection at http://127.0.0.1:8000'),
        ),
      ),
    ),
  );
}

export default SyncPage;
