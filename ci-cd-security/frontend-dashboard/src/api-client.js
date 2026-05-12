// API Client — connected to real FastAPI backend at http://127.0.0.1:8000
// Mock fallback is disabled. Empty safe defaults are used when backend is unavailable.

window.API_BASE_URL  = 'http://127.0.0.1:8000';
window.USE_MOCK_DATA = false;
window.ALLOW_MOCK_FALLBACK = false;

// Normalize a raw `ai_scores` row from the FastAPI backend into the shape the
// dashboard components expect. Real scanner metadata is extracted from raw_input.
window._normalizeScore = function (r) {
  let raw = {};
  if (r.raw_input) {
    try { raw = JSON.parse(r.raw_input); } catch (_) { /* ignore */ }
  }

  const ddId = r.defectdojo_finding_id || null;

  const cveId =
    (raw.vulnerability_id && String(raw.vulnerability_id).trim()) ||
    (r.cve_id             && String(r.cve_id).trim())             ||
    (ddId ? `Finding-${ddId}` : `Finding-${r.id}`);

  const title =
    (raw.title            && String(raw.title).trim())            ||
    (raw.vulnerability_id && String(raw.vulnerability_id).trim()) ||
    (r.cve_id             && String(r.cve_id).trim())             ||
    (ddId ? `Finding #${ddId}` : `Finding #${r.id}`);

  const product =
    (r.product_name       && String(r.product_name).trim())       ||
    (raw.product_name     && String(raw.product_name).trim())     ||
    (r.source === 'api' ? 'Manual' : 'DefectDojo');

  const scannerType =
    (r.scanner_type && String(r.scanner_type).trim().toUpperCase()) || 'SCA';

  // SCA findings usually carry component_name/component_version.
  // DAST/header findings do not have a package, so show a meaningful web label.
  const componentName =
    (raw.component_name && String(raw.component_name).trim()) || null;

  const componentVersion =
    (raw.component_version && String(raw.component_version).trim()) || null;

  const packageName =
    (componentName && componentVersion) ? `${componentName}@${componentVersion}` :
    componentName ? componentName :
    (raw.package_name && String(raw.package_name).trim()) ? String(raw.package_name).trim() :
    (scannerType === 'DAST' ? 'Web response/header' : 'N/A');

  // SAST findings normally have a source file; DAST findings are HTTP/web-target based.
  const filePath =
    (raw.file_path && String(raw.file_path).trim()) ? String(raw.file_path).trim() :
    (raw.url && String(raw.url).trim())             ? String(raw.url).trim() :
    (raw.endpoint && String(raw.endpoint).trim())   ? String(raw.endpoint).trim() :
    (scannerType === 'DAST' ? 'HTTP response' : 'N/A');

  const riskScore = r.risk_score ?? 0;

  const riskCategory =
    r.risk_category ||
    (riskScore >= 70 ? 'High' : riskScore >= 30 ? 'Medium' : 'Low');

  const severity = r.predicted_severity || 'Medium';

  return {
    id:                    r.id,
    created_at:            r.created_at,
    cve_id:                cveId,
    scanner_type:          scannerType,
    cvss_score:            r.cvss_score          ?? 0,
    risk_score:            riskScore,
    risk_category:         riskCategory,
    is_high_risk:          Boolean(r.is_high_risk),
    predicted_severity:    severity,
    exploit_probability:   r.exploit_probability ?? 0,
    prob_low:              r.prob_low            ?? 0,
    prob_medium:           r.prob_medium         ?? 0,
    prob_high:             r.prob_high           ?? 0,
    prob_critical:         r.prob_critical       ?? 0,
    source:                r.source              || 'defectdojo',
    defectdojo_finding_id: ddId,

    title:              title,
    severity:           severity,
    product:            product,
    package_name:       packageName,
    file_path:          filePath,
    fix_recommendation: 'Review and remediate based on AI risk score',
  };
};

window.ApiClient = {
  async getHealth() {
    if (window.USE_MOCK_DATA) return [];
    try {
      const res = await fetch(`${window.API_BASE_URL}/api/health/`);
      if (!res.ok) throw new Error('Backend unreachable');
      return await res.json();
    } catch (e) {
      console.warn('Health check failed:', e);
      return { status: 'offline' };
    }
  },

  async getProducts() {
    if (window.USE_MOCK_DATA) {
      return [
        { id: 3, name: 'juice-shop' },
        { id: 4, name: 'DVWA' },
        { id: 5, name: 'dvna' },
        { id: 6, name: 'nodegoat' },
      ];
    }

    try {
      const res = await fetch(`${window.API_BASE_URL}/api/products/`);
      if (!res.ok) throw new Error('Failed to fetch products');
      const data = await res.json();

      return Array.isArray(data)
        ? data.map(p => ({ id: p.id, name: String(p.name || p.id) }))
        : [];
    } catch (e) {
      console.warn('Products fetch failed:', e);
      return [];
    }
  },

  async getScores(params = {}) {
    if (window.USE_MOCK_DATA) return [];

    try {
      const qs = new URLSearchParams({
        source: 'defectdojo',
        limit: 2000,
        ...params,
      }).toString();

      const res = await fetch(`${window.API_BASE_URL}/api/scores/?${qs}`);
      if (!res.ok) throw new Error('Failed to fetch scores');

      const rows = await res.json();
      return rows.map(window._normalizeScore);
    } catch (e) {
      console.warn('Scores fetch failed:', e);
      return [];
    }
  },

  async scoreFinding(payload) {
    if (window.USE_MOCK_DATA) {
      await new Promise(r => setTimeout(r, 500));
      return null;
    }

    try {
      const res = await fetch(`${window.API_BASE_URL}/api/score-finding/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error('Scoring failed');
      return await res.json();
    } catch (e) {
      console.warn('Score finding failed:', e);
      throw e;
    }
  },

  async getNotifications(limit = 10) {
    if (window.USE_MOCK_DATA) return window.MOCK_NOTIFICATIONS || [];

    try {
      const res = await fetch(`${window.API_BASE_URL}/api/notifications/?limit=${limit}`);
      if (!res.ok) throw new Error('Failed to fetch notifications');

      const rows = await res.json();

      return rows.map(n => ({
        id:         n.id,
        cve:        n.cve || (n.defectdojo_finding_id ? `Finding-${n.defectdojo_finding_id}` : `#${n.id}`),
        severity:   n.severity || 'High',
        risk_score: n.risk_score ?? 0,
        product:    n.product_name || 'DefectDojo',
        time:       _humanTime(n.created_at),
        message:    n.message || '',
      }));
    } catch (e) {
      console.warn('Notifications fetch failed:', e);
      return [];
    }
  },

  async getTrends(weeks = 8) {
    if (window.USE_MOCK_DATA) return [];

    try {
      const res = await fetch(`${window.API_BASE_URL}/api/trends/?weeks=${weeks}`);
      if (!res.ok) throw new Error('Failed to fetch trends');

      const rows = await res.json();

      return rows.map(r => ({
        date:     r.date,
        critical: r.Critical ?? r.critical ?? 0,
        high:     r.High     ?? r.high     ?? 0,
        medium:   r.Medium   ?? r.medium   ?? 0,
        low:      r.Low      ?? r.low      ?? 0,
      }));
    } catch (e) {
      console.warn('Trends fetch failed:', e);
      return [];
    }
  },

  async syncDefectDojo(payload) {
    if (window.USE_MOCK_DATA) {
      await new Promise(r => setTimeout(r, 1500));
      return window.MOCK_SYNC_STATUS;
    }

    try {
      const res = await fetch(`${window.API_BASE_URL}/api/sync-defectdojo/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Sync failed');
      }

      return await res.json();
    } catch (e) {
      console.warn('Sync failed:', e);
      throw e;
    }
  },

  async refreshCache() {
    try {
      const [scores, notifications, trends] = await Promise.all([
        this.getScores(),
        this.getNotifications(),
        this.getTrends(),
      ]);

      window._cachedFindings      = scores;
      window._cachedNotifications = notifications;
      window._cachedTrends        = trends;

      return true;
    } catch (e) {
      console.warn('Cache refresh failed:', e);
      return false;
    }
  },
};

function _humanTime(isoStr) {
  if (!isoStr) return '';

  const d = new Date(isoStr);
  const s = Math.floor((Date.now() - d.getTime()) / 1000);

  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;

  return `${Math.floor(s / 86400)}d ago`;
}
