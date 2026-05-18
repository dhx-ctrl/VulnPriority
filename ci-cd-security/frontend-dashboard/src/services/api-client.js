// API Client — connected to the FastAPI backend.
// Protected endpoints send X-API-Key after successful login.
// Backend URL priority:
//   1. window.VULNPRIORITY_API_BASE_URL
//   2. localStorage VULNPRIORITY_API_BASE_URL
//   3. <meta name="vulnpriority-api-base-url" content="...">
//   4. default local prototype URL: http://127.0.0.1:8000
//
// Dual-model frontend normalization:
//   - operational_rank_score is the primary dashboard sorting / queue-priority score.
//   - clean_ai_score is the strict leakage-safe confidence signal.
//   - legacy risk_score / risk_category / is_high_risk are kept as aliases for
//     the operational ranker so older pages do not break.

(function initApiConfig() {
  function cleanBaseUrl(value) {
    return String(value || '').trim().replace(/\/+$/, '');
  }

  function metaApiBaseUrl() {
    const tag = document.querySelector('meta[name="vulnpriority-api-base-url"]');
    return tag ? tag.getAttribute('content') : '';
  }

  window.ApiConfig = window.ApiConfig || {
    getApiBaseUrl() {
      return cleanBaseUrl(
        window.VULNPRIORITY_API_BASE_URL ||
        localStorage.getItem('VULNPRIORITY_API_BASE_URL') ||
        metaApiBaseUrl() ||
        'http://127.0.0.1:8000'
      );
    },

    setApiBaseUrl(url) {
      const cleaned = cleanBaseUrl(url);
      if (cleaned) {
        localStorage.setItem('VULNPRIORITY_API_BASE_URL', cleaned);
        window.API_BASE_URL = cleaned;
      }
      return window.API_BASE_URL;
    },

    clearApiBaseUrl() {
      localStorage.removeItem('VULNPRIORITY_API_BASE_URL');
      window.API_BASE_URL = this.getApiBaseUrl();
      return window.API_BASE_URL;
    },
  };

  window.API_BASE_URL = window.ApiConfig.getApiBaseUrl();
})();

window.USE_MOCK_DATA = false;
window.ALLOW_MOCK_FALLBACK = false;

window.API_AUTH_TOKEN =
  window.API_AUTH_TOKEN ||
  localStorage.getItem('VULNPRIORITY_API_TOKEN') ||
  '';

window.ApiAuth = {
  getToken() {
    return window.API_AUTH_TOKEN || localStorage.getItem('VULNPRIORITY_API_TOKEN') || '';
  },

  setToken(token) {
    const cleaned = String(token || '').trim();
    window.API_AUTH_TOKEN = cleaned;

    if (cleaned) {
      localStorage.setItem('VULNPRIORITY_API_TOKEN', cleaned);
    } else {
      localStorage.removeItem('VULNPRIORITY_API_TOKEN');
    }
  },

  clearToken() {
    window.API_AUTH_TOKEN = '';
    localStorage.removeItem('VULNPRIORITY_API_TOKEN');
  },

  authHeaders(extra = {}) {
    const token = this.getToken();
    return token ? { ...extra, 'X-API-Key': token } : { ...extra };
  },
};

async function readJsonOrText(res) {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (_) {
    return { detail: text };
  }
}

async function requireOk(res, fallbackMessage) {
  if (res.ok) return res;

  const body = await readJsonOrText(res);
  const detail = body.detail || body.message || fallbackMessage || `HTTP ${res.status}`;
  throw new Error(detail);
}

function _num(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function _nullableNum(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function _bool(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0 || value === null || value === undefined || value === '') return false;
  const s = String(value).trim().toLowerCase();
  return ['1', 'true', 'yes', 'y'].includes(s);
}

function _scoreCategory(score) {
  const n = _num(score, 0);
  if (n >= 70) return 'High';
  if (n >= 30) return 'Medium';
  return 'Low';
}

function _scannerSeverityRank(sev) {
  const s = String(sev || '').trim().toLowerCase();
  if (s === 'critical') return 4;
  if (s === 'high') return 3;
  if (s === 'medium') return 2;
  if (s === 'low') return 1;
  return 0;
}

function _buildPriorityTier(f) {
  const opScore = _num(f.operational_rank_score ?? f.risk_score, 0);
  const scannerRank = _scannerSeverityRank(
    f.scanner_severity || f.severity || f.defectdojo_severity
  );

  // Review First = operational ranker says it is urgent.
  // Clean AI flag is secondary, not a hard gate.
  if (f.operational_is_high_risk || opScore >= 70) {
    return 'Review First';
  }

  // Review Soon = medium operational score OR clean model also flags it.
  if (opScore >= 30 || f.clean_is_high_risk) {
    return 'Review Soon';
  }

  // Scanner says High/Critical, but operational rank is low.
  if (scannerRank >= 3) {
    return 'Severity Watch';
  }

  return 'Backlog';
}


function _buildNextAction(f) {
  switch (f.priority_tier) {
    case 'Review First':
      return 'Prioritize in analyst queue';
    case 'Review Soon':
      return 'Review after top-priority findings';
    case 'Severity Watch':
      return 'Check scanner severity and context';
    default:
      return 'Monitor / backlog';
  }
}

window._assignOperationalPercentiles = function (items) {
  if (!Array.isArray(items) || items.length === 0) return [];

  const sorted = [...items]
    .map((item, index) => ({ item, index }))
    .sort((a, b) => _num(b.item.operational_rank_score, 0) - _num(a.item.operational_rank_score, 0));

  const n = sorted.length;
  const byOriginalIndex = new Map();

  sorted.forEach((entry, rankIndex) => {
    const rank = rankIndex + 1;
    const scorePercentile = n <= 1
      ? 100
      : Math.round(((n - rankIndex - 1) / (n - 1)) * 1000) / 10;

    const topPercentile = Math.max(1, Math.ceil((rank / n) * 100));

    const patched = {
      ...entry.item,
      operational_rank: rank,
      operational_score_percentile: scorePercentile,
      operational_rank_percentile: entry.item.operational_rank_percentile ?? scorePercentile,
      operational_top_percentile: topPercentile,
    };

    patched.priority_tier = _buildPriorityTier(patched);
    patched.fix_recommendation = _buildNextAction(patched);
    patched.next_action = patched.fix_recommendation;

    byOriginalIndex.set(entry.index, patched);
  });

  return items.map((_, index) => byOriginalIndex.get(index));
};

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

  const componentName =
    (raw.component_name && String(raw.component_name).trim()) || null;

  const componentVersion =
    (raw.component_version && String(raw.component_version).trim()) || null;

  const packageName =
    (componentName && componentVersion) ? `${componentName}@${componentVersion}` :
    componentName ? componentName :
    (raw.package_name && String(raw.package_name).trim()) ? String(raw.package_name).trim() :
    (scannerType === 'DAST' ? 'Web response/header' : 'N/A');

  const filePath =
    (raw.file_path && String(raw.file_path).trim()) ? String(raw.file_path).trim() :
    (raw.url && String(raw.url).trim())             ? String(raw.url).trim() :
    (raw.endpoint && String(raw.endpoint).trim())   ? String(raw.endpoint).trim() :
    (scannerType === 'DAST' ? 'HTTP response' : 'N/A');

  const severity =
    r.scanner_severity ||
    r.defectdojo_severity ||
    r.severity ||
    raw.severity ||
    r.predicted_severity ||
    'Medium';

  const cleanScore = _nullableNum(r.clean_ai_score);
  const cleanExploitProbability = _nullableNum(r.clean_exploit_probability);

  const operationalRankScore =
    _nullableNum(r.operational_rank_score) ??
    _nullableNum(r.risk_score) ??
    0;

  const operationalExploitProbability =
    _nullableNum(r.operational_exploit_probability) ??
    _nullableNum(r.exploit_probability) ??
    (operationalRankScore / 100);

  const operationalCategory =
    r.operational_rank_category ||
    r.risk_category ||
    _scoreCategory(operationalRankScore);

  const cleanCategory =
    r.clean_ai_category ||
    (cleanScore === null ? null : _scoreCategory(cleanScore));

  const operationalIsHighRisk =
    r.operational_is_high_risk !== undefined && r.operational_is_high_risk !== null && r.operational_is_high_risk !== ''
      ? _bool(r.operational_is_high_risk)
      : _bool(r.is_high_risk);

  const cleanIsHighRisk = _bool(r.clean_is_high_risk);

  const normalized = {
    id:                    r.id,
    created_at:            r.created_at,
    cve_id:                cveId,
    scanner_type:          scannerType,
    cvss_score:            _num(r.cvss_score, 0),

    risk_score:            operationalRankScore,
    risk_category:         operationalCategory,
    is_high_risk:          operationalIsHighRisk,
    exploit_probability:   operationalExploitProbability,

    clean_ai_score:            cleanScore,
    clean_ai_category:         cleanCategory,
    clean_is_high_risk:        cleanIsHighRisk,
    clean_exploit_probability: cleanExploitProbability,
    clean_threshold_used:      _nullableNum(r.clean_threshold_used),
    clean_model_version:       r.clean_model_version || null,

    operational_rank_score:          operationalRankScore,
    operational_rank_category:       operationalCategory,
    operational_is_high_risk:        operationalIsHighRisk,
    operational_exploit_probability: operationalExploitProbability,
    operational_threshold_used:      _nullableNum(r.operational_threshold_used),
    operational_rank_percentile:     _nullableNum(r.operational_rank_percentile),
    operational_model_version:       r.operational_model_version || null,

    scanner_severity:      severity,
    defectdojo_severity:   severity,
    predicted_severity:    r.predicted_severity || null,

    prob_low:              r.prob_low ?? 0,
    prob_medium:           r.prob_medium ?? 0,
    prob_high:             r.prob_high ?? 0,
    prob_critical:         r.prob_critical ?? 0,

    source:                r.source || 'defectdojo',
    defectdojo_finding_id: ddId,

    title:                 title,
    severity:              severity,
    product:               product,
    package_name:          packageName,
    file_path:             filePath,

    priority_tier:         null,
    fix_recommendation:    'Review according to operational rank, clean AI flag, CVSS, and scanner severity',
    next_action:           'Review according to operational rank',
  };

  normalized.priority_tier = _buildPriorityTier(normalized);
  normalized.fix_recommendation = _buildNextAction(normalized);
  normalized.next_action = normalized.fix_recommendation;

  return normalized;
};

window.ApiClient = {
  async login(username, password) {
    const res = await fetch(`${window.API_BASE_URL}/api/login/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    const data = await readJsonOrText(res);

    if (!res.ok) {
      const detail = data.detail || data.message || {};

      const message =
        typeof detail === 'object'
          ? (detail.message || 'Login failed')
          : String(detail || 'Login failed');

      const err = new Error(message);
      err.status = res.status;
      err.code = typeof detail === 'object' ? detail.code : undefined;
      err.access_status = typeof detail === 'object' ? detail.access_status : undefined;
      throw err;
    }

    if (!data.access_token) {
      throw new Error('Login response did not include access_token');
    }

    window.ApiAuth.setToken(data.access_token);
    return data;
  },

  async register(username, password) {
    const res = await fetch(`${window.API_BASE_URL}/api/register/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    const data = await readJsonOrText(res);

    if (!res.ok) {
      const detail = data.detail || data.message || 'Registration failed';

      const msg = Array.isArray(detail)
        ? detail.map(e => e.msg || String(e)).join(', ')
        : typeof detail === 'object'
          ? (detail.message || JSON.stringify(detail))
          : String(detail);

      throw new Error(msg);
    }

    return data;
  },

  async getUsers() {
    const res = await fetch(`${window.API_BASE_URL}/api/users/`, {
      headers: window.ApiAuth.authHeaders(),
    });

    await requireOk(res, 'Failed to fetch users');
    const data = await readJsonOrText(res);
    return Array.isArray(data) ? data : [];
  },

  async updateUserAccess(userId, payload) {
    const res = await fetch(`${window.API_BASE_URL}/api/users/${userId}/access/`, {
      method: 'PATCH',
      headers: window.ApiAuth.authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(payload),
    });

    await requireOk(res, 'Failed to update user access');
    return await readJsonOrText(res);
  },

  async getHealth() {
    if (window.USE_MOCK_DATA) return window.MOCK_HEALTH || { status: 'mock' };

    try {
      const res = await fetch(`${window.API_BASE_URL}/api/health/`);
      await requireOk(res, 'Backend unreachable');
      return await readJsonOrText(res);
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
      const res = await fetch(`${window.API_BASE_URL}/api/products/`, {
        headers: window.ApiAuth.authHeaders(),
      });

      await requireOk(res, 'Failed to fetch products');
      const data = await readJsonOrText(res);

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

      const res = await fetch(`${window.API_BASE_URL}/api/scores/?${qs}`, {
        headers: window.ApiAuth.authHeaders(),
      });

      await requireOk(res, 'Failed to fetch scores');
      const rows = await readJsonOrText(res);

      const normalized = Array.isArray(rows) ? rows.map(window._normalizeScore) : [];
      return window._assignOperationalPercentiles(normalized);
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
        headers: window.ApiAuth.authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload),
      });

      await requireOk(res, 'Scoring failed');
      const row = await readJsonOrText(res);
      return window._normalizeScore(row);
    } catch (e) {
      console.warn('Score finding failed:', e);
      throw e;
    }
  },

  async getNotifications(limit = 10) {
    if (window.USE_MOCK_DATA) return window.MOCK_NOTIFICATIONS || [];

    try {
      const res = await fetch(`${window.API_BASE_URL}/api/notifications/?limit=${limit}`, {
        headers: window.ApiAuth.authHeaders(),
      });

      await requireOk(res, 'Failed to fetch notifications');
      const rows = await readJsonOrText(res);

      return Array.isArray(rows)
        ? rows.map(n => {
            const operationalScore = _nullableNum(n.operational_rank_score) ?? _nullableNum(n.risk_score) ?? 0;
            const cleanScore = _nullableNum(n.clean_ai_score);

            return {
              id:         n.id,
              type:       n.type || n.kind || 'notification',
              kind:       n.kind || n.type || 'notification',
              title:      n.title || '',
              cve:        n.cve || (n.defectdojo_finding_id ? `Finding-${n.defectdojo_finding_id}` : `#${n.id}`),
              severity:   n.severity || n.scanner_severity || n.defectdojo_severity || 'Info',
              risk_score: operationalScore,
              operational_rank_score: operationalScore,
              clean_ai_score: cleanScore,
              product:    n.product || n.product_name || 'System',
              product_name: n.product_name || n.product || 'System',
              username:   n.username || null,
              time:       n.time || _humanTime(n.created_at),
              created_at: n.created_at,
              message:    n.message || n.title || '',
              is_read:    Boolean(n.is_read),
            };
          })
        : [];
    } catch (e) {
      console.warn('Notifications fetch failed:', e);
      return [];
    }
  },

  async getTrends(weeks = 8) {
    if (window.USE_MOCK_DATA) return [];

    try {
      const res = await fetch(`${window.API_BASE_URL}/api/trends/?weeks=${weeks}`, {
        headers: window.ApiAuth.authHeaders(),
      });

      await requireOk(res, 'Failed to fetch trends');
      const rows = await readJsonOrText(res);

      return Array.isArray(rows)
        ? rows.map(r => ({
            date:     r.date,
            critical: r.Critical ?? r.critical ?? 0,
            high:     r.High     ?? r.high     ?? 0,
            medium:   r.Medium   ?? r.medium   ?? 0,
            low:      r.Low      ?? r.low      ?? 0,
          }))
        : [];
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
        headers: window.ApiAuth.authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload),
      });

      await requireOk(res, 'Sync failed');
      return await readJsonOrText(res);
    } catch (e) {
      console.warn('Sync failed:', e);
      throw e;
    }
  },

  async refreshData() {
    try {
      const [scores, notifications, trends] = await Promise.all([
        this.getScores(),
        this.getNotifications(),
        this.getTrends(),
      ]);

      window._cachedFindings = scores;
      window._cachedNotifications = notifications;
      window._cachedTrends = trends;

      return { scores, notifications, trends };
    } catch (e) {
      console.warn('Data refresh failed:', e);
      return { scores: [], notifications: [], trends: [] };
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

export const USE_MOCK_DATA = window.USE_MOCK_DATA;
export const ALLOW_MOCK_FALLBACK = window.ALLOW_MOCK_FALLBACK;
export const apiAuth = window.ApiAuth;
export const apiClient = window.ApiClient;
export const apiConfig = window.ApiConfig;