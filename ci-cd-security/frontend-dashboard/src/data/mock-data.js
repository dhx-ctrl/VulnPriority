// Mock data disabled.
// Empty safe defaults only. These variables prevent crashes when backend data is empty/offline.

export const MOCK_PRODUCTS = [];

export const MOCK_SEVERITY_BREAKDOWN = {
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0,
};

export const MOCK_FINDINGS = [];
export const MOCK_SCAN_HISTORY = [];
export const MOCK_NOTIFICATIONS = [];
export const MOCK_TREND_DATA = [];

export const MOCK_SYNC_STATUS = {
  status: 'Disabled',
  lastSync: null,
  product_id: null,
  product_name: null,
  total_fetched: 0,
  scored: 0,
  stored: 0,
  skipped_on_error: 0,
  high_risk_flagged: 0,
  severity_breakdown: {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  },
};

export const MOCK_HEALTH = {
  status: 'offline',
  binary_model: null,
  multiclass_model: null,
  threshold: null,
  binary_features: [],
  multi_features: [],
};
