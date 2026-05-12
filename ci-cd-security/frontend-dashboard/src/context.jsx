// Theme + Router context
const { createContext, useContext, useState, useEffect, useCallback } = React;

// ── Theme ──
const ThemeContext = createContext();
function ThemeProvider({ children }) {
  const [dark, setDark] = useState(() => localStorage.getItem('theme') === 'dark');
  const toggle = useCallback(() => setDark(d => { localStorage.setItem('theme', !d ? 'dark' : 'light'); return !d; }), []);
  useEffect(() => { document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light'); }, [dark]);
  return React.createElement(ThemeContext.Provider, { value: { dark, toggle } }, children);
}
function useTheme() { return useContext(ThemeContext); }

// ── Router ──
const RouterContext = createContext();
function Router({ children }) {
  const [path, setPath] = useState(window.location.hash.slice(1) || '/login');
  useEffect(() => {
    const handler = () => setPath(window.location.hash.slice(1) || '/login');
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);
  const navigate = useCallback((p) => { window.location.hash = p; }, []);
  return React.createElement(RouterContext.Provider, { value: { path, navigate } }, children);
}
function useRouter() { return useContext(RouterContext); }

// ── Auth ──
const AuthContext = createContext();
function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const s = sessionStorage.getItem('user');
    return s ? JSON.parse(s) : null;
  });
  const login = (u, p) => {
    if (u === 'admin' && p === 'admin') {
      const usr = { name: 'Admin User', email: 'admin@devsecops.local', avatar: 'A' };
      sessionStorage.setItem('user', JSON.stringify(usr));
      setUser(usr);
      return true;
    }
    return false;
  };
  const logout = () => { sessionStorage.removeItem('user'); setUser(null); };
  return React.createElement(AuthContext.Provider, { value: { user, login, logout } }, children);
}
function useAuth() { return useContext(AuthContext); }

// ── Settings ──
const SettingsContext = createContext();
function SettingsProvider({ children }) {
  const [settings, setSettings] = useState(() => {
    const s = localStorage.getItem('appSettings');
    return s ? JSON.parse(s) : {
      highRiskThreshold: 80,
      blockThreshold: 90,
      showHighRiskOnly: false,
      hideLowSev: false,
      showFixableOnly: false,
      defaultProduct: 'All',
      notifications: true,
    };
  });
  const update = (key, val) => {
    setSettings(prev => {
      const next = { ...prev, [key]: val };
      localStorage.setItem('appSettings', JSON.stringify(next));
      return next;
    });
  };
  return React.createElement(SettingsContext.Provider, { value: { settings, update } }, children);
}
function useSettings() { return useContext(SettingsContext); }

Object.assign(window, { ThemeProvider, useTheme, Router, useRouter, AuthProvider, useAuth, SettingsProvider, useSettings });
