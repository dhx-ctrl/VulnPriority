import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { apiAuth, apiClient } from '../services/api-client.js';

// Theme
const ThemeContext = createContext(null);

export function ThemeProvider({ children }) {
  const [dark, setDark] = useState(() => localStorage.getItem('theme') === 'dark');

  const toggle = useCallback(() => setDark(d => {
    localStorage.setItem('theme', !d ? 'dark' : 'light');
    return !d;
  }), []);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  }, [dark]);

  return React.createElement(ThemeContext.Provider, { value: { dark, toggle } }, children);
}

export function useTheme() {
  return useContext(ThemeContext);
}

// Hash router
const RouterContext = createContext(null);

export function Router({ children }) {
  const [path, setPath] = useState(window.location.hash.slice(1) || '/login');

  useEffect(() => {
    const handler = () => setPath(window.location.hash.slice(1) || '/login');
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);

  const navigate = useCallback((p) => {
    window.location.hash = p;
  }, []);

  return React.createElement(RouterContext.Provider, { value: { path, navigate } }, children);
}

export function useRouter() {
  return useContext(RouterContext);
}

// Auth
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const s = sessionStorage.getItem('user');
      const token = apiAuth.getToken();
      return s && token ? JSON.parse(s) : null;
    } catch (_) {
      sessionStorage.removeItem('user');
      return null;
    }
  });

  const login = async (username, password) => {
    try {
      const data = await apiClient.login(username, password);
      const backendUser = data.user || {};

      const usr = {
        name: backendUser.name || backendUser.display_name || username || 'User',
        email: backendUser.email || `${username || 'user'}@devsecops.local`,
        avatar: backendUser.avatar || (username?.[0] || 'U').toUpperCase(),
        username: backendUser.username || username,
        is_admin: Boolean(backendUser.is_admin),
        access_status: backendUser.access_status || 'approved',
        source: backendUser.source || 'backend',
      };

      sessionStorage.setItem('user', JSON.stringify(usr));
      setUser(usr);
      return { ok: true, user: usr };
    } catch (e) {
      apiAuth.clearToken();
      sessionStorage.removeItem('user');
      setUser(null);

      if (e.code === 'ACCESS_PENDING') {
        return {
          ok: false,
          pending: true,
          error: e.message || 'Your account is pending approval.',
        };
      }

      if (e.code === 'ACCESS_DISABLED') {
        return {
          ok: false,
          disabled: true,
          error: e.message || 'Your account is disabled.',
        };
      }

      return { ok: false, error: e.message || 'Invalid username or password' };
    }
  };

  const register = async (username, password) => {
    try {
      const data = await apiClient.register(username, password);
      return { ok: true, data };
    } catch (e) {
      return { ok: false, error: e.message || 'Registration failed' };
    }
  };

  const logout = () => {
    apiAuth.clearToken();
    sessionStorage.removeItem('user');
    setUser(null);
  };

  return React.createElement(AuthContext.Provider, {
    value: { user, login, register, logout },
  }, children);
}

export function useAuth() {
  return useContext(AuthContext);
}

// Settings
const SettingsContext = createContext(null);

export function SettingsProvider({ children }) {
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

export function useSettings() {
  return useContext(SettingsContext);
}
