import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { apiClient, USE_MOCK_DATA } from '../services/api-client.js';
import { MOCK_FINDINGS, MOCK_NOTIFICATIONS, MOCK_TREND_DATA } from '../data/mock-data.js';

const DataContext = createContext(null);

export function DataProvider({ children }) {
  const [findings, setFindings] = useState(null);
  const [notifications, setNotifications] = useState(null);
  const [trends, setTrends] = useState(null);
  const [loadingData, setLoadingData] = useState(false);
  const [dataLoaded, setDataLoaded] = useState(false);

  const setData = useCallback(({ scores = [], notifications = [], trends = [] }) => {
    setFindings(scores);
    setNotifications(notifications);
    setTrends(trends);
    setDataLoaded(true);
  }, []);

  const loadData = useCallback(async ({ force = false } = {}) => {
    if (!force && dataLoaded) return true;

    if (USE_MOCK_DATA) {
      setData({ scores: MOCK_FINDINGS, notifications: MOCK_NOTIFICATIONS, trends: MOCK_TREND_DATA });
      return true;
    }

    setLoadingData(true);
    try {
      const data = await apiClient.refreshData();
      setData(data);
      return true;
    } catch (err) {
      console.warn('Dashboard data load failed. Mock fallback disabled:', err);
      setData({ scores: [], notifications: [], trends: [] });
      return false;
    } finally {
      setLoadingData(false);
    }
  }, [dataLoaded, setData]);

  const refreshData = useCallback(() => loadData({ force: true }), [loadData]);

  const clearData = useCallback(() => {
    setFindings(null);
    setNotifications(null);
    setTrends(null);
    setDataLoaded(false);
    setLoadingData(false);
  }, []);

  const value = useMemo(() => ({
    findings: Array.isArray(findings) ? findings : [],
    notifications: Array.isArray(notifications) ? notifications : [],
    trends: Array.isArray(trends) ? trends : [],
    loadingData,
    dataLoaded,
    loadData,
    refreshData,
    clearData,
  }), [findings, notifications, trends, loadingData, dataLoaded, loadData, refreshData, clearData]);

  return React.createElement(DataContext.Provider, { value }, children);
}

export function useData() {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error('useData must be used inside DataProvider');
  return ctx;
}
