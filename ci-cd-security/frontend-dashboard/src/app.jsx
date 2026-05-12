// Main App
function App() {
  const { path } = useRouter();
  const { user } = useAuth();

  // ── ALL hooks must come before any conditional return (Rules of Hooks) ──────
  const [loadingData, setLoadingData] = React.useState(false);
  const [dataLoaded, setDataLoaded] = React.useState(
    // If mock mode or data was already fetched this session, skip loading
    window.USE_MOCK_DATA || Boolean(window._cachedFindings)
  );

  React.useEffect(() => {
    // Only fetch when a user is logged in, not on the login page,
    // and the data hasn't been loaded yet this session.
    if (!user || window.USE_MOCK_DATA || window._cachedFindings) return;

    let cancelled = false;
    setLoadingData(true);

    Promise.all([
      window.ApiClient.getScores(),
      window.ApiClient.getNotifications(),
      window.ApiClient.getTrends(),
    ])
      .then(([scores, notifications, trends]) => {
        if (!cancelled) {
          window._cachedFindings      = scores;
          window._cachedNotifications = notifications;
          window._cachedTrends        = trends;
          setDataLoaded(true);
          setLoadingData(false);
        }
      })
      .catch(err => {
        console.warn('Dashboard data load failed. Mock fallback disabled:', err);
        if (!cancelled) {
          window._cachedFindings      = [];
          window._cachedNotifications = [];
          window._cachedTrends        = [];
          setDataLoaded(true);
          setLoadingData(false);
        }
      });

    return () => { cancelled = true; };
  }, [user]); // re-runs if the logged-in user changes (e.g. logout → login)
  // ─────────────────────────────────────────────────────────────────────────────

  // Protected route guards (after all hooks)
  if (!user && path !== '/login') {
    window.location.hash = '/login';
    return null;
  }
  if (user && path === '/login') {
    window.location.hash = '/dashboard';
    return null;
  }

  if (path === '/login') return React.createElement(LoginPage, null);

  // Show a single app-level loading screen instead of per-page spinners
  if (loadingData && !dataLoaded) {
    return React.createElement(AppLayout, null,
      React.createElement('div', {
        style: { padding: 40, fontSize: 14, color: '#64748b', textAlign: 'center' },
      }, 'Loading findings from FastAPI backend…')
    );
  }

  const pages = {
    '/dashboard':  DashboardPage,
    '/findings':   FindingsPage,
    '/scans':      ScanHistoryPage,
    '/model':      ModelInsightsPage,
    '/parameters': ParametersPage,
    '/sync':       SyncPage,
    '/summary':    SummaryPage,
  };
  const Page = pages[path] || DashboardPage;

  return React.createElement(AppLayout, null, React.createElement(Page, null));
}

function Root() {
  return React.createElement(Router, null,
    React.createElement(ThemeProvider, null,
      React.createElement(AuthProvider, null,
        React.createElement(SettingsProvider, null,
          React.createElement(App, null),
        ),
      ),
    ),
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(Root, null));