// Layout: Sidebar + Topbar + Notifications
// Grouped sidebar: Workspace / Intelligence / Settings
const { useState, useRef, useEffect } = React;

// ── SVG Icon component ──
function NavIcon({ name, size = 18 }) {
  const p = {
    xmlns: 'http://www.w3.org/2000/svg',
    width: size,
    height: size,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    style: { width: size, height: size, display: 'block', flexShrink: 0 },
  };

  const icons = {
    dashboard: React.createElement('svg', p,
      React.createElement('rect', { x: 3, y: 3, width: 7, height: 7, rx: 1 }),
      React.createElement('rect', { x: 14, y: 3, width: 7, height: 7, rx: 1 }),
      React.createElement('rect', { x: 14, y: 14, width: 7, height: 7, rx: 1 }),
      React.createElement('rect', { x: 3, y: 14, width: 7, height: 7, rx: 1 }),
    ),

    findings: React.createElement('svg', p,
      React.createElement('path', { d: 'M9 11l3 3L22 4' }),
      React.createElement('path', { d: 'M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11' }),
    ),

    scans: React.createElement('svg', p,
      React.createElement('circle', { cx: 12, cy: 12, r: 9 }),
      React.createElement('path', { d: 'M12 7v5l3 3' }),
    ),

    model: React.createElement('svg', p,
      React.createElement('path', { d: 'M12 2L2 7l10 5 10-5-10-5z' }),
      React.createElement('path', { d: 'M2 17l10 5 10-5' }),
      React.createElement('path', { d: 'M2 12l10 5 10-5' }),
    ),

    settings: React.createElement('svg', p,
      React.createElement('path', { d: 'M12.22 2h-.44a2 2 0 00-2 2v.18a2 2 0 01-1 1.73l-.43.25a2 2 0 01-2 0l-.15-.08a2 2 0 00-2.73.73l-.22.38a2 2 0 00.73 2.73l.15.1a2 2 0 011 1.72v.51a2 2 0 01-1 1.74l-.15.09a2 2 0 00-.73 2.73l.22.38a2 2 0 002.73.73l.15-.08a2 2 0 012 0l.43.25a2 2 0 011 1.73V20a2 2 0 002 2h.44a2 2 0 002-2v-.18a2 2 0 011-1.73l.43-.25a2 2 0 012 0l.15.08a2 2 0 002.73-.73l.22-.39a2 2 0 00-.73-2.73l-.15-.08a2 2 0 01-1-1.74v-.5a2 2 0 011-1.74l.15-.09a2 2 0 00.73-2.73l-.22-.38a2 2 0 00-2.73-.73l-.15.08a2 2 0 01-2 0l-.43-.25a2 2 0 01-1-1.73V4a2 2 0 00-2-2z' }),
      React.createElement('circle', { cx: 12, cy: 12, r: 3 }),
    ),

    sync: React.createElement('svg', p,
      React.createElement('path', { d: 'M21 2v6h-6' }),
      React.createElement('path', { d: 'M3 12a9 9 0 0115-6.7L21 8' }),
      React.createElement('path', { d: 'M3 22v-6h6' }),
      React.createElement('path', { d: 'M21 12a9 9 0 01-15 6.7L3 16' }),
    ),

    summary: React.createElement('svg', p,
      React.createElement('path', { d: 'M4 6h16M4 12h12M4 18h8' }),
    ),

    logout: React.createElement('svg', p,
      React.createElement('path', { d: 'M9 21H5V3h4' }),
      React.createElement('polyline', { points: '16 17 21 12 16 7' }),
      React.createElement('line', { x1: 21, y1: 12, x2: 9, y2: 12 }),
    ),

    chevronLeft: React.createElement('svg', p,
      React.createElement('path', { d: 'M15 18l-6-6 6-6' }),
    ),

    chevronRight: React.createElement('svg', p,
      React.createElement('path', { d: 'M9 18l6-6-6-6' }),
    ),

    sun: React.createElement('svg', p,
      React.createElement('circle', { cx: 12, cy: 12, r: 5 }),
      React.createElement('path', { d: 'M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42' }),
    ),

    moon: React.createElement('svg', p,
      React.createElement('path', { d: 'M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z' }),
    ),

    bell: React.createElement('svg', p,
      React.createElement('path', { d: 'M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9' }),
      React.createElement('path', { d: 'M13.73 21a2 2 0 01-3.46 0' }),
    ),

    shield: React.createElement('svg', p,
      React.createElement('path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }),
    ),
  };

  return icons[name] || null;
}

// ── Grouped navigation ──
const NAV_GROUPS = [
  {
    title: 'Workspace',
    items: [
      { path: '/dashboard', label: 'Dashboard', icon: 'dashboard' },
      { path: '/findings', label: 'Findings', icon: 'findings', badge: 'findings_count' },
      { path: '/scans', label: 'Scan History', icon: 'scans' },
      { path: '/sync', label: 'Sync', icon: 'sync' },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { path: '/model', label: 'Model Insights', icon: 'model' },
      { path: '/summary', label: 'Summary', icon: 'summary' },
    ],
  },
  {
    title: 'Settings',
    items: [
      { path: '/parameters', label: 'Parameters', icon: 'settings' },
    ],
  },
];

// ── Sidebar ──
function Sidebar({ collapsed, setCollapsed }) {
  const { dark } = useTheme();
  const { path } = useRouter();
  const { logout } = useAuth();
  const [hoveredItem, setHoveredItem] = useState(null);

  const findingCount = Array.isArray(window._cachedFindings)
    ? window._cachedFindings.length
    : 0;

  const c = dark ? {
    bg: '#0f1420',
    border: 'rgba(255,255,255,0.06)',
    text: '#7a8ba5',
    textHover: '#e2e8f0',
    active: '#3884f4',
    activeBg: 'rgba(56,132,244,0.12)',
    activeBorder: '#3884f4',
    hoverBg: 'rgba(255,255,255,0.04)',
    group: '#64748b',
    badgeBg: 'rgba(239,68,68,0.16)',
    badgeText: '#fb7185',
    logoText: '#f1f5f9',
  } : {
    bg: '#ffffff',
    border: 'rgba(0,0,0,0.06)',
    text: '#64748b',
    textHover: '#1e293b',
    active: '#3884f4',
    activeBg: 'rgba(56,132,244,0.07)',
    activeBorder: '#3884f4',
    hoverBg: 'rgba(0,0,0,0.03)',
    group: '#94a3b8',
    badgeBg: 'rgba(239,68,68,0.10)',
    badgeText: '#e11d48',
    logoText: '#1e293b',
  };

  const renderBadge = (item) => {
    if (collapsed) return null;
    if (item.badge !== 'findings_count') return null;
    if (!findingCount) return null;

    return React.createElement('span', {
      style: {
        marginLeft: 'auto',
        minWidth: 28,
        height: 20,
        padding: '0 8px',
        borderRadius: 999,
        background: c.badgeBg,
        color: c.badgeText,
        fontSize: 11,
        fontWeight: 800,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontVariantNumeric: 'tabular-nums',
      },
    }, findingCount > 999 ? '999+' : findingCount);
  };

  return React.createElement('aside', {
    style: {
      width: collapsed ? 64 : 240,
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      background: c.bg,
      borderRight: `1px solid ${c.border}`,
      transition: 'width 0.25s ease',
      overflow: 'hidden',
      flexShrink: 0,
      zIndex: 10,
      position: 'relative',
    },
  },

    // Logo header
    React.createElement('div', {
      style: {
        height: 56,
        padding: collapsed ? '0 16px' : '0 20px',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        borderBottom: `1px solid ${c.border}`,
        flexShrink: 0,
      },
    },
      React.createElement('div', {
        style: {
          width: 32,
          height: 32,
          borderRadius: 8,
          background: 'linear-gradient(135deg,#3884f4,#2563eb)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          color: '#fff',
        },
      }, React.createElement(NavIcon, { name: 'shield', size: 16 })),

      !collapsed && React.createElement('span', {
        style: {
          fontSize: 14,
          fontWeight: 700,
          color: c.logoText,
          whiteSpace: 'nowrap',
          letterSpacing: '-0.02em',
        },
      }, 'VulnPriority'),
    ),

    // Navigation groups
    React.createElement('nav', {
      style: {
        flex: 1,
        overflowY: 'auto',
        padding: collapsed ? '10px 0' : '14px 0',
      },
    },
      NAV_GROUPS.map((group, groupIndex) =>
        React.createElement('div', {
          key: group.title,
          style: {
            marginTop: groupIndex === 0 ? 0 : collapsed ? 8 : 18,
          },
        },

          !collapsed && React.createElement('div', {
            style: {
              padding: '0 20px',
              marginBottom: 7,
              color: c.group,
              fontSize: 10,
              fontWeight: 900,
              textTransform: 'uppercase',
              letterSpacing: '0.16em',
              lineHeight: 1,
            },
          }, group.title),

          group.items.map(item => {
            const active = path === item.path;
            const hovered = hoveredItem === item.path;

            return React.createElement('a', {
              key: item.path,
              href: `#${item.path}`,
              title: collapsed ? item.label : undefined,
              onMouseEnter: () => setHoveredItem(item.path),
              onMouseLeave: () => setHoveredItem(null),
              style: {
                position: 'relative',
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                minHeight: 40,
                margin: collapsed ? '3px 10px' : '3px 12px',
                padding: collapsed ? '0 12px' : '0 14px',
                textDecoration: 'none',
                fontSize: 13,
                fontWeight: active ? 700 : 600,
                color: active ? c.active : (hovered ? c.textHover : c.text),
                background: active ? c.activeBg : (hovered ? c.hoverBg : 'transparent'),
                borderRadius: 8,
                transition: 'all 0.15s ease',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
              },
            },

              active && React.createElement('span', {
                style: {
                  position: 'absolute',
                  left: -10,
                  top: 9,
                  bottom: 9,
                  width: 3,
                  borderRadius: 999,
                  background: c.activeBorder,
                },
              }),

              React.createElement('span', {
                style: {
                  flexShrink: 0,
                  width: 20,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                },
              }, React.createElement(NavIcon, { name: item.icon, size: 16 })),

              !collapsed && React.createElement('span', {
                style: {
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                },
              }, item.label),

              renderBadge(item),
            );
          }),
        ),
      ),
    ),

    // Footer
    React.createElement('div', {
      style: {
        borderTop: `1px solid ${c.border}`,
        flexShrink: 0,
      },
    },

      React.createElement('button', {
        onClick: () => {
          logout();
          window.location.hash = '/login';
        },
        onMouseEnter: (e) => {
          e.currentTarget.style.background = c.hoverBg;
          e.currentTarget.style.color = c.textHover;
        },
        onMouseLeave: (e) => {
          e.currentTarget.style.background = 'transparent';
          e.currentTarget.style.color = c.text;
        },
        style: {
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          width: '100%',
          minHeight: 40,
          padding: collapsed ? '0 22px' : '0 24px',
          border: 'none',
          background: 'transparent',
          color: c.text,
          cursor: 'pointer',
          fontSize: 13,
          fontWeight: 600,
          textAlign: 'left',
          transition: 'all 0.15s ease',
        },
      },
        React.createElement('span', {
          style: {
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 20,
          },
        }, React.createElement(NavIcon, { name: 'logout', size: 16 })),

        !collapsed && 'Sign Out',
      ),

      React.createElement('div', {
        style: {
          padding: collapsed ? '8px 18px' : '8px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        },
      },
        React.createElement('button', {
          onClick: () => setCollapsed(!collapsed),
          title: collapsed ? 'Expand sidebar' : 'Collapse sidebar',
          onMouseEnter: (e) => {
            e.currentTarget.style.background = c.hoverBg;
            e.currentTarget.style.color = c.textHover;
          },
          onMouseLeave: (e) => {
            e.currentTarget.style.background = 'transparent';
            e.currentTarget.style.color = c.text;
          },
          style: {
            width: 28,
            height: 28,
            border: 'none',
            background: 'transparent',
            color: c.text,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: 6,
            transition: 'all 0.15s ease',
            flexShrink: 0,
          },
        }, React.createElement(NavIcon, {
          name: collapsed ? 'chevronRight' : 'chevronLeft',
          size: 14,
        })),

        !collapsed && React.createElement('span', {
          style: {
            fontSize: 11,
            color: c.text,
          },
        }, 'v1.0.0'),
      ),
    ),
  );
}

// ── Notification Dropdown ──
function NotificationDropdown({ show, onClose }) {
  const { dark } = useTheme();
  const { navigate } = useRouter();
  const ref = useRef(null);

  const notifications = Array.isArray(window._cachedNotifications)
    ? window._cachedNotifications
    : [];

  useEffect(() => {
    if (!show) return;

    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) onClose();
    };

    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [show, onClose]);

  if (!show) return null;

  const c = dark
    ? { bg: '#111827', border: 'rgba(255,255,255,0.06)', text: '#e2e8f0', sub: '#7a8ba5', itemBorder: 'rgba(255,255,255,0.04)' }
    : { bg: 'rgba(255,255,255,0.98)', border: 'rgba(0,0,0,0.06)', text: '#1e293b', sub: '#64748b', itemBorder: 'rgba(0,0,0,0.04)' };

  const sevColor = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#22c55e',
  };

  return React.createElement('div', {
    ref,
    style: {
      position: 'absolute',
      top: 'calc(100% + 8px)',
      right: 0,
      width: 380,
      maxHeight: 440,
      overflowY: 'auto',
      background: c.bg,
      border: `1px solid ${c.border}`,
      borderRadius: 12,
      boxShadow: '0 16px 48px rgba(0,0,0,0.25)',
      zIndex: 200,
    },
  },

    React.createElement('div', {
      style: {
        padding: '12px 16px',
        borderBottom: `1px solid ${c.border}`,
        fontSize: 12,
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        color: c.sub,
      },
    }, 'Recent Alerts'),

    notifications.length === 0 && React.createElement('div', {
      style: {
        padding: '18px 16px',
        fontSize: 13,
        color: c.sub,
      },
    }, 'No recent alerts.'),

    notifications.map(n =>
      React.createElement('div', {
        key: n.id,
        onClick: () => {
          onClose();
          navigate('/findings');
        },
        style: {
          padding: '10px 16px',
          borderBottom: `1px solid ${c.itemBorder}`,
          borderLeft: `3px solid ${sevColor[n.severity] || '#64748b'}`,
          display: 'flex',
          gap: 10,
          alignItems: 'flex-start',
          cursor: 'pointer',
          transition: 'background 0.15s',
        },
        onMouseEnter: (e) => {
          e.currentTarget.style.background = dark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)';
        },
        onMouseLeave: (e) => {
          e.currentTarget.style.background = 'transparent';
        },
      },
        React.createElement('div', {
          style: {
            flex: 1,
            minWidth: 0,
          },
        },
          React.createElement('div', {
            style: {
              fontSize: 12,
              fontWeight: 600,
              color: '#3884f4',
              fontFamily: 'monospace',
            },
          }, n.cve || 'Finding'),

          React.createElement('div', {
            style: {
              fontSize: 13,
              fontWeight: 500,
              color: c.text,
              marginTop: 2,
            },
          }, n.message || 'High-risk finding detected'),
        ),

        React.createElement('div', {
          style: {
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
            gap: 4,
            flexShrink: 0,
          },
        },
          React.createElement('span', {
            style: {
              fontSize: 11,
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 6,
              background: (sevColor[n.severity] || '#64748b') + '18',
              color: sevColor[n.severity] || '#64748b',
            },
          }, n.severity || 'High'),

          React.createElement('span', {
            style: {
              fontSize: 11,
              color: c.sub,
              whiteSpace: 'nowrap',
            },
          }, n.time || ''),
        ),
      ),
    ),

    React.createElement('div', {
      style: {
        padding: '10px 16px',
      },
    },
      React.createElement('a', {
        onClick: () => {
          navigate('/findings');
          onClose();
        },
        style: {
          fontSize: 12,
          color: '#3884f4',
          cursor: 'pointer',
          fontWeight: 600,
        },
      }, 'View all findings →'),
    ),
  );
}

// ── Topbar ──
function Topbar() {
  const { dark, toggle } = useTheme();
  const { user } = useAuth();
  const [notifOpen, setNotifOpen] = useState(false);

  const findingCount = Array.isArray(window._cachedFindings)
    ? window._cachedFindings.length
    : 0;

  const notificationCount = Array.isArray(window._cachedNotifications)
    ? window._cachedNotifications.length
    : 0;

  const c = dark
    ? { bg: '#0f1420', border: 'rgba(255,255,255,0.06)', text: '#e2e8f0', sub: '#7a8ba5' }
    : { bg: '#ffffff', border: 'rgba(0,0,0,0.04)', text: '#1e293b', sub: '#64748b' };

  const iconBtnStyle = {
    width: 34,
    height: 34,
    borderRadius: 8,
    border: 'none',
    background: dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.03)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: c.sub,
    transition: 'all 0.15s',
    position: 'relative',
  };

  return React.createElement('header', {
    style: {
      height: 56,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      background: c.bg,
      borderBottom: `1px solid ${c.border}`,
      position: 'sticky',
      top: 0,
      zIndex: 10,
    },
  },

    React.createElement('div', {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      },
    },
      React.createElement('span', {
        style: {
          fontSize: 11,
          padding: '4px 10px',
          borderRadius: 8,
          background: 'rgba(16,185,129,0.12)',
          color: '#10b981',
          fontWeight: 600,
        },
      }, '● Synced'),

      React.createElement('span', {
        style: {
          fontSize: 12,
          color: c.sub,
        },
      }, `DefectDojo · ${findingCount} findings`),
    ),

    React.createElement('div', {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      },
    },

      React.createElement('button', {
        onClick: toggle,
        title: 'Toggle theme',
        onMouseEnter: (e) => {
          e.currentTarget.style.color = c.text;
          e.currentTarget.style.background = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
        },
        onMouseLeave: (e) => {
          e.currentTarget.style.color = c.sub;
          e.currentTarget.style.background = dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.03)';
        },
        style: iconBtnStyle,
      }, React.createElement(NavIcon, {
        name: dark ? 'sun' : 'moon',
        size: 16,
      })),

      React.createElement('div', {
        style: {
          position: 'relative',
        },
      },
        React.createElement('button', {
          onClick: () => setNotifOpen(!notifOpen),
          title: 'Notifications',
          onMouseEnter: (e) => {
            e.currentTarget.style.color = c.text;
            e.currentTarget.style.background = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
          },
          onMouseLeave: (e) => {
            e.currentTarget.style.color = c.sub;
            e.currentTarget.style.background = dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.03)';
          },
          style: iconBtnStyle,
        },
          React.createElement(NavIcon, {
            name: 'bell',
            size: 16,
          }),

          notificationCount > 0 && React.createElement('span', {
            style: {
              position: 'absolute',
              top: 4,
              right: 4,
              minWidth: 14,
              height: 14,
              borderRadius: 7,
              background: '#ef4444',
              color: '#fff',
              fontSize: 9,
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '0 3px',
              lineHeight: 1,
            },
          }, notificationCount > 9 ? '9+' : notificationCount),
        ),

        React.createElement(NotificationDropdown, {
          show: notifOpen,
          onClose: () => setNotifOpen(false),
        }),
      ),

      React.createElement('div', {
        style: {
          width: 32,
          height: 32,
          borderRadius: '50%',
          background: 'linear-gradient(135deg,#3884f4,#2563eb)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#fff',
          fontSize: 12,
          fontWeight: 700,
          marginLeft: 4,
        },
      }, user?.avatar || 'A'),
    ),
  );
}

// ── AppLayout ──
function AppLayout({ children }) {
  const [collapsed, setCollapsed] = useState(false);

  return React.createElement('div', {
    style: {
      display: 'flex',
      minHeight: '100vh',
    },
  },
    React.createElement(InteractiveBackground, {
      playful: false,
    }),

    React.createElement(Sidebar, {
      collapsed,
      setCollapsed,
    }),

    React.createElement('div', {
      style: {
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        zIndex: 1,
      },
    },
      React.createElement(Topbar, null),

      React.createElement('main', {
        style: {
          flex: 1,
          padding: 28,
          overflowY: 'auto',
        },
      }, children),
    ),
  );
}

Object.assign(window, {
  AppLayout,
  Sidebar,
  Topbar,
  NavIcon,
});