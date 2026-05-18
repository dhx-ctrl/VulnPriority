import React, { useState, useRef, useEffect } from 'react';
import { useAuth, useRouter, useTheme } from '../context/AppContext.jsx';
import { useData } from '../context/DataContext.jsx';
import { InteractiveBackground } from '../pages/LoginPage.jsx';

// Layout: Sidebar + Topbar + Notifications

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
    dashboard: (
      <svg {...p}>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
      </svg>
    ),

    findings: (
      <svg {...p}>
        <path d="M9 11l3 3L22 4" />
        <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
      </svg>
    ),

    scans: (
      <svg {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 3" />
      </svg>
    ),

    model: (
      <svg {...p}>
        <path d="M12 2L2 7l10 5 10-5-10-5z" />
        <path d="M2 17l10 5 10-5" />
        <path d="M2 12l10 5 10-5" />
      </svg>
    ),

    settings: (
      <svg {...p}>
        <path d="M12.22 2h-.44a2 2 0 00-2 2v.18a2 2 0 01-1 1.73l-.43.25a2 2 0 01-2 0l-.15-.08a2 2 0 00-2.73.73l-.22.38a2 2 0 00.73 2.73l.15.1a2 2 0 011 1.72v.51a2 2 0 01-1 1.74l-.15.09a2 2 0 00-.73 2.73l.22.38a2 2 0 002.73.73l.15-.08a2 2 0 012 0l.43.25a2 2 0 011 1.73V20a2 2 0 002 2h.44a2 2 0 002-2v-.18a2 2 0 011-1.73l.43-.25a2 2 0 012 0l.15.08a2 2 0 002.73-.73l.22-.39a2 2 0 00-.73-2.73l-.15-.08a2 2 0 01-1-1.74v-.5a2 2 0 011-1.74l.15-.09a2 2 0 00.73-2.73l-.22-.38a2 2 0 00-2.73-.73l-.15.08a2 2 0 01-2 0l-.43-.25a2 2 0 01-1-1.73V4a2 2 0 00-2-2z" />
        <circle cx="12" cy="12" r="3" />
      </svg>
    ),

    users: (
      <svg {...p}>
        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 00-3-3.87" />
        <path d="M16 3.13a4 4 0 010 7.75" />
      </svg>
    ),

    sync: (
      <svg {...p}>
        <path d="M21 2v6h-6" />
        <path d="M3 12a9 9 0 0115-6.7L21 8" />
        <path d="M3 22v-6h6" />
        <path d="M21 12a9 9 0 01-15 6.7L3 16" />
      </svg>
    ),

    summary: (
      <svg {...p}>
        <path d="M4 6h16M4 12h12M4 18h8" />
      </svg>
    ),

    logout: (
      <svg {...p}>
        <path d="M9 21H5V3h4" />
        <polyline points="16 17 21 12 16 7" />
        <line x1="21" y1="12" x2="9" y2="12" />
      </svg>
    ),

    chevronLeft: (
      <svg {...p}>
        <path d="M15 18l-6-6 6-6" />
      </svg>
    ),

    chevronRight: (
      <svg {...p}>
        <path d="M9 18l6-6-6-6" />
      </svg>
    ),

    sun: (
      <svg {...p}>
        <circle cx="12" cy="12" r="5" />
        <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
      </svg>
    ),

    moon: (
      <svg {...p}>
        <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" />
      </svg>
    ),

    bell: (
      <svg {...p}>
        <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9" />
        <path d="M13.73 21a2 2 0 01-3.46 0" />
      </svg>
    ),

    shield: (
      <svg {...p}>
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  };

  return icons[name] || null;
}

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
      { path: '/users', label: 'Users', icon: 'users', adminOnly: true },
      { path: '/parameters', label: 'Parameters', icon: 'settings' },
    ],
  },
];

function Sidebar({ collapsed, setCollapsed }) {
  const { dark } = useTheme();
  const { path, navigate } = useRouter();
  const { logout, user } = useAuth();
  const { findings } = useData();
  const [hoveredItem, setHoveredItem] = useState(null);

  const findingCount = findings.length;

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

    return (
      <span
        style={{
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
        }}
      >
        {findingCount > 999 ? '999+' : findingCount}
      </span>
    );
  };

  return (
    <aside
      style={{
        width: collapsed ? 64 : 240,
        minWidth: collapsed ? 64 : 240,
        maxWidth: collapsed ? 64 : 240,
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        background: c.bg,
        borderRight: `1px solid ${c.border}`,
        transition: 'width 0.25s ease, min-width 0.25s ease, max-width 0.25s ease',
        overflow: 'hidden',
        flexShrink: 0,
        zIndex: 10,
        position: 'relative',
      }}
    >
      <div
        style={{
          height: 56,
          padding: collapsed ? '0 16px' : '0 20px',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          borderBottom: `1px solid ${c.border}`,
          flexShrink: 0,
          boxSizing: 'border-box',
        }}
      >
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: 8,
            background: 'linear-gradient(135deg,#3884f4,#2563eb)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            color: '#fff',
          }}
        >
          <NavIcon name="shield" size={16} />
        </div>

        {!collapsed && (
          <span
            style={{
              fontSize: 14,
              fontWeight: 700,
              color: c.logoText,
              whiteSpace: 'nowrap',
              letterSpacing: '-0.02em',
            }}
          >
            VulnPriority
          </span>
        )}
      </div>

      <nav
        style={{
          flex: 1,
          overflowY: 'auto',
          overflowX: 'hidden',
          padding: collapsed ? '10px 0' : '14px 0',
        }}
      >
        {NAV_GROUPS.map((group, groupIndex) => {
          const visibleItems = group.items.filter(item => !item.adminOnly || user?.is_admin);
          if (visibleItems.length === 0) return null;

          return (
            <div
              key={group.title}
              style={{ marginTop: groupIndex === 0 ? 0 : collapsed ? 8 : 18 }}
            >
              {!collapsed && (
                <div
                  style={{
                    padding: '0 20px',
                    marginBottom: 7,
                    color: c.group,
                    fontSize: 10,
                    fontWeight: 900,
                    textTransform: 'uppercase',
                    letterSpacing: '0.16em',
                    lineHeight: 1,
                  }}
                >
                  {group.title}
                </div>
              )}

              {visibleItems.map(item => {
                const active = path === item.path;
                const hovered = hoveredItem === item.path;

                return (
                  <a
                    key={item.path}
                    href={`#${item.path}`}
                    title={collapsed ? item.label : undefined}
                    onMouseEnter={() => setHoveredItem(item.path)}
                    onMouseLeave={() => setHoveredItem(null)}
                    style={{
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
                      color: active ? c.active : hovered ? c.textHover : c.text,
                      background: active ? c.activeBg : hovered ? c.hoverBg : 'transparent',
                      borderRadius: 8,
                      transition: 'all 0.15s ease',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      boxSizing: 'border-box',
                    }}
                  >
                    {active && (
                      <span
                        style={{
                          position: 'absolute',
                          left: -10,
                          top: 9,
                          bottom: 9,
                          width: 3,
                          borderRadius: 999,
                          background: c.activeBorder,
                        }}
                      />
                    )}

                    <span
                      style={{
                        flexShrink: 0,
                        width: 20,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <NavIcon name={item.icon} size={16} />
                    </span>

                    {!collapsed && (
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {item.label}
                      </span>
                    )}

                    {renderBadge(item)}
                  </a>
                );
              })}
            </div>
          );
        })}
      </nav>

      <div style={{ borderTop: `1px solid ${c.border}`, flexShrink: 0 }}>
        <button
          onClick={() => {
            logout();
            navigate('/login');
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = c.hoverBg;
            e.currentTarget.style.color = c.textHover;
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'transparent';
            e.currentTarget.style.color = c.text;
          }}
          style={{
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
            boxSizing: 'border-box',
          }}
        >
          <span
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 20,
              flexShrink: 0,
            }}
          >
            <NavIcon name="logout" size={16} />
          </span>

          {!collapsed && 'Sign Out'}
        </button>

        <div
          style={{
            padding: collapsed ? '8px 18px' : '8px 16px',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            boxSizing: 'border-box',
          }}
        >
          <button
            onClick={() => setCollapsed(!collapsed)}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = c.hoverBg;
              e.currentTarget.style.color = c.textHover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.color = c.text;
            }}
            style={{
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
            }}
          >
            <NavIcon name={collapsed ? 'chevronRight' : 'chevronLeft'} size={14} />
          </button>

          {!collapsed && (
            <span style={{ fontSize: 11, color: c.text }}>
              v1.0.0
            </span>
          )}
        </div>
      </div>
    </aside>
  );
}

function NotificationDropdown({ show, onClose }) {
  const { dark } = useTheme();
  const { navigate } = useRouter();
  const ref = useRef(null);
  const { notifications } = useData();

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
    ? {
        bg: '#111827',
        border: 'rgba(255,255,255,0.06)',
        text: '#e2e8f0',
        sub: '#7a8ba5',
        itemBorder: 'rgba(255,255,255,0.04)',
      }
    : {
        bg: 'rgba(255,255,255,0.98)',
        border: 'rgba(0,0,0,0.06)',
        text: '#1e293b',
        sub: '#64748b',
        itemBorder: 'rgba(0,0,0,0.04)',
      };

  const sevColor = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#22c55e',
    Info: '#3884f4',
  };

  return (
    <div
      ref={ref}
      style={{
        position: 'absolute',
        top: 'calc(100% + 8px)',
        right: 0,
        width: 380,
        maxWidth: 'calc(100vw - 24px)',
        maxHeight: 440,
        overflowY: 'auto',
        background: c.bg,
        border: `1px solid ${c.border}`,
        borderRadius: 12,
        boxShadow: '0 16px 48px rgba(0,0,0,0.25)',
        zIndex: 200,
      }}
    >
      <div
        style={{
          padding: '12px 16px',
          borderBottom: `1px solid ${c.border}`,
          fontSize: 12,
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
          color: c.sub,
        }}
      >
        Recent Alerts
      </div>

      {notifications.length === 0 && (
        <div style={{ padding: '18px 16px', fontSize: 13, color: c.sub }}>
          No recent alerts.
        </div>
      )}

      {notifications.map(n => {
        const severity = n.severity || 'Info';
        const color = sevColor[severity] || '#64748b';

        return (
          <div
            key={n.id}
            onClick={() => {
              onClose();
              if (n.kind && String(n.kind).includes('user')) {
                navigate('/users');
              } else {
                navigate('/findings');
              }
            }}
            style={{
              padding: '10px 16px',
              borderBottom: `1px solid ${c.itemBorder}`,
              borderLeft: `3px solid ${color}`,
              display: 'flex',
              gap: 10,
              alignItems: 'flex-start',
              cursor: 'pointer',
              transition: 'background 0.15s',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = dark
                ? 'rgba(255,255,255,0.03)'
                : 'rgba(0,0,0,0.02)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
            }}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: '#3884f4',
                  fontFamily: 'monospace',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {n.cve || n.title || 'Notification'}
              </div>

              <div
                style={{
                  fontSize: 13,
                  fontWeight: 500,
                  color: c.text,
                  marginTop: 2,
                  lineHeight: 1.35,
                }}
              >
                {n.message || 'Dashboard notification'}
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-end',
                gap: 4,
                flexShrink: 0,
              }}
            >
              <span
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: 6,
                  background: color + '18',
                  color,
                }}
              >
                {severity}
              </span>

              <span
                style={{
                  fontSize: 11,
                  color: c.sub,
                  whiteSpace: 'nowrap',
                }}
              >
                {n.time || ''}
              </span>
            </div>
          </div>
        );
      })}

      <div style={{ padding: '10px 16px' }}>
        <button
          onClick={() => {
            navigate('/findings');
            onClose();
          }}
          style={{
            border: 'none',
            background: 'transparent',
            fontSize: 12,
            color: '#3884f4',
            cursor: 'pointer',
            fontWeight: 600,
            padding: 0,
          }}
        >
          View findings →
        </button>
      </div>
    </div>
  );
}

function Topbar() {
  const { dark, toggle } = useTheme();
  const { user } = useAuth();
  const { findings, notifications } = useData();
  const [notifOpen, setNotifOpen] = useState(false);

  const findingCount = findings.length;
  const notificationCount = notifications.length;

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
    flexShrink: 0,
  };

  return (
    <header
      style={{
        height: 56,
        width: '100%',
        maxWidth: '100%',
        boxSizing: 'border-box',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        padding: '0 24px',
        background: c.bg,
        borderBottom: `1px solid ${c.border}`,
        position: 'sticky',
        top: 0,
        zIndex: 20,
        flexShrink: 0,
        overflow: 'visible',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          minWidth: 0,
          flex: '1 1 auto',
          overflow: 'hidden',
        }}
      >
        <span
          style={{
            fontSize: 11,
            padding: '4px 10px',
            borderRadius: 8,
            background: 'rgba(16,185,129,0.12)',
            color: '#10b981',
            fontWeight: 600,
            whiteSpace: 'nowrap',
            flexShrink: 0,
          }}
        >
          ● Synced
        </span>

        <span
          style={{
            fontSize: 12,
            color: c.sub,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            minWidth: 0,
          }}
        >
          DefectDojo · {findingCount} findings
        </span>
      </div>

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexShrink: 0,
          marginLeft: 'auto',
        }}
      >
        <button
          onClick={toggle}
          title="Toggle theme"
          onMouseEnter={(e) => {
            e.currentTarget.style.color = c.text;
            e.currentTarget.style.background = dark
              ? 'rgba(255,255,255,0.08)'
              : 'rgba(0,0,0,0.06)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = c.sub;
            e.currentTarget.style.background = dark
              ? 'rgba(255,255,255,0.04)'
              : 'rgba(0,0,0,0.03)';
          }}
          style={iconBtnStyle}
        >
          <NavIcon name={dark ? 'sun' : 'moon'} size={16} />
        </button>

        <div style={{ position: 'relative', flexShrink: 0 }}>
          <button
            onClick={() => setNotifOpen(!notifOpen)}
            title="Notifications"
            onMouseEnter={(e) => {
              e.currentTarget.style.color = c.text;
              e.currentTarget.style.background = dark
                ? 'rgba(255,255,255,0.08)'
                : 'rgba(0,0,0,0.06)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = c.sub;
              e.currentTarget.style.background = dark
                ? 'rgba(255,255,255,0.04)'
                : 'rgba(0,0,0,0.03)';
            }}
            style={iconBtnStyle}
          >
            <NavIcon name="bell" size={16} />

            {notificationCount > 0 && (
              <span
                style={{
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
                }}
              >
                {notificationCount > 9 ? '9+' : notificationCount}
              </span>
            )}
          </button>

          <NotificationDropdown
            show={notifOpen}
            onClose={() => setNotifOpen(false)}
          />
        </div>

        <div
          style={{
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
            flexShrink: 0,
          }}
        >
          {user?.avatar || 'A'}
        </div>
      </div>
    </header>
  );
}

export function AppLayout({ children }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div
      style={{
        display: 'flex',
        width: '100vw',
        height: '100vh',
        maxWidth: '100vw',
        maxHeight: '100vh',
        overflow: 'hidden',
        position: 'relative',
      }}
    >
      <InteractiveBackground playful={false} />

      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />

      <div
        style={{
          flex: '1 1 0%',
          minWidth: 0,
          width: 0,
          maxWidth: '100%',
          height: '100vh',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          zIndex: 1,
          overflow: 'hidden',
        }}
      >
        <Topbar />

        <main
          style={{
            flex: '1 1 auto',
            minWidth: 0,
            maxWidth: '100%',
            padding: 28,
            overflowY: 'auto',
            overflowX: 'auto',
            boxSizing: 'border-box',
          }}
        >
          {children}
        </main>
      </div>
    </div>
  );
}

export { Sidebar, Topbar, NavIcon };