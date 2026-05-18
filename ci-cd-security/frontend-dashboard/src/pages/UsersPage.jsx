import React, { useEffect, useState } from 'react';
import { useTheme } from '../context/AppContext.jsx';
import { apiClient } from '../services/api-client.js';
import { GlassCard } from './DashboardPage.jsx';

export default function UsersPage() {
  const { dark } = useTheme();

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState('');

  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';
  const border = dark ? 'rgba(255,255,255,0.06)' : 'rgba(15,23,42,0.07)';

  const loadUsers = async () => {
    setLoading(true);
    setError('');

    try {
      const rows = await apiClient.getUsers();
      setUsers(rows);
    } catch (e) {
      setError(e.message || 'Could not load users.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const updateUser = async (id, payload) => {
    setBusyId(id);
    setError('');

    try {
      await apiClient.updateUserAccess(id, payload);
      await loadUsers();
    } catch (e) {
      setError(e.message || 'Could not update user.');
    } finally {
      setBusyId(null);
    }
  };

  const statusColor = (status) => {
    if (status === 'approved') return '#22c55e';
    if (status === 'pending') return '#f97316';
    if (status === 'disabled') return '#ef4444';
    return '#64748b';
  };

  const btn = (color, disabled = false) => ({
    padding: '7px 10px',
    borderRadius: 8,
    border: `1px solid ${color}${dark ? '55' : '35'}`,
    background: color + (dark ? '22' : '12'),
    color,
    fontSize: 12,
    fontWeight: 800,
    cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled ? 0.55 : 1,
    whiteSpace: 'nowrap',
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 24, fontWeight: 850, color: t, margin: '0 0 4px' }}>
          Users
        </h1>

        <p style={{ fontSize: 14, color: sub, margin: 0, lineHeight: 1.5 }}>
          Approve registered users, disable access, or grant admin permission.
        </p>
      </div>

      <GlassCard style={{ padding: 0, overflow: 'hidden' }}>
        {error && (
          <div style={{ padding: 14, color: '#ef4444', fontSize: 13, borderBottom: `1px solid ${border}` }}>
            {error}
          </div>
        )}

        {loading ? (
          <div style={{ padding: 34, textAlign: 'center', color: sub, fontSize: 14 }}>
            Loading users...
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 820 }}>
              <thead>
                <tr>
                  {['Username', 'Display Name', 'Status', 'Role', 'Created', 'Last Login', 'Actions'].map(h => (
                    <th
                      key={h}
                      style={{
                        textAlign: 'left',
                        padding: '12px 14px',
                        color: sub,
                        fontSize: 11,
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        borderBottom: `1px solid ${border}`,
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {users.length === 0 && (
                  <tr>
                    <td colSpan={7} style={{ padding: 30, textAlign: 'center', color: sub }}>
                      No registered users yet.
                    </td>
                  </tr>
                )}

                {users.map(u => {
                  const status = u.access_status || (u.is_active ? 'approved' : 'pending');
                  const color = statusColor(status);
                  const busy = busyId === u.id;

                  return (
                    <tr key={u.id} style={{ borderBottom: `1px solid ${border}` }}>
                      <td style={{ padding: '12px 14px', color: t, fontWeight: 800 }}>
                        {u.username}
                      </td>

                      <td style={{ padding: '12px 14px', color: sub }}>
                        {u.display_name || u.username}
                      </td>

                      <td style={{ padding: '12px 14px' }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            padding: '4px 9px',
                            borderRadius: 999,
                            background: color + (dark ? '22' : '12'),
                            color,
                            fontSize: 11,
                            fontWeight: 850,
                            textTransform: 'capitalize',
                          }}
                        >
                          {status}
                        </span>
                      </td>

                      <td style={{ padding: '12px 14px', color: u.is_admin ? '#3884f4' : sub, fontWeight: 800 }}>
                        {u.is_admin ? 'Admin' : 'User'}
                      </td>

                      <td style={{ padding: '12px 14px', color: sub, fontSize: 12 }}>
                        {u.created_at ? new Date(u.created_at).toLocaleString() : '—'}
                      </td>

                      <td style={{ padding: '12px 14px', color: sub, fontSize: 12 }}>
                        {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}
                      </td>

                      <td style={{ padding: '12px 14px' }}>
                        <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
                          <button
                            disabled={busy || status === 'approved'}
                            onClick={() => updateUser(u.id, { access_status: 'approved' })}
                            style={btn('#22c55e', busy || status === 'approved')}
                          >
                            Approve
                          </button>

                          <button
                            disabled={busy || status === 'disabled'}
                            onClick={() => updateUser(u.id, { access_status: 'disabled' })}
                            style={btn('#ef4444', busy || status === 'disabled')}
                          >
                            Disable
                          </button>

                          <button
                            disabled={busy}
                            onClick={() => updateUser(u.id, { is_admin: !u.is_admin })}
                            style={btn('#3884f4', busy)}
                          >
                            {u.is_admin ? 'Remove Admin' : 'Make Admin'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>
    </div>
  );
}
