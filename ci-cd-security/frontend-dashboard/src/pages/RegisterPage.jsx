import React, { useState } from 'react';
import { useAuth, useRouter, useTheme } from '../context/AppContext.jsx';
import { InteractiveBackground } from './LoginPage.jsx';

function passwordValid(password) {
  return /^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{6,}$/.test(password);
}

export default function RegisterPage() {
  const { dark } = useTheme();
  const { register } = useAuth();
  const { navigate } = useRouter();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [focused, setFocused] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const text = dark ? '#f1f5f9' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';

  const cardStyle = {
    position: 'relative',
    zIndex: 2,
    maxWidth: 430,
    width: '100%',
    margin: '0 auto',
    padding: '44px 40px',
    borderRadius: 14,
    background: dark ? 'rgba(16,22,40,0.85)' : 'rgba(255,255,255,0.75)',
    backdropFilter: 'blur(24px)',
    WebkitBackdropFilter: 'blur(24px)',
    border: `1px solid ${dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)'}`,
    boxShadow: dark ? '0 24px 80px rgba(0,0,0,0.5)' : '0 24px 80px rgba(0,0,0,0.08)',
  };

  const inputStyle = (name) => ({
    width: '100%',
    padding: '14px 16px',
    borderRadius: 8,
    fontSize: 15,
    outline: 'none',
    border: `2px solid ${focused === name ? '#3884f4' : (dark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.08)')}`,
    background: dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)',
    color: text,
    transition: 'all 0.3s ease',
    boxSizing: 'border-box',
    boxShadow: focused === name ? `0 0 0 4px ${dark ? 'rgba(56,132,244,0.15)' : 'rgba(56,132,244,0.12)'}` : 'none',
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    const cleanUsername = username.trim();

    if (cleanUsername.length < 3) {
      setError('Username must be at least 3 characters long.');
      return;
    }

    if (!passwordValid(password)) {
      setError('Password must be at least 6 characters and include one letter, one number, and one special character.');
      return;
    }

    setLoading(true);
    const result = await register(cleanUsername, password);
    setLoading(false);

    if (result.ok) {
      navigate('/pending-access');
    } else {
      setError(result.error || 'Registration failed.');
    }
  };

  return (
    <div style={{ position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <InteractiveBackground playful={true} />

      <div style={cardStyle}>
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{ width: 52, height: 52, borderRadius: 10, background: 'linear-gradient(135deg, #3884f4, #2563eb)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', color: '#fff', fontWeight: 900, fontSize: 22 }}>
            +
          </div>

          <h1 style={{ fontSize: 25, fontWeight: 750, color: text, margin: '0 0 6px', letterSpacing: '-0.02em' }}>
            Create Account
          </h1>

          <p style={{ fontSize: 14, color: sub, margin: 0 }}>
            Register first, then wait for admin approval.
          </p>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: sub, marginBottom: 6 }}>
              Username
            </label>

            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              onFocus={() => setFocused('user')}
              onBlur={() => setFocused(null)}
              placeholder="choose_a_username"
              style={inputStyle('user')}
              autoComplete="username"
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: sub, marginBottom: 6 }}>
              Password
            </label>

            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onFocus={() => setFocused('pass')}
              onBlur={() => setFocused(null)}
              placeholder="Min 6 chars, letter, number, symbol"
              style={inputStyle('pass')}
              autoComplete="new-password"
            />

            <div style={{ fontSize: 11, color: sub, marginTop: 6, lineHeight: 1.4 }}>
              Must contain at least one letter, one number, and one special character.
            </div>
          </div>

          {error && (
            <div style={{ padding: '10px 14px', borderRadius: 6, background: dark ? 'rgba(244,63,94,0.12)' : 'rgba(244,63,94,0.08)', color: '#f43f5e', fontSize: 13, fontWeight: 500 }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              padding: '14px',
              borderRadius: 8,
              border: 'none',
              cursor: 'pointer',
              background: 'linear-gradient(135deg, #3884f4, #2563eb)',
              color: '#fff',
              fontSize: 15,
              fontWeight: 650,
              marginTop: 4,
              opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? 'Creating account...' : 'Create Account'}
          </button>
        </form>

        <p style={{ textAlign: 'center', fontSize: 12, color: sub, marginTop: 20 }}>
          Already approved?{' '}
          <button
            onClick={() => navigate('/login')}
            style={{ border: 'none', background: 'transparent', color: '#3884f4', fontWeight: 750, cursor: 'pointer', padding: 0 }}
          >
            Sign in
          </button>
        </p>
      </div>
    </div>
  );
}
