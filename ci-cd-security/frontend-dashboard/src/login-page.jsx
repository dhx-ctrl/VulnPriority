// Interactive Background + Login Page
const { useState, useRef, useCallback, useEffect } = React;

// ── Interactive Background ──
function InteractiveBackground({ playful }) {
  const { dark } = useTheme();
  const ref = useRef(null);
  const [mouse, setMouse] = useState({ x: 50, y: 50 });
  const [ripples, setRipples] = useState([]);

  const handleMove = useCallback((e) => {
    const r = ref.current?.getBoundingClientRect();
    if (!r) return;
    setMouse({ x: ((e.clientX - r.left) / r.width) * 100, y: ((e.clientY - r.top) / r.height) * 100 });
  }, []);

  const handleClick = useCallback((e) => {
    if (!playful) return;
    const r = ref.current?.getBoundingClientRect();
    if (!r) return;
    const id = Date.now();
    setRipples(prev => [...prev.slice(-4), { id, x: e.clientX - r.left, y: e.clientY - r.top }]);
    setTimeout(() => setRipples(prev => prev.filter(r => r.id !== id)), 1200);
  }, [playful]);

  const bgStyle = {
    position: 'fixed', inset: 0, zIndex: 0, overflow: 'hidden', pointerEvents: 'auto',
    background: dark
      ? `radial-gradient(600px circle at ${mouse.x}% ${mouse.y}%, rgba(56,132,244,0.06), transparent 60%), #0a0e1a`
      : `radial-gradient(600px circle at ${mouse.x}% ${mouse.y}%, rgba(56,132,244,0.04), transparent 60%), #f1f3f8`,
    transition: 'background 0.3s ease',
  };

  return React.createElement('div', { ref, style: bgStyle, onMouseMove: handleMove, onClick: handleClick },
    ripples.map(r => React.createElement('span', {
      key: r.id,
      style: {
        position: 'absolute', left: r.x, top: r.y, width: 0, height: 0,
        borderRadius: '50%', transform: 'translate(-50%,-50%)',
        background: dark ? 'rgba(56,132,244,0.12)' : 'rgba(56,132,244,0.08)',
        animation: 'ripple 1.2s ease-out forwards', pointerEvents: 'none',
      }
    }))
  );
}

// ── Login Page ──
function LoginPage() {
  const { dark } = useTheme();
  const { login } = useAuth();
  const { navigate } = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [focused, setFocused] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    await new Promise(r => setTimeout(r, 800));
    if (login(username, password)) {
      navigate('/dashboard');
    } else {
      setError('Invalid credentials');
    }
    setLoading(false);
  };

  const cardStyle = {
    position: 'relative', zIndex: 2, maxWidth: 420, width: '100%', margin: '0 auto',
    padding: '48px 40px', borderRadius: 14,
    background: dark ? 'rgba(16,22,40,0.85)' : 'rgba(255,255,255,0.75)',
    backdropFilter: 'blur(24px)', WebkitBackdropFilter: 'blur(24px)',
    border: `1px solid ${dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)'}`,
    boxShadow: dark ? '0 24px 80px rgba(0,0,0,0.5)' : '0 24px 80px rgba(0,0,0,0.08)',
    transition: 'all 0.4s ease',
  };

  const inputStyle = (name) => ({
    width: '100%', padding: '14px 16px', borderRadius: 8, fontSize: 15, outline: 'none',
    border: `2px solid ${focused === name ? (dark ? '#3884f4' : '#3884f4') : (dark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.08)')}`,
    background: dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)',
    color: dark ? '#e2e8f0' : '#1e293b', transition: 'all 0.3s ease', boxSizing: 'border-box',
    boxShadow: focused === name ? `0 0 0 4px ${dark ? 'rgba(56,132,244,0.15)' : 'rgba(56,132,244,0.12)'}` : 'none',
  });

  return React.createElement('div', { style: { position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24 } },
    React.createElement(InteractiveBackground, { playful: true }),
    React.createElement('div', { style: cardStyle },
      React.createElement('div', { style: { textAlign: 'center', marginBottom: 32 } },
        React.createElement('div', { style: { width: 52, height: 52, borderRadius: 10, background: 'linear-gradient(135deg, #3884f4, #2563eb)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' } }, React.createElement('svg',{xmlns:'http://www.w3.org/2000/svg',width:24,height:24,viewBox:'0 0 24 24',fill:'none',stroke:'#fff',strokeWidth:2,strokeLinecap:'square'},React.createElement('polygon',{points:'12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2'}),React.createElement('line',{x1:12,y1:22,x2:12,y2:15.5}),React.createElement('polyline',{points:'22 8.5 12 15.5 2 8.5'}))),
        React.createElement('h1', { style: { fontSize: 26, fontWeight: 700, color: dark ? '#f1f5f9' : '#1e293b', margin: '0 0 6px', letterSpacing: '-0.02em' } }, 'VulnPriority AI'),
        React.createElement('p', { style: { fontSize: 14, color: dark ? '#94a3b8' : '#64748b', margin: 0 } }, 'AI-Powered Vulnerability Prioritization'),
      ),
      React.createElement('form', { onSubmit: handleSubmit, style: { display: 'flex', flexDirection: 'column', gap: 18 } },
        React.createElement('div', null,
          React.createElement('label', { style: { display: 'block', fontSize: 13, fontWeight: 600, color: dark ? '#94a3b8' : '#64748b', marginBottom: 6 } }, 'Username'),
          React.createElement('input', { type: 'text', value: username, onChange: e => setUsername(e.target.value), onFocus: () => setFocused('user'), onBlur: () => setFocused(null), placeholder: 'admin', style: inputStyle('user'), autoComplete: 'username' }),
        ),
        React.createElement('div', null,
          React.createElement('label', { style: { display: 'block', fontSize: 13, fontWeight: 600, color: dark ? '#94a3b8' : '#64748b', marginBottom: 6 } }, 'Password'),
          React.createElement('input', { type: 'password', value: password, onChange: e => setPassword(e.target.value), onFocus: () => setFocused('pass'), onBlur: () => setFocused(null), placeholder: '••••••', style: inputStyle('pass'), autoComplete: 'current-password' }),
        ),
        error && React.createElement('div', { style: { padding: '10px 14px', borderRadius: 6, background: dark ? 'rgba(244,63,94,0.12)' : 'rgba(244,63,94,0.08)', color: '#f43f5e', fontSize: 13, fontWeight: 500 } }, error),
        React.createElement('button', {
          type: 'submit', disabled: loading,
          style: {
            padding: '14px', borderRadius: 8, border: 'none', cursor: 'pointer',
            background: 'linear-gradient(135deg, #3884f4, #2563eb)', color: '#fff',
            fontSize: 15, fontWeight: 600, transition: 'all 0.3s ease', marginTop: 4,
            opacity: loading ? 0.7 : 1, transform: loading ? 'scale(0.98)' : 'scale(1)',
          },
        }, loading ? 'Signing in...' : 'Sign In'),
      ),
      React.createElement('p', { style: { textAlign: 'center', fontSize: 12, color: dark ? '#64748b' : '#94a3b8', marginTop: 20 } }, 'Demo credentials: admin / admin'),
    ),
  );
}

Object.assign(window, { InteractiveBackground, LoginPage });
