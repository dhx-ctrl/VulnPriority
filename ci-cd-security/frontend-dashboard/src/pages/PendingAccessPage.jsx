import React from 'react';
import { useRouter, useTheme } from '../context/AppContext.jsx';
import { InteractiveBackground } from './LoginPage.jsx';

export default function PendingAccessPage() {
  const { dark } = useTheme();
  const { navigate } = useRouter();

  const text = dark ? '#f1f5f9' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';

  return (
    <div style={{ position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <InteractiveBackground playful={true} />

      <div
        style={{
          position: 'relative',
          zIndex: 2,
          maxWidth: 460,
          width: '100%',
          padding: '42px 38px',
          borderRadius: 16,
          textAlign: 'center',
          background: dark ? 'rgba(16,22,40,0.86)' : 'rgba(255,255,255,0.78)',
          backdropFilter: 'blur(24px)',
          WebkitBackdropFilter: 'blur(24px)',
          border: `1px solid ${dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)'}`,
          boxShadow: dark ? '0 24px 80px rgba(0,0,0,0.5)' : '0 24px 80px rgba(0,0,0,0.08)',
        }}
      >
        <div style={{ width: 58, height: 58, borderRadius: 16, margin: '0 auto 18px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: dark ? 'rgba(249,115,22,0.18)' : 'rgba(249,115,22,0.12)', color: '#f97316', fontSize: 28, fontWeight: 900 }}>
          !
        </div>

        <h1 style={{ fontSize: 25, fontWeight: 850, color: text, margin: '0 0 8px' }}>
          Waiting for Admin Approval
        </h1>

        <p style={{ fontSize: 14, color: sub, lineHeight: 1.65, margin: '0 0 22px' }}>
          Your account was registered successfully, but you do not have dashboard access yet. Contact an admin to approve your account.
        </p>

        <button
          onClick={() => navigate('/login')}
          style={{
            padding: '12px 18px',
            borderRadius: 9,
            border: 'none',
            background: 'linear-gradient(135deg, #3884f4, #2563eb)',
            color: '#fff',
            fontSize: 14,
            fontWeight: 750,
            cursor: 'pointer',
          }}
        >
          Back to Login
        </button>
      </div>
    </div>
  );
}
