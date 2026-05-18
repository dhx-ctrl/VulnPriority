import React, { useEffect, useState } from 'react';
import { useSettings, useTheme } from '../context/AppContext.jsx';
import { GlassCard } from './DashboardPage.jsx';
import { apiClient } from '../services/api-client.js';

// Parameters Page — read-only model configuration + UI preferences.
// Model thresholds are loaded from backend metadata, not changed here.

function ParametersPage() {
  const { dark, toggle } = useTheme();
  const { settings, update } = useSettings();

  const [health, setHealth] = useState(null);

  useEffect(() => {
    let cancelled = false;

    apiClient.getHealth()
      .then(h => {
        if (!cancelled) setHealth(h);
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, []);

  const t = dark ? '#e2e8f0' : '#1e293b';
  const sub = dark ? '#94a3b8' : '#64748b';
  const border = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
  const inputBg = dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)';

  const cleanModel = health?.models?.clean || {};
  const rankerModel = health?.models?.operational_ranker || {};

  const rankerThreshold = Number(rankerModel.threshold ?? health?.threshold);
  const cleanThreshold = Number(cleanModel.threshold);

  const rankerThresholdText = Number.isFinite(rankerThreshold)
    ? rankerThreshold.toFixed(4)
    : 'metadata';

  const cleanThresholdText = Number.isFinite(cleanThreshold)
    ? cleanThreshold.toFixed(4)
    : 'metadata';

  const rankerFeatures = Array.isArray(rankerModel.features)
    ? rankerModel.features.length
    : Array.isArray(health?.binary_features)
      ? health.binary_features.length
      : 'metadata';

  const cleanFeatures = Array.isArray(cleanModel.features)
    ? cleanModel.features.length
    : 'metadata';

  function Section({ title, subtitle, children }) {
    return (
      <GlassCard style={{ marginBottom: 0 }}>
        <h3
          style={{
            fontSize: 16,
            fontWeight: 800,
            color: t,
            margin: '0 0 4px',
          }}
        >
          {title}
        </h3>

        {subtitle && (
          <p
            style={{
              fontSize: 12,
              color: sub,
              margin: '0 0 18px',
              lineHeight: 1.5,
            }}
          >
            {subtitle}
          </p>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {children}
        </div>
      </GlassCard>
    );
  }

  function Toggle({ label, desc, checked, onChange }) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: 16,
        }}
      >
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: t }}>{label}</div>
          {desc && (
            <div style={{ fontSize: 12, color: sub, marginTop: 4, lineHeight: 1.4 }}>
              {desc}
            </div>
          )}
        </div>

        <button
          onClick={() => onChange(!checked)}
          style={{
            width: 44,
            height: 24,
            borderRadius: 12,
            border: 'none',
            cursor: 'pointer',
            flexShrink: 0,
            background: checked
              ? '#3884f4'
              : dark
                ? 'rgba(255,255,255,0.12)'
                : 'rgba(0,0,0,0.1)',
            position: 'relative',
            transition: 'background 0.2s',
          }}
        >
          <div
            style={{
              width: 18,
              height: 18,
              borderRadius: '50%',
              background: '#fff',
              position: 'absolute',
              top: 3,
              left: checked ? 23 : 3,
              transition: 'left 0.2s',
              boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
            }}
          />
        </button>
      </div>
    );
  }

  function ReadOnlyRow({ label, value, note, color }) {
    return (
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr auto',
          gap: 14,
          padding: '10px 0',
          borderBottom: `1px solid ${dark ? 'rgba(255,255,255,0.045)' : 'rgba(15,23,42,0.055)'}`,
        }}
      >
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: t }}>{label}</div>
          {note && (
            <div style={{ fontSize: 12, color: sub, marginTop: 3, lineHeight: 1.4 }}>
              {note}
            </div>
          )}
        </div>

        <div
          className="num"
          style={{
            fontSize: 13,
            fontWeight: 850,
            color: color || t,
            textAlign: 'right',
            maxWidth: 220,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {String(value)}
        </div>
      </div>
    );
  }

  function Badge({ children, color = '#3884f4' }) {
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          padding: '4px 9px',
          borderRadius: 999,
          background: color + (dark ? '22' : '12'),
          color,
          border: `1px solid ${color}${dark ? '34' : '22'}`,
          fontSize: 11,
          fontWeight: 850,
          whiteSpace: 'nowrap',
        }}
      >
        {children}
      </span>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 820 }}>
      <div>
        <h1
          style={{
            fontSize: 24,
            fontWeight: 800,
            color: t,
            margin: 0,
          }}
        >
          Parameters
        </h1>

        <p
          style={{
            fontSize: 14,
            color: sub,
            margin: '6px 0 0',
            lineHeight: 1.5,
          }}
        >
          Model thresholds are loaded from backend metadata. This page explains the active scoring setup and stores UI preferences only.
        </p>
      </div>

      <Section
        title="Active AI Models"
        subtitle="The dashboard uses two models with different roles. They should not be merged blindly because they use different labels and feature sets."
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 14,
          }}
        >
          <div
            style={{
              padding: 14,
              borderRadius: 12,
              border: `1px solid ${border}`,
              background: inputBg,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 850, color: t }}>
                Operational Ranker
              </div>
              <Badge color="#3884f4">Rank /100</Badge>
            </div>

            <ReadOnlyRow
              label="Purpose"
              value="Queue sorting"
              note="Main score used to order findings in Dashboard and Findings."
              color="#3884f4"
            />

            <ReadOnlyRow
              label="Strict alert threshold"
              value={rankerThresholdText}
              note="Loaded from model metadata. This creates operational_is_high_risk, but the table still sorts by Rank /100."
            />

            <ReadOnlyRow
              label="Features"
              value={rankerFeatures}
              note="EPSS-only ranker can use CVSS because CVSS is not the target label."
            />
          </div>

          <div
            style={{
              padding: 14,
              borderRadius: 12,
              border: `1px solid ${border}`,
              background: inputBg,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 850, color: t }}>
                Clean Leakage-Safe Model
              </div>
              <Badge color="#22c55e">Clean /100</Badge>
            </div>

            <ReadOnlyRow
              label="Purpose"
              value="Confidence signal"
              note="Secondary strict signal. It is not used to hide findings."
              color="#22c55e"
            />

            <ReadOnlyRow
              label="Clean threshold"
              value={cleanThresholdText}
              note="Loaded from model metadata. Used for the clean confidence flag."
            />

            <ReadOnlyRow
              label="Features"
              value={cleanFeatures}
              note="Removes EPSS, CVSS score, scanner severity, exploit refs, source metadata, raw IDs, and CVSS subcomponents."
            />
          </div>
        </div>
      </Section>

      <Section
        title="Dashboard Priority Rules"
        subtitle="These are display rules used by the frontend. They do not retrain the models."
      >
        <ReadOnlyRow
          label="Review First"
          value="Rank ≥ 70"
          note="Also includes findings where the strict operational alert is true."
          color="#ef4444"
        />

        <ReadOnlyRow
          label="Review Soon"
          value="Rank ≥ 30 or Clean flag"
          note="Medium-priority operational findings or strict clean-model confidence."
          color="#f97316"
        />

        <ReadOnlyRow
          label="Severity Watch"
          value="High/Critical scanner severity"
          note="Scanner severity is high, but operational rank is below 30."
          color="#eab308"
        />

        <ReadOnlyRow
          label="Backlog"
          value="Lower priority"
          note="Still visible. The dashboard does not silently hide findings."
          color="#64748b"
        />
      </Section>

      <Section
        title="Display Preferences"
        subtitle="These preferences affect the local dashboard interface only."
      >
        <Toggle
          label="Notifications"
          desc="Show alerts for new critical, high-severity, or high-priority findings."
          checked={settings.notifications}
          onChange={v => update('notifications', v)}
        />

        <Toggle
          label="Dark Mode"
          desc="Switch between light and dark theme."
          checked={dark}
          onChange={() => toggle()}
        />
      </Section>

      <Section
        title="Notes"
        subtitle="Important boundaries for interpreting this page."
      >
        <div
          style={{
            padding: 14,
            borderRadius: 12,
            border: `1px solid ${border}`,
            background: dark ? 'rgba(56,132,244,0.08)' : 'rgba(56,132,244,0.05)',
            fontSize: 13,
            color: sub,
            lineHeight: 1.6,
          }}
        >
          Changing values on this page does not retrain XGBoost and does not edit model metadata.
          The active model thresholds are stored in the model output folders and loaded by the backend.
          Scanner severity, CVSS, Rank /100, and Clean /100 should be interpreted together during review.
        </div>
      </Section>
    </div>
  );
}

export default ParametersPage;