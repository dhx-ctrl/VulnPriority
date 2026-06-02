# VulnPriority Architecture

This document describes the current VulnPriority architecture after the single-model v4 migration.

## System overview

VulnPriority is a local DevSecOps security platform that collects vulnerability findings from CI/CD scanners and DefectDojo, enriches them with AI prioritization, stores the results in the backend database, and displays them in the React dashboard.

The current system has one AI prioritization model:

- **Model:** XGBoost stacked ensemble (v4)
- **Model folder:** `backend-ai/model_output_SINGLE_v4/`
- **Main decision threshold:** `0.386`
- **Purpose:** predict exploitation-likelihood / high-risk priority for vulnerability triage.
- **Output:** probability, score `/100`, risk label, binary high-risk decision, confidence indicator.

The previous two-model design has been replaced. There is no longer a separate strict model and separate queue model in the active architecture.

## High-level data flow

```text
GitHub Actions / scanner jobs
        |
        |  SAST / SCA / DAST reports
        v
DefectDojo
        |
        |  Product findings fetched through API
        v
FastAPI backend
        |
        |  normalization + feature preparation
        v
Single v4 AI model
        |
        |  ai_probability, ai_risk_score, ai_risk_label,
        |  ai_decision, ai_confidence
        v
SQLite / backend storage
        |
        v
React dashboard
```

## Repository layout

```text
ci-cd-security/
├── backend-ai/
│   ├── main.py
│   ├── core/
│   ├── database/
│   ├── routers/
│   ├── services/
│   ├── schemas.py
│   ├── model_output_SINGLE_v4/
│   │   ├── model_leakage_safe.pkl
│   │   ├── model_leakage_safe.pkl.sha256
│   │   ├── model_meta.json
│   │   ├── feature_columns.json
│   │   ├── shap_feature_importance.csv
│   │   └── threshold_comparison.csv
│   └── training/
│       ├── 03_train_leakage_safe_xgb.py
│       └── osv_text_fetcher.py
│
├── frontend-dashboard/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Layout.jsx
│   │   │   └── ui/
│   │   ├── context/
│   │   ├── pages/
│   │   └── services/
│   └── package.json
│
└── docs/
    ├── architecture.md
    ├── model_explanation.md
    └── ai_vs_cvss_benchmark.md
```

## Backend responsibilities

The backend is responsible for:

1. Authenticating users and protecting API routes.
2. Fetching products and findings from DefectDojo.
3. Normalizing findings into a consistent schema.
4. Preparing the feature columns expected by the model.
5. Loading the single v4 AI model from `model_output_SINGLE_v4`.
6. Verifying model artifact hashes before loading.
7. Producing AI outputs for every finding.
8. Storing scored findings locally.
9. Serving the dashboard, model metadata, findings, and sync status through FastAPI endpoints.

## AI output fields

The active dashboard should use the following fields from the AI layer:

| Field | Meaning |
|---|---|
| `ai_probability` | Raw model probability for high-risk/exploitation-likelihood. Best ranking field. |
| `ai_risk_score` | Rounded score from 0 to 100 for display. |
| `ai_risk_label` | Human-readable label such as Low, Medium, High, or Critical. |
| `ai_decision` | Boolean high-risk decision based on the selected threshold. |
| `ai_confidence` | Confidence bucket based on distance from the threshold. |

Scanner severity and CVSS remain visible, but they are treated as separate evidence rather than the final priority decision.

## Frontend responsibilities

The frontend is a Vite + React dashboard. It reads backend data through `src/services/api-client.js` and displays:

- total findings,
- severity distribution,
- findings grouped by product,
- review queue,
- model status,
- sync status,
- user/admin pages.

Reusable UI elements were moved into `src/components/ui/` to keep page files shorter and reduce duplicated card/badge/table styling.

## Deployment notes

For local PowerShell execution, the backend can use:

```env
DEFECTDOJO_URL=http://127.0.0.1:8080
AI_MODEL_DIR=model_output_SINGLE_v4
```

For backend execution inside Docker while DefectDojo runs on the host, use:

```env
DEFECTDOJO_URL=http://host.docker.internal:8080
AI_MODEL_DIR=model_output_SINGLE_v4
```

Generated folders such as `dist/`, `node_modules/`, `.venv/`, `.env`, and local database files should not be committed.
