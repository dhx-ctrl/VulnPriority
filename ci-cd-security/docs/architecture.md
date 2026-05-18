# Architecture

## Overview

VulnPriority is structured as a DevSecOps vulnerability prioritization platform.

```text
Target application repository
        |
        | GitHub Actions / self-hosted runner
        v
Scanner scripts
  - Semgrep
  - Trivy filesystem
  - Trivy image
  - OWASP ZAP baseline
        |
        v
DefectDojo import / reimport
        |
        v
DefectDojo vulnerability database
        |
        v
FastAPI backend sync
        |
        v
AI scoring + SQLite cache
        |
        v
React dashboard
```

## Repository structure

```text
ci-cd-security/
├── backend-ai/
│   ├── main.py
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── .env.example
│   ├── model_output_FINAL_clean_minimal_features/
│   └── model_output_EPSS_operational_ranker/
│
├── frontend-dashboard/
│   ├── src/
│   ├── package.json
│   ├── Dockerfile
│   ├── nginx.conf
│   └── .env.example
│
├── scripts/
│   ├── run_pipeline.sh
│   ├── import_scans.sh
│   ├── run_semgrep.sh
│   ├── run_trivy_fs.sh
│   ├── run_trivy_image.sh
│   └── run_zap.sh
│
├── products/
├── example-workflows/
└── docs/
```

## Backend

The backend is a FastAPI service. Its main responsibilities are:

- authenticate dashboard users;
- manage pending/approved/disabled dashboard users;
- expose health and metadata endpoints;
- synchronize findings from DefectDojo;
- normalize scanner findings into model input features;
- run the clean leakage-safe model and the operational EPSS ranker;
- store scored findings in SQLite;
- serve scored findings, products, trends, and notifications to the dashboard.

The backend loads two model folders:

```text
backend-ai/model_output_FINAL_clean_minimal_features/
backend-ai/model_output_EPSS_operational_ranker/
```

Each model folder contains:

```text
model_leakage_safe.pkl
model_leakage_safe.pkl.sha256
model_meta.json
model_meta.json.sha256
feature_columns.json
feature_columns.json.sha256
```

The SHA-256 files are verified before loading the model artifacts.

## Frontend

The frontend is a Vite React dashboard. It includes:

- Login page
- Registration page
- Pending access page
- Dashboard overview
- Findings table
- Scan history
- Model insights
- Summary
- Sync page
- Parameters page
- Admin Users page

The dashboard uses the backend API through:

```text
frontend-dashboard/src/services/api-client.js
```

The dashboard displays four main finding concepts:

| Field | Meaning |
|---|---|
| Scanner severity | Original severity from scanner or DefectDojo |
| CVSS | Standard severity baseline |
| Rank /100 | Operational EPSS ranker score used for queue ordering |
| Clean /100 | Leakage-safe model confidence signal |

## CI/CD scanning scripts

The scripts folder handles scanner orchestration and DefectDojo import.

Main flow:

```text
run_pipeline.sh
    -> run_semgrep.sh
    -> run_trivy_fs.sh
    -> run_trivy_image.sh
    -> start_app.sh / wait_for_app.sh / run_zap.sh
    -> import_scans.sh
```

`import_scans.sh` resolves or creates:

- product type;
- product;
- engagement;
- test;
- import or reimport operation.

This makes CI/CD imports repeatable and avoids manual DefectDojo setup for every run.

## DefectDojo integration

The backend communicates with DefectDojo using:

```env
DEFECTDOJO_URL
DEFECTDOJO_API_KEY
DEFECTDOJO_PRODUCT_ID
```

When a sync is triggered, the backend pulls findings from DefectDojo, scores them, and stores them locally in SQLite.

SQLite is used as a local runtime cache, not as the source of truth. DefectDojo remains the central finding source.

## Docker architecture

The project can be started with Docker Compose:

```text
docker-compose.yml
    -> backend-ai service
    -> frontend-dashboard service
```

The backend exposes port `8000`.

The frontend is built with Vite and served by Nginx on port `5173`.

## Runtime data

The following files are runtime/local and should not be committed:

```text
backend-ai/.env
backend-ai/ai_scores.db
frontend-dashboard/dist/
frontend-dashboard/node_modules/
```

The following files are safe to commit:

```text
backend-ai/.env.example
frontend-dashboard/.env.example
docker-compose.yml
Dockerfile files
source code
model artifact folders
documentation
```
