# VulnPriority — AI-driven vulnerability prioritization

VulnPriority is a DevSecOps platform that centralizes vulnerability findings from CI/CD security scanners, imports them into DefectDojo, synchronizes them into a FastAPI backend, scores them with a single v4 AI prioritization model, and displays the results in a React dashboard.

The goal is not to replace security scanners or CVSS. The goal is to help analysts decide which findings should be reviewed first.

## Main components

```text
ci-cd-security/
├── backend-ai/              # FastAPI backend + single v4 AI model + SQLite runtime cache
├── frontend-dashboard/      # Vite React dashboard
├── scripts/                 # CI/CD scanner orchestration and DefectDojo import scripts
├── products/                # Per-target application scan configuration templates
├── example-workflows/       # Example GitHub Actions workflow
└── docs/                    # Architecture, security fixes, model explanation, benchmark notes
```

## What the platform does

1. A target application such as DVNA, DVWA, Juice Shop, or NodeGoat is scanned through CI/CD.
2. The scanner outputs are imported into DefectDojo.
3. The FastAPI backend synchronizes findings from DefectDojo.
4. Each finding receives one AI prioritization result from the single v4 model:
   - **AI /100** risk score.
   - **AI probability** for high-risk prioritization.
   - **AI risk label** for dashboard readability.
   - **AI confidence** for interpretation.
   - **AI high-risk decision** based on the selected threshold.
5. The React dashboard displays findings using practical triage labels:
   - **Review First**
   - **Review Soon**
   - **Severity Watch**
   - **Backlog**

## Scanner layer

The scanner layer detects vulnerabilities. VulnPriority currently supports the following workflow:

| Scanner | Role | Purpose |
|---|---|---|
| Semgrep | SAST | Static source-code analysis |
| Trivy filesystem | SCA | Dependency and filesystem vulnerability scanning |
| Trivy image | SCA | Container image vulnerability scanning |
| OWASP ZAP baseline | DAST | Dynamic web application testing |

DefectDojo is used as the central vulnerability management platform.

## AI scoring layer

VulnPriority uses one production AI model: a single v4 stacked binary classifier for vulnerability prioritization.

The model combines XGBoost, Random Forest, and Logistic Regression as base learners, with a Logistic Regression meta-learner. It produces a high-risk probability, which the backend converts into dashboard-friendly fields.

Active model folder:

```text
backend-ai/model_output_SINGLE_v4/
```

Model configuration:

```env
AI_MODEL_DIR=model_output_SINGLE_v4
AI_MODEL_FILE=model_leakage_safe.pkl
```

Main output fields:

| Field | Meaning |
|---|---|
| `ai_probability` | Raw model probability for high-risk/exploitation-likelihood prioritization |
| `ai_risk_score` | Rounded score from 0 to 100 for display |
| `ai_risk_label` | Human-readable risk category |
| `ai_decision` | Boolean high-risk decision based on the threshold |
| `ai_confidence` | Confidence bucket based on distance from the threshold |

The selected balanced threshold is:

```text
0.386
```

The old dual-model architecture has been replaced. Older `clean_*` and `operational_*` fields may still be filled internally as compatibility aliases, but they are not the current documentation model.

## Priority labels

| Label | Rule | Meaning |
|---|---|---|
| Review First | AI high-risk decision is true or AI /100 >= 70 | Highest review priority |
| Review Soon | AI /100 >= 30 | Should be reviewed after top queue |
| Severity Watch | Scanner severity High/Critical but AI /100 is low | Important scanner severity, but not an AI emergency |
| Backlog | Everything else | Lower operational priority |

## Environment configuration

Do not commit real secrets.

Create a local file:

```text
backend-ai/.env
```

from the safe template:

```text
backend-ai/.env.example
```

Example:

```powershell
Copy-Item backend-ai\.env.example backend-ai\.env
```

Then fill in the real values locally.

The real `.env` is ignored by Git. Only `.env.example` should be committed.

## Running locally with Docker Compose

From the `ci-cd-security` folder:

```powershell
docker compose up --build
```

Frontend:

```text
http://127.0.0.1:5173
```

Backend health endpoint:

```text
http://127.0.0.1:8000/api/health/
```

If DefectDojo runs on the host machine while the backend runs in Docker, use:

```env
DEFECTDOJO_URL=http://host.docker.internal:8080
```

For local PowerShell execution without Docker, use:

```env
DEFECTDOJO_URL=http://127.0.0.1:8080
```

## Important note about the frontend Docker build

The frontend Docker image serves the already-built React production files from:

```text
frontend-dashboard/dist/
```

Build the frontend before running Docker Compose if the `dist/` folder is missing or outdated:

```powershell
cd frontend-dashboard
npm install
npm run build
```

Then return to the project folder and start Docker Compose:

```powershell
cd ..
docker compose up --build
```

The reason for this setup is that the final Docker image uses Nginx to serve the static React build. The frontend Dockerfile copies the `dist/` folder directly into Nginx.

If the dashboard source code changes, run:

```powershell
cd frontend-dashboard
npm run build
```

Then commit the updated source changes. Do not commit `dist/` unless the repository intentionally tracks the built frontend.

## Running without Docker

Backend:

```powershell
cd backend-ai
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
cd frontend-dashboard
npm install
npm run dev
```

## Authentication and users

The backend uses a local dashboard authentication system.

Initial bootstrap admin credentials are configured in:

```env
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=replace_with_admin_password
```

Users can register from the dashboard. Newly registered users are marked as pending and cannot access the dashboard until an admin approves them on the Users page.

## Security controls implemented

- CORS restricted to configured dashboard origins.
- Protected API endpoints require an API key/session token.
- Admin-only user approval/disable controls.
- Real secrets excluded from Git.
- `.env.example` provided as a safe template.
- Model artifacts loaded with SHA-256 verification.
- DefectDojo tokens masked in CI logs.
- Scan metadata loading restricted to whitelisted keys.

More details are in:

```text
docs/security_fixes.md
```

## Model documentation

Model behavior and limitations are documented in:

```text
docs/model_explanation.md
docs/ai_vs_cvss_benchmark.md
```

## Important limitation

The AI score is not a vulnerability detector. The scanners detect vulnerabilities. The AI model only helps prioritize which scanner findings should be reviewed first. Human review is still required, especially for internet-facing systems, authentication issues, business-critical systems, and findings with uncertain exploitability.
