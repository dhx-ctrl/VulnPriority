# VulnPriority — AI-driven vulnerability prioritization

VulnPriority is a DevSecOps platform that centralizes vulnerability findings from CI/CD security scanners, imports them into DefectDojo, synchronizes them into a FastAPI backend, scores them with AI prioritization models, and displays the results in a React dashboard.

The goal is not to replace security scanners or CVSS. The goal is to help analysts decide which findings should be reviewed first.

## Main components

```text
ci-cd-security/
├── backend-ai/              # FastAPI backend + AI models + SQLite runtime cache
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
4. Each finding receives two AI scores:
   - **Rank /100** from the operational EPSS ranker.
   - **Clean /100** from the leakage-safe confidence model.
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

VulnPriority uses a dual-model setup.

### 1. Clean leakage-safe model

This model is used as a strict confidence signal. It avoids direct shortcut features such as EPSS score, CVSS score, scanner severity, exploit references, source metadata, raw identifiers, and CVSS subcomponents.

It is used to support the scientific argument that the model can learn useful prioritization patterns without directly copying the target label or obvious severity shortcuts.

### 2. Operational EPSS ranker

This model is used as the main dashboard ranking model. It predicts an EPSS-based exploitation-likelihood label and is allowed to use CVSS and vulnerability metadata because its target is not CVSS.

The operational ranker is used to sort the queue and compare prioritization against CVSS-only ordering.

## Priority labels

| Label | Rule | Meaning |
|---|---|---|
| Review First | Operational alert is true or Rank /100 >= 70 | Highest review priority |
| Review Soon | Rank /100 >= 30 or clean model flag is true | Should be reviewed after top queue |
| Severity Watch | Scanner severity High/Critical but operational rank is low | Important scanner severity, but not an AI emergency |
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

From the repository root:

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

The AI score is not a vulnerability detector. The scanners detect vulnerabilities. The AI models only help prioritize which scanner findings should be reviewed first. Human review is still required, especially for internet-facing systems, authentication issues, business-critical systems, and findings with uncertain exploitability.
