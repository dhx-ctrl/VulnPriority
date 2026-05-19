# VulnPriority

VulnPriority is a DevSecOps project for AI-assisted vulnerability prioritization. It combines CI/CD security scanners, DefectDojo, a FastAPI AI backend, and a React dashboard to help analysts review the most important findings first.

The project does **not** replace SAST, SCA, DAST, CVSS, DefectDojo, or human review. The scanners detect vulnerabilities. VulnPriority adds a prioritization layer on top of those findings.

---

## Project structure

```text
VulnPriority/
├── README.md
└── ci-cd-security/
    ├── README.md
    ├── docker-compose.yml
    ├── backend-ai/
    ├── frontend-dashboard/
    ├── scripts/
    ├── products/
    ├── example-workflows/
    └── docs/
```

The main project files are inside:

```text
ci-cd-security/
```

---

## Main components

### 1. CI/CD scanner pipeline

The scanner scripts run security tools against target applications and import the results into DefectDojo.

Current scanner flow:

| Tool | Type | Purpose |
|---|---|---|
| Semgrep | SAST | Static source-code analysis |
| Trivy filesystem | SCA | Dependency and filesystem vulnerability scanning |
| Trivy image | SCA | Container image vulnerability scanning |
| OWASP ZAP baseline | DAST | Dynamic web application testing |

The main import script is:

```text
ci-cd-security/scripts/import_scans.sh
```

It automatically resolves or creates DefectDojo product types, products, engagements, and tests before importing or reimporting scan results.

---

### 2. DefectDojo

DefectDojo is used as the central vulnerability management platform.

It stores findings from the scanners. The AI backend later synchronizes findings from DefectDojo, scores them, and stores the scored results in a local SQLite cache.

---

### 3. FastAPI AI backend

The backend is located in:

```text
ci-cd-security/backend-ai/
```

It provides:

- dashboard login and local user management;
- pending user registration and admin approval;
- DefectDojo synchronization;
- AI risk scoring;
- stored score browsing;
- product summaries;
- notifications;
- trend endpoints;
- model health and metadata.

The backend uses a local SQLite database as a runtime cache:

```text
ci-cd-security/backend-ai/ai_scores.db
```

This database is generated locally and should not be committed.

---

### 4. Dual AI model setup

The backend uses two separate models.

#### Clean leakage-safe model

This model is used as a stricter scientific confidence signal. It excludes direct shortcut features such as EPSS score, CVSS score, scanner severity, exploit references, source metadata, raw identifiers, and CVSS subcomponents.

Dashboard field:

```text
Clean /100
```

#### Operational EPSS ranker

This model is used as the main practical ranking model. It predicts an EPSS-based target and is used to sort findings in the dashboard review queue.

Dashboard field:

```text
Rank /100
```

Important distinction:

```text
Clean model = leakage-aware scientific signal
Operational ranker = practical queue-sorting model
```

The operational ranker is not presented as the leakage-safe model. It is presented as a practical ranking model that improves over CVSS-only ordering by combining CVSS with additional vulnerability and package metadata.

---

### 5. React dashboard

The dashboard is located in:

```text
ci-cd-security/frontend-dashboard/
```

It is a Vite React application with pages for:

- Login
- Register
- Pending Access
- Dashboard
- Findings
- Scan History
- Model Insights
- Summary
- Sync
- Parameters
- Users

The dashboard uses the backend API and displays:

| Field | Meaning |
|---|---|
| Scanner Severity | Original severity from scanner or DefectDojo |
| CVSS | Standard severity baseline |
| Rank /100 | Operational EPSS ranker score |
| Clean /100 | Leakage-safe model confidence signal |

---

## Priority logic

The dashboard uses these triage labels:

| Label | Rule | Meaning |
|---|---|---|
| Review First | Operational alert is true or Rank /100 >= 70 | Highest review priority |
| Review Soon | Rank /100 >= 30 or clean model flag is true | Review after the top queue |
| Severity Watch | Scanner severity High/Critical but Rank /100 < 30 | Keep visible because scanner severity is important |
| Backlog | Everything else | Lower operational priority |

---

## Security improvements

The project includes several security fixes:

- CORS restricted to configured dashboard origins.
- Sensitive endpoints protected with API/session token authentication.
- Admin-only user approval and access control.
- User registration creates pending accounts by default.
- Real `.env` files are ignored by Git.
- Safe `.env.example` templates are provided.
- DefectDojo tokens are masked in CI logs.
- Scan metadata is loaded through a whitelist instead of blindly sourced.
- Temporary files are stored in a private runner directory.
- Model artifacts are verified with SHA-256 before loading.
- SQLite database files are excluded from Git.

---

## Environment files

Do not commit real secrets.

Commit:

```text
.env.example
```

Do not commit:

```text
.env
```

For the backend, create a local environment file from the example:

```powershell
cd ci-cd-security/backend-ai
Copy-Item .env.example .env
```

Then fill in your real values locally.

---

## Running with Docker Compose

The main application is inside:

ci-cd-security/

Before running Docker Compose, make sure the frontend production build exists:

cd ci-cd-security/frontend-dashboard
npm install
npm run build

Then start the full application:

cd ..
docker compose up --build

Frontend:

http://127.0.0.1:5173

Backend health endpoint:

http://127.0.0.1:8000/api/health/

Note: the frontend Docker image serves the prebuilt frontend-dashboard/dist/ folder through Nginx.

---

## Running locally without Docker

### Backend

```powershell
cd ci-cd-security/backend-ai
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

```powershell
cd ci-cd-security/frontend-dashboard
npm install
npm run dev
```

---

## Documentation

Detailed documentation is available in:

```text
ci-cd-security/docs/
```

Recommended reading:

| File | Purpose |
|---|---|
| architecture.md | Explains the full platform architecture |
| security_fixes.md | Summarizes security fixes and audit response |
| model_explanation.md | Explains the dual-model setup |
| ai_vs_cvss_benchmark.md | Documents AI ranking vs CVSS-only ranking |

---

## Repository hygiene

The following files should not be committed:

```text
.env
.env.*
ai_scores.db
*.db
node_modules/
dist/
.venv/
__pycache__/
*.log
```

The final model artifact folders should be committed unless they are too large for GitHub. If `.pkl` files are too large, use Git LFS.

---

## Important limitation

VulnPriority is a prioritization system, not a vulnerability detector.

The scanners detect findings. DefectDojo stores them. The AI models help sort and explain which findings should be reviewed first. Final remediation decisions still require human security review.
