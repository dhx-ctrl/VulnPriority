# Security fixes and audit response

This document summarizes the main security improvements made to VulnPriority.

## 1. CORS restriction

Original risk: the backend could be called from any website if CORS allowed all origins.

Current fix:

- CORS is configured using `DASHBOARD_ORIGINS`.
- Only known dashboard origins are allowed.
- Required frontend methods such as `GET`, `POST`, and `PATCH` are allowed.
- The frontend origin is configured through `.env`.

Example safe value:

```env
DASHBOARD_ORIGINS=http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:5500,http://localhost:5500
```

## 2. API authentication

Original risk: sensitive backend endpoints could be accessed without authentication.

Current fix:

- Protected API routes require the `X-API-Key` header.
- The dashboard receives a session token after login.
- The backend also keeps a bootstrap API token through `API_AUTH_TOKEN`.
- Admin-only actions require admin privileges.

Protected operations include:

- scoring;
- DefectDojo sync;
- score browsing;
- product browsing;
- notifications;
- trends;
- user approval and disabling.

## 3. User registration and approval

A local dashboard user system was added.

Flow:

```text
User registers
    -> account stored as pending
    -> login redirects to pending access page
    -> admin opens Users page
    -> admin approves or disables user
    -> approved user can access dashboard
```

Security benefits:

- users are not automatically trusted;
- admin approval is required;
- disabled users lose access;
- user management is not done manually in the backend anymore.

## 4. Secret handling

Real secrets are kept in:

```text
backend-ai/.env
```

This file is ignored by Git.

Safe templates are committed as:

```text
backend-ai/.env.example
frontend-dashboard/.env.example
```

The repository `.gitignore` excludes:

```text
.env
.env.*
*.db
*.sqlite
*.sqlite3
node_modules/
dist/
.venv/
```

## 5. DefectDojo token protection in CI logs

The scan import script now masks secrets before logging.

Implemented protections:

- masks `DOJO_TOKEN`;
- masks `DEFECTDOJO_API_KEY`;
- disables shell tracing using `set +x`;
- redacts secrets from API error bodies;
- avoids printing sensitive curl headers.

## 6. Safer temporary files

The scan import script now uses a private temporary directory based on:

```text
RUNNER_TEMP
RUN_OUTPUT_DIR
```

instead of using predictable shared files directly under `/tmp`.

The temporary directory is created with restrictive permissions and cleaned at exit.

## 7. Safe metadata loading

Original risk: sourcing an untrusted `scan_meta.env` file could allow unwanted environment variables to override sensitive values.

Current fix:

- `scan_meta.env` is parsed through Python.
- Only whitelisted keys are accepted.
- Values are shell-quoted.
- Unknown keys are ignored.

This prevents malicious or accidental variable injection through metadata files.

## 8. Model loading hardening

Original risk: loading pickle files directly is unsafe if artifacts are modified.

Current fix:

- model files are loaded with `joblib`;
- every artifact is verified with SHA-256 before loading;
- the backend refuses to start if a hash mismatch is found.

Each model folder contains:

```text
model_leakage_safe.pkl
model_leakage_safe.pkl.sha256
model_meta.json
model_meta.json.sha256
feature_columns.json
feature_columns.json.sha256
```

## 9. Runtime database handling

The SQLite database is treated as a runtime cache.

It is not committed:

```text
backend-ai/ai_scores.db
```

The backend can recreate the schema at startup.

This prevents leaking local findings or user data into Git.

## 10. Notification fixes

Dashboard notifications now include:

- pending user registrations;
- completed DefectDojo sync events;
- Review First findings;
- live fallback for pending users.

This improves admin visibility and makes the user approval workflow easier to operate.

## Remaining security notes

For a production deployment, the following would still be recommended:

- use a real OAuth2/OIDC or session-based authentication layer;
- store sessions with expiry and revocation;
- use HTTPS;
- move SQLite to PostgreSQL;
- rotate tokens regularly;
- use a dedicated secrets manager;
- add automated security tests.
