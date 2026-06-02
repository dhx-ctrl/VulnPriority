# VulnPriority backend refactor

This refactor splits the original 3100+ line `main.py` into a FastAPI router/service/database structure.

## New structure

```text
main.py
core/
  config.py
  security.py
database/
  crud.py
services/
  scoring.py
  defectdojo.py
routers/
  auth.py
  scoring.py
  defectdojo_sync.py
  meta.py
schemas.py
```

## What stayed the same

- Same endpoint paths, e.g. `/api/login/`, `/api/sync-defectdojo/`, `/api/scores/`
- Same SQLite database name and schema migration logic
- Same model-loading behavior and `.env` variables
- Same DefectDojo sync behavior

## Run

From `ci-cd-security/backend-ai`:

```powershell
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
