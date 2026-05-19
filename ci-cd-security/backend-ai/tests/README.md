# Backend smoke tests

These are minimal backend tests for VulnPriority.

They check:

- health endpoint
- admin login
- wrong password rejection
- pending user registration
- dual-model scoring response

Run from `ci-cd-security/backend-ai`:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q tests
```
