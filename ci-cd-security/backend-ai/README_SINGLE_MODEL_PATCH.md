# VulnPriority single-model backend patch

This patch replaces the old dual-model backend logic with one v4 stacked AI model.

## Main changes

- `services/scoring.py` now loads one model from `model_output_SINGLE_v4/`.
- `routers/scoring.py` uses `run_model()` instead of `run_dual_models()`.
- `routers/defectdojo_sync.py` scores DefectDojo findings with the single model.
- `routers/meta.py` reports one model in `/api/health/`.
- The old `clean_*` and `operational_*` fields are still filled as aliases so the current frontend and SQLite schema do not crash during migration.
- `model_output_SINGLE_v4/` includes:
  - `model_leakage_safe.pkl`
  - `model_meta.json`
  - `feature_columns.json`
  - SHA-256 files for the main artifacts
  - comparison / SHAP / threshold CSVs for documentation

## Environment

Add or update:

```env
AI_MODEL_DIR=model_output_SINGLE_v4
AI_MODEL_FILE=model_leakage_safe.pkl
```

The default already points to `model_output_SINGLE_v4`, so these are optional unless you rename the folder/file.
