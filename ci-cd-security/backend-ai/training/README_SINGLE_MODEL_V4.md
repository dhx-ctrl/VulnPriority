# Training Scripts — Single v4 Model

This folder contains the final training utilities for the VulnPriority single v4 AI risk model.

## Main script

```text
03_train_leakage_safe_xgb.py
```

This script trains the final leakage-safe stacked model. It supports:

- grouped train/test split,
- grouped cross-validation,
- Optuna tuning,
- early stopping,
- sample weights,
- optional OSV text fetching,
- CWE tier features,
- SHAP artifacts,
- comparison against CVSS baselines.

Recommended run:

```powershell
python .\03_train_leakage_safe_xgb.py `
  --input .\merged_trainable.csv `
  --out-dir .\model_output_SINGLE_v4 `
  --fetch-text `
  --tune `
  --n-trials 60 `
  --cv-folds 4 `
  --threshold-strategy f1 `
  --fbeta 2.0 `
  --stack `
  --compare-models
```

## Active production model

The backend uses:

```text
backend-ai/model_output_SINGLE_v4/
```

The active model metadata reports:

- model type: XGBoost stacked ensemble (v4),
- threshold: 0.386,
- precision: 0.7098,
- recall: 0.5957,
- F1: 0.6478,
- ROC-AUC: 0.9056,
- AUC-PR: 0.7387.

## Obsolete scripts

Older experimental scripts that trained separate queue/ranking models should be removed from the final repository to avoid confusing the project architecture. The final report and dashboard describe one active v4 AI risk model.
