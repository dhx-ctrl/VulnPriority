# VulnPriority single v4 documentation patch

This patch updates the documentation and benchmark text so it matches the final single v4 AI model architecture.

## Files updated

```text
ci-cd-security/docs/architecture.md
ci-cd-security/docs/model_explanation.md
ci-cd-security/docs/ai_vs_cvss_benchmark.md
ci-cd-security/docs/assets/shap_summary_beeswarm.png
ci-cd-security/backend-ai/benchmark_results/ai_vs_cvss_summary.md
ci-cd-security/backend-ai/training/03_train_leakage_safe_xgb.py
ci-cd-security/backend-ai/training/osv_text_fetcher.py
ci-cd-security/backend-ai/training/README_SINGLE_MODEL_V4.md
```

## Apply from repo root

```powershell
cd "C:\Users\user\Desktop\VulnPriority"

Expand-Archive -Force "$env:USERPROFILE\Downloads\vulnpriority_docs_single_v4_patch.zip" "$env:TEMP\vulnpriority_docs_single_v4_patch"

Copy-Item -Recurse -Force "$env:TEMP\vulnpriority_docs_single_v4_patch\ci-cd-security\*" ".\ci-cd-security\"
```

## Remove obsolete training files

Remove the old experimental training/evaluation scripts that no longer match the final single-model architecture:

```powershell
git rm ci-cd-security/backend-ai/training/03_train_epss_operational_ranker.py
git rm ci-cd-security/backend-ai/training/evaluate_ai_vs_cvss.py
```

## Commit

```powershell
git add ci-cd-security/docs `
        ci-cd-security/backend-ai/benchmark_results/ai_vs_cvss_summary.md `
        ci-cd-security/backend-ai/training/03_train_leakage_safe_xgb.py `
        ci-cd-security/backend-ai/training/osv_text_fetcher.py `
        ci-cd-security/backend-ai/training/README_SINGLE_MODEL_V4.md `
        ci-cd-security/README_DOCS_SINGLE_V4_PATCH.md

git commit -m "Update documentation for single v4 AI model"
git push
```
