# AI v4 Model vs CVSS — Benchmark Summary

This benchmark summarizes the final VulnPriority single v4 model against a CVSS-only baseline.

## Model

| Item | Value |
|---|---|
| Model | XGBoost stacked ensemble (v4) |
| Rows used | 7,114 |
| Positive rate | 16.4% |
| Split | group |
| Features | 51 |
| Default threshold | 0.386 |
| Text features | True |
| Sample weights | True |

## Default operating point

| Metric | Value |
|---|---:|
| Accuracy | 0.8946 |
| Precision | 0.7098 |
| Recall | 0.5957 |
| F1 | 0.6478 |
| F1-macro | 0.7929 |
| MCC | 0.5895 |
| Balanced accuracy | 0.7742 |
| ROC-AUC | 0.9056 |
| AUC-PR | 0.7387 |

Confusion matrix: TN=1128, FP=56, FN=93, TP=137.

## Comparison table

| Model | Precision | Recall | F1 | F1-macro | ROC-AUC | AUC-PR |
|---|---:|---:|---:|---:|---:|---:|
| OLD (fixed params, target-precision thr) | 0.7076 | 0.5261 | 0.6035 | 0.7690 | 0.9022 | 0.7354 |
| NEW (stacked: XGB+RF+LogReg) | 0.7098 | 0.5957 | 0.6478 | 0.7929 | 0.9056 | 0.7387 |
| Random Forest | 0.4725 | 0.7478 | 0.5791 | 0.7336 | 0.9037 | 0.7255 |
| Logistic Regression | 0.4396 | 0.7913 | 0.5652 | 0.7185 | 0.8859 | 0.7158 |
| CVSS baseline (cvss>=9.0) | 0.4049 | 0.4348 | 0.4193 | 0.6507 | 0.7847 |  |

## CVSS threshold details

| CVSS rule | Precision | Recall | F1 | F1-macro |
|---|---:|---:|---:|---:|
| CVSS >= 7.0 | 0.2194 | 0.6478 | 0.3278 | 0.5047 |
| CVSS >= 8.0 | 0.3182 | 0.5174 | 0.3940 | 0.6147 |
| CVSS >= 9.0 | 0.4049 | 0.4348 | 0.4193 | 0.6507 |

## Interpretation

The single v4 AI model provides a stronger prioritization signal than CVSS alone. It improves F1 from 0.4193 to 0.6478 and ROC-AUC from 0.7847 to 0.9056.

The AI model should be used to order the review queue and highlight findings that need analyst attention first. CVSS and scanner severity remain visible in the dashboard as supporting evidence.
