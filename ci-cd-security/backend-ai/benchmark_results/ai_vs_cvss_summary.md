# AI vs CVSS Benchmark Summary

## Purpose

This file closes the audit point about the missing AI-vs-CVSS comparison.

The goal is to show whether the operational AI ranking model improves the vulnerability review queue compared with sorting findings by CVSS alone.

The audit explicitly asked for a comparison between AI scores and CVSS, including precision, recall, ranking quality, and the practical gain in vulnerability management.

## Compared methods

| Method | Sorting logic | Meaning |
|---|---|---|
| CVSS baseline | `cvss_score DESC` | Traditional severity-first prioritization |
| AI operational ranker | `operational_rank_score DESC` | VulnPriority queue ordering |

## Evaluation target

The benchmark uses the held-out test split saved during the operational ranker evaluation.

The operational ranker is evaluated against an EPSS-positive target. In other words, the benchmark asks:

> Which sorting method brings likely exploited vulnerabilities closer to the top of the review queue?

## Main result

| Metric | AI operational ranker | CVSS baseline |
|---|---:|---:|
| AUCPR | 0.2802 | 0.1176 |
| ROC-AUC | 0.8243 | 0.6177 |
| NDCG | 0.7533 | 0.6064 |
| Findings needed for 80% coverage | 431 | 733 |

## Workload reduction

The operational AI ranker needed 431 reviewed findings to cover 80% of EPSS-positive cases.

The CVSS-only baseline needed 733 reviewed findings for the same coverage.

```text
reduction = (733 - 431) / 733
reduction = 41.2%
```

So the operational result is:

> The AI operational ranker reduced the review queue needed for 80% EPSS-positive coverage by approximately 41.2% compared with CVSS-only sorting.

## Precision and recall at K

| K | AI Precision@K | CVSS Precision@K | AI Recall@K | CVSS Recall@K |
|---:|---:|---:|---:|---:|
| 10 | 0.40 | 0.10 | 0.0471 | 0.0118 |
| 20 | 0.30 | 0.15 | 0.0706 | 0.0353 |
| 50 | 0.32 | 0.16 | 0.1882 | 0.0941 |
| 100 | 0.34 | 0.16 | 0.4000 | 0.1882 |

This means the top of the AI-ranked queue contains more EPSS-positive findings than the CVSS-ranked queue.

## Important limitation

This benchmark is for the **operational EPSS ranker**.

It should not be described as the clean leakage-safe model.

Correct wording:

> The operational ranker improves over CVSS-only prioritization by combining CVSS with additional vulnerability and package metadata.

Avoid saying:

> The operational ranker is fully leakage-safe.

The clean leakage-safe model is a separate model and is used as a stricter scientific confidence signal in the dashboard.

## Files

This benchmark is documented by:

```text
backend-ai/benchmark_results/ai_vs_cvss_metrics.json
backend-ai/benchmark_results/ai_vs_cvss_summary.md
backend-ai/training/evaluate_ai_vs_cvss.py
```
