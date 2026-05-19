# AI vs CVSS Benchmark Summary

## Purpose

This benchmark compares two vulnerability prioritization strategies:

1. **CVSS-only prioritization**, where findings are sorted by CVSS score.
2. **VulnPriority AI prioritization**, where findings are sorted by the operational AI rank score.

The goal is to evaluate whether the AI ranking helps reduce the number of findings that need to be reviewed while still covering the most relevant vulnerabilities.

## Compared Methods

| Method | Sorting Logic |
|---|---|
| CVSS baseline | cvss_score DESC |
| AI operational ranker | operational_rank_score DESC |

## Main Results

| Metric | AI Operational Ranker | CVSS Baseline |
|---|---:|---:|
| AUCPR | 0.2802 | 0.1176 |
| ROC-AUC | 0.8243 | 0.6177 |
| NDCG | 0.7533 | 0.6064 |
| Findings needed for 80% coverage | 431 | 733 |

## Review Workload Reduction

To cover 80% of EPSS-positive findings:

| Method | Findings Needed |
|---|---:|
| AI operational ranker | 431 |
| CVSS baseline | 733 |

The reduction in review workload is:

**(733 - 431) / 733 = 41.2%**

This means that, on the held-out test set, the AI operational ranker reduced the number of findings required to reach 80% coverage by approximately **41.2%** compared with CVSS-only sorting.

## Precision and Recall at K

| K | AI Precision@K | CVSS Precision@K | AI Recall@K | CVSS Recall@K |
|---:|---:|---:|---:|---:|
| 10 | 0.40 | 0.10 | 0.0471 | 0.0118 |
| 20 | 0.30 | 0.15 | 0.0706 | 0.0353 |
| 50 | 0.32 | 0.16 | 0.1882 | 0.0941 |
| 100 | 0.34 | 0.16 | 0.4000 | 0.1882 |

## Interpretation

The AI operational ranker performs better than the CVSS baseline across the tested ranking metrics.

The most relevant operational result is the review workload reduction: the AI ranker required **431 reviewed findings** to reach 80% coverage, while CVSS-only sorting required **733 reviewed findings**.

This indicates that the AI score is useful as a prioritization layer on top of scanner and CVSS results.

## Important Note

This benchmark evaluates the **operational EPSS ranker** used for dashboard ordering.

It should be interpreted as a practical prioritization model, not as the leakage-safe model. The clean leakage-safe model is used separately as a stricter confidence signal in the dashboard.
