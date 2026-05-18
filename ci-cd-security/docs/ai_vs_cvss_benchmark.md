# AI vs CVSS benchmark

This document explains how VulnPriority evaluates AI prioritization against CVSS-only ranking.

## Why this benchmark matters

The project objective is not only to assign AI scores. The important question is:

```text
Does AI help analysts review fewer findings while still covering the important ones?
```

A simple CVSS-only workflow sorts findings by CVSS severity or CVSS score.

VulnPriority compares that baseline against the operational EPSS ranker.

## Compared rankings

Two ranking strategies are compared:

### 1. CVSS baseline

Findings are sorted by:

```text
cvss_score DESC
```

This represents the traditional severity-first workflow.

### 2. AI operational ranker

Findings are sorted by:

```text
operational_rank_score DESC
```

This represents the VulnPriority workflow.

## Label used for evaluation

The operational benchmark uses an EPSS-based label, such as:

```text
EPSS >= 0.05
```

This means the evaluation checks how well each ranking strategy brings EPSS-positive findings toward the top of the queue.

## Metrics

Recommended metrics:

| Metric | Purpose |
|---|---|
| AUCPR | Measures ranking quality under class imbalance |
| ROC-AUC | Measures separation between positive and negative cases |
| NDCG | Measures quality of ordering near the top of the queue |
| Precision@10 / @50 / @100 | Measures how many top findings are relevant |
| Recall@10 / @50 / @100 | Measures how much of the relevant set is captured early |
| Findings needed for 80% coverage | Operational workload metric |

## Current benchmark result

The held-out benchmark showed that the operational AI ranker performed better than CVSS-only ranking.

Observed comparison:

| Metric | AI ranker | CVSS baseline |
|---|---:|---:|
| AUCPR | 0.2646 | 0.1176 |
| ROC-AUC | 0.8270 | 0.6177 |
| NDCG | 0.7124 | 0.6064 |
| Findings needed for 80% coverage | 389 | 733 |

The operational result means that the AI ranking required fewer findings to be reviewed to reach the same 80% coverage of EPSS-positive cases.

Workload reduction:

```text
(733 - 389) / 733 = 46.9%
```

So the dashboard can claim:

> In the held-out benchmark, the operational AI ranker reduced the review queue required to cover 80% of EPSS-positive findings by approximately 46.9% compared with CVSS-only sorting.

## Important limitation

This does not mean the operational model is leakage-safe.

The operational ranker uses CVSS and vulnerability metadata as input features.

The fair interpretation is:

> The operational ranker improves over CVSS alone by combining CVSS with additional vulnerability and package metadata.

The clean leakage-safe model is documented separately and is used as the anti-leakage scientific signal.

## How to reproduce

Recommended repository files:

```text
backend-ai/training/
├── 08_train_epss_operational_ranker.py
└── evaluate_ai_vs_cvss.py

backend-ai/benchmark_results/
├── ai_vs_cvss_metrics.json
├── ai_vs_cvss_summary.md
└── plots/
```

Suggested evaluation steps:

1. Load the held-out test set.
2. Generate operational AI scores.
3. Sort the same rows by CVSS score.
4. Sort the same rows by AI rank score.
5. Compute AUCPR, ROC-AUC, NDCG, Precision@K, Recall@K.
6. Compute how many findings must be reviewed to cover 80% of EPSS-positive findings.
7. Save metrics and plots in `benchmark_results/`.

## Report wording

Use this wording in the final report:

> The AI component was evaluated against a CVSS-only baseline using ranking metrics. The operational EPSS ranker achieved higher AUCPR, ROC-AUC, and NDCG than CVSS-only sorting. Most importantly, it required 389 reviewed findings to cover 80% of EPSS-positive cases, compared with 733 findings for CVSS-only sorting. This corresponds to an approximate 46.9% reduction in review workload. The result is presented as an operational prioritization gain, not as a claim that the ranker is leakage-safe.
