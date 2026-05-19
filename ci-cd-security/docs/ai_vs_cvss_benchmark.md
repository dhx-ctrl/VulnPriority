# AI vs CVSS Benchmark

## Purpose

This document explains how VulnPriority evaluates AI-based vulnerability prioritization against a CVSS-only baseline.

The objective is to measure whether the AI ranking helps an analyst reach the most relevant findings earlier than a traditional CVSS-based ordering.

## Compared Ranking Strategies

| Strategy | Sorting Logic |
|---|---|
| CVSS baseline | Findings are sorted by CVSS score in descending order |
| AI operational ranker | Findings are sorted by operational AI rank score in descending order |

## Current Model

The current operational model is a leakage-hardened EPSS ranker.

| Field | Value |
|---|---|
| Model | Current operational EPSS ranker |
| Label mode | EPSS-only |
| EPSS threshold for label | 0.10 |
| Train/test split | Temporal |
| Feature count | 30 |

The current operational ranker removes raw package identity, raw CVSS vector strings, and package scope strings. It also uses a temporal split, CWE-family bucketing, a label-shuffle sanity check, and permutation-importance reporting.

## Main Benchmark Results

| Metric | AI Operational Ranker | CVSS Baseline |
|---|---:|---:|
| AUCPR | 0.0582 | 0.0158 |
| ROC-AUC | 0.7640 | 0.5740 |
| NDCG | 0.3510 | 0.2715 |
| Findings needed for 80% coverage | 441 | 1053 |

The most important operational metric is the number of findings needed to cover 80% of EPSS-positive cases.

The AI ranker needed 441 reviewed findings.

The CVSS baseline needed 1053 reviewed findings.

This corresponds to:

(1053 - 441) / 1053 = 58.1%

So, in this benchmark, the AI operational ranker reduces the review workload by approximately 58.1% compared with CVSS-only ordering.

## Precision and Recall at K

| K | AI Precision@K | CVSS Precision@K | AI Recall@K | CVSS Recall@K |
|---:|---:|---:|---:|---:|
| 10 | 0.10 | 0.00 | 0.125 | 0.000 |
| 20 | 0.10 | 0.00 | 0.250 | 0.000 |
| 50 | 0.04 | 0.02 | 0.250 | 0.125 |
| 100 | 0.03 | 0.03 | 0.375 | 0.375 |

## Binary Classification Note

The operational ranker has a conservative selected threshold of 0.8905.

At this threshold, the temporal test split produced no positive binary predictions, so the threshold-based precision, recall, and F1 are 0.0. This does not invalidate the ranking comparison, because the dashboard uses the continuous operational rank score for queue ordering.

Therefore, the correct interpretation is:

The operational ranker is useful as a ranking and prioritization model.

It should not be presented as a strict binary yes/no classifier.

## Correct Report Wording

Use this wording:

The updated operational EPSS ranker was evaluated against a CVSS-only baseline using ranking metrics. On the temporal held-out test split, the AI ranker required 441 reviewed findings to cover 80% of EPSS-positive cases, compared with 1053 findings for CVSS-only ordering. This corresponds to an approximate 58.1% reduction in review workload. The result is presented as an operational prioritization gain, not as a claim that the model is a strict binary classifier.

## Important Distinction

The project uses two separate models:

| Model | Role |
|---|---|
| Clean leakage-safe model | Strict confidence signal |
| Operational EPSS ranker | Practical dashboard queue-ordering model |

The operational ranker is leakage-hardened, but it is still not the same as the clean leakage-safe model. It should be described as the practical ranking model used for prioritization.