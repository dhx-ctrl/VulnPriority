# AI vs CVSS Benchmark Summary

## Purpose

This benchmark compares two vulnerability prioritization strategies:

1. CVSS-only prioritization, where findings are sorted by CVSS score.
2. VulnPriority AI prioritization, where findings are sorted by the operational AI rank score.

The goal is to evaluate whether the AI ranking helps reduce the number of findings that need to be reviewed while still covering the most relevant vulnerabilities.

## Model Evaluated

The benchmark uses the current leakage-hardened operational EPSS ranker.

| Field | Value |
|---|---|
| Model | Current operational EPSS ranker |
| Label mode | EPSS-only |
| EPSS threshold for label | 0.10 |
| Split type | Temporal train/test split |
| Features used | 30 |
| Dashboard field | Rank /100 |

## Leakage-Hardening Changes

The updated operational ranker was hardened against memorisation by removing high-cardinality or near-unique features.

| Removed feature | Reason |
|---|---|
| package_name | Could memorise per-package EPSS base rates |
| cvss_vector | Redundant with parsed CVSS subcomponents and near-unique |
| feat_package_scope | Could memorise ecosystem-level patterns |

The model also uses a temporal split, label-shuffle sanity check, CWE-family bucketing, and permutation-importance export.

## Compared Methods

| Method | Sorting Logic |
|---|---|
| CVSS baseline | cvss_score DESC |
| AI operational ranker | operational_rank_score DESC |

## Main Ranking Results

| Metric | AI Operational Ranker | CVSS Baseline |
|---|---:|---:|
| AUCPR | 0.0582 | 0.0158 |
| ROC-AUC | 0.7640 | 0.5740 |
| NDCG | 0.3510 | 0.2715 |
| Findings needed for 80% coverage | 441 | 1053 |

## Review Workload Reduction

To cover 80% of EPSS-positive findings:

| Method | Findings Needed |
|---|---:|
| AI operational ranker | 441 |
| CVSS baseline | 1053 |

The reduction in review workload is:

(1053 - 441) / 1053 = 58.1%

This means that, on the held-out temporal test set, the AI operational ranker reduced the number of findings required to reach 80% coverage by approximately 58.1% compared with CVSS-only sorting.

## Precision and Recall at K

| K | AI Precision@K | CVSS Precision@K | AI Recall@K | CVSS Recall@K |
|---:|---:|---:|---:|---:|
| 10 | 0.10 | 0.00 | 0.125 | 0.000 |
| 20 | 0.10 | 0.00 | 0.250 | 0.000 |
| 50 | 0.04 | 0.02 | 0.250 | 0.125 |
| 100 | 0.03 | 0.03 | 0.375 | 0.375 |

## Classification Threshold Note

The selected operating threshold is conservative.

| Metric | Value |
|---|---:|
| Threshold | 0.8905 |
| Test precision | 0.0000 |
| Test recall | 0.0000 |
| Test F1 | 0.0000 |
| Test ROC-AUC | 0.7640 |
| Test AUCPR | 0.0582 |

At this threshold, no positive finding crossed the binary high-risk decision boundary on the temporal test split. Therefore, this model should be interpreted primarily as a ranking model for queue ordering, not as a strict yes/no classifier.

## Interpretation

The operational ranker performs better than the CVSS baseline as a ranking model. It reaches 80% coverage of EPSS-positive cases after reviewing 441 findings, while CVSS-only ordering requires 1053 findings.

This supports the use of the AI score as a prioritization layer on top of scanner and CVSS results.

## Important Note

This benchmark evaluates the operational EPSS ranker used for dashboard ordering.

It should be interpreted as a practical prioritization model, not as the clean leakage-safe model. The clean leakage-safe model is used separately as a stricter confidence signal in the dashboard.