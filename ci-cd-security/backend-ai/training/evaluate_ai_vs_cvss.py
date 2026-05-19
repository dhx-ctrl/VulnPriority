#!/usr/bin/env python3
"""
evaluate_ai_vs_cvss.py

Generate AI-vs-CVSS benchmark artifacts for VulnPriority.

This script reads the held-out ranking comparison saved in the operational
ranker's model_meta.json and writes reproducible benchmark files to:

    backend-ai/benchmark_results/
      - ai_vs_cvss_metrics.json
      - ai_vs_cvss_summary.md

Important:
This benchmark is for the operational EPSS ranker, not the clean leakage-safe
model. Do not describe the operational ranker as fully leakage-safe.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")

    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def pct_reduction(ai_needed: float, cvss_needed: float) -> float:
    if not cvss_needed:
        return 0.0
    return ((cvss_needed - ai_needed) / cvss_needed) * 100.0


def build_summary(metrics: Dict[str, Any]) -> str:
    rank = metrics["ranking_comparison_test"]
    reduction = metrics["interpretation"]["workload_reduction_for_80pct_coverage_pct"]

    return f"""# AI vs CVSS Benchmark Summary

## Purpose

This file documents the comparison between VulnPriority's operational AI ranker and a CVSS-only prioritization baseline.

The benchmark answers this question:

> Does the AI ranking reduce the number of findings an analyst needs to review to cover the same share of EPSS-positive vulnerabilities?

## Compared methods

| Method | Sorting logic |
|---|---|
| CVSS baseline | `cvss_score DESC` |
| AI operational ranker | `operational_rank_score DESC` |

## Main result

| Metric | AI operational ranker | CVSS baseline |
|---|---:|---:|
| AUCPR | {rank.get("ai_aucpr", 0):.4f} | {rank.get("cvss_aucpr", 0):.4f} |
| ROC-AUC | {rank.get("ai_roc_auc", 0):.4f} | {rank.get("cvss_roc_auc", 0):.4f} |
| NDCG | {rank.get("ai_ndcg", 0):.4f} | {rank.get("cvss_ndcg", 0):.4f} |
| Findings needed for 80% coverage | {rank.get("ai_needed_for_80pct", 0)} | {rank.get("cvss_needed_for_80pct", 0)} |

## Workload reduction

```text
AI needed:   {rank.get("ai_needed_for_80pct", 0)}
CVSS needed: {rank.get("cvss_needed_for_80pct", 0)}
Reduction:   {reduction:.1f}%
```

The operational AI ranker reduced the review queue required to cover 80% of EPSS-positive cases by approximately **{reduction:.1f}%** compared with CVSS-only sorting.

## Precision and recall at K

| K | AI Precision@K | CVSS Precision@K | AI Recall@K | CVSS Recall@K |
|---:|---:|---:|---:|---:|
| 10 | {rank.get("ai_precision_at_10", 0):.2f} | {rank.get("cvss_precision_at_10", 0):.2f} | {rank.get("ai_recall_at_10", 0):.4f} | {rank.get("cvss_recall_at_10", 0):.4f} |
| 20 | {rank.get("ai_precision_at_20", 0):.2f} | {rank.get("cvss_precision_at_20", 0):.2f} | {rank.get("ai_recall_at_20", 0):.4f} | {rank.get("cvss_recall_at_20", 0):.4f} |
| 50 | {rank.get("ai_precision_at_50", 0):.2f} | {rank.get("cvss_precision_at_50", 0):.2f} | {rank.get("ai_recall_at_50", 0):.4f} | {rank.get("cvss_recall_at_50", 0):.4f} |
| 100 | {rank.get("ai_precision_at_100", 0):.2f} | {rank.get("cvss_precision_at_100", 0):.2f} | {rank.get("ai_recall_at_100", 0):.4f} | {rank.get("cvss_recall_at_100", 0):.4f} |

## Important limitation

This benchmark evaluates the **operational EPSS ranker**, not the clean leakage-safe model.

Correct wording:

> The operational ranker improves over CVSS-only prioritization by combining CVSS with additional vulnerability and package metadata.

Do not claim that the operational ranker is fully leakage-safe.
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--meta",
        default="model_output_EPSS_operational_ranker/model_meta.json",
        help="Path to the operational ranker's model_meta.json",
    )
    parser.add_argument(
        "--out-dir",
        default="benchmark_results",
        help="Directory where benchmark files will be written",
    )
    args = parser.parse_args()

    meta_path = Path(args.meta)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    meta = load_json(meta_path)

    if "ranking_comparison_test" not in meta:
        raise KeyError(
            "model_meta.json does not contain ranking_comparison_test. "
            "Run the operational ranker training/evaluation first."
        )

    rank = meta["ranking_comparison_test"]
    test_metrics = meta.get("test_metrics", {})

    ai_needed = rank.get("ai_needed_for_80pct", 0)
    cvss_needed = rank.get("cvss_needed_for_80pct", 0)
    reduction = pct_reduction(ai_needed, cvss_needed)

    metrics = {
        "benchmark_name": "AI operational ranker vs CVSS baseline",
        "source": str(meta_path),
        "evaluation_split": "held-out test set",
        "label_definition": "EPSS-positive operational label used during ranker evaluation",
        "model": {
            "name": "EPSS operational ranker",
            "version": meta.get("model_version", meta.get("model_name", "epss-operational-ranker-v1")),
            "primary_dashboard_field": "operational_rank_score / Rank /100",
            "threshold": test_metrics.get("threshold"),
            "purpose": "dashboard queue ordering and operational vulnerability prioritization",
        },
        "test_metrics": test_metrics,
        "ranking_comparison_test": rank,
        "interpretation": {
            "workload_reduction_for_80pct_coverage_pct": reduction,
            "summary": (
                f"On the held-out test set, the AI operational ranker needed "
                f"{ai_needed} reviewed findings to cover 80% of EPSS-positive cases, "
                f"compared with {cvss_needed} findings for CVSS-only ordering."
            ),
            "important_limitation": (
                "This benchmark evaluates the operational ranker, not the clean leakage-safe model. "
                "The operational ranker is a practical queue-sorting model and should not be described "
                "as fully leakage-safe."
            ),
        },
    }

    metrics_path = out_dir / "ai_vs_cvss_metrics.json"
    summary_path = out_dir / "ai_vs_cvss_summary.md"

    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    summary_path.write_text(build_summary(metrics), encoding="utf-8")

    print(f"Wrote {metrics_path}")
    print(f"Wrote {summary_path}")
    print(f"AI needed for 80% coverage:   {ai_needed}")
    print(f"CVSS needed for 80% coverage: {cvss_needed}")
    print(f"Workload reduction:           {reduction:.1f}%")


if __name__ == "__main__":
    main()
