#!/usr/bin/env python3
"""
Train an EPSS-only operational ranking model — v2 (leakage-hardened).

Changes from v1
----------------
1.  Dropped `package_name` as a direct feature (high-cardinality one-hot
    memorises per-package EPSS base-rates).  Derived features
    `feat_package_len` and `feat_is_scoped_package` are kept (low-cardinality,
    legitimate signal).
2.  Dropped `cvss_vector` raw string (redundant with parsed sub-components,
    near-unique categories → memorisation).
3.  Dropped `feat_package_scope` (npm scope strings memorise ecosystem-level
    EPSS patterns).
4.  `feat_cwe_family` bucketed to top-N families + "OTHER" to reduce
    memorisation via rare CWE IDs.
5.  Added `--temporal-split` flag: train on older CVEs, test on newer ones
    (simulates real deployment).
6.  Added label-shuffle sanity check: trains once on randomised labels and
    reports AUC.  If AUC >> 0.5 the feature set still memorises.
7.  Added permutation-importance dump so you can see what the model actually
    relies on.

Allowed features
-----------------
CVSS score + CVSS subcomponents are allowed because CVSS is NOT used to build
the EPSS label.

Target
------
y = 1  if  epss_score >= threshold
y = 0  otherwise

Run
---
python 08_train_epss_operational_ranker_v2.py ^
  --input ".\\dataset_merged\\merged_trainable.csv" ^
  --out-dir ".\\model_output_EPSS_operational_ranker_v2" ^
  --epss-threshold 0.10 ^
  --target-precision 0.70

# Add --temporal-split to use time-based train/test instead of group-random
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    ndcg_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier


# ── Direct target-leakage / memorisation columns ────────────────────────────
DROP_ALWAYS = {
    # Labels / outputs
    "label_high_risk", "high_risk_label", "target", "label", "y",
    "label_source", "label_from_epss", "label_from_cvss", "label_from_severity",
    "risk_score", "ai_risk_score", "priority_score", "exploit_probability",
    "prediction", "predicted_label", "optimal_threshold", "threshold",

    # EPSS target signal — NEVER as feature for EPSS-only model
    "epss", "epss_score", "epss_percentile", "percentile",

    # Raw IDs / advisory IDs that can memorise vulnerabilities
    "id", "osv_id", "cve_id", "ghsa_id", "advisory_id", "aliases", "alias",
    "cve", "ghsa", "all_cve_ids", "all_ghsa_ids", "vulnerability_id",

    # Exploit/KEV shortcuts
    "has_exploit_ref", "feat_has_exploit_ref", "known_exploited", "is_kev", "in_kev",
    "kev_listed", "public_exploit", "has_public_exploit", "exploit_maturity",

    # Source metadata bias
    "source_dataset", "data_source", "source_database", "source",

    # ── NEW in v2: high-cardinality memorisation risks ──
    "package_name",        # per-package EPSS base-rate memorisation
    "cvss_vector",         # redundant with parsed sub-components, near-unique
    "feat_package_scope",  # npm scope memorises ecosystem patterns
}

# ── Feature allow-list (backend-compatible) ─────────────────────────────────
# REMOVED from v1: package_name, cvss_vector, feat_package_scope
CANDIDATE_FEATURES = [
    # CVSS (legitimate — independent of EPSS label)
    "cvss_score",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",

    # Advisory metadata (low-cardinality, legitimate)
    "ranges_count",
    "versions_count",
    "summary_len",
    "details_len",
    "references_count",
    "github_reviewed",
    "has_patch_ref",
    "has_advisory_ref",
    "has_cve",
    "scanner_type",
    "is_static",
    "is_dynamic",

    # Engineered (low-cardinality, legitimate)
    "feat_has_cve",
    "feat_has_ghsa",
    "feat_cwe_family",      # bucketed to top-N + OTHER in v2
    "feat_has_cwe",
    "feat_published_year",
    "feat_days_since_published",
    "feat_modified_year",
    "feat_days_since_modified",
    "feat_withdrawn_year",
    "feat_days_since_withdrawn",
    "feat_package_len",
    "feat_is_scoped_package",
]

CVSS_VECTOR_RE = re.compile(r"CVSS:\d\.\d/[^\s]+", re.I)

# How many distinct CWE families to keep before bucketing to "OTHER"
CWE_FAMILY_TOP_N = 30


# ── Helpers ─────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="Path to merged_trainable.csv")
    p.add_argument("--out-dir", required=True, help="Output model folder")
    p.add_argument("--epss-threshold", type=float, default=0.10)
    p.add_argument("--target-precision", type=float, default=0.70)
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument("--temporal-split", action="store_true",
                   help="Use time-based train/test split instead of group-random")
    p.add_argument("--skip-shuffle-test", action="store_true",
                   help="Skip the label-shuffle sanity check (saves time)")
    return p.parse_args()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sha256(path: Path) -> None:
    path.with_name(path.name + ".sha256").write_text(sha256_file(path) + "\n", encoding="utf-8")


def clean_missing(x: Any) -> Any:
    if pd.isna(x):
        return np.nan
    s = str(x).strip()
    if s == "" or s.lower() in {"nan", "none", "null"}:
        return np.nan
    return s


def first_existing(df: pd.DataFrame, names: List[str]) -> str | None:
    lower = {c.lower(): c for c in df.columns}
    for n in names:
        if n in df.columns:
            return n
        if n.lower() in lower:
            return lower[n.lower()]
    return None


def normalize_cve(value: Any) -> Any:
    if pd.isna(value):
        return np.nan
    m = re.search(r"CVE-\d{4}-\d{4,}", str(value).upper())
    return m.group(0) if m else np.nan


def make_groups(df: pd.DataFrame) -> pd.Series:
    group = pd.Series(np.nan, index=df.index, dtype=object)
    for col in ["cve_id", "ghsa_id", "osv_id", "advisory_id", "id"]:
        if col in df.columns:
            vals = df[col].apply(clean_missing)
            group = group.where(group.notna(), vals)

    # Fallback: row-level unique (no package-based grouping to avoid leaking
    # package identity into group structure)
    fallback = pd.Series([f"row_{i}" for i in range(len(df))], index=df.index)
    return group.where(group.notna(), fallback).astype(str)


# ── CVSS vector parsing ────────────────────────────────────────────────────

def parse_cvss_vector_to_components(vector: Any) -> Dict[str, str]:
    if pd.isna(vector) or not str(vector).strip():
        return {}
    text = str(vector).strip()
    m = CVSS_VECTOR_RE.search(text)
    if m:
        text = m.group(0)

    maps = {
        "AV": {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"},
        "AC": {"L": "LOW", "H": "HIGH"},
        "PR": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "UI": {"N": "NONE", "R": "REQUIRED"},
        "S": {"U": "UNCHANGED", "C": "CHANGED"},
        "C": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "I": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "A": {"N": "NONE", "L": "LOW", "H": "HIGH"},
    }
    out = {}
    try:
        parts = {}
        for seg in text.split("/"):
            if ":" in seg:
                k, v = seg.split(":", 1)
                parts[k.upper()] = v.upper()
        out = {
            "attack_vector": maps["AV"].get(parts.get("AV"), np.nan),
            "attack_complexity": maps["AC"].get(parts.get("AC"), np.nan),
            "privileges_required": maps["PR"].get(parts.get("PR"), np.nan),
            "user_interaction": maps["UI"].get(parts.get("UI"), np.nan),
            "scope": maps["S"].get(parts.get("S"), np.nan),
            "confidentiality_impact": maps["C"].get(parts.get("C"), np.nan),
            "integrity_impact": maps["I"].get(parts.get("I"), np.nan),
            "availability_impact": maps["A"].get(parts.get("A"), np.nan),
        }
    except Exception:
        return {}
    return out


def normalize_cvss_components(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    vector_col = "cvss_vector" if "cvss_vector" in df.columns else None
    if vector_col:
        parsed_rows = df[vector_col].apply(parse_cvss_vector_to_components)
        for col in [
            "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope",
            "confidentiality_impact", "integrity_impact", "availability_impact",
        ]:
            if col not in df.columns:
                df[col] = np.nan
            recovered = parsed_rows.apply(lambda d: d.get(col, np.nan) if isinstance(d, dict) else np.nan)
            df[col] = df[col].where(df[col].notna(), recovered)
    return df


# ── Feature engineering ─────────────────────────────────────────────────────

def add_backend_compatible_engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    if "package_name" not in df.columns:
        df["package_name"] = "UNKNOWN_PACKAGE"
    df["package_name"] = df["package_name"].fillna("UNKNOWN_PACKAGE").astype(str)

    # CVE / GHSA existence features
    cve_col = first_existing(df, ["cve_id", "cve", "all_cve_ids", "aliases"])
    ghsa_col = first_existing(df, ["ghsa_id", "ghsa", "all_ghsa_ids", "aliases"])

    cve_series = df[cve_col].astype(str) if cve_col else pd.Series("", index=df.index)
    ghsa_series = df[ghsa_col].astype(str) if ghsa_col else pd.Series("", index=df.index)

    df["has_cve"] = cve_series.str.contains(r"CVE-\d{4}-\d{4,}", case=False, regex=True).astype(int)
    df["feat_has_cve"] = df["has_cve"]
    df["feat_has_ghsa"] = ghsa_series.str.contains("GHSA-", case=False, regex=False).astype(int)

    # CWE family — bucketed to top-N + OTHER to prevent memorisation
    cwe_source = None
    for c in ["cwe_id", "cwe", "all_cwe_ids"]:
        if c in df.columns:
            cwe_source = c
            break
    if cwe_source:
        cwe_text = df[cwe_source].astype(str)
        extracted = cwe_text.str.extract(r"(\d+)", expand=False).fillna("UNKNOWN")
        # Bucket rare CWE families
        top_cwes = extracted.value_counts().nlargest(CWE_FAMILY_TOP_N).index.tolist()
        df["feat_cwe_family"] = extracted.where(extracted.isin(top_cwes), "OTHER")
        df["feat_has_cwe"] = (extracted != "UNKNOWN").astype(int)
    else:
        df["feat_cwe_family"] = "OTHER"
        df["feat_has_cwe"] = 0

    # Dates / temporal features
    def year_from_any(x):
        if pd.isna(x):
            return np.nan
        m = re.search(r"(19|20)\d{2}", str(x))
        return float(m.group(0)) if m else np.nan

    today = pd.Timestamp.utcnow().tz_localize(None)

    def days_since_any(x):
        if pd.isna(x):
            return np.nan
        dt = pd.to_datetime(x, errors="coerce", utc=True)
        if pd.isna(dt):
            y = year_from_any(x)
            if pd.isna(y):
                return np.nan
            dt = pd.Timestamp(year=int(y), month=1, day=1, tz="UTC")
        return float((today - dt.tz_localize(None)).days)

    if "published_year" in df.columns:
        df["feat_published_year"] = pd.to_numeric(df["published_year"], errors="coerce")
    elif "published" in df.columns:
        df["feat_published_year"] = df["published"].apply(year_from_any)
    elif "year" in df.columns:
        df["feat_published_year"] = pd.to_numeric(df["year"], errors="coerce")
    else:
        df["feat_published_year"] = np.nan

    if "published" in df.columns:
        df["feat_days_since_published"] = df["published"].apply(days_since_any)
    elif "days_since_published" in df.columns:
        df["feat_days_since_published"] = pd.to_numeric(df["days_since_published"], errors="coerce")
    else:
        df["feat_days_since_published"] = np.nan

    if "modified" in df.columns:
        df["feat_modified_year"] = df["modified"].apply(year_from_any)
        df["feat_days_since_modified"] = df["modified"].apply(days_since_any)
    else:
        df["feat_modified_year"] = np.nan
        df["feat_days_since_modified"] = np.nan

    if "withdrawn" in df.columns:
        df["feat_withdrawn_year"] = df["withdrawn"].apply(year_from_any)
        df["feat_days_since_withdrawn"] = df["withdrawn"].apply(days_since_any)
    else:
        df["feat_withdrawn_year"] = np.nan
        df["feat_days_since_withdrawn"] = np.nan

    # Package-derived features (low-cardinality only — no raw name or scope)
    df["feat_package_len"] = df["package_name"].astype(str).str.len()
    df["feat_is_scoped_package"] = df["package_name"].astype(str).str.startswith("@").astype(int)

    # Required numeric defaults if absent
    for col in ["ranges_count", "versions_count", "summary_len", "details_len", "references_count"]:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce")

    for col in ["github_reviewed", "has_patch_ref", "has_advisory_ref", "is_static", "is_dynamic"]:
        if col not in df.columns:
            df[col] = 0
        df[col] = df[col].fillna(0).astype(int)

    if "scanner_type" not in df.columns:
        df["scanner_type"] = "UNKNOWN"
    df["scanner_type"] = df["scanner_type"].fillna("UNKNOWN").astype(str).str.upper()

    return df


# ── Dataset preparation ────────────────────────────────────────────────────

def prepare_dataset(df: pd.DataFrame, epss_threshold: float) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    df = df.copy()
    epss_col = first_existing(df, ["epss_score", "epss"])
    if not epss_col:
        raise ValueError("No epss_score column found. EPSS-only model cannot be trained.")

    df[epss_col] = pd.to_numeric(df[epss_col], errors="coerce")
    df = df[df[epss_col].notna()].copy()
    y = (df[epss_col] >= epss_threshold).astype(int)

    groups = make_groups(df)

    df = normalize_cvss_components(df)
    df = add_backend_compatible_engineered_features(df)

    # Build feature matrix — everything must pass both allow-list AND not be in DROP_ALWAYS
    features = [c for c in CANDIDATE_FEATURES if c in df.columns and c not in DROP_ALWAYS]

    # cvss_score fallback
    if "cvss_score" not in df.columns:
        cvss_col = first_existing(df, ["cvss_base_score", "cvss"])
        if cvss_col:
            df["cvss_score"] = pd.to_numeric(df[cvss_col], errors="coerce")
            if "cvss_score" not in features:
                features.insert(0, "cvss_score")

    # Drop fully constant features
    keep_features = [c for c in features if df[c].nunique(dropna=True) > 1]

    X = df[keep_features].copy()
    return X, y.reset_index(drop=True), groups.reset_index(drop=True)


# ── Splitting ───────────────────────────────────────────────────────────────

def split_grouped(X, y, groups, test_size, random_state):
    if groups.nunique() >= 10:
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        tr, te = next(splitter.split(X, y, groups))
        return tr, te, "group"
    splitter = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    tr, te = next(splitter.split(X, y))
    return tr, te, "stratified"


def split_temporal(df_full: pd.DataFrame, X: pd.DataFrame, y: pd.Series,
                   test_ratio: float = 0.20):
    """Split by publication date: train on older, test on newer."""
    pub_col = first_existing(df_full, ["published", "published_year"])
    if pub_col is None:
        raise ValueError("No publication date column for temporal split")

    dates = pd.to_datetime(df_full[pub_col], errors="coerce", utc=True)
    # Use the subset that ended up in X (same index after EPSS filtering)
    dates = dates.iloc[X.index] if len(dates) > len(X) else dates
    dates = dates.reset_index(drop=True)

    # Fallback for rows without dates: treat as old (conservative)
    median_date = dates.dropna().median()
    dates = dates.fillna(median_date)

    cutoff = dates.quantile(1.0 - test_ratio)
    train_mask = dates <= cutoff
    test_mask = dates > cutoff

    train_idx = np.where(train_mask)[0]
    test_idx = np.where(test_mask)[0]

    print(f"  Temporal split: train={len(train_idx)}, test={len(test_idx)}, "
          f"cutoff={cutoff}")
    return train_idx, test_idx, "temporal"


# ── Preprocessing ───────────────────────────────────────────────────────────

def make_preprocessor(X_train: pd.DataFrame):
    numeric_cols = X_train.select_dtypes(include=[np.number, "bool"]).columns.tolist()
    categorical_cols = [c for c in X_train.columns if c not in numeric_cols]

    onehot = OneHotEncoder(handle_unknown="ignore", min_frequency=10, sparse_output=True)
    pre = ColumnTransformer(
        transformers=[
            ("num", SimpleImputer(strategy="median"), numeric_cols),
            ("cat", Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("onehot", onehot),
            ]), categorical_cols),
        ],
        remainder="drop",
        sparse_threshold=0.3,
    )
    return pre, numeric_cols, categorical_cols


# ── Threshold selection ─────────────────────────────────────────────────────

def choose_threshold(y_val, p_val, target_precision):
    precision, recall, thresholds = precision_recall_curve(y_val, p_val)
    valid = np.where(precision[:-1] >= target_precision)[0]
    if len(valid):
        best = valid[np.argmax(recall[valid])]
        return float(thresholds[best]), {
            "mode": "target_precision",
            "validation_precision": float(precision[best]),
            "validation_recall": float(recall[best]),
        }
    f1s = (2 * precision[:-1] * recall[:-1]) / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    best = int(np.nanargmax(f1s))
    return float(thresholds[best]), {
        "mode": "max_f1_fallback",
        "validation_precision": float(precision[best]),
        "validation_recall": float(recall[best]),
        "warning": "target precision not reachable on validation",
    }


# ── Evaluation ──────────────────────────────────────────────────────────────

def evaluate(y_true, probs, threshold):
    pred = (probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "aucpr": float(average_precision_score(y_true, probs)),
        "roc_auc": float(roc_auc_score(y_true, probs)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def ranking_metrics(y_true, ai_score, cvss_score):
    out: Dict[str, Any] = {}
    y = np.asarray(y_true).astype(int)
    total_pos = int(y.sum())

    def topk(scores, k):
        idx = np.argsort(-scores)[:min(k, len(scores))]
        hits = int(y[idx].sum())
        return {
            f"precision_at_{k}": hits / max(len(idx), 1),
            f"recall_at_{k}": hits / max(total_pos, 1),
            f"hits_at_{k}": hits,
        }

    def needed_for_coverage(scores, coverage=0.80):
        if total_pos == 0:
            return None
        idx = np.argsort(-scores)
        cum = np.cumsum(y[idx])
        target = coverage * total_pos
        found = np.where(cum >= target)[0]
        return int(found[0] + 1) if len(found) else None

    for label, scores in [("ai", ai_score), ("cvss", cvss_score)]:
        out[f"{label}_aucpr"] = float(average_precision_score(y, scores))
        out[f"{label}_roc_auc"] = float(roc_auc_score(y, scores))
        try:
            out[f"{label}_ndcg"] = float(ndcg_score([y], [scores]))
        except Exception:
            out[f"{label}_ndcg"] = float("nan")
        out[f"{label}_needed_for_80pct"] = needed_for_coverage(scores, 0.80)
        for k in [10, 20, 50, 100]:
            out.update({f"{label}_{kk}": vv for kk, vv in topk(scores, k).items()})

    ai_need = out.get("ai_needed_for_80pct")
    cvss_need = out.get("cvss_needed_for_80pct")
    if ai_need is not None and cvss_need is not None and cvss_need > 0:
        out["coverage_80pct_change_vs_cvss_pct"] = float(((ai_need - cvss_need) / cvss_need) * 100)
    else:
        out["coverage_80pct_change_vs_cvss_pct"] = None

    return out


# ── Label-shuffle sanity check ──────────────────────────────────────────────

def label_shuffle_sanity_check(X_train, y_train, X_test, y_test,
                               preprocessor, scale_pos_weight, random_state):
    """
    Train on shuffled labels.  If AUC >> 0.5, features still allow memorisation.
    A clean feature set should give AUC ≈ 0.5 on shuffled labels.
    """
    print("\n══ Label-shuffle sanity check ══")
    rng = np.random.RandomState(random_state)
    y_shuffled = rng.permutation(y_train)

    model_shuf = XGBClassifier(
        n_estimators=200, max_depth=4, min_child_weight=4,
        learning_rate=0.05, subsample=0.90, colsample_bytree=0.90,
        reg_lambda=2.0, reg_alpha=0.15, objective="binary:logistic",
        eval_metric="aucpr", scale_pos_weight=scale_pos_weight,
        random_state=random_state, n_jobs=-1, tree_method="hist",
    )
    pipe_shuf = Pipeline([
        ("preprocess", preprocessor),
        ("model", model_shuf),
    ])
    pipe_shuf.fit(X_train, y_shuffled)
    p_shuf = pipe_shuf.predict_proba(X_test)[:, 1]

    try:
        auc_shuffled = roc_auc_score(y_test, p_shuf)
    except ValueError:
        auc_shuffled = float("nan")
    try:
        aucpr_shuffled = average_precision_score(y_test, p_shuf)
    except ValueError:
        aucpr_shuffled = float("nan")

    pos_rate = float(y_test.mean())

    print(f"  Shuffled-label ROC-AUC on test: {auc_shuffled:.4f}  (expect ≈ 0.50)")
    print(f"  Shuffled-label AUCPR on test:   {aucpr_shuffled:.4f}  (expect ≈ {pos_rate:.4f})")

    if auc_shuffled > 0.60:
        print("  ⚠️  WARNING: shuffled AUC > 0.60 — features may still allow memorisation!")
    else:
        print("  ✓  Shuffled AUC ≈ 0.50 — no evidence of feature-level memorisation.")

    return {"shuffled_roc_auc": auc_shuffled, "shuffled_aucpr": aucpr_shuffled}


# ── Permutation importance ──────────────────────────────────────────────────

def permutation_importance_fast(pipe, X_test, y_test, n_repeats=5, random_state=42):
    """Quick permutation importance on raw (pre-pipeline) features."""
    rng = np.random.RandomState(random_state)
    base_proba = pipe.predict_proba(X_test)[:, 1]
    base_auc = roc_auc_score(y_test, base_proba)

    results = {}
    for col in X_test.columns:
        drops = []
        for _ in range(n_repeats):
            X_perm = X_test.copy()
            X_perm[col] = rng.permutation(X_perm[col].values)
            try:
                p_perm = pipe.predict_proba(X_perm)[:, 1]
                perm_auc = roc_auc_score(y_test, p_perm)
                drops.append(base_auc - perm_auc)
            except Exception:
                drops.append(0.0)
        results[col] = {"mean_auc_drop": float(np.mean(drops)),
                        "std_auc_drop": float(np.std(drops))}

    # Sort by importance
    sorted_feats = sorted(results.items(), key=lambda x: x[1]["mean_auc_drop"], reverse=True)
    print("\n══ Permutation importance (AUC drop when feature shuffled) ══")
    for feat, vals in sorted_feats:
        print(f"  {feat:40s}  Δ AUC = {vals['mean_auc_drop']:+.5f}  (± {vals['std_auc_drop']:.5f})")

    return dict(sorted_feats)


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df_raw = pd.read_csv(args.input, low_memory=False)
    print(f"Loaded rows: {len(df_raw):,}")

    X, y, groups = prepare_dataset(df_raw, args.epss_threshold)
    print(f"EPSS-labeled usable rows: {len(X):,}")
    print(f"EPSS-positive rows: {int(y.sum()):,}")
    print(f"EPSS-negative rows: {int((y == 0).sum()):,}")
    print(f"Features used: {len(X.columns)}")
    print("Feature columns:")
    for c in X.columns:
        print(f"  - {c}")

    # ── Split ───────────────────────────────────────────────────────────────
    if args.temporal_split:
        print("\nUsing temporal split (train=older, test=newer)...")
        trainval_idx, test_idx, split_test = split_temporal(
            df_raw, X, y, test_ratio=0.20)
    else:
        trainval_idx, test_idx, split_test = split_grouped(
            X, y, groups, 0.20, args.random_state)

    X_trainval = X.iloc[trainval_idx].reset_index(drop=True)
    y_trainval = y.iloc[trainval_idx].reset_index(drop=True)
    groups_trainval = groups.iloc[trainval_idx].reset_index(drop=True)

    if args.temporal_split:
        # For temporal: take the last 20% of trainval as validation
        n_val = int(len(X_trainval) * 0.20)
        train_rel = np.arange(len(X_trainval) - n_val)
        val_rel = np.arange(len(X_trainval) - n_val, len(X_trainval))
        split_val = "temporal"
    else:
        train_rel, val_rel, split_val = split_grouped(
            X_trainval, y_trainval, groups_trainval, 0.20, args.random_state + 1)

    train_idx = trainval_idx[train_rel]
    val_idx = trainval_idx[val_rel]

    X_train, y_train = X.iloc[train_idx], y.iloc[train_idx].to_numpy()
    X_val, y_val = X.iloc[val_idx], y.iloc[val_idx].to_numpy()
    X_test, y_test = X.iloc[test_idx], y.iloc[test_idx].to_numpy()

    neg = max(int((y_train == 0).sum()), 1)
    pos = max(int((y_train == 1).sum()), 1)
    scale_pos_weight = neg / pos

    preprocessor, numeric_cols, categorical_cols = make_preprocessor(X_train)

    # ── Train ───────────────────────────────────────────────────────────────
    model = XGBClassifier(
        n_estimators=550,
        max_depth=4,
        min_child_weight=4,
        learning_rate=0.035,
        subsample=0.90,
        colsample_bytree=0.90,
        reg_lambda=2.0,
        reg_alpha=0.15,
        objective="binary:logistic",
        eval_metric="aucpr",
        scale_pos_weight=scale_pos_weight,
        random_state=args.random_state,
        n_jobs=-1,
        tree_method="hist",
    )

    pipe = Pipeline([
        ("preprocess", preprocessor),
        ("model", model),
    ])

    print("\nTraining EPSS-only operational XGBoost ranker (v2, leakage-hardened)...")
    pipe.fit(X_train, y_train)

    # ── Evaluate ────────────────────────────────────────────────────────────
    p_val = pipe.predict_proba(X_val)[:, 1]
    threshold, threshold_info = choose_threshold(y_val, p_val, args.target_precision)

    p_test = pipe.predict_proba(X_test)[:, 1]
    val_metrics = evaluate(y_val, p_val, threshold)
    test_metrics = evaluate(y_test, p_test, threshold)

    cvss_test = pd.to_numeric(
        X_test.get("cvss_score", pd.Series(0, index=X_test.index)),
        errors="coerce"
    ).fillna(0).to_numpy()
    rank_metrics = ranking_metrics(y_test, p_test, cvss_test)

    print("\nValidation metrics:")
    for k, v in val_metrics.items():
        print(f"  {k}: {v}")

    print("\nTest metrics:")
    for k, v in test_metrics.items():
        print(f"  {k}: {v}")

    print("\nRanking comparison on held-out test set: AI score vs CVSS score")
    for k in ["ai_aucpr", "cvss_aucpr", "ai_roc_auc", "cvss_roc_auc",
              "ai_ndcg", "cvss_ndcg", "ai_needed_for_80pct",
              "cvss_needed_for_80pct", "coverage_80pct_change_vs_cvss_pct"]:
        print(f"  {k}: {rank_metrics.get(k)}")

    # ── Diagnostics ─────────────────────────────────────────────────────────
    shuffle_results = {}
    if not args.skip_shuffle_test:
        # Need a fresh preprocessor for the shuffle test
        pre_shuf, _, _ = make_preprocessor(X_train)
        shuffle_results = label_shuffle_sanity_check(
            X_train, y_train, X_test, y_test,
            pre_shuf, scale_pos_weight, args.random_state)

    perm_imp = permutation_importance_fast(pipe, X_test, y_test,
                                           n_repeats=5, random_state=args.random_state)

    # ── Save artifacts (backend-compatible names) ───────────────────────────
    model_path = out_dir / "model_leakage_safe.pkl"
    meta_path = out_dir / "model_meta.json"
    feat_path = out_dir / "feature_columns.json"

    joblib.dump(pipe, model_path)

    feature_columns = list(X.columns)
    feat_path.write_text(json.dumps(feature_columns, indent=2), encoding="utf-8")

    meta = {
        "model_type": "XGBoost EPSS-only operational ranking classifier",
        "model_version": "epss-operational-ranker-v2-leakage-hardened",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(Path(args.input).resolve()),
        "label_mode": "epss_only",
        "epss_threshold_for_label_only": args.epss_threshold,
        "target_precision": args.target_precision,
        "optimal_threshold": threshold,
        "threshold_selection": threshold_info,
        "rows_loaded": int(len(df_raw)),
        "rows_labeled_used": int(len(X)),
        "positive_rows": int(y.sum()),
        "negative_rows": int((y == 0).sum()),
        "scale_pos_weight": float(scale_pos_weight),
        "split_kind_train_test": split_test,
        "split_kind_train_val": split_val,
        "numeric_feature_count": len(numeric_cols),
        "categorical_feature_count": len(categorical_cols),
        "feature_columns_before_preprocessing": feature_columns,
        "leakage_policy": {
            "removed_v2": [
                "package_name (high-cardinality memorisation)",
                "cvss_vector (redundant with parsed components, near-unique)",
                "feat_package_scope (ecosystem-level memorisation)",
            ],
            "removed_direct_label_signals": [
                "epss_score", "epss_percentile", "label columns",
                "generated risk outputs",
            ],
            "allowed_operational_signals": ["cvss_score", "cvss subcomponents"],
            "cwe_bucketing": f"top-{CWE_FAMILY_TOP_N} CWE families + OTHER",
            "important_note": "CVSS is allowed because it is not used to define the EPSS target label.",
        },
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "ranking_comparison_test": rank_metrics,
        "diagnostics": {
            "label_shuffle_sanity": shuffle_results,
            "permutation_importance_top10": {
                k: v for k, v in list(perm_imp.items())[:10]
            },
        },
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    pd.DataFrame({"feature": feature_columns}).to_csv(
        out_dir / "feature_columns.csv", index=False)
    pd.DataFrame([rank_metrics]).to_csv(
        out_dir / "ranking_comparison_test.csv", index=False)

    # Permutation importance full dump
    pd.DataFrame([
        {"feature": k, **v} for k, v in perm_imp.items()
    ]).sort_values("mean_auc_drop", ascending=False).to_csv(
        out_dir / "permutation_importance.csv", index=False)

    for p in [model_path, meta_path, feat_path]:
        write_sha256(p)

    print("\nSaved backend-compatible artifacts:")
    for f in [model_path, meta_path, feat_path]:
        print(f"  {f}")
        print(f"  {f}.sha256")
    print(f"  {out_dir / 'permutation_importance.csv'}")


if __name__ == "__main__":
    main()