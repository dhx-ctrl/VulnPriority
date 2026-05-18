#!/usr/bin/env python3
"""
Train an EPSS-only operational ranking model.

Purpose
-------
This is NOT the strict scientific minimal model.
This is an operational ranker designed to compete with CVSS on EPSS-proxy labels.

Target:
    y = 1 if epss_score >= threshold else 0
    y = 0 if epss_score < threshold

Allowed features:
    CVSS score + CVSS subcomponents are allowed because CVSS is NOT used to build the label.

Still removed:
    EPSS score/percentile, label columns, raw advisory IDs, KEV/exploit shortcut columns.

Outputs are backend-compatible with main_final_pipeline_sha256.py:
    model_leakage_safe.pkl
    model_leakage_safe.pkl.sha256
    model_meta.json
    model_meta.json.sha256
    feature_columns.json
    feature_columns.json.sha256

Run:
python 08_train_epss_operational_ranker.py ^
  --input ".\\dataset_merged\\merged_trainable.csv" ^
  --out-dir ".\\model_output_EPSS_operational_ranker" ^
  --epss-threshold 0.10 ^
  --target-precision 0.70
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


# Direct target leakage / memorization columns.
DROP_ALWAYS = {
    # Labels / outputs
    "label_high_risk", "high_risk_label", "target", "label", "y",
    "label_source", "label_from_epss", "label_from_cvss", "label_from_severity",
    "risk_score", "ai_risk_score", "priority_score", "exploit_probability",
    "prediction", "predicted_label", "optimal_threshold", "threshold",

    # EPSS target signal: NEVER as feature for EPSS-only model
    "epss", "epss_score", "epss_percentile", "percentile",

    # Raw IDs / advisory IDs that can memorize vulnerabilities
    "id", "osv_id", "cve_id", "ghsa_id", "advisory_id", "aliases", "alias",
    "cve", "ghsa", "all_cve_ids", "all_ghsa_ids", "vulnerability_id",

    # Exploit/KEV shortcuts
    "has_exploit_ref", "feat_has_exploit_ref", "known_exploited", "is_kev", "in_kev",
    "kev_listed", "public_exploit", "has_public_exploit", "exploit_maturity",

    # Source metadata bias
    "source_dataset", "data_source", "source_database", "source",
}

# Keep the feature set backend-compatible with the current patched main.py.
# IMPORTANT: If you add new feature names here, main.py must know how to build them too.
CANDIDATE_FEATURES = [
    # Package / advisory metadata
    "package_name",
    "cvss_score",
    "cvss_vector",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",

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

    # Engineered features already supported by patched backend
    "feat_has_cve",
    "feat_has_ghsa",
    "feat_cwe_family",
    "feat_has_cwe",
    "feat_published_year",
    "feat_days_since_published",
    "feat_modified_year",
    "feat_days_since_modified",
    "feat_withdrawn_year",
    "feat_days_since_withdrawn",
    "feat_package_len",
    "feat_is_scoped_package",
    "feat_package_scope",
]

CVSS_VECTOR_RE = re.compile(r"CVSS:\d\.\d/[^\s]+", re.I)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="Path to merged_trainable.csv")
    p.add_argument("--out-dir", required=True, help="Output model folder")
    p.add_argument("--epss-threshold", type=float, default=0.10)
    p.add_argument("--target-precision", type=float, default=0.70)
    p.add_argument("--random-state", type=int, default=42)
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

    if "package_name" in df.columns:
        fallback = df["package_name"].fillna("UNKNOWN_PACKAGE").astype(str) + "__" + df.index.astype(str)
    else:
        fallback = pd.Series([f"row_{i}" for i in range(len(df))], index=df.index)

    return group.where(group.notna(), fallback).astype(str)


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

    # If components are missing but vector exists, recover components from vector.
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

    # CWE family: keep first CWE number as broad categorical signal.
    cwe_source = None
    for c in ["cwe_id", "cwe", "all_cwe_ids"]:
        if c in df.columns:
            cwe_source = c
            break
    if cwe_source:
        cwe_text = df[cwe_source].astype(str)
        extracted = cwe_text.str.extract(r"(\d+)", expand=False)
        df["feat_cwe_family"] = extracted.fillna("UNKNOWN")
        df["feat_has_cwe"] = (df["feat_cwe_family"] != "UNKNOWN").astype(int)
    else:
        df["feat_cwe_family"] = "UNKNOWN"
        df["feat_has_cwe"] = 0

    # Dates / temporal features.
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

    df["feat_package_len"] = df["package_name"].astype(str).str.len()
    df["feat_is_scoped_package"] = df["package_name"].astype(str).str.startswith("@").astype(int)
    df["feat_package_scope"] = np.where(
        df["package_name"].astype(str).str.startswith("@"),
        df["package_name"].astype(str).str.split("/").str[0],
        "unscoped",
    )

    # Required numeric defaults if absent.
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

    # Build backend-compatible feature matrix.
    features = [c for c in CANDIDATE_FEATURES if c in df.columns and c not in DROP_ALWAYS]

    # If cvss_score is missing, create fallback from existing cvss-like columns if possible.
    if "cvss_score" not in df.columns:
        cvss_col = first_existing(df, ["cvss_base_score", "cvss"])
        if cvss_col:
            df["cvss_score"] = pd.to_numeric(df[cvss_col], errors="coerce")
            if "cvss_score" not in features:
                features.insert(1, "cvss_score")

    # Drop fully constant features.
    keep_features = []
    for c in features:
        if df[c].nunique(dropna=True) > 1:
            keep_features.append(c)

    X = df[keep_features].copy()
    return X, y.reset_index(drop=True), groups.reset_index(drop=True)


def split_grouped(X: pd.DataFrame, y: pd.Series, groups: pd.Series, test_size: float, random_state: int):
    if groups.nunique() >= 10:
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        tr, te = next(splitter.split(X, y, groups))
        return tr, te, "group"
    splitter = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    tr, te = next(splitter.split(X, y))
    return tr, te, "stratified"


def make_preprocessor(X_train: pd.DataFrame):
    numeric_cols = X_train.select_dtypes(include=[np.number, "bool"]).columns.tolist()
    categorical_cols = [c for c in X_train.columns if c not in numeric_cols]

    onehot = OneHotEncoder(handle_unknown="ignore", min_frequency=5, sparse_output=True)
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


def choose_threshold(y_val: np.ndarray, p_val: np.ndarray, target_precision: float):
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


def evaluate(y_true: np.ndarray, probs: np.ndarray, threshold: float) -> Dict[str, Any]:
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


def ranking_metrics(y_true: np.ndarray, ai_score: np.ndarray, cvss_score: np.ndarray) -> Dict[str, Any]:
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

    # 64% train, 16% validation, 20% test via grouped splitting.
    trainval_idx, test_idx, split_test = split_grouped(X, y, groups, 0.20, args.random_state)
    X_trainval = X.iloc[trainval_idx].reset_index(drop=True)
    y_trainval = y.iloc[trainval_idx].reset_index(drop=True)
    groups_trainval = groups.iloc[trainval_idx].reset_index(drop=True)

    train_rel, val_rel, split_val = split_grouped(X_trainval, y_trainval, groups_trainval, 0.20, args.random_state + 1)

    train_idx = trainval_idx[train_rel]
    val_idx = trainval_idx[val_rel]

    X_train, y_train = X.iloc[train_idx], y.iloc[train_idx].to_numpy()
    X_val, y_val = X.iloc[val_idx], y.iloc[val_idx].to_numpy()
    X_test, y_test = X.iloc[test_idx], y.iloc[test_idx].to_numpy()

    neg = max(int((y_train == 0).sum()), 1)
    pos = max(int((y_train == 1).sum()), 1)
    scale_pos_weight = neg / pos

    preprocessor, numeric_cols, categorical_cols = make_preprocessor(X_train)

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

    print("Training EPSS-only operational XGBoost ranker...")
    pipe.fit(X_train, y_train)

    p_val = pipe.predict_proba(X_val)[:, 1]
    threshold, threshold_info = choose_threshold(y_val, p_val, args.target_precision)

    p_test = pipe.predict_proba(X_test)[:, 1]
    val_metrics = evaluate(y_val, p_val, threshold)
    test_metrics = evaluate(y_test, p_test, threshold)

    cvss_test = pd.to_numeric(X_test.get("cvss_score", pd.Series(0, index=X_test.index)), errors="coerce").fillna(0).to_numpy()
    rank_metrics = ranking_metrics(y_test, p_test, cvss_test)

    print("\nValidation metrics:")
    for k, v in val_metrics.items():
        print(f"  {k}: {v}")

    print("\nTest metrics:")
    for k, v in test_metrics.items():
        print(f"  {k}: {v}")

    print("\nRanking comparison on held-out test set: AI score vs CVSS score")
    for k in ["ai_aucpr", "cvss_aucpr", "ai_roc_auc", "cvss_roc_auc", "ai_ndcg", "cvss_ndcg", "ai_needed_for_80pct", "cvss_needed_for_80pct", "coverage_80pct_change_vs_cvss_pct"]:
        print(f"  {k}: {rank_metrics.get(k)}")

    # Save artifacts using backend-compatible names.
    model_path = out_dir / "model_leakage_safe.pkl"
    meta_path = out_dir / "model_meta.json"
    feat_path = out_dir / "feature_columns.json"

    joblib.dump(pipe, model_path)

    feature_columns = list(X.columns)
    feat_path.write_text(json.dumps(feature_columns, indent=2), encoding="utf-8")

    meta = {
        "model_type": "XGBoost EPSS-only operational ranking classifier",
        "model_version": "epss-operational-ranker-v1",
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
            "removed_direct_label_signals": ["epss_score", "epss_percentile", "label columns", "generated risk outputs"],
            "allowed_operational_signals": ["cvss_score", "cvss subcomponents"],
            "important_note": "This EPSS-only model may use CVSS as an input because CVSS is not used to define the EPSS target label.",
        },
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "ranking_comparison_test": rank_metrics,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    pd.DataFrame({"feature": feature_columns}).to_csv(out_dir / "feature_columns.csv", index=False)
    pd.DataFrame([rank_metrics]).to_csv(out_dir / "ranking_comparison_test.csv", index=False)

    for p in [model_path, meta_path, feat_path]:
        write_sha256(p)

    print("\nSaved backend-compatible artifacts:")
    print(f"  {model_path}")
    print(f"  {model_path}.sha256")
    print(f"  {meta_path}")
    print(f"  {meta_path}.sha256")
    print(f"  {feat_path}")
    print(f"  {feat_path}.sha256")


if __name__ == "__main__":
    main()
