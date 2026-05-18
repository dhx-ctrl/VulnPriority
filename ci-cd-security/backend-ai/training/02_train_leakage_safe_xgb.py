#!/usr/bin/env python3
"""
Leakage-safe XGBoost trainer for AI vulnerability risk scoring.

Key idea:
- You may use EPSS/CVSS/severity to CREATE the supervised target label.
- You must NOT give EPSS/CVSS/severity/label-source/risk-score columns to the model as input features.
- Splits are grouped by advisory/CVE/GHSA/OSV id to avoid the same vulnerability appearing in train and test.

Example:
python 03_train_leakage_safe_xgb.py ^
  --input ".\\dataset_deep_fixed\\trainable_data.csv" ^
  --out-dir ".\\model_output_leakage_safe" ^
  --label-mode hybrid_existing ^
  --target-precision 0.70

Cleaner exploit-likelihood experiment:
python 03_train_leakage_safe_xgb.py ^
  --input ".\\dataset_deep_fixed\\all_data.csv" ^
  --out-dir ".\\model_output_epss_only" ^
  --label-mode epss_only ^
  --epss-threshold 0.10 ^
  --target-precision 0.70
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import re
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier

warnings.filterwarnings("ignore", category=UserWarning)

TARGET_CANDIDATES = [
    "label_high_risk",
    "high_risk_label",
    "target_high_risk",
    "target",
    "label",
    "y",
]

EXACT_LEAKAGE_COLUMNS = {
    # duplicate/basic temporal fields
    "published",
    "modified",
    "withdrawn",
    "published_year",
    "days_since_published",
    "days_since_modified",
    "year",

    # raw CWE fields, keep only engineered CWE features
    "cwe_id",
    "all_cwe_ids",
    "cwe",
    "source_dataset",
    "data_source",
    "source_database",
    "source",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "has_exploit_ref",
    "feat_has_exploit_ref",
    "label_high_risk",
    "high_risk_label",
    "target_high_risk",
    "target",
    "label",
    "y",
    "ai_risk_score",
    "risk_score",
    "risk",
    "priority",
    "priority_score",
    "exploit_probability",
    "probability_high_risk",
    "prediction",
    "predicted_label",
    "optimal_threshold",
    "threshold",

    "epss",
    "epss_score",
    "epss_percentile",
    "percentile",
    "cvss",
    "cvss_score",
    "cvss_base_score",
    "cvss_vector",
    "severity",
    "severity_text",
    "scanner_severity",
    "github_severity",
    "ghsa_severity",
    "database_specific_severity",
    "label_source",
    "label_from_epss",
    "label_from_cvss",
    "label_from_severity",

    "id",
    "osv_id",
    "cve_id",
    "ghsa_id",
    "advisory_id",
    "aliases",
    "alias",
    "cve",
    "ghsa",

    "summary",
    "details",
    "description",
    "title",
    "references",
    "ref_urls",
}

LEAKAGE_SUBSTRINGS = [
    "epss",
    "cvss",
    "severity",
    "label",
    "target",
    "risk_score",
    "ai_risk",
    "exploit_probability",
    "priority_score",
    "threshold",
]

EXPLOIT_SIGNAL_SUBSTRINGS = [
    "kev",
    "known_exploited",
    "exploited_in_the_wild",
    "public_exploit",
    "exploit_maturity",
    "metasploit",
    "poc",
]

ID_SUBSTRINGS = [
    "cve_id",
    "ghsa_id",
    "osv_id",
    "advisory_id",
    "aliases",
]

SAFE_TEXT_COLUMNS = ["summary", "details", "description", "title"]

HIGH_SEVERITIES = {"HIGH", "CRITICAL", "SEVERE"}
LOW_SEVERITIES = {"LOW", "MEDIUM", "MODERATE", "NONE", "UNKNOWN"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train leakage-safe XGBoost vulnerability risk model")
    p.add_argument("--input", required=True, help="CSV from OSV/DefectDojo dataset builder")
    p.add_argument("--out-dir", required=True, help="Output directory for model and metrics")
    p.add_argument(
        "--label-mode",
        default="hybrid_existing",
        choices=["hybrid_existing", "hybrid_rebuild", "epss_only"],
        help=(
            "hybrid_existing = use existing label_high_risk if present; "
            "hybrid_rebuild = rebuild target from EPSS -> CVSS -> severity; "
            "epss_only = only train rows with EPSS and label by EPSS threshold"
        ),
    )
    p.add_argument("--epss-threshold", type=float, default=0.10, help="EPSS threshold for positive class")
    p.add_argument("--cvss-threshold", type=float, default=7.0, help="CVSS threshold for positive class")
    p.add_argument("--target-precision", type=float, default=0.70, help="Desired precision on validation set")
    p.add_argument("--test-size", type=float, default=0.20, help="Held-out test size")
    p.add_argument("--val-size", type=float, default=0.20, help="Validation size from trainval")
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument(
        "--allow-exploit-signal-features",
        action="store_true",
        help=(
            "By default, KEV/public exploit/PoC-like columns are removed too. "
            "Use this flag only if your supervisor accepts them as available inference-time features."
        ),
    )
    return p.parse_args()


def normalize_missing(s: pd.Series) -> pd.Series:
    return s.replace({"": np.nan, "nan": np.nan, "None": np.nan, "NONE": np.nan, "null": np.nan})

def safe_join_columns(df: pd.DataFrame, cols: List[str]) -> pd.Series:
    """
    Safely joins multiple columns into one text string.
    Prevents crashes when cells contain NaN, floats, lists, or mixed types.
    """
    if not cols:
        return pd.Series("", index=df.index)

    return (
        df[cols]
        .fillna("")
        .astype(str)
        .apply(lambda row: " ".join([x for x in row.tolist() if x and x.lower() != "nan"]), axis=1)
    )


def first_existing_col(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    lower_to_real = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c in df.columns:
            return c
        if c.lower() in lower_to_real:
            return lower_to_real[c.lower()]
    return None


def to_numeric_series(df: pd.DataFrame, col: str) -> pd.Series:
    if col not in df.columns:
        return pd.Series(np.nan, index=df.index)
    return pd.to_numeric(df[col], errors="coerce")


def get_severity_series(df: pd.DataFrame) -> pd.Series:
    severity_cols = [c for c in df.columns if "severity" in c.lower()]
    if not severity_cols:
        return pd.Series(np.nan, index=df.index, dtype="object")

    out = pd.Series(np.nan, index=df.index, dtype="object")
    for col in severity_cols:
        values = normalize_missing(df[col].astype(str).str.upper().str.strip())
        out = out.where(out.notna(), values)
    return out


def build_target(
    df: pd.DataFrame,
    mode: str,
    epss_threshold: float,
    cvss_threshold: float,
) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    df = df.copy()

    if mode == "hybrid_existing":
        target_col = first_existing_col(df, TARGET_CANDIDATES)
        if target_col is not None:
            y = pd.to_numeric(df[target_col], errors="coerce")
            source = (
                df["label_source"].astype(str)
                if "label_source" in df.columns
                else pd.Series("existing_label", index=df.index)
            )
            keep = y.notna()
            return df.loc[keep].copy(), y.loc[keep].astype(int), source.loc[keep]

        mode = "hybrid_rebuild"

    epss_col = first_existing_col(df, ["epss_score", "epss"])
    cvss_col = first_existing_col(df, ["cvss_score", "cvss_base_score", "cvss"])

    epss = to_numeric_series(df, epss_col) if epss_col else pd.Series(np.nan, index=df.index)
    cvss = to_numeric_series(df, cvss_col) if cvss_col else pd.Series(np.nan, index=df.index)
    severity = get_severity_series(df)

    y = pd.Series(np.nan, index=df.index, dtype="float")
    source = pd.Series("unlabeled", index=df.index, dtype="object")

    if mode == "epss_only":
        has_epss = epss.notna()
        y.loc[has_epss] = (epss.loc[has_epss] >= epss_threshold).astype(int)
        source.loc[has_epss] = "epss_only"

    elif mode == "hybrid_rebuild":
        has_epss = epss.notna()
        y.loc[has_epss] = (epss.loc[has_epss] >= epss_threshold).astype(int)
        source.loc[has_epss] = "epss"

        unlabeled = y.isna() & cvss.notna()
        y.loc[unlabeled] = (cvss.loc[unlabeled] >= cvss_threshold).astype(int)
        source.loc[unlabeled] = "cvss"

        unlabeled = y.isna() & severity.notna()
        sev = severity.loc[unlabeled].astype(str).str.upper().str.strip()
        y.loc[unlabeled] = sev.isin(HIGH_SEVERITIES).astype(int)
        source.loc[unlabeled] = "severity"

    else:
        raise ValueError(f"Unknown label mode: {mode}")

    keep = y.notna()
    return df.loc[keep].copy(), y.loc[keep].astype(int), source.loc[keep]


def parse_year(value) -> float:
    if pd.isna(value):
        return np.nan
    text = str(value)
    m = re.search(r"(19|20)\d{2}", text)
    if m:
        return float(m.group(0))
    return np.nan


def days_since(value) -> float:
    if pd.isna(value):
        return np.nan
    try:
        dt = pd.to_datetime(value, errors="coerce", utc=True)
        if pd.isna(dt):
            return np.nan
        now = pd.Timestamp.now(tz="UTC")
        return float((now - dt).days)
    except Exception:
        return np.nan


def add_safe_engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    joined_id_cols = []
    for col in df.columns:
        lc = col.lower()
        if any(key in lc for key in ["cve", "ghsa", "osv", "alias", "advisory"]):
            joined_id_cols.append(col)

    if joined_id_cols:
        id_text = safe_join_columns(df, joined_id_cols)
    else:
        id_text = pd.Series("", index=df.index)

    df["feat_has_cve"] = id_text.str.contains(r"CVE-\d{4}-\d+", regex=True, na=False).astype(int)
    df["feat_has_ghsa"] = id_text.str.contains(
        r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}",
        case=False,
        regex=True,
        na=False,
    ).astype(int)

    cwe_cols = [c for c in df.columns if "cwe" in c.lower()]
    if cwe_cols:
        cwe_text = safe_join_columns(df, cwe_cols)
        df["feat_cwe_family"] = cwe_text.str.extract(r"CWE[-_ ]?(\d+)", expand=False).fillna("UNKNOWN")
        df["feat_has_cwe"] = (df["feat_cwe_family"] != "UNKNOWN").astype(int)
    else:
        df["feat_cwe_family"] = "UNKNOWN"
        df["feat_has_cwe"] = 0

    for base in ["published", "modified", "withdrawn"]:
        col = first_existing_col(df, [base, f"{base}_date", f"{base}_at"])
        if col:
            df[f"feat_{base}_year"] = df[col].apply(parse_year)
            df[f"feat_days_since_{base}"] = df[col].apply(days_since)

    pkg_col = first_existing_col(df, ["package_name", "pkg_name", "name", "package"])
    if pkg_col:
        pkg = df[pkg_col].astype(str)
        df["feat_package_len"] = pkg.str.len().clip(0, 200)
        df["feat_is_scoped_package"] = pkg.str.startswith("@").astype(int)
        df["feat_package_scope"] = np.where(pkg.str.startswith("@"), pkg.str.split("/").str[0], "unscoped")
    else:
        df["feat_package_len"] = np.nan
        df["feat_is_scoped_package"] = 0
        df["feat_package_scope"] = "unknown"

    ref_col = first_existing_col(df, ["references", "ref_urls", "urls"])
    if ref_col:
        ref_text = df[ref_col].astype(str)
        df["feat_num_references_rough"] = ref_text.str.count("http").clip(0, 100)
    else:
        df["feat_num_references_rough"] = np.nan

    text_cols_present = [c for c in SAFE_TEXT_COLUMNS if c in df.columns]
    if text_cols_present:
        text_joined = safe_join_columns(df, text_cols_present)
        df["feat_text_len"] = text_joined.str.len().clip(0, 10000)
        df["feat_mentions_rce"] = text_joined.str.contains(
            r"remote code execution|\brce\b",
            case=False,
            regex=True,
            na=False,
        ).astype(int)
        df["feat_mentions_xss"] = text_joined.str.contains(
            r"cross.site scripting|\bxss\b",
            case=False,
            regex=True,
            na=False,
        ).astype(int)
        df["feat_mentions_injection"] = text_joined.str.contains(
            r"injection|sql injection|command injection",
            case=False,
            regex=True,
            na=False,
        ).astype(int)
        df["feat_mentions_prototype_pollution"] = text_joined.str.contains(
            r"prototype pollution",
            case=False,
            regex=True,
            na=False,
        ).astype(int)
        df["feat_mentions_dos"] = text_joined.str.contains(
            r"denial of service|\bdos\b",
            case=False,
            regex=True,
            na=False,
        ).astype(int)
    else:
        df["feat_text_len"] = np.nan
        df["feat_mentions_rce"] = 0
        df["feat_mentions_xss"] = 0
        df["feat_mentions_injection"] = 0
        df["feat_mentions_prototype_pollution"] = 0
        df["feat_mentions_dos"] = 0

    for maybe_col in ["affected", "ranges", "events", "versions"]:
        col = first_existing_col(df, [maybe_col])
        if col:
            txt = df[col].astype(str)
            df[f"feat_{maybe_col}_len"] = txt.str.len().clip(0, 10000)

    return df


def build_groups(df: pd.DataFrame) -> pd.Series:
    candidates = ["cve_id", "ghsa_id", "osv_id", "advisory_id", "id"]
    group = pd.Series(np.nan, index=df.index, dtype="object")

    for col in candidates:
        real = first_existing_col(df, [col])
        if real:
            vals = normalize_missing(df[real].astype(str))
            group = group.where(group.notna(), vals)

    pkg_col = first_existing_col(df, ["package_name", "pkg_name", "package", "name"])
    title_col = first_existing_col(df, ["summary", "title", "details"])

    pkg = df[pkg_col] if pkg_col else pd.Series("pkg_unknown", index=df.index)
    title = df[title_col] if title_col else pd.Series("row", index=df.index)

    fallback = pkg.astype(str) + "__" + title.astype(str).str.slice(0, 80)
    group = group.where(group.notna(), fallback)

    return group.astype(str)


def should_drop_column(col: str, allow_exploit_signal_features: bool) -> bool:
    lc = col.lower()

    if lc in EXACT_LEAKAGE_COLUMNS:
        return True

    if any(s in lc for s in LEAKAGE_SUBSTRINGS):
        return True

    if any(s in lc for s in ID_SUBSTRINGS):
        return True

    if not allow_exploit_signal_features and any(s in lc for s in EXPLOIT_SIGNAL_SUBSTRINGS):
        return True

    return False


def select_features(df: pd.DataFrame, allow_exploit_signal_features: bool) -> Tuple[pd.DataFrame, List[str]]:
    dropped = []
    keep_cols = []

    for col in df.columns:
        if should_drop_column(col, allow_exploit_signal_features):
            dropped.append(col)
        else:
            keep_cols.append(col)

    X = df[keep_cols].copy()

    extra_drop = []
    n = len(X)

    for col in X.columns:
        nunique = X[col].nunique(dropna=True)

        if nunique <= 1:
            extra_drop.append(col)

        elif X[col].dtype == "object" and n > 0 and nunique / n > 0.80:
            extra_drop.append(col)

    if extra_drop:
        X = X.drop(columns=extra_drop)
        dropped.extend(extra_drop)

    return X, sorted(set(dropped))


def grouped_or_stratified_split(X, y, groups, test_size, random_state):
    unique_groups = groups.nunique()

    if unique_groups >= 10:
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        train_idx, test_idx = next(splitter.split(X, y, groups))
        return train_idx, test_idx, "group"

    splitter = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(splitter.split(X, y))
    return train_idx, test_idx, "stratified"


def make_preprocessor(X_train: pd.DataFrame) -> Tuple[ColumnTransformer, List[str], List[str]]:
    numeric_cols = X_train.select_dtypes(include=[np.number, "bool"]).columns.tolist()
    categorical_cols = [c for c in X_train.columns if c not in numeric_cols]

    try:
        encoder = OneHotEncoder(handle_unknown="ignore", min_frequency=5, sparse_output=True)
    except TypeError:
        encoder = OneHotEncoder(handle_unknown="ignore", min_frequency=5, sparse=True)

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", SimpleImputer(strategy="median"), numeric_cols),
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", encoder),
                    ]
                ),
                categorical_cols,
            ),
        ],
        remainder="drop",
        sparse_threshold=0.3,
    )

    return preprocessor, numeric_cols, categorical_cols


def pick_threshold_for_precision(
    y_val: np.ndarray,
    p_val: np.ndarray,
    target_precision: float,
) -> Tuple[float, Dict[str, float]]:
    precision, recall, thresholds = precision_recall_curve(y_val, p_val)

    candidate_idxs = np.where(precision[:-1] >= target_precision)[0]

    if len(candidate_idxs) > 0:
        best_idx = candidate_idxs[np.argmax(recall[candidate_idxs])]
        threshold = float(thresholds[best_idx])

        chosen = {
            "mode": "target_precision",
            "validation_precision": float(precision[best_idx]),
            "validation_recall": float(recall[best_idx]),
        }

        return threshold, chosen

    f1s = (2 * precision[:-1] * recall[:-1]) / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    best_idx = int(np.nanargmax(f1s))
    threshold = float(thresholds[best_idx])

    chosen = {
        "mode": "max_f1_fallback",
        "validation_precision": float(precision[best_idx]),
        "validation_recall": float(recall[best_idx]),
        "warning": f"Target precision {target_precision} was not reachable on validation; used max-F1 threshold instead.",
    }

    return threshold, chosen


def evaluate(y_true: np.ndarray, p: np.ndarray, threshold: float) -> Dict[str, float]:
    y_pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    out = {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "aucpr": float(average_precision_score(y_true, p)) if len(np.unique(y_true)) > 1 else float("nan"),
        "roc_auc": float(roc_auc_score(y_true, p)) if len(np.unique(y_true)) > 1 else float("nan"),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }

    return out


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df_raw = pd.read_csv(args.input, low_memory=False)
    print(f"Loaded rows: {len(df_raw):,}")

    df_labeled, y, label_source = build_target(
        df_raw,
        mode=args.label_mode,
        epss_threshold=args.epss_threshold,
        cvss_threshold=args.cvss_threshold,
    )

    df_labeled = df_labeled.reset_index(drop=True)
    y = y.reset_index(drop=True)
    label_source = label_source.reset_index(drop=True)

    print(f"Usable labeled rows: {len(df_labeled):,}")
    print(f"High-risk labels: {int(y.sum()):,}")
    print(f"Low-risk labels: {int((y == 0).sum()):,}")
    print("Label source counts:")
    print(label_source.value_counts(dropna=False).to_string())

    if len(df_labeled) < 500:
        raise SystemExit("Too few labeled rows. Use hybrid_existing/hybrid_rebuild or inspect label columns.")

    if y.nunique() < 2:
        raise SystemExit("Only one class found. Change thresholds or check labels.")

    groups = build_groups(df_labeled)
    df_feat = add_safe_engineered_features(df_labeled)

    X, dropped_cols = select_features(
        df_feat,
        allow_exploit_signal_features=args.allow_exploit_signal_features,
    )

    print(f"Feature columns after leakage drop: {X.shape[1]:,}")
    print(f"Dropped leakage/useless columns: {len(dropped_cols):,}")

    trainval_idx, test_idx, split_kind_1 = grouped_or_stratified_split(
        X,
        y,
        groups,
        test_size=args.test_size,
        random_state=args.random_state,
    )

    X_trainval, X_test = X.iloc[trainval_idx], X.iloc[test_idx]
    y_trainval, y_test = y.iloc[trainval_idx].to_numpy(), y.iloc[test_idx].to_numpy()
    groups_trainval = groups.iloc[trainval_idx]

    train_idx_rel, val_idx_rel, split_kind_2 = grouped_or_stratified_split(
        X_trainval.reset_index(drop=True),
        pd.Series(y_trainval),
        groups_trainval.reset_index(drop=True),
        test_size=args.val_size,
        random_state=args.random_state + 1,
    )

    X_train = X_trainval.iloc[train_idx_rel]
    X_val = X_trainval.iloc[val_idx_rel]

    y_train = y_trainval[train_idx_rel]
    y_val = y_trainval[val_idx_rel]

    neg = max(int((y_train == 0).sum()), 1)
    pos = max(int((y_train == 1).sum()), 1)
    scale_pos_weight = neg / pos

    preprocessor, numeric_cols, categorical_cols = make_preprocessor(X_train)

    model = XGBClassifier(
        n_estimators=400,
        max_depth=4,
        min_child_weight=5,
        learning_rate=0.05,
        subsample=0.85,
        colsample_bytree=0.85,
        reg_lambda=2.0,
        reg_alpha=0.2,
        objective="binary:logistic",
        eval_metric="aucpr",
        scale_pos_weight=scale_pos_weight,
        random_state=args.random_state,
        n_jobs=-1,
        tree_method="hist",
    )

    pipe = Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("model", model),
        ]
    )

    print("Training leakage-safe XGBoost...")
    pipe.fit(X_train, y_train)

    p_val = pipe.predict_proba(X_val)[:, 1]
    threshold, threshold_info = pick_threshold_for_precision(
        y_val,
        p_val,
        args.target_precision,
    )

    p_test = pipe.predict_proba(X_test)[:, 1]

    test_metrics = evaluate(y_test, p_test, threshold)
    val_metrics = evaluate(y_val, p_val, threshold)

    print("\nValidation metrics:")
    for k, v in val_metrics.items():
        print(f"  {k}: {v}")

    print("\nTest metrics:")
    for k, v in test_metrics.items():
        print(f"  {k}: {v}")

    meta = {
        "model_type": "XGBoost leakage-safe binary classifier",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": os.path.abspath(args.input),
        "label_mode": args.label_mode,
        "epss_threshold_for_label_only": args.epss_threshold,
        "cvss_threshold_for_label_only": args.cvss_threshold,
        "target_precision": args.target_precision,
        "optimal_threshold": threshold,
        "threshold_selection": threshold_info,
        "test_metrics": test_metrics,
        "validation_metrics": val_metrics,
        "rows_loaded": int(len(df_raw)),
        "rows_labeled_used": int(len(df_labeled)),
        "positive_rows": int(y.sum()),
        "negative_rows": int((y == 0).sum()),
        "scale_pos_weight": float(scale_pos_weight),
        "split_kind_train_test": split_kind_1,
        "split_kind_train_val": split_kind_2,
        "group_split_note": "Grouped by advisory/CVE/GHSA/OSV where possible to avoid same-vulnerability leakage.",
        "leakage_policy": {
            "removed_direct_label_signals": [
                "epss_score",
                "cvss_score",
                "severity",
                "label_source",
                "risk/score/priority outputs",
            ],
            "removed_raw_ids": [
                "cve_id",
                "ghsa_id",
                "osv_id",
                "advisory_id",
                "aliases",
            ],
            "removed_exploit_signals": not args.allow_exploit_signal_features,
            "important_note": "EPSS/CVSS/severity may be used to create y, but are not used as X features.",
        },
        "numeric_feature_count": len(numeric_cols),
        "categorical_feature_count": len(categorical_cols),
        "feature_columns_before_preprocessing": X.columns.tolist(),
    }

    with open(out_dir / "model_leakage_safe.pkl", "wb") as f:
        pickle.dump(pipe, f)

    with open(out_dir / "model_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    with open(out_dir / "feature_columns.json", "w", encoding="utf-8") as f:
        json.dump(X.columns.tolist(), f, indent=2)

    pd.DataFrame({"dropped_columns": dropped_cols}).to_csv(
        out_dir / "dropped_leakage_columns.csv",
        index=False,
    )

    pd.DataFrame({"label_source": label_source}).value_counts().reset_index(name="count").to_csv(
        out_dir / "label_source_counts_used.csv",
        index=False,
    )

    print(f"\nSaved model: {out_dir / 'model_leakage_safe.pkl'}")
    print(f"Saved meta:  {out_dir / 'model_meta.json'}")
    print(f"Saved dropped leakage list: {out_dir / 'dropped_leakage_columns.csv'}")

    if test_metrics["aucpr"] > 0.98 or test_metrics["roc_auc"] > 0.98:
        print("\nWARNING: Metrics are still extremely high. Inspect dropped_leakage_columns.csv and feature_columns.json.")
        print("If a direct answer column remains, add it to EXACT_LEAKAGE_COLUMNS or LEAKAGE_SUBSTRINGS.")


if __name__ == "__main__":
    main()
