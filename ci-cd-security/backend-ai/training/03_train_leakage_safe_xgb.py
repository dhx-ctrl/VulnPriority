#!/usr/bin/env python3
"""
Leakage-safe vulnerability risk scoring — FINAL build (v4).

Improvements over v3, all aimed at higher recall + F1 while staying leakage-safe:
  1. RAW TEXT FEATURES   — fetch summary/details from OSV (osv_text_fetcher.py) and
                           build keyword signals (unauthenticated, remote, rce, ...).
                           Falls back to length-based features if the fetch is blocked.
  2. CWE EXPLOITABILITY TIERS — map raw CWE numbers to semantic risk classes
                           (rce / injection / auth-bypass / memory / disclosure / dos).
  3. SAMPLE WEIGHTS      — weight rows by label confidence (borderline EPSS gets less
                           weight than EPSS>=0.30 or CVSS>=9). Reduces label noise.
  4. F-BETA OPTUNA       — tuning objective is out-of-fold F-beta (beta>1 favours
                           recall), not AUCPR, so hyper-parameters land recall-friendly.
                           Early stopping picks the tree count per fold.
  5. STACKING            — XGB + RF + LogReg out-of-fold predictions feed a calibrated
                           logistic-regression meta-learner (leakage-safe via OOF).

Comparison produced every run:
  * OLD model (v1-style fixed params, AUCPR threshold) vs NEW tuned/stacked model.
  * NEW model vs Random Forest, Logistic Regression, single tuned XGB.
  * NEW model vs the CVSS baseline (cvss>=7/8/9 and cvss-as-score AUC).

Leakage controls (unchanged and extended):
  * EPSS / CVSS / severity build the label y only — never features.
  * Label-availability proxies (has_cve/has_ghsa/has_cvss/...) removed.
  * Test set split off FIRST (grouped) and scored once at the very end.
  * Optuna uses grouped CV; preprocessor refit inside each fold.
  * Threshold + stack meta-learner trained on OUT-OF-FOLD predictions only.
  * Sample weights derive from the same signals as the label, never from test.

Run (recommended):
    python 03_train_leakage_safe_xgb.py \
        --input merged_trainable.csv --out-dir model_output_SINGLE_v4 \
        --fetch-text --tune --n-trials 60 --cv-folds 4 \
        --threshold-strategy fbeta --fbeta 2.0 --stack --compare-models
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
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, average_precision_score, confusion_matrix, f1_score, fbeta_score,
    precision_recall_curve, precision_score, recall_score, roc_auc_score, roc_curve,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from xgboost import XGBClassifier

from imblearn.pipeline import Pipeline as ImbPipeline

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

try:
    import optuna
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    HAVE_OPTUNA = True
except Exception:
    HAVE_OPTUNA = False


# --------------------------------------------------------------------------- #
# Column policy
# --------------------------------------------------------------------------- #
TARGET_CANDIDATES = ["label_high_risk", "high_risk_label", "target_high_risk", "target", "label", "y"]
EXACT_LEAKAGE_COLUMNS = {
    "published", "modified", "withdrawn", "year",
    "cwe_id", "all_cwe_ids", "cwe",
    "source_dataset", "data_source", "source_database", "source",
    "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
    "scope", "confidentiality_impact", "integrity_impact", "availability_impact",
    "has_exploit_ref", "feat_has_exploit_ref",
    "label_high_risk", "high_risk_label", "target_high_risk", "target", "label", "y",
    "ai_risk_score", "risk_score", "risk", "priority", "priority_score",
    "exploit_probability", "probability_high_risk", "prediction", "predicted_label",
    "optimal_threshold", "threshold",
    "epss", "epss_score", "epss_percentile", "percentile",
    "cvss", "cvss_score", "cvss_base_score", "cvss_vector",
    "severity", "severity_text", "scanner_severity", "github_severity",
    "ghsa_severity", "database_specific_severity",
    "label_source", "label_from_epss", "label_from_cvss", "label_from_severity",
    "has_cve", "has_ghsa", "has_cvss", "has_severity_text", "feat_has_cve", "feat_has_ghsa",
    "id", "osv_id", "cve_id", "all_cve_ids", "ghsa_id", "all_ghsa_ids",
    "advisory_id", "aliases", "alias", "cve", "ghsa",
    "summary", "details", "description", "title", "references", "ref_urls",
    "raw_summary", "raw_details",  # raw text consumed by feature builder, then dropped
}
LEAKAGE_SUBSTRINGS = ["epss", "cvss", "severity", "label", "target", "risk_score",
                      "ai_risk", "exploit_probability", "priority_score", "threshold"]
EXPLOIT_SIGNAL_SUBSTRINGS = ["kev", "known_exploited", "exploited_in_the_wild",
                             "public_exploit", "exploit_maturity", "metasploit", "poc"]
ID_SUBSTRINGS = ["cve_id", "ghsa_id", "osv_id", "advisory_id", "aliases"]
HIGH_SEVERITIES = {"HIGH", "CRITICAL", "SEVERE"}

# CWE -> exploitability tier (semantic grouping; pure feature engineering, no leakage)
CWE_TIERS = {
    "rce": {94, 95, 96, 502, 78, 77, 917, 434, 1336},      # code/command exec, deserialization, upload
    "injection": {89, 79, 91, 90, 564, 943, 74, 75, 80, 87, 116, 1333, 400},
    "auth_bypass": {287, 306, 862, 863, 285, 269, 522, 798, 259, 640, 384, 613},
    "memory": {119, 120, 121, 122, 125, 787, 416, 415, 476, 190, 191, 824, 763},
    "disclosure": {200, 201, 209, 532, 359, 312, 319, 538, 668},
    "ssrf_path": {918, 22, 23, 36, 59, 706},
    "dos": {400, 401, 770, 834, 674},
}


def cwe_to_tier(cwe_num: Optional[int]) -> str:
    if cwe_num is None:
        return "unknown"
    for tier, members in CWE_TIERS.items():
        if cwe_num in members:
            return tier
    return "other"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Leakage-safe vuln risk model — final build (v4)")
    p.add_argument("--input", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--label-mode", default="hybrid_existing",
                   choices=["hybrid_existing", "hybrid_rebuild", "epss_only"])
    p.add_argument("--epss-threshold", type=float, default=0.10)
    p.add_argument("--cvss-threshold", type=float, default=7.0)

    p.add_argument("--fetch-text", action="store_true",
                   help="Fetch raw summary/details from OSV for NLP features (cached).")
    p.add_argument("--text-cache", default=None, help="Path to OSV text cache JSON.")
    p.add_argument("--max-fetch", type=int, default=None, help="Cap number of new OSV fetches.")
    p.add_argument("--github-token", default=None,
                   help="GitHub PAT for GHSA fallback when OSV fetch fails (optional).")

    p.add_argument("--tune", action="store_true", help="Optuna grouped-CV tuning + early stopping.")
    p.add_argument("--n-trials", type=int, default=60)
    p.add_argument("--cv-folds", type=int, default=4)
    p.add_argument("--early-stopping-rounds", type=int, default=50)
    p.add_argument("--tune-objective", default="aucpr", choices=["fbeta", "f1", "aucpr"],
                   help="Optuna objective on OOF. aucpr (default) optimizes the whole "
                        "precision-recall frontier; the threshold then sets the operating point.")

    p.add_argument("--stack", action="store_true",
                   help="Train a stacking meta-learner over XGB+RF+LogReg OOF predictions.")

    p.add_argument("--threshold-strategy", default="f1",
                   choices=["f1", "fbeta", "f1_macro", "youden", "target_precision"],
                   help="f1 = balanced (default); fbeta = recall mode (set --fbeta).")
    p.add_argument("--fbeta", type=float, default=2.0)
    p.add_argument("--target-precision", type=float, default=0.70)

    p.add_argument("--use-sample-weights", action="store_true", default=True)
    p.add_argument("--no-sample-weights", dest="use_sample_weights", action="store_false")

    p.add_argument("--compare-models", action="store_true")
    p.add_argument("--no-shap", action="store_true")
    p.add_argument("--shap-sample", type=int, default=1500)
    p.add_argument("--test-size", type=float, default=0.20)
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument("--allow-exploit-signal-features", action="store_true")
    return p.parse_args()


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def normalize_missing(s):
    return s.replace({"": np.nan, "nan": np.nan, "None": np.nan, "NONE": np.nan, "null": np.nan})

def safe_join_columns(df, cols):
    if not cols:
        return pd.Series("", index=df.index)
    return (df[cols].fillna("").astype(str)
            .apply(lambda r: " ".join(x for x in r.tolist() if x and x.lower() != "nan"), axis=1))

def first_existing_col(df, candidates):
    lower = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c in df.columns:
            return c
        if c.lower() in lower:
            return lower[c.lower()]
    return None

def to_numeric_series(df, col):
    if col not in df.columns:
        return pd.Series(np.nan, index=df.index)
    return pd.to_numeric(df[col], errors="coerce")

def get_severity_series(df):
    cols = [c for c in df.columns if "severity" in c.lower()]
    if not cols:
        return pd.Series(np.nan, index=df.index, dtype="object")
    out = pd.Series(np.nan, index=df.index, dtype="object")
    for col in cols:
        out = out.where(out.notna(), normalize_missing(df[col].astype(str).str.upper().str.strip()))
    return out


# --------------------------------------------------------------------------- #
# Target + sample weights (EPSS/CVSS/severity used HERE only)
# --------------------------------------------------------------------------- #
def build_target(df, mode, epss_threshold, cvss_threshold):
    df = df.copy()
    if mode == "hybrid_existing":
        tcol = first_existing_col(df, TARGET_CANDIDATES)
        if tcol is not None:
            y = pd.to_numeric(df[tcol], errors="coerce")
            src = df["label_source"].astype(str) if "label_source" in df.columns \
                else pd.Series("existing_label", index=df.index)
            keep = y.notna()
            return df.loc[keep].copy(), y.loc[keep].astype(int), src.loc[keep]
        mode = "hybrid_rebuild"
    epss = to_numeric_series(df, first_existing_col(df, ["epss_score", "epss"]) or "__none__")
    cvss = to_numeric_series(df, first_existing_col(df, ["cvss_score", "cvss_base_score", "cvss"]) or "__none__")
    severity = get_severity_series(df)
    y = pd.Series(np.nan, index=df.index, dtype="float")
    src = pd.Series("unlabeled", index=df.index, dtype="object")
    if mode == "epss_only":
        m = epss.notna(); y.loc[m] = (epss.loc[m] >= epss_threshold).astype(int); src.loc[m] = "epss_only"
    else:
        m = epss.notna(); y.loc[m] = (epss.loc[m] >= epss_threshold).astype(int); src.loc[m] = "epss"
        m = y.isna() & cvss.notna(); y.loc[m] = (cvss.loc[m] >= cvss_threshold).astype(int); src.loc[m] = "cvss"
        m = y.isna() & severity.notna()
        y.loc[m] = severity.loc[m].astype(str).str.upper().str.strip().isin(HIGH_SEVERITIES).astype(int)
        src.loc[m] = "severity"
    keep = y.notna()
    return df.loc[keep].copy(), y.loc[keep].astype(int), src.loc[keep]


def build_sample_weights(df_raw_aligned, y):
    """
    Confidence weight per row, from the SAME signals that built the label.
    High-confidence cases count more; borderline (near-threshold) count less.
    Range ~[0.4, 1.3]. Leakage-safe: derived from label-construction signals only,
    and only ever applied to training rows.
    """
    epss = to_numeric_series(df_raw_aligned, "epss_score").to_numpy()
    cvss = to_numeric_series(df_raw_aligned, "cvss_score").to_numpy()
    w = np.ones(len(y), dtype=float)
    yv = y.to_numpy()
    for i in range(len(y)):
        e, c = epss[i], cvss[i]
        if yv[i] == 1:
            if (not np.isnan(e) and e >= 0.30) or (not np.isnan(c) and c >= 9.0):
                w[i] = 1.30                                   # confident positive
            elif not np.isnan(e) and e < 0.15:
                w[i] = 0.55                                   # borderline positive
            else:
                w[i] = 1.0
        else:
            if not np.isnan(e) and 0.05 <= e < 0.10:
                w[i] = 0.60                                   # borderline negative
            elif (not np.isnan(e) and e < 0.02) or (not np.isnan(c) and c < 4.0):
                w[i] = 1.10                                   # confident negative
            else:
                w[i] = 1.0
    return w


# --------------------------------------------------------------------------- #
# Feature engineering (safe metadata + real text when available)
# --------------------------------------------------------------------------- #
TEXT_PATTERNS = {
    "kw_unauth": r"unauthenticated|without authentication|no authentication|"
                 r"without credentials|anonymous|unauthorized access",
    "kw_remote": r"\bremote\b|remotely|over the network|network-based",
    "kw_rce": r"remote code execution|arbitrary code|\brce\b|code injection|"
              r"execute arbitrary|command execution",
    "kw_no_interaction": r"no user interaction|without interaction|"
                         r"no interaction required|zero[- ]click",
    "kw_priv_esc": r"privilege escalation|escalate privileges|gain root|"
                   r"administrative access|elevation of privilege",
    "kw_injection": r"injection|sql injection|command injection|xss|"
                    r"cross.site scripting|template injection",
    "kw_deserialize": r"deserializ|unserializ|insecure deserialization",
    "kw_bypass": r"bypass|circumvent|defeat the|evade",
    "kw_overflow": r"buffer overflow|heap overflow|stack overflow|out.of.bounds",
    "kw_disclosure": r"information disclosure|sensitive information|data leak|"
                     r"expose|leak.*information",
    "kw_dos": r"denial of service|\bdos\b|crash|resource exhaustion|infinite loop",
    "kw_prototype": r"prototype pollution",
    "kw_path": r"path traversal|directory traversal|\.\./|arbitrary file",
}


def add_features(df, has_real_text):
    df = df.copy()

    # --- CWE tier + raw family ---
    cwe_cols = [c for c in df.columns if "cwe" in c.lower() and c not in ("feat_cwe_family",)]
    cwe_text = safe_join_columns(df, cwe_cols) if cwe_cols else pd.Series("", index=df.index)
    cwe_num = cwe_text.str.extract(r"CWE[-_ ]?(\d+)", expand=False)
    df["feat_cwe_family"] = cwe_num.fillna("UNKNOWN")
    df["feat_has_cwe"] = (df["feat_cwe_family"] != "UNKNOWN").astype(int)
    df["feat_cwe_tier"] = cwe_num.apply(lambda v: cwe_to_tier(int(v)) if pd.notna(v) else "unknown")

    # --- text features ---
    if has_real_text and "raw_summary" in df.columns:
        text = (df["raw_summary"].fillna("").astype(str) + " " +
                df["raw_details"].fillna("").astype(str))
        df["feat_text_len"] = text.str.len().clip(0, 20000)
        df["feat_word_count"] = text.str.split().apply(len).clip(0, 4000)
        for name, pat in TEXT_PATTERNS.items():
            df[f"feat_{name}"] = text.str.contains(pat, case=False, regex=True, na=False).astype(int)
        # count of distinct danger keywords present (a strong aggregate signal)
        kw_cols = [f"feat_{k}" for k in TEXT_PATTERNS]
        df["feat_danger_kw_count"] = df[kw_cols].sum(axis=1)
    else:
        # fallback: length-based proxies only (no raw text available)
        for base in ["summary_len", "details_len"]:
            if base in df.columns:
                df[f"feat_{base}"] = pd.to_numeric(df[base], errors="coerce")

    # --- temporal ---
    for base in ["published", "modified", "withdrawn"]:
        col = first_existing_col(df, [base, f"{base}_date", f"{base}_at"])
        if col:
            df[f"feat_{base}_year"] = df[col].apply(
                lambda v: float(re.search(r"(19|20)\d{2}", str(v)).group(0))
                if pd.notna(v) and re.search(r"(19|20)\d{2}", str(v)) else np.nan)
    for c in ["days_since_published", "days_since_modified"]:
        if c in df.columns:
            df[f"feat_{c}"] = pd.to_numeric(df[c], errors="coerce")

    # --- counts kept directly (safe) ---
    for c in ["references_count", "ranges_count", "versions_count",
              "github_reviewed", "has_patch_ref", "has_advisory_ref", "is_static", "is_dynamic"]:
        if c in df.columns:
            df[f"feat_{c}"] = pd.to_numeric(df[c], errors="coerce")

    # --- package ---
    pkg_col = first_existing_col(df, ["package_name", "pkg_name", "name", "package"])
    if pkg_col:
        pkg = df[pkg_col].astype(str)
        df["feat_package_len"] = pkg.str.len().clip(0, 200)
        df["feat_is_scoped_package"] = pkg.str.startswith("@").astype(int)
        df["feat_package_scope"] = np.where(pkg.str.startswith("@"), pkg.str.split("/").str[0], "unscoped")

    if "scanner_type" in df.columns:
        df["feat_scanner_type"] = df["scanner_type"].astype(str)
    return df


# --------------------------------------------------------------------------- #
# Grouping / selection / split / preprocessing
# --------------------------------------------------------------------------- #
def build_groups(df):
    group = pd.Series(np.nan, index=df.index, dtype="object")
    for col in ["cve_id", "ghsa_id", "osv_id", "advisory_id", "id"]:
        real = first_existing_col(df, [col])
        if real:
            group = group.where(group.notna(), normalize_missing(df[real].astype(str)))
    pkg_col = first_existing_col(df, ["package_name", "pkg_name", "package", "name"])
    pkg = df[pkg_col] if pkg_col else pd.Series("pkg", index=df.index)
    fallback = pkg.astype(str) + "__" + pd.Series(df.index.astype(str), index=df.index)
    return group.where(group.notna(), fallback).astype(str)

def should_drop(col, allow_exploit):
    lc = col.lower()
    if lc in EXACT_LEAKAGE_COLUMNS:
        return True
    if any(s in lc for s in LEAKAGE_SUBSTRINGS):
        return True
    if any(s in lc for s in ID_SUBSTRINGS):
        return True
    if not allow_exploit and any(s in lc for s in EXPLOIT_SIGNAL_SUBSTRINGS):
        return True
    if lc == "fetch_ok":
        return True
    return False

def select_features(df, allow_exploit):
    # keep engineered features + a few safe raw numerics; drop everything risky
    dropped, keep = [], []
    for col in df.columns:
        if col.startswith("feat_"):
            keep.append(col)
        elif should_drop(col, allow_exploit):
            dropped.append(col)
        else:
            # keep only safe numerics/categoricals not already engineered
            keep.append(col)
    X = df[keep].copy()
    extra, n = [], len(X)
    for col in X.columns:
        nu = X[col].nunique(dropna=True)
        if nu <= 1:
            extra.append(col)
        elif X[col].dtype == "object" and n > 0 and nu / n > 0.80:
            extra.append(col)
    if extra:
        X = X.drop(columns=extra); dropped.extend(extra)
    # final guard: never keep a raw-text or id column
    for c in list(X.columns):
        if c in ("raw_summary", "raw_details") or should_drop(c, allow_exploit):
            X = X.drop(columns=[c]); dropped.append(c)
    return X, sorted(set(dropped))

def grouped_or_stratified_split(X, y, groups, test_size, random_state):
    if groups.nunique() >= 10:
        s = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        tr, te = next(s.split(X, y, groups)); return tr, te, "group"
    s = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    tr, te = next(s.split(X, y)); return tr, te, "stratified"

def make_preprocessor(X_train, scale=False):
    num = X_train.select_dtypes(include=[np.number, "bool"]).columns.tolist()
    cat = [c for c in X_train.columns if c not in num]
    try:
        ohe = OneHotEncoder(handle_unknown="ignore", min_frequency=10, sparse_output=False)
    except TypeError:
        ohe = OneHotEncoder(handle_unknown="ignore", min_frequency=10, sparse=False)
    num_steps = [("imp", SimpleImputer(strategy="median"))]
    if scale:
        num_steps.append(("sc", StandardScaler()))
    pre = ColumnTransformer([
        ("num", ImbPipeline(num_steps), num),
        ("cat", ImbPipeline([("imp", SimpleImputer(strategy="most_frequent")), ("oh", ohe)]), cat),
    ], remainder="drop")
    return pre, num, cat


# --------------------------------------------------------------------------- #
# XGBoost helpers / Optuna grouped-CV / stacking
# --------------------------------------------------------------------------- #
def base_xgb_kwargs(random_state):
    return dict(objective="binary:logistic", eval_metric="aucpr",
                tree_method="hist", random_state=random_state, n_jobs=-1)

def _score_oof(y, oof, objective, beta):
    if objective == "aucpr":
        return average_precision_score(y, oof)
    grid = np.linspace(0.05, 0.95, 91)
    if objective == "f1":
        return max(f1_score(y, (oof >= g).astype(int), zero_division=0) for g in grid)
    return max(fbeta_score(y, (oof >= g).astype(int), beta=beta, zero_division=0) for g in grid)

def cv_oof_xgb(params, X, y, folds, early_rounds, random_state, sample_w=None):
    oof = np.zeros(len(X)); iters = []
    for tr_i, va_i in folds:
        pre, _, _ = make_preprocessor(X.iloc[tr_i])
        Xtr = pre.fit_transform(X.iloc[tr_i]); Xva = pre.transform(X.iloc[va_i])
        m = XGBClassifier(n_estimators=3000, early_stopping_rounds=early_rounds,
                          **base_xgb_kwargs(random_state), **params)
        fit_kw = {}
        if sample_w is not None:
            fit_kw["sample_weight"] = sample_w[tr_i]
        m.fit(Xtr, y[tr_i], eval_set=[(Xva, y[va_i])], verbose=False, **fit_kw)
        oof[va_i] = m.predict_proba(Xva)[:, 1]
        iters.append(int(m.best_iteration) if m.best_iteration is not None else m.n_estimators)
    return oof, iters

def tune_xgb(X, y, groups, n_trials, cv_folds, early_rounds, random_state,
             objective, beta, sample_w):
    folds = list(GroupKFold(n_splits=cv_folds).split(X, y, groups))
    spw_max = float(max((y == 0).sum() / max((y == 1).sum(), 1), 1.0))

    def obj(trial):
        params = dict(
            max_depth=trial.suggest_int("max_depth", 3, 7),
            learning_rate=trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
            subsample=trial.suggest_float("subsample", 0.6, 1.0),
            colsample_bytree=trial.suggest_float("colsample_bytree", 0.6, 1.0),
            min_child_weight=trial.suggest_int("min_child_weight", 1, 12),
            reg_lambda=trial.suggest_float("reg_lambda", 1e-2, 20.0, log=True),
            reg_alpha=trial.suggest_float("reg_alpha", 1e-3, 10.0, log=True),
            gamma=trial.suggest_float("gamma", 1e-3, 5.0, log=True),
            scale_pos_weight=trial.suggest_float("scale_pos_weight", 1.0, min(spw_max, 5.0)),
        )
        oof, _ = cv_oof_xgb(params, X, y, folds, early_rounds, random_state, sample_w)
        return _score_oof(y, oof, objective, beta)

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=random_state))
    study.optimize(obj, n_trials=n_trials, show_progress_bar=False)
    oof, iters = cv_oof_xgb(study.best_params, X, y, folds, early_rounds, random_state, sample_w)
    return study.best_params, oof, int(np.median(iters)), iters, folds

def stack_oof(X, y, folds, best_xgb, best_n, random_state, sample_w):
    """Out-of-fold predictions from XGB, RF, LogReg -> meta features (leakage-safe)."""
    oof = {"xgb": np.zeros(len(X)), "rf": np.zeros(len(X)), "lr": np.zeros(len(X))}
    for tr_i, va_i in folds:
        # XGB (scaled n_estimators, no early stop here to keep it simple/stable)
        pre, _, _ = make_preprocessor(X.iloc[tr_i])
        Xtr = pre.fit_transform(X.iloc[tr_i]); Xva = pre.transform(X.iloc[va_i])
        sw = sample_w[tr_i] if sample_w is not None else None
        mx = XGBClassifier(n_estimators=best_n, **base_xgb_kwargs(random_state), **best_xgb)
        mx.fit(Xtr, y[tr_i], sample_weight=sw)
        oof["xgb"][va_i] = mx.predict_proba(Xva)[:, 1]
        mr = RandomForestClassifier(n_estimators=400, min_samples_leaf=2,
                                    class_weight="balanced", random_state=random_state, n_jobs=-1)
        mr.fit(Xtr, y[tr_i], sample_weight=sw)
        oof["rf"][va_i] = mr.predict_proba(Xva)[:, 1]
        pre2, _, _ = make_preprocessor(X.iloc[tr_i], scale=True)
        Xtr2 = pre2.fit_transform(X.iloc[tr_i]); Xva2 = pre2.transform(X.iloc[va_i])
        ml = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=random_state)
        ml.fit(Xtr2, y[tr_i], sample_weight=sw)
        oof["lr"][va_i] = ml.predict_proba(Xva2)[:, 1]
    meta_X = np.column_stack([oof["xgb"], oof["rf"], oof["lr"]])
    meta = LogisticRegression(max_iter=2000, random_state=random_state)
    meta.fit(meta_X, y)
    return meta, oof


# --------------------------------------------------------------------------- #
# Thresholds / evaluation
# --------------------------------------------------------------------------- #
def all_thresholds(y_ref, p_ref, target_precision, beta=2.0):
    out = {}
    P, R, T = precision_recall_curve(y_ref, p_ref)
    f1 = (2 * P[:-1] * R[:-1]) / np.maximum(P[:-1] + R[:-1], 1e-12)
    i = int(np.nanargmax(f1)); out["f1"] = {"threshold": float(T[i])}
    grid = np.linspace(0.02, 0.98, 193)
    fb = [fbeta_score(y_ref, (p_ref >= g).astype(int), beta=beta, zero_division=0) for g in grid]
    out["fbeta"] = {"threshold": float(grid[int(np.argmax(fb))]), "beta": beta}
    mac = [f1_score(y_ref, (p_ref >= g).astype(int), average="macro", zero_division=0) for g in grid]
    out["f1_macro"] = {"threshold": float(grid[int(np.argmax(mac))])}
    fpr, tpr, Tr = roc_curve(y_ref, p_ref)
    out["youden"] = {"threshold": float(Tr[int(np.argmax(tpr - fpr))])}
    cand = np.where(P[:-1] >= target_precision)[0]
    out["target_precision"] = {"threshold": float(T[cand[np.argmax(R[:-1][cand])]]) if len(cand) else float(T[i])}
    return out

def evaluate(y_true, p, threshold):
    from sklearn.metrics import matthews_corrcoef, balanced_accuracy_score
    y_pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    multi = len(np.unique(y_true)) > 1
    return {"threshold": float(threshold), "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            "mcc": float(matthews_corrcoef(y_true, y_pred)) if len(np.unique(y_pred)) > 1 else 0.0,
            "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
            "aucpr": float(average_precision_score(y_true, p)) if multi else float("nan"),
            "roc_auc": float(roc_auc_score(y_true, p)) if multi else float("nan"),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}

def cvss_baseline(df_raw, test_idx_abs, y_test):
    col = first_existing_col(df_raw, ["cvss_score", "cvss_base_score", "cvss"])
    if col is None:
        return {"available": False}
    cvss = pd.to_numeric(df_raw.loc[test_idx_abs, col], errors="coerce")
    have = cvss.notna().to_numpy()
    res = {"available": True, "rows_with_cvss": int(have.sum())}
    if have.sum() > 0 and len(np.unique(y_test[have])) > 1:
        res["auc_cvss_as_score"] = float(roc_auc_score(y_test[have], cvss[have].to_numpy()))
    filled = cvss.fillna(0.0).to_numpy()
    for t in (7.0, 8.0, 9.0):
        yp = (filled >= t).astype(int)
        res[f"cvss_ge_{t}"] = {"precision": float(precision_score(y_test, yp, zero_division=0)),
                               "recall": float(recall_score(y_test, yp, zero_division=0)),
                               "f1": float(f1_score(y_test, yp, zero_division=0)),
                               "f1_macro": float(f1_score(y_test, yp, average="macro", zero_division=0))}
    return res


# --------------------------------------------------------------------------- #
# SHAP
# --------------------------------------------------------------------------- #
def generate_shap(pre, model, X_sample, out_dir):
    try:
        import shap, matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        print(f"SHAP unavailable, skipping: {e}")
        return None
    Xt = pre.transform(X_sample); names = list(pre.get_feature_names_out())
    sv = shap.TreeExplainer(model).shap_values(Xt)
    paths = {}
    plt.figure(); shap.summary_plot(sv, Xt, feature_names=names, show=False, max_display=20)
    plt.tight_layout(); p1 = out_dir / "shap_summary_beeswarm.png"
    plt.savefig(p1, dpi=130, bbox_inches="tight"); plt.close(); paths["beeswarm"] = str(p1)
    plt.figure(); shap.summary_plot(sv, Xt, feature_names=names, plot_type="bar", show=False, max_display=20)
    plt.tight_layout(); p2 = out_dir / "shap_importance_bar.png"
    plt.savefig(p2, dpi=130, bbox_inches="tight"); plt.close(); paths["bar"] = str(p2)
    pd.DataFrame({"feature": names, "mean_abs_shap": np.abs(sv).mean(axis=0)}) \
        .sort_values("mean_abs_shap", ascending=False).to_csv(out_dir / "shap_feature_importance.csv", index=False)
    paths["csv"] = str(out_dir / "shap_feature_importance.csv")
    return paths


# --------------------------------------------------------------------------- #
# A small wrapper so the saved stacked model has .predict_proba
# --------------------------------------------------------------------------- #
class StackedModel:
    """Final stacked predictor: base models -> meta logistic regression."""
    def __init__(self, pre_tree, pre_lin, xgb, rf, lr, meta):
        self.pre_tree = pre_tree; self.pre_lin = pre_lin
        self.xgb = xgb; self.rf = rf; self.lr = lr; self.meta = meta
    def predict_proba(self, X):
        Xt = self.pre_tree.transform(X); Xl = self.pre_lin.transform(X)
        m = np.column_stack([self.xgb.predict_proba(Xt)[:, 1],
                             self.rf.predict_proba(Xt)[:, 1],
                             self.lr.predict_proba(Xl)[:, 1]])
        p = self.meta.predict_proba(m)[:, 1]
        return np.column_stack([1 - p, p])


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    args = parse_args()
    if args.tune and not HAVE_OPTUNA:
        raise SystemExit("--tune requires optuna (pip install optuna).")
    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)

    df_raw = pd.read_csv(args.input, low_memory=False)
    print(f"Loaded rows: {len(df_raw):,}")

    # ---- optional: fetch raw text from OSV ----
    has_real_text = False
    if args.fetch_text:
        try:
            from osv_text_fetcher import fetch_text_for_ids
            cache = args.text_cache or str(out_dir / "osv_text_cache.json")
            ids = df_raw["osv_id"].dropna().tolist() if "osv_id" in df_raw.columns else []
            if ids:
                txt = fetch_text_for_ids(ids, cache_path=cache, max_fetch=args.max_fetch, github_token=getattr(args, "github_token", None))
                df_raw = df_raw.merge(txt, on="osv_id", how="left")
                has_real_text = bool(txt["fetch_ok"].any())
                print(f"Raw text available: {has_real_text} "
                      f"(fetch_ok rate {txt['fetch_ok'].mean():.2f})")
            else:
                print("No osv_id column; skipping text fetch.")
        except Exception as e:
            print(f"Text fetch failed ({e}); using length-based text features.")

    # ---- label + sample weights ----
    df_lab, y, label_source = build_target(df_raw, args.label_mode, args.epss_threshold, args.cvss_threshold)
    abs_index = df_lab.index.copy()
    df_lab = df_lab.reset_index(drop=True); y = y.reset_index(drop=True)
    sample_w_all = build_sample_weights(df_lab, y) if args.use_sample_weights else None
    print(f"Usable rows: {len(df_lab):,} | high-risk: {int(y.sum()):,} ({y.mean():.1%}) | "
          f"sample weights: {'on' if sample_w_all is not None else 'off'}")
    if len(df_lab) < 500 or y.nunique() < 2:
        raise SystemExit("Need >=500 rows and both classes.")

    groups = build_groups(df_lab)
    X, dropped_cols = select_features(add_features(df_lab, has_real_text), args.allow_exploit_signal_features)
    print(f"Features kept: {X.shape[1]:,} | dropped: {len(dropped_cols):,} | real_text_features: {has_real_text}")

    # ---- hold out test FIRST (grouped) ----
    tv_idx, te_idx, k1 = grouped_or_stratified_split(X, y, groups, args.test_size, args.random_state)
    X_tv = X.iloc[tv_idx].reset_index(drop=True); X_test = X.iloc[te_idx]
    y_tv = y.iloc[tv_idx].to_numpy(); y_test = y.iloc[te_idx].to_numpy()
    g_tv = groups.iloc[tv_idx].reset_index(drop=True)
    w_tv = sample_w_all[tv_idx] if sample_w_all is not None else None
    test_idx_abs = abs_index[te_idx]
    print(f"Split[{k1}] -> trainval {len(X_tv)} (pos {int(y_tv.sum())}) | test {len(X_test)} (pos {int(y_test.sum())})")

    comparison_rows = []   # collected for the comparison CSV

    # ===================================================================== #
    # (A) OLD model — v1-style: fixed params, no tuning, no weights, no text-extra,
    #     threshold = max precision>=target (the original "ghost"-prone setup).
    # ===================================================================== #
    print("\n[A] OLD baseline model (fixed params, target-precision threshold)...")
    pre_old, _, _ = make_preprocessor(X_tv)
    old = XGBClassifier(n_estimators=400, max_depth=4, min_child_weight=5, learning_rate=0.05,
                        subsample=0.85, colsample_bytree=0.85, reg_lambda=2.0, reg_alpha=0.2,
                        **base_xgb_kwargs(args.random_state))
    # simple internal val for old threshold
    tr_o, va_o, _ = grouped_or_stratified_split(X_tv, pd.Series(y_tv), g_tv, 0.2, args.random_state + 7)
    pre_old.fit(X_tv.iloc[tr_o])
    old.fit(pre_old.transform(X_tv.iloc[tr_o]), y_tv[tr_o])
    p_va_o = old.predict_proba(pre_old.transform(X_tv.iloc[va_o]))[:, 1]
    Po, Ro, To = precision_recall_curve(y_tv[va_o], p_va_o)
    cand = np.where(Po[:-1] >= 0.70)[0]
    thr_old = float(To[cand[np.argmax(Ro[:-1][cand])]]) if len(cand) else 0.5
    # refit on all trainval, eval test
    pre_old.fit(X_tv); old.fit(pre_old.transform(X_tv), y_tv)
    p_test_old = old.predict_proba(pre_old.transform(X_test))[:, 1]
    old_metrics = evaluate(y_test, p_test_old, thr_old)
    print(f"    OLD: P={old_metrics['precision']:.3f} R={old_metrics['recall']:.3f} "
          f"F1={old_metrics['f1']:.3f} AUC={old_metrics['roc_auc']:.3f}")
    comparison_rows.append({"model": "OLD (fixed params, target-precision thr)", **{
        k: round(old_metrics[k], 4) for k in ["precision", "recall", "f1", "f1_macro", "roc_auc", "aucpr"]}})

    # ===================================================================== #
    # (B) NEW model — tuned XGB (+ optional stacking), recall-oriented threshold.
    # ===================================================================== #
    best_params = None; best_n = None; cv_iters = None; folds = None; oof_main = None
    if args.tune:
        print(f"\n[B] Tuning XGB: {args.n_trials} trials x {args.cv_folds}-fold grouped CV "
              f"(objective={args.tune_objective}, early stop {args.early_stopping_rounds})...")
        best_params, oof_main, best_n, cv_iters, folds = tune_xgb(
            X_tv, y_tv, g_tv, args.n_trials, args.cv_folds, args.early_stopping_rounds,
            args.random_state, args.tune_objective, args.fbeta, w_tv)
        print(f"    best params: {best_params}")
        print(f"    trees (median): {best_n} {cv_iters}")
    else:
        folds = list(GroupKFold(n_splits=args.cv_folds).split(X_tv, y_tv, g_tv))
        best_params = dict(max_depth=4, min_child_weight=5, learning_rate=0.05, subsample=0.85,
                           colsample_bytree=0.85, reg_lambda=2.0, reg_alpha=0.2)
        oof_main, cv_iters = cv_oof_xgb(best_params, X_tv, y_tv, folds,
                                        args.early_stopping_rounds, args.random_state, w_tv)
        best_n = int(np.median(cv_iters))

    if args.stack:
        print("\n[B] Building stacking meta-learner (XGB + RF + LogReg, OOF)...")
        meta, base_oof = stack_oof(X_tv, y_tv, folds, best_params, best_n, args.random_state, w_tv)
        meta_oof = meta.predict_proba(np.column_stack([base_oof["xgb"], base_oof["rf"], base_oof["lr"]]))[:, 1]
        ref_oof = meta_oof
        # fit final base models on ALL trainval, wrap in StackedModel
        pre_tree, _, _ = make_preprocessor(X_tv); Xtv_t = pre_tree.fit_transform(X_tv)
        pre_lin, _, _ = make_preprocessor(X_tv, scale=True); Xtv_l = pre_lin.fit_transform(X_tv)
        fx = XGBClassifier(n_estimators=best_n, **base_xgb_kwargs(args.random_state), **best_params)
        fx.fit(Xtv_t, y_tv, sample_weight=w_tv)
        fr = RandomForestClassifier(n_estimators=400, min_samples_leaf=2, class_weight="balanced",
                                    random_state=args.random_state, n_jobs=-1)
        fr.fit(Xtv_t, y_tv, sample_weight=w_tv)
        fl = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=args.random_state)
        fl.fit(Xtv_l, y_tv, sample_weight=w_tv)
        final_model = StackedModel(pre_tree, pre_lin, fx, fr, fl, meta)
        p_test_new = final_model.predict_proba(X_test)[:, 1]
        new_name = "NEW (stacked: XGB+RF+LogReg)"
        shap_pre, shap_model = pre_tree, fx
    else:
        ref_oof = oof_main
        pre_new, _, _ = make_preprocessor(X_tv); Xtv_t = pre_new.fit_transform(X_tv)
        fx = XGBClassifier(n_estimators=best_n, **base_xgb_kwargs(args.random_state), **best_params)
        fx.fit(Xtv_t, y_tv, sample_weight=w_tv)
        final_model = ImbPipeline([("preprocess", pre_new), ("model", fx)])
        p_test_new = fx.predict_proba(pre_new.transform(X_test))[:, 1]
        new_name = "NEW (tuned XGB)"
        shap_pre, shap_model = pre_new, fx

    # threshold from OOF (unbiased), evaluate on test
    thr_table = all_thresholds(y_tv, ref_oof, args.target_precision, beta=args.fbeta)
    chosen_threshold = thr_table[args.threshold_strategy]["threshold"]

    # ---- recommended operating points for an exploitation-likelihood triage model ----
    # Two principled points on the precision/recall frontier, both chosen on OOF:
    #   balanced   = max F1 (also maximizes F1-macro & MCC here) -> the default
    #   high_recall= max F-beta(1.5) -> catch more exploitable vulns, accept more FPs
    from sklearn.metrics import matthews_corrcoef as _mcc
    _grid = np.linspace(0.02, 0.98, 481)
    t_balanced = float(_grid[int(np.argmax(
        [f1_score(y_tv, (ref_oof >= t).astype(int), zero_division=0) for t in _grid]))])
    t_high_recall = float(_grid[int(np.argmax(
        [fbeta_score(y_tv, (ref_oof >= t).astype(int), beta=1.5, zero_division=0) for t in _grid]))])
    operating_points = {
        "balanced_default": {"threshold": t_balanced, "rationale":
            "max F1 on OOF; also maximizes F1-macro and MCC. Best single-number balance.",
            "test": evaluate(y_test, p_test_new, t_balanced)},
        "high_recall_mode": {"threshold": t_high_recall, "rationale":
            "max F-beta(1.5) on OOF; favours catching exploitable vulns (recall) at the "
            "cost of more false positives. Use when a missed vuln is much worse than a FP.",
            "test": evaluate(y_test, p_test_new, t_high_recall)},
    }
    # default the model to the balanced point unless the user forced another strategy
    if args.threshold_strategy == "f1":
        chosen_threshold = t_balanced
    new_metrics = evaluate(y_test, p_test_new, chosen_threshold)
    print(f"\n[B] {new_name}  (threshold {args.threshold_strategy}={chosen_threshold:.3f})")
    for k in ["precision", "recall", "f1", "f1_macro", "mcc", "roc_auc", "aucpr"]:
        print(f"    {k}: {new_metrics[k]:.4f}")
    print(f"    confusion: TP={new_metrics['tp']} FP={new_metrics['fp']} "
          f"FN={new_metrics['fn']} TN={new_metrics['tn']}")

    print("\n[B] RECOMMENDED OPERATING POINTS (ROC-AUC & AUCPR are threshold-independent):")
    print(f"    ROC-AUC={new_metrics['roc_auc']:.4f}  AUCPR={new_metrics['aucpr']:.4f}  (fixed, cannot be traded)")
    for nm_, op in operating_points.items():
        m = op["test"]
        print(f"    {nm_:18s} thr={op['threshold']:.3f} | P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f} F1m={m['f1_macro']:.3f} MCC={m['mcc']:.3f}")
    comparison_rows.append({"model": new_name, **{
        k: round(new_metrics[k], 4) for k in ["precision", "recall", "f1", "f1_macro", "roc_auc", "aucpr"]}})

    # threshold sweep table
    print("\n[B] Threshold options (OOF-chosen, eval on test):")
    sweep = []
    for strat, info in thr_table.items():
        m = evaluate(y_test, p_test_new, info["threshold"])
        mark = "*" if strat == args.threshold_strategy else " "
        print(f"   {mark} {strat:16s} thr={info['threshold']:.3f} P={m['precision']:.3f} "
              f"R={m['recall']:.3f} F1={m['f1']:.3f} F1m={m['f1_macro']:.3f}")
        sweep.append({"strategy": strat, "threshold": info["threshold"],
                      "precision": m["precision"], "recall": m["recall"],
                      "f1": m["f1"], "f1_macro": m["f1_macro"]})
    pd.DataFrame(sweep).to_csv(out_dir / "threshold_comparison.csv", index=False)

    # ===================================================================== #
    # (C) Other algorithms (same features), at the chosen threshold.
    # ===================================================================== #
    if args.compare_models:
        print("\n[C] Other algorithms (same pipeline & threshold):")
        # RF
        pre_rf, _, _ = make_preprocessor(X_tv); Xtv_r = pre_rf.fit_transform(X_tv)
        rf = RandomForestClassifier(n_estimators=400, min_samples_leaf=2, class_weight="balanced",
                                    random_state=args.random_state, n_jobs=-1)
        rf.fit(Xtv_r, y_tv, sample_weight=w_tv)
        p_rf = rf.predict_proba(pre_rf.transform(X_test))[:, 1]
        # LogReg
        pre_lr, _, _ = make_preprocessor(X_tv, scale=True); Xtv_lr = pre_lr.fit_transform(X_tv)
        lr = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=args.random_state)
        lr.fit(Xtv_lr, y_tv, sample_weight=w_tv)
        p_lr = lr.predict_proba(pre_lr.transform(X_test))[:, 1]
        for nm, pp in [("Random Forest", p_rf), ("Logistic Regression", p_lr)]:
            mm = evaluate(y_test, pp, chosen_threshold)
            print(f"    {nm:20s} P={mm['precision']:.3f} R={mm['recall']:.3f} "
                  f"F1={mm['f1']:.3f} AUC={mm['roc_auc']:.3f} AUCPR={mm['aucpr']:.3f}")
            comparison_rows.append({"model": nm, **{
                k: round(mm[k], 4) for k in ["precision", "recall", "f1", "f1_macro", "roc_auc", "aucpr"]}})

    # ===================================================================== #
    # (D) CVSS baseline.
    # ===================================================================== #
    base = cvss_baseline(df_raw, test_idx_abs, y_test)
    if base.get("available"):
        best_t = max(("7.0", "8.0", "9.0"), key=lambda t: base[f"cvss_ge_{t}"]["f1"])
        bb = base[f"cvss_ge_{best_t}"]
        print(f"\n[D] CVSS baseline: AUC={base.get('auc_cvss_as_score', float('nan')):.3f} | "
              f"best cvss>={best_t}: P={bb['precision']:.3f} R={bb['recall']:.3f} F1={bb['f1']:.3f}")
        comparison_rows.append({"model": f"CVSS baseline (cvss>={best_t})",
                                "precision": round(bb["precision"], 4), "recall": round(bb["recall"], 4),
                                "f1": round(bb["f1"], 4), "f1_macro": round(bb["f1_macro"], 4),
                                "roc_auc": round(base.get("auc_cvss_as_score", float("nan")), 4),
                                "aucpr": None})

    # ---- comparison CSV + console table ----
    cmp_df = pd.DataFrame(comparison_rows)
    cmp_df.to_csv(out_dir / "model_comparison.csv", index=False)
    print("\n================ FINAL COMPARISON (test set) ================")
    print(cmp_df.to_string(index=False))
    print("=============================================================")

    # ---- SHAP ----
    shap_paths = None
    if not args.no_shap:
        print("\nGenerating SHAP for the XGB component...")
        n = min(args.shap_sample, len(X_test))
        shap_paths = generate_shap(shap_pre, shap_model, X_test.iloc[:n], out_dir)
        if shap_paths:
            print(f"    saved {shap_paths.get('beeswarm')}")

    # ---- persist ----
    meta_json = {
        "model_type": ("XGBoost stacked ensemble (v4)" if args.stack else "XGBoost tuned (v4)"),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": os.path.abspath(args.input),
        "real_text_features": has_real_text, "sample_weights": bool(args.use_sample_weights),
        "tuned": bool(args.tune), "tune_objective": args.tune_objective,
        "stacked": bool(args.stack), "n_trials": args.n_trials if args.tune else None,
        "cv_folds": args.cv_folds, "best_params": best_params,
        "n_estimators_early_stopping": best_n, "per_fold_best_iteration": cv_iters,
        "threshold_strategy": args.threshold_strategy, "fbeta": args.fbeta,
        "chosen_threshold": chosen_threshold, "threshold_table": thr_table,
        "recommended_operating_points": operating_points,
        "new_model_test_metrics": new_metrics, "old_model_test_metrics": old_metrics,
        "comparison": comparison_rows, "cvss_baseline": base,
        "rows_loaded": int(len(df_raw)), "rows_used": int(len(df_lab)),
        "positive_rate": float(y.mean()), "split_kind": k1,
        "feature_columns": X.columns.tolist(),
        "leakage_controls": [
            "EPSS/CVSS/severity build label only, never features",
            "label-availability proxies removed",
            "test split off first, scored once",
            "grouped CV, preprocessor refit per fold",
            "threshold + stack meta-learner from OOF predictions",
            "sample weights from label-construction signals, train-only",
        ],
        "shap_artifacts": shap_paths,
    }
    with open(out_dir / "model_leakage_safe.pkl", "wb") as f:
        pickle.dump(final_model, f)
    with open(out_dir / "model_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta_json, f, indent=2, default=str)
    with open(out_dir / "feature_columns.json", "w", encoding="utf-8") as f:
        json.dump(X.columns.tolist(), f, indent=2)
    pd.DataFrame({"dropped_columns": dropped_cols}).to_csv(out_dir / "dropped_leakage_columns.csv", index=False)
    print(f"\nSaved everything to: {out_dir.resolve()}")


if __name__ == "__main__":
    main()