"""Single-model AI scoring service for VulnPriority.

This replaces the old dual-model setup. The backend now loads one trained
stacked model and exposes one risk score. The old clean_* and operational_*
fields are still emitted as temporary compatibility aliases for the current
frontend/database schema.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

from core.config import AI_MODEL_DIR, AI_MODEL_FILE, BASE_DIR, log


class StackedModel:
    """Loader/runtime class for the v4 stacked model pickled from training.

    The uploaded model was pickled from a training script where this class lived
    in __main__. Pickle/joblib therefore needs a class with the same name to
    exist at load time. Runtime prediction uses:
      XGB + RF on the tree preprocessor,
      Logistic Regression on the linear preprocessor,
      then a meta Logistic Regression over the three probabilities.
    """

    def predict_proba(self, X):
        x_tree = self.pre_tree.transform(X)
        x_lin = self.pre_lin.transform(X)

        base_probs = np.column_stack([
            self.xgb.predict_proba(x_tree)[:, 1],
            self.rf.predict_proba(x_tree)[:, 1],
            self.lr.predict_proba(x_lin)[:, 1],
        ])

        return self.meta.predict_proba(base_probs)

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


# The pickle references __main__.StackedModel. Make it resolvable even when
# uvicorn imports this module normally.
setattr(sys.modules.get("__main__"), "StackedModel", StackedModel)


# ══════════════════════════════════════════════════════════════════════════════
# DefectDojo/scanner helper constants kept here because services.defectdojo
# imports them for normalization.
# ══════════════════════════════════════════════════════════════════════════════

_SEV_CVSS_FALLBACK = {
    "Critical": 9.0,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Info": 0.5,
}

_SAST_TOOLS = {
    "semgrep", "semgrep json", "bandit", "flake8", "sonarqube", "sonar",
    "checkmarx", "sast", "eslint", "codeql", "static analysis",
}
_DAST_TOOLS = {
    "zap", "owasp zap", "zaproxy", "zaproxy baseline", "burp", "nikto",
    "dast", "nuclei", "nessus", "dynamic analysis",
}
_SCA_TOOLS = {
    "trivy", "trivy scan", "trivy filesystem", "trivy image",
    "npm audit", "npm-audit", "dependency-check", "dependency check",
    "dependency scanning", "vulnerable dependency", "sca", "snyk", "osv",
    "grype", "container", "image scan", "package", "component",
}


# ══════════════════════════════════════════════════════════════════════════════
# Artifact loading
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_model_dir() -> Path:
    candidate = Path(AI_MODEL_DIR)
    if not candidate.is_absolute():
        candidate = BASE_DIR / candidate
    return candidate


def _pick_model_file(model_dir: Path) -> Path:
    if AI_MODEL_FILE:
        p = Path(AI_MODEL_FILE)
        if not p.is_absolute():
            p = model_dir / p
        return p

    for name in ("model_leakage_safe.pkl", "model.pkl", "model.joblib", "model_v4.pkl"):
        p = model_dir / name
        if p.exists():
            return p

    raise FileNotFoundError(
        f"No model artifact found in {model_dir}. Expected model_leakage_safe.pkl, model.pkl, or model.joblib."
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_sha256_if_present(path: Path) -> Optional[str]:
    sha_path = path.with_name(path.name + ".sha256")
    if not sha_path.exists():
        log.warning(f"No SHA-256 file found for {path.name}; loading without integrity verification.")
        return None

    expected = sha_path.read_text(encoding="utf-8").strip().split()[0].lower()
    actual = _sha256_file(path)

    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ValueError(f"Invalid SHA-256 content in {sha_path}")

    if not secrets.compare_digest(expected, actual):
        raise RuntimeError(
            f"SHA-256 integrity check failed for {path.name}. Expected {expected}, got {actual}."
        )

    log.info(f"SHA-256 verified for {path.name}: {actual}")
    return actual


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required JSON artifact not found: {path}")
    _verify_sha256_if_present(path)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_features(path: Path, meta: Dict[str, Any]) -> List[str]:
    if path.exists():
        data = _load_json(path)
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise ValueError("feature_columns.json must be a JSON list of strings.")
        return data

    features = meta.get("feature_columns") or meta.get("features") or meta.get("feature_columns_before_preprocessing")
    if not features:
        raise FileNotFoundError(f"Missing feature_columns.json and no feature list in {path.parent / 'model_meta.json'}")
    return list(features)


def _choose_threshold(meta: Dict[str, Any]) -> float:
    # New v4 metadata uses chosen_threshold = 0.386.
    for key in ("chosen_threshold", "optimal_threshold", "threshold"):
        val = meta.get(key)
        try:
            if val is not None:
                return float(val)
        except (TypeError, ValueError):
            pass

    try:
        return float(meta["recommended_operating_points"]["balanced_default"]["threshold"])
    except Exception:
        pass

    try:
        return float(meta["threshold_table"]["f1"]["threshold"])
    except Exception:
        pass

    return 0.5


def _model_version(meta: Dict[str, Any]) -> str:
    return str(
        meta.get("model_type")
        or meta.get("model_version")
        or meta.get("created_at_utc")
        or "single-risk-model"
    )


MODEL_DIR = _resolve_model_dir()
MODEL_PATH = _pick_model_file(MODEL_DIR)
_verify_sha256_if_present(MODEL_PATH)
MODEL = joblib.load(MODEL_PATH)

MODEL_META = _load_json(MODEL_DIR / "model_meta.json")
FEATURES = _load_features(MODEL_DIR / "feature_columns.json", MODEL_META)
OPTIMAL_THRESHOLD = _choose_threshold(MODEL_META)
MODEL_VERSION = _model_version(MODEL_META)

log.info(
    f"Single AI model loaded from {MODEL_PATH} "
    f"(threshold={OPTIMAL_THRESHOLD}, features={len(FEATURES)}, version={MODEL_VERSION})"
)


# ══════════════════════════════════════════════════════════════════════════════
# Feature helpers
# ══════════════════════════════════════════════════════════════════════════════

def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if text.lower() in {"", "none", "null", "nan"}:
        return default
    return text


def _parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    text = _safe_str(value)
    if not text:
        return None

    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        match = re.search(r"(19|20)\d{2}", text)
        if match:
            return datetime(int(match.group(0)), 1, 1, tzinfo=timezone.utc)

    return None


def _days_since(value: Any) -> Optional[float]:
    dt = _parse_datetime(value)
    if not dt:
        return None
    return float((datetime.now(timezone.utc) - dt).days)


def _year_from_any(*values: Any) -> Optional[int]:
    for value in values:
        if value is None:
            continue

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            year = int(value)
            if 1990 <= year <= 2100:
                return year

        dt = _parse_datetime(value)
        if dt:
            return int(dt.year)

        match = re.search(r"(19|20)\d{2}", str(value))
        if match:
            return int(match.group(0))

    return None


def _count_references(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    text = str(value)
    http_count = len(re.findall(r"https?://", text, flags=re.I))
    if http_count:
        return http_count
    return 1 if text.strip() else 0


def normalise_cwe(raw: Any) -> int:
    if raw is None:
        return 0
    cleaned = str(raw).strip().upper().replace("CWE-", "").split(".")[0]
    try:
        return int(cleaned)
    except ValueError:
        return 0


def year_from_cve(cve_id: Optional[str]) -> Optional[int]:
    if not cve_id:
        return None
    match = re.search(r"CVE-(\d{4})-\d+", str(cve_id), re.IGNORECASE)
    return int(match.group(1)) if match else None


def _cwe_tier(cwe_int: int) -> str:
    if not cwe_int:
        return "UNKNOWN"

    # Broad categories, deliberately simple. The one-hot encoder handles
    # unknown values gracefully.
    if cwe_int in {78, 79, 89, 90, 91, 94, 95, 96, 97, 98, 99, 564, 643, 652, 917}:
        return "injection"
    if cwe_int in {22, 23, 35, 36, 73, 200, 201, 209, 284, 285, 287, 306, 319, 352, 522, 532, 798, 862, 863}:
        return "access_control_or_disclosure"
    if cwe_int in {119, 120, 121, 122, 125, 190, 191, 416, 787, 788}:
        return "memory_safety"
    if cwe_int in {400, 401, 404, 770, 772}:
        return "availability"
    if cwe_int in {20, 74, 77, 502, 611, 918}:
        return "input_parsing"
    return "other"


def _contains_any(text: str, words: Tuple[str, ...]) -> int:
    return int(any(re.search(pattern, text, flags=re.I) for pattern in words))


def _build_feature_frame(payload: Any) -> Tuple[pd.DataFrame, int, int]:
    cwe_source = getattr(payload, "cwe_id", None) if getattr(payload, "cwe_id", None) is not None else getattr(payload, "cwe", None)
    cwe_int = normalise_cwe(cwe_source)

    year = (
        getattr(payload, "year", None)
        or year_from_cve(getattr(payload, "cve_id", None))
        or _year_from_any(getattr(payload, "published", None), getattr(payload, "published_year", None))
        or 2022
    )

    package_name = (
        _safe_str(getattr(payload, "package_name", None))
        or _safe_str(getattr(payload, "component_name", None))
        or "UNKNOWN_PACKAGE"
    )

    title = _safe_str(getattr(payload, "title", None))
    description = _safe_str(getattr(payload, "description", None))
    references = _safe_str(getattr(payload, "references", None))
    details_text = " ".join(
        x for x in [
            description,
            _safe_str(getattr(payload, "file_path", None)),
            _safe_str(getattr(payload, "component_name", None)),
            _safe_str(getattr(payload, "component_version", None)),
            _safe_str(getattr(payload, "vulnerability_id", None)),
            references,
        ] if x
    )

    full_text = f"{title} {details_text}".strip()
    full_text_l = full_text.lower()

    published_value = getattr(payload, "published", None) or getattr(payload, "year", None) or year
    modified_value = getattr(payload, "modified", None)
    withdrawn_value = getattr(payload, "withdrawn", None)

    published_year = (
        getattr(payload, "published_year", None)
        or _year_from_any(published_value, getattr(payload, "cve_id", None))
        or year
    )
    modified_year = _year_from_any(modified_value)
    withdrawn_year = _year_from_any(withdrawn_value)

    summary_len = getattr(payload, "summary_len", None)
    if summary_len is None:
        summary_len = len(title)

    details_len = getattr(payload, "details_len", None)
    if details_len is None:
        details_len = len(details_text)

    references_count = int(getattr(payload, "references_count", None) or _count_references(getattr(payload, "references", None)))

    has_patch_ref = bool(
        getattr(payload, "has_patch_ref", False)
        or re.search(r"\b(patch|patched|fixed|fix|commit|pull request|pr/|upgrade|update)\b", full_text_l)
    )
    has_advisory_ref = bool(
        getattr(payload, "has_advisory_ref", False)
        or re.search(r"\b(advisory|nvd|osv|ghsa|github advisory|cve)\b", full_text_l)
    )

    scanner_type = _safe_str(getattr(payload, "scanner_type", None), "SCA").upper()
    is_static = int(bool(getattr(payload, "is_static", False)))
    is_dynamic = int(bool(getattr(payload, "is_dynamic", False)))

    has_cve = bool(
        getattr(payload, "has_cve", False)
        or getattr(payload, "cve_id", None)
        or _safe_str(getattr(payload, "vulnerability_id", "")).upper().startswith("CVE-")
    )

    kw = {
        "feat_kw_unauth": _contains_any(full_text_l, (r"\bunauth", r"without authentication", r"no authentication")),
        "feat_kw_remote": _contains_any(full_text_l, (r"\bremote\b", r"network", r"over the network")),
        "feat_kw_rce": _contains_any(full_text_l, (r"\brce\b", r"remote code execution", r"arbitrary code", r"command execution")),
        "feat_kw_no_interaction": _contains_any(full_text_l, (r"no user interaction", r"without user interaction", r"zero[- ]click")),
        "feat_kw_priv_esc": _contains_any(full_text_l, (r"privilege escalation", r"privileges?", r"\bprivesc\b", r"elevation of privilege")),
        "feat_kw_injection": _contains_any(full_text_l, (r"injection", r"\bsqli\b", r"sql injection", r"command injection", r"xss", r"cross-site scripting")),
        "feat_kw_deserialize": _contains_any(full_text_l, (r"deseriali", r"unseriali")),
        "feat_kw_bypass": _contains_any(full_text_l, (r"bypass", r"circumvent")),
        "feat_kw_overflow": _contains_any(full_text_l, (r"overflow", r"out[- ]of[- ]bounds", r"buffer")),
        "feat_kw_disclosure": _contains_any(full_text_l, (r"disclosure", r"information leak", r"exposure", r"sensitive")),
        "feat_kw_dos": _contains_any(full_text_l, (r"denial of service", r"\bdos\b", r"crash", r"resource exhaustion")),
        "feat_kw_prototype": _contains_any(full_text_l, (r"prototype pollution",)),
        "feat_kw_path": _contains_any(full_text_l, (r"path traversal", r"directory traversal", r"\.\./")),
    }
    danger_kw_count = int(sum(kw.values()))

    row: Dict[str, Any] = {
        "package_name": package_name,
        "published_year": published_year,
        "days_since_published": _days_since(published_value),
        "days_since_modified": _days_since(modified_value),
        "ranges_count": int(getattr(payload, "ranges_count", 0) or 0),
        "versions_count": int(getattr(payload, "versions_count", 0) or (1 if getattr(payload, "component_version", None) else 0)),
        "summary_len": int(summary_len or 0),
        "details_len": int(details_len or 0),
        "references_count": references_count,
        "github_reviewed": int(bool(getattr(payload, "github_reviewed", False))),
        "has_patch_ref": int(has_patch_ref),
        "has_advisory_ref": int(has_advisory_ref),
        "scanner_type": scanner_type,
        "is_static": is_static,
        "is_dynamic": is_dynamic,

        "feat_cwe_family": str(cwe_int) if cwe_int else "UNKNOWN",
        "feat_has_cwe": int(cwe_int != 0),
        "feat_cwe_tier": _cwe_tier(cwe_int),
        "feat_text_len": int(len(full_text)),
        "feat_word_count": int(len(re.findall(r"\b\w+\b", full_text))),
        **kw,
        "feat_danger_kw_count": danger_kw_count,
        "feat_published_year": published_year,
        "feat_modified_year": modified_year,
        "feat_withdrawn_year": withdrawn_year,
        "feat_days_since_published": _days_since(published_value),
        "feat_days_since_modified": _days_since(modified_value),
        "feat_references_count": references_count,
        "feat_ranges_count": int(getattr(payload, "ranges_count", 0) or 0),
        "feat_versions_count": int(getattr(payload, "versions_count", 0) or (1 if getattr(payload, "component_version", None) else 0)),
        "feat_github_reviewed": int(bool(getattr(payload, "github_reviewed", False))),
        "feat_has_patch_ref": int(has_patch_ref),
        "feat_has_advisory_ref": int(has_advisory_ref),
        "feat_is_static": is_static,
        "feat_is_dynamic": is_dynamic,
        "feat_package_len": int(len(package_name)),
        "feat_is_scoped_package": int(package_name.startswith("@")),
        "feat_package_scope": package_name.split("/")[0] if package_name.startswith("@") else "unscoped",
        "feat_scanner_type": scanner_type,
    }

    missing = [f for f in FEATURES if f not in row]
    if missing:
        raise ValueError(f"Feature builder missing model feature(s): {missing}")

    frame = pd.DataFrame([{col: row.get(col) for col in FEATURES}], columns=FEATURES)
    return frame, cwe_int, int(year)


def resolve_features(payload: Any) -> Tuple[pd.DataFrame, int, int]:
    """Convert an API/DefectDojo payload into the single model feature frame."""
    return _build_feature_frame(payload)


def _risk_category(score: float) -> str:
    if score < 30:
        return "Low"
    if score < 70:
        return "Medium"
    return "High"


def run_model(row: pd.DataFrame) -> Dict[str, Any]:
    """Run the single model and return canonical + compatibility fields."""
    prob = float(MODEL.predict_proba(row)[0][1])
    score = round(prob * 100, 2)
    is_high = bool(prob >= OPTIMAL_THRESHOLD)
    category = _risk_category(score)

    result = {
        "exploit_probability": round(prob, 4),
        "risk_score": score,
        "risk_category": category,
        "is_high_risk": is_high,
        "threshold_used": float(OPTIMAL_THRESHOLD),
        "model_version": MODEL_VERSION,

        # Temporary compatibility aliases for old frontend/db columns.
        "clean_exploit_probability": round(prob, 4),
        "clean_ai_score": score,
        "clean_ai_category": category,
        "clean_is_high_risk": is_high,
        "clean_threshold_used": float(OPTIMAL_THRESHOLD),
        "clean_model_version": MODEL_VERSION,

        "operational_exploit_probability": round(prob, 4),
        "operational_rank_score": score,
        "operational_rank_category": category,
        "operational_is_high_risk": is_high,
        "operational_threshold_used": float(OPTIMAL_THRESHOLD),
        "operational_rank_percentile": None,
        "operational_model_version": MODEL_VERSION,
    }
    return result


# Backwards-compatible name for any stale import during transition.
def run_binary(row: pd.DataFrame) -> Dict[str, Any]:
    return run_model(row)


# Backwards-compatible names so older imports do not immediately explode.
CLEAN_FEATURES = FEATURES
RANKER_FEATURES = FEATURES
CLEAN_MODEL_VERSION = MODEL_VERSION
RANKER_MODEL_VERSION = MODEL_VERSION
CLEAN_OPTIMAL_THRESHOLD = OPTIMAL_THRESHOLD
RANKER_OPTIMAL_THRESHOLD = OPTIMAL_THRESHOLD
