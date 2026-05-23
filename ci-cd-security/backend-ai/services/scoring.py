"""Model artifact loading, feature engineering, and dual-model scoring."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import pandas as pd

from core.config import BASE_DIR, log
from schemas import VulnFeatures

def _sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file, streaming in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _read_expected_sha256(sha_path: Path) -> str:
    """Read a .sha256 file containing either '<hash>' or '<hash>  filename'."""
    if not sha_path.exists():
        raise FileNotFoundError(
            f"Missing SHA-256 integrity file: {sha_path}\n"
            "Generate it after training with: certutil -hashfile <artifact> SHA256"
        )

    raw = sha_path.read_text(encoding="utf-8").strip()
    if not raw:
        raise ValueError(f"SHA-256 file is empty: {sha_path}")

    expected = raw.split()[0].strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ValueError(
            f"Invalid SHA-256 format in {sha_path}. Expected 64 hex characters."
        )
    return expected

def _verify_sha256(path: Path) -> str:
    """Verify '<artifact>.sha256' before loading any model/metadata artifact."""
    if not path.exists():
        raise FileNotFoundError(f"Required artifact file not found: {path}")

    sha_path = path.with_name(path.name + ".sha256")
    expected = _read_expected_sha256(sha_path)
    actual = _sha256_file(path)

    if not secrets.compare_digest(actual, expected):
        raise RuntimeError(
            "SHA-256 integrity check failed for artifact.\n"
            f"File:     {path}\n"
            f"Expected: {expected}\n"
            f"Actual:   {actual}\n"
            "Refusing to start because the artifact may be corrupted or tampered with."
        )

    log.info(f"SHA-256 verified for {path.name}: {actual}")
    return actual

def _load_model_artifact(path: Path, label: str) -> Any:
    """Load a trusted sklearn/joblib artifact only after SHA-256 verification."""
    _verify_sha256(path)
    try:
        return joblib.load(path)
    except Exception as exc:
        raise RuntimeError(f"Could not load {label} from {path}: {exc}") from exc

def _load_json(path: Path) -> Dict:
    _verify_sha256(path)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def _resolve_model_dir(env_name: str, default_subdir: str, fallback_env: Optional[str] = None) -> Path:
    configured = os.getenv(env_name, "").strip()
    if not configured and fallback_env:
        configured = os.getenv(fallback_env, "").strip()
    if configured:
        candidate = Path(configured)
        if not candidate.is_absolute():
            candidate = BASE_DIR / candidate
        return candidate
    return BASE_DIR / default_subdir

def _load_feature_columns(path: Path, meta: Dict) -> List[str]:
    if path.exists():
        data = _load_json(path)
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise ValueError(f"feature_columns.json must be a JSON list of strings: {path}")
        return data

    # Fallback for older leakage-safe metadata files.
    features = meta.get("feature_columns_before_preprocessing") or meta.get("features")
    if not features:
        raise FileNotFoundError(
            f"Required feature file not found: {path}. "
            "Expected feature_columns.json or feature list inside model_meta.json."
        )
    return list(features)

def _model_version(meta: Dict) -> str:
    return str(
        meta.get("model_version")
        or meta.get("model_type")
        or meta.get("created_at_utc")
        or "leakage-safe-xgb"
    )

def _load_pipeline_bundle(model_dir: Path, label: str) -> Dict[str, Any]:
    model = _load_model_artifact(model_dir / "model_leakage_safe.pkl", label)
    meta = _load_json(model_dir / "model_meta.json")
    features = _load_feature_columns(model_dir / "feature_columns.json", meta)
    threshold = float(meta.get("optimal_threshold", 0.5))
    version = _model_version(meta)
    log.info(
        f"{label} loaded from {model_dir} "
        f"(threshold={threshold}, features={len(features)}, version={version})"
    )
    return {
        "label": label,
        "dir": model_dir,
        "model": model,
        "meta": meta,
        "features": features,
        "threshold": threshold,
        "version": version,
    }


CLEAN_MODEL_DIR = _resolve_model_dir(
    "AI_CLEAN_MODEL_DIR",
    "model_output_FINAL_clean_minimal_features",
    fallback_env="AI_MODEL_DIR",
)
RANKER_MODEL_DIR = _resolve_model_dir(
    "AI_RANKER_MODEL_DIR",
    "model_output_EPSS_operational_ranker",
)

clean_bundle = _load_pipeline_bundle(CLEAN_MODEL_DIR, "clean leakage-safe triage model")
ranker_bundle = _load_pipeline_bundle(RANKER_MODEL_DIR, "EPSS operational ranking model")

# Constants kept for older code / frontend compatibility.
MODEL_DIR = RANKER_MODEL_DIR
model_binary = ranker_bundle["model"]
meta_binary = ranker_bundle["meta"]
OPTIMAL_THRESHOLD: float = float(ranker_bundle["threshold"])
BINARY_FEATURES: List[str] = list(ranker_bundle["features"])
BINARY_MODEL_VERSION: str = str(ranker_bundle["version"])

CLEAN_OPTIMAL_THRESHOLD: float = float(clean_bundle["threshold"])
CLEAN_FEATURES: List[str] = list(clean_bundle["features"])
CLEAN_MODEL_VERSION: str = str(clean_bundle["version"])

RANKER_OPTIMAL_THRESHOLD: float = float(ranker_bundle["threshold"])
RANKER_FEATURES: List[str] = list(ranker_bundle["features"])
RANKER_MODEL_VERSION: str = str(ranker_bundle["version"])


# ══════════════════════════════════════════════════════════════════════════════
# LOOKUP TABLES
# ══════════════════════════════════════════════════════════════════════════════

# CVSS v3 vector abbreviation → canonical string used in training data
_AV  = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL",     "P": "PHYSICAL"}
_AC  = {"L": "LOW",     "H": "HIGH"}
_PR  = {"N": "NONE",    "L": "LOW",               "H": "HIGH"}
_UI  = {"N": "NONE",    "R": "REQUIRED"}
_S   = {"U": "UNCHANGED", "C": "CHANGED"}
_CIA = {"N": "NONE",    "L": "LOW",               "H": "HIGH"}

# Severity → fallback CVSS score when a finding has no numeric CVSS
_SEV_CVSS_FALLBACK = {
    "Critical": 9.0, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 0.5,
}

# DefectDojo tool names → scanner_type token used by the binary model
# Keep these broad because DefectDojo integrations expose tool names differently
# across imports (test_type_name, found_by, scan_type, title, etc.).
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


def normalise_cwe(raw: Any) -> int:
    """
    Accept any common CWE representation and return a plain integer.
    Examples:  "CWE-79"  →  79
               "79.0"    →  79
               79        →  79
               None      →  0  (treated as unknown)
    """
    if raw is None:
        return 0
    cleaned = (
        str(raw).strip().upper()
        .replace("CWE-", "")
        .split(".")[0]          # remove ".0" suffix
    )
    try:
        return int(cleaned)
    except ValueError:
        return 0

def year_from_cve(cve_id: Optional[str]) -> Optional[int]:
    """Extract the 4-digit year from a CVE identifier like 'CVE-2021-44228'."""
    if not cve_id:
        return None
    match = re.search(r"CVE-(\d{4})-\d+", str(cve_id), re.IGNORECASE)
    return int(match.group(1)) if match else None

def parse_cvss_vector(vector: Optional[str]) -> Dict[str, str]:
    """
    Parse a CVSS v3 vector string into the feature names used by the models.
    Returns an empty dict if the vector is absent or unparseable.

    Example input:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    Example output: {"attack_vector": "NETWORK", "attack_complexity": "LOW", ...}
    """
    if not vector:
        return {}
    try:
        parts: Dict[str, str] = {}
        for segment in vector.split("/"):
            if ":" in segment:
                k, v = segment.split(":", 1)
                parts[k.upper()] = v.upper()

        return {
            "attack_vector":          _AV.get(parts.get("AV", ""), "UNKNOWN"),
            "attack_complexity":      _AC.get(parts.get("AC", ""), "UNKNOWN"),
            "privileges_required":    _PR.get(parts.get("PR", ""), "UNKNOWN"),
            "user_interaction":       _UI.get(parts.get("UI", ""), "UNKNOWN"),
            "scope":                  _S.get( parts.get("S",  ""), "UNKNOWN"),
            "confidentiality_impact": _CIA.get(parts.get("C", ""), "UNKNOWN"),
            "integrity_impact":       _CIA.get(parts.get("I", ""), "UNKNOWN"),
            "availability_impact":    _CIA.get(parts.get("A", ""), "UNKNOWN"),
        }
    except Exception as exc:
        log.debug(f"Could not parse CVSS vector '{vector}': {exc}")
        return {}

def safe_label_encode(value: str, feature_key: str, encoders: Dict,
                       fallback: str = "UNKNOWN") -> int:
    """
    Encode a categorical string value using the fitted LabelEncoder for
    `feature_key`.  Falls back to `fallback` if the value was unseen during
    training, and to index 0 if even the fallback is missing.
    """
    le = encoders.get(feature_key)
    if le is None:
        return 0
    classes: List[str] = list(le.classes_)
    if value in classes:
        return int(le.transform([value])[0])
    if fallback in classes:
        log.debug(f"Unseen value '{value}' for '{feature_key}' → '{fallback}'")
        return int(le.transform([fallback])[0])
    return 0

def encode_cwe_top(cwe_int: int, encoders: Dict) -> int:
    """
    CWEs are stored in the encoder as float-strings ("79.0") or "OTHER".
    Checks the fitted cwe_top LabelEncoder classes_ dynamically:
      - If f"{float(cwe_int)}" exists in the encoder → encode it.
      - Otherwise → encode "OTHER".
    No hardcoded CWE list; works correctly for any model version.
    """
    le = encoders.get("cwe_top")
    if le is None:
        return 0
    classes: List[str] = list(le.classes_)
    cwe_str = f"{float(cwe_int)}"
    if cwe_str in classes:
        return int(le.transform([cwe_str])[0])
    if "OTHER" in classes:
        return int(le.transform(["OTHER"])[0])
    return 0

def build_feature_row(
    feature_list: List[str],
    encoders: Dict,
    *,
    cvss_score: float,
    year: int,
    av: str, ac: str, pr: str, ui: str, sc: str,
    ci: str, ii: str, ai_: str,
    cwe_int: int,
    scanner_type: str = "SCA",
    in_kev: int = 0,
    has_cve: float = 0.0,
    is_static: float = 0.0,
    is_dynamic: float = 0.0,
) -> List[float]:
    """
    Build a model-ready feature row whose column order is driven entirely by
    `feature_list` (read from the model's metadata JSON at startup).

    Supported feature names (all features either model could ever require):
      cvss_score, year, attack_vector, attack_complexity,
      privileges_required, user_interaction, scope,
      confidentiality_impact, integrity_impact, availability_impact,
      cwe_top, scanner_type, in_kev, has_cve, is_static, is_dynamic

    Adding a new feature to a future model only requires updating the
    metadata JSON — no code change needed here.
    """
    # scanner_type encoder key: v3.1 uses "scanner_type"; older models used
    # "scanner_type_enc".  Try the canonical key first and fall back gracefully.
    _scanner_enc_key = "scanner_type" if "scanner_type" in encoders else "scanner_type_enc"

    lookup: Dict[str, float] = {
        "cvss_score":             float(cvss_score),
        "year":                   float(year),
        "attack_vector":          float(safe_label_encode(av,           "attack_vector",          encoders)),
        "attack_complexity":      float(safe_label_encode(ac,           "attack_complexity",      encoders)),
        "privileges_required":    float(safe_label_encode(pr,           "privileges_required",    encoders)),
        "user_interaction":       float(safe_label_encode(ui,           "user_interaction",       encoders)),
        "scope":                  float(safe_label_encode(sc,           "scope",                  encoders)),
        "confidentiality_impact": float(safe_label_encode(ci,           "confidentiality_impact", encoders)),
        "integrity_impact":       float(safe_label_encode(ii,           "integrity_impact",       encoders)),
        "availability_impact":    float(safe_label_encode(ai_,          "availability_impact",    encoders)),
        "cwe_top":                float(encode_cwe_top(cwe_int,         encoders)),
        # scanner_type: use whichever encoder key is present in this model's pkl
        "scanner_type":           float(safe_label_encode(scanner_type, _scanner_enc_key,         encoders, fallback="SCA")),
        # in_kev is a plain binary flag — no label encoding required
        "in_kev":                 float(in_kev),
        # v3.1 features — plain binary flags, no label encoding required
        "has_cve":                float(has_cve),
        "is_static":              float(is_static),
        "is_dynamic":             float(is_dynamic),
    }
    unknown = [f for f in feature_list if f not in lookup]
    if unknown:
        raise ValueError(
            f"build_feature_row: metadata requests unknown feature(s): {unknown}. "
            "Update build_feature_row to handle them."
        )
    return [lookup[f] for f in feature_list]

def _risk_category(score: float) -> str:
    """Map a 0-100 risk score to Low / Medium / High label."""
    if score < 30:
        return "Low"
    if score < 70:
        return "Medium"
    return "High"

def _safe_str(value: Any, default: str = "") -> str:
    """Return a clean string without propagating 'None'/'nan' text."""
    if value is None:
        return default
    text = str(value).strip()
    if text.lower() in {"", "none", "null", "nan"}:
        return default
    return text

def _parse_datetime(value: Any) -> Optional[datetime]:
    """Best-effort parsing for ISO/date strings; returns timezone-aware UTC datetime."""
    if value is None:
        return None
    text = _safe_str(value)
    if not text:
        return None
    try:
        # Accept common ISO strings from OSV / DefectDojo.
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
    """Rough reference count from list/dict/string reference fields."""
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

def _extract_cwe_family(cwe_value: Any) -> str:
    cwe_int = normalise_cwe(cwe_value)
    return str(cwe_int) if cwe_int else "UNKNOWN"

def _build_pipeline_feature_frame(payload: VulnFeatures, *, cwe_int: int, year: int, feature_columns: List[str]) -> pd.DataFrame:
    """
    Build the exact DataFrame expected by the leakage-safe sklearn Pipeline.

    The pipeline contains its own imputers and one-hot encoder, so the backend
    should NOT manually label-encode categorical values. Missing optional values
    can stay None/pd.NA and will be handled by the pipeline preprocessor.
    """
    package_name = (
        _safe_str(payload.package_name)
        or _safe_str(payload.component_name)
        or "UNKNOWN_PACKAGE"
    )

    published_value = payload.published or payload.year or year
    modified_value = payload.modified
    withdrawn_value = payload.withdrawn

    published_year = (
        payload.published_year
        or _year_from_any(payload.published, payload.year, payload.cve_id)
        or year
    )

    summary_text = _safe_str(payload.title)
    details_text = " " .join(x for x in [
        _safe_str(payload.file_path),
        _safe_str(payload.component_name),
        _safe_str(payload.component_version),
        _safe_str(payload.vulnerability_id),
    ] if x)

    summary_len = payload.summary_len if payload.summary_len is not None else len(summary_text)
    details_len = payload.details_len if payload.details_len is not None else len(details_text)

    has_cve = bool(payload.has_cve or payload.cve_id or payload.vulnerability_id and str(payload.vulnerability_id).upper().startswith("CVE-"))
    has_ghsa = bool(
        (_safe_str(payload.vulnerability_id).upper().startswith("GHSA-"))
        or ("GHSA-" in _safe_str(payload.title).upper())
    )

    cwe_raw = payload.cwe_id if payload.cwe_id is not None else payload.cwe
    cwe_family = _extract_cwe_family(cwe_raw)

    row: Dict[str, Any] = {
        # Common metadata features from the leakage-safe training pipeline.
        "package_name": package_name,
        # Required by the EPSS-only operational ranker. The clean model simply
        # does not request these columns, so they are harmless here.
        "cvss_score": float(payload.cvss_score),
        "cvss_vector": payload.cvss_vector,
        "cwe_id": cwe_raw,
        "all_cwe_ids": payload.all_cwe_ids if payload.all_cwe_ids is not None else (f"CWE-{cwe_int}" if cwe_int else None),
        "published": payload.published,
        "modified": payload.modified,
        "withdrawn": payload.withdrawn,
        "published_year": published_year,
        "days_since_published": _days_since(published_value),
        "days_since_modified": _days_since(modified_value),
        "ranges_count": int(payload.ranges_count or 0),
        "versions_count": int(payload.versions_count or (1 if payload.component_version else 0)),
        "summary_len": int(summary_len or 0),
        "details_len": int(details_len or 0),
        "references_count": int(payload.references_count or 0),
        "github_reviewed": int(bool(payload.github_reviewed)),
        "has_patch_ref": int(bool(payload.has_patch_ref)),
        "has_advisory_ref": int(bool(payload.has_advisory_ref)),
        "has_cve": int(has_cve),
        "source_dataset": payload.source_dataset or payload.data_source or "runtime_api",
        "scanner_type": _safe_str(payload.scanner_type, "SCA").upper(),
        "is_static": int(bool(payload.is_static)),
        "is_dynamic": int(bool(payload.is_dynamic)),
        "data_source": payload.data_source or payload.source_dataset or "runtime_api",

        # Backwards compatibility for older leakage-safe models that still used
        # CVSS subcomponents. The final minimal model does not request them.
        "attack_vector": payload.attack_vector,
        "attack_complexity": payload.attack_complexity,
        "privileges_required": payload.privileges_required,
        "user_interaction": payload.user_interaction,
        "scope": payload.scope,
        "confidentiality_impact": payload.confidentiality_impact,
        "integrity_impact": payload.integrity_impact,
        "availability_impact": payload.availability_impact,
        "cwe": cwe_int,
        "year": year,

        # Engineered features used by the final minimal model.
        "feat_has_cve": int(has_cve),
        "feat_has_ghsa": int(has_ghsa),
        "feat_cwe_family": cwe_family,
        "feat_has_cwe": int(cwe_int != 0),
        "feat_published_year": published_year,
        "feat_days_since_published": _days_since(published_value),
        "feat_modified_year": _year_from_any(modified_value),
        "feat_days_since_modified": _days_since(modified_value),
        "feat_withdrawn_year": _year_from_any(withdrawn_value),
        "feat_days_since_withdrawn": _days_since(withdrawn_value),
        "feat_package_len": len(package_name),
        "feat_is_scoped_package": int(package_name.startswith("@")),
        "feat_package_scope": package_name.split("/")[0] if package_name.startswith("@") else "unscoped",
    }

    # Enforce the model's exact feature order. Any unknown future feature fails
    # loudly instead of silently scoring with the wrong schema.
    missing_features = [f for f in feature_columns if f not in row]
    if missing_features:
        raise ValueError(
            f"Feature builder does not know how to create: {missing_features}. "
            "Update _build_pipeline_feature_frame for this model version."
        )

    return pd.DataFrame([{col: row.get(col) for col in feature_columns}], columns=feature_columns)

def resolve_features(payload: VulnFeatures) -> Tuple[pd.DataFrame, pd.DataFrame, int, int]:
    """
    Convert a VulnFeatures payload into both model feature frames.

    Returns:
      (X_clean_dataframe, X_ranker_dataframe, cwe_int, year)
    """
    # Keep CVSS vector parsing for backwards compatibility with existing API
    # payloads and older model artifacts. The final minimal model does not use
    # CVSS subcomponents, but older leakage-safe pipelines may still request them.
    if payload.cvss_vector:
        parsed = parse_cvss_vector(payload.cvss_vector)
        if parsed:
            payload.attack_vector = parsed.get("attack_vector", payload.attack_vector)
            payload.attack_complexity = parsed.get("attack_complexity", payload.attack_complexity)
            payload.privileges_required = parsed.get("privileges_required", payload.privileges_required)
            payload.user_interaction = parsed.get("user_interaction", payload.user_interaction)
            payload.scope = parsed.get("scope", payload.scope)
            payload.confidentiality_impact = parsed.get("confidentiality_impact", payload.confidentiality_impact)
            payload.integrity_impact = parsed.get("integrity_impact", payload.integrity_impact)
            payload.availability_impact = parsed.get("availability_impact", payload.availability_impact)

    cwe_source = payload.cwe_id if payload.cwe_id is not None else payload.cwe
    cwe_int: int = normalise_cwe(cwe_source)
    year: int = payload.year or year_from_cve(payload.cve_id) or _year_from_any(payload.published, payload.published_year) or 2022

    row_clean = _build_pipeline_feature_frame(payload, cwe_int=cwe_int, year=year, feature_columns=CLEAN_FEATURES)
    row_ranker = _build_pipeline_feature_frame(payload, cwe_int=cwe_int, year=year, feature_columns=RANKER_FEATURES)
    return row_clean, row_ranker, cwe_int, year

def _run_pipeline(bundle: Dict[str, Any], row: pd.DataFrame) -> Dict[str, Any]:
    """Run one sklearn Pipeline bundle and return a normalized score dict."""
    prob = float(bundle["model"].predict_proba(row)[0][1])
    score = round(prob * 100, 2)
    threshold = float(bundle["threshold"])
    return {
        "probability": round(prob, 4),
        "score": score,
        "category": _risk_category(score),
        "is_high_risk": bool(prob >= threshold),
        "threshold_used": threshold,
        "model_version": str(bundle["version"]),
    }

def run_dual_models(row_clean: pd.DataFrame, row_ranker: pd.DataFrame) -> Dict[str, Any]:
    """
    Run both models and return one combined result.

    Compatibility rule:
      - legacy exploit_probability/risk_score/risk_category/is_high_risk are
        aliases for the operational EPSS ranker because that is the primary
        dashboard sorting score.
      - clean_* fields expose the strict leakage-safe triage model separately.
    """
    clean = _run_pipeline(clean_bundle, row_clean)
    operational = _run_pipeline(ranker_bundle, row_ranker)

    return {
        # Legacy / compatibility aliases used by old frontend code.
        "exploit_probability": operational["probability"],
        "risk_score": operational["score"],
        "risk_category": operational["category"],
        "is_high_risk": operational["is_high_risk"],
        "threshold_used": operational["threshold_used"],

        # Clean leakage-safe model output.
        "clean_exploit_probability": clean["probability"],
        "clean_ai_score": clean["score"],
        "clean_ai_category": clean["category"],
        "clean_is_high_risk": clean["is_high_risk"],
        "clean_threshold_used": clean["threshold_used"],
        "clean_model_version": clean["model_version"],

        # EPSS operational ranking model output.
        "operational_exploit_probability": operational["probability"],
        "operational_rank_score": operational["score"],
        "operational_rank_category": operational["category"],
        "operational_is_high_risk": operational["is_high_risk"],
        "operational_threshold_used": operational["threshold_used"],
        "operational_rank_percentile": None,
        "operational_model_version": operational["model_version"],
    }

def run_binary(row: pd.DataFrame) -> Dict:
    """
    Backwards-compatible wrapper: runs the operational ranker only.

    New code should call run_dual_models(). This function remains to avoid
    breaking older imports/tests that call run_binary directly.
    """
    operational = _run_pipeline(ranker_bundle, row)
    return {
        "exploit_probability": operational["probability"],
        "risk_score": operational["score"],
        "risk_category": operational["category"],
        "is_high_risk": operational["is_high_risk"],
        "threshold_used": operational["threshold_used"],
    }

