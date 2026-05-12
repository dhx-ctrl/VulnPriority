"""
DevSecOps AI Risk Scoring API  ·  main.py
==========================================
FastAPI backend for XGBoost v3.2-compatible binary exploit classifier
and v3.2-compatible multiclass severity classifier.

Architecture:
  /api/health/             → liveness + model info
  /api/risk-score/         → binary EPSS model only
  /api/severity-predict/   → multiclass severity model only
  /api/score-finding/      → both models + persist to SQLite
  /api/sync-defectdojo/    → pull DefectDojo findings, score all, store all
  /api/scores/             → browse stored results

Preprocessing rules (important):
  - Feature order is enforced by BINARY_FEATURES / MULTI_FEATURES from metadata JSON
  - CWE normalised: "CWE-79", "79.0", 79 → int 79, then bucketed against the
    fitted cwe_top LabelEncoder classes (dynamic — no hardcoded CWE list)
  - Year extracted from CVE-ID when not supplied; median year (2022) as final fallback
  - Unknown categorical values → "UNKNOWN" (or "OTHER" for cwe_top bucket)
  - cvss_score missing → 5.0
  - CVSS vector string parsed if supplied; overrides individual component fields
  - Feature presence (e.g. in_kev) is metadata-driven — no hardcoded vector size
  - in_kev / known_exploited both default to False; either field sets the KEV flag
"""

# ─── stdlib ──────────────────────────────────────────────────────────────────
import json
import logging
import os
import pickle
import re
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─── third-party ─────────────────────────────────────────────────────────────
import numpy as np
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator

# ─── load .env before anything else ──────────────────────────────────────────
load_dotenv()

# ══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("devsecops_ai")


# ══════════════════════════════════════════════════════════════════════════════
# PATHS & ENVIRONMENT CONFIG
# ══════════════════════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent
DB_PATH  = BASE_DIR / "ai_scores.db"

# DefectDojo connection – read from .env
DEFECTDOJO_URL        = os.getenv("DEFECTDOJO_URL", "").rstrip("/")
DEFECTDOJO_API_KEY    = os.getenv("DEFECTDOJO_API_KEY", "")
DEFECTDOJO_PRODUCT_ID = os.getenv("DEFECTDOJO_PRODUCT_ID", "")


# ══════════════════════════════════════════════════════════════════════════════
# MODEL LOADING  (happens once at import time, not per-request)
# ══════════════════════════════════════════════════════════════════════════════

def _load_pickle(path: Path, label: str) -> Any:
    if not path.exists():
        raise FileNotFoundError(
            f"Required model file not found: {path}\n"
            f"Hint: make sure all .pkl files are in the same directory as main.py."
        )
    with open(path, "rb") as fh:
        return pickle.load(fh)


def _load_json(path: Path) -> Dict:
    if not path.exists():
        raise FileNotFoundError(f"Required metadata file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ── Binary (EPSS exploit-likelihood) model ────────────────────────────────────
model_binary    = _load_pickle(BASE_DIR / "model_v3.pkl",          "binary model")
encoders_binary = _load_pickle(BASE_DIR / "label_encoders_v3.pkl", "binary label encoders")
meta_binary     = _load_json(BASE_DIR / "model_meta_v3.json")

# ── Multiclass (severity) model ───────────────────────────────────────────────
model_multi     = _load_pickle(BASE_DIR / "model_v3_multi.pkl",          "multi model")
encoders_multi  = _load_pickle(BASE_DIR / "label_encoders_v3_multi.pkl", "multi label encoders")
meta_multi      = _load_json(BASE_DIR / "model_meta_v3_multi.json")

# ── Constants extracted from metadata (single source of truth) ────────────────
OPTIMAL_THRESHOLD: float     = float(meta_binary["optimal_threshold"])
BINARY_FEATURES:   List[str] = meta_binary["features"]   # metadata-driven; count from model_meta_v3.json
MULTI_FEATURES:    List[str] = meta_multi["features"]    # metadata-driven; count from model_meta_v3_multi.json
CLASS_MAP:         Dict[int, str] = {
    int(k): v for k, v in meta_multi["class_map"].items()
}  # {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}

log.info(
    f"Binary model v{meta_binary['model_version']} loaded "
    f"(threshold={OPTIMAL_THRESHOLD}, features={len(BINARY_FEATURES)})"
)
log.info(
    f"Multiclass model v{meta_multi['model_version']} loaded "
    f"(classes={list(CLASS_MAP.values())}, features={len(MULTI_FEATURES)})"
)


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

# DefectDojo tool names → scanner_type token used by the multiclass model
# Keep these broad because DefectDojo integrations expose tool names differently
# across imports (test_type_name, found_by, scan_type, title, etc.).
_SAST_TOOLS = {
    "semgrep", "bandit", "flake8", "sonarqube", "checkmarx",
    "sast", "eslint", "codeql", "static", "static analysis",
}
_DAST_TOOLS = {
    "zap", "owasp zap", "zaproxy", "burp", "nikto",
    "dast", "nuclei", "nessus", "dynamic", "dynamic analysis",
}
_SCA_TOOLS = {
    "trivy", "npm audit", "npm-audit", "dependency", "dependency-check",
    "sca", "snyk", "osv", "grype", "container", "image scan",
}


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════

# Split into two parts so migrations (ALTER TABLE ADD COLUMN) can run
# between table creation and index creation.
# Indexes that reference columns like is_high_risk must be created AFTER
# those columns exist — doing it in one executescript() call fails when the
# table already exists from an older schema that is missing those columns.

_SCHEMA_TABLE = """
CREATE TABLE IF NOT EXISTS ai_scores (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at              TEXT    NOT NULL,
    cve_id                  TEXT,
    scanner_type            TEXT,
    cvss_score              REAL,
    exploit_probability     REAL,
    risk_score              REAL,
    risk_category           TEXT,
    is_high_risk            INTEGER,
    predicted_severity      TEXT,
    prob_low                REAL,
    prob_medium             REAL,
    prob_high               REAL,
    prob_critical           REAL,
    source                  TEXT,
    defectdojo_finding_id   INTEGER,
    product_name            TEXT,
    product_id              INTEGER,
    raw_input               TEXT
);
"""

_SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_scores_source      ON ai_scores(source);
CREATE INDEX IF NOT EXISTS idx_scores_high_risk   ON ai_scores(is_high_risk);
CREATE INDEX IF NOT EXISTS idx_scores_created     ON ai_scores(created_at);
CREATE INDEX IF NOT EXISTS idx_scores_dd_finding  ON ai_scores(defectdojo_finding_id);
CREATE INDEX IF NOT EXISTS idx_scores_product_id  ON ai_scores(product_id);
"""


# Minimum columns that MUST exist for the app to function.
# If the table is missing any of these it is from an incompatible old schema
# and will be dropped + recreated (safe: ai_scores is a local scoring cache,
# not a source-of-truth store — data can always be regenerated by re-syncing).
_CORE_COLS = {"id", "created_at", "exploit_probability", "predicted_severity"}

# All nullable columns that can be added to an existing compatible table
# via ALTER TABLE ADD COLUMN without breaking existing rows.
_ADDABLE_COLS: List[Tuple[str, str]] = [
    ("cve_id",                "TEXT"),
    ("scanner_type",          "TEXT"),
    ("cvss_score",            "REAL"),
    ("exploit_probability",   "REAL"),
    ("risk_score",            "REAL"),
    ("risk_category",         "TEXT"),
    ("is_high_risk",          "INTEGER"),
    ("predicted_severity",    "TEXT"),
    ("prob_low",              "REAL"),
    ("prob_medium",           "REAL"),
    ("prob_high",             "REAL"),
    ("prob_critical",         "REAL"),
    ("source",                "TEXT"),
    ("defectdojo_finding_id", "INTEGER"),
    ("product_name",          "TEXT"),
    ("product_id",            "INTEGER"),
    ("raw_input",             "TEXT"),
]


def init_db() -> None:
    """
    Start-up DB initialisation with automatic migration.

    Strategy
    --------
    1. If ai_scores does not exist → create it fresh (table + indexes).
    2. If ai_scores exists and has all _CORE_COLS → it is a compatible schema:
         add any missing nullable columns via ALTER TABLE ADD COLUMN, then
         create any missing indexes.
    3. If ai_scores exists but is missing core columns → it is from a completely
         different old schema. Drop it and recreate from scratch.
         (ai_scores is a local scoring cache; rows can be regenerated by
          re-running /api/sync-defectdojo/ or re-posting findings.)
    """
    with sqlite3.connect(DB_PATH) as con:
        # Check what columns the table already has (empty set = table absent)
        existing_cols = {
            row[1]
            for row in con.execute("PRAGMA table_info(ai_scores)").fetchall()
        }

        if existing_cols and not _CORE_COLS.issubset(existing_cols):
            # Incompatible old schema — drop and recreate
            log.warning(
                "ai_scores table has an incompatible schema "
                f"(missing core columns: {_CORE_COLS - existing_cols}). "
                "Dropping and recreating the table. "
                "Re-run /api/sync-defectdojo/ to repopulate scores."
            )
            con.execute("DROP TABLE IF EXISTS ai_scores")
            existing_cols = set()   # treat as fresh

        # Phase 1 — create table if absent (fresh DB or just dropped above)
        con.executescript(_SCHEMA_TABLE)

        # Phase 2 — add any nullable column missing from a compatible old table
        # Re-read after possible CREATE TABLE above
        existing_cols = {
            row[1]
            for row in con.execute("PRAGMA table_info(ai_scores)").fetchall()
        }
        added: List[str] = []
        for col_name, col_type in _ADDABLE_COLS:
            if col_name not in existing_cols:
                con.execute(
                    f"ALTER TABLE ai_scores ADD COLUMN {col_name} {col_type}"
                )
                added.append(col_name)
        if added:
            log.info(f"DB migration: added missing column(s): {added}")

        # Phase 3 — indexes (all referenced columns are guaranteed to exist now)
        con.executescript(_SCHEMA_INDEXES)

    log.info(f"SQLite ready at {DB_PATH}")


@contextmanager
def get_db():
    """Yield a committed-or-rolled-back SQLite connection."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ══════════════════════════════════════════════════════════════════════════════
# PREPROCESSING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════════
# PYDANTIC SCHEMAS
# ══════════════════════════════════════════════════════════════════════════════

class VulnFeatures(BaseModel):
    """
    Normalised vulnerability feature payload accepted by all scoring endpoints.

    You can provide:
      - Individual CVSS component fields (attack_vector, etc.)
      - OR a raw cvss_vector string (overrides component fields if parseable)
    """
    cve_id:                  Optional[str]   = Field(None, description="CVE identifier, e.g. CVE-2021-44228")
    cvss_score:              float           = Field(5.0, ge=0.0, le=10.0)
    year:                    Optional[int]   = Field(None, ge=1999, le=2030, description="Year CVE was published")
    attack_vector:           str             = Field("NETWORK",   description="NETWORK | LOCAL | ADJACENT_NETWORK | PHYSICAL")
    attack_complexity:       str             = Field("LOW",       description="LOW | HIGH")
    privileges_required:     str             = Field("NONE",      description="NONE | LOW | HIGH")
    user_interaction:        str             = Field("NONE",      description="NONE | REQUIRED")
    scope:                   str             = Field("UNCHANGED", description="UNCHANGED | CHANGED")
    confidentiality_impact:  str             = Field("HIGH",      description="HIGH | LOW | NONE")
    integrity_impact:        str             = Field("HIGH",      description="HIGH | LOW | NONE")
    availability_impact:     str             = Field("HIGH",      description="HIGH | LOW | NONE")
    cwe:                     Any             = Field(0,           description="CWE as int (79), 'CWE-79', or '79.0'")
    scanner_type:            str             = Field("SCA",       description="SCA | SAST | DAST")
    cvss_vector:             Optional[str]   = Field(None,        description="Raw CVSS v3 vector string; overrides component fields")
    # ── KEV fields ──────────────────────────────────────────────────────────
    # `in_kev` is the canonical name used by both model metadata files.
    # `known_exploited` is the DefectDojo field name; supplying either
    # (or both) sets in_kev=True for both models.  Both default to False so
    # existing callers that omit KEV information continue to work unchanged.
    in_kev:          bool = Field(False, description="True if the CVE appears in the CISA KEV catalog")
    known_exploited: bool = Field(False, description="DefectDojo alias for in_kev; merged into in_kev at validation time")
    # ── v3.1 features ────────────────────────────────────────────────────────
    has_cve:    bool = Field(False, description="True if a CVE identifier is associated with this finding")
    is_static:  bool = Field(False, description="True if the finding was produced by a static analysis (SAST) tool")
    is_dynamic: bool = Field(False, description="True if the finding was produced by a dynamic analysis (DAST) tool")

    # ── Display metadata ─────────────────────────────────────────────────────
    # These fields are NOT model features. They are preserved in raw_input so
    # the dashboard can show real finding names / packages / paths instead of
    # generic "Finding #N" / "N/A" placeholders.
    title:             Optional[str] = Field(None, description="Human-readable finding title from the scanner")
    component_name:    Optional[str] = Field(None, description="Vulnerable package or component name (e.g. 'lodash')")
    component_version: Optional[str] = Field(None, description="Installed version of the vulnerable component")
    file_path:         Optional[str] = Field(None, description="Source file or path where the finding was detected")
    vulnerability_id:  Optional[str] = Field(None, description="Primary vulnerability identifier (CVE, GHSA, etc.)")

    @model_validator(mode="after")
    def _resolve_kev(self) -> "VulnFeatures":
        """Merge known_exploited into in_kev so downstream code only reads in_kev."""
        if self.known_exploited:
            self.in_kev = True
        return self

    @field_validator("cvss_score", mode="before")
    @classmethod
    def _default_cvss(cls, v: Any) -> float:
        """Coerce cvss_score and fall back to 5.0 on bad input."""
        try:
            val = float(v)
            return val if 0.0 <= val <= 10.0 else 5.0
        except (TypeError, ValueError):
            return 5.0

    @field_validator("attack_vector", "attack_complexity", "privileges_required",
                     "user_interaction", "scope", "confidentiality_impact",
                     "integrity_impact", "availability_impact", "scanner_type",
                     mode="before")
    @classmethod
    def _upper(cls, v: Any) -> str:
        return str(v).strip().upper() if v else ""


class SyncDefectDojoRequest(BaseModel):
    """
    Body for /api/sync-defectdojo/.

    Resolution order for the target product:
      1. product_id  — used directly if provided (must be >= 1).
      2. product_name — looked up via GET /api/v2/products/ if product_id is absent.
      3. DEFECTDOJO_PRODUCT_ID env var — fallback when neither field is supplied.
    """
    product_id:   Optional[int] = Field(
        None, ge=1,
        description="DefectDojo numeric product ID (>= 1). Takes priority over product_name.",
    )
    product_name: Optional[str] = Field(
        None,
        description="Human-readable product name (e.g. 'JuiceShop'). Looked up via DefectDojo API.",
    )
    active_only: bool = Field(True,  description="Only fetch active (non-resolved) findings")
    limit:       int  = Field(2000,  ge=1, le=2000, description="Max findings to process")


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE RESOLUTION  (VulnFeatures → model-ready rows)
# ══════════════════════════════════════════════════════════════════════════════

def resolve_features(payload: VulnFeatures) -> Tuple[List[float], List[float], int, int]:
    """
    Convert a VulnFeatures payload into two model-ready feature rows.

    Priority order for CVSS component fields:
      1. Parsed cvss_vector (if provided and parseable)
      2. Explicit individual fields from the payload
      3. Field defaults defined in VulnFeatures

    The column order and presence of optional features (e.g. in_kev) is
    determined entirely by BINARY_FEATURES / MULTI_FEATURES loaded from the
    model metadata JSON at startup — no fixed feature count is assumed here.

    Returns:
      (row_binary, row_multi, cwe_int, year)
        row_binary – feature list for the binary model   (len == len(BINARY_FEATURES))
        row_multi  – feature list for the multiclass model (len == len(MULTI_FEATURES))
        cwe_int    – normalised CWE integer
        year       – resolved publication year
    """
    # Start from explicit field values (already upper-cased by validator)
    av  = payload.attack_vector
    ac  = payload.attack_complexity
    pr  = payload.privileges_required
    ui  = payload.user_interaction
    sc  = payload.scope
    ci  = payload.confidentiality_impact
    ii  = payload.integrity_impact
    ai_ = payload.availability_impact

    # Override with parsed CVSS vector when available
    if payload.cvss_vector:
        parsed = parse_cvss_vector(payload.cvss_vector)
        if parsed:
            av  = parsed.get("attack_vector",          av)
            ac  = parsed.get("attack_complexity",      ac)
            pr  = parsed.get("privileges_required",    pr)
            ui  = parsed.get("user_interaction",       ui)
            sc  = parsed.get("scope",                  sc)
            ci  = parsed.get("confidentiality_impact", ci)
            ii  = parsed.get("integrity_impact",       ii)
            ai_ = parsed.get("availability_impact",    ai_)

    # CWE normalisation
    cwe_int: int = normalise_cwe(payload.cwe)

    # Year resolution: explicit → CVE ID extraction → median fallback
    year: int = payload.year or year_from_cve(payload.cve_id) or 2022

    # in_kev: merged from known_exploited by the model_validator; default 0
    in_kev_int: int = int(payload.in_kev)

    # Shared kwargs for both calls — build_feature_row selects only the
    # columns each model actually needs based on its feature_list.
    shared = dict(
        cvss_score=payload.cvss_score, year=year,
        av=av, ac=ac, pr=pr, ui=ui, sc=sc, ci=ci, ii=ii, ai_=ai_,
        cwe_int=cwe_int,
        scanner_type=payload.scanner_type,
        in_kev=in_kev_int,
        has_cve=float(payload.has_cve),
        is_static=float(payload.is_static),
        is_dynamic=float(payload.is_dynamic),
    )

    row_binary = build_feature_row(BINARY_FEATURES, encoders_binary, **shared)
    row_multi  = build_feature_row(MULTI_FEATURES,  encoders_multi,  **shared)

    return row_binary, row_multi, cwe_int, year


# ══════════════════════════════════════════════════════════════════════════════
# PREDICTION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def run_binary(row: List[float]) -> Dict:
    """Run the binary EPSS model; return structured prediction dict."""
    X = np.array(row, dtype=float).reshape(1, -1)
    prob  = float(model_binary.predict_proba(X)[0][1])
    score = round(prob * 100, 2)
    return {
        "exploit_probability": round(prob, 4),
        "risk_score":          score,
        "risk_category":       _risk_category(score),
        "is_high_risk":        prob >= OPTIMAL_THRESHOLD,
        "threshold_used":      OPTIMAL_THRESHOLD,
    }


def run_multi(row: List[float]) -> Dict:
    """Run the multiclass severity model; return structured prediction dict."""
    X     = np.array(row, dtype=float).reshape(1, -1)
    probs = model_multi.predict_proba(X)[0]   # [P_Low, P_Med, P_High, P_Crit]
    idx   = int(probs.argmax())
    return {
        "predicted_severity": CLASS_MAP[idx],
        "confidence":         round(float(probs.max()), 4),
        "probabilities": {
            "Low":      round(float(probs[0]), 4),
            "Medium":   round(float(probs[1]), 4),
            "High":     round(float(probs[2]), 4),
            "Critical": round(float(probs[3]), 4),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# SQLITE PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════

def persist_score(
    payload: VulnFeatures,
    binary_res: Dict,
    multi_res: Dict,
    source: str = "api",
    defectdojo_finding_id: Optional[int] = None,
    product_name: Optional[str] = None,
    product_id: Optional[int] = None,
) -> int:
    """Insert a combined score record; returns the new row ID."""
    probs = multi_res["probabilities"]
    with get_db() as con:
        cur = con.execute(
            """
            INSERT INTO ai_scores (
                created_at, cve_id, scanner_type, cvss_score,
                exploit_probability, risk_score, risk_category, is_high_risk,
                predicted_severity, prob_low, prob_medium, prob_high, prob_critical,
                source, defectdojo_finding_id, product_name, product_id, raw_input
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                payload.cve_id,
                payload.scanner_type,
                payload.cvss_score,
                binary_res["exploit_probability"],
                binary_res["risk_score"],
                binary_res["risk_category"],
                int(binary_res["is_high_risk"]),
                multi_res["predicted_severity"],
                probs["Low"],
                probs["Medium"],
                probs["High"],
                probs["Critical"],
                source,
                defectdojo_finding_id,
                product_name,
                product_id,
                payload.model_dump_json(),
            ),
        )
        return cur.lastrowid


# ══════════════════════════════════════════════════════════════════════════════
# DEFECTDOJO INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

def _dd_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Token {DEFECTDOJO_API_KEY}",
        "Content-Type":  "application/json",
    }


def _extract_product_id_from_finding(finding: Dict) -> Optional[int]:
    """
    Best-effort extraction of product_id from a DefectDojo finding response.

    DefectDojo findings belong to a product through:
        finding -> test -> engagement -> product

    This helper is used as a defensive local safety filter because some
    DefectDojo installations do not reliably filter findings with the old
    `product_id` query parameter.
    """
    # Most useful when `related_fields=true` is passed.
    related = finding.get("related_fields") or {}
    try:
        pid = (
            related.get("test", {})
                   .get("engagement", {})
                   .get("product", {})
                   .get("id")
        )
        if pid is not None:
            return int(pid)
    except (AttributeError, TypeError, ValueError):
        pass

    # Some DefectDojo versions expose product info inside the prefetched test.
    raw_test = finding.get("test")
    if isinstance(raw_test, dict):
        try:
            pid = (
                raw_test.get("engagement", {})
                        .get("product", {})
                        .get("id")
            )
            if pid is not None:
                return int(pid)
        except (AttributeError, TypeError, ValueError):
            pass

    # Some versions expose direct fields.
    for key in ("product_id", "product"):
        try:
            val = finding.get(key)
            if val is not None:
                return int(val)
        except (TypeError, ValueError):
            pass

    return None


def fetch_dd_findings(product_id: int, active_only: bool, limit: int) -> List[Dict]:
    """
    Paginate /api/v2/findings/ for findings whose test engagement belongs
    to product_id.

    Important fix:
      - Uses DefectDojo's nested product filter:
            test__engagement__product=<product_id>
        instead of the weaker/incorrect product_id parameter.
      - Applies a local safety filter when product metadata is returned, so
        mixed JuiceShop/DVWA/DVNA results are discarded.

    Result behavior:
      - `limit` is a maximum cap, not an exact target.
      - If DVNA has 120 active findings and limit=500, this returns 120.
      - If more than `limit` match, this returns only `limit`.
    """
    url = f"{DEFECTDOJO_URL}/api/v2/findings/"
    page = min(limit, 100)  # DefectDojo max page size is normally 100
    offset = 0

    matched_findings: List[Dict] = []
    raw_seen = 0
    discarded_wrong_product = 0
    missing_product_metadata = 0

    while len(matched_findings) < limit:
        # Build params as a list of tuples so repeated keys (prefetch[]) work.
        params: List[Tuple[str, Any]] = [
            # Correct product filter path: finding -> test -> engagement -> product
            ("test__engagement__product", product_id),
            ("limit", page),
            ("offset", offset),
            ("prefetch[]", "test"),
            ("prefetch[]", "found_by"),
            ("related_fields", "true"),
        ]
        if active_only:
            params.append(("active", "true"))

        resp = requests.get(url, headers=_dd_headers(), params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        batch = data.get("results", [])
        raw_seen += len(batch)

        for finding in batch:
            found_product_id = _extract_product_id_from_finding(finding)

            # If DefectDojo returns product metadata, enforce it strictly.
            # If metadata is absent, keep it because the API-side nested filter
            # may still have been applied correctly. We log how often this happens.
            if found_product_id is not None and found_product_id != int(product_id):
                discarded_wrong_product += 1
                continue

            if found_product_id is None:
                missing_product_metadata += 1

            matched_findings.append(finding)
            if len(matched_findings) >= limit:
                break

        if not data.get("next") or not batch:
            break

        offset += page

    log.info(
        f"DefectDojo findings filter: requested product_id={product_id}, "
        f"raw_seen={raw_seen}, matched={len(matched_findings)}, "
        f"discarded_wrong_product={discarded_wrong_product}, "
        f"missing_product_metadata={missing_product_metadata}, limit={limit}"
    )

    return matched_findings[:limit]

def fetch_dd_products() -> List[Dict]:
    """
    Return all DefectDojo products as a list of {"id": int, "name": str} dicts,
    paging through /api/v2/products/ until exhausted.
    """
    url    = f"{DEFECTDOJO_URL}/api/v2/products/"
    offset = 0
    page   = 100
    products: List[Dict] = []

    while True:
        resp = requests.get(
            url,
            headers=_dd_headers(),
            params={"limit": page, "offset": offset},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        for p in data.get("results", []):
            products.append({"id": p["id"], "name": p["name"]})

        if not data.get("next"):
            break
        offset += page

    return products


def resolve_dd_product_id(product_name: str) -> Tuple[int, str]:
    """
    Look up *product_name* in DefectDojo and return (product_id, resolved_name).

    Resolution rules:
      1. Exact case-insensitive match  → use it directly.
      2. Partial / substring matches   → use the sole match, or raise 400 if ambiguous.
      3. No match at all               → raise 404.
    """
    try:
        products = fetch_dd_products()
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach DefectDojo while listing products: {exc}",
        )

    needle = product_name.strip().lower()

    # Exact case-insensitive match first — unambiguous
    exact = [p for p in products if p["name"].lower() == needle]
    if len(exact) == 1:
        return exact[0]["id"], exact[0]["name"]

    # Multiple exact hits (shouldn't happen but handle it)
    if len(exact) > 1:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Multiple DefectDojo products match '{product_name}' exactly. "
                           "Provide product_id instead.",
                "candidates": [{"id": p["id"], "name": p["name"]} for p in exact],
            },
        )

    # Substring / partial match fallback
    partial = [p for p in products if needle in p["name"].lower()]
    if len(partial) == 1:
        return partial[0]["id"], partial[0]["name"]

    if len(partial) > 1:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"'{product_name}' matches multiple DefectDojo products. "
                           "Refine the name or supply product_id directly.",
                "candidates": [{"id": p["id"], "name": p["name"]} for p in partial],
            },
        )

    # Nothing matched
    raise HTTPException(
        status_code=404,
        detail=f"No DefectDojo product found matching '{product_name}'. "
               "Check the name or use /api/products/ to browse available products.",
    )


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cve_from_finding(finding: Dict) -> Optional[str]:
    """
    Search for a CVE identifier in the most likely locations of a DefectDojo
    finding dict.  Returns the first match (upper-cased) or None.

    Fields searched in order:
      1. cve                  – top-level string field
      2. vulnerability_ids    – list of {"vulnerability_id": "CVE-..."} dicts
                                (or a list of plain strings for older DD versions)
      3. vuln_id_from_tool    – string populated by some scanner integrations
      4. title                – free-text; e.g. "CVE-2021-44228 in log4j"
      5. description          – longer free-text; last resort before title
      6. references           – URL list or blob; contains CVE links in some exports
    """
    # 1. Top-level cve field
    raw_cve = finding.get("cve")
    if raw_cve and isinstance(raw_cve, str):
        m = _CVE_RE.search(raw_cve)
        if m:
            return m.group(0).upper()

    # 2. vulnerability_ids list
    raw_vuln_ids = finding.get("vulnerability_ids") or []
    if isinstance(raw_vuln_ids, list):
        for item in raw_vuln_ids:
            if isinstance(item, dict):
                vid = item.get("vulnerability_id") or ""
            else:
                vid = str(item)
            m = _CVE_RE.search(vid)
            if m:
                return m.group(0).upper()

    # 3–6. Free-text fields (searched in priority order)
    for field in ("vuln_id_from_tool", "title", "description", "references"):
        val = finding.get(field)
        if val and isinstance(val, str):
            m = _CVE_RE.search(val)
            if m:
                return m.group(0).upper()

    return None


def normalise_dd_finding(finding: Dict) -> Tuple["VulnFeatures", Optional[str]]:
    """
    Map one DefectDojo finding dict to a VulnFeatures object ready for scoring.

    Fields used from the DefectDojo response:
      cve / vulnerability_ids / vuln_id_from_tool / title / description / references
                      → cve_id  (via extract_cve_from_finding — all six fields searched)
      cwe             → cwe
      cvssv3_score    → cvss_score
      cvssv3          → cvss_vector (parsed for component fields)
      severity        → fallback cvss_score when numeric score is absent
      test            → scanner_type via test_type_name (when prefetched)
      found_by        → scanner_type fallback (list of strings or dicts)
      date / created  → year fallback

    Defensive notes:
      - `test` is an integer ID unless prefetch[]=test was requested.
        We handle both: if it is a dict we read test_type_name; if it is an
        integer we silently fall back to found_by without crashing.
      - `found_by` items can be strings or dicts depending on whether
        prefetch[]=found_by was requested — both forms are handled.
      - `cwe` from DefectDojo is typically an integer but can arrive as a
        string or None; normalise_cwe() handles all variants.

    Returns (VulnFeatures, product_name_or_None).
    """
    cve_id      = extract_cve_from_finding(finding)
    raw_cwe     = finding.get("cwe") or 0
    cvss_score  = float(finding.get("cvssv3_score") or 0.0)
    cvss_vector = finding.get("cvssv3") or None
    severity    = (finding.get("severity") or "Medium").strip().title()

    # Fallback CVSS from severity band when no numeric score is present
    if not cvss_score:
        cvss_score = _SEV_CVSS_FALLBACK.get(severity, 5.0)

    # ── Scanner type detection (strong, DefectDojo-aware) ────────────────
    # Priority:
    #   1. DefectDojo static_finding / dynamic_finding booleans
    #   2. Test metadata (test_type_name, scan_type, title, name, tool, etc.)
    #   3. ALL found_by tools, not only the first one
    #   4. Finding text fallback
    #   5. Default to SCA
    #
    # Why this matters:
    # Some DefectDojo responses expose Semgrep/ZAP only through found_by,
    # scan_type, title, or static/dynamic booleans. The old logic checked only
    # test_type_name or the first found_by item, so mixed SCA/SAST/DAST products
    # were often saved as SCA only.
    raw_test = finding.get("test")
    raw_found_by = finding.get("found_by") or []

    static_flag = bool(finding.get("static_finding") or False)
    dynamic_flag = bool(finding.get("dynamic_finding") or False)

    tool_candidates: List[str] = []

    # Direct DefectDojo booleans are the strongest signal.
    if static_flag:
        tool_candidates.append("semgrep sast static")
    if dynamic_flag:
        tool_candidates.append("zap dast dynamic")

    # Test metadata: may be a prefetched object or just an integer ID.
    if isinstance(raw_test, dict):
        for key in (
            "test_type_name", "scan_type", "title", "name", "tool", "test_type",
        ):
            val = raw_test.get(key)
            if val:
                tool_candidates.append(str(val).lower())

        # Some DefectDojo versions nest scan/test type as dicts.
        for key in ("test_type", "scan_type"):
            val = raw_test.get(key)
            if isinstance(val, dict):
                for subkey in ("name", "title", "test_type_name", "scan_type"):
                    subval = val.get(subkey)
                    if subval:
                        tool_candidates.append(str(subval).lower())
    elif raw_test is not None:
        log.debug(
            f"Finding {finding.get('id')}: 'test' is {type(raw_test).__name__} "
            f"({raw_test!r}) — not a prefetched object. Falling back to found_by."
        )

    # found_by can contain multiple tools. Check all of them, not only first.
    if isinstance(raw_found_by, list):
        for item in raw_found_by:
            if isinstance(item, dict):
                for key in ("name", "title", "test_type_name", "scan_type"):
                    val = item.get(key)
                    if val:
                        tool_candidates.append(str(val).lower())
            else:
                tool_candidates.append(str(item).lower())
    elif raw_found_by:
        tool_candidates.append(str(raw_found_by).lower())

    # Extra fallback from finding text. This helps when DD importers store tool
    # hints in the title/description/path rather than in test metadata.
    for key in ("title", "description", "file_path", "component_name"):
        val = finding.get(key)
        if val:
            tool_candidates.append(str(val).lower())

    tool_blob = " ".join(tool_candidates)
    scanner_type = "SCA"

    # DAST first because ZAP findings can contain web/static words in text too.
    if any(t in tool_blob for t in _DAST_TOOLS) or "dynamic" in tool_blob:
        scanner_type = "DAST"
    elif any(t in tool_blob for t in _SAST_TOOLS) or "static" in tool_blob:
        scanner_type = "SAST"
    elif any(t in tool_blob for t in _SCA_TOOLS):
        scanner_type = "SCA"

    log.debug(
        f"Finding {finding.get('id')} scanner detection: "
        f"static={static_flag}, dynamic={dynamic_flag}, "
        f"tool_blob='{tool_blob[:250]}', scanner_type={scanner_type}"
    )

    # Year from CVE-ID, then finding date, then fallback
    year = year_from_cve(cve_id)
    if year is None:
        date_str = finding.get("date") or finding.get("created") or ""
        if date_str and len(date_str) >= 4:
            try:
                year = int(date_str[:4])
            except ValueError:
                year = None

    # Resolve product name from several possible locations in the response.
    # With ?related_fields=true, DefectDojo nests the product under
    #   finding["related_fields"]["test"]["engagement"]["product"]["name"]
    # but older servers may put it directly on the finding as "product_name".
    product_name = (finding.get("product_name") or "").strip()

    if not product_name:
        related = finding.get("related_fields") or {}
        try:
            product_name = (
                related.get("test", {})
                       .get("engagement", {})
                       .get("product", {})
                       .get("name", "")
            ).strip()
        except (AttributeError, TypeError):
            product_name = ""

    if not product_name:
        # Some DefectDojo versions expose it via the prefetched `test` object
        if isinstance(raw_test, dict):
            try:
                product_name = (
                    raw_test.get("engagement", {})
                            .get("product", {})
                            .get("name", "")
                ).strip()
            except (AttributeError, TypeError):
                product_name = ""

    # ── Display metadata — preserved verbatim from the DefectDojo finding ──
    # These go into VulnFeatures so they're serialised into raw_input and are
    # available to the frontend without any extra DB columns.
    dd_title = (finding.get("title") or "").strip() or None

    # component_name / component_version come from Trivy / Snyk / npm-audit
    dd_component_name    = (finding.get("component_name")    or "").strip() or None
    dd_component_version = (finding.get("component_version") or "").strip() or None

    # file_path is populated by SAST tools (Semgrep) and sometimes by Trivy
    dd_file_path = (finding.get("file_path") or "").strip() or None

    # vulnerability_ids is a list of {"vulnerability_id": "CVE-...", ...} dicts.
    # Fall back to the top-level cve field when the list is absent or empty.
    raw_vuln_ids = finding.get("vulnerability_ids") or []
    if isinstance(raw_vuln_ids, list) and raw_vuln_ids:
        first_vid = raw_vuln_ids[0]
        dd_vuln_id = (
            first_vid.get("vulnerability_id") if isinstance(first_vid, dict) else str(first_vid)
        ) or None
    else:
        dd_vuln_id = cve_id   # already extracted above

    # ── v3.1 binary flags derived from the DefectDojo finding ─────────────
    has_cve    = cve_id is not None
    is_static  = static_flag
    is_dynamic = dynamic_flag

    return VulnFeatures(
        cve_id             = cve_id,
        cvss_score         = cvss_score,
        year               = year,
        cwe                = raw_cwe,
        scanner_type       = scanner_type,
        cvss_vector        = cvss_vector,
        in_kev             = bool(finding.get("known_exploited") or False),
        has_cve            = has_cve,
        is_static          = is_static,
        is_dynamic         = is_dynamic,
        # Display metadata
        title              = dd_title,
        component_name     = dd_component_name,
        component_version  = dd_component_version,
        file_path          = dd_file_path,
        vulnerability_id   = dd_vuln_id,
    ), (product_name or None)


# ══════════════════════════════════════════════════════════════════════════════
# TODO (OPTIONAL): Push AI scores back to DefectDojo
# ══════════════════════════════════════════════════════════════════════════════
#
# When you're ready to write scores back, uncomment and adapt this function.
# Option A: append a note to the finding's notes list.
# Option B: use a custom metadata / tag endpoint.
#
# def push_score_to_defectdojo(
#     finding_id: int, risk_score: float, risk_category: str, predicted_severity: str
# ) -> None:
#     """PATCH a DefectDojo finding with the AI-generated risk metadata."""
#     url = f"{DEFECTDOJO_URL}/api/v2/findings/{finding_id}/"
#     note_text = (
#         f"[AI Risk Scoring v3]  "
#         f"Risk Score: {risk_score:.1f}/100  |  "
#         f"Category: {risk_category}  |  "
#         f"Predicted Severity: {predicted_severity}"
#     )
#     payload = {"risk_accepted": False}   # extend as needed
#     # POST to /api/v2/notes/ to add a note without touching other fields:
#     note_url = f"{DEFECTDOJO_URL}/api/v2/notes/"
#     note_payload = {"entry": note_text, "finding": finding_id}
#     resp = requests.post(note_url, headers=_dd_headers(), json=note_payload, timeout=10)
#     resp.raise_for_status()
#
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB on startup; nothing to tear down on shutdown."""
    init_db()
    log.info("DevSecOps AI API is ready.")
    yield


app = FastAPI(
    title="DevSecOps AI Risk Scoring API",
    description=(
        "XGBoost v3.2-compatible binary EPSS classifier + multiclass severity classifier. "
        "Scores Semgrep, Trivy, and ZAP findings from DefectDojo."
    ),
    version="3.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    # restrict to your dashboard origin in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/health/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/health/", tags=["Meta"], summary="Liveness check + model info")
def health():
    """
    Returns loaded model versions, feature lists, optimal threshold,
    and DB location. Use this to confirm the server is up and models loaded.
    """
    return {
        "status":         "ok",
        "binary_model":   meta_binary["model_version"],
        "multi_model":    meta_multi["model_version"],
        "threshold":      OPTIMAL_THRESHOLD,
        "binary_features": BINARY_FEATURES,
        "multi_features":  MULTI_FEATURES,
        "class_map":      CLASS_MAP,
        "db":             str(DB_PATH),
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/risk-score/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/risk-score/", tags=["Scoring"],
          summary="Binary exploit-likelihood model only")
def risk_score(payload: VulnFeatures):
    """
    Runs only the binary EPSS classifier (model_v3.pkl).

    Returns:
      - exploit_probability (0–1)
      - risk_score (0–100)
      - risk_category (Low / Medium / High)
      - is_high_risk (bool, based on optimal_threshold from metadata)

    Does NOT write to the database.
    Use /api/score-finding/ for persistent scoring.
    """
    row_binary, _, cwe_int, year = resolve_features(payload)
    result = run_binary(row_binary)
    return {
        "cve_id":        payload.cve_id,
        "year":          year,
        "cwe":           cwe_int,
        "scanner_type":  payload.scanner_type,
        **result,
        "model_version": meta_binary["model_version"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/severity-predict/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/severity-predict/", tags=["Scoring"],
          summary="Multiclass severity model only")
def severity_predict(payload: VulnFeatures):
    """
    Runs only the multiclass severity classifier (model_v3_multi.pkl).

    Returns predicted severity class (Low / Medium / High / Critical)
    and the full probability distribution across all four classes.

    Ideal for SAST findings (Semgrep) that have no CVE or EPSS score.
    Does NOT write to the database.
    """
    _, row_multi, cwe_int, year = resolve_features(payload)
    result = run_multi(row_multi)
    return {
        "cve_id":        payload.cve_id,
        "scanner_type":  payload.scanner_type,
        "year":          year,
        "cwe":           cwe_int,
        **result,
        "model_version": meta_multi["model_version"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/score-finding/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/score-finding/", tags=["Scoring"],
          summary="Both models + persist to SQLite (main triage endpoint)")
def score_finding(payload: VulnFeatures):
    """
    Runs BOTH models and stores the combined result in ai_scores.db.
    This is the primary endpoint for production triage.

    Returns the merged output from both models plus the database row ID
    so the dashboard can reference it later.
    """
    row_binary, row_multi, cwe_int, year = resolve_features(payload)

    binary_res = run_binary(row_binary)
    multi_res  = run_multi(row_multi)

    record_id = persist_score(payload, binary_res, multi_res, source="api")

    return {
        "id":            record_id,
        "cve_id":        payload.cve_id,
        "scanner_type":  payload.scanner_type,
        "cvss_score":    payload.cvss_score,
        "year":          year,
        "cwe":           cwe_int,
        # ── Binary model ──────────────────────────────────────────────────────
        "exploit_probability":    binary_res["exploit_probability"],
        "risk_score":             binary_res["risk_score"],
        "risk_category":          binary_res["risk_category"],
        "is_high_risk":           binary_res["is_high_risk"],
        "threshold_used":         OPTIMAL_THRESHOLD,
        # ── Multiclass model ──────────────────────────────────────────────────
        "predicted_severity":     multi_res["predicted_severity"],
        "confidence":             multi_res["confidence"],
        "severity_probabilities": multi_res["probabilities"],
        # ── Meta ──────────────────────────────────────────────────────────────
        "stored":        True,
        "model_versions": {
            "binary": meta_binary["model_version"],
            "multi":  meta_multi["model_version"],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/sync-defectdojo/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/sync-defectdojo/", tags=["DefectDojo"],
          summary="Pull findings from DefectDojo, score all, replace local cache")
def sync_defectdojo(request: SyncDefectDojoRequest):
    """
    Full sync pipeline (replace semantics — NOT append):
      1. Validates DefectDojo credentials from environment variables.
      2. Fetches active findings from /api/v2/findings/ (paginated).
      3. Normalises and scores every finding in memory with both models.
      4. If at least one finding scored successfully:
           a. Deletes existing rows for this product_id where source='defectdojo'.
           b. Inserts the freshly scored rows.
           c. Commits both operations as a single atomic transaction.
      5. If the DefectDojo fetch fails entirely, no rows are touched.
      6. source='api' rows are never deleted or modified.
      7. Other products' cached rows are never deleted or modified.
      8. Returns a summary: totals, severity breakdown, high-risk count.

    This means fixed findings disappear from the dashboard after the next sync
    because the local cache is fully replaced with the current active findings.

    NOTE: This endpoint is READ-ONLY against DefectDojo.
    It does NOT push scores back to DefectDojo yet.
    See the push_score_to_defectdojo() TODO block above when you're ready.
    """
    # ── Validate environment config ───────────────────────────────────────────
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        raise HTTPException(
            status_code=503,
            detail=(
                "DEFECTDOJO_URL and DEFECTDOJO_API_KEY must be set in .env. "
                "See .env.example."
            ),
        )

    # ── Resolve product_id ────────────────────────────────────────────────────
    # Priority: explicit product_id → product_name lookup → env-var fallback.
    product_id   = request.product_id      # already validated ge=1 by Pydantic
    product_name = request.product_name    # optional human-readable name

    if product_id:
        # product_id supplied directly — accept as-is.  product_name (if also
        # supplied) is ignored because the numeric ID is unambiguous.
        pass

    elif product_name:
        # Resolve the name to an id via the DefectDojo products API.
        product_id, product_name = resolve_dd_product_id(product_name)
        log.info(f"Resolved product name '{request.product_name}' → product_id={product_id}")

    else:
        # Neither field provided — fall back to DEFECTDOJO_PRODUCT_ID in .env.
        if DEFECTDOJO_PRODUCT_ID:
            try:
                product_id = int(DEFECTDOJO_PRODUCT_ID)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="DEFECTDOJO_PRODUCT_ID in .env is not a valid integer.",
                )
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Provide product_id or product_name in the request body, "
                    "or set DEFECTDOJO_PRODUCT_ID in .env."
                ),
            )

    # Capture the resolved product name so it can be used as a fallback for
    # findings that don't carry an embedded product name in the API response.
    # product_name is set when the caller supplied a name (or it was looked up);
    # it remains None when only product_id was provided or the env-var was used.
    resolved_product_name: Optional[str] = product_name

    # ── Fetch findings ────────────────────────────────────────────────────────
    log.info(
        f"DefectDojo sync: product_id={product_id}, "
        f"active_only={request.active_only}, limit={request.limit}"
    )
    try:
        findings = fetch_dd_findings(
            product_id  = product_id,
            active_only = request.active_only,
            limit       = request.limit,
        )
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"DefectDojo API returned HTTP {exc.response.status_code}: "
                   f"{exc.response.text[:300]}",
        )
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach DefectDojo at '{DEFECTDOJO_URL}': {exc}",
        )

    total_fetched = len(findings)
    log.info(f"Fetched {total_fetched} findings from DefectDojo product {product_id}")

    # ── Phase 1: Score all findings into memory ───────────────────────────────
    # We score everything before touching the DB so that a mid-loop model error
    # never leaves the cache in a half-written state.
    scored_rows: List[tuple] = []
    skipped = 0
    high_risk_count = 0
    severity_breakdown: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    errors: List[Dict] = []

    for finding in findings:
        finding_id = finding.get("id")
        try:
            vuln, dd_product_name = normalise_dd_finding(finding)
            # Use the product name embedded in the finding response when available;
            # fall back to the resolved name from the sync request (product_name
            # lookup or request.product_name).  This ensures every row carries a
            # meaningful product label even when DefectDojo omits it from the
            # finding payload.
            row_product_name = dd_product_name or resolved_product_name
            row_binary, row_multi, _, _ = resolve_features(vuln)

            binary_res = run_binary(row_binary)
            multi_res  = run_multi(row_multi)

            probs = multi_res["probabilities"]
            scored_rows.append((
                datetime.now(timezone.utc).isoformat(),
                vuln.cve_id,
                vuln.scanner_type,
                vuln.cvss_score,
                binary_res["exploit_probability"],
                binary_res["risk_score"],
                binary_res["risk_category"],
                int(binary_res["is_high_risk"]),
                multi_res["predicted_severity"],
                probs["Low"],
                probs["Medium"],
                probs["High"],
                probs["Critical"],
                "defectdojo",
                finding_id,
                row_product_name,
                product_id,          # store the synced product_id on every row
                vuln.model_dump_json(),
            ))

            if binary_res["is_high_risk"]:
                high_risk_count += 1

            sev = multi_res["predicted_severity"]
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1

        except Exception as exc:
            skipped += 1
            errors.append({"finding_id": finding_id, "error": str(exc)})
            log.warning(f"Failed to score DefectDojo finding {finding_id}: {exc}")

    scored = len(scored_rows)

    # ── Phase 2: Atomic replace — delete old cache for THIS product only ─────
    # The DELETE targets only rows for the currently synced product_id so that
    # other products' cached findings (JuiceShop, DVWA, etc.) are preserved.
    # The DELETE only runs when at least one finding scored successfully.
    # source='api' rows are never touched regardless.
    stored = 0
    if scored_rows:
        with get_db() as con:
            con.execute(
                "DELETE FROM ai_scores WHERE source = 'defectdojo' AND product_id = ?",
                (product_id,),
            )
            con.executemany(
                """
                INSERT INTO ai_scores (
                    created_at, cve_id, scanner_type, cvss_score,
                    exploit_probability, risk_score, risk_category, is_high_risk,
                    predicted_severity, prob_low, prob_medium, prob_high, prob_critical,
                    source, defectdojo_finding_id, product_name, product_id, raw_input
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                scored_rows,
            )
            stored = scored
        log.info(
            f"Sync complete: replaced defectdojo cache for product_id={product_id} "
            f"with {stored} findings ({skipped} failed to score, {high_risk_count} high-risk)."
        )
    else:
        log.warning(
            f"Sync: 0 of {total_fetched} findings scored successfully "
            f"({skipped} failed). Old DefectDojo cache for product_id={product_id} was NOT modified."
        )

    return {
        "product_id":         product_id,
        "total_fetched":      total_fetched,
        "scored":             scored,
        "stored":             stored,
        "skipped_on_error":   skipped,
        "high_risk_flagged":  high_risk_count,
        "severity_breakdown": severity_breakdown,
        "errors":             errors if errors else None,
        "note": (
            f"DefectDojo cache replaced atomically for product_id={product_id} only. "
            "Other products' cached rows are untouched. "
            "source='api' rows are untouched. "
            "DefectDojo findings have NOT been modified. "
            "See push_score_to_defectdojo() TODO in main.py when ready to write back."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/scores/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/scores/", tags=["Meta"],
         summary="Browse stored AI scores from SQLite")
def get_scores(
    source:       Optional[str]  = Query(None, description="Filter by source: 'api' or 'defectdojo'"),
    is_high_risk: Optional[bool] = Query(None, description="Filter by high-risk flag"),
    severity:     Optional[str]  = Query(None, description="Filter by predicted_severity: Critical/High/Medium/Low"),
    product_id:   Optional[int]  = Query(None, description="Filter by DefectDojo product_id (defectdojo rows only)"),
    limit:        int             = Query(50, ge=1, le=2000),
):
    """Browse the most recent AI score records stored in SQLite."""
    query  = "SELECT * FROM ai_scores"
    params: List[Any] = []
    where: List[str]  = []

    if source:
        where.append("source = ?")
        params.append(source)
    if is_high_risk is not None:
        where.append("is_high_risk = ?")
        params.append(int(is_high_risk))
    if severity:
        where.append("predicted_severity = ?")
        params.append(severity.title())
    if product_id is not None:
        where.append("product_id = ?")
        params.append(product_id)

    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_db() as con:
        rows = con.execute(query, params).fetchall()

    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/products/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/products/", tags=["DefectDojo"],
         summary="List all DefectDojo products available for syncing")
def get_products():
    """
    Proxies GET /api/v2/products/ from DefectDojo and returns a slim list of
    ``{"id": int, "name": str}`` objects — one per product.

    Use the returned ``id`` or ``name`` values as inputs to
    ``POST /api/sync-defectdojo/`` instead of guessing numeric IDs.

    Example response::

        [
            {"id": 1, "name": "JuiceShop"},
            {"id": 2, "name": "DVWA"},
            {"id": 3, "name": "DVNA"},
            {"id": 4, "name": "NodeGoat"}
        ]
    """
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        raise HTTPException(
            status_code=503,
            detail=(
                "DEFECTDOJO_URL and DEFECTDOJO_API_KEY must be set in .env. "
                "See .env.example."
            ),
        )
    try:
        return fetch_dd_products()
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"DefectDojo API returned HTTP {exc.response.status_code}: "
                   f"{exc.response.text[:300]}",
        )
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach DefectDojo at '{DEFECTDOJO_URL}': {exc}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/notifications/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/notifications/", tags=["Meta"],
         summary="Most recent high-risk findings as notifications")
def get_notifications(limit: int = Query(10, ge=1, le=50)):
    """
    Returns the most recently stored high-risk findings formatted as
    notification objects for the dashboard sidebar.
    """
    with get_db() as con:
        rows = con.execute(
            """
            SELECT id, cve_id, predicted_severity, risk_score, risk_category,
                   scanner_type, source, defectdojo_finding_id, product_name, created_at
            FROM   ai_scores
            WHERE  is_high_risk = 1
            ORDER  BY id DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()

    results = []
    for r in rows:
        r = dict(r)
        cve      = r["cve_id"] or "N/A"
        sev      = r["predicted_severity"] or "High"
        score    = round(r["risk_score"] or 0, 1)
        scanner  = r["scanner_type"] or "scanner"
        category = r["risk_category"] or "High"
        product  = r["product_name"] or "Unknown"

        message = (
            f"{sev} severity {cve} flagged by {scanner} — "
            f"AI risk score {score}/100 ({category})"
        ) if cve != "N/A" else (
            f"{sev} severity finding flagged by {scanner} — "
            f"AI risk score {score}/100 ({category})"
        )

        results.append({
            "id":                    r["id"],
            "cve":                   cve,
            "severity":              sev,
            "risk_score":            score,
            "scanner_type":          scanner,
            "source":                r["source"],
            "defectdojo_finding_id": r["defectdojo_finding_id"],
            "product_name":          product,
            "created_at":            r["created_at"],
            "message":               message,
        })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/trends/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/trends/", tags=["Meta"],
         summary="Weekly severity counts for trend charts")
def get_trends(weeks: int = Query(8, ge=1, le=52)):
    """
    Aggregates ai_scores by ISO week and returns per-severity counts,
    suitable for the dashboard trend line/bar chart.
    """
    with get_db() as con:
        rows = con.execute(
            """
            SELECT
                strftime('%Y-W%W', created_at)          AS week,
                SUM(predicted_severity = 'Critical')    AS critical,
                SUM(predicted_severity = 'High')        AS high,
                SUM(predicted_severity = 'Medium')      AS medium,
                SUM(predicted_severity = 'Low')         AS low_count,
                COUNT(*)                                AS total,
                SUM(is_high_risk)                       AS high_risk,
                ROUND(AVG(risk_score), 1)               AS avg_risk_score
            FROM   ai_scores
            WHERE  created_at >= datetime('now', ? || ' days')
            GROUP  BY week
            ORDER  BY week ASC
            """,
            (f"-{weeks * 7}",),
        ).fetchall()

    return [
        {
            "date":           r["week"],
            "Critical":       int(r["critical"]   or 0),
            "High":           int(r["high"]        or 0),
            "Medium":         int(r["medium"]      or 0),
            "Low":            int(r["low_count"]   or 0),
            "total":          int(r["total"]       or 0),
            "high_risk":      int(r["high_risk"]   or 0),
            "avg_risk_score": float(r["avg_risk_score"] or 0.0),
        }
        for r in rows
    ]
