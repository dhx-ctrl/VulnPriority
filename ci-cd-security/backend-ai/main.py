"""
DevSecOps AI Risk Scoring API  ·  main.py
==========================================
FastAPI backend for the final VulnPriority binary EPSS-based risk prioritization model.

Architecture:
  /api/login/              → dashboard login, returns API token
  /api/users/              → protected local user creation/listing
  /api/health/             → liveness + model info
  /api/risk-score/         → binary EPSS prioritization model only
  /api/score-finding/      → binary model + persist to SQLite
  /api/sync-defectdojo/    → pull DefectDojo findings, keep scanner severity, score all, store all
  /api/scores/             → browse stored results

Final model decision:
  - The previous multiclass severity model was removed from the production workflow.
  - DefectDojo/scanner severity is preserved as the severity label.
  - The AI model only adds prioritization: exploit_probability, AI risk score,
    AI risk category, and high-risk flag.

Preprocessing rules (important):
  - Feature order is enforced by BINARY_FEATURES from model_meta_v3.json
  - CWE normalised: "CWE-79", "79.0", 79 → int 79, then bucketed against the
    fitted cwe_top LabelEncoder classes (dynamic — no hardcoded CWE list)
  - Year extracted from CVE-ID when not supplied; median year (2022) as final fallback
  - Unknown categorical values → "UNKNOWN" (or "OTHER" for cwe_top bucket)
  - cvss_score missing → severity-based fallback, then 5.0
  - CVSS vector string parsed if supplied; overrides individual component fields
  - EPSS score / percentile are NOT input features; EPSS was used only to build the training target
"""

# ─── stdlib ──────────────────────────────────────────────────────────────────
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─── third-party ─────────────────────────────────────────────────────────────
import joblib
import numpy as np
import pandas as pd
import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query
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

# Lightweight local API authentication.
# Protected endpoints require this token in the HTTP header:
#   X-API-Key: <API_AUTH_TOKEN>
# Keep /api/health/, /docs and /openapi.json open for local diagnostics.
API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN", "").strip()
API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN", "").strip()
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()
AUTH_HEADER_NAME = "X-API-Key"

# Dashboard login credentials for the local prototype.
# The frontend sends these to POST /api/login/.
# On success, the backend returns API_AUTH_TOKEN to the dashboard.
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()

# Allowed dashboard origins for CORS.
# Do not use allow_origins=["*"] because protected API endpoints should only
# accept browser requests from the local dashboard origin.
DASHBOARD_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "DASHBOARD_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500"
    ).split(",")
    if origin.strip()
]




# ══════════════════════════════════════════════════════════════════════════════
# LIGHTWEIGHT API AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_session_user(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None

    token_digest = _token_hash(token)

    with get_db() as con:
        row = con.execute(
            """
            SELECT
                s.id AS session_id,
                s.username,
                s.is_admin,
                s.created_at,
                u.id AS user_id,
                u.display_name,
                u.is_active,
                u.access_status
            FROM dashboard_sessions s
            LEFT JOIN dashboard_users u ON u.username = s.username
            WHERE s.token_hash = ?
            """,
            (token_digest,),
        ).fetchone()

    if not row:
        return None

    data = dict(row)

    # If this is a SQLite-backed user, enforce current access status even if
    # they still have an old session token saved in the browser.
    if data.get("user_id") is not None:
        if not data.get("is_active") or data.get("access_status") != "approved":
            return None

    return {
        "username": data["username"],
        "display_name": data.get("display_name") or data["username"],
        "is_admin": bool(data.get("is_admin")),
        "source": "session",
    }


def require_api_key(x_api_key: Optional[str] = Header(default=None, alias=AUTH_HEADER_NAME)) -> Dict[str, Any]:
    """
    Accept either:
      1. API_AUTH_TOKEN from .env as a bootstrap/admin token
      2. A login session token returned by /api/login/

    The old API_AUTH_TOKEN path is kept so your PowerShell/backend tests still work.
    The frontend login now receives a per-login session token instead of always
    receiving the raw API_AUTH_TOKEN.
    """
    if not API_AUTH_TOKEN:
        raise HTTPException(
            status_code=503,
            detail=(
                "Backend API authentication is enabled but API_AUTH_TOKEN is not set. "
                "Add API_AUTH_TOKEN to your backend .env file and send it as X-API-Key."
            ),
        )

    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid or missing API key. Send the token in the {AUTH_HEADER_NAME} header.",
        )

    # Bootstrap/admin token from .env. Useful for local tests and first setup.
    if secrets.compare_digest(str(x_api_key), API_AUTH_TOKEN):
        return {
            "username": DASHBOARD_USERNAME or "admin",
            "display_name": "Bootstrap Admin",
            "is_admin": True,
            "source": "env-token",
        }

    session_user = get_session_user(str(x_api_key))
    if session_user:
        return session_user

    raise HTTPException(
        status_code=401,
        detail=f"Invalid or missing API key. Send the token in the {AUTH_HEADER_NAME} header.",
    )


def require_admin_user(current_user: Dict[str, Any] = Depends(require_api_key)) -> Dict[str, Any]:
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return current_user

PROTECTED_ENDPOINT = [Depends(require_api_key)]

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard user helpers
# ─────────────────────────────────────────────────────────────────────────────

_PASSWORD_ALGORITHM = "pbkdf2_sha256"
_PASSWORD_ITERATIONS = 120_000


def hash_password(password: str) -> str:
    """
    Hash a dashboard password using only Python stdlib.

    Format:
      pbkdf2_sha256$iterations$salt$hash
    """
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        _PASSWORD_ITERATIONS,
    ).hex()
    return f"{_PASSWORD_ALGORITHM}${_PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2 hash."""
    try:
        algorithm, iterations_raw, salt, expected = stored_hash.split("$", 3)
        if algorithm != _PASSWORD_ALGORITHM:
            return False
        iterations = int(iterations_raw)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def password_is_valid(password: str) -> bool:
    """At least 6 chars, one letter, one number, and one special character."""
    if len(password) < 6:
        return False
    if not re.search(r"[A-Za-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


def safe_user(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row.get("id"),
        "username": row.get("username"),
        "display_name": row.get("display_name") or row.get("username"),
        "is_admin": bool(row.get("is_admin")),
        "is_active": bool(row.get("is_active")),
        "access_status": row.get("access_status") or ("approved" if row.get("is_active") else "pending"),
        "created_at": row.get("created_at"),
        "last_login_at": row.get("last_login_at"),
    }


def get_dashboard_user(username: str) -> Optional[Dict[str, Any]]:
    """Return a dashboard user row as dict, including pending/disabled users."""
    with get_db() as con:
        row = con.execute(
            """
            SELECT id, username, password_hash, display_name, is_admin, is_active,
                   access_status, created_at, last_login_at
            FROM dashboard_users
            WHERE username = ?
            """,
            (username.strip(),),
        ).fetchone()

    return dict(row) if row else None


def create_dashboard_user(
    *,
    username: str,
    password: str,
    display_name: Optional[str] = None,
    is_admin: bool = False,
    access_status: str = "pending",
) -> Dict[str, Any]:
    """Create a dashboard user in SQLite and return a safe user object."""
    username = username.strip()
    access_status = access_status.strip().lower()

    if access_status not in {"pending", "approved", "disabled"}:
        raise HTTPException(status_code=400, detail="Invalid access_status.")

    if not password_is_valid(password):
        raise HTTPException(
            status_code=422,
            detail="Password must be at least 6 characters and include one letter, one number, and one special character.",
        )

    now = datetime.now(timezone.utc).isoformat()
    pwd_hash = hash_password(password)
    is_active = 1 if access_status == "approved" else 0

    try:
        with get_db() as con:
            cur = con.execute(
                """
                INSERT INTO dashboard_users (
                    username, password_hash, display_name, is_admin, is_active,
                    access_status, created_at, last_login_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    username,
                    pwd_hash,
                    display_name or username,
                    int(is_admin),
                    int(is_active),
                    access_status,
                    now,
                ),
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="A user with this username already exists.")

    return {
        "id": user_id,
        "username": username,
        "display_name": display_name or username,
        "is_admin": bool(is_admin),
        "is_active": bool(is_active),
        "access_status": access_status,
        "created_at": now,
    }


def create_dashboard_session(username: str, is_admin: bool) -> str:
    token = secrets.token_urlsafe(32)
    token_digest = _token_hash(token)
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as con:
        con.execute(
            """
            INSERT INTO dashboard_sessions (token_hash, username, is_admin, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (token_digest, username, int(is_admin), now),
        )

    return token


def authenticate_dashboard_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate against SQLite users first.

    Pending users are recognized but not allowed into the dashboard.
    The .env admin remains as a bootstrap admin.
    """
    username = username.strip()

    db_user = get_dashboard_user(username)

    if db_user and verify_password(password, db_user["password_hash"]):
        status = db_user.get("access_status") or ("approved" if db_user.get("is_active") else "pending")

        if status == "pending":
            return {
                "auth_blocked": True,
                "code": "ACCESS_PENDING",
                "message": "Your account was created. Contact an admin to give you access.",
                "username": username,
                "access_status": "pending",
            }

        if status == "disabled" or not db_user.get("is_active"):
            return {
                "auth_blocked": True,
                "code": "ACCESS_DISABLED",
                "message": "Your account is disabled. Contact an admin.",
                "username": username,
                "access_status": "disabled",
            }

        with get_db() as con:
            con.execute(
                "UPDATE dashboard_users SET last_login_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), db_user["id"]),
            )

        return {
            "name": db_user.get("display_name") or db_user["username"],
            "email": f"{db_user['username']}@devsecops.local",
            "avatar": (db_user["username"][:1] or "U").upper(),
            "username": db_user["username"],
            "is_admin": bool(db_user.get("is_admin")),
            "access_status": "approved",
            "source": "sqlite",
        }

    # Bootstrap fallback from .env.
    if DASHBOARD_PASSWORD and username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD:
        return {
            "name": "Admin User",
            "email": f"{DASHBOARD_USERNAME}@devsecops.local",
            "avatar": (DASHBOARD_USERNAME[:1] or "A").upper(),
            "username": DASHBOARD_USERNAME,
            "is_admin": True,
            "access_status": "approved",
            "source": "env",
        }

    return None

# ══════════════════════════════════════════════════════════════════════════════
# MODEL LOADING  (happens once at import time, not per-request)
# ══════════════════════════════════════════════════════════════════════════════

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


# ── Dual sklearn Pipeline models ─────────────────────────────────────────────
# The backend now loads TWO XGBoost/sklearn Pipeline artifacts:
#   1) Clean leakage-safe triage model
#      - strict scientific signal, no CVSS/severity shortcut features
#   2) EPSS-only operational ranker
#      - practical queue-sorting model, allowed to use CVSS because the target is EPSS-only
#
# Required .env values:
#   AI_CLEAN_MODEL_DIR=model_output_FINAL_clean_minimal_features
#   AI_RANKER_MODEL_DIR=model_output_EPSS_operational_ranker
#
# Backwards compatibility:
#   If AI_CLEAN_MODEL_DIR is absent, AI_MODEL_DIR is used for the clean model.
#   The old response fields risk_score/risk_category/is_high_risk remain aliases
#   for the operational ranker so existing frontend logic keeps working.

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
    scanner_severity        TEXT,
    defectdojo_severity     TEXT,
    predicted_severity      TEXT,   -- legacy alias; stores scanner_severity for old UI compatibility
    prob_low                REAL,   -- legacy nullable; multiclass model removed
    prob_medium             REAL,   -- legacy nullable; multiclass model removed
    prob_high               REAL,   -- legacy nullable; multiclass model removed
    prob_critical           REAL,   -- legacy nullable; multiclass model removed
    source                  TEXT,
    defectdojo_finding_id   INTEGER,
    product_name            TEXT,
    product_id              INTEGER,

    -- Two-model output fields. Legacy risk_score/risk_category/is_high_risk
    -- remain aliases for the operational ranker.
    clean_ai_score                 REAL,
    clean_ai_category              TEXT,
    clean_is_high_risk             INTEGER,
    clean_exploit_probability      REAL,
    clean_threshold_used           REAL,
    clean_model_version            TEXT,

    operational_rank_score         REAL,
    operational_rank_category      TEXT,
    operational_is_high_risk       INTEGER,
    operational_exploit_probability REAL,
    operational_threshold_used     REAL,
    operational_rank_percentile    REAL,
    operational_model_version      TEXT,

    raw_input               TEXT
);
"""

_SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_scores_source      ON ai_scores(source);
CREATE INDEX IF NOT EXISTS idx_scores_high_risk   ON ai_scores(is_high_risk);
CREATE INDEX IF NOT EXISTS idx_scores_created     ON ai_scores(created_at);
CREATE INDEX IF NOT EXISTS idx_scores_dd_finding  ON ai_scores(defectdojo_finding_id);
CREATE INDEX IF NOT EXISTS idx_scores_product_id  ON ai_scores(product_id);
CREATE INDEX IF NOT EXISTS idx_scores_operational_score ON ai_scores(operational_rank_score);
CREATE INDEX IF NOT EXISTS idx_scores_clean_high_risk   ON ai_scores(clean_is_high_risk);
"""

_SCHEMA_USERS = """
CREATE TABLE IF NOT EXISTS dashboard_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    display_name    TEXT,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    is_active       INTEGER NOT NULL DEFAULT 0,
    access_status   TEXT    NOT NULL DEFAULT 'pending',
    created_at      TEXT    NOT NULL,
    last_login_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_dashboard_users_username ON dashboard_users(username);
CREATE INDEX IF NOT EXISTS idx_dashboard_users_status   ON dashboard_users(access_status);

CREATE TABLE IF NOT EXISTS dashboard_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT    NOT NULL UNIQUE,
    username        TEXT    NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_token ON dashboard_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_user  ON dashboard_sessions(username);
"""

_SCHEMA_NOTIFICATIONS = """
CREATE TABLE IF NOT EXISTS app_notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    title           TEXT    NOT NULL,
    message         TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'Info',
    product_name    TEXT,
    product_id      INTEGER,
    username        TEXT,
    is_read         INTEGER NOT NULL DEFAULT 0,
    metadata_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_app_notifications_created ON app_notifications(created_at);
CREATE INDEX IF NOT EXISTS idx_app_notifications_kind    ON app_notifications(kind);
CREATE INDEX IF NOT EXISTS idx_app_notifications_read    ON app_notifications(is_read);
"""



# Minimum columns that MUST exist for the app to function.
# If the table is missing any of these it is from an incompatible old schema
# and will be dropped + recreated (safe: ai_scores is a local scoring cache,
# not a source-of-truth store — data can always be regenerated by re-syncing).
_CORE_COLS = {"id", "created_at", "exploit_probability", "risk_score"}

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
    ("scanner_severity",      "TEXT"),
    ("defectdojo_severity",   "TEXT"),
    ("predicted_severity",    "TEXT"),  # legacy alias; stores scanner_severity
    ("prob_low",              "REAL"),  # legacy nullable; multiclass model removed
    ("prob_medium",           "REAL"),
    ("prob_high",             "REAL"),
    ("prob_critical",         "REAL"),
    ("source",                "TEXT"),
    ("defectdojo_finding_id", "INTEGER"),
    ("product_name",          "TEXT"),
    ("product_id",            "INTEGER"),
    ("clean_ai_score",                 "REAL"),
    ("clean_ai_category",              "TEXT"),
    ("clean_is_high_risk",             "INTEGER"),
    ("clean_exploit_probability",      "REAL"),
    ("clean_threshold_used",           "REAL"),
    ("clean_model_version",            "TEXT"),
    ("operational_rank_score",         "REAL"),
    ("operational_rank_category",      "TEXT"),
    ("operational_is_high_risk",       "INTEGER"),
    ("operational_exploit_probability", "REAL"),
    ("operational_threshold_used",     "REAL"),
    ("operational_rank_percentile",    "REAL"),
    ("operational_model_version",      "TEXT"),
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

        # Dashboard user table for lightweight local authentication.
        # The .env admin login remains as a bootstrap fallback, but newly created
        # users are stored here with PBKDF2 password hashes.
        con.executescript(_SCHEMA_USERS)

        # User table migration for older DBs.
        user_cols = {
            row[1]
            for row in con.execute("PRAGMA table_info(dashboard_users)").fetchall()
        }

        if "access_status" not in user_cols:
            con.execute(
                "ALTER TABLE dashboard_users ADD COLUMN access_status TEXT NOT NULL DEFAULT 'approved'"
            )
            log.info("DB migration: added dashboard_users.access_status")

        # Existing old users were already active, so mark them approved.
        con.execute(
            """
            UPDATE dashboard_users
            SET access_status = 'approved'
            WHERE is_active = 1 AND (access_status IS NULL OR access_status = '')
            """
        )

        # Dashboard notification table for pending users, sync events, and Review First alerts.
        con.executescript(_SCHEMA_NOTIFICATIONS)

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


def create_app_notification(
    *,
    kind: str,
    title: str,
    message: str,
    severity: str = "Info",
    product_name: Optional[str] = None,
    product_id: Optional[int] = None,
    username: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Store a dashboard notification.

    Used for pending user registrations, sync completed events, and future
    dashboard/system messages.
    """
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as con:
        con.execute(
            """
            INSERT INTO app_notifications (
                created_at, kind, title, message, severity,
                product_name, product_id, username, is_read, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                now,
                kind,
                title,
                message,
                severity,
                product_name,
                product_id,
                username,
                json.dumps(metadata or {}, ensure_ascii=False),
            ),
        )


def _human_notification_time(iso_str: Optional[str]) -> str:
    if not iso_str:
        return ""

    try:
        dt = datetime.fromisoformat(str(iso_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt

        seconds = int(delta.total_seconds())
        if seconds < 60:
            return f"{seconds}s ago"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        return f"{seconds // 86400}d ago"
    except Exception:
        return ""

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
    scanner_severity:        str             = Field("Medium",    description="Original scanner/DefectDojo severity: Critical | High | Medium | Low | Info")
    defectdojo_severity:     Optional[str]   = Field(None,        description="Alias for scanner_severity when imported from DefectDojo")
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

    # ── Leakage-safe pipeline features / metadata inputs ─────────────────────
    # These are optional so existing API callers do not break. The backend
    # derives sensible defaults from DefectDojo fields when they are absent.
    package_name:      Optional[str] = Field(None, description="Alias for component_name/package name")
    published:         Optional[str] = Field(None, description="Published date/string if available")
    modified:          Optional[str] = Field(None, description="Modified date/string if available")
    withdrawn:         Optional[str] = Field(None, description="Withdrawn date/string if available")
    published_year:    Optional[int] = Field(None, description="Published year if already available")

    ranges_count:      int = Field(0, ge=0, description="Number of affected ranges if available")
    versions_count:    int = Field(0, ge=0, description="Number of affected versions if available")
    summary_len:       Optional[int] = Field(None, ge=0, description="Length of title/summary text")
    details_len:       Optional[int] = Field(None, ge=0, description="Length of description/details text")
    references_count:  int = Field(0, ge=0, description="Approximate number of reference URLs")

    github_reviewed:   bool = Field(False, description="Whether the advisory was GitHub reviewed, if known")
    has_patch_ref:     bool = Field(False, description="Whether references/text mention patch/fix/commit")
    has_advisory_ref:  bool = Field(False, description="Whether references/text mention advisory sources")

    # Raw fields retained only for compatibility with older trained feature sets.
    # The final minimal model drops these, but this lets the same backend run
    # either the 26-feature final model or an older leakage-safe pipeline.
    cwe_id:            Optional[Any] = Field(None, description="Raw CWE id alias")
    all_cwe_ids:       Optional[Any] = Field(None, description="Raw all-CWE list/string alias")
    data_source:       Optional[str] = Field(None, description="Optional source metadata, normally dropped in final model")
    source_dataset:    Optional[str] = Field(None, description="Optional source metadata, normally dropped in final model")

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

    @field_validator("scanner_severity", "defectdojo_severity", mode="before")
    @classmethod
    def _title_severity(cls, v: Any) -> str:
        raw = str(v or "Medium").strip().title()
        return "Medium" if raw in {"", "None", "Null"} else raw

    @model_validator(mode="after")
    def _resolve_defectdojo_severity(self) -> "VulnFeatures":
        if self.defectdojo_severity:
            self.scanner_severity = self.defectdojo_severity.title()
        else:
            self.defectdojo_severity = self.scanner_severity.title()
        return self


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


class LoginRequest(BaseModel):
    """Dashboard login request."""
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class RegisterRequest(BaseModel):
    """Public account registration request."""
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=6, max_length=128)

    @field_validator("username")
    @classmethod
    def _clean_username(cls, v: str) -> str:
        cleaned = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", cleaned):
            raise ValueError("Username may only contain letters, numbers, dot, underscore, or dash.")
        return cleaned

    @field_validator("password")
    @classmethod
    def _valid_password(cls, v: str) -> str:
        if not password_is_valid(v):
            raise ValueError("Password must include one letter, one number, and one special character.")
        return v


class UserCreateRequest(BaseModel):
    """Admin-created dashboard user."""
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=6, max_length=128)
    display_name: Optional[str] = Field(None, max_length=128)
    is_admin: bool = Field(False)
    access_status: str = Field("approved", description="pending | approved | disabled")

    @field_validator("username")
    @classmethod
    def _clean_username(cls, v: str) -> str:
        cleaned = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", cleaned):
            raise ValueError("Username may only contain letters, numbers, dot, underscore, or dash.")
        return cleaned

    @field_validator("password")
    @classmethod
    def _valid_password(cls, v: str) -> str:
        if not password_is_valid(v):
            raise ValueError("Password must include one letter, one number, and one special character.")
        return v

    @field_validator("access_status")
    @classmethod
    def _valid_status(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if cleaned not in {"pending", "approved", "disabled"}:
            raise ValueError("access_status must be pending, approved, or disabled.")
        return cleaned


class UserAccessUpdateRequest(BaseModel):
    access_status: Optional[str] = Field(None, description="pending | approved | disabled")
    is_admin: Optional[bool] = None

    @field_validator("access_status")
    @classmethod
    def _valid_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        cleaned = v.strip().lower()
        if cleaned not in {"pending", "approved", "disabled"}:
            raise ValueError("access_status must be pending, approved, or disabled.")
        return cleaned


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE RESOLUTION  (VulnFeatures → model-ready rows)
# ══════════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════════
# PREDICTION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════════
# SQLITE PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════

def _score_record_tuple(
    *,
    payload: VulnFeatures,
    dual_res: Dict[str, Any],
    sev: str,
    source: str,
    defectdojo_finding_id: Optional[int],
    product_name: Optional[str],
    product_id: Optional[int],
) -> tuple:
    """Build the INSERT tuple for ai_scores, keeping legacy aliases intact."""
    return (
        datetime.now(timezone.utc).isoformat(),
        payload.cve_id,
        payload.scanner_type,
        payload.cvss_score,
        dual_res["exploit_probability"],
        dual_res["risk_score"],
        dual_res["risk_category"],
        int(dual_res["is_high_risk"]),
        sev,
        sev,
        sev,          # legacy predicted_severity alias for old UI code
        None,
        None,
        None,
        None,
        source,
        defectdojo_finding_id,
        product_name,
        product_id,
        dual_res.get("clean_ai_score"),
        dual_res.get("clean_ai_category"),
        int(bool(dual_res.get("clean_is_high_risk"))),
        dual_res.get("clean_exploit_probability"),
        dual_res.get("clean_threshold_used"),
        dual_res.get("clean_model_version"),
        dual_res.get("operational_rank_score"),
        dual_res.get("operational_rank_category"),
        int(bool(dual_res.get("operational_is_high_risk"))),
        dual_res.get("operational_exploit_probability"),
        dual_res.get("operational_threshold_used"),
        dual_res.get("operational_rank_percentile"),
        dual_res.get("operational_model_version"),
        payload.model_dump_json(),
    )


_AI_SCORE_INSERT_SQL = """
INSERT INTO ai_scores (
    created_at, cve_id, scanner_type, cvss_score,
    exploit_probability, risk_score, risk_category, is_high_risk,
    scanner_severity, defectdojo_severity, predicted_severity,
    prob_low, prob_medium, prob_high, prob_critical,
    source, defectdojo_finding_id, product_name, product_id,
    clean_ai_score, clean_ai_category, clean_is_high_risk,
    clean_exploit_probability, clean_threshold_used, clean_model_version,
    operational_rank_score, operational_rank_category, operational_is_high_risk,
    operational_exploit_probability, operational_threshold_used,
    operational_rank_percentile, operational_model_version,
    raw_input
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def persist_score(
    payload: VulnFeatures,
    binary_res: Dict,
    source: str = "api",
    defectdojo_finding_id: Optional[int] = None,
    product_name: Optional[str] = None,
    product_id: Optional[int] = None,
) -> int:
    """
    Insert both AI model outputs and preserve original scanner severity.

    Legacy fields risk_score/risk_category/is_high_risk are stored as aliases
    for the operational EPSS ranker so existing frontend code remains stable.
    """
    sev = (payload.scanner_severity or payload.defectdojo_severity or "Medium").title()
    with get_db() as con:
        cur = con.execute(
            _AI_SCORE_INSERT_SQL,
            _score_record_tuple(
                payload=payload,
                dual_res=binary_res,
                sev=sev,
                source=source,
                defectdojo_finding_id=defectdojo_finding_id,
                product_name=product_name,
                product_id=product_id,
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

    # ── Scanner type detection (DefectDojo-aware, with SCA preserved) ───
    # Priority:
    #   1. Explicit tool names from test/found_by/text:
    #        ZAP/Burp/etc.    -> DAST
    #        Trivy/npm/Snyk   -> SCA
    #        Semgrep/Sonar    -> SAST
    #   2. DefectDojo dynamic_finding flag -> DAST
    #   3. DefectDojo static_finding flag  -> SAST only as a last fallback
    #   4. Default -> SCA
    #
    # Important: DefectDojo often marks SCA imports such as Trivy as
    # static_finding=True. Therefore static_finding must NOT automatically
    # override explicit SCA tool names, otherwise Trivy becomes SAST.
    raw_test = finding.get("test")
    raw_found_by = finding.get("found_by") or []

    static_flag = bool(finding.get("static_finding") or False)
    dynamic_flag = bool(finding.get("dynamic_finding") or False)

    tool_candidates: List[str] = []

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

    # Extra fallback from finding text.
    # Keep this useful but do not let generic static_finding flags dominate.
    for key in ("title", "description", "file_path", "component_name"):
        val = finding.get(key)
        if val:
            tool_candidates.append(str(val).lower())

    tool_blob = " ".join(tool_candidates)

    explicit_dast = any(t in tool_blob for t in _DAST_TOOLS)
    explicit_sca  = any(t in tool_blob for t in _SCA_TOOLS)
    explicit_sast = any(t in tool_blob for t in _SAST_TOOLS)

    scanner_type = "SCA"

    # Explicit tool names beat generic DefectDojo flags.
    # DAST first because ZAP/Burp should never be treated as SCA/SAST.
    # SCA before SAST because Trivy/npm-audit findings can be static_finding=True.
    if explicit_dast:
        scanner_type = "DAST"
    elif explicit_sca:
        scanner_type = "SCA"
    elif explicit_sast:
        scanner_type = "SAST"
    elif dynamic_flag:
        scanner_type = "DAST"
    elif static_flag:
        scanner_type = "SAST"

    log.debug(
        f"Finding {finding.get('id')} scanner detection: "
        f"static={static_flag}, dynamic={dynamic_flag}, "
        f"explicit_sca={explicit_sca}, explicit_sast={explicit_sast}, explicit_dast={explicit_dast}, "
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
        scanner_severity   = severity,
        defectdojo_severity= severity,
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
        # Leakage-safe pipeline metadata features
        package_name       = dd_component_name,
        published          = finding.get("date") or finding.get("created"),
        modified           = finding.get("updated") or finding.get("last_reviewed"),
        ranges_count       = 0,
        versions_count     = 1 if dd_component_version else 0,
        summary_len        = len(dd_title or ""),
        details_len        = len(str(finding.get("description") or "")),
        references_count   = _count_references(finding.get("references")),
        has_patch_ref      = bool(re.search(r"patch|fixed|fix|commit|pull request|pr/", str(finding.get("references") or finding.get("description") or ""), re.I)),
        has_advisory_ref   = bool(re.search(r"advisory|nvd|osv|ghsa|github.com/advisories", str(finding.get("references") or finding.get("description") or ""), re.I)),
        cwe_id             = raw_cwe,
        all_cwe_ids        = f"CWE-{normalise_cwe(raw_cwe)}" if normalise_cwe(raw_cwe) else None,
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
        "XGBoost v3.2-compatible binary EPSS-based risk prioritization API. "
        "Preserves scanner/DefectDojo severity and adds an AI risk score."
    ),
    version="3.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=DASHBOARD_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/register/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/register/", tags=["Auth"], summary="Register a pending dashboard user")
def register_user(request: RegisterRequest):
    """
    Public registration endpoint.

    New users are created as:
      access_status = pending
      is_active = 0

    They cannot access the dashboard until an admin approves them.
    """
    user = create_dashboard_user(
        username=request.username,
        password=request.password,
        display_name=request.username,
        is_admin=False,
        access_status="pending",
    )

    create_app_notification(
        kind="user_pending",
        title="New user pending approval",
        message=f"User '{user['username']}' registered and is waiting for admin approval.",
        severity="Medium",
        username=user["username"],
        metadata={
            "user_id": user["id"],
            "access_status": "pending",
        },
    )

    return {
        "registered": True,
        "message": "Account created. Contact an admin to give you access.",
        "user": user,
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/login/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/login/", tags=["Auth"], summary="Dashboard login")
def login(request: LoginRequest):
    """
    Validate dashboard credentials.

    Approved users receive a session token.
    Pending users receive ACCESS_PENDING.
    Disabled users receive ACCESS_DISABLED.
    """
    user = authenticate_dashboard_user(request.username, request.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if user.get("auth_blocked"):
        raise HTTPException(
            status_code=403,
            detail={
                "code": user.get("code"),
                "message": user.get("message"),
                "username": user.get("username"),
                "access_status": user.get("access_status"),
            },
        )

    access_token = create_dashboard_session(
        username=user["username"],
        is_admin=bool(user.get("is_admin")),
    )

    return {
        "access_token": access_token,
        "token_type": "api_key",
        "header": AUTH_HEADER_NAME,
        "user": user,
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/users/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/users/", tags=["Auth"], summary="Admin creates a dashboard user")
def create_user(
    request: UserCreateRequest,
    current_user: Dict[str, Any] = Depends(require_admin_user),
):
    user = create_dashboard_user(
        username=request.username,
        password=request.password,
        display_name=request.display_name,
        is_admin=request.is_admin,
        access_status=request.access_status,
    )
    return {"created": True, "user": user}


@app.get("/api/users/", tags=["Auth"], summary="Admin lists dashboard users")
def list_users(current_user: Dict[str, Any] = Depends(require_admin_user)):
    """List dashboard users without exposing password hashes."""
    with get_db() as con:
        rows = con.execute(
            """
            SELECT id, username, display_name, is_admin, is_active,
                   access_status, created_at, last_login_at
            FROM dashboard_users
            ORDER BY id ASC
            """
        ).fetchall()

    return [safe_user(dict(r)) for r in rows]


@app.patch("/api/users/{user_id}/access/", tags=["Auth"], summary="Admin updates user access")
def update_user_access(
    user_id: int,
    request: UserAccessUpdateRequest,
    current_user: Dict[str, Any] = Depends(require_admin_user),
):
    updates = []
    params: List[Any] = []

    if request.access_status is not None:
        is_active = 1 if request.access_status == "approved" else 0
        updates.append("access_status = ?")
        params.append(request.access_status)
        updates.append("is_active = ?")
        params.append(is_active)

    if request.is_admin is not None:
        updates.append("is_admin = ?")
        params.append(int(request.is_admin))

    if not updates:
        raise HTTPException(status_code=400, detail="No user changes requested.")

    params.append(user_id)

    with get_db() as con:
        cur = con.execute(
            f"UPDATE dashboard_users SET {', '.join(updates)} WHERE id = ?",
            params,
        )

        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found.")

        row = con.execute(
            """
            SELECT id, username, display_name, is_admin, is_active,
                   access_status, created_at, last_login_at
            FROM dashboard_users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    return {"updated": True, "user": safe_user(dict(row))}


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/health/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/health/", tags=["Meta"], summary="Liveness check + model info")
def health():
    """
    Returns loaded binary model version, feature list, optimal threshold,
    auth status and DB location.
    """
    return {
        "status":          "ok",
        # Legacy keys kept for existing dashboard checks. They refer to the
        # operational ranker because it owns risk_score/is_high_risk aliases.
        "binary_model":    RANKER_MODEL_VERSION,
        "threshold":       RANKER_OPTIMAL_THRESHOLD,
        "binary_features": RANKER_FEATURES,
        "models": {
            "clean": {
                "model": CLEAN_MODEL_VERSION,
                "threshold": CLEAN_OPTIMAL_THRESHOLD,
                "features": CLEAN_FEATURES,
                "purpose": "strict leakage-safe confidence signal",
            },
            "operational_ranker": {
                "model": RANKER_MODEL_VERSION,
                "threshold": RANKER_OPTIMAL_THRESHOLD,
                "features": RANKER_FEATURES,
                "purpose": "primary dashboard sorting / EPSS exploitation-likelihood ranking",
            },
        },
        "multiclass_model_removed": True,
        "severity_source": "DefectDojo/scanner severity is preserved; no AI severity model is used.",
        "db":              str(DB_PATH),
        "auth": {
            "dashboard_login": True,
            "supports_user_creation": True,
            "protected_endpoints_require_api_key": True,
            "header": AUTH_HEADER_NAME,
            "configured": bool(API_AUTH_TOKEN and (DASHBOARD_PASSWORD or True)),
            "bootstrap_admin_configured": bool(DASHBOARD_PASSWORD),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/risk-score/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/risk-score/", tags=["Scoring"], dependencies=PROTECTED_ENDPOINT,
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
    row_clean, row_ranker, cwe_int, year = resolve_features(payload)
    result = run_dual_models(row_clean, row_ranker)
    return {
        "cve_id":        payload.cve_id,
        "year":          year,
        "cwe":           cwe_int,
        "scanner_type":  payload.scanner_type,
        **result,
        "model_versions": {
            "clean": CLEAN_MODEL_VERSION,
            "operational_ranker": RANKER_MODEL_VERSION,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/score-finding/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/score-finding/", tags=["Scoring"], dependencies=PROTECTED_ENDPOINT,
          summary="Binary AI risk model + persist to SQLite")
def score_finding(payload: VulnFeatures):
    """
    Runs the final binary EPSS-trained risk model and stores the result.

    The endpoint preserves the original scanner/DefectDojo severity. It does not
    predict severity with a multiclass model anymore.
    """
    row_clean, row_ranker, cwe_int, year = resolve_features(payload)
    binary_res = run_dual_models(row_clean, row_ranker)

    record_id = persist_score(payload, binary_res, source="api")
    sev = (payload.scanner_severity or payload.defectdojo_severity or "Medium").title()

    return {
        "id":            record_id,
        "cve_id":        payload.cve_id,
        "scanner_type":  payload.scanner_type,
        "scanner_severity": sev,
        "defectdojo_severity": sev,
        "severity":      sev,
        "cvss_score":    payload.cvss_score,
        "year":          year,
        "cwe":           cwe_int,
        "exploit_probability": binary_res["exploit_probability"],
        "risk_score":          binary_res["risk_score"],
        "risk_category":       binary_res["risk_category"],
        "is_high_risk":        binary_res["is_high_risk"],
        "threshold_used":      binary_res["threshold_used"],
        "clean_ai_score":     binary_res["clean_ai_score"],
        "clean_ai_category":  binary_res["clean_ai_category"],
        "clean_is_high_risk": binary_res["clean_is_high_risk"],
        "clean_exploit_probability": binary_res["clean_exploit_probability"],
        "operational_rank_score": binary_res["operational_rank_score"],
        "operational_rank_category": binary_res["operational_rank_category"],
        "operational_is_high_risk": binary_res["operational_is_high_risk"],
        "operational_exploit_probability": binary_res["operational_exploit_probability"],
        "operational_rank_percentile": binary_res["operational_rank_percentile"],
        "stored":             True,
        "model_versions": {
            "clean": CLEAN_MODEL_VERSION,
            "operational_ranker": RANKER_MODEL_VERSION,
        },
        "note": "Operational ranker is the primary sorting score; clean AI score is a secondary leakage-safe confidence signal.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/sync-defectdojo/
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/sync-defectdojo/", tags=["DefectDojo"], dependencies=PROTECTED_ENDPOINT,
          summary="Pull findings from DefectDojo, preserve scanner severity, score with AI risk model")
def sync_defectdojo(request: SyncDefectDojoRequest):
    """
    Full sync pipeline (replace semantics — NOT append):
      1. Validates DefectDojo credentials from environment variables.
      2. Resolves the target product by product_id or product_name.
      3. Fetches active findings from /api/v2/findings/.
      4. Preserves each finding's original DefectDojo/scanner severity.
      5. Runs the binary AI risk model only.
      6. Replaces the local cache for this product_id atomically.

    The final AI workflow does NOT predict severity. Severity comes from
    DefectDojo/scanner data. AI only adds risk_score, risk_category and
    is_high_risk.
    """
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        raise HTTPException(
            status_code=503,
            detail=(
                "DEFECTDOJO_URL and DEFECTDOJO_API_KEY must be set in .env. "
                "See .env.example."
            ),
        )

    product_id   = request.product_id
    product_name = request.product_name

    if product_id:
        pass
    elif product_name:
        product_id, product_name = resolve_dd_product_id(product_name)
        log.info(f"Resolved product name '{request.product_name}' → product_id={product_id}")
    else:
        if DEFECTDOJO_PRODUCT_ID:
            try:
                product_id = int(DEFECTDOJO_PRODUCT_ID)
            except ValueError:
                raise HTTPException(status_code=400, detail="DEFECTDOJO_PRODUCT_ID in .env is not a valid integer.")
        else:
            raise HTTPException(
                status_code=400,
                detail="Provide product_id or product_name, or set DEFECTDOJO_PRODUCT_ID in .env.",
            )

    resolved_product_name: Optional[str] = product_name

    log.info(f"DefectDojo sync: product_id={product_id}, active_only={request.active_only}, limit={request.limit}")
    try:
        findings = fetch_dd_findings(product_id=product_id, active_only=request.active_only, limit=request.limit)
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"DefectDojo API returned HTTP {exc.response.status_code}: {exc.response.text[:300]}",
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach DefectDojo at '{DEFECTDOJO_URL}': {exc}")

    total_fetched = len(findings)
    log.info(f"Fetched {total_fetched} findings from DefectDojo product {product_id}")

    scored_items: List[Dict[str, Any]] = []
    skipped = 0
    high_risk_count = 0
    clean_high_risk_count = 0
    severity_breakdown: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    errors: List[Dict] = []

    for finding in findings:
        finding_id = finding.get("id")
        try:
            vuln, dd_product_name = normalise_dd_finding(finding)
            row_product_name = dd_product_name or resolved_product_name
            row_clean, row_ranker, _, _ = resolve_features(vuln)
            dual_res = run_dual_models(row_clean, row_ranker)

            sev = (vuln.scanner_severity or vuln.defectdojo_severity or finding.get("severity") or "Medium").strip().title()
            if sev not in severity_breakdown:
                sev = "Medium" if sev in {"Info", "Informational", "Unknown", ""} else sev
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1

            scored_items.append({
                "payload": vuln,
                "dual_res": dual_res,
                "sev": sev,
                "source": "defectdojo",
                "defectdojo_finding_id": finding_id,
                "product_name": row_product_name,
                "product_id": product_id,
            })

            if dual_res["operational_is_high_risk"]:
                high_risk_count += 1
            if dual_res["clean_is_high_risk"]:
                clean_high_risk_count += 1

        except Exception as exc:
            skipped += 1
            errors.append({"finding_id": finding_id, "error": str(exc)})
            log.warning(f"Failed to score DefectDojo finding {finding_id}: {exc}")

    # Compute per-product operational rank percentiles for this sync batch.
    # Higher percentile = higher priority within the synced product queue.
    if scored_items:
        scores = np.array([float(item["dual_res"].get("operational_rank_score") or 0.0) for item in scored_items], dtype=float)
        if len(scores) == 1:
            percentiles = np.array([100.0])
        else:
            order = np.argsort(scores)  # ascending
            ranks = np.empty_like(order, dtype=float)
            ranks[order] = np.arange(1, len(scores) + 1, dtype=float)
            percentiles = (ranks - 1) / max(len(scores) - 1, 1) * 100.0
        for item, percentile in zip(scored_items, percentiles):
            item["dual_res"]["operational_rank_percentile"] = round(float(percentile), 2)

    scored_rows = [
        _score_record_tuple(
            payload=item["payload"],
            dual_res=item["dual_res"],
            sev=item["sev"],
            source=item["source"],
            defectdojo_finding_id=item["defectdojo_finding_id"],
            product_name=item["product_name"],
            product_id=item["product_id"],
        )
        for item in scored_items
    ]

    scored = len(scored_rows)
    stored = 0

    if scored_rows:
        with get_db() as con:
            con.execute(
                "DELETE FROM ai_scores WHERE source = 'defectdojo' AND product_id = ?",
                (product_id,),
            )
            con.executemany(_AI_SCORE_INSERT_SQL, scored_rows)
            stored = scored
        log.info(
            f"Sync complete: replaced defectdojo cache for product_id={product_id} "
            f"with {stored} findings ({skipped} failed, {high_risk_count} operational high-risk, {clean_high_risk_count} clean high-risk)."
        )
    else:
        log.warning(
            f"Sync: 0 of {total_fetched} findings scored successfully ({skipped} failed). "
            f"Old cache for product_id={product_id} was NOT modified."
        )

    response = {
        "product_id":         product_id,
        "product_name":       resolved_product_name,
        "total_fetched":      total_fetched,
        "scored":             scored,
        "stored":             stored,
        "skipped_on_error":   skipped,
        "high_risk_flagged":  high_risk_count,  # legacy alias: operational ranker threshold
        "operational_high_risk_flagged": high_risk_count,
        "clean_high_risk_flagged": clean_high_risk_count,
        "severity_breakdown": severity_breakdown,
        "errors":             errors if errors else None,
        "models_used": {
            "clean": CLEAN_MODEL_VERSION,
            "operational_ranker": RANKER_MODEL_VERSION,
        },
        "model_used":         "dual_model_operational_ranker_primary",
        "severity_source":    "DefectDojo/scanner severity preserved",
        "note": (
            f"DefectDojo cache replaced atomically for product_id={product_id} only. "
            "Severity is preserved from DefectDojo/scanner data. "
            "risk_score/is_high_risk are operational ranker aliases; clean_ai_* fields expose the strict leakage-safe model."
        ),
    }

    create_app_notification(
        kind="sync_complete",
        title="DefectDojo sync complete",
        message=(
            f"Synced {stored}/{total_fetched} findings"
            f"{' for ' + str(resolved_product_name) if resolved_product_name else ''}. "
            f"{high_risk_count} strict operational alert(s), {skipped} skipped."
        ),
        severity="High" if high_risk_count > 0 else "Low",
        product_name=resolved_product_name,
        product_id=product_id,
        metadata=response,
    )

    return response


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/scores/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/scores/", tags=["Meta"], dependencies=PROTECTED_ENDPOINT,
         summary="Browse stored AI risk scores from SQLite")
def get_scores(
    source:       Optional[str]  = Query(None, description="Filter by source: 'api' or 'defectdojo'"),
    is_high_risk: Optional[bool] = Query(None, description="Filter by high-risk flag"),
    severity:     Optional[str]  = Query(None, description="Filter by scanner/DefectDojo severity: Critical/High/Medium/Low"),
    product_id:   Optional[int]  = Query(None, description="Filter by DefectDojo product_id (defectdojo rows only)"),
    limit:        int             = Query(50, ge=1, le=2000),
):
    """Browse the most recent AI risk score records stored in SQLite."""
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
        where.append("COALESCE(scanner_severity, defectdojo_severity, predicted_severity) = ?")
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

    results = []
    for r in rows:
        d = dict(r)
        sev = d.get("scanner_severity") or d.get("defectdojo_severity") or d.get("predicted_severity") or "Medium"
        d["scanner_severity"] = sev
        d["defectdojo_severity"] = d.get("defectdojo_severity") or sev
        d["severity"] = sev
        # Keep predicted_severity only as a legacy alias so older frontend code cannot crash.
        d["predicted_severity"] = sev

        # Backfill two-model fields for rows created before this migration.
        # This keeps the frontend stable while old cache rows still exist.
        d["operational_rank_score"] = d.get("operational_rank_score") if d.get("operational_rank_score") is not None else d.get("risk_score")
        d["operational_rank_category"] = d.get("operational_rank_category") or d.get("risk_category")
        d["operational_is_high_risk"] = bool(d.get("operational_is_high_risk") if d.get("operational_is_high_risk") is not None else d.get("is_high_risk"))
        d["operational_exploit_probability"] = d.get("operational_exploit_probability") if d.get("operational_exploit_probability") is not None else d.get("exploit_probability")
        d["clean_is_high_risk"] = bool(d.get("clean_is_high_risk")) if d.get("clean_is_high_risk") is not None else False
        results.append(d)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/products/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/products/", tags=["DefectDojo"], dependencies=PROTECTED_ENDPOINT,
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

@app.get("/api/notifications/", tags=["Meta"], dependencies=PROTECTED_ENDPOINT,
         summary="Dashboard notifications")
def get_notifications(limit: int = Query(10, ge=1, le=50)):
    """
    Returns dashboard notifications from three sources:
      1. app_notifications table: pending users + sync completed
      2. pending users live fallback
      3. Review First findings: operational alert OR Rank /100 >= 70
    """
    results: List[Dict[str, Any]] = []

    with get_db() as con:
        # 1) Explicit app/system notifications
        app_rows = con.execute(
            """
            SELECT id, created_at, kind, title, message, severity,
                   product_name, product_id, username, is_read
            FROM app_notifications
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        for r in app_rows:
            d = dict(r)
            results.append({
                "id": f"app-{d['id']}",
                "kind": d["kind"],
                "type": d["kind"],
                "title": d["title"],
                "message": d["message"],
                "severity": d["severity"] or "Info",
                "risk_score": 0,
                "operational_rank_score": 0,
                "clean_ai_score": None,
                "product": d.get("product_name") or "System",
                "product_name": d.get("product_name") or "System",
                "username": d.get("username"),
                "created_at": d["created_at"],
                "time": _human_notification_time(d["created_at"]),
                "is_read": bool(d.get("is_read")),
            })

        # 2) Pending users as live notifications, so they show even if notification insertion failed.
        pending_rows = con.execute(
            """
            SELECT id, username, display_name, created_at
            FROM dashboard_users
            WHERE access_status = 'pending'
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        for r in pending_rows:
            d = dict(r)
            results.append({
                "id": f"pending-user-{d['id']}",
                "kind": "user_pending_live",
                "type": "user_pending",
                "title": "User waiting for approval",
                "message": f"User '{d['username']}' is waiting for admin approval.",
                "severity": "Medium",
                "risk_score": 0,
                "operational_rank_score": 0,
                "clean_ai_score": None,
                "product": "Users",
                "product_name": "Users",
                "username": d["username"],
                "created_at": d["created_at"],
                "time": _human_notification_time(d["created_at"]),
                "is_read": False,
            })

        # 3) Review First findings from the scoring cache.
        finding_rows = con.execute(
            """
            SELECT id, cve_id,
                   COALESCE(scanner_severity, defectdojo_severity, predicted_severity, 'High') AS severity,
                   COALESCE(operational_rank_score, risk_score, 0) AS operational_rank_score,
                   COALESCE(clean_ai_score, 0) AS clean_ai_score,
                   COALESCE(operational_rank_category, risk_category, 'High') AS risk_category,
                   scanner_type, source, defectdojo_finding_id, product_name, created_at
            FROM ai_scores
            WHERE COALESCE(operational_is_high_risk, is_high_risk, 0) = 1
               OR COALESCE(operational_rank_score, risk_score, 0) >= 70
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        for r in finding_rows:
            d = dict(r)

            cve = d.get("cve_id") or (
                f"Finding-{d.get('defectdojo_finding_id')}"
                if d.get("defectdojo_finding_id")
                else "Finding"
            )

            sev = d.get("severity") or "High"
            score = round(float(d.get("operational_rank_score") or 0), 1)
            clean_score = round(float(d.get("clean_ai_score") or 0), 1)
            scanner = d.get("scanner_type") or "scanner"
            product = d.get("product_name") or "Unknown"

            results.append({
                "id": f"finding-{d['id']}",
                "kind": "review_first_finding",
                "type": "finding",
                "title": "Review First finding",
                "cve": cve,
                "message": (
                    f"{cve} from {scanner} should be reviewed first — "
                    f"Rank {score}/100, Clean {clean_score}/100, scanner severity {sev}."
                ),
                "severity": sev,
                "risk_score": score,
                "operational_rank_score": score,
                "clean_ai_score": clean_score,
                "product": product,
                "product_name": product,
                "created_at": d["created_at"],
                "time": _human_notification_time(d["created_at"]),
                "is_read": False,
            })

    results.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    return results[:limit]


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/trends/
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/trends/", tags=["Meta"], dependencies=PROTECTED_ENDPOINT,
         summary="Weekly scanner-severity counts for trend charts")
def get_trends(weeks: int = Query(8, ge=1, le=52)):
    """Aggregates ai_scores by ISO week and scanner/DefectDojo severity."""
    with get_db() as con:
        rows = con.execute(
            """
            SELECT
                strftime('%Y-W%W', created_at) AS week,
                SUM(COALESCE(scanner_severity, defectdojo_severity, predicted_severity) = 'Critical') AS critical,
                SUM(COALESCE(scanner_severity, defectdojo_severity, predicted_severity) = 'High')     AS high,
                SUM(COALESCE(scanner_severity, defectdojo_severity, predicted_severity) = 'Medium')   AS medium,
                SUM(COALESCE(scanner_severity, defectdojo_severity, predicted_severity) = 'Low')      AS low_count,
                COUNT(*) AS total,
                SUM(is_high_risk) AS high_risk,
                ROUND(AVG(risk_score), 1) AS avg_risk_score
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
