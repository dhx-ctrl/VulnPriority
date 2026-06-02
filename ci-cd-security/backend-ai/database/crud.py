"""SQLite schema, CRUD helpers, dashboard users, notifications, and score persistence."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import os
import hashlib
import secrets

from fastapi import HTTPException

from core.config import DASHBOARD_PASSWORD, DASHBOARD_USERNAME, DB_PATH, log



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

_PASSWORD_ALGORITHM = "pbkdf2_sha256"
_PASSWORD_ITERATIONS = 260000
_PASSWORD_SALT_BYTES = 16

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

    -- Legacy compatibility fields for the previous two-model frontend.
    -- In the single-model backend, these are aliases for the same risk score.
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

def _score_record_tuple(
    *,
    payload: VulnFeatures,
    dual_res: Dict[str, Any],  # single model result; name kept for compatibility
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
    Insert one AI model output and preserve original scanner severity.

    Legacy clean_* and operational_* columns are filled as aliases so the existing frontend remains stable during migration.
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

