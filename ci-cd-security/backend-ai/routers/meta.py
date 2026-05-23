"""Health, score browsing, notifications, and trend routes."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query

from core.config import API_AUTH_TOKEN, AUTH_HEADER_NAME, DASHBOARD_PASSWORD, DB_PATH
from core.security import PROTECTED_ENDPOINT
from database.crud import _human_notification_time, get_db
from services.scoring import FEATURES, MODEL_META, MODEL_VERSION, OPTIMAL_THRESHOLD

router = APIRouter()

@router.get("/api/health/", tags=["Meta"], summary="Liveness check + single model info")
def health():
    """
    Returns loaded single-model version, feature list, threshold, auth status
    and DB location.
    """
    metrics = MODEL_META.get("new_model_test_metrics") or MODEL_META.get("recommended_operating_points", {}).get("balanced_default", {}).get("test", {})

    return {
        "status": "ok",
        "binary_model": MODEL_VERSION,
        "threshold": OPTIMAL_THRESHOLD,
        "binary_features": FEATURES,
        "model": {
            "name": MODEL_VERSION,
            "threshold": OPTIMAL_THRESHOLD,
            "features": FEATURES,
            "feature_count": len(FEATURES),
            "test_metrics": metrics,
            "purpose": "single exploit-likelihood / vulnerability prioritization model",
        },
        "models": {
            "single": {
                "model": MODEL_VERSION,
                "threshold": OPTIMAL_THRESHOLD,
                "features": FEATURES,
                "feature_count": len(FEATURES),
                "purpose": "only AI scoring model used by backend",
            }
        },
        "dual_model_removed": True,
        "multiclass_model_removed": True,
        "severity_source": "DefectDojo/scanner severity is preserved; AI only predicts priority/risk.",
        "db": str(DB_PATH),
        "auth": {
            "dashboard_login": True,
            "supports_user_creation": True,
            "protected_endpoints_require_api_key": True,
            "header": AUTH_HEADER_NAME,
            "configured": bool(API_AUTH_TOKEN and (DASHBOARD_PASSWORD or True)),
            "bootstrap_admin_configured": bool(DASHBOARD_PASSWORD),
        },
    }


@router.get("/api/scores/", tags=["Meta"], dependencies=PROTECTED_ENDPOINT,
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
        d["clean_ai_score"] = d.get("clean_ai_score") if d.get("clean_ai_score") is not None else d.get("risk_score")
        d["clean_ai_category"] = d.get("clean_ai_category") or d.get("risk_category")
        d["clean_is_high_risk"] = bool(d.get("clean_is_high_risk") if d.get("clean_is_high_risk") is not None else d.get("is_high_risk"))
        d["clean_exploit_probability"] = d.get("clean_exploit_probability") if d.get("clean_exploit_probability") is not None else d.get("exploit_probability")
        results.append(d)

    return results


@router.get("/api/notifications/", tags=["Meta"], dependencies=PROTECTED_ENDPOINT,
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


@router.get("/api/trends/", tags=["Meta"], dependencies=PROTECTED_ENDPOINT,
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
