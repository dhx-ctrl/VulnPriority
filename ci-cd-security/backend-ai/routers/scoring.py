"""Direct vulnerability scoring routes."""
from __future__ import annotations

from fastapi import APIRouter

from core.security import PROTECTED_ENDPOINT
from database.crud import persist_score
from schemas import VulnFeatures
from services.scoring import (
    CLEAN_MODEL_VERSION,
    RANKER_MODEL_VERSION,
    resolve_features,
    run_dual_models,
)

router = APIRouter()

@router.post("/api/risk-score/", tags=["Scoring"], dependencies=PROTECTED_ENDPOINT,
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


@router.post("/api/score-finding/", tags=["Scoring"], dependencies=PROTECTED_ENDPOINT,
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
