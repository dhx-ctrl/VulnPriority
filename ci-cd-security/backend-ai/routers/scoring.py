"""Direct vulnerability scoring routes."""
from __future__ import annotations

from fastapi import APIRouter

from core.security import PROTECTED_ENDPOINT
from database.crud import persist_score
from schemas import VulnFeatures
from services.scoring import MODEL_VERSION, resolve_features, run_model

router = APIRouter()


@router.post(
    "/api/risk-score/",
    tags=["Scoring"],
    dependencies=PROTECTED_ENDPOINT,
    summary="Single AI exploit-likelihood / prioritization score",
)
def risk_score(payload: VulnFeatures):
    """
    Runs the single v4 model.

    Returns one canonical score:
      - exploit_probability (0–1)
      - risk_score (0–100)
      - risk_category (Low / Medium / High)
      - is_high_risk (bool, based on chosen threshold from model_meta.json)

    Does not write to the database.
    """
    row, cwe_int, year = resolve_features(payload)
    result = run_model(row)

    return {
        "cve_id": payload.cve_id,
        "year": year,
        "cwe": cwe_int,
        "scanner_type": payload.scanner_type,
        **result,
        "model_used": MODEL_VERSION,
        "model_versions": {"single": MODEL_VERSION},
    }


@router.post(
    "/api/score-finding/",
    tags=["Scoring"],
    dependencies=PROTECTED_ENDPOINT,
    summary="Single AI risk model + persist to SQLite",
)
def score_finding(payload: VulnFeatures):
    """
    Runs the single v4 model and stores the result.

    Scanner/DefectDojo severity is preserved; the AI model only adds
    prioritization/risk scoring.
    """
    row, cwe_int, year = resolve_features(payload)
    result = run_model(row)

    record_id = persist_score(payload, result, source="api")
    sev = (payload.scanner_severity or payload.defectdojo_severity or "Medium").title()

    return {
        "id": record_id,
        "cve_id": payload.cve_id,
        "scanner_type": payload.scanner_type,
        "scanner_severity": sev,
        "defectdojo_severity": sev,
        "severity": sev,
        "cvss_score": payload.cvss_score,
        "year": year,
        "cwe": cwe_int,
        **result,
        "stored": True,
        "model_used": MODEL_VERSION,
        "model_versions": {"single": MODEL_VERSION},
        "note": "Single v4 model is the only AI scoring model. Legacy clean_* and operational_* fields are compatibility aliases.",
    }
