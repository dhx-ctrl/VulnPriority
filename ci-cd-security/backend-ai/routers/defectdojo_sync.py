"""DefectDojo product listing and synchronization routes."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np
import requests
from fastapi import APIRouter, HTTPException

from core.config import DEFECTDOJO_API_KEY, DEFECTDOJO_PRODUCT_ID, DEFECTDOJO_URL, log
from core.security import PROTECTED_ENDPOINT
from database.crud import _AI_SCORE_INSERT_SQL, _score_record_tuple, create_app_notification, get_db
from schemas import SyncDefectDojoRequest
from services.defectdojo import (
    fetch_dd_findings,
    fetch_dd_products,
    normalise_dd_finding,
    resolve_dd_product_id,
)
from services.scoring import MODEL_VERSION, resolve_features, run_model

router = APIRouter()


@router.post(
    "/api/sync-defectdojo/",
    tags=["DefectDojo"],
    dependencies=PROTECTED_ENDPOINT,
    summary="Pull findings from DefectDojo and score with the single AI risk model",
)
def sync_defectdojo(request: SyncDefectDojoRequest):
    """
    Full sync pipeline:
      1. Validate DefectDojo credentials.
      2. Resolve the target product by product_id/product_name/env fallback.
      3. Fetch active findings from DefectDojo.
      4. Preserve original scanner/DefectDojo severity.
      5. Run the single v4 AI model.
      6. Replace local cache for this product_id atomically.
    """
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="DEFECTDOJO_URL and DEFECTDOJO_API_KEY must be set in .env.",
        )

    product_id = request.product_id
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
    severity_breakdown: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    errors: List[Dict[str, Any]] = []

    for finding in findings:
        finding_id = finding.get("id")
        try:
            vuln, dd_product_name = normalise_dd_finding(finding)
            row_product_name = dd_product_name or resolved_product_name

            row, _, _ = resolve_features(vuln)
            result = run_model(row)

            sev = (vuln.scanner_severity or vuln.defectdojo_severity or finding.get("severity") or "Medium").strip().title()
            if sev not in severity_breakdown:
                sev = "Medium" if sev in {"Info", "Informational", "Unknown", ""} else sev
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1

            scored_items.append({
                "payload": vuln,
                "result": result,
                "sev": sev,
                "source": "defectdojo",
                "defectdojo_finding_id": finding_id,
                "product_name": row_product_name,
                "product_id": product_id,
            })

            if result["is_high_risk"]:
                high_risk_count += 1

        except Exception as exc:
            skipped += 1
            errors.append({"finding_id": finding_id, "error": str(exc)})
            log.warning(f"Failed to score DefectDojo finding {finding_id}: {exc}")

    # Per-product percentile for dashboard ordering compatibility.
    if scored_items:
        scores = np.array([float(item["result"].get("risk_score") or 0.0) for item in scored_items], dtype=float)
        if len(scores) == 1:
            percentiles = np.array([100.0])
        else:
            order = np.argsort(scores)  # ascending
            ranks = np.empty_like(order, dtype=float)
            ranks[order] = np.arange(1, len(scores) + 1, dtype=float)
            percentiles = (ranks - 1) / max(len(scores) - 1, 1) * 100.0

        for item, percentile in zip(scored_items, percentiles):
            item["result"]["operational_rank_percentile"] = round(float(percentile), 2)
            item["result"]["rank_percentile"] = round(float(percentile), 2)

    scored_rows = [
        _score_record_tuple(
            payload=item["payload"],
            dual_res=item["result"],  # parameter name kept for DB compatibility
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
            f"with {stored} findings ({skipped} failed, {high_risk_count} high-risk)."
        )
    else:
        log.warning(
            f"Sync: 0 of {total_fetched} findings scored successfully ({skipped} failed). "
            f"Old cache for product_id={product_id} was NOT modified."
        )

    response = {
        "product_id": product_id,
        "product_name": resolved_product_name,
        "total_fetched": total_fetched,
        "scored": scored,
        "stored": stored,
        "skipped_on_error": skipped,
        "high_risk_flagged": high_risk_count,
        # Temporary compatibility aliases for older frontend wording.
        "operational_high_risk_flagged": high_risk_count,
        "clean_high_risk_flagged": high_risk_count,
        "severity_breakdown": severity_breakdown,
        "errors": errors if errors else None,
        "models_used": {"single": MODEL_VERSION},
        "model_used": MODEL_VERSION,
        "severity_source": "DefectDojo/scanner severity preserved",
        "note": (
            f"DefectDojo cache replaced atomically for product_id={product_id}. "
            "The backend now uses one single AI model; clean_* and operational_* DB fields are compatibility aliases."
        ),
    }

    create_app_notification(
        kind="sync_complete" if skipped == 0 else "sync_partial",
        title="DefectDojo sync completed" if skipped == 0 else "DefectDojo sync partially completed",
        message=(
            f"Product {resolved_product_name or product_id}: fetched {total_fetched}, "
            f"stored {stored}, skipped {skipped}, high-risk {high_risk_count}."
        ),
        severity="Info" if skipped == 0 else "Medium",
        product_name=resolved_product_name,
        product_id=product_id,
        metadata=response,
    )

    return response


@router.get("/api/products/", tags=["DefectDojo"], dependencies=PROTECTED_ENDPOINT,
          summary="List DefectDojo products available for sync")
def list_defectdojo_products():
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="DEFECTDOJO_URL and DEFECTDOJO_API_KEY must be set in .env.",
        )

    try:
        return fetch_dd_products()
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"DefectDojo API returned HTTP {exc.response.status_code}: {exc.response.text[:300]}",
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach DefectDojo at '{DEFECTDOJO_URL}': {exc}")
