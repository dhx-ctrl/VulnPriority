"""FastAPI application entrypoint for VulnPriority."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import DASHBOARD_ORIGINS, log
from database.crud import init_db
from routers.auth import router as auth_router
from routers.defectdojo_sync import router as defectdojo_router
from routers.meta import router as meta_router
from routers.scoring import router as scoring_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB on startup; nothing to tear down on shutdown."""
    init_db()
    log.info("DevSecOps AI API is ready.")
    yield


app = FastAPI(
    title="DevSecOps AI Risk Scoring API",
    description=(
        "Single v4 XGBoost stacked risk-prioritization API. "
        "Preserves scanner/DefectDojo severity and adds an AI risk score."
    ),
    version="4.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=DASHBOARD_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

app.include_router(auth_router)
app.include_router(scoring_router)
app.include_router(defectdojo_router)
app.include_router(meta_router)
