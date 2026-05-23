"""Application configuration loaded from environment variables."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(override=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("devsecops_ai")

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "ai_scores.db")))

DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "").rstrip("/")
DEFECTDOJO_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
DEFECTDOJO_PRODUCT_ID = os.getenv("DEFECTDOJO_PRODUCT_ID", "")

API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN", "").strip()
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()
AUTH_HEADER_NAME = "X-API-Key"

DASHBOARD_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "DASHBOARD_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:5173,http://localhost:5173",
    ).split(",")
    if origin.strip()
]
