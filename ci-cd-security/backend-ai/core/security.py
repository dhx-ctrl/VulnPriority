"""API-key and session-token authentication dependencies."""
from __future__ import annotations

import secrets
from typing import Any, Dict, Optional

from fastapi import Depends, Header, HTTPException

from core.config import API_AUTH_TOKEN, AUTH_HEADER_NAME, DASHBOARD_USERNAME
from database.crud import get_session_user

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
