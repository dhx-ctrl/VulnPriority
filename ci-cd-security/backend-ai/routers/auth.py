"""Authentication, registration, and dashboard user management routes."""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from core.config import AUTH_HEADER_NAME
from core.security import require_admin_user
from database.crud import (
    authenticate_dashboard_user,
    create_app_notification,
    create_dashboard_session,
    create_dashboard_user,
    get_db,
    safe_user,
)
from schemas import LoginRequest, RegisterRequest, UserAccessUpdateRequest, UserCreateRequest

router = APIRouter()

@router.post("/api/register/", tags=["Auth"], summary="Register a pending dashboard user")
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


@router.post("/api/login/", tags=["Auth"], summary="Dashboard login")
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


@router.post("/api/users/", tags=["Auth"], summary="Admin creates a dashboard user")
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


@router.get("/api/users/", tags=["Auth"], summary="Admin lists dashboard users")
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


@router.patch("/api/users/{user_id}/access/", tags=["Auth"], summary="Admin updates user access")
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
