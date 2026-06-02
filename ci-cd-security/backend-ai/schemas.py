"""Pydantic request models for the VulnPriority backend."""
from __future__ import annotations

import re
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def password_is_valid(password: str) -> bool:
    if len(password) < 6:
        return False
    if not re.search(r"[A-Za-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


class VulnFeatures(BaseModel):
    """Normalized vulnerability payload accepted by scoring and sync routes."""

    model_config = ConfigDict(extra="allow")

    cve_id: Optional[str] = Field(None)
    cvss_score: float = Field(5.0, ge=0.0, le=10.0)
    year: Optional[int] = Field(None, ge=1990, le=2100)

    attack_vector: str = Field("NETWORK")
    attack_complexity: str = Field("LOW")
    privileges_required: str = Field("NONE")
    user_interaction: str = Field("NONE")
    scope: str = Field("UNCHANGED")
    confidentiality_impact: str = Field("HIGH")
    integrity_impact: str = Field("HIGH")
    availability_impact: str = Field("HIGH")

    cwe: Any = Field(0)
    scanner_type: str = Field("SCA")
    scanner_severity: str = Field("Medium")
    defectdojo_severity: Optional[str] = None
    cvss_vector: Optional[str] = None

    in_kev: bool = False
    known_exploited: bool = False
    has_cve: bool = False
    is_static: bool = False
    is_dynamic: bool = False

    # Display / text metadata used by the new v4 feature builder.
    title: Optional[str] = None
    description: Optional[str] = None
    references: Optional[Any] = None
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    file_path: Optional[str] = None
    vulnerability_id: Optional[str] = None

    package_name: Optional[str] = None
    published: Optional[str] = None
    modified: Optional[str] = None
    withdrawn: Optional[str] = None
    published_year: Optional[int] = None

    ranges_count: int = Field(0, ge=0)
    versions_count: int = Field(0, ge=0)
    summary_len: Optional[int] = Field(None, ge=0)
    details_len: Optional[int] = Field(None, ge=0)
    references_count: int = Field(0, ge=0)

    github_reviewed: bool = False
    has_patch_ref: bool = False
    has_advisory_ref: bool = False

    cwe_id: Optional[Any] = None
    all_cwe_ids: Optional[Any] = None
    data_source: Optional[str] = None
    source_dataset: Optional[str] = None

    @model_validator(mode="after")
    def _resolve_kev(self) -> "VulnFeatures":
        if self.known_exploited:
            self.in_kev = True
        return self

    @field_validator("cvss_score", mode="before")
    @classmethod
    def _default_cvss(cls, v: Any) -> float:
        try:
            val = float(v)
            return val if 0.0 <= val <= 10.0 else 5.0
        except (TypeError, ValueError):
            return 5.0

    @field_validator(
        "attack_vector", "attack_complexity", "privileges_required",
        "user_interaction", "scope", "confidentiality_impact",
        "integrity_impact", "availability_impact", "scanner_type",
        mode="before",
    )
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
    product_id: Optional[int] = Field(None, ge=1)
    product_name: Optional[str] = None
    active_only: bool = True
    limit: int = Field(2000, ge=1, le=2000)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class RegisterRequest(BaseModel):
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
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=6, max_length=128)
    display_name: Optional[str] = Field(None, max_length=128)
    is_admin: bool = False
    access_status: str = Field("approved")

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
    access_status: Optional[str] = None
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
