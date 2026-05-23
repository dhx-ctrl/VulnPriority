"""Pydantic request/response schemas."""
from __future__ import annotations

import re
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from database.crud import password_is_valid

class VulnFeatures(BaseModel):
    """
    Normalised vulnerability feature payload accepted by all scoring endpoints.

    You can provide:
      - Individual CVSS component fields (attack_vector, etc.)
      - OR a raw cvss_vector string (overrides component fields if parseable)
    """
    cve_id:                  Optional[str]   = Field(None, description="CVE identifier, e.g. CVE-2021-44228")
    cvss_score:              float           = Field(5.0, ge=0.0, le=10.0)
    year:                    Optional[int]   = Field(None, ge=1999, le=2030, description="Year CVE was published")
    attack_vector:           str             = Field("NETWORK",   description="NETWORK | LOCAL | ADJACENT_NETWORK | PHYSICAL")
    attack_complexity:       str             = Field("LOW",       description="LOW | HIGH")
    privileges_required:     str             = Field("NONE",      description="NONE | LOW | HIGH")
    user_interaction:        str             = Field("NONE",      description="NONE | REQUIRED")
    scope:                   str             = Field("UNCHANGED", description="UNCHANGED | CHANGED")
    confidentiality_impact:  str             = Field("HIGH",      description="HIGH | LOW | NONE")
    integrity_impact:        str             = Field("HIGH",      description="HIGH | LOW | NONE")
    availability_impact:     str             = Field("HIGH",      description="HIGH | LOW | NONE")
    cwe:                     Any             = Field(0,           description="CWE as int (79), 'CWE-79', or '79.0'")
    scanner_type:            str             = Field("SCA",       description="SCA | SAST | DAST")
    scanner_severity:        str             = Field("Medium",    description="Original scanner/DefectDojo severity: Critical | High | Medium | Low | Info")
    defectdojo_severity:     Optional[str]   = Field(None,        description="Alias for scanner_severity when imported from DefectDojo")
    cvss_vector:             Optional[str]   = Field(None,        description="Raw CVSS v3 vector string; overrides component fields")
    # ── KEV fields ──────────────────────────────────────────────────────────
    # `in_kev` is the canonical name used by both model metadata files.
    # `known_exploited` is the DefectDojo field name; supplying either
    # (or both) sets in_kev=True for both models.  Both default to False so
    # existing callers that omit KEV information continue to work unchanged.
    in_kev:          bool = Field(False, description="True if the CVE appears in the CISA KEV catalog")
    known_exploited: bool = Field(False, description="DefectDojo alias for in_kev; merged into in_kev at validation time")
    # ── v3.1 features ────────────────────────────────────────────────────────
    has_cve:    bool = Field(False, description="True if a CVE identifier is associated with this finding")
    is_static:  bool = Field(False, description="True if the finding was produced by a static analysis (SAST) tool")
    is_dynamic: bool = Field(False, description="True if the finding was produced by a dynamic analysis (DAST) tool")

    # ── Display metadata ─────────────────────────────────────────────────────
    # These fields are NOT model features. They are preserved in raw_input so
    # the dashboard can show real finding names / packages / paths instead of
    # generic "Finding #N" / "N/A" placeholders.
    title:             Optional[str] = Field(None, description="Human-readable finding title from the scanner")
    component_name:    Optional[str] = Field(None, description="Vulnerable package or component name (e.g. 'lodash')")
    component_version: Optional[str] = Field(None, description="Installed version of the vulnerable component")
    file_path:         Optional[str] = Field(None, description="Source file or path where the finding was detected")
    vulnerability_id:  Optional[str] = Field(None, description="Primary vulnerability identifier (CVE, GHSA, etc.)")

    # ── Leakage-safe pipeline features / metadata inputs ─────────────────────
    # These are optional so existing API callers do not break. The backend
    # derives sensible defaults from DefectDojo fields when they are absent.
    package_name:      Optional[str] = Field(None, description="Alias for component_name/package name")
    published:         Optional[str] = Field(None, description="Published date/string if available")
    modified:          Optional[str] = Field(None, description="Modified date/string if available")
    withdrawn:         Optional[str] = Field(None, description="Withdrawn date/string if available")
    published_year:    Optional[int] = Field(None, description="Published year if already available")

    ranges_count:      int = Field(0, ge=0, description="Number of affected ranges if available")
    versions_count:    int = Field(0, ge=0, description="Number of affected versions if available")
    summary_len:       Optional[int] = Field(None, ge=0, description="Length of title/summary text")
    details_len:       Optional[int] = Field(None, ge=0, description="Length of description/details text")
    references_count:  int = Field(0, ge=0, description="Approximate number of reference URLs")

    github_reviewed:   bool = Field(False, description="Whether the advisory was GitHub reviewed, if known")
    has_patch_ref:     bool = Field(False, description="Whether references/text mention patch/fix/commit")
    has_advisory_ref:  bool = Field(False, description="Whether references/text mention advisory sources")

    # Raw fields retained only for compatibility with older trained feature sets.
    # The final minimal model drops these, but this lets the same backend run
    # either the 26-feature final model or an older leakage-safe pipeline.
    cwe_id:            Optional[Any] = Field(None, description="Raw CWE id alias")
    all_cwe_ids:       Optional[Any] = Field(None, description="Raw all-CWE list/string alias")
    data_source:       Optional[str] = Field(None, description="Optional source metadata, normally dropped in final model")
    source_dataset:    Optional[str] = Field(None, description="Optional source metadata, normally dropped in final model")

    @model_validator(mode="after")
    def _resolve_kev(self) -> "VulnFeatures":
        """Merge known_exploited into in_kev so downstream code only reads in_kev."""
        if self.known_exploited:
            self.in_kev = True
        return self

    @field_validator("cvss_score", mode="before")
    @classmethod
    def _default_cvss(cls, v: Any) -> float:
        """Coerce cvss_score and fall back to 5.0 on bad input."""
        try:
            val = float(v)
            return val if 0.0 <= val <= 10.0 else 5.0
        except (TypeError, ValueError):
            return 5.0

    @field_validator("attack_vector", "attack_complexity", "privileges_required",
                     "user_interaction", "scope", "confidentiality_impact",
                     "integrity_impact", "availability_impact", "scanner_type",
                     mode="before")
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
    """
    Body for /api/sync-defectdojo/.

    Resolution order for the target product:
      1. product_id  — used directly if provided (must be >= 1).
      2. product_name — looked up via GET /api/v2/products/ if product_id is absent.
      3. DEFECTDOJO_PRODUCT_ID env var — fallback when neither field is supplied.
    """
    product_id:   Optional[int] = Field(
        None, ge=1,
        description="DefectDojo numeric product ID (>= 1). Takes priority over product_name.",
    )
    product_name: Optional[str] = Field(
        None,
        description="Human-readable product name (e.g. 'JuiceShop'). Looked up via DefectDojo API.",
    )
    active_only: bool = Field(True,  description="Only fetch active (non-resolved) findings")
    limit:       int  = Field(2000,  ge=1, le=2000, description="Max findings to process")

class LoginRequest(BaseModel):
    """Dashboard login request."""
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

class RegisterRequest(BaseModel):
    """Public account registration request."""
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
    """Admin-created dashboard user."""
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=6, max_length=128)
    display_name: Optional[str] = Field(None, max_length=128)
    is_admin: bool = Field(False)
    access_status: str = Field("approved", description="pending | approved | disabled")

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
    access_status: Optional[str] = Field(None, description="pending | approved | disabled")
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

