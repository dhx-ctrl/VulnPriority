"""DefectDojo API integration and finding normalization."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastapi import HTTPException

from core.config import DEFECTDOJO_API_KEY, DEFECTDOJO_URL, log
from schemas import VulnFeatures
from services.scoring import (
    _DAST_TOOLS,
    _SAST_TOOLS,
    _SCA_TOOLS,
    _SEV_CVSS_FALLBACK,
    _count_references,
    normalise_cwe,
    year_from_cve,
)

def _dd_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Token {DEFECTDOJO_API_KEY}",
        "Content-Type":  "application/json",
    }

def _extract_product_id_from_finding(finding: Dict) -> Optional[int]:
    """
    Best-effort extraction of product_id from a DefectDojo finding response.

    DefectDojo findings belong to a product through:
        finding -> test -> engagement -> product

    This helper is used as a defensive local safety filter because some
    DefectDojo installations do not reliably filter findings with the old
    `product_id` query parameter.
    """
    # Most useful when `related_fields=true` is passed.
    related = finding.get("related_fields") or {}
    try:
        pid = (
            related.get("test", {})
                   .get("engagement", {})
                   .get("product", {})
                   .get("id")
        )
        if pid is not None:
            return int(pid)
    except (AttributeError, TypeError, ValueError):
        pass

    # Some DefectDojo versions expose product info inside the prefetched test.
    raw_test = finding.get("test")
    if isinstance(raw_test, dict):
        try:
            pid = (
                raw_test.get("engagement", {})
                        .get("product", {})
                        .get("id")
            )
            if pid is not None:
                return int(pid)
        except (AttributeError, TypeError, ValueError):
            pass

    # Some versions expose direct fields.
    for key in ("product_id", "product"):
        try:
            val = finding.get(key)
            if val is not None:
                return int(val)
        except (TypeError, ValueError):
            pass

    return None

def fetch_dd_findings(product_id: int, active_only: bool, limit: int) -> List[Dict]:
    """
    Paginate /api/v2/findings/ for findings whose test engagement belongs
    to product_id.

    Important fix:
      - Uses DefectDojo's nested product filter:
            test__engagement__product=<product_id>
        instead of the weaker/incorrect product_id parameter.
      - Applies a local safety filter when product metadata is returned, so
        mixed JuiceShop/DVWA/DVNA results are discarded.

    Result behavior:
      - `limit` is a maximum cap, not an exact target.
      - If DVNA has 120 active findings and limit=500, this returns 120.
      - If more than `limit` match, this returns only `limit`.
    """
    url = f"{DEFECTDOJO_URL}/api/v2/findings/"
    page = min(limit, 100)  # DefectDojo max page size is normally 100
    offset = 0

    matched_findings: List[Dict] = []
    raw_seen = 0
    discarded_wrong_product = 0
    missing_product_metadata = 0

    while len(matched_findings) < limit:
        # Build params as a list of tuples so repeated keys (prefetch[]) work.
        params: List[Tuple[str, Any]] = [
            # Correct product filter path: finding -> test -> engagement -> product
            ("test__engagement__product", product_id),
            ("limit", page),
            ("offset", offset),
            ("prefetch[]", "test"),
            ("prefetch[]", "found_by"),
            ("related_fields", "true"),
        ]
        if active_only:
            params.append(("active", "true"))

        resp = requests.get(url, headers=_dd_headers(), params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        batch = data.get("results", [])
        raw_seen += len(batch)

        for finding in batch:
            found_product_id = _extract_product_id_from_finding(finding)

            # If DefectDojo returns product metadata, enforce it strictly.
            # If metadata is absent, keep it because the API-side nested filter
            # may still have been applied correctly. We log how often this happens.
            if found_product_id is not None and found_product_id != int(product_id):
                discarded_wrong_product += 1
                continue

            if found_product_id is None:
                missing_product_metadata += 1

            matched_findings.append(finding)
            if len(matched_findings) >= limit:
                break

        if not data.get("next") or not batch:
            break

        offset += page

    log.info(
        f"DefectDojo findings filter: requested product_id={product_id}, "
        f"raw_seen={raw_seen}, matched={len(matched_findings)}, "
        f"discarded_wrong_product={discarded_wrong_product}, "
        f"missing_product_metadata={missing_product_metadata}, limit={limit}"
    )

    return matched_findings[:limit]

def fetch_dd_products() -> List[Dict]:
    """
    Return all DefectDojo products as a list of {"id": int, "name": str} dicts,
    paging through /api/v2/products/ until exhausted.
    """
    url    = f"{DEFECTDOJO_URL}/api/v2/products/"
    offset = 0
    page   = 100
    products: List[Dict] = []

    while True:
        resp = requests.get(
            url,
            headers=_dd_headers(),
            params={"limit": page, "offset": offset},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        for p in data.get("results", []):
            products.append({"id": p["id"], "name": p["name"]})

        if not data.get("next"):
            break
        offset += page

    return products

def resolve_dd_product_id(product_name: str) -> Tuple[int, str]:
    """
    Look up *product_name* in DefectDojo and return (product_id, resolved_name).

    Resolution rules:
      1. Exact case-insensitive match  → use it directly.
      2. Partial / substring matches   → use the sole match, or raise 400 if ambiguous.
      3. No match at all               → raise 404.
    """
    try:
        products = fetch_dd_products()
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach DefectDojo while listing products: {exc}",
        )

    needle = product_name.strip().lower()

    # Exact case-insensitive match first — unambiguous
    exact = [p for p in products if p["name"].lower() == needle]
    if len(exact) == 1:
        return exact[0]["id"], exact[0]["name"]

    # Multiple exact hits (shouldn't happen but handle it)
    if len(exact) > 1:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Multiple DefectDojo products match '{product_name}' exactly. "
                           "Provide product_id instead.",
                "candidates": [{"id": p["id"], "name": p["name"]} for p in exact],
            },
        )

    # Substring / partial match fallback
    partial = [p for p in products if needle in p["name"].lower()]
    if len(partial) == 1:
        return partial[0]["id"], partial[0]["name"]

    if len(partial) > 1:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"'{product_name}' matches multiple DefectDojo products. "
                           "Refine the name or supply product_id directly.",
                "candidates": [{"id": p["id"], "name": p["name"]} for p in partial],
            },
        )

    # Nothing matched
    raise HTTPException(
        status_code=404,
        detail=f"No DefectDojo product found matching '{product_name}'. "
               "Check the name or use /api/products/ to browse available products.",
    )

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

def extract_cve_from_finding(finding: Dict) -> Optional[str]:
    """
    Search for a CVE identifier in the most likely locations of a DefectDojo
    finding dict.  Returns the first match (upper-cased) or None.

    Fields searched in order:
      1. cve                  – top-level string field
      2. vulnerability_ids    – list of {"vulnerability_id": "CVE-..."} dicts
                                (or a list of plain strings for older DD versions)
      3. vuln_id_from_tool    – string populated by some scanner integrations
      4. title                – free-text; e.g. "CVE-2021-44228 in log4j"
      5. description          – longer free-text; last resort before title
      6. references           – URL list or blob; contains CVE links in some exports
    """
    # 1. Top-level cve field
    raw_cve = finding.get("cve")
    if raw_cve and isinstance(raw_cve, str):
        m = _CVE_RE.search(raw_cve)
        if m:
            return m.group(0).upper()

    # 2. vulnerability_ids list
    raw_vuln_ids = finding.get("vulnerability_ids") or []
    if isinstance(raw_vuln_ids, list):
        for item in raw_vuln_ids:
            if isinstance(item, dict):
                vid = item.get("vulnerability_id") or ""
            else:
                vid = str(item)
            m = _CVE_RE.search(vid)
            if m:
                return m.group(0).upper()

    # 3–6. Free-text fields (searched in priority order)
    for field in ("vuln_id_from_tool", "title", "description", "references"):
        val = finding.get(field)
        if val and isinstance(val, str):
            m = _CVE_RE.search(val)
            if m:
                return m.group(0).upper()

    return None

def normalise_dd_finding(finding: Dict) -> Tuple["VulnFeatures", Optional[str]]:
    """
    Map one DefectDojo finding dict to a VulnFeatures object ready for scoring.

    Fields used from the DefectDojo response:
      cve / vulnerability_ids / vuln_id_from_tool / title / description / references
                      → cve_id  (via extract_cve_from_finding — all six fields searched)
      cwe             → cwe
      cvssv3_score    → cvss_score
      cvssv3          → cvss_vector (parsed for component fields)
      severity        → fallback cvss_score when numeric score is absent
      test            → scanner_type via test_type_name (when prefetched)
      found_by        → scanner_type fallback (list of strings or dicts)
      date / created  → year fallback

    Defensive notes:
      - `test` is an integer ID unless prefetch[]=test was requested.
        We handle both: if it is a dict we read test_type_name; if it is an
        integer we silently fall back to found_by without crashing.
      - `found_by` items can be strings or dicts depending on whether
        prefetch[]=found_by was requested — both forms are handled.
      - `cwe` from DefectDojo is typically an integer but can arrive as a
        string or None; normalise_cwe() handles all variants.

    Returns (VulnFeatures, product_name_or_None).
    """
    cve_id      = extract_cve_from_finding(finding)
    raw_cwe     = finding.get("cwe") or 0
    cvss_score  = float(finding.get("cvssv3_score") or 0.0)
    cvss_vector = finding.get("cvssv3") or None
    severity    = (finding.get("severity") or "Medium").strip().title()

    # Fallback CVSS from severity band when no numeric score is present
    if not cvss_score:
        cvss_score = _SEV_CVSS_FALLBACK.get(severity, 5.0)

    # ── Scanner type detection (DefectDojo-aware, with SCA preserved) ───
    # Priority:
    #   1. Explicit tool names from test/found_by/text:
    #        ZAP/Burp/etc.    -> DAST
    #        Trivy/npm/Snyk   -> SCA
    #        Semgrep/Sonar    -> SAST
    #   2. DefectDojo dynamic_finding flag -> DAST
    #   3. DefectDojo static_finding flag  -> SAST only as a last fallback
    #   4. Default -> SCA
    #
    # Important: DefectDojo often marks SCA imports such as Trivy as
    # static_finding=True. Therefore static_finding must NOT automatically
    # override explicit SCA tool names, otherwise Trivy becomes SAST.
    raw_test = finding.get("test")
    raw_found_by = finding.get("found_by") or []

    static_flag = bool(finding.get("static_finding") or False)
    dynamic_flag = bool(finding.get("dynamic_finding") or False)

    tool_candidates: List[str] = []

    # Test metadata: may be a prefetched object or just an integer ID.
    if isinstance(raw_test, dict):
        for key in (
            "test_type_name", "scan_type", "title", "name", "tool", "test_type",
        ):
            val = raw_test.get(key)
            if val:
                tool_candidates.append(str(val).lower())

        # Some DefectDojo versions nest scan/test type as dicts.
        for key in ("test_type", "scan_type"):
            val = raw_test.get(key)
            if isinstance(val, dict):
                for subkey in ("name", "title", "test_type_name", "scan_type"):
                    subval = val.get(subkey)
                    if subval:
                        tool_candidates.append(str(subval).lower())
    elif raw_test is not None:
        log.debug(
            f"Finding {finding.get('id')}: 'test' is {type(raw_test).__name__} "
            f"({raw_test!r}) — not a prefetched object. Falling back to found_by."
        )

    # found_by can contain multiple tools. Check all of them, not only first.
    if isinstance(raw_found_by, list):
        for item in raw_found_by:
            if isinstance(item, dict):
                for key in ("name", "title", "test_type_name", "scan_type"):
                    val = item.get(key)
                    if val:
                        tool_candidates.append(str(val).lower())
            else:
                tool_candidates.append(str(item).lower())
    elif raw_found_by:
        tool_candidates.append(str(raw_found_by).lower())

    # Extra fallback from finding text.
    # Keep this useful but do not let generic static_finding flags dominate.
    for key in ("title", "description", "file_path", "component_name"):
        val = finding.get(key)
        if val:
            tool_candidates.append(str(val).lower())

    tool_blob = " ".join(tool_candidates)

    explicit_dast = any(t in tool_blob for t in _DAST_TOOLS)
    explicit_sca  = any(t in tool_blob for t in _SCA_TOOLS)
    explicit_sast = any(t in tool_blob for t in _SAST_TOOLS)

    scanner_type = "SCA"

    # Explicit tool names beat generic DefectDojo flags.
    # DAST first because ZAP/Burp should never be treated as SCA/SAST.
    # SCA before SAST because Trivy/npm-audit findings can be static_finding=True.
    if explicit_dast:
        scanner_type = "DAST"
    elif explicit_sca:
        scanner_type = "SCA"
    elif explicit_sast:
        scanner_type = "SAST"
    elif dynamic_flag:
        scanner_type = "DAST"
    elif static_flag:
        scanner_type = "SAST"

    log.debug(
        f"Finding {finding.get('id')} scanner detection: "
        f"static={static_flag}, dynamic={dynamic_flag}, "
        f"explicit_sca={explicit_sca}, explicit_sast={explicit_sast}, explicit_dast={explicit_dast}, "
        f"tool_blob='{tool_blob[:250]}', scanner_type={scanner_type}"
    )

    # Year from CVE-ID, then finding date, then fallback
    year = year_from_cve(cve_id)
    if year is None:
        date_str = finding.get("date") or finding.get("created") or ""
        if date_str and len(date_str) >= 4:
            try:
                year = int(date_str[:4])
            except ValueError:
                year = None

    # Resolve product name from several possible locations in the response.
    # With ?related_fields=true, DefectDojo nests the product under
    #   finding["related_fields"]["test"]["engagement"]["product"]["name"]
    # but older servers may put it directly on the finding as "product_name".
    product_name = (finding.get("product_name") or "").strip()

    if not product_name:
        related = finding.get("related_fields") or {}
        try:
            product_name = (
                related.get("test", {})
                       .get("engagement", {})
                       .get("product", {})
                       .get("name", "")
            ).strip()
        except (AttributeError, TypeError):
            product_name = ""

    if not product_name:
        # Some DefectDojo versions expose it via the prefetched `test` object
        if isinstance(raw_test, dict):
            try:
                product_name = (
                    raw_test.get("engagement", {})
                            .get("product", {})
                            .get("name", "")
                ).strip()
            except (AttributeError, TypeError):
                product_name = ""

    # ── Display metadata — preserved verbatim from the DefectDojo finding ──
    # These go into VulnFeatures so they're serialised into raw_input and are
    # available to the frontend without any extra DB columns.
    dd_title = (finding.get("title") or "").strip() or None

    # component_name / component_version come from Trivy / Snyk / npm-audit
    dd_component_name    = (finding.get("component_name")    or "").strip() or None
    dd_component_version = (finding.get("component_version") or "").strip() or None

    # file_path is populated by SAST tools (Semgrep) and sometimes by Trivy
    dd_file_path = (finding.get("file_path") or "").strip() or None

    # vulnerability_ids is a list of {"vulnerability_id": "CVE-...", ...} dicts.
    # Fall back to the top-level cve field when the list is absent or empty.
    raw_vuln_ids = finding.get("vulnerability_ids") or []
    if isinstance(raw_vuln_ids, list) and raw_vuln_ids:
        first_vid = raw_vuln_ids[0]
        dd_vuln_id = (
            first_vid.get("vulnerability_id") if isinstance(first_vid, dict) else str(first_vid)
        ) or None
    else:
        dd_vuln_id = cve_id   # already extracted above

    # ── v3.1 binary flags derived from the DefectDojo finding ─────────────
    has_cve    = cve_id is not None
    is_static  = static_flag
    is_dynamic = dynamic_flag

    return VulnFeatures(
        cve_id             = cve_id,
        cvss_score         = cvss_score,
        year               = year,
        cwe                = raw_cwe,
        scanner_type       = scanner_type,
        scanner_severity   = severity,
        defectdojo_severity= severity,
        cvss_vector        = cvss_vector,
        in_kev             = bool(finding.get("known_exploited") or False),
        has_cve            = has_cve,
        is_static          = is_static,
        is_dynamic         = is_dynamic,
        # Display metadata
        title              = dd_title,
        description        = finding.get("description"),
        references         = finding.get("references"),
        component_name     = dd_component_name,
        component_version  = dd_component_version,
        file_path          = dd_file_path,
        vulnerability_id   = dd_vuln_id,
        # Leakage-safe pipeline metadata features
        package_name       = dd_component_name,
        published          = finding.get("date") or finding.get("created"),
        modified           = finding.get("updated") or finding.get("last_reviewed"),
        ranges_count       = 0,
        versions_count     = 1 if dd_component_version else 0,
        summary_len        = len(dd_title or ""),
        details_len        = len(str(finding.get("description") or "")),
        references_count   = _count_references(finding.get("references")),
        has_patch_ref      = bool(re.search(r"patch|fixed|fix|commit|pull request|pr/", str(finding.get("references") or finding.get("description") or ""), re.I)),
        has_advisory_ref   = bool(re.search(r"advisory|nvd|osv|ghsa|github.com/advisories", str(finding.get("references") or finding.get("description") or ""), re.I)),
        cwe_id             = raw_cwe,
        all_cwe_ids        = f"CWE-{normalise_cwe(raw_cwe)}" if normalise_cwe(raw_cwe) else None,
    ), (product_name or None)

