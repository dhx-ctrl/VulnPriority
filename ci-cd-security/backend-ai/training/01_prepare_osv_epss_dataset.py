#!/usr/bin/env python3
r"""
Build a larger trainable npm OSV dataset for an AI vulnerability risk scorer.

Why this version exists:
- Many OSV npm records are GHSA advisories, not CVEs.
- EPSS only works for CVE IDs, so EPSS-only training drops most rows.
- This script extracts CVE, GHSA, CVSS, CWE, and severity more aggressively,
  including nested fields such as database_specific.severity, affected[].severity,
  and any CVSS vector stored anywhere in the JSON.
- It also writes an audit CSV for unlabeled rows so you can see what is still missing.

Example PowerShell:
python 01_build_huge_osv_dataset_DEEP_FIXED.py `
  --osv-zip ".\all.zip" `
  --epss-csv ".\epss_scores-current.csv.gz" `
  --out-dir ".\dataset_deep_fixed"
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import os
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pandas as pd

CVSS_VECTOR_RE = re.compile(r"CVSS:[0-9]\.[0-9]/[^\s,\"'}]+", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

SEVERITY_ORDER = {
    "NONE": 0,
    "LOW": 1,
    "MODERATE": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
SEVERITY_CANON = {
    "NONE": "NONE",
    "LOW": "LOW",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


# ----------------------------- general helpers -----------------------------

def parse_date_year(value: Any) -> Optional[int]:
    if not value:
        return None
    s = str(value)
    m = re.search(r"(19|20)\d{2}", s)
    return int(m.group(0)) if m else None


def days_since(value: Any) -> Optional[float]:
    if not value:
        return None
    s = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - dt).days, 0)
    except Exception:
        return None


def iter_json_values(obj: Any) -> Iterable[Any]:
    """Yield every nested scalar/dict/list value from JSON."""
    yield obj
    if isinstance(obj, dict):
        for v in obj.values():
            yield from iter_json_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_json_values(v)


def iter_key_value_pairs(obj: Any) -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k), v
            yield from iter_key_value_pairs(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_key_value_pairs(v)


def first_nonempty(values: Sequence[Any]) -> Optional[Any]:
    for v in values:
        if v is not None and str(v).strip() != "":
            return v
    return None


# ----------------------------- id extraction -----------------------------

def extract_cve_ids(record: Dict[str, Any]) -> List[str]:
    hits = set()

    for alias in record.get("aliases", []) or []:
        if isinstance(alias, str):
            hits.update(x.upper() for x in CVE_RE.findall(alias))

    # Some records hide CVEs in details/references/database_specific.
    for value in iter_json_values(record):
        if isinstance(value, str):
            hits.update(x.upper() for x in CVE_RE.findall(value))

    return sorted(hits)


def extract_ghsa_ids(record: Dict[str, Any]) -> List[str]:
    hits = set()
    rid = record.get("id")
    if isinstance(rid, str):
        hits.update(x.upper() for x in GHSA_RE.findall(rid))

    for alias in record.get("aliases", []) or []:
        if isinstance(alias, str):
            hits.update(x.upper() for x in GHSA_RE.findall(alias))

    for value in iter_json_values(record):
        if isinstance(value, str):
            hits.update(x.upper() for x in GHSA_RE.findall(value))

    return sorted(hits)


def extract_cwes(record: Dict[str, Any]) -> List[str]:
    hits = set()
    for value in iter_json_values(record):
        if isinstance(value, str):
            hits.update(x.upper() for x in CWE_RE.findall(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    hits.update(x.upper() for x in CWE_RE.findall(item))
    return sorted(hits)


# ----------------------------- severity/CVSS extraction -----------------------------

def normalize_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().upper()
    # GitHub uses MODERATE; most scanners use MEDIUM.
    if s in SEVERITY_CANON:
        return SEVERITY_CANON[s]
    # Sometimes fields contain e.g. "severity: high".
    for key in SEVERITY_ORDER:
        if re.fullmatch(key, s):
            return SEVERITY_CANON[key]
    return None


def max_severity(values: Iterable[Any]) -> Optional[str]:
    best = None
    best_score = -1
    for v in values:
        sev = normalize_severity(v)
        if sev is None:
            continue
        score = SEVERITY_ORDER.get(sev, -1)
        if score > best_score:
            best = sev
            best_score = score
    return best


def extract_severity_text(record: Dict[str, Any]) -> Optional[str]:
    candidates: List[Any] = []

    # Known OSV/GHSA locations.
    ds = record.get("database_specific") or {}
    if isinstance(ds, dict):
        candidates.append(ds.get("severity"))
        candidates.append(ds.get("github_severity"))
        candidates.append(ds.get("cvss_severity"))

    # Root severity can be a list of dicts with type/score, or rarely text.
    root_sev = record.get("severity")
    if isinstance(root_sev, str):
        candidates.append(root_sev)
    elif isinstance(root_sev, list):
        for item in root_sev:
            if isinstance(item, dict):
                candidates.extend([item.get("severity"), item.get("rating"), item.get("level")])
            else:
                candidates.append(item)

    # affected[].database_specific and affected[].severity sometimes carry GHSA/CVSS info.
    for aff in record.get("affected", []) or []:
        if not isinstance(aff, dict):
            continue
        ads = aff.get("database_specific") or {}
        if isinstance(ads, dict):
            candidates.extend([ads.get("severity"), ads.get("github_severity"), ads.get("cvss_severity")])
        aff_sev = aff.get("severity")
        if isinstance(aff_sev, str):
            candidates.append(aff_sev)
        elif isinstance(aff_sev, list):
            for item in aff_sev:
                if isinstance(item, dict):
                    candidates.extend([item.get("severity"), item.get("rating"), item.get("level")])
                else:
                    candidates.append(item)

    # Deep recursive fallback: any key containing severity/rating/level with value high/moderate/etc.
    for key, value in iter_key_value_pairs(record):
        lk = key.lower()
        if any(token in lk for token in ["severity", "rating", "level"]):
            if isinstance(value, str):
                candidates.append(value)
            elif isinstance(value, dict):
                candidates.extend(value.values())

    return max_severity(candidates)


def extract_cvss_vector(record: Dict[str, Any]) -> Optional[str]:
    candidates: List[str] = []

    def add_candidate(value: Any) -> None:
        if isinstance(value, str):
            candidates.extend(CVSS_VECTOR_RE.findall(value))

    # Known OSV severity structure.
    for item in record.get("severity", []) or []:
        if isinstance(item, dict):
            add_candidate(item.get("score"))
            add_candidate(item.get("vector"))

    for aff in record.get("affected", []) or []:
        if not isinstance(aff, dict):
            continue
        for item in aff.get("severity", []) or []:
            if isinstance(item, dict):
                add_candidate(item.get("score"))
                add_candidate(item.get("vector"))

    # Deep fallback: any string anywhere that looks like a CVSS vector.
    for value in iter_json_values(record):
        add_candidate(value)

    return candidates[0].upper() if candidates else None


def extract_numeric_cvss_score(record: Dict[str, Any]) -> Optional[float]:
    # Some sources store numeric score directly.
    numeric_candidates: List[float] = []
    for key, value in iter_key_value_pairs(record):
        lk = key.lower()
        if "cvss" in lk and any(tok in lk for tok in ["score", "base_score", "basescore"]):
            try:
                f = float(value)
                if 0.0 <= f <= 10.0:
                    numeric_candidates.append(f)
            except Exception:
                pass

    if numeric_candidates:
        return max(numeric_candidates)

    vector = extract_cvss_vector(record)
    if not vector:
        return None

    # Best path: use cvss package if installed.
    try:
        if vector.startswith("CVSS:3"):
            from cvss import CVSS3  # type: ignore
            return float(CVSS3(vector).scores()[0])
        if vector.startswith("CVSS:2"):
            from cvss import CVSS2  # type: ignore
            return float(CVSS2(vector).scores()[0])
    except Exception:
        pass

    # Fallback approximation for CVSS v3.x only. This is not perfect, but better than dropping.
    try:
        if vector.startswith("CVSS:3"):
            parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
            impact = 0.0
            if parts.get("C") == "H": impact += 2.0
            elif parts.get("C") == "L": impact += 1.0
            if parts.get("I") == "H": impact += 2.0
            elif parts.get("I") == "L": impact += 1.0
            if parts.get("A") == "H": impact += 2.0
            elif parts.get("A") == "L": impact += 1.0
            exploit = 0.0
            if parts.get("AV") == "N": exploit += 1.2
            elif parts.get("AV") == "A": exploit += 0.8
            if parts.get("AC") == "L": exploit += 1.0
            if parts.get("PR") == "N": exploit += 1.0
            if parts.get("UI") == "N": exploit += 0.8
            approx = min(10.0, max(0.0, 1.0 + impact + exploit))
            return round(approx, 1)
    except Exception:
        return None

    return None


def severity_from_cvss(score: Optional[float]) -> Optional[str]:
    if score is None or pd.isna(score):
        return None
    score = float(score)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


# ----------------------------- package extraction -----------------------------

def affected_npm_packages(record: Dict[str, Any], include_all_ecosystems: bool = False) -> List[Dict[str, Any]]:
    rows = []
    for aff in record.get("affected", []) or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        if not isinstance(pkg, dict):
            continue
        ecosystem = str(pkg.get("ecosystem") or "").strip()
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        if not include_all_ecosystems and ecosystem.lower() != "npm":
            continue
        rows.append({
            "package_name": name,
            "ecosystem": ecosystem or "UNKNOWN",
            "ranges_count": len(aff.get("ranges", []) or []),
            "versions_count": len(aff.get("versions", []) or []),
            "affected_database_specific": aff.get("database_specific") or {},
        })
    return rows


def references_features(record: Dict[str, Any]) -> Dict[str, int]:
    refs = record.get("references", []) or []
    text = " ".join(json.dumps(r, ensure_ascii=False).lower() for r in refs if isinstance(r, (dict, list, str)))
    details = str(record.get("details") or "").lower()
    summary = str(record.get("summary") or "").lower()
    combined = " ".join([text, details, summary])
    return {
        "has_exploit_ref": int(any(x in combined for x in ["exploit", "metasploit", "proof of concept", "poc", "0-day", "0day"])),
        "has_patch_ref": int(any(x in combined for x in ["patch", "fix", "commit", "pull request", "release"])),
        "has_advisory_ref": int(any(x in combined for x in ["advisory", "security-advisories", "github.com/advisories", "nvd.nist.gov"])),
    }


# ----------------------------- EPSS -----------------------------

def load_epss(path: Optional[str]) -> pd.DataFrame:
    if not path:
        return pd.DataFrame(columns=["cve_id", "epss_score", "epss_percentile"])
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"EPSS file not found: {p}")
    df = pd.read_csv(p, comment="#", compression="infer")
    df.columns = [str(c).strip().lower() for c in df.columns]
    # FIRST EPSS columns are usually: cve, epss, percentile
    rename = {}
    if "cve" in df.columns:
        rename["cve"] = "cve_id"
    if "epss" in df.columns:
        rename["epss"] = "epss_score"
    if "percentile" in df.columns:
        rename["percentile"] = "epss_percentile"
    df = df.rename(columns=rename)
    keep = [c for c in ["cve_id", "epss_score", "epss_percentile"] if c in df.columns]
    df = df[keep].copy()
    df["cve_id"] = df["cve_id"].astype(str).str.upper()
    df["epss_score"] = pd.to_numeric(df.get("epss_score"), errors="coerce")
    if "epss_percentile" in df.columns:
        df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce")
    else:
        df["epss_percentile"] = pd.NA
    df = df.dropna(subset=["cve_id"]).drop_duplicates(subset=["cve_id"], keep="first")
    return df


# ----------------------------- dataset builder -----------------------------

def build_rows(osv_zip: str, include_all_ecosystems: bool = False, max_records: Optional[int] = None) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    skipped_bad_json = 0
    seen = 0

    with zipfile.ZipFile(osv_zip, "r") as zf:
        names = [n for n in zf.namelist() if n.lower().endswith(".json")]
        for name in names:
            if max_records and seen >= max_records:
                break
            seen += 1
            try:
                with zf.open(name) as f:
                    record = json.load(f)
            except Exception:
                skipped_bad_json += 1
                continue

            if not isinstance(record, dict):
                continue

            packages = affected_npm_packages(record, include_all_ecosystems=include_all_ecosystems)
            if not packages:
                continue

            cve_ids = extract_cve_ids(record)
            ghsa_ids = extract_ghsa_ids(record)
            cwes = extract_cwes(record)
            cvss_vector = extract_cvss_vector(record)
            cvss_score = extract_numeric_cvss_score(record)
            sev_text = extract_severity_text(record) or severity_from_cvss(cvss_score)
            ref_feats = references_features(record)

            aliases = record.get("aliases", []) or []
            aliases_str = ";".join(str(a) for a in aliases)
            cve_id = cve_ids[0] if cve_ids else None
            ghsa_id = ghsa_ids[0] if ghsa_ids else (record.get("id") if str(record.get("id", "")).upper().startswith("GHSA-") else None)
            published = record.get("published")
            modified = record.get("modified")
            withdrawn = record.get("withdrawn")
            dbs = record.get("database_specific") or {}
            if not isinstance(dbs, dict):
                dbs = {}

            for pkg in packages:
                rows.append({
                    "osv_id": record.get("id"),
                    "cve_id": cve_id,
                    "all_cve_ids": ";".join(cve_ids),
                    "ghsa_id": ghsa_id,
                    "all_ghsa_ids": ";".join(ghsa_ids),
                    "aliases": aliases_str,
                    "package_name": pkg["package_name"],
                    "ecosystem": pkg["ecosystem"],
                    "severity": sev_text,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cwe_id": cwes[0] if cwes else None,
                    "all_cwe_ids": ";".join(cwes),
                    "published": published,
                    "modified": modified,
                    "withdrawn": withdrawn,
                    "published_year": parse_date_year(published),
                    "days_since_published": days_since(published),
                    "days_since_modified": days_since(modified),
                    "ranges_count": pkg["ranges_count"],
                    "versions_count": pkg["versions_count"],
                    "summary_len": len(str(record.get("summary") or "")),
                    "details_len": len(str(record.get("details") or "")),
                    "references_count": len(record.get("references", []) or []),
                    "github_reviewed": int(bool(dbs.get("github_reviewed"))) if "github_reviewed" in dbs else 0,
                    "source_database": str(dbs.get("source") or ""),
                    **ref_feats,
                })

    df = pd.DataFrame(rows)
    if skipped_bad_json:
        print(f"Skipped bad JSON files: {skipped_bad_json:,}")
    return df


def add_epss(df: pd.DataFrame, epss_df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    if epss_df.empty:
        df["epss_score"] = pd.NA
        df["epss_percentile"] = pd.NA
        return df
    return df.merge(epss_df, on="cve_id", how="left")


def add_hybrid_labels(df: pd.DataFrame, epss_threshold: float = 0.10, cvss_threshold: float = 7.0) -> pd.DataFrame:
    df = df.copy()
    epss = pd.to_numeric(df.get("epss_score"), errors="coerce")
    cvss = pd.to_numeric(df.get("cvss_score"), errors="coerce")
    sev = df.get("severity", pd.Series([None] * len(df))).astype(str).str.upper().replace({"MODERATE": "MEDIUM"})

    label = pd.Series(pd.NA, index=df.index, dtype="Int64")
    source = pd.Series("unlabeled", index=df.index, dtype="object")

    has_epss = epss.notna()
    label.loc[has_epss] = (epss.loc[has_epss] >= epss_threshold).astype(int).values
    source.loc[has_epss] = "epss"

    needs = label.isna() & cvss.notna()
    label.loc[needs] = (cvss.loc[needs] >= cvss_threshold).astype(int).values
    source.loc[needs] = "cvss"

    needs = label.isna() & sev.isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    label.loc[needs] = sev.loc[needs].isin(["HIGH", "CRITICAL"]).astype(int).values
    source.loc[needs] = "severity"

    df["label_high_risk"] = label
    df["label_source"] = source
    df["label_from_epss"] = (source == "epss").astype(int)
    df["has_cve"] = df["cve_id"].notna().astype(int)
    df["has_ghsa"] = df["ghsa_id"].notna().astype(int)
    df["has_cvss"] = cvss.notna().astype(int)
    df["has_severity_text"] = sev.isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).astype(int)
    return df


def write_audit(df: pd.DataFrame, out_dir: Path) -> None:
    unlabeled = df[df["label_high_risk"].isna()].copy()
    audit_path = out_dir / "unlabeled_audit_sample.csv"
    cols = [
        "osv_id", "ghsa_id", "cve_id", "package_name", "ecosystem", "aliases",
        "severity", "cvss_score", "cvss_vector", "published", "modified",
        "summary_len", "details_len", "references_count", "has_advisory_ref", "has_patch_ref", "has_exploit_ref",
    ]
    cols = [c for c in cols if c in unlabeled.columns]
    unlabeled[cols].head(500).to_csv(audit_path, index=False)

    counts_path = out_dir / "label_source_counts.csv"
    df["label_source"].value_counts(dropna=False).rename_axis("label_source").reset_index(name="rows").to_csv(counts_path, index=False)

    sev_path = out_dir / "severity_counts.csv"
    df["severity"].fillna("MISSING").value_counts(dropna=False).rename_axis("severity").reset_index(name="rows").to_csv(sev_path, index=False)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--osv-zip", required=True, help="Path to OSV all.zip")
    ap.add_argument("--epss-csv", default=None, help="Path to epss_scores-current.csv.gz")
    ap.add_argument("--out-dir", required=True, help="Output directory")
    ap.add_argument("--all-ecosystems", action="store_true", help="Do not filter to npm ecosystem")
    ap.add_argument("--epss-threshold", type=float, default=0.10)
    ap.add_argument("--cvss-threshold", type=float, default=7.0)
    ap.add_argument("--max-records", type=int, default=None, help="Debug only: limit OSV JSON files processed")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Building OSV dataframe...")
    df = build_rows(args.osv_zip, include_all_ecosystems=args.all_ecosystems, max_records=args.max_records)
    print(f"Rows after npm affected-package extraction: {len(df):,}")

    if df.empty:
        raise SystemExit("No rows found. Check --osv-zip and ecosystem filtering.")

    print("Loading EPSS and merging by CVE...")
    epss_df = load_epss(args.epss_csv)
    df = add_epss(df, epss_df)

    print("Building hybrid labels: EPSS -> CVSS -> severity text...")
    df = add_hybrid_labels(df, epss_threshold=args.epss_threshold, cvss_threshold=args.cvss_threshold)

    # Deduplicate exact duplicated package/advisory rows, not vulnerability IDs globally.
    dedupe_cols = ["osv_id", "package_name", "ecosystem", "cve_id", "ghsa_id"]
    before = len(df)
    df = df.drop_duplicates(subset=[c for c in dedupe_cols if c in df.columns], keep="first")
    after = len(df)
    if after != before:
        print(f"Dropped exact duplicate package/advisory rows: {before-after:,}")

    all_path = out_dir / "all_data.csv"
    train_path = out_dir / "trainable_data.csv"
    df.to_csv(all_path, index=False)
    trainable = df[df["label_high_risk"].notna()].copy()
    trainable["label_high_risk"] = trainable["label_high_risk"].astype(int)
    trainable.to_csv(train_path, index=False)

    write_audit(df, out_dir)

    rows_with_epss = int(pd.to_numeric(df.get("epss_score"), errors="coerce").notna().sum())
    rows_with_cvss = int(pd.to_numeric(df.get("cvss_score"), errors="coerce").notna().sum())
    rows_with_sev = int(df.get("has_severity_text", pd.Series(dtype=int)).sum())
    high = int(trainable["label_high_risk"].sum()) if not trainable.empty else 0
    low = int(len(trainable) - high)

    print("\nDone.")
    print(f"  Total rows:                  {len(df):,}")
    print(f"  Rows with EPSS:              {rows_with_epss:,}")
    print(f"  Rows with real/parsed CVSS:  {rows_with_cvss:,}")
    print(f"  Rows with severity text:     {rows_with_sev:,}")
    print(f"  Hybrid-trainable rows:       {len(trainable):,}")
    print(f"  High-risk labels:            {high:,}")
    print(f"  Low-risk labels:             {low:,}")
    print(f"  Output all_data.csv:         {all_path}")
    print(f"  Output trainable_data.csv:   {train_path}")
    print(f"  Audit sample:                {out_dir / 'unlabeled_audit_sample.csv'}")
    print(f"  Label counts:                {out_dir / 'label_source_counts.csv'}")

    if len(trainable) < 20000:
        print("\nWARNING: trainable rows are still low.")
        print("This usually means the remaining OSV rows genuinely do not contain CVE, CVSS, or GHSA severity.")
        print("Open unlabeled_audit_sample.csv to confirm what fields are missing before inventing labels.")


if __name__ == "__main__":
    main()
