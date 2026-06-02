#!/usr/bin/env python3
"""
Fetch raw vulnerability descriptions from the OSV API with a GHSA fallback.

Strategy per ID:
  1. Try OSV  https://api.osv.dev/v1/vulns/<id>  (no auth needed)
  2. If that fails AND the id looks like a GHSA AND a github_token was given,
     retry via the GitHub GraphQL API (needs token for higher rate limits).

All results are cached on disk so subsequent runs are instant.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, Optional

import pandas as pd

OSV_URL   = "https://api.osv.dev/v1/vulns/{}"
GHSA_URL  = "https://api.github.com/graphql"

GHSA_QUERY = """
query($id: String!) {
  securityAdvisory(ghsaId: $id) {
    summary
    description
  }
}
"""


def _load_cache(p: Path) -> Dict[str, dict]:
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_cache(p: Path, cache: Dict[str, dict]) -> None:
    p.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")


def _fetch_osv(osv_id: str, timeout: float = 10.0) -> dict:
    req = urllib.request.Request(
        OSV_URL.format(osv_id),
        headers={"User-Agent": "vuln-risk-pipeline/1.0 (research)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        return {"summary": data.get("summary", "") or "",
                "details": data.get("details", "") or "", "ok": True, "source": "osv"}
    except urllib.error.HTTPError as e:
        reason = e.headers.get("x-deny-reason", "") if e.headers else ""
        return {"summary": "", "details": "", "ok": False,
                "error": f"HTTP {e.code} {reason}".strip()}
    except Exception as e:
        return {"summary": "", "details": "", "ok": False, "error": type(e).__name__}


def _fetch_ghsa(ghsa_id: str, token: str, timeout: float = 10.0) -> dict:
    # normalise: GHSA API wants uppercase with dashes
    gid = ghsa_id.upper()
    body = json.dumps({"query": GHSA_QUERY, "variables": {"id": gid}}).encode()
    req = urllib.request.Request(
        GHSA_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "vuln-risk-pipeline/1.0 (research)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        adv = (data.get("data") or {}).get("securityAdvisory") or {}
        if not adv:
            return {"summary": "", "details": "", "ok": False, "error": "no advisory in response"}
        return {"summary": adv.get("summary", "") or "",
                "details": adv.get("description", "") or "", "ok": True, "source": "ghsa"}
    except urllib.error.HTTPError as e:
        return {"summary": "", "details": "", "ok": False,
                "error": f"GHSA HTTP {e.code}"}
    except Exception as e:
        return {"summary": "", "details": "", "ok": False, "error": type(e).__name__}


def _is_ghsa_id(s: str) -> bool:
    return s.upper().startswith("GHSA-")


def fetch_text_for_ids(
    ids: Iterable[str],
    cache_path: str = "osv_text_cache.json",
    sleep: float = 0.05,
    max_fetch: Optional[int] = None,
    github_token: Optional[str] = None,
    verbose: bool = True,
) -> pd.DataFrame:
    cache_p = Path(cache_path)
    cache = _load_cache(cache_p)
    uniq = [str(i) for i in dict.fromkeys(ids) if str(i) not in ("", "nan", "None")]
    to_fetch = [i for i in uniq if i not in cache]
    if max_fetch is not None:
        to_fetch = to_fetch[:max_fetch]
    if verbose:
        print(f"[osv] {len(uniq)} unique ids | cached {len(uniq)-len(to_fetch)} | "
              f"to fetch {len(to_fetch)}"
              + (f" | GHSA fallback: ON" if github_token else " | GHSA fallback: OFF (no token)"))

    n_ok = n_fail = 0
    for k, osv_id in enumerate(to_fetch, 1):
        res = _fetch_osv(osv_id)
        # fallback to GHSA API when OSV fails and we have a token
        if not res["ok"] and github_token and _is_ghsa_id(osv_id):
            res = _fetch_ghsa(osv_id, github_token)
        cache[osv_id] = res
        n_ok += int(res["ok"]); n_fail += int(not res["ok"])
        if verbose and (k % 200 == 0 or k == len(to_fetch)):
            pct = n_ok / k * 100
            print(f"[osv] {k}/{len(to_fetch)} fetched — {n_ok} ok ({pct:.0f}%), {n_fail} failed")
            _save_cache(cache_p, cache)
        if res["ok"]:
            time.sleep(sleep)
    _save_cache(cache_p, cache)

    if to_fetch and n_ok == 0 and verbose:
        sample = next((v.get("error","?") for v in cache.values() if not v.get("ok")), "?")
        print(f"[osv] WARNING: 0 successful fetches. Sample error: '{sample}'")
        if not github_token:
            print("[osv] TIP: pass --github-token <PAT> to enable GHSA fallback.")

    rows = []
    for osv_id in uniq:
        c = cache.get(osv_id, {"summary": "", "details": "", "ok": False})
        rows.append({"osv_id": osv_id, "raw_summary": c.get("summary", ""),
                     "raw_details": c.get("details", ""), "fetch_ok": bool(c.get("ok"))})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    import sys
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "merged_trainable.csv"
    token    = sys.argv[2] if len(sys.argv) > 2 else None
    df = pd.read_csv(csv_path, low_memory=False)
    ids = df["osv_id"].dropna().tolist()
    out = fetch_text_for_ids(ids, github_token=token)
    print(f"fetch_ok rate: {out['fetch_ok'].mean():.2%}")
    print(out[out.fetch_ok].head(3)[["osv_id","raw_summary"]].to_string())