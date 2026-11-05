"""Fetch NWS flood categories (action, minor, moderate, major) for USGS gauges from the NWS National Water
Prediction Service (NWPS) and check that NWS stage and USGS gage height share a datum.

For each USGS site: GET https://api.water.noaa.gov/nwps/v1/gauges/<USGS id> (the API resolves the USGS id to
the NWS location id). Writes data/nws/<site>.json (raw response) and data/nws/<site>.meta.json (query URL,
human gauge page https://water.noaa.gov/gauges/<lid>, retrieval time UTC, SHA-256).

Datum check: the NWPS response carries the latest observed stage and its valid time; the USGS IV gage height
(00065) at the same time is fetched and stored as data/nws/<site>.datum.json. pqcap.nws.datum_ok compares them.

Usage: python scripts/fetch_nws.py SITE [SITE ...]
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

NWPS = "https://api.water.noaa.gov/nwps/v1/gauges/"
USGS = "https://waterservices.usgs.gov/nwis/iv/"
OUT = Path(__file__).resolve().parents[1] / "data" / "nws"


def _get(url: str) -> tuple[bytes, str, int]:
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read(), r.geturl(), r.status


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def fetch(site: str) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    url = NWPS + site
    body, final, status = _get(url)
    d = json.loads(body)
    (OUT / f"{site}.json").write_bytes(body)
    meta = {"query_url": url, "final_url": final, "http_status": status, "retrieved_utc": _now(),
            "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body), "usgs_site": site, "lid": d["lid"],
            "gauge_page": f"https://water.noaa.gov/gauges/{d['lid']}"}
    (OUT / f"{site}.meta.json").write_text(json.dumps(meta, indent=2))
    obs = d["status"]["observed"]
    # the legacy IV service returns no values for a startDT/endDT range ending now; period=P2D does
    uurl = f"{USGS}?format=json&sites={site}&period=P2D&parameterCd=00065&siteStatus=all"
    ub, _, ust = _get(uurl)
    (OUT / f"{site}.datum.json").write_text(json.dumps({
        "nws_valid_time": obs["validTime"], "nws_observed_stage": obs["primary"], "nws_unit": obs["primaryUnit"],
        "usgs_query_url": uurl, "usgs_http_status": ust, "usgs_sha256": hashlib.sha256(ub).hexdigest(),
        "retrieved_utc": _now(), "usgs_response": json.loads(ub)}, indent=1))
    return OUT / f"{site}.json"


if __name__ == "__main__":
    for s in sys.argv[1:]:
        print(fetch(s))
