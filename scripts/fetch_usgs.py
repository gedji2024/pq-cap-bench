"""Fetch a USGS NWIS instantaneous-values series and cache the raw JSON in data/.

Writes data/<stem>.json (raw response, unmodified) and data/<stem>.meta.json
(query URL, final URL after redirects, HTTP status, retrieval time UTC, SHA-256).

Usage: python scripts/fetch_usgs.py SITE PARAM START END
       e.g. python scripts/fetch_usgs.py 08074000 00065 2017-08-26 2017-08-31
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

BASE = "https://waterservices.usgs.gov/nwis/iv/"
DATA = Path(__file__).resolve().parents[1] / "data"


def fetch(site: str, param: str, start: str, end: str) -> Path:
    url = f"{BASE}?format=json&sites={site}&startDT={start}&endDT={end}&parameterCd={param}&siteStatus=all"
    with urllib.request.urlopen(url, timeout=120) as r:  # follows the 301 to nwis.waterservices.usgs.gov
        body, final, status = r.read(), r.geturl(), r.status
    DATA.mkdir(exist_ok=True)
    stem = f"usgs_{site}_{param}_{start}_{end}"
    (DATA / f"{stem}.json").write_bytes(body)
    meta = {"query_url": url, "final_url": final, "http_status": status,
            "retrieved_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
            "site": site, "parameter_cd": param, "start": start, "end": end}
    (DATA / f"{stem}.meta.json").write_text(json.dumps(meta, indent=2))
    return DATA / f"{stem}.json"


if __name__ == "__main__":
    print(fetch(*sys.argv[1:5]))
