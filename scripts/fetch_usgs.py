"""Fetch a USGS NWIS instantaneous-values series and cache the raw JSON in data/.

Writes data/<stem>.json (raw response, unmodified) and data/<stem>.meta.json
(query URL, final URL after redirects, HTTP status, retrieval time UTC, SHA-256).

Usage: python scripts/fetch_usgs.py SITE PARAM START END
       e.g. python scripts/fetch_usgs.py 08074000 00065 2017-08-26 2017-08-31
       python scripts/fetch_usgs.py --years SITE PARAM FIRST_YEAR LAST_YEAR   (F5: one gzipped file per year in
       data/usgs10/; the SHA-256 in the meta file is that of the raw, uncompressed response)
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

BASE = "https://waterservices.usgs.gov/nwis/iv/"
DATA = Path(__file__).resolve().parents[1] / "data"


def fetch(site: str, param: str, start: str, end: str, out: Path = DATA, gz: bool = False) -> Path:
    url = f"{BASE}?format=json&sites={site}&startDT={start}&endDT={end}&parameterCd={param}&siteStatus=all"
    with urllib.request.urlopen(url, timeout=300) as r:  # follows the 301 to nwis.waterservices.usgs.gov
        body, final, status = r.read(), r.geturl(), r.status
    out.mkdir(parents=True, exist_ok=True)
    stem = f"usgs_{site}_{param}_{start}_{end}"
    path = out / (f"{stem}.json.gz" if gz else f"{stem}.json")
    path.write_bytes(gzip.compress(body, mtime=0) if gz else body)
    meta = {"query_url": url, "final_url": final, "http_status": status,
            "retrieved_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body), "gzip": gz,
            "site": site, "parameter_cd": param, "start": start, "end": end}
    (out / f"{stem}.meta.json").write_text(json.dumps(meta, indent=2))
    return path


if __name__ == "__main__":
    if sys.argv[1] == "--years":
        site, param, y0, y1 = sys.argv[2:6]
        for y in range(int(y0), int(y1) + 1):
            print(fetch(site, param, f"{y}-01-01", f"{y}-12-31", DATA / "usgs10", gz=True))
    else:
        print(fetch(*sys.argv[1:5]))
