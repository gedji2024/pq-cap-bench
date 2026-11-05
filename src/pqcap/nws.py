"""F4: NWS flood categories (NWPS API responses cached in data/nws/) and the NWS-vs-USGS datum check."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

CATEGORIES = ("action", "minor", "moderate", "major")
MISSING = -9999


def parse_categories(d: dict) -> dict:
    """NWPS gauge JSON -> {lid, name, unit, action, minor, moderate, major} (None where NWS gives none)."""
    f = d["flood"]
    cats = {k: (None if f["categories"][k]["stage"] in (MISSING, None) else float(f["categories"][k]["stage"]))
            for k in CATEGORIES}
    return {"lid": d["lid"], "usgs_site": d.get("usgsId"), "name": d["name"], "unit": f["stageUnits"], **cats}


def usgs_value_at(usgs: dict, when: str) -> float | None:
    """USGS IV gage height (ft) at exactly `when` (ISO, UTC), or None if that reading is absent."""
    t = dt.datetime.fromisoformat(when.replace("Z", "+00:00"))
    ts = usgs["value"]["timeSeries"]
    if not ts:
        return None
    nod = float(ts[0]["variable"]["noDataValue"])
    for v in ts[0]["values"][0]["value"]:
        if dt.datetime.fromisoformat(v["dateTime"]) == t and float(v["value"]) != nod:
            return float(v["value"])
    return None


def datum_check(datum: dict, tol_ft: float) -> dict:
    u = usgs_value_at(datum["usgs_response"], datum["nws_valid_time"])
    n = float(datum["nws_observed_stage"])
    diff = None if u is None else abs(u - n)
    return {"nws_stage_ft": n, "usgs_gage_height_ft": u, "abs_diff_ft": diff,
            "datum_ok": diff is not None and diff <= tol_ft, "valid_time": datum["nws_valid_time"]}


def load(directory: Path, site: str, tol_ft: float) -> dict:
    """Categories + source metadata + datum check for one USGS site."""
    d = Path(directory)
    cats = parse_categories(json.loads((d / f"{site}.json").read_text()))
    meta = json.loads((d / f"{site}.meta.json").read_text())
    dc = datum_check(json.loads((d / f"{site}.datum.json").read_text()), tol_ft)
    return {**cats, **{k: meta[k] for k in ("query_url", "gauge_page", "retrieved_utc", "sha256")}, **dc}
