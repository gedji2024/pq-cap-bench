"""F4: NWS flood-category parser and datum check."""

import json

import pytest

from pqcap import harm, nws
from pqcap.config import REPO_ROOT

D = REPO_ROOT / "data/nws"


def _g(cats):
    return {"lid": "XXXX1", "usgsId": "1", "name": "n", "flood": {"stageUnits": "ft", "categories": {
        k: {"stage": v, "flow": -9999} for k, v in cats.items()}}}


def test_parse_categories():
    c = nws.parse_categories(_g({"action": 17, "minor": 28, "moderate": 29.5, "major": -9999}))
    assert c["action"] == 17.0 and c["moderate"] == 29.5 and c["major"] is None and c["unit"] == "ft"
    real = nws.parse_categories(json.loads((D / "08074000.json").read_text()))
    assert real["lid"] == "BBST2" and real["minor"] is not None


def test_usgs_value_and_datum():
    u = {"value": {"timeSeries": [{"variable": {"noDataValue": -999999.0}, "values": [{"value": [
        {"value": "2.36", "dateTime": "2026-11-04T22:15:00.000-06:00"},
        {"value": "-999999", "dateTime": "2026-11-04T22:30:00.000-06:00"}]}]}]}}
    assert nws.usgs_value_at(u, "2026-11-05T04:15:00Z") == 2.36
    assert nws.usgs_value_at(u, "2026-11-05T04:30:00Z") is None            # noData
    assert nws.usgs_value_at({"value": {"timeSeries": []}}, "2026-11-05T04:15:00Z") is None
    ok = nws.datum_check({"usgs_response": u, "nws_valid_time": "2026-11-05T04:15:00Z", "nws_observed_stage": 2.5}, 0.5)
    assert ok["datum_ok"] and ok["abs_diff_ft"] == pytest.approx(0.14)
    bad = nws.datum_check({"usgs_response": u, "nws_valid_time": "2026-11-05T04:15:00Z", "nws_observed_stage": 3.0}, 0.5)
    assert not bad["datum_ok"]
    miss = nws.datum_check({"usgs_response": u, "nws_valid_time": "2026-11-05T05:15:00Z", "nws_observed_stage": 3.0}, 0.5)
    assert not miss["datum_ok"] and miss["abs_diff_ft"] is None


def test_load_committed_and_thresholds():
    r = nws.load(D, "08074000", 0.5)
    assert r["gauge_page"] == "https://water.noaa.gov/gauges/BBST2" and r["datum_ok"]
    th = harm.nws_thresholds(r, 30.48)
    assert th["alert_cm"] == round(r["action"] * 30.48)
    assert th["band_cm"] == (round((2 * r["action"] - r["minor"]) * 30.48), round(r["minor"] * 30.48))
    assert len(th["levels_cm"]) == len(th["level_names"]) and th["source"] == "NWS BBST2"
    assert harm.nws_thresholds({**r, "datum_ok": False}, 30.48) is None
    assert harm.nws_thresholds({**r, "action": None}, 30.48) is None


def test_run_uses_nws_thresholds():
    from pqcap.config import CONFIG, load_yaml
    h = {**load_yaml(CONFIG / "harm.yaml"), "workers": 1}
    a = load_yaml(CONFIG / "actions.yaml")
    evs = [{"name": "harvey", "file": h["series"]["file"], "start": "2017-08-27", "end": "2017-08-29", "usgs": "08074000"}]
    cfg = {**h, "events": evs, "events_rule": None, "events_prereg": None, "schemes": ["S6"], "compromises": ["C1"],
           "attacker": {"strategies": ["suppress"]}, "battery": {**h["battery"], "profiles": h["battery"]["profiles"][:1]}}
    df, _, meta = harm.run(cfg, a, REPO_ROOT)
    e = meta["events"][0]
    cats = nws.load(D, "08074000", 0.5)
    assert e["threshold_source"] == "NWS BBST2" and e["level_names"] == ["action", "minor", "moderate", "major"]
    assert e["alert_threshold_cm"] == round(cats["action"] * 30.48)
    assert e["levels_cm"][1] == pytest.approx(cats["minor"] * 30.48) and len(df) == 1


def test_section_f4(tmp_path):
    from pqcap.config import CONFIG
    from pqcap.report import section_f4
    md = section_f4(CONFIG)
    assert "**F4 - NWS flood categories**" in md and "BBST2" in md and "https://water.noaa.gov/gauges/BBST2" in md
    assert section_f4(tmp_path) == "_no NWS flood categories_"
