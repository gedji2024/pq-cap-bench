"""Harm replay: data loading, crossings, battery derivation, invariant behaviour (property tests), simulation."""

import json
import math

import numpy as np
import pandas as pd
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pqcap import envelope as ev
from pqcap import harm
from pqcap.config import CONFIG, REPO_ROOT, load_yaml

HCFG = {**load_yaml(CONFIG / "harm.yaml"), "workers": 1}   # coverage is measured in-process
ACFG = load_yaml(CONFIG / "actions.yaml")
CAT, ENV, FW = ev.catalogue_from_config(ACFG), ev.envelope_from_config(ACFG), ev.firmware_policy_from_config(ACFG)
INV = ev.invariants_from_config(ACFG)


from pqcap.devices import load_catalogue  # noqa: E402

DEVS = {d.model: d for d in load_catalogue(CONFIG / "devices")}
BATS = {p["name"]: harm.battery_from_profile(p, DEVS) for p in HCFG["battery"]["profiles"]}
LEVELS_FT = [10, 20, 30, 40]  # test-only absolute levels for the synthetic hydrographs


def _cfg(battery_profile="LWL01/poor", **over):
    c = {**HCFG, "_profile_inv": INV, "_battery": BATS[battery_profile]}
    for k, v in over.items():
        c[k] = {**c[k], **v}
    return c


def _hydrograph(peak_cm=900.0, minutes=2 * 1440, base=150.0):
    t = np.arange(minutes)
    return base + (peak_cm - base) * np.exp(-((t - minutes / 2) / (minutes / 8)) ** 2)


def test_load_series_and_gaps(tmp_path):
    raw = {"value": {"timeSeries": [{"variable": {"noDataValue": -999999.0}, "values": [{"value": [
        {"value": "1.0", "dateTime": "2017-08-26T00:00:00.000-05:00"},
        {"value": "-999999", "dateTime": "2017-08-26T00:15:00.000-05:00"},
        {"value": "2.0", "dateTime": "2017-08-26T02:00:00.000-05:00"}]}]}]}}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(raw))
    s = harm.load_series(p, 30.48)
    assert list(s.round(2)) == [30.48, 60.96]                       # noData dropped, ft -> cm
    assert harm.max_gap_min(s) == 120 and harm.gaps(s, 60)[0]["minutes"] == 120
    m = harm.to_minutes(s)
    assert m.size == 121 and m[60] == pytest.approx(45.72)          # linear interpolation


def test_cached_usgs_series_matches_meta():
    import hashlib
    f = REPO_ROOT / HCFG["series"]["file"]
    meta = json.loads(f.with_suffix(".meta.json").read_text())
    assert hashlib.sha256(f.read_bytes()).hexdigest() == meta["sha256"]
    assert meta["query_url"].startswith("https://waterservices.usgs.gov/nwis/iv/")
    s = harm.load_series(f, 30.48)
    assert s.size == 460 and s.max() == pytest.approx(41.90 * 30.48)


def test_crossings_and_score():
    stage = np.array([0, 5, 12, 12, 3, 15, 2.0])
    assert harm.crossings(stage, 10) == [(2, 3), (5, 5)]
    assert harm.crossings(np.array([11.0, 11.0]), 10) == [(0, 1)]
    sc = harm.score(stage, [(2, 12.0, 4), (5, 15.0, 50)], [10], tol_min=30)
    assert sc["crossings"] == 2 and sc["on_time"] == 1 and sc["delayed"] == 1 and sc["missed"] == 0
    sc = harm.score(stage, [], [10], 30)
    assert sc["missed"] == 2 and np.isnan(sc["mean_delay_min"])


def test_battery_profiles_from_manufacturer_data():
    from pqcap.radio import LoraPhy, time_on_air_s
    g, p = BATS["PS-LB/good"], BATS["PS-LB/poor"]
    assert g["capacity"] == 8500 and g["sleep_per_h"] == pytest.approx(0.005)          # 8500 mAh, 5 uA (manual)
    assert g["tx_mA"] == 82 and p["tx_mA"] == 125                                      # 14 / 20 dBm (manual)
    assert g["phy_payload_bytes"] == 9 + 13                                             # 9-B uplink + LoRaWAN framing
    assert g["uplink_toa_s"] == pytest.approx(time_on_air_s(22, LoraPhy(sf=7, bw_hz=125e3)))
    assert g["q"] == pytest.approx(82 * g["uplink_toa_s"] / 3600) and g["lower_bound"]
    assert BATS["LWL01/good"]["q"] == pytest.approx(1 / 12000) and BATS["LWL01/poor"]["q"] == pytest.approx(1 / 1300)
    with pytest.raises(ValueError):
        harm.battery_from_profile({"name": "x", "device": "LWL01", "model": "bogus"}, DEVS)


@settings(max_examples=300, deadline=None)
@given(interval=st.integers(1, 1440), alert=st.booleans(), soc=st.floats(0, 100))
def test_effective_interval_respects_invariants(interval, alert, soc):
    e = harm.effective_interval(interval, alert, soc, INV)
    low = soc < INV.battery_floor_pct
    if low:
        assert e >= INV.low_batt_min_interval                      # battery floor dominates
    elif alert:
        assert e <= INV.alert_max_interval
    else:
        assert e == interval
    assert harm.effective_interval(interval, alert, soc, ev.NO_INVARIANTS) == interval


@settings(max_examples=12, deadline=None)
@given(soc0=st.integers(5, 100), peak=st.floats(400, 1400), strategy=st.sampled_from(["drain", "suppress"]),
       scheme=st.sampled_from(["S4-F", "S4-E", "S6"]))
def test_bounded_schemes_never_violate_battery_floor_under_c1(soc0, peak, strategy, scheme):
    """Property: with invariants enforced below the agent, an attacker holding the session key cannot
    make the device uplink below the floor at a forbidden rate, nor kill it."""
    cfg = _cfg(battery={"initial_soc_pct": soc0})                  # LWL01/poor: the drain-sensitive profile
    r = harm.simulate(_hydrograph(peak), scheme, "C1", strategy, cfg, CAT, ENV, FW)
    assert r["stats"]["floor_violating_uplinks"] == 0 and r["stats"]["died_min"] is None


def test_s4_drain_kills_and_c1c3_matches_s4():
    stage = _hydrograph(1000, minutes=3 * 1440)
    s4 = harm.simulate(stage, "S4", "C1", "drain", _cfg(), CAT, ENV, FW)["stats"]
    assert s4["died_min"] is not None and s4["floor_violating_uplinks"] > 0
    s6 = harm.simulate(stage, "S6", "C1+C3", "drain", _cfg(), CAT, ENV, FW)["stats"]
    assert s6["died_min"] == s4["died_min"]                         # permissive envelope == S4
    f = harm.simulate(stage, "S4-F", "C1+C3", "drain", _cfg(), CAT, ENV, FW)["stats"]
    assert f["died_min"] is None                                    # firmware bounds survive C3


def test_suppress_and_legit():
    stage = _hydrograph(1000)
    lv = [x * 30.48 for x in LEVELS_FT]
    s4 = harm.simulate(stage, "S4", "C1", "suppress", _cfg(), CAT, ENV, FW)
    assert harm.score(stage, s4["delivered"], lv, 30)["missed"] == harm.score(stage, s4["delivered"], lv, 30)["crossings"]
    s6 = harm.simulate(stage, "S6", "C1", "suppress", _cfg(), CAT, ENV, FW)
    assert harm.score(stage, s6["delivered"], lv, 30)["missed"] == 0  # enable-only envelope keeps the sensor on
    leg = harm.simulate(stage, "S6", "none", None, _cfg(), CAT, ENV, FW)["stats"]
    assert leg["legit_sent"] > 0 and leg["attacker_sent"] == 0
    idle = harm.simulate(stage, "S6", "C1", None, _cfg(), CAT, ENV, FW)["stats"]
    assert idle["attacker_sent"] == 0 and idle["legit_sent"] == 0
    with pytest.raises(ValueError):
        harm.attacker_command("bogus", harm.Scheme("S6", CAT, ENV, FW, False), harm.Dev(60, 600), ev.DeviceState())


def test_legit_policy_rules():
    p = harm.LegitPolicy(HCFG["legit_policy"])
    assert p.command(60) is None                                    # no data yet
    p.observe([(0, 100.0), (60, 200.0)])                            # +100 cm/h rise
    assert p.command(60) == (ev.A_INTERVAL, HCFG["legit_policy"]["fast_interval_min"])
    q = harm.LegitPolicy(HCFG["legit_policy"])
    for k in range(5):
        q.observe([(k * 60, 100.0)])
    cmds = [q.command(10) for _ in range(3)]
    assert cmds[-1] == (ev.A_INTERVAL, HCFG["legit_policy"]["slow_interval_min"])
    assert q.command(HCFG["legit_policy"]["slow_interval_min"]) is None


def test_run_end_to_end():
    one = {**HCFG, "schemes": ["S4", "S6"], "compromises": ["none", "C1"], "attacker": {"strategies": ["drain"]},
           "battery": {**HCFG["battery"], "profiles": HCFG["battery"]["profiles"][-1:]}, "events": None,
           "events_rule": None, "events_prereg": None, "harm": {**HCFG["harm"], "reference_levels_ft": LEVELS_FT, "relative": None},
           "device": {**HCFG["device"], "alert_threshold_cm": 610}, "energy_budget": None}
    df, evs, meta = harm.run(one, ACFG, REPO_ROOT)
    assert len(df) == 2 * (len(HCFG["legit_policy"]["variants"]) + 1) and set(df.strategy) == {"-", "drain"}
    assert set(df.energy_budget) == {"off"} and df.epoch_budget_uplinks.isna().all()
    assert set(df[df.compromise == "none"].legit_policy) == set(HCFG["legit_policy"]["variants"])
    e = meta["events"][0]
    assert e["n_readings"] == 460 and len(e["gaps_over_60_min"]) >= 1 and e["peak_bracketed_by_gap"] is True                 # Harvey peak bracketed by 600- and 405-min gaps
    assert evs.level_cm.unique().size == len(LEVELS_FT)


def test_limit_aware_policy():
    p = harm.LegitPolicy(HCFG["legit_policy"], "limit_aware", 1, 1440)
    p.observe([(0, 100.0), (60, 200.0)])                              # rise -> wants the fast interval
    fast = HCFG["legit_policy"]["fast_interval_min"]
    assert p.command(60, lambda v: v == fast) == (ev.A_INTERVAL, fast)
    assert p.command(60, lambda v: v >= 30) == (ev.A_INTERVAL, 30)    # closest accepted value
    assert p.command(60, lambda v: False) is None                    # nothing acceptable -> no request
    assert p.command(30, lambda v: v >= 30) is None                   # already there
    naive = harm.LegitPolicy(HCFG["legit_policy"], "naive")
    naive.observe([(0, 100.0), (60, 200.0)])
    assert naive.command(60, lambda v: False) == (ev.A_INTERVAL, fast)
    with pytest.raises(ValueError):
        harm.LegitPolicy(HCFG["legit_policy"], "bogus")


def test_limit_aware_never_rejected_on_replay():
    stage = _hydrograph(1000)
    for scheme in ("S4-F", "S6"):
        st = harm.simulate(stage, scheme, "none", None, _cfg(), CAT, ENV, FW, "limit_aware")["stats"]
        assert st["legit_rejected"] == 0 and st["legit_intents"] > 0


def test_s6f_resists_suppress_without_op_key():
    stage = _hydrograph(1000)
    lv = [x * 30.48 for x in LEVELS_FT]
    f = harm.simulate(stage, "S4-F", "C1", "suppress", _cfg(), CAT, ENV, FW)
    sf = harm.simulate(stage, "S6+F", "C1+C3", "suppress", _cfg(), CAT, ENV, FW)
    op = harm.simulate(stage, "S6+F", "C1+C3+OP", "suppress", _cfg(), CAT, ENV, FW)
    sc = lambda r: harm.score(stage, r["delivered"], lv, 30)  # noqa: E731
    assert sc(f)["missed"] == sc(f)["crossings"] and sc(sf)["missed"] == 0
    assert sc(op)["missed"] == sc(op)["crossings"]                      # OP key compromised -> disable accepted
    assert harm.Scheme("S6", CAT, ENV, FW, False).floor == ev.NO_INVARIANTS


def test_event_window_and_fraction_levels():
    f = HCFG["series"]["file"]
    evs = [{"name": "w", "file": f, "start": "2017-08-27", "end": "2017-08-29"}]
    assert harm.event_list({"events": evs}) == evs
    assert harm.event_list({"series": {"file": f}})[0]["file"] == f
    stage, s = harm.event_stage(evs[0], HCFG, REPO_ROOT)
    assert str(s.index[0]) >= "2017-08-27" and str(s.index[-1]) <= "2017-08-29 00:00:00-05:00"
    cfg = {**HCFG, "events": evs, "events_rule": None, "events_prereg": None, "schemes": ["S6"], "compromises": ["C1"], "attacker": {"strategies": ["drain"]},
           "battery": {**HCFG["battery"], "profiles": HCFG["battery"]["profiles"][:1]},
           "harm": {**HCFG["harm"], "reference_levels_ft": None, "reference_level_fractions": [0.5]}}
    df, ev_, meta = harm.run(cfg, ACFG, REPO_ROOT)
    lv = meta["events"][0]["levels_cm"][0]
    assert lv == pytest.approx(stage.min() + 0.5 * (stage.max() - stage.min()))
    assert list(df.energy_budget) == ["off", "on"]                     # S6 is run with and without the G3 budget


# ---------------------------------------------------------------- D4
def test_select_events_rule():
    t = pd.date_range("2017-01-01", periods=60 * 24, freq="h", tz="UTC")
    v = np.zeros(t.size)
    v[[100, 105, 600, 1200]] = [9.0, 8.0, 7.0, 5.0]                    # 100/105 are within 14 days
    s = pd.Series(v, index=t)
    e = harm.select_events(s, 2, 14, 3)
    assert [x["peak"] for x in e] == [9.0, 7.0]
    assert e[0]["end"] - e[0]["start"] == pd.Timedelta(days=6)
    assert len(harm.select_events(s, 10, 14, 1)) == 3                  # no 4th time is >=14 d from days 4, 25, 50
    assert harm.select_events(s, 3, 14, 1)[2]["peak"] == 5.0


def test_d4_events_and_provenance():
    import hashlib
    rule = HCFG["superseded_events_rule"]
    evs = harm.event_list({**HCFG, "events_prereg": None, "events_rule": rule}, REPO_ROOT)
    assert len(evs) == len(rule["gauges"]) * rule["top_k"] >= 5 and len(rule["gauges"]) >= 3
    assert any("08074000" in e["name"] and "2017-08-28" in e["name"] for e in evs)          # Harvey selected
    for g in rule["gauges"]:
        f = REPO_ROOT / g["file"]
        m = json.loads(f.with_suffix(".meta.json").read_text())
        assert hashlib.sha256(f.read_bytes()).hexdigest() == m["sha256"] and m["query_url"].startswith("https://")


def test_relative_profile():
    stage = np.array([100.0, 300.0, 500.0])
    a, alert = harm.relative_profile(ACFG, stage, {"alert_fraction": 0.5, "envelope_band": [0.25, 0.75]})
    assert alert == 300
    r = a["envelope"]["rules"]["set_alert_threshold"]
    assert (r["lo"], r["hi"]) == (200, 400)
    fw = a["firmware_bounds"]["rules"]["set_alert_threshold"]
    assert (fw["lo"], fw["hi"]) == (ACFG["catalogue"]["set_alert_threshold"]["min"], ACFG["catalogue"]["set_alert_threshold"]["max"])
    assert ACFG["envelope"]["rules"]["set_alert_threshold"]["lo"] != 200                     # input not mutated


def test_bootstrap_and_summary():
    med, lo, hi = harm.bootstrap_ci(np.array([1.0, 2.0, 3.0, np.nan]), 2000, 1)
    assert med == 2.0 and 1.0 <= lo <= med <= hi <= 3.0
    assert harm.bootstrap_ci(np.array([3.0, 3.0]), 100, 1) == (3.0, 3.0, 3.0)
    assert all(math.isnan(x) for x in harm.bootstrap_ci(np.array([np.nan]), 10, 1))
    df = pd.DataFrame([{"event": f"e{i}", "battery_profile": "b", "scheme": "S6", "compromise": "C1",
                        "strategy": "drain", "legit_policy": "-", "crossings": 4, "missed": i % 2, "delayed": 1,
                        "max_delay_min": 10.0 * i, "floor_violating_uplinks": 0, "died": False,
                        "legit_unique_rejection_rate": 0.0} for i in range(5)])
    s = harm.summarize_events(df, 500, 7).iloc[0]
    assert s.events == 5 and s.missed_frac_median == 0.0 and s.delayed_frac_median == 0.25
    assert s.max_delay_min_ci_lo <= s.max_delay_min_median <= s.max_delay_min_ci_hi


# ---------------------------------------------------------------- F5
def test_select_events_above():
    idx = pd.date_range("2020-01-01", periods=24 * 20, freq="h", tz="UTC")
    v = np.zeros(len(idx))
    for h, x in ((24, 5), (30, 6), (24 * 10, 4), (24 * 10 + 80, 7)):   # two runs 6 h apart; two 80 h apart
        v[h] = x
    s = pd.Series(v, index=idx)
    e = harm.select_events_above(s, 3.0, 72, 5, 2)
    assert [x["peak"] for x in e] == [6.0, 4.0, 7.0]             # 5 (6 h from 6) merged; 4 and 7 are 80 h apart
    assert e[0]["end"] - e[0]["start"] == pd.Timedelta(days=7)
    assert harm.select_events_above(s, 100.0, 72, 5, 2) == []


def test_prereg_events_f5():
    import gzip
    import hashlib
    pr = load_yaml(CONFIG / "events_prereg.yaml")
    evs = harm.event_list(HCFG, REPO_ROOT)
    gauges = {e["usgs"] for e in evs}
    assert len(evs) >= 20 and len(gauges) >= 5 and "08074000" in gauges
    assert any(e["usgs"] == "08074000" and "2017-08-28" in e["name"] for e in evs)        # Harvey
    from pqcap import nws
    for g in gauges:
        minor = nws.load(REPO_ROOT / "data/nws", g, 0.5)["minor"] * HCFG["series"]["ft_to_cm"]
        mine = [e for e in evs if e["usgs"] == g]
        peaks = [pd.Timestamp(e["start"]) + pd.Timedelta(days=pr["rule"]["window"]["before_peak_d"]) for e in mine]
        assert all(abs((a - b).total_seconds()) >= 72 * 3600 for i, a in enumerate(peaks) for b in peaks[i + 1:])
        stage, _ = harm.event_stage(mine[0], HCFG, REPO_ROOT)
        assert stage.max() >= minor - 1e-6
    for f in sorted((REPO_ROOT / "data/usgs10").glob("*.json.gz"))[:3]:
        m = json.loads((f.parent / f.name.replace(".json.gz", ".meta.json")).read_text())
        assert hashlib.sha256(gzip.decompress(f.read_bytes())).hexdigest() == m["sha256"] and m["gzip"]


def test_parallel_run_matches_serial():
    evs = [{"name": "w", "file": HCFG["series"]["file"], "start": "2017-08-27", "end": "2017-08-28"},
           {"name": "x", "file": HCFG["series"]["file"], "start": "2017-08-28", "end": "2017-08-29"}]
    cfg = {**HCFG, "events": evs, "events_rule": None, "events_prereg": None, "schemes": ["S6"], "compromises": ["C1"],
           "attacker": {"strategies": ["drain"]}, "battery": {**HCFG["battery"], "profiles": HCFG["battery"]["profiles"][:1]}}
    a, _, _ = harm.run({**cfg, "workers": 1}, ACFG, REPO_ROOT)
    b, _, _ = harm.run({**cfg, "workers": 2}, ACFG, REPO_ROOT)
    pd.testing.assert_frame_equal(a, b)


def test_delay_distribution():
    ev = pd.DataFrame({"event": ["a", "a", "b", "c"], "battery_profile": "p", "scheme": "S", "compromise": "C1",
                       "strategy": "x", "legit_policy": "-", "delay_min": [0, 40, None, 10]})
    r = harm.delay_distribution(ev, 30, 2000, 1).iloc[0]
    assert r.crossings == 4 and r.missed == 1 and r.events == 3
    assert r.median_delay_min == 10 and r.p90_delay_min == np.inf and r.max_delay_min == np.inf
    assert r.late_or_missed_share == 0.5 and 0 <= r.late_or_missed_share_ci_lo <= 0.5 <= r.late_or_missed_share_ci_hi
    assert r.median_delay_min_ci_lo <= r.median_delay_min <= r.median_delay_min_ci_hi


def test_load_series_empty_and_gz(tmp_path):
    import gzip
    p = tmp_path / "e.json.gz"
    p.write_bytes(gzip.compress(json.dumps({"value": {"timeSeries": []}}).encode()))
    assert harm.load_series(p, 30.48).empty
    assert harm.load_series([p, p], 30.48).empty


def test_prereg_skips_gauge_without_data(tmp_path):
    import yaml
    pr = load_yaml(CONFIG / "events_prereg.yaml")
    pr["gauges"] = [{"usgs": "04174500", "site": "Huron (NWS data, no 10-year files)"}]
    p = tmp_path / "pr.yaml"
    p.write_text(yaml.safe_dump(pr))
    assert harm.prereg_events({**HCFG, "events_prereg": {"file": str(p), "data_dir": "data/usgs10"}}, REPO_ROOT) == []


def test_f3_commissioning_closes_c1c3_threshold_weakness():
    evs = [{"name": "harvey", "file": HCFG["series"]["file"], "start": "2017-08-26", "end": "2017-08-31", "usgs": "08074000"}]
    base = {**HCFG, "events": evs, "events_rule": None, "events_prereg": None, "schemes": ["S6+F"],
            "compromises": ["C1+C3"], "attacker": {"strategies": ["suppress"]},
            "battery": {**HCFG["battery"], "profiles": HCFG["battery"]["profiles"][:1]}}
    off, _, m0 = harm.run({**base, "commissioning": None}, ACFG, REPO_ROOT)
    on, _, m1 = harm.run(base, ACFG, REPO_ROOT)
    assert m0["events"][0]["commissioning_max_alert_threshold_cm"] == 0
    assert m1["events"][0]["commissioning_max_alert_threshold_cm"] == m1["events"][0]["alert_threshold_cm"] > 0
    assert off.iloc[0].delayed + off.iloc[0].missed > on.iloc[0].delayed + on.iloc[0].missed
    assert on.iloc[0].missed == 0
    sch = harm.Scheme("S6", harm.ev.catalogue_from_config(ACFG), harm.ev.envelope_from_config(ACFG),
                      harm.ev.firmware_policy_from_config(ACFG), False, max_alert_threshold=10)
    assert sch.floor == harm.ev.NO_INVARIANTS                     # only S6+F has the floor


def test_epoch_budget_g3():
    eb = HCFG["energy_budget"]
    b = BATS["LWL01/poor"]                 # 1,300 uplinks per battery (manual), SOC 60 -> floor 20 (ASSUMED)
    want = math.floor((60 - INV.battery_floor_pct) / 100 * 1300 / eb["horizon_d"] - 24 * 60 / 60)
    assert harm.epoch_budget(b, HCFG, INV.battery_floor_pct, eb) == want == 50
    assert harm.epoch_budget({**b, "capacity": 1e-6}, HCFG, INV.battery_floor_pct, eb) == 0


def test_energy_budget_curbs_drain_g3():
    stage = _hydrograph(1000, minutes=4 * 1440)
    lv = [x * 30.48 for x in LEVELS_FT]
    off = harm.simulate(stage, "S6", "C1", "drain", _cfg(), CAT, ENV, FW)
    on = harm.simulate(stage, "S6", "C1", "drain", _cfg(), CAT, ENV, FW, budget=20)
    assert on["stats"]["uplinks"] < off["stats"]["uplinks"] and on["stats"]["min_soc_pct"] > off["stats"]["min_soc_pct"]
    assert on["stats"]["budget_used"] <= 20 * 4 and on["stats"]["budget_denied_requests"] > 0
    so, sn = harm.score(stage, off["delivered"], lv, 30), harm.score(stage, on["delivered"], lv, 30)
    assert sn["missed"] + sn["delayed"] <= so["missed"] + so["delayed"]
    # budget 0: only the default schedule and firmware alert uplinks -> every crossing is still reported
    z = harm.simulate(stage, "S6", "C1", "drain", _cfg(), CAT, ENV, FW, budget=0)
    assert z["stats"]["budget_used"] == 0 and harm.score(stage, z["delivered"], lv, 30)["missed"] == 0


def test_energy_budget_rows_g3():
    evs = [{"name": "w", "file": HCFG["series"]["file"], "start": "2017-08-27", "end": "2017-08-29"}]
    cfg = {**HCFG, "events": evs, "events_rule": None, "events_prereg": None, "schemes": ["S4", "S6", "S6+F"],
           "compromises": ["C1", "C1+C3"], "attacker": {"strategies": ["drain"]},
           "battery": {**HCFG["battery"], "profiles": HCFG["battery"]["profiles"][-1:]}}
    df, _, meta = harm.run(cfg, ACFG, REPO_ROOT)
    assert set(df[df.scheme == "S4"].energy_budget) == {"off"}
    on = df[df.energy_budget == "on"].set_index(["scheme", "compromise"])
    assert on.loc[("S6", "C1"), "epoch_budget_uplinks"] == 50
    assert pd.isna(on.loc[("S6", "C1+C3"), "epoch_budget_uplinks"])      # envelope replaced: budget lost
    assert on.loc[("S6+F", "C1+C3"), "epoch_budget_uplinks"] == 50       # commissioning floor keeps it
    assert meta["battery_profiles"][0]["epoch_budget_uplinks"] == 50


def test_storm_clusters_g4():
    peaks = {"a": "2017-08-27T00:00Z", "b": "2017-08-29T12:00Z", "c": "2017-09-01T00:00Z", "d": "2018-01-01T00:00Z"}
    cl = harm.storm_clusters(peaks, 72)
    assert cl["a"] == cl["b"] == cl["c"] != cl["d"]                      # chained within 72 h -> one cluster
    assert len(set(harm.storm_clusters(peaks, 24).values())) == 4


def test_delay_distribution_clusters_and_excess_g4():
    base = {"battery_profile": "p", "scheme": "S", "strategy": "-", "level_cm": 1.0}
    rows = []
    for e, cm in (("a", 0), ("b", 0), ("c", 0)):
        rows.append({**base, "event": e, "compromise": "none", "legit_policy": "naive", "cross_min": cm,
                     "delay_min": 5 if e != "c" else None})
        rows.append({**base, "event": e, "compromise": "C1", "strategy": "drain", "legit_policy": "-",
                     "cross_min": cm, "delay_min": 100 if e == "a" else (5 if e == "b" else None)})
    ev_ = pd.DataFrame(rows)
    cl = {"a": 0, "b": 0, "c": 1}
    d = harm.delay_distribution(ev_, 30, 500, 1, clusters=cl).set_index("compromise")
    assert d.loc["C1", "resampling_units"] == 2 and d.loc["C1", "events"] == 3
    assert harm.delay_distribution(ev_, 30, 50, 1).iloc[0].resampling_units == 3
    x = harm.excess_over_baseline(ev_, 30, 500, 1, clusters=cl).iloc[0]
    # baseline misses c (counted as baseline); the attack adds only a
    assert x.baseline_share == pytest.approx(1 / 3) and x.attack_share == pytest.approx(2 / 3)
    assert x.excess == pytest.approx(1 / 3) and x.excess_ci_lo <= x.excess <= x.excess_ci_hi
    assert x.resampling_units == 2
    # no baseline rows -> no excess row
    assert harm.excess_over_baseline(ev_[ev_.compromise != "none"], 30, 50, 1).empty


def test_simulate_init_config():
    stage = _hydrograph(1000)
    lv = [x * 30.48 for x in LEVELS_FT]
    off = harm.simulate(stage, "S4", "C1", None, _cfg(), CAT, ENV, FW, init={"enabled": False})
    sc = harm.score(stage, off["delivered"], lv, 30)
    assert sc["missed"] == sc["crossings"] > 0
    slow = harm.simulate(stage, "S4", "C1", None, _cfg(), CAT, ENV, FW, init={"interval": 1440, "threshold": 1500,
                                                                             "soc_pct": 50})
    base = harm.simulate(stage, "S4", "C1", None, _cfg(), CAT, ENV, FW)
    assert slow["stats"]["uplinks"] < base["stats"]["uplinks"]


def test_budget_sweep_h2():
    evs = [{"name": "w", "file": HCFG["series"]["file"], "start": "2017-08-27", "end": "2017-08-29"},
           {"name": "v", "file": HCFG["series"]["file"], "start": "2017-08-30", "end": "2017-09-01"}]
    sw = {"values_per_epoch": [None, 0, 50], "battery_profile": "LWL01/poor", "scheme": "S6+F", "compromise": "C1",
          "strategy": "drain"}
    cfg = {**HCFG, "events": evs, "events_rule": None, "events_prereg": None, "workers": 1,
           "statistics": {**HCFG["statistics"], "bootstrap": 50},
           "energy_budget": {**HCFG["energy_budget"], "sweep": sw}}
    t, fl = harm.budget_sweep(cfg, ACFG, REPO_ROOT, {"w": 0, "v": 1})
    assert len(t) == 3 and (t.initial_soc_pct == HCFG["battery"]["initial_soc_pct"]).all()
    assert (t.derived_budget == 50).all() and len(fl) == 2 * 3 * 2
    ft = harm.floor_timing(fl, [None, 0, 50]).set_index("events_reaching_floor", drop=False)
    assert list(ft.events) == [2, 2, 2]
    assert ft.events_reaching_floor.max() >= 1 and ft.earliest_event.notna().any()       # no budget: drained
    assert harm.floor_timing(fl, [0]).events_reaching_floor.iloc[0] == 0                 # budget 0: never
    lo, _ = harm.budget_sweep(cfg, ACFG, REPO_ROOT, {"w": 0, "v": 1}, soc_pct=40)
    assert (lo.derived_budget < 50).all() and (lo.initial_soc_pct == 40).all()
    sens = harm.soc_sensitivity(pd.concat([t, lo]), 0.10).set_index("initial_soc_pct")
    assert sens.loc[60, "derived_budget"] == 50 and sens.loc[40, "derived_budget"] < 50
    none = harm.soc_sensitivity(t.assign(excess=0.0), 0.10).iloc[0]
    assert pd.isna(none.smallest_budget_excess_over) and none.largest_budget_at_or_below == 50
    allover = harm.soc_sensitivity(t.assign(excess=1.0), 0.10).iloc[0]
    assert allover.smallest_budget_excess_over == 0 and pd.isna(allover.largest_budget_at_or_below)
    assert (t.legit_resampling_units == 2).all() and (t.scheme == "S6+F").all() and (t.epoch_h == 24).all()
    off = t[t.budget_per_epoch.isna()].iloc[0]
    zero = t[t.budget_per_epoch == 0].iloc[0]
    assert zero.excess <= off.excess                                     # no command-caused uplinks: no drain
    for c in ("legit_p90_delay_min", "excess"):
        assert (t[f"{c}_ci_lo"] <= t[c] + 1e-9).all() and (t[c] <= t[f"{c}_ci_hi"] + 1e-9).all()
    a, _ = harm.budget_sweep({**cfg, "workers": 2}, ACFG, REPO_ROOT, {"w": 0, "v": 1})
    pd.testing.assert_frame_equal(a, t)


def test_f3_ablation_clusters():
    evs = [{"name": "w", "file": HCFG["series"]["file"], "start": "2017-08-27", "end": "2017-08-29", "usgs": "08074000"}]
    cfg = {**HCFG, "events": evs, "events_rule": None, "events_prereg": None, "workers": 1,
           "compromises": ["none", "C1+C3"], "statistics": {**HCFG["statistics"], "bootstrap": 50}}
    t = harm.f3_ablation(cfg, ACFG, REPO_ROOT, {"w": 0})
    assert set(t.commissioning_bound) == {"with bound", "without bound"} and (t.scheme == "S6+F").all()
    k = t.set_index(["commissioning_bound", "compromise"])
    assert k.loc[("with bound", "C1+C3"), "late_or_missed_share"] <= k.loc[("without bound", "C1+C3"),
                                                                           "late_or_missed_share"]
    assert pd.isna(k.loc[("with bound", "none"), "excess"]) and (t.resampling_units == 1).all()
