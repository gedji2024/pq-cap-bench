"""Harm replay: data loading, crossings, battery derivation, invariant behaviour (property tests), simulation."""

import json

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pqcap import envelope as ev
from pqcap import harm
from pqcap.config import CONFIG, REPO_ROOT, load_yaml

HCFG = load_yaml(CONFIG / "harm.yaml")
ACFG = load_yaml(CONFIG / "actions.yaml")
CAT, ENV, FW = ev.catalogue_from_config(ACFG), ev.envelope_from_config(ACFG), ev.firmware_policy_from_config(ACFG)
INV = ev.invariants_from_config(ACFG)


def _cfg(**over):
    c = {**HCFG, "_profile_inv": INV}
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


def test_uplink_charge_derivation():
    b = HCFG["battery"]
    q = harm.uplink_charge_mAh(b)
    n = 7 * 24 * 60 / b["week_drain_uplink_period_min"]
    assert q * n + b["sleep_current_mA"] * 168 == pytest.approx(b["capacity_mAh"])   # empties in exactly a week


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
    cfg = _cfg(battery={"initial_soc_pct": soc0})
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
    lv = [x * 30.48 for x in HCFG["harm"]["reference_levels_ft"]]
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
    df, evs, meta = harm.run({**HCFG, "schemes": ["S4", "S6"], "compromises": ["none", "C1"],
                              "attacker": {"strategies": ["drain"]}}, ACFG, REPO_ROOT)
    assert len(df) == 2 * (len(HCFG["legit_policy"]["variants"]) + 1) and set(df.strategy) == {"-", "drain"}
    assert set(df[df.compromise == "none"].legit_policy) == set(HCFG["legit_policy"]["variants"])
    assert meta["n_readings"] == 460 and len(meta["gaps_over_60_min"]) >= 1
    assert (evs.level_cm.unique().size == len(HCFG["harm"]["reference_levels_ft"]))


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
    lv = [x * 30.48 for x in HCFG["harm"]["reference_levels_ft"]]
    f = harm.simulate(stage, "S4-F", "C1", "suppress", _cfg(), CAT, ENV, FW)
    sf = harm.simulate(stage, "S6+F", "C1+C3", "suppress", _cfg(), CAT, ENV, FW)
    op = harm.simulate(stage, "S6+F", "C1+C3+OP", "suppress", _cfg(), CAT, ENV, FW)
    sc = lambda r: harm.score(stage, r["delivered"], lv, 30)  # noqa: E731
    assert sc(f)["missed"] == sc(f)["crossings"] and sc(sf)["missed"] == 0
    assert sc(op)["missed"] == sc(op)["crossings"]                      # OP key compromised -> disable accepted
    assert harm.Scheme("S6", CAT, ENV, FW, False).floor == ev.NO_INVARIANTS
