"""Manufacturer catalogue parser, provenance checks and policy-swept blast radius."""

import itertools
import json
import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pqcap import devices as D
from pqcap.config import CONFIG, REPO_ROOT, load_yaml

DEVS = D.load_catalogue(CONFIG / "devices")
BY = {d.model: d for d in DEVS}
STATE = {"alert_active": True, "battery_below_floor": False}


def test_catalogue_contents_from_manuals():
    assert set(BY) == {"EM400-UDL", "EM410-RDL", "PS-LB", "LWL01"}
    assert BY["EM400-UDL"].fport == 85 and BY["EM410-RDL"].fport == 85
    assert BY["PS-LB"].fport is None and BY["LWL01"].fport is None            # NOT FOUND in the manuals
    ri = BY["EM410-RDL"].action("set_reporting_interval")
    assert (ri.payload_bytes, ri.dims[0].lo, ri.dims[0].hi, ri.dims[0].unit, ri.default) == (5, 1, 1440, "min", 1440)
    assert BY["EM400-UDL"].action("set_reporting_interval").dims[0].range_source == "app_setting"
    assert BY["LWL01"].action("set_reporting_interval").dims[0].range_source == "encoding"
    assert BY["LWL01"].action("alarm_disable").payload_bytes == 2
    assert BY["PS-LB"].battery["capacity_mAh"]["value"] == 8500
    assert {u["value"] for u in BY["LWL01"].battery["uplinks_per_battery"]} == {12000, 1300}
    for d in DEVS:
        for a in d.actions:
            assert a.action in {"set_reporting_interval", "set_collect_interval", "set_alarm_threshold",
                                "alarm_enable", "alarm_disable", "set_adr", "set_dr", "reboot"}


def test_every_document_and_quote_verified():
    v = json.loads((REPO_ROOT / "data/devices/verification.json").read_text())
    assert set(v["devices"]) == {"em400-udl", "em410-rdl", "ps-lb", "lwl01"}
    for dev, r in v["devices"].items():
        y = load_yaml(CONFIG / "devices" / f"{dev}.yaml")
        assert all(x["sha256_match"] for x in r["docs"].values())
        assert {k: x["sha256"] for k, x in r["docs"].items()} == {k: d["sha256"] for k, d in y["docs"].items()}
        assert r["quotes"] and all(q["found"] for q in r["quotes"])


def test_loader_errors(tmp_path):
    base = {"device": {"manufacturer": "m", "model": "x"}, "docs": {}, "downlink_fport": {"value": None},
            "actions": [{"action": "reboot", "command": "00", "payload_bytes": 2, "dims": []}]}
    p = tmp_path / "x.yaml"
    p.write_text(json.dumps(base))
    assert D.load_device(p).action("reboot").payload_bytes == 2 and D.load_device(p).action("nope") is None
    bad = json.loads(json.dumps(base))
    bad["actions"][0]["dims"] = [{"name": "v", "unit": "s", "min": 5, "max": 1, "range_source": "encoding"}]
    p.write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="min > max"):
        D.load_device(p)
    bad["actions"][0]["dims"] = [{"name": "v", "unit": "s", "min": None, "max": 1, "range_source": "encoding"}]
    p.write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="integer"):
        D.load_device(p)


def test_window_and_policy():
    d = D.Dim("i", "min", 1, 1440, "downlink_table")
    assert D.window(d, 1.0, 1440) == (1, 1440)
    lo, hi = D.window(d, 0.01, 1440)
    assert hi == 1440 and hi - lo + 1 == math.ceil(0.01 * 1440)              # clipped at the top
    assert D.window(D.Dim("m", "enum", 1, 5, "x"), 0.1, None) == (1, 1)
    lv = load_yaml(CONFIG / "policies.yaml")["levels"]
    tight = D.policy_for(BY["LWL01"], lv["tight"])
    assert set(tight) == {"set_reporting_interval"}
    assert set(D.policy_for(BY["PS-LB"], lv["loose"])) == {a.action for a in BY["PS-LB"].actions}


def _brute(ctx, a, state):
    rng = [range(d.lo, d.hi + 1) for d in a.dims]
    return sum(D.accepts(ctx, a, v, state) for v in itertools.product(*rng)) if a.dims else int(D.accepts(ctx, a, (), state))


@settings(max_examples=150, deadline=None)
@given(data=st.data(), unit=st.sampled_from(["s", "min"]), alert=st.booleans(), low=st.booleans(),
       key=st.booleans(), has_pol=st.booleans())
def test_cell_count_equals_brute_force(data, unit, alert, low, key, has_pol):
    def dim(name):
        lo = data.draw(st.integers(0, 40))
        return D.Dim(name, unit, lo, lo + data.draw(st.integers(0, 30)), "encoding")
    a = D.DevAction(data.draw(st.sampled_from(["set_reporting_interval", "set_alarm_threshold"])), "x", 4,
                    (dim("a"), dim("b")), None)
    box = tuple((lo := data.draw(st.integers(d.lo - 3, d.hi + 3)), lo + data.draw(st.integers(0, 20))) for d in a.dims)
    inv = {"alert_max_interval_min": data.draw(st.integers(0, 2)), "low_battery_min_interval_min": data.draw(st.integers(0, 2))}
    ctx = D.Context(key, {a.action: box} if has_pol else None, inv)
    st_ = {"alert_active": alert, "battery_below_floor": low}
    assert D.count_accepted(ctx, a, st_) == _brute(ctx, a, st_)


def test_context_rules():
    a = BY["LWL01"].action("alarm_disable")
    assert D.count_accepted(D.Context(True, None, None), a, STATE) == 1
    assert D.count_accepted(D.Context(False, None, None), a, STATE) == 0
    inv = {"alert_forbid_disable": True}
    assert D.count_accepted(D.Context(True, None, inv), a, STATE) == 0
    assert D.count_accepted(D.Context(True, None, None, op_required=("alarm_disable",)), a, STATE) == 0
    assert D.count_accepted(D.Context(True, None, None, op_required=("alarm_disable",), has_op_token=True), a, STATE) == 1
    r = BY["EM410-RDL"].action("set_reporting_interval")
    assert D.count_accepted(D.Context(True, None, None, floor={"alert_max_interval_min": 15}), r, STATE) == 15
    assert D.count_accepted(D.Context(True, None, None, pdp_policy={}), r, STATE) == 0


def test_catalogue_sweep_ranges():
    df, k5, k6 = D.run(CONFIG)
    assert len(df) == 4 * 3 * len(load_yaml(CONFIG / "threat.yaml")["compromises"]) * len(D.SCHEMES)
    s4 = df[df.scheme == "S4"].set_index(["device", "policy", "compromise"]).accepted
    s4c = df[df.scheme == "S4c"].set_index(["device", "policy", "compromise"]).accepted
    assert (s4 == s4c).all()
    c1 = df[df.compromise == "C1"]
    assert (c1[c1.scheme == "S4"].fraction == 1).all()
    e, s = (c1[c1.scheme == x].set_index(["device", "policy"]).accepted for x in ("S4-E", "S6"))
    assert (e == s).all()                                                        # K6 = 1 under C1, every case
    r = k6.set_index("compromise")
    assert r.loc["C4", "ratio_max"] > 1 and r.loc["C2", "both_zero_cases"] == r.loc["C2", "cases"]
    assert set(k5.columns) >= {"fraction_min", "fraction_max", "type_coverage_min", "type_coverage_max"}


def test_accepts_domain_and_low_battery():
    r = BY["EM410-RDL"].action("set_reporting_interval")
    ctx = D.Context(True, None, {"low_battery_min_interval_min": 120})
    low = {"alert_active": False, "battery_below_floor": True}
    assert not D.accepts(ctx, r, (0,), low) and not D.accepts(ctx, r, (1441,), low)   # outside documented range
    assert not D.accepts(ctx, r, (119,), low) and D.accepts(ctx, r, (120,), low)
    assert D.count_accepted(ctx, r, low) == 1440 - 120 + 1
