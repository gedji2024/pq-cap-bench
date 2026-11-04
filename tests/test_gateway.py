"""D6 gateway-side filtering and the forging power it requires."""

import pytest

from pqcap import devices as D
from pqcap import gateway as gw
from pqcap import model as M
from pqcap.config import CONFIG, load_yaml

DEVS = D.load_catalogue(CONFIG / "devices")
POL = load_yaml(CONFIG / "policies.yaml")
MODEL = load_yaml(CONFIG / "model.yaml")
CH = M.channels(load_yaml(CONFIG / "radio.yaml"), MODEL)
LC = lambda n, c: M.link_cost(n, c, MODEL["fragment_header_bytes"])  # noqa: E731


def test_in_bounds_and_mix():
    dev = next(d for d in DEVS if d.model == "EM410-RDL")
    full = gw.in_bounds_by_type(dev, D.full_policy(dev))
    assert all(i == n for i, n in full.values())
    tight = gw.in_bounds_by_type(dev, D.policy_for(dev, POL["levels"]["tight"]))
    assert tight["reboot"][0] == 0 and tight["set_reporting_interval"][0] == pytest.approx(0.01 * 1440, abs=1)
    for mix in ("uniform_payload", "uniform_type"):
        assert sum(gw.mix_weights(dev, mix).values()) == pytest.approx(1.0)
    with pytest.raises(ValueError):
        gw.mix_weights(dev, "bogus")


def test_filter_savings():
    f = gw.filter_savings(DEVS, POL, CH, 300, [10, 200], LC, ["uniform_type"])
    assert (f[f.policy == "loose"].saved_s_per_h == 0).all()                       # nothing to filter
    assert (f.saved_s_per_h <= f.carried_s_per_h + 1e-9).all() and (f.carried_s_per_h <= f.airtime_budget_s_per_h + 1e-9).all()
    eu = f[(f.region == "EU868") & (f.dr == 0) & (f.devices == 200) & (f.policy == "tight")]
    assert (eu.carried_s_per_h == eu.airtime_budget_s_per_h).all()                   # 1 % duty saturated by the flood
    assert ((eu.saved_share_of_budget > 0) & (eu.saved_share_of_budget <= 1)).all()     # share of the saturated budget
    t = f[f.policy == "tight"]
    assert (t.saved_s_per_h > 0).all()


def test_s4e_filtering_gateway_can_forge():
    a = load_yaml(CONFIG / "actions.yaml")
    fp = gw.forging_power(DEVS, POL, load_yaml(CONFIG / "threat.yaml"), a["invariants"],
                          {"alert_active": True, "battery_below_floor": False})
    s4e = fp[(fp.scheme == "S4-E") & (fp.compromise == "C1 + filtering gateway")]
    assert (s4e.accepted == s4e.catalogue).all()                                     # whole catalogue
    s6 = fp[fp.scheme == "S6"].pivot_table(index=["device", "policy"], columns="compromise", values="accepted")
    assert (s6["C1"] == s6["C1 + filtering gateway"]).all()                          # S6 gateway adds nothing
