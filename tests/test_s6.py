"""S6 pre-positioned envelopes: calm feasibility, crisis capacity, comparison, K4 (fixture sizes)."""

import pytest

from pqcap import kill
from pqcap import model as M
from pqcap import s6
from tests.test_model import FIX_KEM, FIX_SIG, cfgs  # noqa: F401


@pytest.fixture
def s6cfg(cfgs):  # noqa: F811
    token, radio, model = cfgs
    model["s6"] = {**model["s6"], "signers": ["PQ-A", "MISSING"],
                   "compare": [["S1", "PQ-A"], ["S4", "HMAC-SHA256-T16"]]}
    return token, radio, model


def test_sizes():
    assert s6.envelope_bytes({"h": 16, "b": 64, "i": 32}, 1000) == 1112
    assert s6.crisis_bytes({"a": 4, "b": 4, "c": 8}, 8) == 24


def test_s6_outputs(s6cfg):
    token, radio, model = s6cfg
    out = M.build(token, radio, model, FIX_SIG, FIX_KEM)
    calm, crisis, cmp_ = out["model_s6_calm"], out["model_s6_crisis"], out["model_s6_compare"]
    assert set(calm.signer) == {"PQ-A"}                                   # missing signer skipped
    r = calm[(calm.region == "US915") & (calm.dr == 8) & (calm.calm_hours == 6) & (calm.devices == 10)].iloc[0]
    assert r.envelope_bytes == 1112 and r.envelope_frames == 22 and r.downlink_opportunities == 72
    assert r.device_feasible and r.gateway_feasible and r.feasible
    assert r.gateway_utilisation == pytest.approx(10 * r.envelope_airtime_s / (6 * 3600))
    # EU868 DR0 at 1 % duty: 200 devices x long envelope cannot fit in 6 h
    e = calm[(calm.region == "EU868") & (calm.dr == 0) & (calm.calm_hours == 6) & (calm.devices == 200)].iloc[0]
    assert not e.gateway_feasible and not e.feasible
    assert e.max_devices_by_airtime == int(6 * 3600 * 0.01 // e.envelope_airtime_s)
    s6r = crisis[crisis.scheme == "S6"]
    assert set(s6r.cmd_bytes) == {24, 32} and s6r.fits_one_frame.all()
    c = crisis[(crisis.region == "US915") & (crisis.dr == 8) & (crisis.window_min == 30) & (crisis.devices == 50)]
    by = c.set_index(["scheme", "tag_bytes"])
    for t in (8, 16):                                                     # like-for-like tag lengths
        assert by.loc[("S6", t), "cmds_gateway"] == 50 * 6                # 6 opportunities x 50 devices, 1 frame
        assert by.loc[("S4c", t), "cmds_gateway"] == by.loc[("S6", t), "cmds_gateway"]
        assert by.loc[("S4", t), "cmd_bytes"] == 80 + t and by.loc[("S4", t), "frames"] == 2
        assert by.loc[("S4", t), "cmds_gateway"] == 50 * 3
    assert set(cmp_.scheme) == {"S6", "S4", "S4c", "S1"}
    assert set(cmp_.window_min) == set(model["s6"]["crisis_windows_min"])


def test_k4(s6cfg):
    token, radio, model = s6cfg
    out = M.build(token, radio, model, FIX_SIG, FIX_KEM)
    k = kill.k4(out)
    assert k["answer"] == "yes" and all(r["failing_drs"] == "-" for r in k["rows"])
    model["s6"] = {**model["s6"], "crisis_fields": {"params": 60}}         # 68-76 B > 53 B at DR8
    k = kill.k4(M.build(token, radio, model, FIX_SIG, FIX_KEM))
    assert k["answer"] == "no" and "DR8" in k["rows"][0]["failing_drs"]
    assert kill.k4({})["answer"] == "n/a"
