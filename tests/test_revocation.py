"""Envelope validity cap (property test), exposure windows and renewal cost."""

import hashlib
import hmac
import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pqcap import envelope as ev
from pqcap import model as M
from pqcap import revocation as rv
from pqcap.config import CONFIG, load_yaml

ACFG = load_yaml(CONFIG / "actions.yaml")
KEY = b"p" * 32


@settings(max_examples=300, deadline=None)
@given(nb=st.integers(0, 2**31), length=st.integers(0, 2**31 - 1), cap=st.integers(0, 7 * 86400))  # u32 fields
def test_no_installed_envelope_exceeds_validity_cap(nb, length, cap):
    env = ev.envelope_from_config(ACFG, nb, nb + length)
    blob = ev.encode_envelope(env)
    got = ev.install_envelope_s4e(blob, hmac.new(KEY, blob, hashlib.sha256).digest(), KEY, cap)
    assert (got is not None) == (length <= cap)
    if got is not None:
        assert got.not_after - got.not_before <= cap
    got6 = ev.install_envelope_s6(blob, b"sig", lambda b, s: True, cap)
    assert (got6 is not None) == (length <= cap)


def test_install_rejections():
    blob = ev.encode_envelope(ev.envelope_from_config(ACFG, 0, 10))
    assert ev.install_envelope_s6(blob, b"x", lambda b, s: False) is None
    assert ev.validity_ok(ev.envelope_from_config(ACFG, 10, 5), None) is False
    assert ev.validity_ok(ev.envelope_from_config(ACFG, 0, 10), None) is True


def test_push_time():
    # per-device bound: 3 frames x 300 s + 1 s + last ToA; gateway bound: N x airtime / duty
    assert rv.push_time_s(3, 1.0, 0.5, 10, 300, None) == pytest.approx(901.5)
    assert rv.push_time_s(1, 10.0, 0.5, 200, 300, 0.01) == pytest.approx(200 * 10 / 0.01)


@pytest.fixture
def chans_lc():
    radio, model = load_yaml(CONFIG / "radio.yaml"), load_yaml(CONFIG / "model.yaml")
    return M.channels(radio, model), (lambda n, ch: M.link_cost(n, ch, 2)), model


def test_exposure_and_renewal(chans_lc):
    chans, lc, model = chans_lc
    cfg = {"validity_hours": [6, 24], "devices": [10, 50], "active_push": True}
    e = rv.exposure(chans, {"S4-E": 144, "S6": 1112}, cfg, 300, lc)
    assert math.isinf(e[(e.scheme == "S4") & (e.validity_h == 6)].exposure_worst_h.iloc[0])
    pas = e[(e.scheme == "S6") & (e.mechanism == "passive expiry") & (e.validity_h == 24)].iloc[0]
    assert pas.exposure_worst_h == 24 and pas.exposure_expected_h == 12
    push = e[e.mechanism == "active push"]
    assert (push.exposure_worst_h <= push.validity_h).all()
    a = push[(push.scheme == "S6") & (push.region == "US915") & (push.dr == 8) & (push.devices == 10)].iloc[0]
    assert a.envelope_frames == 22 and a.push_time_h == pytest.approx((22 * 300 + 1 + 0) / 3600, abs=0.01)
    assert rv.exposure(chans, {"S6": 1112}, {**cfg, "active_push": False}, 300, lc).mechanism.ne("active push").all()
    r = rv.renewal_cost(chans, {"S4-E": 144, "S6": 1112}, cfg, 300, lc)
    x = r[(r.scheme == "S6") & (r.region == "EU868") & (r.dr == 0) & (r.validity_h == 6) & (r.devices == 50)].iloc[0]
    assert x.gateway_utilisation == pytest.approx(50 * x.airtime_per_renewal_s * 4 / (86400 * 0.01))
    assert x.feasible == (x.gateway_utilisation <= 1 and x.device_downlink_share <= 1)
    y = r[(r.scheme == "S4-E") & (r.region == "US915") & (r.dr == 13)]
    assert y.feasible.all()


# ---------------------------------------------------------------- D1: S6-R
CAT = ev.catalogue_from_config(ACFG)
ENV = ev.envelope_from_config(ACFG)
HK = b"s" * 32


@settings(max_examples=300, deadline=None)
@given(r=st.binary(min_size=16, max_size=16) | st.binary(min_size=32, max_size=32),
       aid=st.integers(0, 255), value=st.integers(-(2**31), 2**31 - 1), ctr=st.integers(1, 2**32 - 1))
def test_no_command_accepted_after_revocation(r, aid, value, ctr):
    commits = {ENV.handle: ev.rev_commitment(r)}
    dec, s = ev.apply_revocation(commits, ev.DeviceState(0), ev.make_revocation(ENV.handle, r))
    assert dec.accepted and ENV.handle in s.revoked
    msg = ev.make_command(HK, ENV.handle, ctr, aid, 0, value, 8)
    assert not ev.check_s6(ENV, CAT, s, msg, HK, 8)[0].accepted


@settings(max_examples=200, deadline=None)
@given(r=st.binary(min_size=32, max_size=32), wrong=st.binary(min_size=32, max_size=32))
def test_wrong_reveal_does_not_revoke(r, wrong):
    commits = {ENV.handle: ev.rev_commitment(r)}
    dec, s = ev.apply_revocation(commits, ev.DeviceState(0), ev.make_revocation(ENV.handle, wrong))
    assert dec.accepted == (wrong == r) and (ENV.handle in s.revoked) == (wrong == r)


def test_revocation_message_format():
    r = bytes(16)
    assert len(ev.make_revocation(1, r)) == 20 and len(ev.make_revocation(1, bytes(32))) == 36
    with pytest.raises(ValueError):
        ev.make_revocation(1, bytes(8))
    assert ev.apply_revocation({}, ev.DeviceState(), b"\0" * 7)[0].reason == "length"
    assert ev.apply_revocation({}, ev.DeviceState(), ev.make_revocation(9, r))[0].reason == "bad_reveal"
    s = ev.DeviceState(0, revoked=frozenset({ENV.handle}))
    assert ev.check_s6(ENV, CAT, s, ev.make_command(HK, ENV.handle, 1, 1, 0, 10, 8), HK, 8)[0].reason == "revoked"


def test_s6r_push_is_one_frame(chans_lc):
    chans, lc, _ = chans_lc
    cfg = {"validity_hours": [6], "devices": [50], "active_push": True}
    e = rv.exposure(chans, {"S6": 2532, "S6-R": 2564}, cfg, 300, lc, {"S6-R": [20, 36]})
    r = e[(e.scheme == "S6-R") & e.mechanism.str.startswith("reveal") & (e.region == "US915")]
    assert len(r) == 2 * 6 and (r.envelope_frames == 1).all()
    s6 = e[(e.scheme == "S6") & (e.mechanism == "active push") & (e.region == "US915")].set_index("dr").push_time_h
    assert (r.set_index("dr").push_time_h <= s6.reindex(r.dr).values).all()
    assert not e[e.scheme == "S6-R"].mechanism.eq("active push").any()
