"""Property tests for device-side checks (hypothesis) + blast-radius accounting."""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pqcap import blast
from pqcap import envelope as ev
from pqcap.config import CONFIG, load_yaml

KEY = b"k" * 32
I32 = st.integers(min_value=-(2**31), max_value=2**31 - 1)
U8 = st.integers(min_value=0, max_value=255)
ACFG = load_yaml(CONFIG / "actions.yaml")
CAT = ev.catalogue_from_config(ACFG)
INV = ev.invariants_from_config(ACFG)
SETTINGS = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@st.composite
def invariants(draw):
    return ev.Invariants(draw(st.integers(0, 1440)), draw(st.booleans()), draw(st.integers(0, 100)),
                         draw(st.integers(0, 1440)), draw(st.booleans()))


@st.composite
def policies(draw):
    """Random envelopes: rules over catalogue actions with arbitrary bounds/targets, invariants, validity."""
    rules = {}
    for a in draw(st.lists(st.sampled_from(list(CAT.values())), unique_by=lambda a: a.id, max_size=len(CAT))):
        lo = draw(st.integers(a.min - 5, a.max + 5))
        hi = draw(st.integers(lo, a.max + 10))
        rules[a.id] = ev.Rule(a.id, draw(st.frozensets(st.integers(0, 7), max_size=8)), lo, hi)
    nb = draw(st.integers(0, 2**31))
    return ev.Policy(draw(st.integers(0, 2**32 - 1)), rules, draw(invariants()), nb,
                     draw(st.integers(nb, 2**32 - 1)))


@st.composite
def states(draw):
    return ev.DeviceState(draw(st.integers(0, 2**32 - 2)), draw(st.booleans()),
                          draw(st.floats(0, 100, allow_nan=False)), draw(st.integers(0, 2**32 - 1)))


@SETTINGS
@given(env=policies(), aid=U8, target=U8, value=I32, counter=st.integers(1, 2**32 - 1), s=states(),
       tag_len=st.sampled_from([8, 16]))
def test_no_accepted_command_outside_bounds(env, aid, target, value, counter, s, tag_len):
    """Soundness: anything S6/S4-E accepts is inside bounds, catalogue, validity and every invariant."""
    msg = ev.make_command(KEY, env.handle, counter, aid, target, value, tag_len)
    d, new = ev.check_s6(env, CAT, s, msg, KEY, tag_len)
    if d.accepted:
        r = env.rules[aid]
        assert target in r.targets and r.lo <= value <= r.hi
        assert CAT[aid].min <= value <= CAT[aid].max and target < CAT[aid].targets
        assert env.not_before <= s.now <= env.not_after
        assert ev.invariant_violation(env.invariants, s, aid, value) is None
        assert counter > s.last_counter and new.last_counter == counter
    else:
        assert new == s


@SETTINGS
@given(fw=policies(), aid=U8, target=U8, value=I32, s=states(), tag_len=st.sampled_from([8, 16]))
def test_s4f_sound(fw, aid, target, value, s, tag_len):
    msg = ev.make_command(KEY, 0, s.last_counter + 1, aid, target, value, tag_len)
    if ev.check_s4f(fw, CAT, s, msg, KEY, tag_len)[0].accepted:
        assert ev.within_bounds(fw, aid, target, value)
        assert ev.invariant_violation(fw.invariants, s, aid, value) is None


@SETTINGS
@given(inv=invariants(), s=states(), value=st.integers(0, 1440))
def test_invariants_hold(inv, s, value):
    """No accepted command breaks the physical invariants (stated directly, independent of the implementation)."""
    low = inv.battery_floor_pct > 0 and s.soc_pct < inv.battery_floor_pct
    for aid, v in [(ev.A_INTERVAL, value), (ev.A_IMMEDIATE, 0), (ev.A_ENABLE, 0), (ev.A_ENABLE, 1)]:
        if ev.invariant_violation(inv, s, aid, v) is None:
            if aid == ev.A_INTERVAL and s.alert_active and inv.alert_max_interval:
                assert v <= inv.alert_max_interval
            if aid == ev.A_INTERVAL and low:
                assert v >= inv.low_batt_min_interval
            if aid == ev.A_IMMEDIATE and low:
                assert not inv.low_batt_block_immediate
            if aid == ev.A_ENABLE and v == 0 and s.alert_active:
                assert not inv.alert_forbid_disable


@SETTINGS
@given(env=policies(), data=st.data(), tag_len=st.sampled_from([8, 16]))
def test_in_bounds_commands_accepted(env, data, tag_len):
    """Completeness: in-bounds, in-catalogue, valid-time, invariant-respecting, fresh commands are accepted."""
    s = ev.DeviceState(6, data.draw(st.booleans()), data.draw(st.floats(0, 100)),
                       data.draw(st.integers(env.not_before, env.not_after)))
    ok = [(r, CAT[r.action_id]) for r in env.rules.values()
          if any(t < CAT[r.action_id].targets for t in r.targets)
          and max(r.lo, CAT[r.action_id].min) <= min(r.hi, CAT[r.action_id].max)]
    if not ok:
        return
    r, a = data.draw(st.sampled_from(ok))
    t = data.draw(st.sampled_from(sorted(x for x in r.targets if x < a.targets)))
    v = data.draw(st.integers(max(r.lo, a.min), min(r.hi, a.max)))
    msg = ev.make_command(KEY, env.handle, 7, a.id, t, v, tag_len)
    d = ev.check_s6(env, CAT, s, msg, KEY, tag_len)[0]
    assert d.accepted == (ev.invariant_violation(env.invariants, s, a.id, v) is None)


@SETTINGS
@given(env=policies(), aid=U8, target=U8, value=I32, s=states(), tag_len=st.sampled_from([8, 16]))
def test_bounded_schemes_accept_subset_of_s4(env, aid, target, value, s, tag_len):
    c = s.last_counter + 1
    m6 = ev.make_command(KEY, env.handle, c, aid, target, value, tag_len)
    m4 = ev.make_command(KEY, 0, c, aid, target, value, tag_len)
    a4 = ev.check_s4(CAT, s, m4, KEY, tag_len)[0].accepted
    if ev.check_s6(env, CAT, s, m6, KEY, tag_len)[0].accepted:
        assert a4
    if ev.check_s4f(env, CAT, s, m4, KEY, tag_len)[0].accepted:
        assert a4


@SETTINGS
@given(aid=U8, target=U8, value=I32)
def test_params_roundtrip(aid, target, value):
    assert ev.decode_params(ev.encode_params(aid, target, value)) == (aid, target, value, 0)


@SETTINGS
@given(env=policies())
def test_envelope_roundtrip(env):
    inv = env.invariants
    env = ev.Policy(env.handle, env.rules, ev.Invariants(inv.alert_max_interval, inv.alert_forbid_disable,
                                                         inv.battery_floor_pct, inv.low_batt_min_interval,
                                                         inv.low_batt_block_immediate), env.not_before, env.not_after)
    blob = ev.encode_envelope(env)
    assert len(blob) == ev.ENVELOPE_BYTES == 112
    assert ev.decode_envelope(blob) == env


@SETTINGS
@given(env=policies(), flip=st.integers(0, 15), tag_len=st.sampled_from([8, 16]))
def test_any_tampering_rejected(env, flip, tag_len):
    msg = bytearray(ev.make_command(KEY, env.handle, 5, 1, 0, 10, tag_len))
    msg[flip] ^= 0x01                                    # flip a bit in handle/counter/params
    assert not ev.check_s6(env, CAT, ev.DeviceState(0), bytes(msg), KEY, tag_len)[0].accepted


# ---------------------------------------------------------------- deterministic cases
ENV = ev.envelope_from_config(ACFG)


@pytest.mark.parametrize("tag_len", [8, 16])
def test_reject_reasons(tag_len):
    s0 = ev.DeviceState(4, alert_active=True, soc_pct=90.0)
    good = ev.make_command(KEY, ENV.handle, 5, ev.A_INTERVAL, 0, 10, tag_len)
    assert ev.check_s6(ENV, CAT, s0, good, KEY, tag_len)[0] == ev.Decision(True, "ok")
    reason = lambda m, st_=s0: ev.check_s6(ENV, CAT, st_, m, KEY, tag_len)[0].reason  # noqa: E731
    cmd = lambda a, v, h=ENV.handle: ev.make_command(KEY, h, 5, a, 0, v, tag_len)  # noqa: E731
    assert reason(good[:-1]) == "length"
    assert reason(good, ev.DeviceState(5)) == "replay"
    assert reason(good[:-1] + bytes([good[-1] ^ 1])) == "tag"
    assert reason(cmd(ev.A_INTERVAL, 10, ENV.handle + 1)) == "handle"
    assert reason(cmd(ev.A_INTERVAL, 30)) == "invariant:alert_min_rate"       # in bounds, too slow during alert
    assert reason(cmd(ev.A_INTERVAL, 90)) == "bounds"
    assert reason(cmd(ev.A_ENABLE, 0)) == "bounds"                            # envelope: enable only
    assert reason(cmd(9, 0)) == "catalogue"
    low = ev.DeviceState(4, alert_active=False, soc_pct=5.0)
    assert reason(cmd(ev.A_IMMEDIATE, 0), low) == "invariant:battery_floor"
    assert reason(cmd(ev.A_INTERVAL, 30), low) == "invariant:battery_floor"
    assert reason(cmd(ev.A_INTERVAL, 30), ev.DeviceState(4, now=5)) == "ok"
    exp = ev.Policy(ENV.handle, ENV.rules, ENV.invariants, 10, 20)
    assert ev.check_s6(exp, CAT, ev.DeviceState(4, now=21), cmd(ev.A_INTERVAL, 30), KEY, tag_len)[0].reason == "expired"
    body = ev.HEADER.pack(ENV.handle, 5) + ev.PARAMS.pack(1, 0, 10, 1)
    assert reason(body + ev.tag(KEY, body, tag_len)) == "catalogue"           # reserved bits set
    body4 = ev.HEADER.pack(0, 5) + ev.PARAMS.pack(1, 0, 10, 1)
    assert ev.check_s4(CAT, s0, body4 + ev.tag(KEY, body4, tag_len), KEY, tag_len)[0].reason == "catalogue"
    assert ev.check_s4(CAT, s0, good[:-1], KEY, tag_len)[0].reason == "length"
    fw = ev.firmware_policy_from_config(ACFG)
    assert ev.check_s4f(fw, CAT, s0, good[:-1], KEY, tag_len)[0].reason == "length"
    assert ev.check_s4f(fw, CAT, ev.DeviceState(4), cmd(ev.A_ENABLE, 0, 0), KEY, tag_len)[0].accepted


def test_encoding_limits_and_config():
    assert len(ev.encode_bounds(ENV)) == 64 and len(ev.encode_invariants(INV)) == 32
    with pytest.raises(ValueError, match="bounds field"):
        ev.encode_bounds(ev.Policy(1, {i: ev.Rule(i, frozenset({0}), 0, 1) for i in range(1, 8)}))  # 70 B
    with pytest.raises(ValueError, match="bitmap"):
        ev.encode_bounds(ev.Policy(1, {1: ev.Rule(1, frozenset({8}), 0, 1)}))
    with pytest.raises(ValueError, match="112"):
        ev.decode_envelope(b"\0" * 10)
    assert ACFG["status"].startswith("assumed")
    p = ev.permissive_policy(CAT)
    assert all(p.rules[a.id].lo == a.min and p.rules[a.id].hi == a.max for a in CAT.values())
    assert ev.invariants_from_config({}) == ev.NO_INVARIANTS


def test_blast_s4_s6_matches_closed_form():
    df = blast.blast_s4_s6(CAT, ENV, INV, 8)
    ref = blast.reference_state_name(ACFG)
    d = df[df.state == ref].pivot_table(index="action", columns="scheme", values="accepted")
    s = ev.DeviceState(0, True, 100.0)
    for a in CAT.values():
        assert d.loc[a.name, "S4"] == a.targets * (a.max - a.min + 1)
        exp = sum(ev.within_bounds(ENV, a.id, t, v) and ev.invariant_violation(INV, s, a.id, v) is None
                  for t in range(a.targets) for v in range(a.min, a.max + 1))
        assert d.loc[a.name, "S6"] == exp
    assert set(df.state) == set(blast.device_states(INV))
    k = blast.k5(df, ref)
    assert k["ratio"] == pytest.approx(k["s6_accepted"] / k["s4_accepted"]) and k["answer"].startswith("S6/S4")
    assert blast.reference_state_name({}) == "alert=True,battery=above_floor"


# ---------------------------------------------------------------- D2: S6+F
@SETTINGS
@given(env=policies(), aid=U8, value=I32, s=states(), op=st.booleans(), tag_len=st.sampled_from([8, 16]))
def test_s6f_floor_and_op_token(env, aid, value, s, op, tag_len):
    """Even under a permissive (attacker-minted) envelope, S6+F never accepts a command that breaks the
    firmware floor, and never accepts 'disable sensor' without a valid OP token."""
    perm = ev.permissive_policy(CAT, env.handle)
    for pol in (env, perm):
        msg = ev.make_command(KEY, pol.handle, s.last_counter + 1, aid, 0, value, tag_len)
        d, _ = ev.check_s6f(pol, INV, CAT, s, msg, KEY, tag_len, op)
        if d.accepted:
            assert ev.invariant_violation(INV, s, aid, value) is None
            assert not (aid == ev.A_ENABLE and value == 0 and not op)
            assert ev.check_s6(pol, CAT, s, msg, KEY, tag_len)[0].accepted     # S6+F accepts a subset of S6


def test_s6f_reasons():
    perm = ev.permissive_policy(CAT, 7)
    s = ev.DeviceState(0, alert_active=False, soc_pct=90.0)
    off = ev.make_command(KEY, 7, 1, ev.A_ENABLE, 0, 0, 8)
    assert ev.check_s6f(perm, INV, CAT, s, off, KEY, 8, False)[0].reason == "op_token_required"
    assert ev.check_s6f(perm, INV, CAT, s, off, KEY, 8, True)[0].accepted
    slow = ev.make_command(KEY, 7, 1, ev.A_INTERVAL, 0, 600, 8)
    assert ev.check_s6f(perm, INV, CAT, ev.DeviceState(0, alert_active=True), slow, KEY, 8, True)[0].reason.startswith("floor:")
    assert ev.check_s6f(perm, INV, CAT, s, slow[:-1], KEY, 8, True)[0].reason == "length"


# ---------------------------------------------------------------- F3: write-once commissioning bound
@SETTINGS
@given(env=policies(), value=st.integers(min_value=0, max_value=1500), s=states(), op=st.booleans(),
       cap=st.integers(min_value=1, max_value=1500))
def test_s6f_commissioning_threshold_cap(env, value, s, op, cap):
    """Whatever envelope is installed (including one minted with sk_PA, C3), S6+F never accepts an alert threshold
    above the write-once commissioning bound -- no message can change the bound."""
    import dataclasses
    floor = dataclasses.replace(INV, max_alert_threshold=cap)
    for pol in (env, ev.permissive_policy(CAT, env.handle)):
        msg = ev.make_command(KEY, pol.handle, s.last_counter + 1, ev.A_THRESHOLD, 0, value, 8)
        d, _ = ev.check_s6f(pol, floor, CAT, s, msg, KEY, 8, op)
        if d.accepted:
            assert value <= cap
        if value > cap:
            assert not d.accepted


def test_commissioning_reason():
    import dataclasses
    floor = dataclasses.replace(INV, max_alert_threshold=500)
    s = ev.DeviceState(0, alert_active=False, soc_pct=90.0)
    assert ev.invariant_violation(floor, s, ev.A_THRESHOLD, 501) == "commissioning:max_alert_threshold"
    assert ev.invariant_violation(floor, s, ev.A_THRESHOLD, 500) is None
    assert ev.invariant_violation(INV, s, ev.A_THRESHOLD, 1500) is None            # no bound by default
    perm = ev.permissive_policy(CAT, 7)
    hi = ev.make_command(KEY, 7, 1, ev.A_THRESHOLD, 0, 900, 8)
    assert ev.check_s6f(perm, floor, CAT, s, hi, KEY, 8, True)[0].reason == "floor:commissioning:max_alert_threshold"
