"""Property tests for S6 envelope checking (hypothesis) + blast-radius accounting."""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pqcap import blast
from pqcap import envelope as ev
from pqcap.config import CONFIG, load_yaml

KEY = b"k" * 32
I32 = st.integers(min_value=-(2**31), max_value=2**31 - 1)
U8 = st.integers(min_value=0, max_value=255)
CAT = ev.catalogue_from_config(load_yaml(CONFIG / "actions.yaml"))


@st.composite
def envelopes(draw):
    """Random envelopes whose rules reference catalogue actions with arbitrary bounds/targets."""
    rules = {}
    for a in draw(st.lists(st.sampled_from(list(CAT.values())), unique_by=lambda a: a.id, max_size=len(CAT))):
        lo = draw(st.integers(a.min - 5, a.max + 5))
        hi = draw(st.integers(lo, a.max + 10))
        targets = draw(st.frozensets(st.integers(0, 7), max_size=8))
        rules[a.id] = ev.Rule(a.id, targets, lo, hi)
    return ev.Envelope(draw(st.integers(0, 2**32 - 1)), rules)


SETTINGS = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@SETTINGS
@given(env=envelopes(), aid=U8, target=U8, value=I32, counter=st.integers(1, 2**32 - 1),
       last=st.integers(0, 2**32 - 1), tag_len=st.sampled_from([8, 16]))
def test_no_accepted_command_outside_bounds(env, aid, target, value, counter, last, tag_len):
    """Soundness: anything S6 accepts is inside the envelope AND the catalogue, with a fresh counter."""
    msg = ev.make_command(KEY, env.handle, counter, aid, target, value, tag_len)
    d, new = ev.check_s6(env, CAT, ev.DeviceState(last), msg, KEY, tag_len)
    if d.accepted:
        r = env.rules[aid]
        assert target in r.targets and r.lo <= value <= r.hi
        assert CAT[aid].min <= value <= CAT[aid].max and target < CAT[aid].targets
        assert counter > last and new.last_counter == counter
    else:
        assert new.last_counter == last


@SETTINGS
@given(env=envelopes(), data=st.data(), tag_len=st.sampled_from([8, 16]))
def test_in_bounds_commands_accepted(env, data, tag_len):
    """Completeness: every command inside envelope and catalogue, with fresh counter, is accepted."""
    ok = [(r, CAT[r.action_id]) for r in env.rules.values()
          if any(t < CAT[r.action_id].targets for t in r.targets)
          and max(r.lo, CAT[r.action_id].min) <= min(r.hi, CAT[r.action_id].max)]
    if not ok:
        return
    r, a = data.draw(st.sampled_from(ok))
    t = data.draw(st.sampled_from(sorted(x for x in r.targets if x < a.targets)))
    v = data.draw(st.integers(max(r.lo, a.min), min(r.hi, a.max)))
    msg = ev.make_command(KEY, env.handle, 7, a.id, t, v, tag_len)
    assert ev.check_s6(env, CAT, ev.DeviceState(6), msg, KEY, tag_len)[0].accepted


@SETTINGS
@given(env=envelopes(), aid=U8, target=U8, value=I32, tag_len=st.sampled_from([8, 16]))
def test_s6_accepts_subset_of_s4(env, aid, target, value, tag_len):
    m6 = ev.make_command(KEY, env.handle, 2, aid, target, value, tag_len)
    m4 = ev.make_command(KEY, 0, 2, aid, target, value, tag_len)
    if ev.check_s6(env, CAT, ev.DeviceState(1), m6, KEY, tag_len)[0].accepted:
        assert ev.check_s4(CAT, ev.DeviceState(1), m4, KEY, tag_len)[0].accepted


@SETTINGS
@given(aid=U8, target=U8, value=I32)
def test_params_roundtrip(aid, target, value):
    assert ev.decode_params(ev.encode_params(aid, target, value)) == (aid, target, value, 0)


@SETTINGS
@given(env=envelopes())
def test_bounds_roundtrip(env):
    env = ev.Envelope(env.handle, {k: r for k, r in env.rules.items() if r.lo >= -(2**31)})
    assert ev.decode_bounds(env.handle, ev.encode_bounds(env)) == env


@SETTINGS
@given(env=envelopes(), flip=st.integers(0, 15), tag_len=st.sampled_from([8, 16]))
def test_any_tampering_rejected(env, flip, tag_len):
    msg = bytearray(ev.make_command(KEY, env.handle, 5, 1, 0, 30, tag_len))
    msg[flip] ^= 0x01                                    # flip a bit in handle/counter/params
    assert not ev.check_s6(env, CAT, ev.DeviceState(0), bytes(msg), KEY, tag_len)[0].accepted


def _scenario():
    cfg = load_yaml(CONFIG / "actions.yaml")
    return ev.envelope_from_config(cfg)


@pytest.mark.parametrize("tag_len", [8, 16])
def test_reject_reasons(tag_len):
    env = _scenario()
    good = ev.make_command(KEY, env.handle, 5, 1, 0, 30, tag_len)
    s0 = ev.DeviceState(4)
    assert ev.check_s6(env, CAT, s0, good, KEY, tag_len)[0] == ev.Decision(True, "ok")
    reason = lambda m, st_=s0: ev.check_s6(env, CAT, st_, m, KEY, tag_len)[0].reason  # noqa: E731
    assert reason(good[:-1]) == "length"
    assert reason(good, ev.DeviceState(5)) == "replay"
    assert reason(good[:-1] + bytes([good[-1] ^ 1])) == "tag"
    assert reason(ev.make_command(KEY, env.handle + 1, 5, 1, 0, 30, tag_len)) == "handle"
    assert reason(ev.make_command(KEY, env.handle, 5, 2, 0, 0, tag_len)) == "envelope"      # disable sensor
    assert reason(ev.make_command(KEY, env.handle, 5, 9, 0, 0, tag_len)) == "catalogue"
    body = ev.HEADER.pack(env.handle, 5) + ev.PARAMS.pack(1, 0, 30, 1)
    assert reason(body + ev.tag(KEY, body, tag_len)) == "reserved"
    body4 = ev.HEADER.pack(0, 5) + ev.PARAMS.pack(1, 0, 30, 1)
    assert ev.check_s4(CAT, s0, body4 + ev.tag(KEY, body4, tag_len), KEY, tag_len)[0].reason == "catalogue"
    assert ev.check_s4(CAT, s0, good[:-1], KEY, tag_len)[0].reason == "length"


def test_encode_bounds_limits():
    env = _scenario()
    assert len(ev.encode_bounds(env)) == 64
    too_many = ev.Envelope(1, {i: ev.Rule(i, frozenset({0}), 0, 1) for i in range(1, 8)})  # 70 B
    with pytest.raises(ValueError, match="bounds field"):
        ev.encode_bounds(too_many)
    with pytest.raises(ValueError, match="bitmap"):
        ev.encode_bounds(ev.Envelope(1, {1: ev.Rule(1, frozenset({8}), 0, 1)}))


def test_blast_radius_matches_closed_form():
    env = _scenario()
    df = blast.blast_radius(CAT, env, 8).set_index("action")
    for a in CAT.values():
        r = env.rules.get(a.id)
        exp6 = 0 if r is None else (len([t for t in r.targets if t < a.targets])
                                    * max(0, min(r.hi, a.max) - max(r.lo, a.min) + 1))
        assert df.loc[a.name, "s4_accepted"] == a.targets * (a.max - a.min + 1) == df.loc[a.name, "catalogue_commands"]
        assert df.loc[a.name, "s6_accepted"] == exp6
    tot = df.loc["TOTAL"]
    assert tot.s6_accepted == df.drop("TOTAL").s6_accepted.sum()
    k = blast.k5(df.reset_index())
    assert k["ratio"] == pytest.approx(tot.s6_accepted / tot.s4_accepted) and k["answer"].startswith("S6/S4")
