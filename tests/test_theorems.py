"""Audit v0.2 A4: falsification test of Theorems 2 and 3 (manuscript v0.2, Sec. V) against harm.simulate.

A random adversary holds the crisis keys (C1) or also replaces the envelope (C1+C3), never the operator's secrets.
At every downlink it sends a random command that S6+F accepts in the current state (any action: interval, immediate
uplink, threshold moves within [band_lo, theta_F] under C1 and [0, theta_F] under C1+C3; never disable), or nothing.
simulate is only instrumented (uplink minutes, state of charge), not changed. Checked on every case:
  Theorem 3: N(t) <= U_B(t) at every minute t, with U_B the manuscript formula (theta_lo as above);
  Theorem 2: every crossing of a level L >= theta_F whose first sample instant tau has stage >= theta_F at every
             sample instant of [tau, tau + I_max] and state of charge >= the floor on that interval is reported
             (the sample at tau delivered) by minute tau + I_max.
Hypothesis is derandomised (fixed seed); each case also carries its own adversary seed, printed on failure.
"""

import math
import random

import numpy as np
from hypothesis import given, settings
from hypothesis import strategies as st

from pqcap import envelope as ev
from pqcap import harm
from pqcap.config import CONFIG, load_yaml

HCFG = {**load_yaml(CONFIG / "harm.yaml"), "workers": 1}
ACFG = load_yaml(CONFIG / "actions.yaml")
INV = ev.invariants_from_config(ACFG)
P = HCFG["device"]["sample_period_min"]
T_DEF = HCFG["device"]["default_reporting_interval_min"]
I_MAX = INV.alert_max_interval
EPOCH = int(HCFG["energy_budget"]["epoch_h"] * 60)
BAND = (460, 760)                         # S6 envelope band of config/actions.yaml (set_alert_threshold lo, hi)


def _battery(n_up: int) -> dict:
    return {"name": "test", "capacity": 1.0, "q": 1.0 / n_up, "sleep_per_h": 0.0}


def u_b(stage: np.ndarray, theta_lo: float, budget: int) -> np.ndarray:
    """Manuscript Theorem 3: U_B(t) = 1 + floor(t/T) + B (floor(t/Te) + 1)
    + sum over maximal runs r of R up to t of (floor(|r|/I_max) + 1 + ceil(ceil(|r|/p) / 2)),
    R = minutes at which the last sampled stage is >= theta_lo; a run still open at t counts with its length so far."""
    n = len(stage)
    out = np.zeros(n, dtype=np.int64)
    held, closed, run = False, 0, 0
    term = lambda r: r // I_MAX + 1 + math.ceil(math.ceil(r / P) / 2) if r else 0  # noqa: E731
    for t in range(n):
        if t % P == 0:
            held = stage[t] >= theta_lo
        if held:
            run += 1
        elif run:
            closed, run = closed + term(run), 0
        out[t] = 1 + t // T_DEF + budget * (t // EPOCH + 1) + closed + term(run)
    return out


def random_adversary(rng: random.Random, theta_lo: int, theta_f: int, greed: float = 0.0):
    """With probability `greed` per downlink the most draining accepted command (immediate uplink, else the
    shortest interval, else the lowest threshold); otherwise a uniformly random accepted command or nothing."""
    ia = (1, 1440)

    def act(sch, d, state):
        if rng.random() < greed:
            for cmd in [(ev.A_IMMEDIATE, 0)] + [(ev.A_INTERVAL, v) for v in range(1, 16)] + [(ev.A_THRESHOLD, theta_lo)]:
                if sch.accepts(state, *cmd):
                    return cmd
        kind = rng.choice(("interval", "interval", "immediate", "immediate", "threshold", "none"))
        for _ in range(30):
            if kind == "none":
                return None
            if kind == "immediate":
                cmd = (ev.A_IMMEDIATE, 0)
            elif kind == "interval":
                cmd = (ev.A_INTERVAL, rng.choice((rng.randint(*ia), rng.randint(1, 15))))
            else:
                cmd = (ev.A_THRESHOLD, rng.randint(theta_lo, theta_f))
            if sch.accepts(state, *cmd):
                return cmd
            kind = rng.choice(("interval", "immediate", "threshold"))
        return None
    return act


def hydrograph(minutes: int, base: float, peak: float, centre: float, width: float, noise: float, seed: int):
    t = np.arange(minutes)
    g = np.random.default_rng(seed)
    s = base + (peak - base) * np.exp(-((t - centre * minutes) / (width * minutes)) ** 2)
    return np.maximum(0.0, s + g.normal(0, noise, minutes).cumsum() / 50)


CASE = dict(days=st.integers(2, 5), peak=st.floats(300, 1400), base=st.floats(50, 500), centre=st.floats(0.2, 0.8),
            width=st.floats(0.03, 0.3), noise=st.floats(0, 30), theta_f=st.integers(*BAND),
            comp=st.sampled_from(["C1", "C1+C3"]), budget=st.integers(0, 120), soc0=st.integers(25, 100),
            n_up=st.sampled_from([300, 1300, 5000]), greed=st.sampled_from([0.0, 0.5, 0.9, 1.0]),
            seed=st.integers(0, 2**31 - 1))


def run_case(days, peak, base, centre, width, noise, theta_f, comp, budget, soc0, n_up, greed, seed, f8="configured"):
    stage = hydrograph(days * 1440, base, peak, centre, width, noise, seed)
    acfg = harm.threshold_profile(ACFG, BAND)
    env, fw, cat = ev.envelope_from_config(acfg), ev.firmware_policy_from_config(acfg), ev.catalogue_from_config(acfg)
    cfg = {**HCFG, "device": {**HCFG["device"], "alert_threshold_cm": theta_f}, "_max_alert_threshold": theta_f,
           "_profile_inv": INV, "_battery": _battery(n_up), "battery": {**HCFG["battery"], "initial_soc_pct": soc0},
           "commissioning": {**HCFG["commissioning"], "free_alert_uplinks": f8}}
    theta_lo = BAND[0] if comp == "C1" else cat[ev.A_THRESHOLD].min
    r = harm.simulate(stage, "S6+F", comp, None, cfg, cat, env, fw, budget=budget,
                      adversary=random_adversary(random.Random(seed), theta_lo, theta_f, greed), trace=True)
    return stage, r, theta_lo


def check_theorem3(stage, r, theta_lo, budget, seed):
    n = np.zeros(len(stage), dtype=np.int64)
    np.add.at(n, np.asarray(r["uplinks_at"], dtype=np.int64), 1)
    n = n.cumsum()
    ub = u_b(stage, theta_lo, budget)
    m = len(r["soc_pct"])                                              # the run stops if the battery dies
    bad = np.nonzero(n[:m] > ub[:m])[0]
    assert bad.size == 0, f"Theorem 3 counterexample (seed {seed}): t={bad[0]} N={n[bad[0]]} U_B={ub[bad[0]]}"


def check_theorem2(stage, r, theta_f, seed):
    sent = {ts: up for ts, _, up in r["delivered"]}
    soc, floor = r["soc_pct"], INV.battery_floor_pct
    checked = 0
    for level in (theta_f, theta_f + 50, theta_f + 200):
        for s0, e0 in harm.crossings(stage, level):
            tau = int(math.ceil(s0 / P) * P)
            if tau > e0 or tau + I_MAX >= len(soc):
                continue
            if not all(stage[u] >= theta_f for u in range(tau, tau + I_MAX + 1, P)):
                continue
            if min(soc[tau:tau + I_MAX + 1]) < floor:
                continue
            checked += 1
            assert tau in sent and sent[tau] <= tau + I_MAX, \
                f"Theorem 2 counterexample (seed {seed}): level {level} tau={tau} delivered at {sent.get(tau)}"
    return checked


@settings(max_examples=500, deadline=None, derandomize=True)
@given(**CASE)
def test_theorems_hold_against_random_adversary(**k):
    stage, r, theta_lo = run_case(**k)
    check_theorem3(stage, r, theta_lo, k["budget"], k["seed"])
    check_theorem2(stage, r, k["theta_f"], k["seed"])


def test_bound_and_checker_detect_violations():
    """The checkers are not vacuous: a fabricated over-count and a late delivery are caught."""
    stage = np.full(200, 100.0)
    ub = u_b(stage, 50.0, 0)
    assert ub[0] == 1 + 0 + 0 + (0 // I_MAX + 1 + 1)                  # run of length 1 at t = 0
    assert u_b(stage, 500.0, 2)[-1] == 1 + 199 // T_DEF + 2 * (199 // EPOCH + 1)
    fake = {"uplinks_at": list(range(0, 200, 2)), "soc_pct": [100.0] * 200, "delivered": []}
    try:
        check_theorem3(stage, fake, 500.0, 0, -1)
        raise AssertionError("not caught")
    except AssertionError as e:
        assert "counterexample" in str(e)
    high = np.full(100, 700.0)
    late = {"delivered": [(0, 700.0, 40)], "soc_pct": [100.0] * 100}
    try:
        check_theorem2(np.r_[np.full(10, 0.0), high][:100], {**late, "delivered": [(10, 700.0, 40)]}, 600, -1)
        raise AssertionError("not caught")
    except AssertionError as e:
        assert "counterexample" in str(e)
    assert check_theorem2(np.full(100, 0.0), late, 600, -1) == 0


@settings(max_examples=300, deadline=None, derandomize=True)
@given(**CASE)
def test_theorems_hold_with_f8(**k):
    """B4: with F8 on (`commissioned`), U_B with theta_lo = theta_F bounds N(t) for every adversary (C1 and C1+C3),
    since an alert uplink is free only when its triggering sample is >= theta_F; Theorem 2 still holds."""
    stage, r, _ = run_case(**k, f8="commissioned")
    check_theorem3(stage, r, k["theta_f"], k["budget"], k["seed"])
    check_theorem2(stage, r, k["theta_f"], k["seed"])
