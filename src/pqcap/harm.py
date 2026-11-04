"""Harm-weighted replay of a real stage series under each scheme and compromise.

A minute-resolution simulation of one cellular/LoRaWAN-style node (one downlink opportunity after each
uplink). The device samples, raises a firmware alert (immediate uplink) when the sample reaches its alert
threshold, buffers samples and uplinks on its reporting interval. After each uplink one queued command is
delivered and run through the scheme's device check (pqcap.envelope). Physical invariants, where the scheme
has them, are enforced both at acceptance and on the device's effective behaviour (hard limits below the
agent). Battery: sleep + per-uplink charge.

Metrics: missed / delayed upward crossings of operator reference levels, detection delay, battery-floor
violation, death; legitimate-command rejection rate (no compromise).
"""

from __future__ import annotations

import datetime as dt
import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from . import envelope as ev

KEY = bytes(range(64, 96))
TAG = 8


# ---------------------------------------------------------------- data
def load_series(path: Path, ft_to_cm: float) -> pd.Series:
    """USGS NWIS IV JSON -> stage (cm) indexed by timestamp; noData values dropped."""
    d = json.loads(Path(path).read_text())
    ts = d["value"]["timeSeries"][0]
    nodata = float(ts["variable"]["noDataValue"])
    pts = [(dt.datetime.fromisoformat(v["dateTime"]), float(v["value"])) for v in ts["values"][0]["value"]
           if float(v["value"]) != nodata]
    s = pd.Series([v for _, v in pts], index=pd.DatetimeIndex([t for t, _ in pts]), name="stage_cm") * ft_to_cm
    return s.sort_index()


def to_minutes(s: pd.Series) -> np.ndarray:
    """Linear interpolation onto a 1-minute grid from the first to the last reading."""
    t0 = s.index[0]
    mins = ((s.index - t0).total_seconds() / 60).to_numpy()
    grid = np.arange(0, int(mins[-1]) + 1)
    return np.interp(grid, mins, s.to_numpy())


def crossings(stage: np.ndarray, level: float) -> list[tuple[int, int]]:
    """Upward crossings: list of (first minute >= level, last minute of that excursion)."""
    above = stage >= level
    out, start = [], None
    for i, a in enumerate(above):
        if a and start is None and (i == 0 or not above[i - 1]):
            start = i
        if start is not None and (not a or i == len(above) - 1):
            out.append((start, i - 1 if not a else i))
            start = None
    return out


def max_gap_min(s: pd.Series) -> float:
    return float(s.index.to_series().diff().dt.total_seconds().max() / 60)


def gaps(s: pd.Series, min_minutes: float) -> list[dict]:
    d = s.index.to_series().diff().dt.total_seconds() / 60
    return [{"after": str(s.index[i - 1]), "before": str(s.index[i]), "minutes": float(d.iloc[i])}
            for i in range(1, len(s)) if d.iloc[i] >= min_minutes]


# ---------------------------------------------------------------- battery
def uplink_charge_mAh(b: dict) -> float:
    """Per-uplink charge derived from the 'drains in a week' interpretation (see config/harm.yaml)."""
    n_week = 7 * 24 * 60 / b["week_drain_uplink_period_min"]
    sleep_week = b["sleep_current_mA"] * 7 * 24
    return (b["capacity_mAh"] - sleep_week) / n_week


# ---------------------------------------------------------------- device
@dataclass
class Dev:
    interval: int
    threshold: int
    enabled: bool = True
    soc_mAh: float = 0.0
    alert: bool = False
    last_uplink: int = -10**9
    pending: bool = False
    counter: int = 0
    buffer: list = field(default_factory=list)


def effective_interval(interval: int, alert: bool, soc_pct: float, inv: ev.Invariants) -> int:
    """Invariants applied to behaviour: alert forces a minimum rate; the battery floor dominates."""
    e = interval
    if alert and inv.alert_max_interval:
        e = min(e, inv.alert_max_interval)
    if inv.battery_floor_pct and soc_pct < inv.battery_floor_pct:
        e = max(e, inv.low_batt_min_interval)
    return e


class Scheme:
    """Device-side check for one scheme, with the policy in force (possibly attacker-replaced)."""

    def __init__(self, name: str, cat, env: ev.Policy, fw: ev.Policy, replaced: bool, op_key: bool = False):
        self.name, self.cat, self.op_key = name, cat, op_key
        enveloped = name in ("S4-E", "S6", "S6+F")
        self.env = ev.permissive_policy(cat, env.handle) if replaced and enveloped else env
        self.fw = fw
        self.handle = self.env.handle if enveloped else 0

    @property
    def invariants(self) -> ev.Invariants:
        if self.name == "S4":
            return ev.NO_INVARIANTS
        return self.fw.invariants if self.name == "S4-F" else self.env.invariants

    @property
    def floor(self) -> ev.Invariants:
        """S6+F non-updatable firmware floor (profile invariants); none for the other schemes."""
        return self.fw.invariants if self.name == "S6+F" else ev.NO_INVARIANTS

    def check(self, state: ev.DeviceState, msg: bytes):
        if self.name == "S4":
            return ev.check_s4(self.cat, state, msg, KEY, TAG)
        if self.name == "S4-F":
            return ev.check_s4f(self.fw, self.cat, state, msg, KEY, TAG)
        if self.name == "S6+F":
            return ev.check_s6f(self.env, self.floor, self.cat, state, msg, KEY, TAG, self.op_key)
        return ev.check_enveloped(self.env, self.cat, state, msg, KEY, TAG)

    def accepts(self, state: ev.DeviceState, aid: int, value: int) -> bool:
        msg = ev.make_command(KEY, self.handle, state.last_counter + 1, aid, 0, value, TAG)
        return self.check(state, msg)[0].accepted


def _dstate(d: Dev, soc_pct: float, t: int) -> ev.DeviceState:
    return ev.DeviceState(d.counter, d.alert, soc_pct, t * 60)


# ---------------------------------------------------------------- controllers
def attacker_command(strategy: str, sch: Scheme, d: Dev, st: ev.DeviceState) -> tuple[int, int] | None:
    """Most harmful command the device would accept now (policy is public; the attacker runs the same check)."""
    cat = sch.cat
    if strategy == "suppress":
        if d.enabled and sch.accepts(st, ev.A_ENABLE, 0):
            return ev.A_ENABLE, 0
        a = cat[ev.A_THRESHOLD]
        best = next((v for v in range(a.max, d.threshold, -1) if sch.accepts(st, ev.A_THRESHOLD, v)), None)
        if best is not None:
            return ev.A_THRESHOLD, best
        a = cat[ev.A_INTERVAL]
        best = next((v for v in range(a.max, d.interval, -1) if sch.accepts(st, ev.A_INTERVAL, v)), None)
        return (ev.A_INTERVAL, best) if best is not None else None
    if strategy == "drain":
        a = cat[ev.A_INTERVAL]
        best = next((v for v in range(a.min, d.interval) if sch.accepts(st, ev.A_INTERVAL, v)), None)
        if best is not None:
            return ev.A_INTERVAL, best
        return (ev.A_IMMEDIATE, 0) if sch.accepts(st, ev.A_IMMEDIATE, 0) else None
    raise ValueError(strategy)


class LegitPolicy:
    """Ramp up on rise, step down when steady (rule-based adaptive reporting).

    variant "naive":       asks for the rule's target interval regardless of the device's limits.
    variant "limit_aware": knows the envelope limits (public) and the device's invariants in the current
                           state; it asks for the accepted value closest to the target, or nothing.
    """

    def __init__(self, p: dict, variant: str = "naive", lo: int = 1, hi: int = 1440):
        if variant not in ("naive", "limit_aware"):
            raise ValueError(variant)
        self.p, self.received, self.steady_n, self.want = p, [], 0, None
        self.variant, self.lo, self.hi = variant, lo, hi

    def observe(self, samples: list[tuple[int, float]]):
        self.received.extend(samples)

    def command(self, current: int, accept=None) -> tuple[int, int] | None:
        r = [x for x in self.received if x[0] >= self.received[-1][0] - 60] if self.received else []
        if len(r) < 2 or r[-1][0] == r[0][0]:
            return None
        rate = (r[-1][1] - r[0][1]) / ((r[-1][0] - r[0][0]) / 60)
        self.steady_n = self.steady_n + 1 if abs(rate) < self.p["steady_cm_per_h"] else 0
        if rate > self.p["rise_cm_per_h"]:
            want = self.p["fast_interval_min"]
        elif self.steady_n >= self.p["steady_reports"]:
            want = self.p["slow_interval_min"]
        else:
            return None
        if self.variant == "limit_aware" and accept is not None and not accept(want):
            ok = sorted((v for v in range(self.lo, self.hi + 1) if accept(v)), key=lambda v: (abs(v - want), v))
            if not ok:
                return None
            want = ok[0]
        return (ev.A_INTERVAL, want) if want != current else None


# ---------------------------------------------------------------- simulation
def simulate(stage: np.ndarray, scheme: str, compromise: str, strategy: str | None, cfg: dict, cat,
             env: ev.Policy, fw: ev.Policy, legit_variant: str = "naive") -> dict:
    dv, bt = cfg["device"], cfg["battery"]
    sch = Scheme(scheme, cat, env, fw, replaced=compromise.startswith("C1+C3"), op_key=compromise.endswith("+OP"))
    inv, floor = sch.invariants, sch.floor
    q_tx, sleep_per_min = uplink_charge_mAh(bt), bt["sleep_current_mA"] / 60
    d = Dev(dv["default_reporting_interval_min"], dv["alert_threshold_cm"], soc_mAh=bt["capacity_mAh"]
            * bt["initial_soc_pct"] / 100)
    ia = cat[ev.A_INTERVAL]
    legit = LegitPolicy(cfg["legit_policy"], legit_variant, ia.min, ia.max) if compromise == "none" else None
    prof = cfg["_profile_inv"]                                       # scored against the PROFILE invariants, all schemes
    cfg_floor = bt["capacity_mAh"] * prof.battery_floor_pct / 100
    cmd_pending = False
    last_rejected = last_sent = None
    stats = {"legit_intents": 0, "legit_intents_rejected": 0, "floor_violating_uplinks": 0, "uplinks": 0, "legit_sent": 0, "legit_rejected": 0, "attacker_sent": 0, "attacker_accepted": 0,
             "minutes_below_floor": 0, "died_min": None, "min_soc_pct": 100.0}
    delivered: list[tuple[int, float, int]] = []                     # (sample minute, value, uplink minute)
    reject_reasons: dict[str, int] = {}
    for t in range(len(stage)):
        d.soc_mAh -= sleep_per_min
        if d.soc_mAh <= 0:
            stats["died_min"] = t
            break
        soc_pct = 100 * d.soc_mAh / bt["capacity_mAh"]
        stats["min_soc_pct"] = min(stats["min_soc_pct"], soc_pct)
        stats["minutes_below_floor"] += d.soc_mAh < cfg_floor
        if t % dv["sample_period_min"] == 0:
            if d.enabled:
                v = float(stage[t])
                d.buffer.append((t, v))
                now_alert = v >= d.threshold
                if now_alert and not d.alert:
                    d.pending = True                                # firmware alert -> immediate uplink
                d.alert = now_alert
            else:
                d.alert = False
        eff = effective_interval(effective_interval(d.interval, d.alert, soc_pct, inv), d.alert, soc_pct, floor)
        since = t - d.last_uplink
        if since < dv["min_uplink_spacing_min"] or not (d.pending or since >= eff):
            continue
        # ---- uplink (a floor violation = uplink below the floor at a rate the battery invariant forbids,
        #      i.e. command-requested immediate uplink or effective interval faster than the low-battery minimum;
        #      firmware alert uplinks are exempt -- they are the purpose of the device)
        if d.soc_mAh < cfg_floor and (cmd_pending or (not d.pending and eff < prof.low_batt_min_interval)):
            stats["floor_violating_uplinks"] += 1
        cmd_pending = False
        d.soc_mAh -= q_tx
        stats["uplinks"] += 1
        delivered += [(ts, v, t) for ts, v in d.buffer]
        if legit:
            legit.observe(d.buffer)
        d.buffer, d.last_uplink, d.pending = [], t, False
        # ---- one downlink opportunity
        st = _dstate(d, 100 * d.soc_mAh / bt["capacity_mAh"], t)
        if legit:
            cmd, who = legit.command(d.interval, lambda v, st=st: sch.accepts(st, ev.A_INTERVAL, v)), "legit"
        elif strategy:
            cmd, who = attacker_command(strategy, sch, d, st), "attacker"
        else:
            cmd, who = None, None
        if cmd is None:
            continue
        aid, value = cmd
        d.counter += 1
        dec, _ = sch.check(st, ev.make_command(KEY, sch.handle, d.counter, aid, 0, value, TAG))
        stats[f"{who}_sent"] += 1
        if who == "legit" and (aid, value) != last_sent:
            stats["legit_intents"] += 1
        last_sent = (aid, value) if who == "legit" else last_sent
        if not dec.accepted:
            if who == "legit":
                stats["legit_rejected"] += 1
                if (aid, value) != last_rejected:
                    stats["legit_intents_rejected"] += 1
                last_rejected = (aid, value)
                reject_reasons[dec.reason] = reject_reasons.get(dec.reason, 0) + 1
            continue
        if who == "attacker":
            stats["attacker_accepted"] += 1
        if aid == ev.A_INTERVAL:
            d.interval = value
        elif aid == ev.A_IMMEDIATE:
            d.pending, cmd_pending = True, True
        elif aid == ev.A_ENABLE:
            d.enabled = bool(value)
        elif aid == ev.A_THRESHOLD:
            d.threshold = value
    stats["reject_reasons"] = reject_reasons
    return {"stats": stats, "delivered": delivered}


def score(stage: np.ndarray, delivered: list[tuple[int, float, int]], levels_cm: list[float], tol_min: int) -> dict:
    """Detection of each upward crossing: first uplink delivering a sample >= level taken during the excursion."""
    rows = []
    for L in levels_cm:
        for start, end in crossings(stage, L):
            hits = [up for ts, v, up in delivered if start <= ts <= end and v >= L]
            det = min(hits) if hits else None
            rows.append({"level_cm": L, "cross_min": start, "detected_min": det,
                         "delay_min": None if det is None else det - start})
    n = len(rows)
    missed = sum(r["detected_min"] is None for r in rows)
    delays = [r["delay_min"] for r in rows if r["delay_min"] is not None]
    delayed = sum(x > tol_min for x in delays)
    return {"crossings": n, "missed": missed, "delayed": delayed, "on_time": n - missed - delayed,
            "mean_delay_min": float(np.mean(delays)) if delays else math.nan,
            "max_delay_min": float(max(delays)) if delays else math.nan, "events": rows}


def run(cfg: dict, actions_cfg: dict, root: Path) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    s = load_series(root / cfg["series"]["file"], cfg["series"]["ft_to_cm"])
    stage = to_minutes(s)
    cat = ev.catalogue_from_config(actions_cfg)
    env = ev.envelope_from_config(actions_cfg)  # routine renewal assumed to succeed: validity never lapses
    fw = ev.firmware_policy_from_config(actions_cfg)
    cfg = {**cfg, "_profile_inv": ev.invariants_from_config(actions_cfg)}
    levels = [x * cfg["series"]["ft_to_cm"] for x in cfg["harm"]["reference_levels_ft"]]
    rows, events = [], []
    for scheme in cfg["schemes"]:
        for comp in cfg["compromises"]:
            runs = ([(None, v) for v in cfg["legit_policy"].get("variants", ["naive"])] if comp == "none"
                    else [(x, "-") for x in cfg["attacker"]["strategies"]])
            for strat, variant in runs:
                r = simulate(stage, scheme, comp, strat, cfg, cat, env, fw, variant if strat is None else "naive")
                sc = score(stage, r["delivered"], levels, cfg["harm"]["delay_tolerance_min"])
                st = r["stats"]
                rows.append({"scheme": scheme, "compromise": comp, "strategy": strat or "-", "legit_policy": variant,
                             **{k: sc[k] for k in ("crossings", "missed", "delayed", "on_time", "mean_delay_min",
                                                   "max_delay_min")},
                             "floor_violating_uplinks": st["floor_violating_uplinks"],
                             "battery_floor_violated": st["floor_violating_uplinks"] > 0 or st["died_min"] is not None,
                             "hours_below_floor": st["minutes_below_floor"] / 60,
                             "min_soc_pct": st["min_soc_pct"], "died": st["died_min"] is not None,
                             "died_h": None if st["died_min"] is None else st["died_min"] / 60,
                             "uplinks": st["uplinks"], "legit_sent": st["legit_sent"],
                             "legit_rejected": st["legit_rejected"],
                             "legit_rejection_rate": (st["legit_rejected"] / st["legit_sent"]) if st["legit_sent"] else 0.0,
                             "legit_intents": st["legit_intents"],
                             "legit_intents_rejected": st["legit_intents_rejected"],
                             "legit_unique_rejection_rate": (st["legit_intents_rejected"] / st["legit_intents"])
                             if st["legit_intents"] else 0.0,
                             "legit_reject_reasons": ";".join(f"{k}={v}" for k, v in sorted(st["reject_reasons"].items())),
                             "attacker_sent": st["attacker_sent"], "attacker_accepted": st["attacker_accepted"]})
                events += [{"scheme": scheme, "compromise": comp, "strategy": strat or "-", "legit_policy": variant, **e}
                           for e in sc["events"]]
    meta = {"gaps_over_60_min": gaps(s, 60), "n_readings": int(s.size), "first": str(s.index[0]), "last": str(s.index[-1]),
            "max_gap_min": max_gap_min(s), "peak_cm": float(s.max()), "peak_time": str(s.idxmax()),
            "minutes": int(stage.size), "uplink_charge_mAh": uplink_charge_mAh(cfg["battery"]),
            "levels_cm": levels}
    return pd.DataFrame(rows), pd.DataFrame(events), meta
