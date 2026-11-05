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

import dataclasses
import datetime as dt
import functools
import gzip
import itertools
import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from . import envelope as ev
from . import nws
from .config import load_yaml as load_yaml_file

KEY = bytes(range(64, 96))
TAG = 8


# ---------------------------------------------------------------- data
def _read_json(path: Path) -> dict:
    p = Path(path)
    return json.loads(gzip.decompress(p.read_bytes()) if p.suffix == ".gz" else p.read_text())


def load_series(path, ft_to_cm: float) -> pd.Series:
    """USGS NWIS IV JSON (optionally gzipped, or a list of files concatenated) -> stage (cm) indexed by UTC
    timestamp; noData values dropped; duplicate timestamps (overlapping files) keep the first reading."""
    if isinstance(path, (list, tuple)):
        s = pd.concat([load_series(p, ft_to_cm) for p in path])
        return s[~s.index.duplicated(keep="first")].sort_index()
    d = _read_json(path)
    if not d["value"]["timeSeries"]:
        return pd.Series([], index=pd.DatetimeIndex([], tz="UTC"), name="stage_cm", dtype=float)
    ts = d["value"]["timeSeries"][0]
    nodata = float(ts["variable"]["noDataValue"])
    pts = [(dt.datetime.fromisoformat(v["dateTime"]), float(v["value"])) for v in ts["values"][0]["value"]
           if float(v["value"]) != nodata]
    idx = pd.to_datetime([t for t, _ in pts], utc=True)   # series crossing DST mix UTC offsets: normalise to UTC
    s = pd.Series([v for _, v in pts], index=idx, name="stage_cm") * ft_to_cm
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
def battery_from_profile(prof: dict, devices: dict) -> dict:
    """D5: battery parameters from the manufacturer catalogue (config/devices/*.yaml).

    model "charge":        capacity_mAh and sleep_uA from the manual; charge per uplink = tx current (manual,
                           at the profile's tx condition) x LoRa time-on-air of the manual's uplink payload
                           (+13 B LoRaWAN framing) at the profile's uplink PHY. Lower bound (RX windows, MCU and
                           probe power not documented).
    model "uplink_budget": the manual states how many uplinks one battery delivers; the battery is normalised to
                           that budget (capacity = 1, charge per uplink = 1/budget), sleep drain neglected.
    """
    from .radio import LoraPhy, MacOverhead, time_on_air_s  # noqa: PLC0415
    b = devices[prof["device"]].battery
    if prof["model"] == "charge":
        tx = next(x["value"] for x in b["tx_mA"] if x["condition"] == prof["tx_condition"])
        u = prof["uplink_phy"]
        phy = LoraPhy(sf=u["sf"], bw_hz=u["bw_khz"] * 1e3, cr=u["cr"], preamble=u["preamble"], crc_on=u["crc_on"])
        pl = MacOverhead().phy_payload(b["uplink_payload_bytes"]["value"])
        toa = time_on_air_s(pl, phy)
        return {"name": prof["name"], "capacity": float(b["capacity_mAh"]["value"]), "sleep_per_h": b["sleep_uA"]["value"] / 1e3,
                "q": tx * toa / 3600, "unit": "mAh", "tx_mA": tx, "uplink_toa_s": toa, "phy_payload_bytes": pl,
                "lower_bound": True}
    if prof["model"] == "uplink_budget":
        n = next(x["value"] for x in b["uplinks_per_battery"] if x["condition"] == prof["condition"])
        return {"name": prof["name"], "capacity": 1.0, "sleep_per_h": 0.0, "q": 1.0 / n, "unit": "battery fraction",
                "uplinks_per_battery": n, "lower_bound": False}
    raise ValueError(prof["model"])


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

    def __init__(self, name: str, cat, env: ev.Policy, fw: ev.Policy, replaced: bool, op_key: bool = False,
                 max_alert_threshold: int = 0):
        self.name, self.cat, self.op_key, self.max_alert_threshold = name, cat, op_key, max_alert_threshold
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
        """S6+F non-updatable firmware floor (profile invariants + F3 write-once commissioning bound on the alert
        threshold); none for the other schemes."""
        if self.name != "S6+F":
            return ev.NO_INVARIANTS
        return dataclasses.replace(self.fw.invariants, max_alert_threshold=self.max_alert_threshold)

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
def epoch_budget(bat: dict, cfg: dict, floor_pct: float, eb: dict) -> int:
    """G3 (POLICY, derived from ASSUMED values): command-caused uplinks allowed per epoch. Chosen so that a device
    that spends its whole budget in every epoch of the planning horizon, on top of its default schedule, still ends
    the horizon above the battery floor: (charge above the floor - sleep drain over the horizon) / charge per uplink,
    spread over the epochs, minus the default-schedule uplinks of one epoch. Firmware alert uplinks and the
    alert-mode minimum rate are never charged to the budget (they are the purpose of the device)."""
    hours = eb["horizon_d"] * 24
    above = bat["capacity"] * (cfg["battery"]["initial_soc_pct"] - floor_pct) / 100 - bat["sleep_per_h"] * hours
    per_epoch = above / bat["q"] / (hours / eb["epoch_h"])
    default = eb["epoch_h"] * 60 / cfg["device"]["default_reporting_interval_min"]
    return max(0, math.floor(per_epoch - default))


def simulate(stage: np.ndarray, scheme: str, compromise: str, strategy: str | None, cfg: dict, cat,
             env: ev.Policy, fw: ev.Policy, legit_variant: str = "naive", bat: dict | None = None,
             budget: int | None = None) -> dict:
    """`budget` (G3): command-caused uplinks allowed per epoch of cfg["energy_budget"]["epoch_h"] (None = no budget).
    An uplink is command-caused if it is requested by `request_immediate_uplink` or comes sooner than the default
    reporting interval would (with the alert-mode and low-battery invariants applied). With no budget left in the
    epoch the device keeps the default schedule and drops immediate-uplink requests; firmware alerts always go."""
    dv = cfg["device"]
    bat = bat or cfg["_battery"]
    sch = Scheme(scheme, cat, env, fw, replaced=compromise.startswith("C1+C3"), op_key=compromise.endswith("+OP"),
                 max_alert_threshold=cfg.get("_max_alert_threshold", 0))
    inv, floor = sch.invariants, sch.floor
    cap, q_tx, sleep_per_min = bat["capacity"], bat["q"], bat["sleep_per_h"] / 60
    d = Dev(dv["default_reporting_interval_min"], dv["alert_threshold_cm"],
            soc_mAh=cap * cfg["battery"]["initial_soc_pct"] / 100)
    ia = cat[ev.A_INTERVAL]
    legit = LegitPolicy(cfg["legit_policy"], legit_variant, ia.min, ia.max) if compromise == "none" else None
    prof = cfg["_profile_inv"]                                       # scored against the PROFILE invariants, all schemes
    cfg_floor = cap * prof.battery_floor_pct / 100
    cmd_pending = alert_pending = False
    epoch_min = int(cfg["energy_budget"]["epoch_h"] * 60) if budget is not None else 0
    cur_epoch, tokens = -1, 0
    last_rejected = last_sent = None
    stats = {"budget_used": 0, "budget_denied_requests": 0, "legit_intents": 0, "legit_intents_rejected": 0, "floor_violating_uplinks": 0, "uplinks": 0, "legit_sent": 0, "legit_rejected": 0, "attacker_sent": 0, "attacker_accepted": 0,
             "minutes_below_floor": 0, "died_min": None, "min_soc_pct": 100.0}
    delivered: list[tuple[int, float, int]] = []                     # (sample minute, value, uplink minute)
    reject_reasons: dict[str, int] = {}
    for t in range(len(stage)):
        d.soc_mAh -= sleep_per_min
        if d.soc_mAh <= 0:
            stats["died_min"] = t
            break
        soc_pct = 100 * d.soc_mAh / cap
        stats["min_soc_pct"] = min(stats["min_soc_pct"], soc_pct)
        stats["minutes_below_floor"] += d.soc_mAh < cfg_floor
        if t % dv["sample_period_min"] == 0:
            if d.enabled:
                v = float(stage[t])
                d.buffer.append((t, v))
                now_alert = v >= d.threshold
                if now_alert and not d.alert:
                    d.pending = alert_pending = True                # firmware alert -> immediate uplink
                d.alert = now_alert
            else:
                d.alert = False
        eff = effective_interval(effective_interval(d.interval, d.alert, soc_pct, inv), d.alert, soc_pct, floor)
        since = t - d.last_uplink
        if since < dv["min_uplink_spacing_min"] or not (d.pending or since >= eff):
            continue
        if budget is not None:                                      # G3: energy budget per epoch
            if t // epoch_min != cur_epoch:
                cur_epoch, tokens = t // epoch_min, budget
            base = effective_interval(effective_interval(dv["default_reporting_interval_min"], d.alert, soc_pct, inv),
                                      d.alert, soc_pct, floor)
            if not (alert_pending or since >= base):
                if tokens <= 0:
                    if cmd_pending:
                        stats["budget_denied_requests"] += 1
                        d.pending = cmd_pending = False
                    continue
                tokens -= 1
                stats["budget_used"] += 1
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
        d.buffer, d.last_uplink, d.pending, alert_pending = [], t, False, False
        # ---- one downlink opportunity
        st = _dstate(d, 100 * d.soc_mAh / cap, t)
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


def select_events(s: pd.Series, k: int, sep_days: float, half_window_days: float) -> list[dict]:
    """D4 rule: the k highest stage peaks of the series that are at least `sep_days` apart; each event is the
    window peak +- half_window_days. Deterministic, no hand-picked dates."""
    picked = []
    for t, v in s.sort_values(ascending=False, kind="stable").items():
        if all(abs((t - p).total_seconds()) >= sep_days * 86400 for p, _ in picked):
            picked.append((t, v))
        if len(picked) == k:
            break
    w = pd.Timedelta(days=half_window_days)
    return [{"peak_time": t, "peak": v, "start": t - w, "end": t + w} for t, v in picked]


def select_events_above(s: pd.Series, level: float, sep_h: float, before_d: float, after_d: float) -> list[dict]:
    """F5 pre-registered rule (config/events_prereg.yaml): candidate peaks = maximum of each maximal run of readings
    >= level; accepted greedily by descending peak if >= sep_h from every accepted peak; window
    [peak - before_d, peak + after_d]. Returned in time order."""
    above = (s >= level).to_numpy()
    if not above.any():
        return []
    run_id = np.cumsum(np.r_[True, above[1:] != above[:-1]])
    cand = [g.idxmax() for _, g in s[above].groupby(run_id[above])]
    picked: list = []
    for t in sorted(cand, key=lambda t: (-s[t], t)):
        if all(abs((t - p).total_seconds()) >= sep_h * 3600 for p in picked):
            picked.append(t)
    return [{"peak_time": t, "peak": float(s[t]), "start": t - pd.Timedelta(days=before_d),
             "end": t + pd.Timedelta(days=after_d)} for t in sorted(picked)]


@functools.lru_cache(maxsize=16)
def _cached_series(files: tuple, ft_to_cm: float) -> pd.Series:
    return load_series(list(files), ft_to_cm)


def prereg_events(cfg: dict, root: Path) -> list[dict]:
    """Events selected by the F5 pre-registered rule from the cached multi-year series."""
    pr = load_yaml_file(root / cfg["events_prereg"]["file"])
    rule, n = pr["rule"], cfg["nws"]
    out = []
    for g in pr["gauges"]:
        cats = nws.load(root / n["dir"], g["usgs"], rule["datum_tolerance_ft"])
        files = tuple(str(p.relative_to(root)) for p in
                      sorted((root / cfg["events_prereg"]["data_dir"]).glob(f"usgs_{g['usgs']}_*.json.gz")))
        if not cats["datum_ok"] or cats["minor"] is None or not files:
            continue
        s = _cached_series(tuple(str(root / f) for f in files), cfg["series"]["ft_to_cm"])
        y0, y1 = pr["period"]["start"], pr["period"]["end"]
        s = s[(s.index >= pd.Timestamp(y0, tz="UTC")) & (s.index < pd.Timestamp(y1, tz="UTC") + pd.Timedelta(days=1))]
        for e in select_events_above(s, cats["minor"] * cfg["series"]["ft_to_cm"], rule["separation_h"],
                                     rule["window"]["before_peak_d"], rule["window"]["after_peak_d"]):
            years = range(e["start"].year, e["end"].year + 1)        # only the yearly files the window touches
            ef = [f for f in files if any(f"_{y}-01-01_" in f for y in years)]
            out.append({"name": f"USGS {g['usgs']} {g['site']} ({e['peak_time']:%Y-%m-%d})", "files": ef,
                        "start": str(e["start"]), "end": str(e["end"]), "usgs": g["usgs"]})
    return out


def event_list(cfg: dict, root: Path | None = None) -> list[dict]:
    """Events to replay: F5 pre-registered (`events_prereg`), rule-selected (D4 `events_rule`), explicit `events`,
    or the single legacy `series`."""
    if cfg.get("events_prereg"):
        return prereg_events(cfg, root)
    rule = cfg.get("events_rule")
    if rule:
        out = []
        for g in rule["gauges"]:
            s = load_series(root / g["file"], cfg["series"]["ft_to_cm"])
            for i, e in enumerate(select_events(s, rule["top_k"], rule["separation_days"], rule["half_window_days"]), 1):
                out.append({"name": f"{g['site']} peak {i} ({e['peak_time']:%Y-%m-%d})", "file": g["file"],
                            "start": str(e["start"]), "end": str(e["end"]), "usgs": g.get("usgs")})
        return out
    if cfg.get("events"):
        return cfg["events"]
    return [{"name": "Buffalo Bayou 08074000 (Harvey)", "file": cfg["series"]["file"], "start": None, "end": None}]


def relative_profile(actions_cfg: dict, stage: np.ndarray, rel: dict) -> tuple[dict, int]:
    """D4 fallback: the legitimate alert threshold and the envelope threshold band are fractions of the event's
    own stage range (ASSUMED fractions)."""
    lo, hi = float(stage.min()), float(stage.max())
    at = lambda f: int(round(lo + f * (hi - lo)))  # noqa: E731
    return threshold_profile(actions_cfg, (at(rel["envelope_band"][0]), at(rel["envelope_band"][1]))), \
        at(rel["alert_fraction"])


def threshold_profile(actions_cfg: dict, band_cm: tuple[int, int]) -> dict:
    """Actions profile with the envelope band for set_alert_threshold replaced by `band_cm`; S4-F firmware threshold
    bounds become the full catalogue range (static firmware cannot know the river)."""
    a = {**actions_cfg, "envelope": {**actions_cfg["envelope"], "rules": dict(actions_cfg["envelope"]["rules"])},
         "firmware_bounds": {**actions_cfg["firmware_bounds"], "rules": dict(actions_cfg["firmware_bounds"]["rules"])}}
    r = a["envelope"]["rules"]["set_alert_threshold"]
    a["envelope"]["rules"]["set_alert_threshold"] = {**r, "lo": int(band_cm[0]), "hi": int(band_cm[1])}
    c = actions_cfg["catalogue"]["set_alert_threshold"]
    a["firmware_bounds"]["rules"]["set_alert_threshold"] = {**a["firmware_bounds"]["rules"]["set_alert_threshold"],
                                                            "lo": c["min"], "hi": c["max"]}
    return a


def nws_thresholds(cats: dict, ft_to_cm: float) -> dict | None:
    """F4: scoring levels, legitimate alert threshold and envelope band from the NWS flood categories.
    levels = every category NWS defines; alert = action stage (choice); envelope band (POLICY) =
    [action - (minor - action), minor]. None if NWS gives no action or minor stage, or the datum check failed."""
    if not cats.get("datum_ok") or cats.get("action") is None or cats.get("minor") is None:
        return None
    cm = lambda ft: int(round(ft * ft_to_cm))  # noqa: E731
    a, m = cats["action"], cats["minor"]
    return {"levels_cm": [ft * ft_to_cm for ft in (cats[k] for k in nws.CATEGORIES) if ft is not None],
            "level_names": [k for k in nws.CATEGORIES if cats[k] is not None],
            "alert_cm": cm(a), "band_cm": (cm(a - (m - a)), cm(m)), "source": f"NWS {cats['lid']}"}


def event_stage(ev_: dict, cfg: dict, root: Path) -> tuple[np.ndarray, pd.Series]:
    if ev_.get("files"):
        s = _cached_series(tuple(str(root / f) for f in ev_["files"]), cfg["series"]["ft_to_cm"])
    else:
        s = load_series(root / ev_["file"], cfg["series"]["ft_to_cm"])
    if ev_.get("start"):
        s = s[(s.index >= pd.Timestamp(ev_["start"], tz=s.index.tz)) & (s.index <= pd.Timestamp(ev_["end"], tz=s.index.tz))]
    return to_minutes(s), s


def _event(args) -> tuple[list, list, dict]:
    """Replay one event over the whole grid (top-level so it can run in a worker process)."""
    ev_, cfg, actions_cfg, root, bats = args
    cat = ev.catalogue_from_config(actions_cfg)
    env = ev.envelope_from_config(actions_cfg)  # routine renewal assumed to succeed: validity never lapses
    fw = ev.firmware_policy_from_config(actions_cfg)
    rel = cfg["harm"].get("relative")
    nws_cfg = cfg.get("nws")
    rows, events, metas = [], [], []
    stage, s = event_stage(ev_, cfg, root)
    ecfg = cfg
    th = None
    if nws_cfg and ev_.get("usgs") and (root / nws_cfg["dir"] / f"{ev_['usgs']}.json").exists():
        th = nws_thresholds(nws.load(root / nws_cfg["dir"], ev_["usgs"], nws_cfg["datum_tol_ft"]),
                            cfg["series"]["ft_to_cm"])
    if th:
        acfg_e = threshold_profile(actions_cfg, th["band_cm"])
        env, fw = ev.envelope_from_config(acfg_e), ev.firmware_policy_from_config(acfg_e)
        ecfg = {**cfg, "device": {**cfg["device"], "alert_threshold_cm": th["alert_cm"]}}
        if (cfg.get("commissioning") or {}).get("max_alert_threshold") == "nws_action":
            ecfg["_max_alert_threshold"] = th["alert_cm"]          # F3: write-once, = NWS action stage
        levels, level_src = th["levels_cm"], th["source"]
    else:
        if rel:
            acfg_e, alert = relative_profile(actions_cfg, stage, rel)
            env, fw = ev.envelope_from_config(acfg_e), ev.firmware_policy_from_config(acfg_e)
            ecfg = {**cfg, "device": {**cfg["device"], "alert_threshold_cm": alert}}
        # reference levels: absolute (ft) when given, else fractions of the event's own stage range (ASSUMED)
        if cfg["harm"].get("reference_levels_ft"):
            levels = [x * cfg["series"]["ft_to_cm"] for x in cfg["harm"]["reference_levels_ft"]]
            level_src = "reference_levels_ft (ASSUMED)"
        else:
            lo, hi = float(stage.min()), float(stage.max())
            levels = [lo + f * (hi - lo) for f in cfg["harm"]["reference_level_fractions"]]
            level_src = "fractions of event range (ASSUMED)"
    metas.append({"event": ev_["name"], "file": ev_.get("file"), "files": ev_.get("files") or [ev_["file"]], "n_readings": int(s.size), "first": str(s.index[0]),
                  "last": str(s.index[-1]), "max_gap_min": max_gap_min(s), "gaps_over_60_min": gaps(s, 60),
                  "peak_cm": float(s.max()), "peak_time": str(s.idxmax()),
                  "alert_threshold_cm": ecfg["device"]["alert_threshold_cm"],
                  "peak_bracketed_by_gap": any(g["after"] <= str(s.idxmax()) <= g["before"] for g in gaps(s, 60)),
                  "minutes": int(stage.size), "levels_cm": levels, "threshold_source": level_src,
                  "commissioning_max_alert_threshold_cm": ecfg.get("_max_alert_threshold", 0),
                  "level_names": th["level_names"] if th else None})
    eb = cfg.get("energy_budget")
    prof_floor = cfg["_profile_inv"].battery_floor_pct
    for bat in bats:
        bud = epoch_budget(bat, cfg, prof_floor, eb) if eb else None
        for scheme in cfg["schemes"]:
            budgets = ["off"] + (["on"] if eb and "on" in eb["variants"] and scheme in eb["schemes"] else [])
            for comp, ebv in itertools.product(cfg["compromises"], budgets):
                runs = ([(None, v) for v in cfg["legit_policy"].get("variants", ["naive"])] if comp == "none"
                        else [(x, "-") for x in cfg["attacker"]["strategies"]])
                # the budget lives in the envelope (lost when C3 lets the attacker replace it) and, for the schemes
                # in `in_floor`, also in the write-once commissioning floor (survives C1+C3)
                b = bud if ebv == "on" and (not comp.startswith("C1+C3") or scheme in eb["in_floor"]) else None
                for strat, variant in runs:
                    r = simulate(stage, scheme, comp, strat, ecfg, cat, env, fw,
                                 variant if strat is None else "naive", bat, b)
                    sc = score(stage, r["delivered"], levels, cfg["harm"]["delay_tolerance_min"])
                    st = r["stats"]
                    key = {"event": ev_["name"], "battery_profile": bat["name"], "scheme": scheme,
                           "compromise": comp, "strategy": strat or "-", "legit_policy": variant,
                           "energy_budget": ebv}
                    rows.append({**key, **{k: sc[k] for k in ("crossings", "missed", "delayed", "on_time",
                                                              "mean_delay_min", "max_delay_min")},
                                 "floor_violating_uplinks": st["floor_violating_uplinks"],
                                 "battery_floor_violated": st["floor_violating_uplinks"] > 0 or st["died_min"] is not None,
                                 "hours_below_floor": st["minutes_below_floor"] / 60,
                                 "min_soc_pct": st["min_soc_pct"], "died": st["died_min"] is not None,
                                 "died_h": None if st["died_min"] is None else st["died_min"] / 60,
                                 "uplinks": st["uplinks"], "legit_sent": st["legit_sent"],
                                 "legit_rejected": st["legit_rejected"], "legit_intents": st["legit_intents"],
                                 "legit_intents_rejected": st["legit_intents_rejected"],
                                 "legit_unique_rejection_rate": (st["legit_intents_rejected"] / st["legit_intents"])
                                 if st["legit_intents"] else 0.0,
                                 "legit_reject_reasons": ";".join(f"{k}={v}" for k, v in sorted(st["reject_reasons"].items())),
                                 "attacker_sent": st["attacker_sent"], "attacker_accepted": st["attacker_accepted"],
                                 "epoch_budget_uplinks": b, "budget_used": st["budget_used"],
                                 "budget_denied_requests": st["budget_denied_requests"]})
                    events += [{**key, **e} for e in sc["events"]]
    return rows, events, metas[0]


def run(cfg: dict, actions_cfg: dict, root: Path) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    from .devices import load_catalogue  # noqa: PLC0415
    devs = {d.model: d for d in load_catalogue(root / "config/devices")}
    bats = [battery_from_profile(p, devs) for p in cfg["battery"]["profiles"]]
    cfg = {**cfg, "_profile_inv": ev.invariants_from_config(actions_cfg)}
    jobs = [(e, cfg, actions_cfg, root, bats) for e in event_list(cfg, root)]
    workers = int(cfg.get("workers", 1))
    if workers > 1:
        from concurrent.futures import ProcessPoolExecutor  # noqa: PLC0415
        with ProcessPoolExecutor(max_workers=workers) as ex:
            out = list(ex.map(_event, jobs))
    else:
        out = [_event(j) for j in jobs]
    rows = [r for o in out for r in o[0]]
    events = [e for o in out for e in o[1]]
    metas = [o[2] for o in out]
    eb = cfg.get("energy_budget")
    if eb:
        bats = [{**b, "epoch_budget_uplinks": epoch_budget(b, cfg, cfg["_profile_inv"].battery_floor_pct, eb)}
                for b in bats]
    meta = {"events": metas, "battery_profiles": bats}
    return pd.DataFrame(rows), pd.DataFrame(events), meta


# ---------------------------------------------------------------- D4 statistics
def _keys(df: pd.DataFrame) -> list[str]:
    return ["battery_profile", "scheme", "compromise", "strategy", "legit_policy"] + \
        (["energy_budget"] if "energy_budget" in df else [])

METRICS = ("missed_frac", "delayed_frac", "max_delay_min", "floor_violating_uplinks", "died",
           "legit_unique_rejection_rate")


def bootstrap_ci(x: np.ndarray, n_boot: int, seed: int, alpha: float = 0.05) -> tuple[float, float, float]:
    """Median and percentile-bootstrap (1-alpha) CI of the median over events. NaNs are dropped."""
    x = np.asarray(x, dtype=float)
    x = x[~np.isnan(x)]
    if x.size == 0:
        return (math.nan, math.nan, math.nan)
    rng = np.random.default_rng(seed)
    meds = np.median(rng.choice(x, size=(n_boot, x.size), replace=True), axis=1)
    return float(np.median(x)), float(np.quantile(meds, alpha / 2)), float(np.quantile(meds, 1 - alpha / 2))


def summarize_events(df: pd.DataFrame, n_boot: int, seed: int) -> pd.DataFrame:
    d = df.assign(missed_frac=df.missed / df.crossings.where(df.crossings > 0),
                  delayed_frac=df.delayed / df.crossings.where(df.crossings > 0), died=df.died.astype(float))
    keys = _keys(d)
    rows = []
    for k, g in d.groupby(keys, sort=False):
        r = dict(zip(keys, k))
        r["events"] = int(g.event.nunique())
        for m in METRICS:
            med, lo, hi = bootstrap_ci(g[m].to_numpy(), n_boot, seed)
            r.update({f"{m}_median": med, f"{m}_ci_lo": lo, f"{m}_ci_hi": hi})
        rows.append(r)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- F5 delay distributions
def _weighted_quantile_rows(v_sorted: np.ndarray, w: np.ndarray, q: float) -> np.ndarray:
    """Row-wise weighted quantile of sorted values v for a weight matrix w (B x N): the smallest value whose
    cumulative weight reaches q x total (inverse empirical CDF; the same rule for point estimates and bootstrap)."""
    cw = np.cumsum(w, axis=1)
    idx = (cw >= q * cw[:, -1:]).argmax(axis=1)
    return v_sorted[idx]


def storm_clusters(peaks: dict, window_h: float) -> dict:
    """G4: events whose peaks lie within `window_h` of each other, on any gauge, share a storm cluster. Single
    linkage: sorted by peak time, a new cluster starts after a gap longer than the window (so chains of events
    each within the window of the next form one cluster). Returns event -> cluster index."""
    out, cid, last = {}, -1, None
    for name in sorted(peaks, key=lambda n: (pd.Timestamp(peaks[n]), n)):
        t = pd.Timestamp(peaks[name])
        if last is None or (t - last).total_seconds() > window_h * 3600:
            cid += 1
        out[name], last = cid, t
    return out


def _units(g: pd.DataFrame, clusters: dict | None) -> tuple[np.ndarray, int]:
    """Resampling unit of each row: its storm cluster (G4) when given, else its event."""
    lab = g.event.map(clusters).to_numpy() if clusters else g.event.to_numpy()
    codes, idx = np.unique(lab, return_inverse=True)
    return idx, len(codes)


def delay_distribution(evdf: pd.DataFrame, tol_min: float, n_boot: int, seed: int, alpha: float = 0.05,
                       clusters: dict | None = None) -> pd.DataFrame:
    """F5 (pre-registered): per scheme x compromise x strategy x battery profile x legit policy (x energy budget),
    the median, p90 and max detection delay over ALL crossings (missed = +inf) and the share of crossings delayed
    beyond `tol_min` or missed, each with a percentile-bootstrap CI. The bootstrap resamples whole storm clusters
    (G4, `clusters`: event -> cluster) or, without them, events."""
    keys = _keys(evdf)
    rng = np.random.default_rng(seed)
    rows = []
    for k, g in evdf.groupby(keys, sort=False):
        d = g.delay_min.astype(float).fillna(np.inf).to_numpy()
        ev_idx, n_units = _units(g, clusters)
        order = np.argsort(d, kind="stable")
        v, e = d[order], ev_idx[order]
        counts = rng.multinomial(n_units, np.full(n_units, 1 / n_units), size=n_boot)
        w = counts[:, e].astype(float)
        bad = (v > tol_min).astype(float)
        boot = {"median": _weighted_quantile_rows(v, w, 0.5), "p90": _weighted_quantile_rows(v, w, 0.9),
                "max": np.where(w > 0, v, -np.inf).max(axis=1),
                "late_or_missed_share": (w * bad).sum(axis=1) / w.sum(axis=1)}
        one = np.ones((1, len(v)))
        point = {"median": float(_weighted_quantile_rows(v, one, 0.5)[0]), "p90": float(_weighted_quantile_rows(v, one, 0.9)[0]),
                 "max": float(v[-1]), "late_or_missed_share": float(bad.mean())}
        r = {**dict(zip(keys, k)), "events": int(g.event.nunique()), "resampling_units": n_units,
             "crossings": len(d), "missed": int(np.isinf(d).sum())}
        for m, x in boot.items():
            r[f"{m}_delay_min" if m != "late_or_missed_share" else m] = point[m]
            lo, hi = np.quantile(x, [alpha / 2, 1 - alpha / 2], method="lower")
            base = f"{m}_delay_min" if m != "late_or_missed_share" else m
            r[f"{base}_ci_lo"], r[f"{base}_ci_hi"] = float(lo), float(hi)
        rows.append(r)
    return pd.DataFrame(rows)


def excess_over_baseline(evdf: pd.DataFrame, tol_min: float, n_boot: int, seed: int, alpha: float = 0.05,
                         clusters: dict | None = None, baseline_policy: str = "naive") -> pd.DataFrame:
    """Attack effect relative to legitimate operation: for every attacked condition, late-or-missed share minus the
    share of the legitimate baseline (compromise "none", `baseline_policy`) of the same battery profile, scheme and
    energy budget. Crossings are paired (same event, level, crossing minute), so crossings the baseline already
    misses count as baseline. CI: paired percentile bootstrap over storm clusters (or events)."""
    keys = _keys(evdf)
    grp = [k for k in keys if k not in ("compromise", "strategy", "legit_policy")]
    pair = ["event", "level_cm", "cross_min"]
    bad = evdf.assign(bad=(evdf.delay_min.astype(float).fillna(np.inf) > tol_min).astype(float))
    rng = np.random.default_rng(seed)
    rows = []
    for gk, g in bad.groupby(grp, sort=False):
        base = g[(g.compromise == "none") & (g.legit_policy == baseline_policy)][pair + ["bad"]]
        for k, a in g[g.compromise != "none"].groupby(keys, sort=False):
            m = a[pair + ["bad"]].merge(base, on=pair, suffixes=("", "_base"))
            if m.empty:
                continue
            idx, n_units = _units(m, clusters)
            diff = (m.bad - m.bad_base).to_numpy()
            w = rng.multinomial(n_units, np.full(n_units, 1 / n_units), size=n_boot)[:, idx].astype(float)
            boot = (w * diff).sum(axis=1) / w.sum(axis=1)
            lo, hi = np.quantile(boot, [alpha / 2, 1 - alpha / 2])
            rows.append({**dict(zip(keys, k)), "crossings": len(m), "resampling_units": n_units,
                         "baseline_share": float(m.bad_base.mean()), "attack_share": float(m.bad.mean()),
                         "excess": float(diff.mean()), "excess_ci_lo": float(lo), "excess_ci_hi": float(hi)})
    return pd.DataFrame(rows)
