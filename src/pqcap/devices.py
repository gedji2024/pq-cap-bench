"""Manufacturer device catalogue (config/devices/*.yaml) and policy-swept blast radius.

Each device lists the downlink commands mapped to our actions, with parameter dims (unit, documented or
encoding range). Envelope bounds come from POLICY levels (config/policies.yaml).

Blast radius = number of distinct command payloads (action x parameter values) the device would accept.
Acceptance is decided by the pure `accepts` check; counts are exact and obtained by evaluating `accepts`
once per cell of the partition induced by every bound that appears in the check (domain, policy,
invariants), then multiplying by the cell's volume -- acceptance is constant within a cell because every
condition is an axis-aligned interval test. Property tests compare with brute-force enumeration.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from .config import load_yaml

UNIT_PER_MIN = {"s": 60, "min": 1}


@dataclass(frozen=True)
class Dim:
    name: str
    unit: str
    lo: int
    hi: int
    range_source: str


@dataclass(frozen=True)
class DevAction:
    action: str
    command: str
    payload_bytes: int
    dims: tuple[Dim, ...]
    default: int | None


@dataclass(frozen=True)
class Device:
    model: str
    manufacturer: str
    fport: int | None
    actions: tuple[DevAction, ...]
    battery: dict = field(default_factory=dict, hash=False, compare=False)
    docs: dict = field(default_factory=dict, hash=False, compare=False)

    def action(self, name: str) -> DevAction | None:
        return next((a for a in self.actions if a.action == name), None)


def _int(v) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"expected an integer, got {v!r}")
    return v


def load_device(path: Path) -> Device:
    y = load_yaml(path)
    acts = []
    for a in y["actions"]:
        dims = tuple(Dim(d["name"], d["unit"], _int(d["min"]), _int(d["max"]), d["range_source"]) for d in a["dims"])
        for d in dims:
            if d.lo > d.hi:
                raise ValueError(f"{path.name}: {a['action']}.{d.name} min > max")
        dflt = a.get("default", {}).get("value") if a.get("default") else None
        acts.append(DevAction(a["action"], a["command"], _int(a["payload_bytes"]), dims, dflt))
    return Device(y["device"]["model"], y["device"]["manufacturer"], y["downlink_fport"]["value"], tuple(acts),
                  y.get("battery", {}), y["docs"])


def load_catalogue(directory: Path) -> list[Device]:
    return [load_device(p) for p in sorted(Path(directory).glob("*.yaml"))]


def domain_size(a: DevAction) -> int:
    return math.prod(d.hi - d.lo + 1 for d in a.dims) if a.dims else 1


# ---------------------------------------------------------------- policies
Box = tuple[tuple[int, int], ...]          # per-dim inclusive (lo, hi)
Policy = dict[str, Box]                    # allowed action -> box


def window(d: Dim, fraction: float, default: int | None) -> tuple[int, int]:
    span = d.hi - d.lo + 1
    n = max(1, math.ceil(fraction * span))
    if d.unit in ("enum", "flag", "n", "DR") or default is None:
        lo = d.lo
    else:
        lo = min(max(d.lo, default - n // 2), d.hi - n + 1)
    return lo, lo + n - 1


def policy_for(dev: Device, level: dict) -> Policy:
    out = {}
    for a in dev.actions:
        if a.action in level["allow"]:
            out[a.action] = tuple(window(d, level["fraction"], a.default if i == 0 else None)
                                  for i, d in enumerate(a.dims))
    return out


def full_policy(dev: Device) -> Policy:
    return {a.action: tuple((d.lo, d.hi) for d in a.dims) for a in dev.actions}


# ---------------------------------------------------------------- acceptance
@dataclass(frozen=True)
class Context:
    has_session_key: bool
    policy: Policy | None          # None = no device-side bounds (S4)
    invariants: dict | None        # None = no invariants
    pdp_policy: Policy | None = None   # C0: proposals filtered by an honest PDP
    op_required: tuple[str, ...] = ()  # actions that need an OP token (S6+F, D2)
    has_op_token: bool = False
    floor: dict | None = None      # non-updatable firmware floor invariants (S6+F, D2)


def _in_box(box: Box, values: tuple[int, ...]) -> bool:
    return all(lo <= v <= hi for (lo, hi), v in zip(box, values))


def _inv_ok(inv: dict | None, a: DevAction, values: tuple[int, ...], state: dict) -> bool:
    if not inv or a.action != "set_reporting_interval" or not a.dims:
        return True
    per_min = UNIT_PER_MIN[a.dims[0].unit]
    v = values[0]
    if state["battery_below_floor"] and inv.get("low_battery_min_interval_min"):
        if v < inv["low_battery_min_interval_min"] * per_min:
            return False
    if state["alert_active"] and inv.get("alert_max_interval_min"):
        if v > inv["alert_max_interval_min"] * per_min:
            return False
    return True


def _disable_ok(inv: dict | None, a: DevAction, state: dict) -> bool:
    return not (inv and inv.get("alert_forbid_disable") and state["alert_active"] and a.action == "alarm_disable")


def accepts(ctx: Context, a: DevAction, values: tuple[int, ...], state: dict) -> bool:
    if not ctx.has_session_key:
        return False
    if not all(d.lo <= v <= d.hi for d, v in zip(a.dims, values)):
        return False
    if ctx.pdp_policy is not None and not (a.action in ctx.pdp_policy and _in_box(ctx.pdp_policy[a.action], values)):
        return False
    if ctx.policy is not None and not (a.action in ctx.policy and _in_box(ctx.policy[a.action], values)):
        return False
    for inv in (ctx.invariants, ctx.floor):
        if not (_inv_ok(inv, a, values, state) and _disable_ok(inv, a, state)):
            return False
    if a.action in ctx.op_required and not ctx.has_op_token:
        return False
    return True


def _breaks(d: Dim, idx: int, a: DevAction, ctx: Context) -> list[int]:
    b = {d.lo, d.hi + 1}
    for pol in (ctx.policy, ctx.pdp_policy):
        if pol and a.action in pol:
            lo, hi = pol[a.action][idx]
            b |= {lo, hi + 1}
    if idx == 0 and a.action == "set_reporting_interval":
        per_min = UNIT_PER_MIN.get(d.unit, 1)
        for inv in (ctx.invariants, ctx.floor):
            if inv:
                for k, off in (("alert_max_interval_min", 1), ("low_battery_min_interval_min", 0)):
                    if inv.get(k):
                        b.add(inv[k] * per_min + off)
    return sorted(x for x in b if d.lo <= x <= d.hi + 1)


def count_accepted(ctx: Context, a: DevAction, state: dict) -> int:
    if not a.dims:
        return int(accepts(ctx, a, (), state))
    cells = []
    for i, d in enumerate(a.dims):
        b = _breaks(d, i, a, ctx)
        cells.append([(b[k], b[k + 1] - b[k]) for k in range(len(b) - 1)])
    total = 0
    for combo in itertools.product(*cells):
        if accepts(ctx, a, tuple(c[0] for c in combo), state):
            total += math.prod(c[1] for c in combo)
    return total


# ---------------------------------------------------------------- compromise sweep (K5/K6 on the catalogue)
SCHEMES = ("S4", "S4c", "S4-F", "S4-E", "S6", "S6+F")


def scheme_context(scheme: str, comp: dict, keys: set[str], dev_policy: Policy, fw_policy: Policy,
                   full: Policy, inv: dict, threat: dict) -> Context:
    session = "session" in keys or comp.get("honest_pdp_filters", False)
    pdp = dev_policy if comp.get("honest_pdp_filters") else None
    if scheme in ("S4", "S4c"):
        return Context(session, None, None, pdp)
    if scheme == "S4-F":
        return Context(session, fw_policy, inv, pdp)
    replaced = threat["envelope_key"].get(scheme) in keys
    if scheme == "S6+F":  # D2: the firmware floor survives envelope replacement; disable needs an OP token
        return Context(session, full if replaced else dev_policy, None if replaced else inv, pdp,
                       op_required=("alarm_disable",), has_op_token="op_approval" in keys, floor=inv)
    return Context(session, full if replaced else dev_policy, None if replaced else inv, pdp)


def blast_catalogue(devices: list[Device], policies: dict, threat: dict, inv: dict, state: dict) -> pd.DataFrame:
    rows = []
    fw_level = policies["levels"][policies["firmware_level"]]
    for dev in devices:
        full, fw = full_policy(dev), policy_for(dev, fw_level)
        cat = sum(domain_size(a) for a in dev.actions)
        for lvl_name, lvl in policies["levels"].items():
            pol = policy_for(dev, lvl)
            for comp, spec in threat["compromises"].items():
                keys = {k for p in spec["parties"] for k in threat["custody"][p]}
                for scheme in SCHEMES:
                    ctx = scheme_context(scheme, spec, keys, pol, fw, full, inv, threat)
                    per = {a.action: count_accepted(ctx, a, state) for a in dev.actions}
                    acc = sum(per.values())
                    rows.append({"device": dev.model, "policy": lvl_name, "compromise": comp, "scope": spec["scope"],
                                 "scheme": scheme, "accepted": acc, "catalogue": cat, "fraction": acc / cat,
                                 "action_types_accepted": sum(v > 0 for v in per.values()),
                                 "action_types": len(per),
                                 "type_coverage": sum(v > 0 for v in per.values()) / len(per),
                                 "accepted_types": ";".join(k for k, v in per.items() if v > 0)})
    return pd.DataFrame(rows)


def k5_k6_ranges(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    k5 = (df.groupby(["compromise", "scheme"], sort=False)
          .agg(fraction_min=("fraction", "min"), fraction_max=("fraction", "max"),
               type_coverage_min=("type_coverage", "min"), type_coverage_max=("type_coverage", "max"),
               accepted_min=("accepted", "min"), accepted_max=("accepted", "max"), cases=("fraction", "size"))
          .reset_index())
    p = df.pivot_table(index=["device", "policy", "compromise"], columns="scheme", values="accepted", sort=False)
    p = p.reset_index()
    p["ratio"] = [(e / s) if s else math.nan for e, s in zip(p["S4-E"], p["S6"])]
    p["both_zero"] = (p["S4-E"] == 0) & (p["S6"] == 0)
    k6 = (p.groupby("compromise", sort=False)
          .agg(ratio_min=("ratio", "min"), ratio_max=("ratio", "max"), both_zero_cases=("both_zero", "sum"),
               cases=("ratio", "size")).reset_index())
    return k5, k6


def run(config: Path) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    devs = load_catalogue(config / "devices")
    pol, thr, acfg = load_yaml(config / "policies.yaml"), load_yaml(config / "threat.yaml"), load_yaml(config / "actions.yaml")
    c = acfg.get("count_state", {"alert_active": True, "battery_above_floor": True})
    state = {"alert_active": c["alert_active"], "battery_below_floor": not c["battery_above_floor"]}
    df = blast_catalogue(devs, pol, thr, acfg["invariants"], state)
    k5, k6 = k5_k6_ranges(df)
    return df, k5, k6


# ---------------------------------------------------------------- F1: scope of the S4-E envelope MAC key under C4
def c4_key_scope(devices: list[Device], policies: dict, threat: dict, inv: dict, state: dict) -> pd.DataFrame:
    """Blast radius when one device is extracted (C4), alone or with C1, for both scopes of the S4-E
    envelope MAC key (`threat.yaml` s4e_key_scope): per-device, or one key shared by a group/fleet.

    target = "extracted": the extracted device itself (its session key and its envelope MAC key are known);
    target = "other": another device of the same group. Its session key is known only with C1; its S4-E
    envelope key only if the key is shared by the group. S6 envelopes need sk_PA, which C4 never yields.
    """
    rows = []
    fw_level = policies["levels"][policies["firmware_level"]]
    firmwares = list(threat.get("c4_firmware", {"variants": {"secure_boot": ""}})["variants"])
    for dev in devices:
        full, fw = full_policy(dev), policy_for(dev, fw_level)
        cat = sum(domain_size(a) for a in dev.actions)
        for lvl_name, lvl in policies["levels"].items():
            pol = policy_for(dev, lvl)
            for variant, firmware, comp, target in itertools.product(
                    threat["s4e_key_scope"]["variants"], firmwares, ("C4", "C1+C4"), ("extracted", "other")):
                keys = set()
                if target == "extracted" or comp == "C1+C4":
                    keys.add("session")
                if target == "extracted" or variant == "group":
                    keys.add("policy_mac")
                for scheme in ("S4-E", "S6"):
                    if firmware == "reflash" and target == "extracted":
                        ctx = Context(True, None, None)        # attacker firmware: no check at all
                    else:
                        ctx = scheme_context(scheme, {"scope": "one_device"}, keys, pol, fw, full, inv, threat)
                    acc = sum(count_accepted(ctx, a, state) for a in dev.actions)
                    rows.append({"device": dev.model, "policy": lvl_name, "key_scope": variant, "firmware": firmware,
                                 "compromise": comp, "target": target, "scheme": scheme, "accepted": acc,
                                 "catalogue": cat})
    return pd.DataFrame(rows)


def c4_k6(df: pd.DataFrame) -> pd.DataFrame:
    """K6 = blast(S4-E) / blast(S6) per key scope, firmware assumption (G2), compromise and target; ranges over
    devices x policies. `meaningful` is False where a reflashed extracted device accepts everything under every
    scheme (the ratio is then 1 by construction and says nothing about the schemes)."""
    if "firmware" not in df:
        df = df.assign(firmware="secure_boot")
    keys = ["key_scope", "firmware", "compromise", "target"]
    p = df.pivot_table(index=["device", "policy", *keys], columns="scheme", values="accepted", sort=False).reset_index()
    p["ratio"] = [(e / s) if s else math.nan for e, s in zip(p["S4-E"], p["S6"])]
    p["both_zero"] = (p["S4-E"] == 0) & (p["S6"] == 0)
    out = (p.groupby(keys, sort=False)
           .agg(ratio_min=("ratio", "min"), ratio_max=("ratio", "max"), both_zero_cases=("both_zero", "sum"),
                s4e_accepted_max=("S4-E", "max"), s6_accepted_max=("S6", "max"), cases=("ratio", "size"))
           .reset_index())
    out["meaningful"] = ~((out.firmware == "reflash") & (out.target == "extracted"))
    return out
