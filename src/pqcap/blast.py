"""Blast radius: how many catalogue commands a device ACCEPTS from an attacker.

Counts come from running every (action, target, value) candidate through the device-side check
(pqcap.envelope) with a valid tag and fresh counter -- not from a closed-form formula. Acceptance
is state-dependent (physical invariants), so every count is made in an explicit device state.
"""

from __future__ import annotations

import pandas as pd

from . import envelope as ev

ATTACKER_KEY = bytes(range(32))  # stands for whichever session key the attacker holds
TAG_LEN_DEFAULT = 8


def device_states(inv: ev.Invariants) -> dict[str, ev.DeviceState]:
    floor = inv.battery_floor_pct or 1
    return {f"alert={a},battery={'above' if b else 'below'}_floor":
            ev.DeviceState(0, a, 100.0 if b else floor - 1.0, 0) for a in (True, False) for b in (True, False)}


def reference_state_name(cfg: dict) -> str:
    c = cfg.get("count_state", {"alert_active": True, "battery_above_floor": True})
    return f"alert={c['alert_active']},battery={'above' if c['battery_above_floor'] else 'below'}_floor"


def candidates(catalogue: dict[int, ev.Action]):
    for a in catalogue.values():
        for t in range(a.targets):
            for v in range(a.min, a.max + 1):
                yield a, t, v


def count_accepted(check, catalogue: dict[int, ev.Action], state: ev.DeviceState, handle: int,
                   tag_len: int) -> dict[int, int]:
    """check(state, msg) -> (Decision, state). Returns accepted counts per action id."""
    out = {a.id: 0 for a in catalogue.values()}
    for n, (a, t, v) in enumerate(candidates(catalogue), start=1):
        s = ev.DeviceState(n - 1, state.alert_active, state.soc_pct, state.now)  # fresh counter each time
        msg = ev.make_command(ATTACKER_KEY, handle, n, a.id, t, v, tag_len)
        out[a.id] += check(s, msg)[0].accepted
    return out


def blast_s4_s6(catalogue, env: ev.Policy, inv: ev.Invariants, tag_len: int = TAG_LEN_DEFAULT) -> pd.DataFrame:
    """S4 vs S6 with the attacker holding the per-command session key (cloud side)."""
    checks = {"S4": (lambda s, m: ev.check_s4(catalogue, s, m, ATTACKER_KEY, tag_len), 0),
              "S6": (lambda s, m: ev.check_s6(env, catalogue, s, m, ATTACKER_KEY, tag_len), env.handle)}
    rows = []
    for sname, st in device_states(inv).items():
        for scheme, (chk, handle) in checks.items():
            for aid, n in count_accepted(chk, catalogue, st, handle, tag_len).items():
                a = catalogue[aid]
                rows.append({"state": sname, "scheme": scheme, "action": a.name, "action_id": aid,
                             "catalogue_commands": a.targets * (a.max - a.min + 1), "accepted": n})
    return pd.DataFrame(rows)


def k5(df: pd.DataFrame, state: str) -> dict:
    d = df[df.state == state]
    p = d.pivot_table(index="action", columns="scheme", values="accepted", aggfunc="sum", sort=False)
    cat = d.drop_duplicates("action").set_index("action").catalogue_commands
    p.insert(0, "catalogue_commands", cat)
    tot = p.sum()
    p.loc["TOTAL"] = tot
    p["ratio_s6_s4"] = p["S6"] / p["S4"]
    r = float(tot["S6"] / tot["S4"])
    return {"state": state, "ratio": r, "s6_accepted": int(tot["S6"]), "s4_accepted": int(tot["S4"]),
            "answer": f"S6/S4 = {r:.4f} ({int(tot['S6']):,} of {int(tot['S4']):,} commands, state {state})",
            "rows": p.reset_index().to_dict("records")}
