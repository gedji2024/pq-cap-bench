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


# ---------------------------------------------------------------- compromise matrix (K6)
SCHEMES = ("S4", "S4-F", "S4-E", "S6")
DEVICE_KEY = bytes(range(100, 132))  # the device's real per-command session key in the count


def attacker_keys(threat: dict, compromise: str) -> set[str]:
    return {k for p in threat["compromises"][compromise]["parties"] for k in threat["custody"][p]}


def blast_compromise(catalogue, env: ev.Policy, firmware: ev.Policy, inv: ev.Invariants, threat: dict,
                     tag_len: int = TAG_LEN_DEFAULT) -> pd.DataFrame:
    """Accepted commands per (scheme, compromise, device state, action).

    The attacker MACs with the device's session key only if a compromised party holds `session` keys;
    otherwise with a key of its own (and the device's MAC check rejects it). For S6 / S4-E the policy in
    force is the legitimate envelope, unless the attacker holds that scheme's envelope key, in which case
    it installs a permissive envelope (whole catalogue, no invariants). Every count runs the device check.
    """
    rows = []
    for comp, spec in threat["compromises"].items():
        keys = attacker_keys(threat, comp)
        pdp = spec.get("honest_pdp_filters", False)   # C0: proposals pass through an honest PDP
        mac_key = DEVICE_KEY if ("session" in keys or pdp) else ATTACKER_KEY
        for scheme in SCHEMES:
            pol = env
            if scheme in threat["envelope_key"] and threat["envelope_key"][scheme] in keys:
                pol = ev.permissive_policy(catalogue, env.handle)
            if scheme == "S4":
                chk, h = (lambda s, m: ev.check_s4(catalogue, s, m, DEVICE_KEY, tag_len)), 0
            elif scheme == "S4-F":
                chk, h = (lambda s, m: ev.check_s4f(firmware, catalogue, s, m, DEVICE_KEY, tag_len)), 0
            else:
                chk, h = (lambda s, m, p=pol: ev.check_enveloped(p, catalogue, s, m, DEVICE_KEY, tag_len)), env.handle
            if pdp:  # the honest PDP only emits commands its policy (event envelope) allows in this state
                chk = _pdp_filtered(chk, env, catalogue, tag_len)
            for sname, st in device_states(inv).items():
                for aid, n in _count_with_key(chk, catalogue, st, h, tag_len, mac_key).items():
                    a = catalogue[aid]
                    rows.append({"compromise": comp, "compromise_label": spec["label"], "scope": spec["scope"],
                                 "scheme": scheme, "state": sname, "action": a.name,
                                 "catalogue_commands": a.targets * (a.max - a.min + 1), "accepted": n,
                                 "attacker_has_session_key": "session" in keys,
                                 "attacker_replaced_envelope": pol is not env})
    return pd.DataFrame(rows)


def _pdp_filtered(check, env: ev.Policy, catalogue, tag_len: int):
    def f(state, msg):
        if not _pdp_allows(env, catalogue, state, msg, tag_len):
            return ev.Decision(False, "pdp"), state
        return check(state, msg)
    return f


def _pdp_allows(env: ev.Policy, catalogue, state, msg: bytes, tag_len: int) -> bool:
    """PDP software policy (C0): the same command, checked against the event envelope in this state."""
    body = msg[:ev.HEADER.size + ev.PARAMS.size]
    _, counter = ev.HEADER.unpack_from(body)
    re = ev.HEADER.pack(env.handle, counter) + body[ev.HEADER.size:]
    return ev.check_enveloped(env, catalogue, state, re + ev.tag(DEVICE_KEY, re, tag_len), DEVICE_KEY,
                              tag_len)[0].accepted


def _count_with_key(check, catalogue, state, handle, tag_len, key) -> dict[int, int]:
    out = {a.id: 0 for a in catalogue.values()}
    for n, (a, t, v) in enumerate(candidates(catalogue), start=1):
        s = ev.DeviceState(n - 1, state.alert_active, state.soc_pct, state.now)
        out[a.id] += check(s, ev.make_command(key, handle, n, a.id, t, v, tag_len))[0].accepted
    return out


PROPERTIES = [
    # (property, S4, S4-F, S4-E, S6, evidence)
    ("Third-party verifiability of the policy without forging power", "n/a (no policy)", "n/a (no OTA policy)",
     "no: verifying needs the per-device key, which also forges",
     "yes: verified with the authority's public key", "tests/test_threat.py::test_third_party_verification"),
    ("Policy provisioning without shared secrets", "n/a", "yes (compiled in)",
     "no: per-device secret in device and HSM", "yes: device stores a public key",
     "config/threat.yaml custody"),
    ("Policy updatable over the air", "n/a (no bounds)", "no", "yes", "yes", "scheme definition"),
    ("One extracted device lets attacker forge envelopes", "n/a", "n/a", "yes, for that device only", "no",
     "custody: S4-E device holds policy_mac"),
]


def k6(df: pd.DataFrame, state: str, envelope_bytes: dict[str, int]) -> dict:
    d = df[df.state == state].groupby(["compromise", "scheme"], sort=False).accepted.sum().unstack()
    scope = df.drop_duplicates("compromise").set_index("compromise").scope if "scope" in df else {}
    rows = []
    for comp, r in d.iterrows():
        e, s6 = int(r["S4-E"]), int(r["S6"])
        rows.append({"compromise": comp, "scope": scope.get(comp, "all") if len(scope) else "all",
                     **{k: int(r[k]) for k in SCHEMES},
                     "ratio_s4e_s6": (e / s6) if s6 else None,
                     "ratio_note": "" if s6 else ("both 0" if e == 0 else "S6 is 0")})
    props = [dict(zip(("property", *SCHEMES, "evidence"), p)) for p in PROPERTIES]
    if "C1+C3" in d.index:  # derived from the matrix, not asserted
        full = d.loc["C1+C3", "S4"]
        props.append({"property": "Blast radius under C1+C3 bounded below S4's", "evidence":
                      "results/model_blast_compromise.csv",
                      **{k: ("yes" if d.loc["C1+C3", k] < full else "no") + f" ({int(d.loc['C1+C3', k])})"
                         for k in SCHEMES}})
    props.append({"property": "Envelope bytes on air (measured authenticator sizes)", "S4": "-", "S4-F": "-",
                  "S4-E": f"{envelope_bytes['S4-E']} B", "S6": f"{envelope_bytes['S6']} B",
                  "evidence": "results/sizes.csv"})
    same = all(r["S4-E"] == r["S6"] for r in rows)
    return {"state": state, "rows": rows, "properties": props,
            "answer": ("S4-E and S6 have the same blast radius under every compromise; they differ in the "
                       "properties listed" if same else "S4-E and S6 blast radii differ (see table)")}
