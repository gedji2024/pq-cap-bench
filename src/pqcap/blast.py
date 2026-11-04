"""Blast radius under cloud-side symmetric-key compromise: S4 vs S6.

The attacker holds the HMAC key, so it can mint a valid tag and a fresh counter for any
message. The blast radius is the number of distinct (action, target, value) commands the
device would ACCEPT. Counts come from running every candidate through the device-side
check (pqcap.envelope), not from a closed-form formula.
"""

from __future__ import annotations

import pandas as pd

from . import envelope as ev

ATTACKER_KEY = bytes(range(32))  # any key: the attacker is assumed to hold the real one


def candidates(catalogue: dict[int, ev.Action]):
    for a in catalogue.values():
        for t in range(a.targets):
            for v in range(a.min, a.max + 1):
                yield a, t, v


def blast_radius(catalogue: dict[int, ev.Action], env: ev.Envelope, tag_len: int) -> pd.DataFrame:
    counts = {a.id: {"action": a.name, "action_id": a.id, "catalogue_commands": 0, "s4_accepted": 0,
                     "s6_accepted": 0} for a in catalogue.values()}
    counter = 0
    for a, t, v in candidates(catalogue):
        counter += 1
        state = ev.DeviceState(counter - 1)   # fresh counter each time (attacker mints it)
        s4_msg = ev.make_command(ATTACKER_KEY, 0, counter, a.id, t, v, tag_len)
        s6_msg = ev.make_command(ATTACKER_KEY, env.handle, counter, a.id, t, v, tag_len)
        c = counts[a.id]
        c["catalogue_commands"] += 1
        c["s4_accepted"] += ev.check_s4(catalogue, state, s4_msg, ATTACKER_KEY, tag_len)[0].accepted
        c["s6_accepted"] += ev.check_s6(env, catalogue, state, s6_msg, ATTACKER_KEY, tag_len)[0].accepted
    df = pd.DataFrame(list(counts.values()))
    total = pd.DataFrame([{"action": "TOTAL", "action_id": 0, **df[["catalogue_commands", "s4_accepted",
                                                                       "s6_accepted"]].sum().to_dict()}])
    df = pd.concat([df, total], ignore_index=True)
    df["ratio_s6_s4"] = df.s6_accepted / df.s4_accepted
    df["tag_bytes"] = tag_len
    return df


def k5(df: pd.DataFrame) -> dict:
    tot = df[df.action == "TOTAL"].iloc[0]
    return {"answer": f"S6/S4 = {tot.ratio_s6_s4:.4f} ({int(tot.s6_accepted):,} of {int(tot.s4_accepted):,} commands)",
            "ratio": float(tot.ratio_s6_s4), "s6_accepted": int(tot.s6_accepted),
            "s4_accepted": int(tot.s4_accepted), "rows": df.to_dict("records")}
