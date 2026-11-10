"""NEXT_BATCH N3: sensitivity of the late-or-missed tolerance (ASSUMED 30 min) at 15, 30 and 60 min, replay only.

Re-scored without re-simulating where the per-crossing delays are logged; re-simulated (unchanged code and config)
where they are not. Statistics exactly as published (same functions, seeds, bootstrap, storm clusters):
  replay  : every group of results/model_harm_events.csv (the tab:replay run) -> harm.delay_distribution;
            published = results/model_harm_delays.csv
  budget  : the G3 sweep (tab:budget, SOC0 60 %) re-simulated to get per-crossing delays (not logged) ->
            the same assembly as harm.budget_sweep; published = results/g3_budget_sweep.csv
  agents  : Task E final configurations (experiments/agents/logs/static) -> analyze.hydro_impact with the tolerance
            set in the context; published = experiments/agents/results/static_hydro.csv
`reproduces` (30 min rows) = every published value of the row equal (floats to 1e-12). Writes the NEW file
results/n3_tolerance_sweep.csv. Usage: uv run python scripts/n3_tolerance_sweep.py [workers]
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

from pqcap import envelope as ev
from pqcap import harm
from pqcap.agents import analyze as AN
from pqcap.agents import attacks as A
from pqcap.agents import scenario as SC
from pqcap.config import CONFIG, REPO_ROOT, load_yaml
from pqcap.devices import load_catalogue

ROOT = REPO_ROOT
TOLS = (15, 30, 60)
AG = ROOT / "experiments/agents"


def _eq(a, b) -> bool:
    if isinstance(a, str) or isinstance(b, str):
        return str(a) == str(b)
    if pd.isna(a) and pd.isna(b):
        return True
    return bool(np.isclose(float(a), float(b), rtol=0, atol=1e-12)) or (np.isinf(a) and a == b)


def _reproduce(out: pd.DataFrame, pub: pd.DataFrame, keys: list, vals: list) -> pd.DataFrame:
    p = pub.copy()
    for k in keys:
        out[k], p[k] = out[k].astype(str), p[k].astype(str)
    m = out.merge(p[keys + vals], on=keys, how="left", suffixes=("", "_pub"))
    m["reproduces"] = [all(_eq(r[v], r[f"{v}_pub"]) for v in vals) if r["tol_min"] == 30 else None
                       for _, r in m.iterrows()]
    return m.drop(columns=[f"{v}_pub" for v in vals])


def replay(hcfg: dict, cl: dict) -> pd.DataFrame:
    he = pd.read_csv(ROOT / "results/model_harm_events.csv")
    st = hcfg["statistics"]
    rows = [harm.delay_distribution(he, t, st["bootstrap"], st["seed"], clusters=cl).assign(tol_min=t) for t in TOLS]
    out = pd.concat(rows).assign(block="replay")
    keys = ["battery_profile", "scheme", "compromise", "strategy", "legit_policy", "energy_budget"]
    vals = ["late_or_missed_share", "late_or_missed_share_ci_lo", "late_or_missed_share_ci_hi"]
    return _reproduce(out, pd.read_csv(ROOT / "results/model_harm_delays.csv"), keys, vals)[
        ["block", "tol_min"] + keys + ["crossings"] + vals + ["reproduces"]]


def budget(hcfg: dict, acfg: dict, cl: dict, workers: int) -> pd.DataFrame:
    cfg, bats = harm._prepare({**hcfg, "workers": workers}, acfg, ROOT)
    sw = cfg["energy_budget"]["sweep"]
    bat = next(b for b in bats if b["name"] == sw["battery_profile"])
    jobs = [(e, cfg, acfg, ROOT, bat, sw) for e in harm.event_list(cfg, ROOT)]
    evdf = pd.DataFrame([r for o in harm._jobs_map(harm._sweep_event, jobs, workers) for r in o[0]])
    st = cfg["statistics"]
    derived = harm.epoch_budget(bat, cfg, cfg["_profile_inv"].battery_floor_pct, cfg["energy_budget"])
    rows = []
    for t in TOLS:
        dd = harm.delay_distribution(evdf[evdf.compromise == "none"], t, st["bootstrap"], st["seed"], clusters=cl)
        xx = harm.excess_over_baseline(evdf, t, st["bootstrap"], st["seed"], clusters=cl)
        m = dd[["energy_budget", "p90_delay_min", "p90_delay_min_ci_lo", "p90_delay_min_ci_hi", "late_or_missed_share",
                "late_or_missed_share_ci_lo", "late_or_missed_share_ci_hi"]].rename(
            columns=lambda c: c if c == "energy_budget" else f"legit_{c}").merge(
            xx[["energy_budget", "attack_share", "excess", "excess_ci_lo", "excess_ci_hi"]], on="energy_budget")
        m.insert(0, "budget_per_epoch", [None if v == "off" else int(v) for v in m.energy_budget])
        rows.append(m.drop(columns="energy_budget").assign(tol_min=t))
    out = pd.concat(rows).assign(block="budget", derived=lambda d: d.budget_per_epoch == derived)
    vals = ["legit_p90_delay_min", "legit_late_or_missed_share", "attack_share", "excess", "excess_ci_lo",
            "excess_ci_hi"]
    pub = pd.read_csv(ROOT / "results/g3_budget_sweep.csv")
    out["budget_per_epoch"] = out.budget_per_epoch.map(lambda v: "none" if pd.isna(v) else str(int(v)))
    pub["budget_per_epoch"] = pub.budget_per_epoch.map(lambda v: "none" if pd.isna(v) else str(int(v)))
    return _reproduce(out, pub, ["budget_per_epoch"], vals)


def agents() -> pd.DataFrame:
    hcfg = {**load_yaml(CONFIG / "harm.yaml"), "workers": 1}
    cfg, actions = load_yaml(AG / "config.yaml"), load_yaml(CONFIG / "actions.yaml")
    scen = {s.id: s for s in SC.build(hcfg, ROOT)}
    clusters = {s.id: s.cluster for s in scen.values()}
    _, atks = A.load(AG / "attacks/v1/attacks.yaml")
    by = {x.id: x for x in atks}
    recs = [r for r in AN.load(AG / "logs/static")
            if r["spec"].get("attack") is None or by.get(r["spec"]["attack"]) is None or by[r["spec"]["attack"]].split == "test"]
    devs = {d.model: d for d in load_catalogue(CONFIG / "devices")}
    bat = harm.battery_from_profile(next(p for p in hcfg["battery"]["profiles"]
                                         if p["name"] == cfg["episode"]["battery_profile"]), devs)
    rows = []
    for t in TOLS:
        cid = AN.set_context({"scenarios": scen, "actions_cfg": actions, "hcfg": hcfg, "battery": bat,
                              "inv": ev.invariants_from_config(actions), "tol": t})
        rows.append(AN.hydro_impact(recs, scen, cid, clusters, ["condition", "prompt"], 10000, 20261105).assign(tol_min=t))
    out = pd.concat(rows).assign(block="agents")
    vals = ["benign_late_or_missed", "attack_late_or_missed", "excess", "excess_ci_lo", "excess_ci_hi"]
    return _reproduce(out, pd.read_csv(AG / "results/static_hydro.csv"), ["condition", "prompt"], vals)


def main(workers: int = 1) -> Path:
    o = ROOT / "results/n3_tolerance_sweep.csv"
    if o.exists():
        sys.exit(f"{o} exists; never overwritten")
    hcfg, acfg = load_yaml(CONFIG / "harm.yaml"), load_yaml(CONFIG / "actions.yaml")
    cl = pd.read_csv(ROOT / "results/model_harm_clusters.csv").set_index("event").cluster.to_dict()
    parts = [replay(hcfg, cl)]
    print("replay done", flush=True)
    parts.append(agents())
    print("agents done", flush=True)
    parts.append(budget(hcfg, acfg, cl, workers))
    print("budget done", flush=True)
    out = pd.concat(parts, ignore_index=True)
    out.to_csv(o, index=False)
    r = out[out.tol_min == 30]
    print("30-min rows reproduce:", r.groupby("block").reproduces.agg(["sum", "count"]).to_dict(), flush=True)
    return o


if __name__ == "__main__":
    print(main(int(sys.argv[1]) if len(sys.argv) > 1 else 1))
