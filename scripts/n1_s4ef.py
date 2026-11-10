"""NEXT_BATCH N1: baseline S4-E+F (S4-E device = per-device symmetric envelope key, plus exactly the S6+F
commissioning floor and budget-in-floor, F8 `free_alert_uplinks: commissioned`) against S6+F, replay only, no LLM.

(1) tab:replay grid: config/harm.yaml events, battery profiles, compromises (none, C1, C1+C3, C1+C3+OP), strategies
    (suppress, drain), budget off/on, schemes [S4-E+F, S6+F]; late-or-missed share with the registered storm-cluster
    bootstrap (statistics.bootstrap / seed, clusters from results/model_harm_clusters.csv), computed per scheme so
    both schemes see the same resampling sequence. `identical_crossings` = every crossing's delay equal to S6+F's.
    -> results/n1_s4ef_replay.csv
(2) tab:lowthr grid: harm.budget_sweep (registered G3 grid; SOC0 60 %) for both schemes, C1 and C1+C3, drain and
    drain_lowthreshold, F8 on. -> results/n1_s4ef_lowthr.csv
New files only; nothing existing is overwritten. Usage: uv run python scripts/n1_s4ef.py [workers]
"""

import itertools
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from pqcap import harm
from pqcap.config import CONFIG, load_yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMES = ["S4-E+F", "S6+F"]


def config(workers: int) -> dict:
    base = load_yaml(CONFIG / "harm.yaml")
    eb = base["energy_budget"]
    return {**base, "workers": workers, "schemes": SCHEMES,
            "commissioning": {**base["commissioning"], "free_alert_uplinks": "commissioned"},
            "energy_budget": {**eb, "schemes": sorted(set(eb["schemes"]) | {"S4-E+F"}),
                              "in_floor": sorted(set(eb["in_floor"]) | {"S4-E+F"})}}


def replay(cfg: dict, acfg: dict, cl: dict) -> pd.DataFrame:
    _, he, _ = harm.run(cfg, acfg, ROOT)
    st, tol = cfg["statistics"], cfg["harm"]["delay_tolerance_min"]
    tabs = {s: harm.delay_distribution(he[he.scheme == s], tol, st["bootstrap"], st["seed"], clusters=cl)
            for s in SCHEMES}
    keys = ["battery_profile", "compromise", "strategy", "legit_policy", "energy_budget"]
    pair = ["event", "level_cm", "cross_min"]
    a = he[he.scheme == "S4-E+F"].set_index(keys + pair).delay_min.astype(float).fillna(np.inf)
    b = he[he.scheme == "S6+F"].set_index(keys + pair).delay_min.astype(float).fillna(np.inf)
    same = (a.sort_index() == b.reindex(a.sort_index().index)).groupby(level=keys).all().rename("identical_crossings")
    out = pd.concat(tabs.values()).merge(same.reset_index(), on=keys, how="left")
    pub = pd.read_csv(ROOT / "results/model_harm_delays.csv")
    pub = pub[pub.scheme == "S6+F"][keys + ["late_or_missed_share"]].rename(
        columns={"late_or_missed_share": "published_s6f_share_f8off"})
    pub["energy_budget"] = pub.energy_budget.astype(str)
    out["energy_budget"] = out.energy_budget.astype(str)
    return out.merge(pub, on=keys, how="left")


def lowthr(cfg: dict, acfg: dict, cl: dict) -> pd.DataFrame:
    rows = []
    for scheme, comp, strat in itertools.product(SCHEMES, ["C1", "C1+C3"], ["drain", "drain_lowthreshold"]):
        sw = {**cfg["energy_budget"]["sweep"], "scheme": scheme, "compromise": comp, "strategy": strat}
        c = {**cfg, "energy_budget": {**cfg["energy_budget"], "sweep": sw}}
        tab, _ = harm.budget_sweep(c, acfg, ROOT, cl, 60)
        rows.append(tab.assign(f8="commissioned"))
        print(f"lowthr {scheme} {comp} {strat} done", flush=True)
    return pd.concat(rows)


def main(workers: int = 1) -> tuple[Path, Path]:
    cfg, acfg = config(workers), load_yaml(CONFIG / "actions.yaml")
    cl = pd.read_csv(ROOT / "results/model_harm_clusters.csv").set_index("event").cluster.to_dict()
    o1, o2 = ROOT / "results/n1_s4ef_replay.csv", ROOT / "results/n1_s4ef_lowthr.csv"
    for o in (o1, o2):
        if o.exists():
            sys.exit(f"{o} exists; never overwritten")
    replay(cfg, acfg, cl).to_csv(o1, index=False)
    print("replay done", flush=True)
    lowthr(cfg, acfg, cl).to_csv(o2, index=False)
    return o1, o2


if __name__ == "__main__":
    print(main(int(sys.argv[1]) if len(sys.argv) > 1 else 1))
