"""Audit v0.2 B3: attacker `drain_lowthreshold` (lower the alert threshold to the lowest accepted value, then
`drain`) against S6+F, LWL01/poor, SOC0 60 %, over the registered G3 budget grid (config/harm.yaml
energy_budget.sweep.values_per_epoch, which contains the derived budget 50), under C1 and C1+C3, with F8 off
(`configured`) and on (`commissioned`). `drain` is run in the same grid as the reference. Storm-cluster bootstrap
CIs as in G3 (clusters from results/model_harm_clusters.csv). Uses harm.budget_sweep unchanged; writes a NEW file
results/b3_drain_lowthreshold.csv (never overwrites G3 results).

Usage: uv run python scripts/b3_drain_lowthreshold.py [workers]
"""

import itertools
import sys
import time
from pathlib import Path

import pandas as pd

from pqcap import harm
from pqcap.config import CONFIG, load_yaml

ROOT = Path(__file__).resolve().parents[1]


def main(workers: int = 1) -> Path:
    base = {**load_yaml(CONFIG / "harm.yaml"), "workers": workers}
    acfg = load_yaml(CONFIG / "actions.yaml")
    cl = pd.read_csv(ROOT / "results/model_harm_clusters.csv").set_index("event").cluster.to_dict()
    rows = []
    for comp, strat, f8 in itertools.product(["C1", "C1+C3"], ["drain", "drain_lowthreshold"],
                                             ["configured", "commissioned"]):
        t0 = time.time()
        cfg = {**base, "commissioning": {**base["commissioning"], "free_alert_uplinks": f8},
               "energy_budget": {**base["energy_budget"],
                                 "sweep": {**base["energy_budget"]["sweep"], "compromise": comp, "strategy": strat}}}
        tab, _ = harm.budget_sweep(cfg, acfg, ROOT, cl, 60)
        rows.append(tab.assign(f8=f8))
        print(f"{comp} {strat} F8={f8}: {time.time() - t0:.0f} s", flush=True)
    out = ROOT / "results/b3_drain_lowthreshold.csv"
    pd.concat(rows).to_csv(out, index=False)
    return out


if __name__ == "__main__":
    print(main(int(sys.argv[1]) if len(sys.argv) > 1 else 1))
