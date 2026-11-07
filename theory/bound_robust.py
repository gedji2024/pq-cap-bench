"""Audit v0.2 B4: Theorem-3 bound U_B for every adversary class, with and without F8. Never calls harm.simulate.

U_B(t) = 1 + floor(t/T) + B (floor(t/Te) + 1) + sum over maximal runs r of R up to t of
         (floor(|r|/I_max) + 1 + ceil(ceil(|r|/p) / 2)),   R = minutes whose last sampled stage >= theta_lo.
theta_lo by adversary class (manuscript Theorem 3; B4 for F8):
  F8 off (`configured`):   C1 -> band_lo (envelope lower bound);  C1+C3 -> 0 (catalogue minimum)
  F8 on  (`commissioned`): theta_F (NWS action stage) for EVERY adversary, C1 and C1+C3: an alert uplink is free
                           only when its triggering sample is >= theta_F, so free alert uplinks lie in R(theta_F).
  fixed threshold:         theta_F (the adversary does not move the threshold; same R as F8 on).
A crossing is certified on time if the stage is >= theta_F at every sample instant of [tau, tau + I_max] and
U_B(tau + I_max) <= K - 1 (Theorem 3 with Theorem 2; K - 1 absorbs rounding, as in bound.py).
P_upper(B) = share of crossings not certified (+ sampling-missed counted apart) = upper bound on the excess
late-or-missed share of any adversary in the class. Writes theory/bound_robust.csv.
"""
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from pqcap import config, harm  # noqa: E402

root = Path(__file__).resolve().parents[1]
cfg = config.load_yaml(root / 'config/harm.yaml')
acfg = config.load_yaml(root / 'config/actions.yaml')
dv, inv = cfg['device'], acfg['invariants']
p, I_a, T_def = dv['sample_period_min'], inv['alert_max_interval_min'], dv['default_reporting_interval_min']
EPOCH = int(cfg['energy_budget']['epoch_h'] * 60)
n_up = 1300                         # LWL01 poor coverage, uplinks per battery (manual p.16), as in bound.py
floor = inv['battery_floor_soc_pct']
BUDGETS = [v for v in cfg['energy_budget']['sweep']['values_per_epoch'] if v is not None]


def u_b(stage: np.ndarray, theta_lo: float, B: int) -> np.ndarray:
    n = len(stage)
    out = np.zeros(n, dtype=np.int64)
    held, closed, run = False, 0, 0

    def term(r):
        return r // I_a + 1 + math.ceil(math.ceil(r / p) / 2) if r else 0
    for t in range(n):
        if t % p == 0:
            held = stage[t] >= theta_lo
        if held:
            run += 1
        elif run:
            closed, run = closed + term(run), 0
        out[t] = 1 + t // T_def + B * (t // EPOCH + 1) + closed + term(run)
    return out


def main():
    rows = []
    for e in harm.event_list(cfg, root):
        cat, env, fw, stage, s, ecfg, th, levels, _ = harm._setup(e, cfg, acfg, root)
        theta_f = ecfg['device']['alert_threshold_cm']           # = NWS action stage (= _max_alert_threshold)
        modes = {'C1_f8off': th['band_cm'][0], 'C1C3_f8off': cat[harm.ev.A_THRESHOLD].min, 'f8on_or_fixed': theta_f}
        cr = []
        for L in levels:
            for s0, e0 in harm.crossings(stage, L):
                tau = int(math.ceil(s0 / p) * p)
                cr.append((L, s0, tau if tau <= e0 else None))
        for mode, theta_lo in modes.items():
            for B in BUDGETS:
                Ut = u_b(stage, theta_lo, B)
                for soc0 in (40, 60, 80):
                    K = (soc0 - floor) / 100 * n_up
                    for L, s0, tau in cr:
                        if tau is None:
                            st = 'sampling_missed'
                        else:
                            held = all(stage[u] >= theta_f for u in range(tau, min(tau + I_a, len(stage) - 1) + 1, p))
                            st = 'certified' if held and Ut[min(tau + I_a, len(stage) - 1)] <= K - 1 else 'not_certified'
                        rows.append({'mode': mode, 'soc0': soc0, 'B': B, 'event': e['name'], 'level': L, 'status': st})
    df = pd.DataFrame(rows)
    g = df.groupby(['mode', 'soc0', 'B']).status.value_counts().unstack(fill_value=0).reset_index()
    for c in ('certified', 'not_certified', 'sampling_missed'):
        if c not in g:
            g[c] = 0
    g['P_upper'] = g.not_certified / (g.certified + g.not_certified + g.sampling_missed)
    out = Path(__file__).with_name('bound_robust.csv')
    g.to_csv(out, index=False)
    print(g.to_string(index=False))
    return out


if __name__ == '__main__':
    main()
