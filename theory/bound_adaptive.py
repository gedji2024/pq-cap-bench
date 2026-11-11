"""Robust variant of the Theorem-3 bound: the adversary may change the alert threshold at every downlink,
anywhere in [theta_lo, theta_hi]. R = sample-held set where stage >= theta_lo (alert is possible only there).
Free uplinks <= 1 + t//T_def (non-alert, gaps >= T_def) + sum over R-runs (len//I_a + 1) (alert-mode, gaps >= I_a)
+ onsets (<= ceil(#sample instants in R-run / 2) per run, an onset needs a non-alert sample before it).
Charged uplinks <= B per started epoch. Never calls simulate."""
import math, numpy as np, pandas as pd
from bound import harm, cfg, acfg, root, p, I_a, T_def, n_up, floor, EPOCH, d_min
def U_rob(stage, theta_lo, B):
    n = len(stage); R = np.zeros(n, bool); cur = False
    for t in range(n):
        if t % p == 0: cur = stage[t] >= theta_lo
        R[t] = cur
    out = np.zeros(n, int); acc = 0; run = 0
    for t in range(n):
        if R[t]: run += 1
        else:
            if run: acc += run // I_a + 1 + math.ceil(math.ceil(run / p) / 2); run = 0
        cur_run = (run // I_a + 1 + math.ceil(math.ceil(run / p) / 2)) if run else 0
        out[t] = 1 + t // T_def + acc + cur_run + (B * (t // EPOCH + 1))
    return out
rows = []
for soc0 in (40, 60, 80):
    K = (soc0 - floor) / 100 * n_up
    for e in harm.event_list(cfg, root):
        cat, env, fw, stage, s, ecfg, th, levels, _ = harm._setup(e, cfg, acfg, root)
        cr = []
        for L in levels:
            for s0, e0 in harm.crossings(stage, L):
                tau = int(math.ceil(s0 / p) * p); cr.append((L, s0, tau if tau <= e0 else None))
        for B in (10, 20, 30, 50, 75, 85, 90, 100):
            Ut = U_rob(stage, th['band_cm'][0], B)
            for L, s0, tau in cr:
                held = tau is not None and all(stage[u] >= ecfg['device']['alert_threshold_cm'] for u in range(tau, min(tau + I_a, len(stage)), p))
                st = 'sampling_missed' if tau is None else ('certified' if held and Ut[min(tau + I_a, len(stage)-1)] <= K - 1 else 'not_certified')
                rows.append({'soc0': soc0, 'B': B, 'status': st})
df = pd.DataFrame(rows)
g = df.groupby(['soc0', 'B']).status.value_counts().unstack(fill_value=0)
g['P_upper'] = g['not_certified'] / g.sum(axis=1)
print(g.to_string()); g.to_csv(__import__('pathlib').Path(__file__).with_name('bound_adaptive_bandlo.csv'))  # FIX_BATCH_v0.3.7 1.1: path next to this file
