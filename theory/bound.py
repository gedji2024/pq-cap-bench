"""Analytic upper bound on drain harm for S6+F (Theorem 3 in the manuscript draft).
Uses ONLY the stage series, the NWS levels and the configuration constants; it never calls harm.simulate.
P(B) = share of crossings that are not certified safe = upper bound on the attack excess late-or-missed share."""
import sys, json, math
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]/'src'))
from pathlib import Path
import numpy as np
from pqcap import harm, config
root = Path(__file__).resolve().parents[1]
cfg = config.load_yaml(root/'config/harm.yaml'); acfg = config.load_yaml(root/'config/actions.yaml')
dv = cfg['device']; inv = acfg['invariants']
p, I_a, T_def, d_min = dv['sample_period_min'], inv['alert_max_interval_min'], dv['default_reporting_interval_min'], dv['min_uplink_spacing_min']
n_up = 1300                       # LWL01 poor coverage, uplinks per battery (manual p.16)
floor = inv['battery_floor_soc_pct']
EPOCH = 1440

def alert_series(stage, theta):
    """alert[t] as the firmware computes it: updated at sample instants, held in between."""
    a = np.zeros(len(stage), bool); cur = False; onsets = np.zeros(len(stage), int)
    for t in range(len(stage)):
        if t % p == 0:
            now = stage[t] >= theta
            if now and not cur: onsets[t] = 1
            cur = now
        a[t] = cur
    return a, onsets

def U(alert, onsets, B):
    """Upper bound on cumulative uplinks N(t) (proof in Appendix): onset uplinks + alert-mode base uplinks
    (gaps >= I_a inside alert periods) + non-alert base uplinks (gaps >= T_def) + B per started epoch + 1."""
    t = np.arange(len(alert))
    # alert-mode base uplinks: per alert period, floor(len_so_far / I_a)
    run = np.zeros(len(alert), int); c = 0
    for i, x in enumerate(alert):
        c = c + 1 if x else 0; run[i] = c
    per = np.zeros(len(alert), int); acc = 0; prev = 0
    for i, x in enumerate(alert):
        if x: per[i] = acc + run[i] // I_a
        else:
            if i > 0 and alert[i-1]: acc += run[i-1] // I_a
            per[i] = acc
    return 1 + np.cumsum(onsets) + per + t // T_def + (0 if B is None else B * (t // EPOCH + 1))

def evaluate(B_list, soc0, theta_mode='actual', budget_none_unbounded=True):
    K = (soc0 - floor) / 100 * n_up
    rows = []
    for e in harm.event_list(cfg, root):
        cat, env, fw, stage, s, ecfg, th, levels, _ = harm._setup(e, cfg, acfg, root)
        theta = ecfg['device']['alert_threshold_cm'] if theta_mode == 'actual' else (th['band_cm'][0] if theta_mode == 'band_lo' else 0)
        alert, on = alert_series(stage, theta)
        th_hi = ecfg['device']['alert_threshold_cm']
        cr = []
        for L in levels:
            for s0, e0 in harm.crossings(stage, L):
                tau = int(math.ceil(s0 / p) * p)
                cr.append((L, s0, e0, tau if tau <= e0 else None))
        for B in B_list:
            if B is None:
                # no budget: drain requests an uplink at every opportunity; bound by spacing d_min
                Ut = 1 + np.arange(len(stage)) // d_min
            else:
                Ut = U(alert, on, B)
            for L, s0, e0, tau in cr:
                if tau is None: status = 'sampling_missed'
                else:
                    tchk = min(tau + I_a, len(stage) - 1)
                    # alert must hold on every sample instant in [tau, tau+I_a) for ANY threshold <= theta_hi
                    # (theta_hi = commissioning cap = NWS action stage); K-1 absorbs floating-point rounding
                    held = all(stage[u] >= th_hi for u in range(tau, min(tau + I_a, len(stage)), p))
                    status = 'certified' if (held and Ut[tchk] <= K - 1) else 'not_certified'
                rows.append({'event': e['name'], 'B': B, 'level': L, 'cross': s0, 'status': status})
    return rows

if __name__ == '__main__':
    import pandas as pd
    out = {}
    for soc0 in (40, 60, 80):
        for mode in ('actual', 'band_lo', 'zero'):
            df = pd.DataFrame(evaluate([None, 10, 20, 30, 50, 75, 85, 90, 100, 150, 200], soc0, mode))
            g = df.groupby('B', dropna=False).status.value_counts().unstack(fill_value=0)
            g['P_upper'] = g.get('not_certified', 0) / g.sum(axis=1)
            out[f'soc{soc0}_{mode}'] = g
            print(f'--- SOC0={soc0}% threshold={mode}  (K={(soc0-floor)/100*n_up:.0f} uplinks above floor)')
            print(g.to_string())
    pd.to_pickle(out, str(Path(__file__).with_name('bound.pkl')))
