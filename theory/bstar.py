"""Corollary (critical budget) B*(tau), closed form, A = 0 (alert-mode uplinks ignored).
B*(tau) = (K - 2 - floor((tau + I_max)/T) - A) / (j + 1),  j = floor((tau + I_max)/T_e).
Inputs come only from config/ and the LWL01 manual figure (1,300 uplinks, poor coverage); harm.simulate is never called.
Day 5 of the window: 5760 <= tau <= 7199 min (peak at minute 7200). Writes theory/bstar_ranges.csv."""
import sys, csv
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'src'))
from pqcap import config
cfg = config.load_yaml(root / 'config/harm.yaml'); acfg = config.load_yaml(root / 'config/actions.yaml')
I_max = acfg['invariants']['alert_max_interval_min']          # 15 (ASSUMED)
T = cfg['device']['default_reporting_interval_min']           # 60
floor = acfg['invariants']['battery_floor_soc_pct']           # 20 (ASSUMED)
N_UP, T_E, A = 1300, 1440, 0                                  # LWL01 poor coverage; epoch = 1 day; A = 0
TAU = range(5760, 7200)

def bstar(K, tau):
    j = (tau + I_max) // T_E
    return (K - 2 - (tau + I_max) // T - A) / (j + 1), j

def ranges(soc0):
    K = (soc0 - floor) / 100 * N_UP
    v = [bstar(K, t) for t in TAU]
    allb = [b for b, _ in v]; j4 = [b for b, j in v if j == 4]
    return {'soc0': soc0, 'K': K, 'bstar_min': round(min(allb), 1), 'bstar_max': round(max(allb), 1),
            'bstar_min_j4': round(min(j4), 1), 'tau_j5_from': min(t for t, (_, j) in zip(TAU, v) if j == 5)}

if __name__ == '__main__':
    rows = [ranges(s) for s in (40, 60, 80)]
    with open(root / 'theory/bstar_ranges.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    for r in rows: print(r)
