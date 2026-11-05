"""Compare the analytic drain bound (computed without the simulator) with the replay results.
Run after bound.py and floor_time.py. Checks: (1) simulated floor time >= t_U for every drain run;
(2) replay excess <= P_upper(B) at every (SOC0, B) grid point present in both."""
from pathlib import Path
import pandas as pd
here = Path(__file__).resolve().parent; res = here.parent / 'results'
r = pd.read_csv(res / 'g3_floor_runs.csv')
r = r[(r.compromise == 'C1') & (r.strategy == 'drain') & (r.scheme == 'S6+F') & (r.energy_budget != 'off')].copy()
r['B'] = r.energy_budget.astype(int)
l = pd.read_csv(here / 'floor_time_lower_bound.csv')
m = r.merge(l, left_on=['event', 'B', 'initial_soc_pct'], right_on=['event', 'B', 'soc0'])
slack_h = (m.floor_reached_min / 1440 - m.tfloor_lower_bound_day) * 24
print(f'floor-time check: {len(m)} runs, violations {(slack_h < -1e-9).sum()}, min slack {slack_h.min():.2f} h')
o = pd.read_pickle(here / 'bound.pkl'); d = pd.read_csv(res / 'g3_soc_sweep.csv'); bad = n = 0
for _, x in d.iterrows():
    g = o[f'soc{int(x.initial_soc_pct)}_actual']
    if pd.isna(x.budget_per_epoch): pu = g[g.index.isna()].P_upper.iloc[0]
    elif x.budget_per_epoch in g.index: pu = g.loc[x.budget_per_epoch, 'P_upper']
    else: continue
    n += 1; bad += x.excess > pu + 1e-12
print(f'excess <= P_upper: {n} grid points, violations {bad}')
