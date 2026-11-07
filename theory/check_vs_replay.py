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
# (3) audit v0.2 B4: B3 replay (drain and drain_lowthreshold, C1 and C1+C3, F8 off/on) against the robust U_B
# (bound_robust.py): F8 off -> theta_lo = band_lo (C1) / 0 (C1+C3); F8 on -> theta_F for every adversary. With F8
# on, also against the fixed-threshold P_upper of bound.py ('actual', Corollary-1 form). Run after bound_robust.py.
b3p = res / 'b3_drain_lowthreshold.csv'
if b3p.exists():
    rb = pd.read_csv(here / 'bound_robust.csv'); b3 = pd.read_csv(b3p); rows = []
    for _, x in b3[b3.budget_per_epoch.notna()].iterrows():
        mode = 'f8on_or_fixed' if x.f8 == 'commissioned' else ('C1_f8off' if x.compromise == 'C1' else 'C1C3_f8off')
        q = rb[(rb['mode'] == mode) & (rb.soc0 == x.initial_soc_pct) & (rb.B == x.budget_per_epoch)]
        g = o[f'soc{int(x.initial_soc_pct)}_actual']
        fixed = g.loc[x.budget_per_epoch, 'P_upper'] if x.budget_per_epoch in g.index else float('nan')
        rows.append({'compromise': x.compromise, 'strategy': x.strategy, 'f8': x.f8, 'B': int(x.budget_per_epoch),
                     'excess': x.excess, 'excess_ci_lo': x.excess_ci_lo, 'excess_ci_hi': x.excess_ci_hi, 'bound_mode': mode,
                     'P_upper': q.P_upper.iloc[0], 'P_upper_fixed_threshold': fixed,
                     'within_bound': bool(x.excess <= q.P_upper.iloc[0] + 1e-12)})
    cv = pd.DataFrame(rows); cv.to_csv(here / 'check_vs_replay_b4.csv', index=False)
    print(f'B4: {len(cv)} B3 grid points, excess > robust P_upper: {(~cv.within_bound).sum()}')
