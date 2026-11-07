### B3. Attacker `drain_lowthreshold` (lower the threshold, then drain)

- **Commit on main.** `b9e4bf3` (cherry-picked from branch `audit/v0.2`; the merge of `theory/predictions` is `c78f357`).

- **Strategy** (`harm.attacker_command`): at each downlink, first the lowest alert threshold S6+F accepts (band_lo under C1, the catalogue minimum 0 under C1+C3; the commissioning floor caps it at theta_F from above, not below), then `drain` (shortest accepted interval, else an immediate uplink). Test: `tests/test_harm.py::test_drain_lowthreshold_strategy_b3`.
- **Runs** (`scripts/b3_drain_lowthreshold.py`, `harm.budget_sweep` unchanged): S6+F, LWL01/poor, SOC0 60 % (ASSUMED, as G3), the registered G3 budget grid (contains the derived budget 50), 41 events, C1 and C1+C3, `drain` and `drain_lowthreshold`, F8 off (`configured`) and on (`commissioned`); storm-cluster bootstrap 95 % CIs as G3. Output: `results/b3_drain_lowthreshold.csv` (new file; no existing result overwritten). Reproduction: the `drain` / C1 / F8-off rows equal `results/g3_budget_sweep.csv` exactly (excess, CI, legitimate p90 at every budget). Bounds from `theory/bound_robust.py` (B4) and, for F8 on, the fixed-threshold P_upper of `theory/bound.py` ('actual').

**Excess late-or-missed share over the legitimate baseline (95 % CI), and P_upper:**

| Budget / day | Compromise | `drain` (F8 off = on) | `drain_lowthreshold`, F8 off | `drain_lowthreshold`, F8 on | P_upper F8 off (C1: band_lo; C1+C3: 0) | P_upper F8 on (theta_F) | P_upper fixed threshold |
|---|---|---|---|---|---|---|---|
| 30 | C1 | 0.007 [0.000, 0.028] | 0.037 [0.006, 0.090] | 0.007 [0.000, 0.028] | 0.104 | 0.052 | 0.044 |
| **50 (derived)** | C1 | 0.037 [0.000, 0.077] | **0.059 [0.020, 0.109]** | **0.037 [0.000, 0.077]** | 0.178 | 0.074 | 0.052 |
| 75 | C1 | 0.052 [0.019, 0.099] | 0.163 [0.102, 0.242] | 0.059 [0.022, 0.104] | 0.407 | 0.222 | 0.141 |
| 85 | C1 | 0.385 [0.291, 0.495] | 0.630 [0.500, 0.765] | 0.556 [0.412, 0.708] | 0.911 | 0.867 | 0.867 |
| 10 | C1+C3 | 0.000 [0.000, 0.000] | 0.022 [0.000, 0.039] | 0.000 [0.000, 0.000] | 0.948 | 0.052 | 0.007 |
| 30 | C1+C3 | 0.007 [0.000, 0.028] | 0.689 [0.565, 0.818] | 0.007 [0.000, 0.028] | 0.948 | 0.052 | 0.044 |
| **50 (derived)** | C1+C3 | 0.037 [0.000, 0.077] | **0.659 [0.550, 0.740]** | **0.037 [0.000, 0.077]** | 0.948 | 0.074 | 0.052 |
| 75 | C1+C3 | 0.052 [0.019, 0.099] | 0.741 [0.649, 0.821] | 0.059 [0.022, 0.104] | 0.956 | 0.222 | 0.141 |
| 85 | C1+C3 | 0.385 [0.291, 0.495] | 0.770 [0.686, 0.847] | 0.556 [0.412, 0.708] | 0.956 | 0.867 | 0.867 |

All budgets: `theory/check_vs_replay_b4.csv`. No budget: `drain` 0.511, `drain_lowthreshold` 0.711 (C1) and 0.785 (C1+C3), F8 has no effect without a budget.

- **Does the attack exceed `drain` at the derived budget?** Yes. C1: 0.059 vs 0.037 (point estimates; the CIs overlap). C1+C3: 0.659 vs 0.037 (CIs disjoint). Lowering the threshold to 0 makes the device stay in alert mode, whose I_max-rate uplinks are free of the budget, so the budget no longer protects the battery (the PREDICTIONS P4 case, now measured).
- **Does F8 bring it back?** At and below the derived budget, yes, exactly: with F8 on, `drain_lowthreshold` equals `drain` at every budget <= 50 under both C1 and C1+C3 (identical point estimates and CIs). At 75 it is 0.059 vs 0.052. Above the cliff (85 and more) F8 still lowers the excess but it stays above `drain` (0.556 vs 0.385 at 85): the battery reaches the floor in both cases and the lowered threshold changes which crossings are lost.
- **Against the bounds:** every one of the 96 budgeted grid points is within its robust P_upper (smallest margin 0.037); every F8-on point is also within the fixed-threshold P_upper of `bound.py`.
- **Runtime note:** `drain_lowthreshold` under C1 scans every threshold below band_lo at each downlink (stateless attacker), 944 s / 684 s per sweep vs 12 s for `drain`.
