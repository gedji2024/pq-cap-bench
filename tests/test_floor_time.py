"""theory/floor_time.py computes the theorem's t_U = min{t : U(t) > K-1} (FIX_BATCH_v0.3.7 1.1, DEVIATIONS 8), and the
committed floor-time CSV gives the manuscript's Sec. VI check: no drain run reaches the floor before t_U, smallest margin
0.65 h."""
import importlib.util
import sys
from pathlib import Path
import pandas as pd
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'theory'))
spec = importlib.util.spec_from_file_location('floor_time', root / 'theory/floor_time.py')
ft = importlib.util.module_from_spec(spec); spec.loader.exec_module(ft)


def test_t_U_uses_K_minus_1():
    assert ft.t_U([0, 1, 2, 3], 3) == 3          # U = 3 > K - 1 = 2: first index; U > K would never hold here
    assert ft.t_U([0, 1, 2, 2], 3) is None
    assert ft.t_U([5, 6], 3) == 0


def test_floor_time_margin_matches_manuscript():
    r = pd.read_csv(root / 'results/g3_floor_runs.csv')
    r = r[(r.compromise == 'C1') & (r.strategy == 'drain') & (r.scheme == 'S6+F') & (r.energy_budget != 'off')].copy()
    r['B'] = r.energy_budget.astype(int)
    lb = pd.read_csv(root / 'theory/floor_time_lower_bound.csv')
    m = r.merge(lb, left_on=['event', 'B', 'initial_soc_pct'], right_on=['event', 'B', 'soc0'])
    slack_h = (m.floor_reached_min / 1440 - m.tfloor_lower_bound_day) * 24
    assert len(m) == 615 and (slack_h < -1e-9).sum() == 0
    assert round(slack_h.min(), 2) == 0.65
