"""Lower bound on the time the battery floor is reached (Theorem 3: N(t) <= U(t), so t_floor >= t_U = min{t : U(t) > K-1},
as in bound.py and bound_robust.py). Never calls simulate. Writes theory/floor_time_lower_bound.csv (next to this file).
FIX_BATCH_v0.3.7 1.1 (DEVIATIONS 8): the threshold was U > K before; it is now the theorem's U > K-1."""
from pathlib import Path
import numpy as np
import pandas as pd
from bound import harm, cfg, acfg, root, U, alert_series, n_up, floor


def t_U(Ut, K):
    """First minute t with U(t) > K - 1 (the theorem's t_U), or None if U never exceeds K - 1 in the window."""
    idx = np.nonzero(np.asarray(Ut) > K - 1)[0]
    return int(idx[0]) if len(idx) else None


if __name__ == '__main__':
    rows = []
    for soc0 in (40, 60, 80):
        K = (soc0 - floor) / 100 * n_up
        for e in harm.event_list(cfg, root):
            cat, env, fw, stage, s, ecfg, th, levels, _ = harm._setup(e, cfg, acfg, root)
            a, on = alert_series(stage, ecfg['device']['alert_threshold_cm'])
            peak = int(np.argmax(stage))
            for B in (50, 75, 85, 90, 100):
                tU = t_U(U(a, on, B), K)
                rows.append({'soc0': soc0, 'event': e['name'], 'B': B,
                             'tfloor_lower_bound_day': None if tU is None else round(tU / 1440, 3),
                             'peak_day': round(peak / 1440, 3), 'window_days': round(len(stage) / 1440, 3)})
    df = pd.DataFrame(rows); df.to_csv(Path(__file__).with_name('floor_time_lower_bound.csv'), index=False)
    print(df[df.soc0 == 60].groupby('B').tfloor_lower_bound_day.describe().to_string())
    print(df[df.soc0 == 60].peak_day.describe().to_string()); print(df.window_days.unique()[:5])
