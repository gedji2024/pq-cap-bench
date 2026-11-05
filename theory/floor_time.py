"""Lower bound on the time the battery floor is reached (N(t) <= U(t) => t_floor >= first t with U(t) > K). Never calls simulate."""
import numpy as np, pandas as pd
from bound import harm, cfg, acfg, root, U, alert_series, n_up, floor
rows = []
for soc0 in (40, 60, 80):
    K = (soc0 - floor) / 100 * n_up
    for e in harm.event_list(cfg, root):
        cat, env, fw, stage, s, ecfg, th, levels, _ = harm._setup(e, cfg, acfg, root)
        a, on = alert_series(stage, ecfg['device']['alert_threshold_cm'])
        peak = int(np.argmax(stage))
        for B in (50, 75, 85, 90, 100):
            Ut = U(a, on, B); idx = np.nonzero(Ut > K)[0]
            tU = int(idx[0]) if len(idx) else None
            rows.append({'soc0': soc0, 'event': e['name'], 'B': B, 'tfloor_lower_bound_day': None if tU is None else round(tU/1440, 3),
                         'peak_day': round(peak/1440, 3), 'window_days': round(len(stage)/1440, 3)})
df = pd.DataFrame(rows); df.to_csv('floor_time_lower_bound.csv', index=False)
print(df[df.soc0 == 60].groupby('B').tfloor_lower_bound_day.describe().to_string())
print(df[df.soc0 == 60].peak_day.describe().to_string()); print(df.window_days.unique()[:5])
