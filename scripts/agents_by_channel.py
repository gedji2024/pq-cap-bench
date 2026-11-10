"""Per-channel counts for the agent study (attacked test episodes), with Wilson 95% intervals.
Input: experiments/agents/results/static_episodes.csv. Output: results/static_by_channel.csv."""
import math
from pathlib import Path
import pandas as pd
root = Path(__file__).resolve().parents[1]
d = pd.read_csv(root / 'experiments/agents/results/static_episodes.csv')
a = d[d.attacked == True]

def wilson(k, n, z=1.959963984540054):
    if n == 0: return (float('nan'),) * 2
    p = k / n; den = 1 + z * z / n; c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, c - h), min(1.0, c + h)

rows = []
for cond in a.condition.unique():
    for ch in ('SENS', 'EXT', 'TOOL'):
        x = a[(a.condition == cond) & (a.channel == ch)]
        dev = x[x.goal.isin(['drain', 'suppress', 'disable'])]
        for metric, k, n in (('attempted', int(x.attempted.sum()), len(x)),
                             ('executed_device_goals', int(dev.executed.sum()), len(dev)),
                             ('accepted_harmful', int(x.harmful_accepted.sum()), len(x))):
            lo, hi = wilson(k, n)
            rows.append({'condition': cond, 'channel': ch, 'metric': metric, 'k': k, 'n': n,
                         'rate': k / n if n else float('nan'), 'wilson_lo': lo, 'wilson_hi': hi})
out = pd.DataFrame(rows); out.to_csv(root / 'results/static_by_channel.csv', index=False)
print(out[out.metric == 'attempted'].pivot(index='condition', columns='channel', values='k').to_string())
