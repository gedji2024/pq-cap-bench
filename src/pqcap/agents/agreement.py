"""H3 judge validation, after the human labels exist: Cohen's kappa between the judge and the human labeller
(REFUSED vs NOT_REFUSED, as `analyze.judge_agreement`) with a percentile bootstrap CI over items, overall, for
the transcripts of mistral-nemo:12b (the judge model judging itself) and for the other two agent models.
Not called by the run; `scripts/agreement.py` is the entry point."""

from __future__ import annotations

import numpy as np
import pandas as pd

from . import stats as ST

JUDGE_MODEL = "mistral-nemo:12b"   # config.yaml judge.model (registered)


def _binary(x) -> str:
    return "REFUSED" if str(x).strip().upper() == "REFUSED" else "NOT_REFUSED"


def merge(key: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    """Labelled items only: item_id, model, judge (binary), human (binary)."""
    lab = labels.assign(human_label=labels.human_label.fillna("").astype(str).str.strip().str.upper())
    m = key.merge(lab[lab.human_label != ""][["item_id", "human_label"]], on="item_id")
    return pd.DataFrame({"item_id": m.item_id, "model": m.model, "judge": [_binary(x) for x in m.judge_label],
                         "human": [_binary(x) for x in m.human_label]})


def kappa_ci(judge: list, human: list, n_boot: int = 10000, seed: int = 20261105, alpha: float = 0.05) -> dict:
    """Kappa with a percentile bootstrap CI (items resampled with replacement; resamples where kappa is
    undefined because both raters use one label are kept as 1.0 if they agree fully, as in stats.cohen_kappa)."""
    k = ST.cohen_kappa(judge, human)
    j, h = np.asarray(judge), np.asarray(human)
    rng = np.random.default_rng(seed)
    boots = [ST.cohen_kappa(list(j[i]), list(h[i]))["kappa"] for i in rng.integers(0, len(j), (n_boot, len(j)))]
    lo, hi = np.quantile(boots, [alpha / 2, 1 - alpha / 2])
    return {**k, "ci_lo": float(lo), "ci_hi": float(hi), "n_boot": n_boot, "seed": seed}


def report(key: pd.DataFrame, labels: pd.DataFrame, n_boot: int = 10000, seed: int = 20261105) -> pd.DataFrame:
    m = merge(key, labels)
    groups = {"all": m, JUDGE_MODEL: m[m.model == JUDGE_MODEL], "other models": m[m.model != JUDGE_MODEL]}
    rows = []
    for name, g in groups.items():
        if g.empty:
            rows.append({"group": name, "n": 0})
            continue
        rows.append({"group": name, **kappa_ci(g.judge.tolist(), g.human.tolist(), n_boot, seed)})
    return pd.DataFrame(rows).assign(unlabelled=len(key) - len(m))
