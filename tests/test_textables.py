import math

import pandas as pd

from pqcap import textables as TX
from pqcap.config import REPO_ROOT


def test_cells():
    assert TX.esc("a_b & 50%") == r"a\_b \& 50\%"
    assert TX.num(1234567) == "1{,}234{,}567" and TX.num(float("inf")) == r"$\infty$"
    assert TX.num(None) == TX.num(math.nan) == "--"
    assert TX.ci(0.5, 0.4, 0.6) == "0.50 [0.40, 0.60]" and TX.ci(math.nan, 0, 1) == "--"
    assert TX.rng(1, 1) == "1" and TX.rng(1, 2) == "1--2"
    assert TX.yn(True) == "yes" and TX.yn(False) == "no" and TX.yn(math.nan) == "--"
    t = TX.tabular(pd.DataFrame({"a": ["x_y"], "b": [TX.T(r"$\infty$")]}), ["A_1", "B"], "lr", ["note"])
    assert t.startswith("% note\n\\begin{tabular}{lr}\n\\toprule") and r"x\_y & $\infty$ \\" in t
    assert r"A\_1 & B \\" in t and t.rstrip().endswith(r"\end{tabular}")


def test_export(tmp_path):
    ag = tmp_path / "agents"
    ag.mkdir()
    pd.DataFrame([{"goal": "all", "k": 0, "n": 1000, "rate": 0.0, "upper95_one_sided": 0.003,
                   "accepted_outside_commands": 0}]).to_csv(ag / "static_primary_hb.csv", index=False)
    rt = pd.DataFrame([{"condition": "S6", "prompt": "naive", "k": 1, "n": 10, "rate": 0.1, "ci_lo": 0.02, "ci_hi": 0.4}])
    for f in ("static_executed_pooled.csv", "static_false_report.csv"):
        rt.to_csv(ag / f, index=False)
    pd.DataFrame([{"model": "m", "condition": "S6", "executed": 1, "ignored": 3}]).to_csv(ag / "static_outcomes.csv",
                                                                                        index=False)
    out = tmp_path / "tables"
    w, s = _run(ag, out)
    assert "agents_attempted" in s and {"sizes", "tamarin", "agents_primary", "agents_outcomes"} <= set(w)
    txt = (out / "sizes.tex").read_text()
    assert "Results commit: abc123" in txt and r"\toprule" in txt and "ML-DSA-44" in txt
    assert "0.0030" in (out / "agents_primary.tex").read_text()
    assert "0.10 [0.02, 0.40] (1/10)" in (out / "agents_false_report.tex").read_text()
    for name in w:
        assert (out / f"{name}.tex").read_text().count(r"\begin{tabular}") == 1


def _run(ag, out):
    # agents results live outside the repo in this test: paths are reported relative to their common root
    return TX.export(REPO_ROOT / "results", ag, out, "abc123", _common(ag))


def _common(ag):
    import os
    return type(ag)(os.path.commonpath([str(ag.resolve()), str(REPO_ROOT.resolve())]))


def test_commit():
    assert len(TX.commit(REPO_ROOT).split("-")[0]) == 40
