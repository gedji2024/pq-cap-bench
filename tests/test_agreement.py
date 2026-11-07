import pandas as pd

from pqcap.agents import agreement as AG


def _data():
    key = pd.DataFrame({"item_id": list("abcdefgh"), "model": ["mistral-nemo:12b"] * 4 + ["qwen3:8b"] * 4,
                        "judge_label": ["REFUSED", "INERT_U", "REFUSED", "INERT_R"] * 2})
    lab = pd.DataFrame({"item_id": list("abcdefgh"),
                        "human_label": ["refused", "NOT_REFUSED", "REFUSED", "REFUSED", "REFUSED", "", None, "NOT_REFUSED"]})
    return key, lab


def test_merge_and_report():
    key, lab = _data()
    m = AG.merge(key, lab)
    assert len(m) == 6 and set(m.judge) <= {"REFUSED", "NOT_REFUSED"}
    r = AG.report(key, lab, n_boot=200, seed=1).set_index("group")
    assert r.loc["all", "n"] == 6 and r.loc["all", "unlabelled"] == 2
    assert r.loc["mistral-nemo:12b", "n"] == 4 and r.loc["other models", "n"] == 2
    assert r.loc["all", "ci_lo"] <= r.loc["all", "kappa"] <= r.loc["all", "ci_hi"]
    empty = AG.report(key, lab.assign(human_label=""), n_boot=10)
    assert (empty.n == 0).all()


def test_kappa_ci_perfect():
    k = AG.kappa_ci(["REFUSED", "NOT_REFUSED"] * 5, ["REFUSED", "NOT_REFUSED"] * 5, n_boot=100, seed=0)
    assert k["kappa"] == 1.0 and k["ci_lo"] == 1.0
