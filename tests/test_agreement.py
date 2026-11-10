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


def test_agreement_extra():
    import importlib.util
    from pathlib import Path
    p = Path(__file__).resolve().parents[1] / "scripts/agreement_extra.py"
    spec = importlib.util.spec_from_file_location("agreement_extra", p)
    X = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(X)
    key = pd.DataFrame({"item_id": ["01ed5c53a9", "b", "c", "d"], "model": ["m"] * 4,
                        "judge_label": ["REFUSED", "REFUSED", "INERT_U", "REFUSED"],
                        "false_report": [True, False, False, True]})
    human = pd.DataFrame({"item_id": ["01ed5c53a9", "b", "c", "d"], "human_label": ["NOT_REFUSED", "REFUSED", "NOT_REFUSED", "NOT_REFUSED"],
                          "human_quote": ["", "no.", "", ""], "human_false_report": ["CLAIM", "NO_CLAIM", "", "NO_CLAIM"]})
    blind = pd.DataFrame({"item_id": ["01ed5c53a9", "b", "c", "d"], "agent_text": ["x", " \n", "y", None]})
    llm = human.assign(human_label=["REFUSED", "REFUSED", "NOT_REFUSED", "NOT_REFUSED"], human_false_report="NO_CLAIM")
    v = X.extra(key, human, blind, llm).set_index(["metric", "subset"]).value
    assert v["observed_agreement_judge_human", "all"] == 0.5
    assert v["confusion_judge_REFUSED_human_NOT_REFUSED", "all"] == 2
    assert v["empty_answers", "all"] == 2 and v["judge_label_on_empty_answer", "b"] == "REFUSED"
    assert v["parser_vs_human_false_report_agree", "labelled"] == 2          # a: CLAIM/True, b: ok, d: NO_CLAIM/True
    assert v["llm_vs_human_label_agree", "all"] == 3 and v["llm_vs_human_label_agree", "excluding_seen_key_rows"] == 3
    assert v["llm_vs_human_false_report_agree", "all_human_labelled"] == 2
    assert "llm_vs_human_label_agree" not in X.extra(key, human, blind, None).metric.values
