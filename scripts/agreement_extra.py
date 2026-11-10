"""NEXT_BATCH N5.2: descriptive H3 extras beside scripts/agreement.py, written to results/labelling/agreement_extra.csv:
observed agreement and confusion matrix (judge x human); the judge's label on the items whose assistant answer is
empty or whitespace only; the human `human_false_report` against the PREREG claims parser (key.csv false_report;
descriptive, PREREG Sec. 6; unlabelled cells are not counted); case (A) only: the human labels against the LLM
pre-annotation (label, quote, false_report) on all items and on the items the LLM annotator had not seen in the key.

Usage: PYTHONPATH=src python scripts/agreement_extra.py <human.csv> [llm_preannotation.csv]
"""

import sys
from pathlib import Path

import pandas as pd

from pqcap.agents import agreement as AG

ROOT = Path(__file__).resolve().parents[1]
SEEN_KEY = ("01ed5c53a9", "0dae625c5b", "0e4a08da68")   # key rows the LLM annotator had seen (NEXT_BATCH 5.2)


def _norm(s) -> str:
    return "" if pd.isna(s) else " ".join(str(s).split())


def extra(key: pd.DataFrame, human: pd.DataFrame, blind: pd.DataFrame, llm: pd.DataFrame | None) -> pd.DataFrame:
    m = AG.merge(key, human)
    rows = [{"metric": "observed_agreement_judge_human", "subset": "all", "n": len(m),
             "value": float((m.judge == m.human).mean())}]
    for j in ("REFUSED", "NOT_REFUSED"):
        for h in ("REFUSED", "NOT_REFUSED"):
            rows.append({"metric": f"confusion_judge_{j}_human_{h}", "subset": "all", "n": len(m),
                         "value": int(((m.judge == j) & (m.human == h)).sum())})
    empty = blind[blind.agent_text.map(_norm) == ""].item_id
    ke = key[key.item_id.isin(empty)]
    rows.append({"metric": "empty_answers", "subset": "all", "n": len(ke), "value": len(ke)})
    for _, r in ke.iterrows():
        rows.append({"metric": "judge_label_on_empty_answer", "subset": r.item_id, "n": 1, "value": r.judge_label})
    hf = human.set_index("item_id").human_false_report.map(_norm).str.upper()
    lab = hf[hf.isin(["CLAIM", "NO_CLAIM"])]
    parser = key.set_index("item_id").false_report.reindex(lab.index)
    agree = int(((lab == "CLAIM") == parser.astype(bool)).sum()) if len(lab) else 0
    rows.append({"metric": "parser_vs_human_false_report_agree", "subset": "labelled", "n": len(lab), "value": agree})
    if llm is not None:
        h = human.set_index("item_id")
        lm = llm.set_index("item_id").reindex(h.index)
        for subset, ids in (("all", h.index), ("excluding_seen_key_rows", h.index.difference(SEEN_KEY))):
            hh, ll = h.loc[ids], lm.loc[ids]
            rows.append({"metric": "llm_vs_human_label_agree", "subset": subset, "n": len(ids),
                         "value": int((hh.human_label.map(_norm).str.upper() == ll.human_label.map(_norm).str.upper()).sum())})
            rows.append({"metric": "llm_vs_human_quote_agree", "subset": subset, "n": len(ids),
                         "value": int((hh.human_quote.map(_norm) == ll.human_quote.map(_norm)).sum())})
            hf2, lf2 = hh.human_false_report.map(_norm).str.upper(), ll.human_false_report.map(_norm).str.upper()
            both = hf2.isin(["CLAIM", "NO_CLAIM"])
            rows.append({"metric": "llm_vs_human_false_report_agree", "subset": f"{subset}_human_labelled",
                         "n": int(both.sum()), "value": int((hf2[both] == lf2[both]).sum())})
            rows.append({"metric": "llm_label_REFUSED", "subset": subset, "n": len(ids),
                         "value": int((ll.human_label.map(_norm).str.upper() == "REFUSED").sum())})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    key = pd.read_csv(ROOT / "results/labelling/key.csv", dtype={"item_id": str})
    human = pd.read_csv(sys.argv[1], dtype={"item_id": str})
    blind = pd.read_csv(ROOT / "results/labelling/to_label.csv", dtype={"item_id": str})
    llm = pd.read_csv(sys.argv[2], dtype={"item_id": str}) if len(sys.argv) > 2 else None
    out = extra(key, human, blind, llm)
    out.to_csv(ROOT / "results/labelling/agreement_extra.csv", index=False)
    print(out.to_string(index=False))
