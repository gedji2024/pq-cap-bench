### N5. H3 human labels and judge agreement

- **Commit.** `b5ac171` (`results/labelling/to_label_human.csv`, `agreement.csv`, `agreement_extra.csv`, `README.md`, `scripts/agreement_extra.py`).
- **Source.** Case A of NEXT_BATCH 5.1: `~/Downloads/to_label.csv` (blank form export, no `ai_prelabel` column), 60 rows, `human_label` filled on every row, item_ids identical to `results/labelling/to_label.csv` (same order, same texts); copied unchanged (SHA-256 342dae6b...36f3). `to_label.csv` is not modified.
- **Labels.** The human labelled all 60 items NOT_REFUSED, gave no quote and left the optional `human_false_report` column empty on every row.
- **Agreement.** Judge REFUSED / human NOT_REFUSED 52, judge NOT_REFUSED / human NOT_REFUSED 8, no human REFUSED. Observed agreement 0.133 (mistral-nemo:12b transcripts 0.048, others 0.179). Cohen's kappa = 0 in every group: with one rater constant, p_o = p_e; `ST.cohen_kappa` returns 0 (it is defined, so it is reported as computed); the bootstrap CI is degenerate [0, 0].
- **Empty answers.** 16 of the 60 items have an empty or whitespace-only assistant answer; the judge labelled all 16 REFUSED. (In the outcome classes `refused` also needs a verbatim quote of at least 8 characters, so no empty answer is classed `refused`.)
- **Claims parser vs human false-report labels.** Not computable: 0 items carry a human false-report label.
- **AI pre-annotation** (`manuscript/labelling/llm_preannotation.csv`, Claude, a family different from the judge's, made without the judge labels; its annotator saw key rows 01ed5c53a9, 0dae625c5b, 0e4a08da68): labels agree with the human on 60/60 (57/57 excluding the three seen rows); quotes 59/60 (the pre-annotation has `?` on 90f74ab91a); false report not comparable (no human labels).
- **Consequence (pre-decided, case b).** No refusal-versus-ignore split is reported; no result depends on the judge.
