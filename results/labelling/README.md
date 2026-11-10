# H3 labelling (Task E judge validation)

| File | What it is |
|---|---|
| `to_label.csv` | The blind, shuffled sample of 60 judged episodes (PREREG stratification, model x outcome class, water filling, seed 20261105). No model, condition or judge label; empty label columns. Never modified. |
| `key.csv` | The key: item_id -> episode key, model, condition, prompt, outcome class, claims-parser false report, judge label and quote. |
| `LABELLING_GUIDE.md` | The one-page guide from the registered judge rubric. |
| `to_label_human.csv` | Human labels: independent labels by the first author exported by the blank form `label_h3.html` (NEXT_BATCH 5.1 case A), copied unchanged from `~/Downloads/to_label.csv` (SHA-256 342dae6b...36f3). |
| `agreement.csv` | Cohen's kappa judge vs human with a percentile bootstrap CI over items (`scripts/agreement.py`): all items, mistral-nemo:12b transcripts, other two models. |
| `agreement_extra.csv` | Observed agreement, confusion matrix, the judge label on empty answers, claims parser vs human false-report labels, AI pre-annotation vs human labels on all 60 items and on the 57 not seen in the key (`scripts/agreement_extra.py`). |

On the manuscript branch (`manuscript/labelling/`): `label_h3.html` (blank offline form), `relecture_H3_60.html` (review
form pre-filled with the AI annotation), and `llm_preannotation.csv`: a pre-annotation of the same 60 items (label,
quote, false report) by an AI model (Claude, a family different from the judge's), made without the judge labels. Its
annotator saw the first three key rows by mistake (01ed5c53a9, 0dae625c5b, 0e4a08da68), as stated in the review form;
agreement with the human labels is therefore also reported on the other 57 items. `to_label_human.csv` has the
blank form's export name and columns (no `ai_prelabel` / `reviewed_by_human` column), i.e. it is not an export of the
pre-filled review form.
