# A6: numbers audit (abstract, Sec. V, VII-E, VII-F, Tables V-VII)

Repo: pq-cap-bench-audit worktree, branch audit/v0.2 @ 5eb8615. Read-only; one light computation (pandas over results CSVs).

## Mapping of the scope
- Abstract: main.tex:57-59
- Section V: `\section{Formal Model and Guarantees}\label{sec:formal}` (formal.tex, \input at main.tex:231). Sections I-IV are Intro, Related, Model, Design.
- Section VII: `\section{Evaluation}\label{sec:eval}` (main.tex:290). Subsections: A Setup, B sec:feas, C sec:k6, D Network-side, **E = sec:replay (main.tex:341-374)**, **F = sec:budget (main.tex:376-427)**.
- Tables, in order: I tab:related, II tab:schemes, III tab:tamarin, IV tab:blast, **V = tab:replay (main.tex:346-370)**, **VI = tab:bstar (383-398)**, **VII = tab:budget (403-426)**. formal.tex has no tables (it has two algorithms).

## Counts
136 numbers checked: **134 OK, 2 DIFF, 0 NO_SOURCE**.

## DIFF rows
1. **VII-F main.tex:377, "up to 75 command-caused uplinks per day the excess stays at or below 0.05".** In results/g3_budget_sweep.csv the excess at B=75 is 0.0519, and Table VII prints 0.052 on that row. The claim holds only after rounding to 2 dp. Suggested wording: "at most 0.052" or "about 0.05".
2. **VII-F main.tex:377, "although the intervals overlap at 50 and 75".** The legitimate p90 CIs in g3_budget_sweep.csv are: no budget [8,15], 10 and 20 [15,18], 30 [13,18], 50 [9,17], 75 [9,15]. The CI at 30 also overlaps the no-budget CI, and 10 and 20 touch it at 15. The sentence implies that only 50 and 75 overlap.

## Worth knowing (OK rows with caveats)
- **B\* ranges (formal.tex:105, Table VI).** The manuscript values 27.6-32.4, 79.6-84.4 and 131.6-136.4 reproduce exactly from Corollary cor:bstar, using K=(SOC-20)/100*1300, j=4, tau in [5760,7199] and floor((tau+15)/60) in [96,120]. theory/PREDICTIONS.md, however, states a different closed form, (K-1-24*4-A)/5, which gives 32.6/84.6/136.6, i.e. 0.2 above the manuscript's upper ends. PREDICTIONS.md should be updated, or a note added saying the manuscript uses K-2 and the floor term.
- **formal.tex:28 \pend note ("artifact at commit b52235a signs enc(E) without id_D").** This is true at b52235a. The audit/v0.2 HEAD, however, already signs "PQCAP-ENV-v1"|DevEUI|112 B (src/pqcap/envelope.py envelope_message, "audit v0.2 B1"), so the note may be stale.
- **Abstract "up to 250 minutes ... at the slowest data rate".** This is the US915 DR8 value (15001 s). EU868 DR0-2 in results/model_delivery.csv give 260 min.
- **VII-F:401 "P_U=0.94 at 50 per day" (C1+C3, threshold 0).** The text does not state the charge. 0.94 matches only 60% (40%: 0.956; 80%: 0.748).
- **"smallest margin 0.54 h"** (computed 0.5407 h, 0 violations over 615 runs). The minimum is over the 524 runs where both the floor time and t_U are finite. 33 runs have no t_U and never reach the floor, and 58 others never reach the floor; both cases are consistent with the bound.
- **"132 crossings meet the stage condition"** matches certified+not_certified in PREDICTIONS.md. The replay's 3 missed crossings are identical under none / C1 / C1+C3 (model_harm_events.csv). Showing that they are the same 3 as the theory's sampling-missed set would require running bound.py, which was not done.
- **Table V** uses the PS-LB/good battery profile and the naive legitimate policy for the suppress rows, and LWL01/poor for the drain rows. All 11 rows match results/model_harm_delays.csv at the shown precision.
