### A6. Numbers in the new manuscript text against the results (report only)

- **Commit on main.** `dd0dc3f` (cherry-picked from branch `audit/v0.2`; the merge of `theory/predictions` is `c78f357`).

Scope: abstract, Sec. V (`sec:formal`), VII-E (`sec:replay`), VII-F (`sec:budget`), Tables V-VII (`tab:replay`, `tab:bstar`, `tab:budget`) of `manuscript/v0.2` at eef3dab, against `results/*.csv`, `theory/` outputs and `config/` at 5eb8615. Full table (claim, manuscript value, source file, source value, OK/DIFF): `results/audit_v02/details/A6_numbers.csv`; notes in `details/A6_details.md`.

**136 numbers: 134 OK, 2 DIFF, 0 without a source.**

| Claim | Manuscript | Source | Value | Status |
|---|---|---|---|---|
| VII-F: "up to 75 per day the excess stays at or below 0.05" | <= 0.05 | `results/g3_budget_sweep.csv`, B = 75, `excess` | 0.0519 (Table VII prints 0.052) | DIFF |
| VII-F: "the intervals overlap at 50 and 75" (legit p90 CI vs no budget [8, 15]) | 50, 75 only | `g3_budget_sweep.csv` `legit_p90_delay_min_ci_*` | 30: [13, 18] also overlaps; 10 and 20: [15, 18] touch at 15 | DIFF |

Caveats on rows marked OK: the B* ranges reproduce from the manuscript's own Corollary 1, which fails at an epoch boundary (A3 row above; corrected ranges there); "P_U = 0.94 at 50 per day" matches only SOC0 60, which the sentence does not state; "250 min at the slowest data rate" is the US915 DR8 value (EU868 DR0-2: 260 min); "smallest margin 0.54 h" recomputed as 0.5407 h over the 524 of 615 runs where both times are finite; the formal.tex note "the artifact at b52235a signs enc(E) without id_D" is stale after B1.
