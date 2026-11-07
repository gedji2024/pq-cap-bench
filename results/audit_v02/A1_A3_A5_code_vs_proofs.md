### A1-A3, A5. Code against Algorithm 1, Theorems 2-3 and Proposition 1 (report only)

Audited at 5eb8615 (main + `theory/predictions`, before B1-B4); full findings with file:line and concrete cases in `results/audit_v02/details/A1_A5_details.md`. Manuscript: branch `manuscript/v0.2` at eef3dab (`parts/formal.tex`, `parts/appendix.tex`). Not fixed here unless an item of B covers it.

| Item | Sub-item | Verdict | Finding |
|---|---|---|---|
| A1 | Order of checks (tag, replay, handle, envelope, floor, approval) | OK | Same order in `check_s6f`; a `length` check comes first. |
| A1 | Floor after the envelope check, same pre-state | OK | `check_s6f`. |
| A1 | State changes only on acceptance (`envelope.py`) | OK | Counter committed only on full acceptance. |
| A1 | Same, inside the harm replay | DIFF | `harm.simulate` increments `Dev.counter` (also the device's last counter) before the check, so it advances on a rejected command; no effect on outcomes (every later message uses counter + 1). |
| A1 | Reason codes | DIFF | Code: `length`, `tag`, `replay`, `revoked`, `catalogue`, `expired`, `bounds`, `invariant:*`, `floor:*`, `op_token_required`; Alg. 1: tag / replay / handle / block / floor / approval. |
| A1 | Extra checks / MAC input | DIFF | Catalogue membership, reserved = 0 and the `target` byte are checked and MACed; Alg. 1 MACs h, n, a, theta only. |
| A1 | Approval by a fresh chain reveal | DIFF | The device takes a boolean `op_token_valid`; it keeps no chain state, so "one reveal = one approval" is not enforced in `check_s6f` (the hash chain is in `opapproval.py`, separately). |
| A1 | Binding | DIFF at 5eb8615, fixed by B1 | B1 signs `"PQCAP-ENV-v1" \|\| DevEUI \|\| enc(E)`; the manuscript writes the tag as `"env"`. |
| A2 | (i) threshold never above theta_F, C1 and C1+C3 without OP | OK (latent DIFF) | Holds for all 41 events. If a gauge had no NWS action stage, `_max_alert_threshold` = 0 would mean no cap; a Task E `init` threshold could also start above theta_F. Neither occurs in the replay. |
| A2 | (ii) effective interval <= I_max in alert above the floor | OK | Firmware-floor layer of `effective_interval` survives envelope replacement (C1+C3). |
| A2 | (iii) `since >= base` never charged / blocked | OK | |
| A2 | (iv) sample at tau delivered by the next uplink | OK | Buffer filled before the uplink decision, flushed at every uplink. |
| A3 | Uplink classification; tokens <= B per started epoch; non-alert free uplinks >= T apart; onsets <= ceil(samples/2) per run | OK | |
| A3 | Alert free uplinks >= I_max apart | OK, unstated assumption | Needs T >= I_max (60 >= 15 here); not stated in the manuscript. |
| A3 | `bound_adaptive.py` = U_B | OK | Term-by-term; \|r\| in minutes, inclusive, open run counted up to t. Covers C1 (band_lo) only; C1+C3 added in B4 (`theory/bound_robust.py`, which reproduces `bound_adaptive_bandlo.csv` exactly). |
| A3 | `bound.py` = U_B | DIFF | Implements the Corollary-1 fixed-threshold form A(t). Its `band_lo` / `zero` modes count onsets at a fixed threshold, so they are not valid bounds for an adversary that toggles the threshold; PREDICTIONS P1 ("band_lo for any C1 adversary") and P4 rely on them. Replaced by `bound_robust.py` (B4). |
| A3 | K | OK | |
| A3 | t_U | DIFF (minor) | `floor_time.py` uses U > K with the A(t) form, not U_B > K - 1; still a valid lower bound for the code's strict floor. |
| A3 | **Corollary 1, B*(tau)** | **DIFF (proof step fails)** | The corollary divides by j + 1 with j = floor(tau / T_e), but the budget tokens available by tau + I_max are B (floor((tau + I_max) / T_e) + 1). For tau in [T_e - I_max, T_e) the bound is too large by up to a factor (j + 2)/(j + 1). With p = 10 this hits tau = 7190 (last sample of epoch 4): the manuscript formula gives B* = 27.6 / 79.6 / 131.6 (SOC0 40 / 60 / 80), the corrected one (j = floor((tau + I_max)/T_e)) gives 23.0 / 66.3 / 109.7. The lower ends of the manuscript's ranges (27.6-32.4, 79.6-84.4, 131.6-136.4, formal.tex and Table VI) come exactly from that tau; the corrected ranges are 23.0-32.4, 66.3-84.4, 109.7-136.4 (27.8 / 79.8 / 131.8 if tau = 7190 is excluded). Arithmetic: K = (SOC0 - 20)/100 x 1300, tau over the epoch-4 sample instants 5760-7190. PREDICTIONS.md also uses K - 1 instead of the manuscript's K - 2 (32.6 vs 32.4). |
| A5 | k = ceil(x / (P - 2)) for x > P, 2-byte header, P = 53 at DR8 | OK | `radio.py`. |
| A5 | Worst / expected delivery time | DIFF (minor) | The code adds the 1 s RX1 delay and the last frame's airtime to k T_up. |
| A5 | Messages per window, push time | OK | Same small tail on push time. |
| A5 | Frame counts 50 / 1 / 2 / 14 / 48 | OK | Reproduced from `results/sizes.csv` (`max`), token body 80 B, envelope 112 B, crisis command constants. |
| A5 | "1 frame for a chain reveal" | DIFF | The reveal alone is 1 frame; the disable message carrying it (24 B command + 32 B reveal = 56 B) is 2 frames in `results/f6_op_approval.csv`. Also the S6-R envelope is 51 frames and an ML-DSA-44 token with a 16-byte-tag command 49. |

Theorem steps that do not hold for the code: none of Theorems 2-3 (and A4 finds no counterexample). Corollary 1 as written does not follow from Theorem 3 at epoch boundaries (above).
