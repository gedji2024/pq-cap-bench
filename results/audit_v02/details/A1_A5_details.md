# Audit A1, A2, A3, A5 (code vs formal.tex / appendix.tex)

Code: worktree `pq-cap-bench-audit` at 5eb8615 (paths below are relative to it). Manuscript: `ms/formal.tex`, `ms/appendix.tex`.
I ran nothing heavy: I read the code and the result CSVs, and ran one 3-line float check.

---------------------------------------------------------------------------------------------------
## A1. Algorithm 1 vs `envelope.check_s6f` / `check_enveloped`

**Summary: the order and the state discipline match (the floor runs after the envelope check, the counter is committed only on full acceptance). DIFF on the reason codes, two extra checks, the approval mechanism, the tagged body, and the counter handling inside the harm replay.**

The call chain is `check_s6f` (src/pqcap/envelope.py:288-301), then `check_enveloped` (270-281), then `_authenticate` (196-206) and `_check_policy` (236-246), then `invariant_violation` (219-233).

| Alg. 1 line | Code | OK/DIFF |
|---|---|---|
| (none) | envelope.py:198-199 checks the length first: `len(msg) != 16 + tag_len` gives reason `length`. | DIFF (extra check before line 1) |
| 1 tag | envelope.py:201-202, reason `tag`, constant-time compare. The tag covers `handle u32 \|\| counter u32 \|\| params[8]`, where params = `action u8 \|\| target u8 \|\| value i32 \|\| reserved u16` (envelope.py:24, 178-179, 190-193). | DIFF (minor). Alg. 1 MACs `h\|\|n\|\|a\|\|θ`. The code also MACs `target` and the `reserved` field, which the formal model leaves out. The order is OK. |
| 2 replay | envelope.py:204-205, `counter <= state.last_counter`, reason `replay` | OK |
| 3 handle | envelope.py:277-280. `handle != env.handle` gives `handle`; `handle in state.revoked` gives **`revoked`** | DIFF (reason code only). Alg. 1 returns `handle` for both cases. The order is the same. |
| 4 block (Auth without floor) | `_check_policy` (envelope.py:236-245) checks in this order: (a) `reserved != 0` or not in catalogue Θ_a gives `catalogue`; (b) `not_before <= now <= not_after` fails gives `expired`; (c) `within_bounds` (action, **target** and value) fails gives `bounds`; (d) `invariant_violation(env.invariants, ...)` gives `invariant:alert_min_rate` / `invariant:battery_floor` | DIFF. Alg. 1 has the single code `block`. The code splits it into 5 codes. It also adds two checks that are not in Def. 2: catalogue membership plus reserved==0, and target ∈ rule.targets. The catalogue check is redundant only if B_E(a) ⊆ Θ_a, which an attacker-minted envelope need not satisfy. Commands carry a target, but Def. 2 has no target dimension. |
| 5 floor | envelope.py:295-298. `invariant_violation(floor, state, ...)` gives `floor:invariant:*` or `floor:commissioning:max_alert_threshold` | OK on order: it runs after the envelope check and is evaluated on the same pre-state. DIFF on the reason string (`floor:<inner>`, not `floor`). |
| 6 approval | envelope.py:299-300. `aid == A_ENABLE and value == 0 and not op_token_valid` gives `op_token_required` | DIFF. (i) The code takes the boolean `op_token_valid` from the caller. It does not check a "fresh chain reveal", keeps no chain anchor x_j in `DeviceState` (envelope.py:83-89), and does not "store y". So one reveal = one approval is **not** enforced by the device code. That property exists only in formal/opchain.spthy and in the size model (opapproval.py). In harm, `op_key` is a constant per run (harm.py:148-150, 176, 272), so under C1+C3+OP every disable is accepted, with no count against approvals. (ii) The reason code is `op_token_required`, not `approval`. (iii) The docstring (envelope.py:289-291) describes a per-command **OP signature token**, while Alg. 1 and formal.tex describe a hash-chain reveal. |
| 7 state update | `_check_policy` returns `replace(state, last_counter=counter)` only on full pass (envelope.py:246). `check_s6f` returns the old `state` on a floor or approval reject (294, 298, 300) and `new` only at 301. Applying c and queuing a receipt are not in envelope.py. Applying c is done in harm.py:367-374, only after acceptance. Receipts are not implemented (the manuscript says so in its \pend note). | OK for check_s6f. DIFF in the harm replay: see the note below. |

**State changes only on acceptance, harm replay (DIFF, no effect on results).** `harm.simulate` uses `Dev.counter` both as the device's last accepted counter (`_dstate`, harm.py:184-185) and as the sender's counter. It increments it *before* the check, whatever the outcome (harm.py:351-352), and throws away the state that `check` returns (`dec, _ =`). So in the replay the device's `last_counter` also advances on a **rejected** command. Concrete case: last accepted n=5, a command n=6 is rejected for `bounds`, and the next `_dstate` reports last_counter=6. Under Alg. 1 s.n is still 5. Outcomes are unchanged, because every later message uses counter+1. Still, the replay does not model "state changes only on acceptance".

**Binding (DIFF, already flagged in the manuscript).** `install_envelope_s6` (envelope.py:349-354) verifies the signature over the 112-byte blob only. There is no `"env"` domain tag and no id_D. formal.tex says the PA signs `"env"||id_D||enc(E)`, and the \pend note admits the artifact at b52235a signs enc(E) only. At 5eb8615 this is **still not aligned**. Also, `install_envelope_s6` adds a firmware validity cap (`validity_ok`, envelope.py:334-338) that formal.tex does not mention.

**Other A1 notes**
- `decode_bounds` (envelope.py:141-148) stops at the first rule with aid==0. The encoding has fixed length, so it is injective on bytes as formal.tex claims. But `Invariants.max_alert_threshold` (F3) is never encoded (encode_invariants, 151-155). θ ≤ θ_F therefore lives only in the floor, which matches formal.tex.
- Attenuation (Def. 1, ⊑) and delegation P2 have no counterpart in envelope.py. I did not audit agents/delegation.py.
- Revocation (`apply_revocation`, envelope.py:322-330): H(r)=c_rev with a 16- or 32-byte r. This matches formal.tex. It returns the reason codes `length` / `bad_reveal`.

---------------------------------------------------------------------------------------------------
## A2. Theorem 2 proof vs `harm.simulate`

**Summary: (i) to (iv) all hold in the code for the replayed data. One latent DIFF: the θ_F floor exists only when NWS action/minor stages are available (otherwise `_max_alert_threshold` = 0 means "no bound"). Two minor scope caveats (Task-E `init`, and OP modelled as a constant).**

### (i) The threshold never exceeds θ_F, under C1 and C1+C3 without OP. OK, with a latent DIFF.
- Initial threshold: `Dev.threshold = init.get("threshold", dv["alert_threshold_cm"])` (harm.py:277). `_setup` sets `alert_threshold_cm = th["alert_cm"]` = NWS action stage (harm.py:535), and sets `_max_alert_threshold = th["alert_cm"]` when `commissioning.max_alert_threshold == "nws_action"` (harm.py:536-537; config/harm.yaml:69). So initial = θ_F.
- A threshold is applied only after acceptance (harm.py:357-364, 373-374). For S6+F, `check_s6f` applies the floor `invariant_violation(floor, ...)`, which rejects `A_THRESHOLD` with value > max_alert_threshold (envelope.py:231-232). The floor is built from `fw.invariants` plus `max_alert_threshold` (harm.py:162-168), independent of the (possibly replaced) envelope. So it holds under C1, where the envelope band [action-(minor-action), minor] allows up to *minor* > θ_F (harm.py:496-506, 533), and under C1+C3, where the permissive policy has no invariants (harm.py:152).
- Disable: under C1 the envelope rule `sensor_enable lo=1 hi=1` blocks it (config/actions.yaml:38). Under C1+C3 without OP, `op_key=False` gives `op_token_required`, and in alert the floor's `alert_forbid_disable` rejects it first (envelope.py:229-230).
- **Latent DIFF:** `invariant_violation` checks the threshold only `if inv.max_alert_threshold` (envelope.py:231). It is 0 (no bound) whenever `_setup` takes the fallback path (no NWS file, or NWS has no action or minor stage, or the datum check fails: harm.py:530-543), and also for the `relative` profile. On that path the S6+F floor has **no θ_F**. Under C1 the attacker can raise the threshold to the envelope's hi (0.65 of the range, against an initial 0.5), and Theorem 2's premise "initial threshold θ_F, floor caps at θ_F" fails. **For the 41 replayed events this does not occur.** results/harm_meta.json gives commissioning_max_alert_threshold_cm == alert_threshold_cm ≠ 0 for all 41.
- Scope caveat: `init` (Task E, harm.py:269, 277-278) can start the threshold above θ_F, or with `enabled=False`. Either makes the premise false. The theorem does not cover these runs.

### (ii) Effective interval ≤ I_max in alert above the floor (also under C1+C3). OK.
- `eff = effective_interval(effective_interval(d.interval, alert, soc, inv), alert, soc, floor)` (harm.py:311). `effective_interval` (harm.py:135-142) takes `min(e, alert_max_interval)` in alert, then `max(e, low_batt_min_interval)` only if `soc_pct < battery_floor_pct` (strict). At or above β_min the max step is skipped. Under C1+C3, `inv` = NO_INVARIANTS, but the outer call with `floor` (fw invariants, alert_max_interval=15, actions.yaml:25) still gives eff ≤ 15. Under C1 both layers give 15. The envelope and firmware invariants come from the same `invariants_from_config`, so the battery floors agree.
- The alert flag is held between samples (harm.py:301-310). The uplink fires when `since >= eff` and `since >= d=2` (harm.py:313). d=2 ≤ I_max=15.

### (iii) An uplink with since ≥ base is never charged or blocked. OK.
- harm.py:318-327: `base` is the default T run through the same two `effective_interval` layers. The charge/block branch runs only `if not (alert_pending or since >= base)`. So with since ≥ base the uplink is neither charged nor dropped. In alert above the floor, base = min(60, 15) = 15 = I_max. At t* (since ≥ I_max ≥ eff and ≥ base) the uplink goes out. Tokens are refilled lazily per epoch index (harm.py:316-317). That is correct, because every charged uplink passes through the refill test first.

### (iv) A buffered sample at τ is delivered by the next uplink. OK.
- The sample is appended to `d.buffer` at the sample instant (harm.py:303-304), before the uplink decision in the same minute. Every uplink delivers the whole buffer and clears it (harm.py:336, 339). An uplink at minute τ itself carries the τ sample. Scoring (harm.py:379-394) counts a crossing as detected by the first uplink carrying a sample ≥ L taken inside the excursion. That matches the theorem's notion of "reported".
- Every step of the appendix proof holds in the code, given the premises: NWS floor present, Task-E `init` not used, `+OP` not set. The proof's "line 6 rejects every disable, except with W3": the code has no W3 event at all. OP is a constant boolean, so the theorem is about the `op_key=False` runs.

---------------------------------------------------------------------------------------------------
## A3. Theorem 3 proof vs `harm.simulate`, and theory/*.py vs U_B

**Summary: the proof's five classification facts all hold in `simulate`. `bound_adaptive.py` implements U_B term by term. DIFF: `bound.py`/`floor_time.py` implement the Corollary-1 A(t) form, not U_B. Their `band_lo`/`zero` modes are not valid bounds for a threshold-moving adversary. `floor_time.py` uses `> K`, not `> K-1`. The Corollary's B*(τ) uses j = ⌊τ/T_e⌋, which undercounts epochs when τ+I_max crosses into the next epoch (an error inside the manuscript). PREDICTIONS.md's B* closed form differs from the manuscript's.**

### Proof facts in `simulate`
- **Classification.** The uncharged condition is `alert_pending or since >= base` (harm.py:320). Type (a) is `alert_pending`, set only at an onset (harm.py:306-307) and cleared at each uplink (339). (b) is `since >= base`. (c) is the token-decrement branch (harm.py:326-327). **OK.** (When `budget is None` there is no class (c) limit; the theorem assumes a budget.)
- **Tokens ≤ B per started epoch.** The refill `tokens = budget` happens on a change of epoch index `t // epoch_min`, and epoch 0 starts at t=0. So at most ⌊t/T_e⌋+1 epochs × B. **OK.** (epoch_h=24, config/harm.yaml:91. theory/ hard-codes EPOCH=1440, consistent.)
- **Non-alert free uplinks ≥ T apart.** Outside alert, `base = effective_interval(T, False, ...)` ≥ T (the low-battery rule only takes a max). Gap to the previous uplink of any type ≥ base ≥ T. **OK**, given the first uplink at t=0 (last_uplink = -1e9).
- **Alert free uplinks ≥ I_max apart, inside R.** In alert, base = min(T, I_max) = 15, or larger below the floor. **OK because T=60 ≥ I_max=15.** If T < I_max the gap would be only T and the per-run term ⌊|r|/I_max⌋+1 would be wrong; the manuscript does not state T ≥ I_max. The alert flag means the last sample ≥ the threshold in force at that sample, which is ≥ θ_lo, so the minute is in R (sample-held). **OK** for C1, where θ_lo = band lo ≤ initial = action, and for C1+C3, where θ_lo = catalogue min 0.
- **Onsets ≤ ⌈samples/2⌉ per run.** An onset at sample s_i requires d.alert False after s_{i-1} (harm.py:305-308), so two consecutive samples cannot both be onsets. At most one uplink per onset, because `alert_pending` is a single flag. **OK.**

### theory/bound_adaptive.py vs U_B: OK
- `U_rob` (bound_adaptive.py:8-20): R is sample-held, `stage[t] >= theta_lo` at `t % p == 0`. That is formal.tex's "last sampled stage ≥ θ_lo". |r| is counted in **minutes**, inclusive, including the partial run up to t ("runs up to t"). Per run: `run // I_a + 1 + ceil(ceil(run/p)/2)`. Since R changes only at sample instants, a run of m minutes has exactly ⌈m/p⌉ sample instants, so it is consistent. Plus `1 + t//T_def + B*(t//EPOCH + 1)`. This is **exactly** U_B. θ_lo = `th['band_cm'][0]` = the envelope threshold lo under C1. OK.
- Coverage: bound_adaptive covers **C1 only**. No script evaluates U_B with θ_lo = catalogue min 0 (the C1+C3 case of Theorem 3).

### theory/bound.py: DIFF (not U_B)
- `U` (bound.py:28-42) = `1 + cumsum(onsets) + Σ_runs floor(run/I_a) + t//T_def + B(t//EPOCH+1)`, with the onsets and alert runs at a **fixed** threshold. This is the Corollary-1 replacement A(t), not the U_B run term (it has no `+1` per run and no ⌈⌈|r|/p⌉/2⌉). For `theta_mode='actual'` this is right for the drain attacker, who never moves the threshold, and the A(t) bookkeeping matches the Corollary. Runs are counted in minutes, inclusive, partial up to t.
- **DIFF:** `theta_mode='band_lo'` and `'zero'` (bound.py:49) compute A(t) for a device whose threshold is *fixed* at θ_lo or 0. That is **not** a bound for an adversary that moves the threshold. Concrete case: stage held at v with θ_lo ≤ v < θ_F. Toggling the threshold between θ_F and θ_lo at successive downlinks creates an onset every second sample, while the fixed-θ_lo series has one onset for the whole run. PREDICTIONS.md P1 ("'band_lo' for any C1 adversary that also moves the threshold") and P4 ("C1+C3, threshold lowered to 0") rely on these modes. The valid version for C1 is bound_adaptive.py, and none exists for C1+C3.
- The stage condition is checked on the half-open `range(tau, tau+I_a, p)` (bound.py:69; bound_adaptive.py:33), while Theorem 2 uses the closed [τ, τ+I_max]. With p=10, I_max=15 and τ ≡ 0 mod 10 this makes no difference. It would matter if I_max were a multiple of p.
- The B=None branch (bound.py:58-61) uses 1+⌊t/d⌋, a separate no-budget bound outside Theorem 3. That is fine.

### K, t_U, B*(τ)
- **K:** `K = (soc0 - floor)/100 * n_up` with n_up=1300 hard-coded (bound.py:13), matching config/devices/lwl01.yaml:22 and the `uplink_budget` model with sleep drain 0. It matches K=(β0-β_min)/q. **OK.** Float check: in `simulate` (strict `<` floor, repeated `-= 1/1300`) the floor is first reached after N = K+1 uplinks (261/521/781 for SOC0 40/60/80). The manuscript's "K-1" margin is therefore conservative.
- **t_U: DIFF (minor).** The manuscript defines t_U = min{t : U_B(t) > K-1}. `floor_time.py:12` uses `Ut > K` and the bound.py A(t)-form `U`, not U_B. For the code's strict-`<` floor this is still a valid lower bound (floor reached at N=K+1). But it is not the manuscript's t_U, which can be one uplink earlier. P3 and check_vs_replay.py test this weaker quantity.
- **B*(τ): DIFF, an error inside the manuscript; the code is right.** The Corollary uses j = ⌊τ/T_e⌋ and divides by (j+1). But U_B(τ+I_max) contains B(⌊(τ+I_max)/T_e⌋+1). When τ+I_max crosses an epoch boundary, B* is anti-conservative. Concrete case: T_e=1440, T=60, I_max=15, K=260, A=0, τ=1430 (j=0). The manuscript gives B* = 258-⌊1445/60⌋ = 234. U_B(1445) ≤ K-1 actually needs 1+24+2B ≤ 259, so B ≤ 117. (With p=10 only τ ≡ 1430 mod 1440 is affected.) bound.py and bound_adaptive.py evaluate U at `tchk = tau + I_a` with `B*(tchk//EPOCH + 1)`, so they are correct. The fix is j = ⌊(τ+I_max)/T_e⌋.
- **B* numbers:** formal.tex's 27.6–32.4 / 79.6–84.4 / 131.6–136.4 follow from formal.tex's own formula with K-2: (258-96)/5 = 32.4, (258-120)/5 = 27.6. PREDICTIONS.md uses `B* = (K - 1 - 24 d_c - A)/(d_c+1)` and gets 32.6/84.6/136.6, which is **K-1, not K-2**, and only the epoch-start point. A 0.2 inconsistency between the PREDICTIONS doc and the manuscript. No code computes B* in closed form.

---------------------------------------------------------------------------------------------------
## A5. Proposition 1 vs delivery / revocation / sizes

**Summary: the formula, the 2-byte header, the messages per window and the push time all match. Small DIFF: the code adds the RX1 delay (1 s) to "one frame time". The frame counts 50/1/2/14/48 reproduce from the code's constants, except that the disable message carrying a 32-byte chain reveal is **2** frames in the code's own F6 table (the reveal alone is 1), and the S6-R envelope (with H(r_rev)) is **51** frames.**

- **k formula / h_f:** `radio.fragment` (src/pqcap/radio.py:61-76). If `message_bytes <= max_app_payload`, 1 frame, no header. Otherwise `ceil(x / (N - frag_header))`. `fragment_header_bytes: 2` (config/model.yaml:3). P is the RP002 **N** (FRMPayload) column minus FOpts (model.py:54; radio.yaml:56: DR8 N=53, M=61), so P=53. **OK** (x>P gives ⌈x/51⌉; x ≤ P gives 1).
- **Worst/expected delivery:** `delivery.time_to_deliver_s` (delivery.py:8-20): worst = k·T_up + tail, expected = (k-½)·T_up + tail, with tail = RX delay + ToA of the last frame. The callers pass RX1_DELAY_S=1.0 (model.py:19, 115; revocation.py:31; opapproval.py:30). **DIFF (minor):** the manuscript says "plus one frame time". The code adds 1 s RX1 delay plus the last-frame ToA. Example: ML-DSA-44 S1 at DR8 has ttd_worst = 15001.29 s, against 250 min = 15000 s in the text (results/model_delivery.csv).
- **Messages per window:** `commands_per_device = (W // T_up) // k` (delivery.py:23-29). **OK.** At W=30 min, T_up=300 s: 6//50 = 0 (results/model_capacity.csv: S1 ML-DSA-44 US915 DR8 W30 cmds_per_device 0).
- **Push time:** `revocation.push_time_s` (revocation.py:27-33) = `max(ttd_worst(k), N·A_k/δ)`, δ=1 when duty is None (US915: radio.yaml:54). A_k = airtime summed over all k frames (`frames_airtime_s`, radio.py:97-98; model.py:93). **OK**, apart from the same 1 s plus last-frame tail inside k·T_up.
- **Frame counts at US915 DR8 (P=53, 51 data bytes per fragment)**, from results/sizes.csv (signature statistic `max`, config/model.yaml:2; `measured_sizes` model.py:59-65):

| Message | Size source | x (B) | k (code) | Manuscript | |
|---|---|---|---|---|---|
| ML-DSA-44 command (S1, depth 0) | TokenModel body 16+64=80 (config/token.yaml) + sig 2420 | 2500 | ⌈2500/51⌉=**50** | 50 | OK |
| Replacement envelope (S6) | ENVELOPE_BYTES 112 (envelope.py:31) + ML-DSA-44 2420 (model.py:336-337) | 2532 | **50** | 50 | OK |
| Replacement/renewal envelope S6-R | 2532 + REV_COMMIT_BYTES 32 (model.py:368) | 2564 | **51** (results/model_renewal_cost.csv) | (50) | DIFF if "replacement envelope" is meant for S6-R. Active S6-R revocation pushes the reveal instead, so the text is OK for S6. |
| Crisis command | crisis_fields 4+4+8 + tag 8 or 16 (model.yaml s6) | 24 / 32 | **1** | 1 | OK |
| Chain reveal alone | f6 reveal_bytes 16/32 | 16 / 32 | **1** | 1 | OK |
| Disable message = command + chain reveal (opapproval.py:29; model.py:356-357, cmd = 24 B with T8) | | 40 / 56 | 1 / **2** | "1 frame for ... a chain reveal" | DIFF for the 32-byte reveal: results/f6_op_approval.csv DR8 gives `chain reveal 32 B, 56 B, 2 frames`. With a T16 command: 48 B (1 frame) / 64 B (2 frames). |
| S6-R revocation frame | REVOCATION.size 4 + r_rev 16/32 (model.py:369) | 20 / 36 | 1 | n/a | |
| Ed25519 approval token | sig 64 (model.py:346-351, signature only) | 64 | ⌈64/51⌉=**2** | 2 | OK (also 2 with the command: 88 B) |
| Falcon-512 approval token | sig_max 664 | 664 | ⌈664/51⌉=13.02→**14** | 14 | OK (688 B with command → 14). With the nominal max 752 it would be 15, so the result depends on taking the *observed* max. |
| ML-DSA-44 approval token | sig 2420 | 2420 | 47.45→**48** | 48 | OK (2444 B with T8 command → 48; **2452 B with a T16 command → 49**) |

- Device-cost remark: "one HMAC-SHA256 over 16 bytes" matches body = 4+4+8 = 16 (envelope.py:192). OK.

---------------------------------------------------------------------------------------------------
## Other mismatches noticed in passing
1. Binding without `"env"||id_D` (see A1). Still open at 5eb8615.
2. The approval mechanism differs. envelope.py and its docstring describe an OP **signature token** passed in as a boolean (D2). formal.tex describes a **hash chain** with stored state x_j. The device code implements neither the chain state nor the "one reveal = one approval" accounting.
3. Commands carry `target` and `reserved` fields that are part of the MAC and of the checks but absent from c=(a,θ) and Def. 2.
4. formal.tex: "I_E is a finite set of invariants ... the artifact uses four". The code has those four plus the F3 commissioning threshold, which lives only in the floor (matches the text). The envelope has no θ_F field.
5. Theorem 3's per-run alert term silently requires T ≥ I_max (true for the config: 60 ≥ 15).
6. Theorem 3 says "the floor is not reached before t_U". The code's floor is strict `<` and is reached at N=K+1. That is consistent, but floor_time.py computes a different quantity (U>K, A(t) form).

---------------------------------------------------------------------------------------------------
## Summary table

| Item | Sub-item | OK/DIFF | Reason |
|---|---|---|---|
| A1 | check order tag→replay→handle→envelope→floor→approval | OK | Same order. An extra `length` check comes first. |
| A1 | floor after envelope, same pre-state | OK | envelope.py:292-298 |
| A1 | state only on acceptance (envelope.py) | OK | counter committed in `_check_policy`, returned only at check_s6f:301 |
| A1 | state only on acceptance (harm replay) | DIFF | `Dev.counter` (= device last_counter) is incremented before the check, even on reject (harm.py:351). No effect on outcomes. |
| A1 | reason codes | DIFF | `length`, `revoked`, `catalogue`/`expired`/`bounds`/`invariant:*`, `floor:*`, `op_token_required` instead of tag/replay/handle/block/floor/approval |
| A1 | extra checks | DIFF | catalogue+reserved==0 and target ∈ rule.targets are not in Def. 2 |
| A1 | approval = fresh chain reveal | DIFF | boolean `op_token_valid`, no chain state or consumption |
| A1 | binding "env"\|\|id_D\|\|enc(E) | DIFF | signature over the 112-byte enc(E) only (envelope.py:349-354) |
| A2 | (i) threshold ≤ θ_F | OK (latent DIFF) | holds for all 41 events. On the no-NWS fallback `_max_alert_threshold`=0 means no cap. Task-E `init` can bypass. |
| A2 | (ii) eff ≤ I_max in alert above floor, C1 and C1+C3 | OK | outer `effective_interval(..., floor)` with alert_max=15 survives envelope replacement |
| A2 | (iii) since ≥ base never charged/blocked | OK | harm.py:320 |
| A2 | (iv) τ sample delivered by next uplink | OK | buffer appended before the uplink decision, flushed at every uplink |
| A3 | uplink classification | OK | alert_pending / since≥base / tokens |
| A3 | ≤ B per started epoch | OK | lazy refill on epoch-index change |
| A3 | non-alert free uplinks ≥ T apart | OK | base ≥ T |
| A3 | alert free uplinks ≥ I_max apart | OK (needs T ≥ I_max) | base = min(T, I_max). The assumption is not stated in the manuscript. |
| A3 | onsets ≤ ⌈samples/2⌉ per run | OK | onset needs a non-alert previous sample, single pending flag |
| A3 | bound_adaptive.py = U_B | OK | term-by-term match. |r| in minutes, inclusive, partial run to t, sample-held R. C1 only. |
| A3 | bound.py = U_B | DIFF | implements the Corollary A(t) form. band_lo/zero modes are invalid for a threshold-moving adversary (PREDICTIONS P1/P4). |
| A3 | K | OK | (soc0-20)/100·1300 |
| A3 | t_U | DIFF (minor) | floor_time.py uses U>K with the A(t) form, not U_B>K-1 |
| A3 | B*(τ) | DIFF (manuscript) | j=⌊τ/T_e⌋ undercounts epochs when τ+I_max crosses an epoch (τ=1430: 234 vs 117). Code correct. PREDICTIONS uses K-1, not K-2. |
| A5 | k=⌈x/(P−2)⌉ if x>P, h_f=2, P=53 | OK | radio.py:61-76, model.yaml:3, radio.yaml:56 |
| A5 | worst/expected delivery | DIFF (minor) | code adds RX1 delay 1 s plus last-frame ToA |
| A5 | messages per window | OK | delivery.py:27-29 |
| A5 | push time | OK | revocation.py:27-33 (same 1 s tail) |
| A5 | frames 50/50/1/2/14/48 | OK | reproduced from sizes.csv max + token/envelope constants |
| A5 | "1 frame for a chain reveal" | DIFF | reveal alone 1, but the disable message with a 32-byte reveal is 2 frames (f6_op_approval.csv). S6-R envelope is 51. ML-DSA-44 token with a T16 command is 49. |
