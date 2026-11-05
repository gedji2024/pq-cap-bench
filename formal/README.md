# Formal models (Tamarin)

Tamarin prover **1.12.0** (Maude 3.5.1), installed with
`brew trust tamarin-prover/tap && brew install tamarin-prover/tap/tamarin-prover`.
The exact version string is in `proofs/VERSION.txt`. Re-run everything with `make formal`. The proof outputs are committed in `proofs/`.

`prove.sh` proves each lemma in its own Tamarin run with a wall-clock cap, writing `proofs/<theory>/<lemma>.txt`. A run killed at the cap ends with `TIMEOUT after N s`, and the report shows it as a timeout. A whole-theory run that crashed after 78 minutes, with no output at all, is the reason for this setup.

Naming follows *Étape 2 — Modèle de menace et propriétés de sécurité* v0.1.
- Compromise C1 is `Reveal_Session` (k_{d,e} revealed).
- C2 is the default Dolev-Yao network: read, drop, replay, inject.
- C3 is `Reveal_PA`.
- The OP approval key has its own `Reveal_OP`.

## `crisis.spthy`: crisis commands, S6 envelopes, S6-R revocation, OP token

| Lemma | Property | Holds under |
|---|---|---|
| `exec_accept`, `exec_disable`, `exec_revoke` | executability: each protocol path can complete | honest run |
| `P1_confinement` | an accepted command is covered by an envelope the honest PA issued for that device, handle and action | C1, C2; breaks only under C3 |
| `revocation` | no command is accepted for a handle after r_rev was received | all |
| `revocation_needs_PA` | a revocation happens only after the PA released r_rev | C1, C2; breaks only under C3 |
| `disable_needs_OP` | "disable" is accepted only for a (device, handle, counter) the OP approved | C1, C2, C3; breaks only if sk_OP is revealed |

All lemmas are proved with `--heuristic=s`. The default heuristic does not terminate on the inductive lemmas.

**Modelling fix found while proving `revocation`.** In the first version, "no envelope" was the state `Hnd(D, 'none')`, and an installed handle `h` was stored as `Hnd(D, h)`. An attacker holding sk_PA (C3) could sign an envelope whose handle is the constant `'none'`. Revoking it left the device in the "no envelope" state while that envelope still accepted commands. Active handles are now stored as `Hnd(D, <'hnd', h>)`, which can never equal `'none'`. With this fix `revocation` verifies under every compromise, C3 included.

## `freshness.spthy`: P4, generated from `crisis.spthy`

| Lemma | Property | Holds under |
|---|---|---|
| `ctr_monotone` (induction, reused) | a later accept carries a strictly larger counter | all |
| `P4_no_replay` | each (device, counter) is accepted at most once | C1, C2, C3 |
| `P4_injective_agreement` | an accepted command was sent by the PDP, once | C2, C3; breaks under C1 (stated disjunct) |

`make_freshness.py` derives this theory from `crisis.spthy` by removing the envelope-state premises of `Device_Accept`: the linear premise `Hnd(D, <'hnd', h>)` with its identical conclusion, and the persistent premise `!Env(D, h, a, c)`. Nothing else changes. `tests/test_formal.py` checks that the committed file matches the generator's output.

**Why the projection is needed:** with `Hnd`/`!Env` in `Device_Accept`, the counter induction did not terminate within 900 s under heuristics s, S, C, P, I, c and p, nor with a goal-ranking oracle. In the projection it verifies in 47,794 steps.

### Lemma (read-only premise dropping)

**Setting.** Let T be a Tamarin theory: multiset-rewriting rules, restrictions, and trace semantics on action facts. Let r = [P, F, !G] --[A]-> [C, F] be a rule in which
- F is a linear fact that r consumes and re-produces *identically* (same fact symbol, same terms);
- !G is a persistent premise.

Let T' be T with r replaced by r' = [P] --[A]-> [C]: F is dropped from both sides, !G from the premises. The other rules, the restrictions and the action labels A are unchanged.

**Claim.** Every trace of T is a trace of T': traces(T) ⊆ traces(T').

**Proof sketch** (induction on execution length).
1. Take an execution S0 →(ρ1) S1 → … → Sn of T, where each Si is a multiset of facts.
2. Map each step by the identity, except that an instance of r becomes the matching instance of r'. Use the same substitution, the same fresh values and the same message deductions.
3. *Base:* both executions start from the empty multiset.
4. *Applicability.* If S(i-1) is the same multiset in both executions, then ρ'i is applicable in T': its premises P are a sub-multiset of those of ρi.
5. *Same successor state.* For ρi an instance of r, T gives Si = S(i-1) − {P, F} + {C, F}. Since F ∈ S(i-1), this equals S(i-1) − P + C, which is exactly the successor in T'. Persistent facts are never consumed, so !G changes nothing.
6. *Other steps* are identical in both theories.
7. *Freshness.* Both executions use the same fresh names, so `Fr` uniqueness is preserved.
8. *Actions.* Every step carries the same action facts, so the two traces are equal. A restriction is a formula over the trace, so it holds for the T' trace exactly when it holds for the T trace. ∎

**Which lemmas transfer** from T' to T:
- **All-traces lemmas over any action facts** transfer: if every trace of T' satisfies φ, so does every trace of T. This covers `ctr_monotone`, `P4_no_replay` and `P4_injective_agreement`.
- **Not exists-trace lemmas:** a witness in T' need not be a trace of T. That is why the executability lemmas are proved in `crisis.spthy` itself.
- **Not observational-equivalence (diff) lemmas.**
- **`[reuse]`:** using the T' proof of an all-traces lemma as a `[reuse]` assumption inside T is sound by the claim. This is the case for `ctr_monotone [reuse]` in `crisis.spthy`.

**Side conditions** for `Device_Accept`, all checked syntactically by `make_freshness.py` and `tests/test_formal.py`:
- the dropped linear fact appears identically as premise and conclusion;
- the dropped `!Env` is persistent;
- no other rule, restriction or lemma is changed.

**Trust boundary.** The argument is on the multiset-rewriting semantics that Tamarin implements. It assumes Tamarin's own soundness (as every Tamarin proof does). It has not been mechanised.

### Computational note: HMAC truncation (Étape 2 H4, T9)

The symbolic model treats `mac/2` as an ideal MAC. The computational cost of truncating HMAC-SHA256 to t bits is quantified in `REPORT.md` Sec. 8c (`pqcap.truncation`, `results/f7_truncation.csv`):
- **Per attempt:** a forger succeeds with probability 2^-t (ideal-PRF bound).
- **Failed attempts do not advance the device counter** (the device accepts any ctr > ctr_D). Attempts are therefore limited by the radio, and q attempts succeed with probability at most q · 2^-t (union bound).
- **Two attacker budgets are evaluated:**
  - every Class A downlink slot for a year, for 1 to 200 devices;
  - the whole 4-byte counter window of one device (2^32 attempts, the most a device processes before a counter wrap forces a new epoch key).
- **Ignored:** the PRF distinguishing advantage of HMAC-SHA256.

## `delegation.spthy`: P2, delegation by attenuation only

| Lemma | Property | Holds under |
|---|---|---|
| `exec_attenuated_child` | a strictly attenuated child envelope can be installed | honest run |
| `P2_attenuation_only` | an installed child's bounds are a sub-multiset of a root the honest PA issued for that device | delegate key revealed or malicious; breaks only under C3 |

## F3 commissioning bounds: why there is no Tamarin lemma

The S6+F write-once commissioning bounds are:
- the maximum alert threshold (NWS action stage);
- the maximum reporting interval while in alert.

**Outside the symbolic model.** Each bound is a numeric interval test on a command parameter, evaluated by firmware against constants written once at installation. No protocol message can create, replace or relax them. `crisis.spthy` abstracts bounds to the action name, so a lemma there would be vacuous: it could not express "threshold ≤ T". The property does not depend on the adversary's knowledge. It holds as soon as the firmware check is correct, whatever keys are compromised (C1, C3, or both).

**Covered by property tests instead** (hypothesis, `tests/test_envelope.py::test_s6f_commissioning_threshold_cap`). For random envelopes, including attacker-minted permissive ones (C3), random device states, OP token present or absent, and random bounds, `check_s6f` never accepts a threshold above the bound.

The behavioural consequence is measured in the replay (REPORT Sec. 7e/7g): S6+F under C1+C3. The symbolic guarantee that the attacker cannot get "disable" without OP stays `disable_needs_OP`.

## Assumptions abstracted away

Cryptography:
- **The PQ signature** (ML-DSA-44 / Falcon-512) is Tamarin's ideal `signing` builtin, which assumes EUF-CMA (Étape 2 H4). Lattice structure, side channels and implementation bugs are not modelled.
- **The truncated HMAC** is an ideal MAC: the free function `mac/2`, with no equations. The forging probability of the 8- or 16-byte truncation (2^-64 per try, Étape 2 T9) is not modelled. That is a computational question.

Envelope content:
- **Bounds** are abstracted to the action name an envelope covers ("covering" = equality) in `crisis.spthy`, and to a multiset of action names in `delegation.spthy`.
- Integer intervals, physical invariants (P6) and their state dependence are covered by the Python property tests (`tests/test_envelope.py`, `tests/test_harm.py`), not by Tamarin.

Time and state:
- **Time is not modelled.** There are no validity windows [t0, t1], no expiry, and no validity-window attenuation in P2. Freshness rests on the monotone counter only (Étape 2 H3).
- **One active envelope per device** (`Hnd(D, handle)`). A device ignores a re-installation of a handle it already held (`install_once`). Several concurrent envelopes per device are not modelled.
- **A persistent counter** is assumed: the counter survives reboots, as the P4 risk note in Étape 2 requires.

Scope:
- **Delegation depth is 1.** Deeper chains repeat the same check; the induction over depth is argued, not mechanised.
- **Not modelled:** receipts (P5), provenance labels (P8), zone invariants (T10), and the radio. Availability attacks under C2 (drop, delay) are allowed by the Dolev-Yao network, but no liveness property is claimed.
- **Single PA and single OP** (`OnlyOnce`), with any number of devices. Multiple authorities are not modelled.
