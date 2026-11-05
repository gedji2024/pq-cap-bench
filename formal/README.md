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

`make_freshness.py` derives this theory from `crisis.spthy` by removing the envelope-state premises (`Hnd`, `!Env`) from `Device_Accept`, and nothing else. `tests/test_formal.py` checks that the committed file matches.

- **Why this is sound.** Removing premises only adds traces. Every trace of `crisis.spthy` is a trace of `freshness.spthy` with the same `Accept`, `Send` and `RevealSess` actions. A trace property over those actions that holds in `freshness.spthy` therefore holds in `crisis.spthy`. That covers `ctr_monotone` and both P4 lemmas.
- **Why it is needed.** With `Hnd`/`!Env` in `Device_Accept`, the counter induction did not terminate within 900 s under heuristics s, S, C, P, I, c and p. A goal-ranking oracle didn't help either. In the projection it verifies in 47,794 steps.
- **Reuse.** `crisis.spthy` still declares `ctr_monotone [reuse]`. That reuse is justified by the proof in `freshness.spthy` plus the trace-inclusion argument above. Tamarin does not check that step itself.

## `delegation.spthy`: P2, delegation by attenuation only

| Lemma | Property | Holds under |
|---|---|---|
| `exec_attenuated_child` | a strictly attenuated child envelope can be installed | honest run |
| `P2_attenuation_only` | an installed child's bounds are a sub-multiset of a root the honest PA issued for that device | delegate key revealed or malicious; breaks only under C3 |

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
