# pq-cap-bench

Measures post-quantum (PQ) signature costs on a host CPU and models what they mean for delivering
**capability tokens** (signed command authorisations) over **LoRaWAN Class A** and **NB-IoT** downlinks.

Every number in `results/`, `figures/` and `REPORT.md` comes from one of two places:
1. an actual run of `make bench` / `make model` on this machine, or
2. a specification table stored in [`config/radio.yaml`](config/radio.yaml), with its citation.

No measured value is hard-coded. Test fixtures in `tests/` use obviously synthetic sizes and never reach the outputs.

## Quick start

```bash
brew install uv cmake ninja openssl@3      # or your distro's equivalents
make liboqs      # builds liboqs 0.16.0 from source into ./vendor, records commit + flags
make all         # bench (~1 h) -> model -> figures -> REPORT.md
make test        # pytest
make cov         # pytest + coverage (fail-under 90 % on model code)
```

| Target | What it does | Writes |
|---|---|---|
| `make bench` | host timing and size benchmark | `results/bench_raw.csv.gz`, `bench_runs.csv`, `bench_summary.csv`, `sizes.csv`, `kem_sizes.csv`, `algorithms.csv`, `env.json` |
| `make model` | token, radio and delivery model from the measured sizes | `results/model_*.csv`, `results/kill_criteria.json` |
| `make report` | figures and report | `figures/*.pdf|png`, `REPORT.md` |

Python dependencies are pinned in `uv.lock`; `liboqs-python` is pinned to git tag `0.16.0.2`.
The liboqs commit, CMake flags and compiler are recorded in `vendor/liboqs-build-info.json` and copied into `results/env.json`.

## Scope

### Algorithms
Algorithms are resolved at runtime against the mechanisms liboqs reports as enabled. The exact names used are logged in `results/algorithms.csv`.
An algorithm that is missing is skipped and the reason is logged. Nothing is substituted silently.

| Requested | Name used with liboqs 0.16.0 |
|---|---|
| ML-DSA-44/65/87 | `ML-DSA-44/65/87` |
| Falcon-512/1024 (FN-DSA) | `Falcon-512`, `Falcon-1024`. There is no `FN-DSA-*` name in 0.16.0; it is tried first, and the fallback is logged. These are the unpadded, variable-length variants. |
| SLH-DSA-SHA2-128s/f | `SLH_DSA_PURE_SHA2_128S/F` (pure, non-prehash) |
| LMS | `LMS_SHA256_H10_W4`: **unavailable for sign/verify**. liboqs-python 0.16.0.2 raises `NotImplementedError` ("verify-only"), so no LMS signature can be produced. Nominal sizes are logged but not measured. |
| XMSS | `XMSS-SHA2_10_256`, measured. It is built with `OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON` for **benchmarking only**. Keys are regenerated outside the timed region when the 2^10 budget is exhausted. |
| ECDSA-P256, Ed25519, HMAC-SHA256-T16/T32 | `pyca/cryptography` on OpenSSL |
| Hybrid | ECDSA-P256 ‖ ML-DSA-44, concatenated; both parts must verify |

Encodings:
- ECDSA signatures are carried as fixed 64-byte r‖s (IEEE P1363 / COSE). The DER↔raw conversion happens inside the timed call.
- The ECDSA public key is the 65-byte SEC1 uncompressed point.
- HMAC uses a 32-byte key and has no public key.

### Measurement protocol (Apple M5 host, not MCU)
- Each op runs 50 warm-up calls, then 1000 timed calls with `time.perf_counter_ns`.
- Garbage collection is disabled inside timed loops.
- Message sizes are 32, 96 and 160 bytes: fixed, seeded content.
- keygen is message-independent and is timed once per run.
- The whole benchmark is repeated 3 times.
  - `bench_runs.csv` gives per-run median, IQR, p95, mean, min and max.
  - `bench_summary.csv` gives pooled statistics plus the run-to-run CV and relative range of the per-run medians.
- Signature sizes are recorded **for every signature produced** (3 runs × 3 sizes × 1000). `sizes.csv` reports min/median/max; this matters for Falcon. The liboqs nominal maximum is listed alongside.
- ML-KEM-512/768 keygen, encaps and decaps are timed. Their ciphertext sizes feed scheme S2.
- **CPU pinning.** `os.sched_setaffinity` is used where it exists (Linux). macOS has no affinity API, so the process is **not pinned**, and this is recorded in `env.json`.
  - Apple-silicon hosts mix performance and efficiency cores under OS-managed DVFS.
  - Check the run-to-run CV before trusting small differences.
- The reference run was done on an **Apple M5 (arm64)**. Every timing is labelled "Apple M5 host, not MCU".
  - The label is derived from `results/env.json`, so a re-run on another host relabels itself.
- **Optional x86 re-run:** on an x86 Linux host, run `make liboqs && make all`. `sched_setaffinity` pinning and the cpufreq governor are then recorded automatically. Not required for the model results, which depend only on sizes.

### Capability-token model (`config/token.yaml`)
- token = header 16 B + constraints 64 B + authenticator + d × (32 B hop constraints + 8 B key id + hop authenticator), for d ∈ {0,1,2,3}.
- Each delegation hop uses the same authenticator mechanism as its scheme. For S2 and S4 that is an HMAC tag per hop, a pessimistic choice compared with macaroon-style chaining, which needs a single final tag.

| Scheme | Per-command authenticator | Extra |
|---|---|---|
| S1 | PQ signature (each available PQ algorithm) | - |
| S2 | HMAC-SHA256-T16 | one **epoch message** per T hours = cert body (`model.yaml: s2_epoch_cert_fields`, 46 B) + ML-DSA-44 signature + ML-KEM ciphertext (512 or 768, measured) |
| S3 | ECDSA-P256 ‖ ML-DSA-44 | - |
| S4 | HMAC-SHA256-T16 with a pre-shared key: the "MAC suffices" baseline | - |
| S5 | ECDSA-P256 | - |

**S6 "pre-positioned capability envelopes"** (`model.yaml: s6`).
- **Calm phase.** Each device receives one PQ-signed envelope during a calm period P ∈ {6, 24, 72} h before the event: header 16 + bounds 64 + invariants 32 B + signature (ML-DSA-44 or Falcon-512, measured).
  - Feasible means the envelope frames fit within the Class A downlink opportunities in P, **and** N × envelope airtime fits within the gateway's airtime budget in P.
- **Crisis phase.** Each command = envelope handle 4 + counter 4 + params 8 + HMAC-SHA256 truncated to 8 or 16 B. The device accepts it only if it lies inside the envelope bounds (`pqcap.envelope`, added with the blast-radius metric).
- The tag length is a truncation design parameter, not a measurement.
- The crisis HMAC key is assumed pre-provisioned, as in S4.
- Outputs: `model_s6_calm.csv`, `model_s6_crisis.csv`, and `model_s6_compare.csv` (vs S1/S2/S4; S2 counts per-command cost only).

**S2 requires a key-establishment step.** The server encapsulates to the device's ML-KEM public key, and the ciphertext travels downlink inside the epoch message.
- The device must have registered its KEM public key beforehand (uplink, **not modelled**), and the device must hold an ML-KEM secret key.
- The S2 per-command token is byte-identical to the S4 token. The difference is the amortised epoch message: `results/model_s2_amortization.csv`.

### Radio model
**Payload tables.** These come from LoRa Alliance **RP002-1.0.3** (2021):
- US902-928: Table 16 (downlink DR8-13 = SF12…SF7 / 500 kHz) and Tables 20/21 (M/N).
- EU863-870: Table 8 (DR0-6 LoRa; DR7 FSK is excluded) and Tables 12/13.
- The default is the *not repeater compatible* table (`payload_table_variant`).
- N assumes an empty FOpts. Piggy-backed MAC commands would reduce it.

**Frame overhead.** PHYPayload = FRMPayload + 13 B (MHDR 1 + FHDR 7 + FPort 1 + MIC 4).
- All four sizes are verified against **TS001-1.0.4**: §4.1 Table 2 (MHDR 1, MIC 4), §4.3.1 Table 6 (FHDR 7..22) and §4.3.2 Table 10 (FPort 0..1).
- FPort is counted only when FRMPayload is non-empty (TS001 §4.3).
- **No double counting.** RP002 §2.4.6/§2.5.6 define M as the max MACPayload (excludes MHDR and MIC) and N as the max FRMPayload with empty FOpts (also excludes FHDR and FPort). A full frame is therefore N + 13 = M + 5 bytes; a unit test checks this for every DR.
- FOpts is assumed empty (`fopts_bytes: 0`). A non-zero value adds to the PHYPayload and lowers the usable N by the same amount.

**PHY settings.** RP002 Table 109: preamble 8, explicit header, CR 4/5.

**CRC.** This follows RP002 Table 109: `crc_on_downlink: false`, `crc_on_uplink: true`. Only downlinks are transmitted in this model.
- The earlier setting (downlink CRC on, +16 bits per frame) is kept as a sensitivity variant: `results/model_sensitivity_crc.csv`, `REPORT.md` §7b, and `K1_crc_sensitivity` in `kill_criteria.json`.
- CRC changes airtime only, never the frame count.

**Time on air.** This is the Semtech SX1276/77/78/79 datasheet Rev. 7 formula (§4.1.1.7, p. 31). Low-data-rate optimisation is switched on automatically when T_sym > 16 ms.
- Unit-tested against **9 published values**: Haxhibeqiri et al., *Sensors* 17:1193 (2017), Table 1, with all parameters stated; and Yasmin et al., *Sensors* 20:6721 (2020), Table 2.
- For Yasmin et al. the paper states only "24-byte payload, CR 4/5". Preamble 8, explicit header, CRC on and LDRO for SF11/12 are inferred LoRaWAN defaults, and the published values reproduce exactly under them.
- Semtech AN1200.13 could not be retrieved, so it is not used.

**Fragmentation.** A message that fits in N bytes is sent unfragmented. Otherwise every frame carries a 2-byte fragment header (configurable) plus N − 2 data bytes.

**Duty cycle.** EU868 gateway downlink defaults to **1 %**.
- Source: ERC Rec 70-03 Annex 1 / ETSI EN 300 220-2 for 868.0-868.6 MHz, which covers RX1 on the default channels.
- RX2 at 869.525 MHz is in a **10 %** sub-band. Set `eu868_duty_cycle: 0.10` to model RX2-only downlinks.
- Off-time = airtime × (1/d − 1).
- US915 has no duty-cycle limit in this model; FCC dwell-time rules are not modelled.

**Class A delivery.** One downlink per uplink, with an uplink every 300 s (configurable).
- Time to deliver an F-frame command:
  - worst case = F × 300 s + RX1 delay (1 s, RP002 §2.3) + last frame's airtime.
  - expected = (F − 0.5) × 300 s + the same tail.
- Commands per device in window W = ⌊W/300 s⌋ ÷ F.
- Commands per gateway = min(N × per-device, ⌊gateway airtime budget ÷ airtime per command⌋). The budget is W × duty cycle in EU868, and W in US915 (one half-duplex radio).
- **Not modelled:** collisions, uplink loss and retransmission, ADR, RX1-vs-RX2 choice, multiple gateways, MAC-command piggy-backing, FOpts.

**NB-IoT.** Only the number of messages is computed, using a configurable 1280-byte payload. This is the brief's default, **not** a specification value. NB-IoT airtime and latency are not modelled.

## Kill criteria (answered automatically in `REPORT.md` §8)
- **K1.** Is S1 with ML-DSA-44 deliverable within W = 30 min for N = 50 at US915 DR8?
  - "Yes" requires both that worst-case time to deliver ≤ W and that the gateway can give each of the N devices at least one command within W.
- **K2.** What is the S2/S4 per-command overhead ratio (airtime and bytes)?
  - It is computed at the configured commands-per-epoch points and at the Class A maximum, for T ∈ {1, 6, 24} h and both ML-KEM sizes.
  - "Near-symmetric" means ratio ≤ 2.0 (configurable).
  - Channels where the epoch message alone needs more downlinks than the epoch provides are reported as infeasible.
- **K3.** For each DR, which is the smallest PQ-carrying token (S1 or S3, depth 0) that fits one frame, or "none"?
- **K4.** Does every S6 crisis command (8 B and 16 B tags) fit in one frame at every US915 downlink DR?
- **K5.** What is the blast-radius ratio S6/S4 under cloud-side HMAC-key compromise?

## Manufacturer device catalogue (`config/devices/`, `pqcap.devices`, `config/policies.yaml`)
**Devices.** Milesight EM400-UDL and EM410-RDL, Dragino PS-LB and LWL01.

**Fields.** Each device file records, for every field, the document URL, access date, section/page and a verbatim quote:
- downlink command codes, payload lengths and parameter ranges;
- FPort;
- battery data.

Where a manual does not state a value, the field is `null` with "NOT FOUND".

**Range labels.** Each parameter range is labelled by its origin:
- `downlink_table`;
- `app_setting`: a ToolBox or AT range that the manual does not state for the downlink;
- `encoding`: no documented limit, so the full encodable range is used.

**Verification.** `scripts/verify_device_docs.py DOCS_DIR` re-hashes the downloaded documents and checks every quote verbatim. The result is in `data/devices/verification.json`. Document texts are not stored in the repository.

**Policy sweep.** Envelope bounds are POLICY levels (tight / medium / loose). K5 and K6 are reported as ranges over devices × policies (`REPORT.md` §8a). Counts are exact, from a cell partition of the check's interval tests, and a property test compares them with brute-force enumeration.

The earlier K5/K6 on the assumed catalogue (`config/actions.yaml`) are **superseded**. That file still drives the harm replay and its invariants, which remain ASSUMED.

## Device profile and blast radius (`config/actions.yaml`, `pqcap.envelope`, `pqcap.blast`)
**Profile.** The action **types** follow Kerkez et al., "Toward Agent-Native Water Systems", ACM DXConf 2026, doi:10.1145/3847238.3849040 (§4.1 single ultrasonic depth sensor per cellular node; §6 adaptive reporting):
- `set_reporting_interval`
- `request_immediate_uplink`
- `sensor_enable` (enable/disable)
- `set_alert_threshold`

Physical invariants (state-dependent):
- a minimum reporting rate, and no sensor disable, during an active alert;
- a battery floor, below which faster reporting and immediate uplinks are refused.

⚠ **Every numeric value is "assumed — pending field profile".** The paper is cited for the action types only.

**Checks.** All checks are pure functions (state in, state out). The 112-byte envelope is fully specified: header 16 (handle, validity), bounds 64, invariants 32.

| Scheme | Device accepts a command if |
|---|---|
| S4 | valid MAC + fresh counter + in catalogue |
| S4-F | the above + static firmware bounds + firmware invariants |
| S4-E / S6 | the above + installed envelope handle + validity window + envelope bounds + envelope invariants |

S4-E and S6 differ only in how the envelope is installed:
- S4-E: HMAC with a per-device policy key.
- S6: PQ signature, verified with the authority's public key.

**Naming.** Adversaries A1–A5, compromise levels C0–C4, properties P1–P8 and attacks T1–T10 follow the internal document *Étape 2 — Modèle de menace et propriétés de sécurité* v0.1 (2026-11-04). Coverage and status are tracked in `config/traceability.yaml` and rendered in `REPORT.md` §8b.

**Baselines and compromises (`config/threat.yaml`, assumed key custody).**
- **S4-F:** per-command HMAC plus static bounds and invariants compiled into firmware. Not updatable over the air.
- **S4-E:** the same envelopes as S6, but authenticated with HMAC-SHA256 under a per-device key that only the policy authority holds; the cloud platform does not.
- **Compromise levels (Étape 2 §3):**
  - C0: nothing compromised. A1/A2/A3/A5 can only send proposals to an honest PDP, which filters them with the event-envelope policy for every scheme (P8 provenance labels are not modelled).
  - C1: the cloud command platform (agent runtime **and** PDP), which holds the per-command session keys k_{d,e}.
  - C2: a network server or gateway, which holds only LoRaWAN network keys. Application-layer authentication is assumed end-to-end.
  - C3: the PA HSM, which holds sk_PA and the S4-E per-device keys.
  - C4: one physically extracted device. Counted for that device only.
  - C1+C3: both, reported as an extra row that is not an Étape 2 level.
- An attacker holding a scheme's envelope key installs a permissive envelope (the whole catalogue, no invariants).
- **K6** = blast(S4-E) / blast(S6) per compromise, plus the properties that separate the two. Third-party verification without forging power is demonstrated with real ML-DSA-44 and HMAC in `tests/test_threat.py`.

**S6+F (D2), two-tier defence.**
- A non-updatable firmware floor (battery floor, minimum alert reporting rate) holds even if the envelope is replaced.
- On top of it sit updatable S6 envelopes.
- "Disable sensor" requires an OP approval token signed with sk_OP, a key distinct from sk_PA (`check_s6f`, property-tested).
- Extra rows C1+C3 (OP key safe) and C1+C3+OP. The token's cost in frames is reported for each measured signature algorithm.

**Counting.** Blast radius = the number of (action, target, value) commands the device accepts. It is counted by running every candidate through the device check in an explicit device state (alert × battery). K5 uses `count_state`; all four states are in `results/model_blast_radius.csv`.

**Hypothesis property tests:**
- soundness: no accepted command is outside bounds, catalogue, validity or any invariant;
- completeness;
- bounded schemes accept a subset of S4;
- tamper rejection;
- 112-B envelope round-trip.

## Revocation (`pqcap.revocation`, `model.yaml: revocation`)
- Envelope validity is V ∈ {6, 24, 72} h, with routine renewal. Firmware rejects any envelope valid for longer than V, including an attacker-minted one (`validity_ok`, property-tested).
- **Exposure window after revocation starts** (detection delay excluded, since it is the same for every scheme):
  - S4 / S4-F under C1: unbounded. There is no over-the-air revocation path that does not depend on the leaked key.
  - S4-E / S6, passive expiry: worst V, expected V/2.
  - S4-E / S6, active push: the time to deliver a replacement envelope to all N devices, capped at V. The authority's downlink path is assumed independent of the compromised platform.
  - S4-E / S6 under C3: each minted envelope is capped at V. Rotating the root key is not modelled.
- **Renewal cost:** the gateway airtime per day of re-sending envelopes every V, against the duty-cycle budget, per DR and N.
- **S6-R (D1), revocation committed in advance.**
  - Each envelope carries H(r_rev), 32 B of SHA-256.
  - Revoking means revealing r_rev (16 or 32 B) plus the 4 B handle, in one frame. No signature is needed: only the PA knows a preimage of the signed commitment.
  - The device then rejects every command for that handle (property-tested).
  - Active-revocation time is compared with S6 and S4-E at every US915 DR in `REPORT.md` §7d.

## Harm-weighted replay (`pqcap.harm`, `config/harm.yaml`)
**Input.** USGS 08074000 Buffalo Bayou at Houston, TX, gage height, 2017-08-26..31 (Hurricane Harvey).
- The raw JSON is cached in `data/`. The query URL, the URL after redirect, the retrieval date and the SHA-256 are in `data/*.meta.json`.
- `make data` re-fetches it.
- Gaps longer than 60 min, including two that bracket the peak, are filled by linear interpolation and listed in the report.

**Simulation.** A minute-resolution model of one node, with one downlink opportunity after each uplink. This holds for both LoRaWAN Class A and the cellular nodes of Kerkez et al. §4.1.
- The device samples, raises a firmware alert (immediate uplink), buffers samples and reports on its interval.
- Each delivered command goes through the scheme's device check.
- Invariants are enforced at acceptance **and** on the device's effective behaviour ("hard limits below the agent", Kerkez et al. §8).

**Battery.** Sleep current 50 µA and transmit current >200 mA come from the paper. The per-uplink charge is derived from its "drains a battery in a week" statement, under a stated interpretation (assumed).

**Attacker.** At every opportunity, the attacker sends the most harmful command the device would accept (*suppress* or *drain*), chosen with the same pure check the device runs.

**Metrics.**
- Missed and delayed crossings of operator reference levels.
- Floor-violating uplinks: uplinks below the floor at a rate the battery invariant forbids, scored identically for every scheme.
- Device death.
- Legitimate-command rejection rate for a ramp-up / step-down adaptive policy, also as distinct intents.

**Property tests:** with invariants below the agent, a C1 attacker never causes a floor-violating uplink or device death under S4-F, S4-E or S6.

## Device-side verification cost (`pqcap.pqm4`, `config/mcu.yaml`, `data/pqm4/`)
**Published pqm4 measurements on the NUCLEO-L4R5ZI.** No hardware is run in this project.
- `benchmarks.md` and `README.md` are stored at two pinned commits, with SHA-256 hashes in `data/pqm4/SOURCE.json`:
  - Head `6ff2be97`: ML-DSA-44 m4f/m4fstack, plus fndsa_provisional-512.
  - `94435189`, the last commit before pqm4 removed its old Falcon code: Falcon-512 m4-ct.
- Verify cycles and stack come from the parsed tables. Time is given at the 24 MHz measurement clock stated in pqm4's README and is not scaled.
- Energy is not reported: no cited current figure is stored.

## What is NOT measured
- **MCU cost on our own hardware.** Only pqm4's *published* verify cycles and stack are used (`REPORT.md` §7f), with no energy figures. Host timings rank algorithms; they do not predict Cortex-M figures.
- **Real radio:** loss, collisions, gateway scheduling and regulatory dwell time. Everything radio-related is analytical.
- Side-channel resistance, and secure state handling for XMSS/LMS.

## Next step
Measure device-side **verify** cost (and S2 ML-KEM decaps) on an MCU with **pqm4** on a Cortex-M4 (e.g. STM32L4/F4). STM32WL (Cortex-M4 + sub-GHz radio) is the realistic LoRaWAN end-device target. Feed the cycles and energy back into this model as a per-command device cost.

## Layout
```
config/   bench.yaml token.yaml model.yaml radio.yaml (cited spec tables)
scripts/  build_liboqs.sh
src/pqcap/ algorithms bench env radio token delivery model kill figures report cli
tests/    ToA oracles, fragmentation, token sizing, scheme accounting, kill criteria, wrappers, report
```
