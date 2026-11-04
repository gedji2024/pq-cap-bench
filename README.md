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

### Measurement protocol (HOST, not MCU)
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
- The reference run was done on an **Apple M5 (arm64)**, not on x86. `env.json` records the actual host. Re-run on the target x86 host for x86 numbers.

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

## What is NOT measured
- **MCU cost:** cycles, RAM, flash and energy for verification on the device. Host timings rank algorithms; they do not predict Cortex-M figures.
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
