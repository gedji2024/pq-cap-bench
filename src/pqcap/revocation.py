"""Envelope validity V with routine renewal: exposure window after compromise, and renewal airtime cost.

Exposure window = how long, after the compromise is detected and revocation starts, the attacker can
still get commands accepted. Detection delay is NOT included (it adds equally to every scheme).

  S4 / S4-F under C1  : unbounded. The only way to revoke the leaked session key is a re-key message, and
                        in these schemes it can only be authenticated by the compromised key itself
                        (or needs a site visit). No over-the-air bound exists.
  S4-E / S6 under C1  : passive expiry -- the authority stops renewing; the envelope in force expires within
                        V (worst V, expected V/2 for a compromise uniform over the renewal period).
                        active push -- the authority pushes a replacement envelope; exposure is the time to
                        deliver it to all N devices (Class A + gateway airtime), capped at V.
  S4-E / S6 under C3  : each attacker-minted envelope is capped at V by firmware (validity_ok), but the
                        attacker can keep minting until the policy root key is rotated (not modelled).
  any scheme under C2 : no accepted forged commands (see K5), so no command exposure.
"""

from __future__ import annotations

import math

import pandas as pd

from . import delivery as dl


def push_time_s(frames: int, airtime_s: float, last_toa_s: float, n_devices: int, uplink_s: float,
                duty: float | None) -> float:
    """Time to deliver one envelope to every one of N devices: per-device Class A latency, or the
    gateway airtime/duty-cycle limit, whichever is longer."""
    per_device = dl.time_to_deliver_s(frames, uplink_s, 1.0, last_toa_s)["ttd_worst_s"]
    gateway = n_devices * airtime_s / (1.0 if duty is None else duty)
    return max(per_device, gateway)


def exposure(chans, envelope_bytes: dict[str, int], cfg: dict, uplink_s: float, link_cost) -> pd.DataFrame:
    rows = []
    for V in cfg["validity_hours"]:
        for scheme in ("S4", "S4-F"):
            rows.append({"scheme": scheme, "compromise": "C1", "validity_h": V, "mechanism": "none OTA",
                         "region": "-", "dr": -1, "devices": -1,
                         "exposure_worst_h": math.inf, "exposure_expected_h": math.inf})
        for scheme, eb in envelope_bytes.items():
            rows.append({"scheme": scheme, "compromise": "C1", "validity_h": V, "mechanism": "passive expiry",
                         "region": "-", "dr": -1, "devices": -1,
                         "exposure_worst_h": float(V), "exposure_expected_h": V / 2})
            rows.append({"scheme": scheme, "compromise": "C3", "validity_h": V,
                         "mechanism": "per minted envelope (until root-key rotation, not modelled)",
                         "region": "-", "dr": -1, "devices": -1,
                         "exposure_worst_h": float(V), "exposure_expected_h": float(V)})
            if not cfg.get("active_push"):
                continue
            for ch in chans:
                if ch.phy is None:
                    continue
                lc = link_cost(eb, ch)
                for N in cfg["devices"]:
                    t = push_time_s(lc["frames"], lc["airtime_s"], lc["last_frame_toa_s"], N, uplink_s, ch.duty) / 3600
                    rows.append({"scheme": scheme, "compromise": "C1", "validity_h": V, "mechanism": "active push",
                                 "region": ch.region, "dr": ch.dr, "devices": N, "envelope_bytes": eb,
                                 "envelope_frames": lc["frames"], "push_time_h": t,
                                 "exposure_worst_h": min(float(V), t), "exposure_expected_h": min(V / 2, t)})
    return pd.DataFrame(rows)


def renewal_cost(chans, envelope_bytes: dict[str, int], cfg: dict, uplink_s: float, link_cost) -> pd.DataFrame:
    """Calm-phase airtime of routine renewal: one envelope per device every V hours."""
    rows = []
    for scheme, eb in envelope_bytes.items():
        for ch in chans:
            if ch.phy is None:
                continue
            lc = link_cost(eb, ch)
            for V in cfg["validity_hours"]:
                per_day = 24 / V
                opp_v = dl.downlink_opportunities(V * 3600, uplink_s)
                budget_day = dl.gateway_airtime_budget_s(86400, ch.duty)
                for N in cfg["devices"]:
                    air_day = N * lc["airtime_s"] * per_day
                    rows.append({"scheme": scheme, "region": ch.region, "dr": ch.dr, "validity_h": V, "devices": N,
                                 "envelope_bytes": eb, "envelope_frames": lc["frames"],
                                 "airtime_per_renewal_s": lc["airtime_s"], "renewals_per_day": per_day,
                                 "gateway_airtime_per_day_s": air_day, "gateway_budget_per_day_s": budget_day,
                                 "gateway_utilisation": air_day / budget_day,
                                 "device_downlink_share": lc["frames"] / opp_v,
                                 "feasible": lc["frames"] <= opp_v and air_day <= budget_day})
    return pd.DataFrame(rows)
