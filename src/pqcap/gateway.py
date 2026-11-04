"""D6: gateway-side filtering of a C1 command flood.

An untrusted gateway that holds the S6 envelopes (public, verified with pk_PA) drops every command outside
the envelope bounds before transmitting it, saving downlink airtime and duty cycle for other tenants.
It does not know the device state, so it filters by bounds only (invariants stay on the device).

ASSUMED (config/model.yaml `d6`): the gateway can read the command parameters, i.e. it is given the LoRaWAN
AppSKey of the filtered devices. AppSKey only provides confidentiality; command integrity comes from the HMAC
session key k_{d,e}, which the gateway never holds, so reading parameters gives no forging power.

S4-E cannot do the same: verifying an S4-E envelope needs the per-device policy MAC key, which also forges
envelopes. `forging_power` quantifies this with the catalogue blast radius under C1 + that gateway.
"""

from __future__ import annotations

import pandas as pd

from . import delivery as dl
from .devices import Context, count_accepted, domain_size, policy_for


def in_bounds_by_type(dev, policy) -> dict[str, tuple[int, int]]:
    """action -> (payloads inside the envelope bounds, payloads in the catalogue). Bounds only, no state."""
    ctx = Context(True, policy, None)
    st = {"alert_active": False, "battery_below_floor": False}
    return {a.action: (count_accepted(ctx, a, st), domain_size(a)) for a in dev.actions}


def mix_weights(dev, mix: str) -> dict[str, float]:
    if mix == "uniform_payload":
        tot = sum(domain_size(a) for a in dev.actions)
        return {a.action: domain_size(a) / tot for a in dev.actions}
    if mix == "uniform_type":
        return {a.action: 1 / len(dev.actions) for a in dev.actions}
    raise ValueError(mix)


def filter_savings(devices, policies: dict, chans, uplink_s: float, devices_per_gw: list[int], link_cost,
                   mixes: list[str]) -> pd.DataFrame:
    rows = []
    for dev in devices:
        for lvl_name, lvl in policies["levels"].items():
            ib = in_bounds_by_type(dev, policy_for(dev, lvl))
            for mix in mixes:
                w = mix_weights(dev, mix)
                out_frac = sum(w[a] * (1 - i / n) for a, (i, n) in ib.items())
                for ch in chans:
                    if ch.phy is None:
                        continue
                    air = {a.action: link_cost(a.payload_bytes, ch)["airtime_s"] for a in dev.actions}
                    mean_air = sum(w[a] * air[a] for a in w)
                    out_air = sum(w[a] * (1 - ib[a][0] / ib[a][1]) * air[a] for a in w)
                    budget_h = dl.gateway_airtime_budget_s(3600, ch.duty)
                    for N in devices_per_gw:
                        demand = N * (3600 / uplink_s) * mean_air          # one flood command per downlink slot
                        carried = min(demand, budget_h)
                        saved = carried * (out_air / mean_air) if mean_air else 0.0
                        rows.append({"device": dev.model, "policy": lvl_name, "mix": mix, "region": ch.region,
                                     "dr": ch.dr, "devices": N, "out_of_envelope_fraction": out_frac,
                                     "flood_airtime_demand_s_per_h": demand, "airtime_budget_s_per_h": budget_h,
                                     "carried_s_per_h": carried, "saved_s_per_h": saved,
                                     "saved_share_of_budget": saved / budget_h})
    return pd.DataFrame(rows)


def forging_power(devices, policies: dict, threat: dict, inv: dict, state: dict) -> pd.DataFrame:
    """Blast radius under C1 + a gateway equipped to filter. S6 gateway: pk_PA only. S4-E gateway: must hold
    policy_mac to verify envelopes -> can also mint them."""
    from .devices import full_policy, scheme_context  # noqa: PLC0415
    rows = []
    fw_level = policies["levels"][policies["firmware_level"]]
    for dev in devices:
        full, fw = full_policy(dev), policy_for(dev, fw_level)
        for lvl_name, lvl in policies["levels"].items():
            pol = policy_for(dev, lvl)
            for scheme, gw_keys in (("S6", {"lorawan_ns"}), ("S4-E", {"lorawan_ns", "policy_mac"})):
                for label, keys in (("C1", {"session"}), ("C1 + filtering gateway", {"session"} | gw_keys)):
                    ctx = scheme_context(scheme, {"scope": "all"}, keys, pol, fw, full, inv, threat)
                    acc = sum(count_accepted(ctx, a, state) for a in dev.actions)
                    rows.append({"device": dev.model, "policy": lvl_name, "scheme": scheme, "compromise": label,
                                 "gateway_keys": ";".join(sorted(gw_keys)), "accepted": acc,
                                 "catalogue": sum(domain_size(a) for a in dev.actions)})
    return pd.DataFrame(rows)
