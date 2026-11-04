"""S6 pre-positioned capability envelopes: calm-phase delivery and crisis-phase capacity."""

from __future__ import annotations

import pandas as pd

from . import delivery as dl


def envelope_bytes(fields: dict, sig_bytes: int) -> int:
    return sum(fields.values()) + sig_bytes


def crisis_bytes(fields: dict, tag: int) -> int:
    return sum(fields.values()) + tag


def calm_feasibility(chans, s6: dict, sig: dict, uplink_s: float, devices: list[int], link_cost) -> pd.DataFrame:
    """Can every one of N devices receive its envelope within the calm period P?

    Device side: envelope frames <= downlink opportunities in P (Class A).
    Gateway side: N x envelope airtime <= airtime budget in P (duty cycle or 100 %).
    """
    rows = []
    for signer in s6["signers"]:
        if signer not in sig:
            continue
        eb = envelope_bytes(s6["envelope_fields"], sig[signer])
        for ch in chans:
            if ch.phy is None:
                continue
            lc = link_cost(eb, ch)
            for P in s6["calm_period_hours"]:
                opp = dl.downlink_opportunities(P * 3600, uplink_s)
                budget = dl.gateway_airtime_budget_s(P * 3600, ch.duty)
                ttd = dl.time_to_deliver_s(lc["frames"], uplink_s, 1.0, lc["last_frame_toa_s"])
                for N in devices:
                    need = N * lc["airtime_s"]
                    rows.append({"signer": signer, "region": ch.region, "dr": ch.dr, "calm_hours": P,
                                 "devices": N, "envelope_bytes": eb, "envelope_frames": lc["frames"],
                                 "envelope_airtime_s": lc["airtime_s"], "downlink_opportunities": opp,
                                 "device_feasible": lc["frames"] <= opp,
                                 "gateway_airtime_needed_s": need, "gateway_budget_s": budget,
                                 "gateway_utilisation": need / budget, "gateway_feasible": need <= budget,
                                 "max_devices_by_airtime": int(budget // lc["airtime_s"]),
                                 "ttd_worst_s": ttd["ttd_worst_s"],
                                 "feasible": lc["frames"] <= opp and need <= budget})
    return pd.DataFrame(rows)


def crisis_capacity(chans, s6: dict, uplink_s: float, devices: list[int], link_cost) -> pd.DataFrame:
    rows = []
    for tag in s6["tag_bytes"]:
        cb = crisis_bytes(s6["crisis_fields"], tag)
        for ch in chans:
            if ch.phy is None:
                continue
            lc = link_cost(cb, ch)
            ttd = dl.time_to_deliver_s(lc["frames"], uplink_s, 1.0, lc["last_frame_toa_s"])
            for W in s6["crisis_windows_min"]:
                for N in devices:
                    g = dl.commands_per_gateway(N, W * 60, uplink_s, lc["frames"], lc["airtime_s"], ch.duty)
                    rows.append({"scheme": "S6", "algorithm": f"envelope+HMAC-SHA256-T{tag}", "tag_bytes": tag,
                                 "region": ch.region, "dr": ch.dr, "max_app_payload": ch.max_app,
                                 "cmd_bytes": cb, "frames": lc["frames"], "fits_one_frame": lc["frames"] == 1
                                 and cb <= ch.max_app, "airtime_s": lc["airtime_s"],
                                 "ttd_worst_s": ttd["ttd_worst_s"], "window_min": W, "devices": N,
                                 "cmds_per_device": dl.commands_per_device(W * 60, uplink_s, lc["frames"]), **g})
    return pd.DataFrame(rows)


def compare(crisis: pd.DataFrame, capacity: pd.DataFrame, delivery: pd.DataFrame, s6: dict) -> pd.DataFrame:
    """Crisis-phase S6 vs per-command S1/S2/S4 (depth 0) at the crisis windows.
    S2 rows count per-command cost only (epoch message excluded; see model_s2_amortization)."""
    keys = ["scheme", "algorithm", "region", "dr", "window_min", "devices"]
    wanted = pd.DataFrame(s6["compare"], columns=["scheme", "algorithm"])
    c = capacity[(capacity.depth == 0) & capacity.window_min.isin(s6["crisis_windows_min"])].merge(wanted)
    d = delivery[delivery.depth == 0][["scheme", "algorithm", "region", "dr", "token_bytes", "airtime_s", "ttd_worst_s"]]
    c = c.merge(d, on=["scheme", "algorithm", "region", "dr"]).rename(columns={"token_bytes": "cmd_bytes"})
    cols = keys + ["cmd_bytes", "frames", "airtime_s", "ttd_worst_s", "cmds_per_device", "cmds_gateway", "binding_limit"]
    return pd.concat([crisis[cols], c[cols]], ignore_index=True)
