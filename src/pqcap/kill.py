"""Kill criteria K1-K3, answered from model outputs only."""

from __future__ import annotations

import pandas as pd

PQ_SCHEMES = ("S1", "S3")  # schemes carrying a PQ signature in every command


def k1(out: dict[str, pd.DataFrame], spec: dict) -> dict:
    cap, dlv = out["model_capacity"], out["model_delivery"]
    sel = lambda df: df[(df.scheme == spec["scheme"]) & (df.algorithm == spec["algorithm"])
                        & (df.depth == spec["depth"]) & (df.region == spec["region"]) & (df.dr == spec["dr"])]
    c = sel(cap)
    c = c[(c.window_min == spec["window_min"]) & (c.devices == spec["devices"])]
    d = sel(dlv)
    if c.empty or d.empty:
        return {"answer": "n/a", "reason": f"no model row for {spec} (algorithm unavailable?)", **spec}
    c, d = c.iloc[0], d.iloc[0]
    W = spec["window_min"] * 60
    ok = bool(c.all_devices_get_one) and d.ttd_worst_s <= W
    return {"answer": "yes" if ok else "no", **spec,
            "token_bytes": int(d.token_bytes), "frames": int(d.frames),
            "airtime_per_cmd_s": float(d.airtime_s), "ttd_worst_s": float(d.ttd_worst_s),
            "ttd_expected_s": float(d.ttd_expected_s), "window_s": W,
            "cmds_per_device": int(c.cmds_per_device), "cmds_gateway": int(c.cmds_gateway),
            "binding_limit": c.binding_limit}


def k2(out: dict[str, pd.DataFrame], threshold: float) -> dict:
    a = out["model_s2_amortization"]
    if a.empty:
        return {"answer": "n/a", "reason": "S2 inputs unavailable", "rows": []}
    g = (a.groupby(["kem", "epoch_hours", "cmds_per_epoch", "is_class_a_max"], as_index=False)
         .agg(ratio_airtime_min=("ratio_airtime_s2_s4", "min"), ratio_airtime_max=("ratio_airtime_s2_s4", "max"),
              ratio_bytes_min=("ratio_bytes_s2_s4", "min"), ratio_bytes_max=("ratio_bytes_s2_s4", "max"),
              n_channels=("dr", "count")))
    g["near_symmetric_all_drs"] = g.ratio_airtime_max <= threshold
    fixed = g[~g.is_class_a_max]
    return {"threshold": threshold,
            "answer": ("yes" if fixed.near_symmetric_all_drs.any() else "no")
            + " (at >=1 of the configured commands-per-epoch points)" if not fixed.empty else "n/a",
            "rows": g.to_dict("records")}


def k3(out: dict[str, pd.DataFrame]) -> list[dict]:
    d = out["model_delivery"]
    d = d[(d.depth == 0) & d.scheme.isin(PQ_SCHEMES)]
    res = []
    for (region, dr), g in d.groupby(["region", "dr"], sort=False):
        fit = g[g.frames == 1].sort_values("token_bytes")
        smallest = g.sort_values("token_bytes").iloc[0]
        res.append({"region": region, "dr": int(dr), "max_app_payload": int(g.max_app_payload.iloc[0]),
                    "fits_one_frame": "none" if fit.empty else f"{fit.iloc[0].scheme}/{fit.iloc[0].algorithm}",
                    "fit_token_bytes": None if fit.empty else int(fit.iloc[0].token_bytes),
                    "smallest_pq": f"{smallest.scheme}/{smallest.algorithm}",
                    "smallest_pq_token_bytes": int(smallest.token_bytes),
                    "smallest_pq_frames": int(smallest.frames)})
    return res


def evaluate(out: dict[str, pd.DataFrame], model: dict) -> dict:
    kc = model["kill_criteria"]
    return {"K1": k1(out, kc["K1"]), "K2": k2(out, kc["K2"]["near_symmetric_ratio"]), "K3": k3(out)}
