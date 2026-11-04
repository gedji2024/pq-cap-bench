"""Render REPORT.md. Every number is read from results/*.csv / *.json; none is typed here."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .config import load_yaml


def md_table(df: pd.DataFrame, fmt: dict | None = None) -> str:
    fmt = fmt or {}
    cols = list(df.columns)

    def cell(c, v):
        if pd.isna(v) or v == "":
            return "-"
        if c in fmt:
            return fmt[c](v)
        if isinstance(v, float):
            return f"{v:,.2f}"
        return str(v)

    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    lines += ["| " + " | ".join(cell(c, v) for c, v in zip(cols, row)) + " |" for row in df.itertuples(index=False)]
    return "\n".join(lines)


us = lambda ns: f"{ns / 1e3:,.1f}"  # noqa: E731
pct = lambda x: f"{100 * x:.1f}%"  # noqa: E731
hrs = lambda s: f"{s / 3600:,.2f}"  # noqa: E731


def timing_label(results: Path) -> str:
    """e.g. 'Apple M5 host, not MCU' - derived from the recorded env.json, never typed by hand."""
    p = results / "env.json"
    if not p.exists():
        return "host (unrecorded CPU), not MCU"
    return f"{json.loads(p.read_text())['cpu'].get('model', 'unknown CPU')} host, not MCU"


def section_env(results: Path) -> str:
    p = results / "env.json"
    if not p.exists():
        return "_results/env.json missing - run `make bench`._"
    e = json.loads(p.read_text())
    c, o = e["cpu"], e["liboqs"]
    rows = [("label", e["label"]), ("date (UTC)", e["date_utc"]), ("CPU", c.get("model")),
            ("arch", c.get("arch")), ("cores (logical)", c.get("cores_logical")),
            ("frequency / governor", f"{c.get('frequency_hz', c.get('frequency_khz_cur', '-'))}; {c.get('frequency_governor')}"),
            ("OS", e["os"]["platform"]), ("Python", e["python"]["version"].split()[0]),
            ("liboqs", f"{o.get('version_runtime')} @ {o.get('liboqs_commit', '?')}"),
            ("liboqs-python", o.get("liboqs_python")), ("compiler", o.get("c_compiler_version")),
            ("C flags (Release)", o.get("cmake_c_flags_release")),
            ("cryptography / OpenSSL", f"{e['python_packages']['cryptography']} / {e['openssl_for_cryptography']}"),
            ("CPU pinning", e["cpu_pinning"])]
    return md_table(pd.DataFrame(rows, columns=["item", "value"]))


def section_algorithms(results: Path) -> str:
    a = pd.read_csv(results / "algorithms.csv").fillna("")
    return md_table(a[["label", "kind", "status", "impl_name", "reason"]].rename(
        columns={"label": "requested", "impl_name": "liboqs / library name"}))


def section_sizes(results: Path) -> str:
    s = pd.read_csv(results / "sizes.csv")
    k = pd.read_csv(results / "kem_sizes.csv")
    i = lambda v: f"{int(v):,}"  # noqa: E731
    t1 = md_table(s[["algorithm", "kind", "pk_bytes", "sk_bytes", "sig_min", "sig_median", "sig_max",
                     "sig_n_observed", "sig_liboqs_nominal_max"]],
                  {c: i for c in ["pk_bytes", "sk_bytes", "sig_min", "sig_max", "sig_n_observed", "sig_liboqs_nominal_max"]}
                  | {"sig_median": lambda v: f"{v:,.1f}"})
    t2 = md_table(k[["algorithm", "pk_bytes", "sk_bytes", "ct_bytes", "ss_bytes"]], {c: i for c in ["pk_bytes", "sk_bytes", "ct_bytes", "ss_bytes"]})
    return t1 + "\n\nML-KEM (S2 key establishment):\n\n" + t2


def section_timing(results: Path) -> str:
    s = pd.read_csv(results / "bench_summary.csv")
    sig = s[s.kind != "kem"]
    piv = sig.pivot_table(index="algorithm", columns=["op", "msg_len"], values="pooled_median_ns", sort=False)
    piv.columns = [f"{op} ({m} B)" if m else op for op, m in piv.columns]
    t1 = md_table(piv.reset_index(), {c: us for c in piv.columns})
    mid = sorted(sig.msg_len[sig.msg_len > 0].unique())[len(sig.msg_len[sig.msg_len > 0].unique()) // 2]
    d = s[(s.msg_len.isin([0, mid]))][["algorithm", "op", "msg_len", "pooled_median_ns", "pooled_iqr_ns",
                                        "pooled_p95_ns", "pooled_n", "run_to_run_cv", "run_to_run_range_rel"]]
    t2 = md_table(d, {"pooled_median_ns": us, "pooled_iqr_ns": us, "pooled_p95_ns": us,
                      "pooled_n": lambda v: f"{int(v)}", "run_to_run_cv": pct, "run_to_run_range_rel": pct})
    lab = timing_label(results)
    return (f"_All timings: **{lab}**._\n\n"
            f"Median per operation, microseconds (all runs pooled; {lab}):\n\n{t1}\n\n"
            f"Dispersion at keygen and the {mid}-byte message (microseconds; {lab}; run-to-run = CV and relative range of the per-run medians):\n\n{t2}")


def section_tokens(results: Path) -> str:
    t = pd.read_csv(results / "model_tokens.csv")
    p = t.pivot_table(index=["scheme", "algorithm"], columns="depth", values="token_bytes", sort=False)
    p.columns = [f"d={c} (B)" for c in p.columns]
    return md_table(p.reset_index(), {c: lambda v: f"{int(v):,}" for c in p.columns})


def section_delivery(results: Path, model: dict) -> str:
    d = pd.read_csv(results / "model_delivery.csv")
    out = []
    for reg, dr in model["figure_channels"]:
        g = d[(d.region == reg) & (d.dr == dr) & (d.depth == 0)].sort_values("token_bytes")
        out.append(f"**{reg} DR{dr}** (max application payload {int(g.max_app_payload.iloc[0])} B), depth 0:\n\n" + md_table(
            g[["scheme", "algorithm", "token_bytes", "frames", "airtime_s", "duty_off_time_s", "ttd_expected_s", "ttd_worst_s"]]
            .rename(columns={"ttd_expected_s": "ttd_expected_h", "ttd_worst_s": "ttd_worst_h"}),
            {"token_bytes": lambda v: f"{int(v):,}", "frames": lambda v: f"{int(v)}",
             "airtime_s": lambda v: f"{v:,.2f}", "duty_off_time_s": lambda v: f"{v:,.1f}",
             "ttd_expected_h": hrs, "ttd_worst_h": hrs}))
    nb = d[(d.region == "NB-IoT") & (d.depth == 0)].sort_values("token_bytes")
    out.append(f"**NB-IoT** (configured max payload {int(nb.max_app_payload.iloc[0])} B), depth 0, messages needed:\n\n"
               + md_table(nb[["scheme", "algorithm", "token_bytes", "frames"]], {"token_bytes": lambda v: f"{int(v):,}"}))
    return "\n\n".join(out)


def section_capacity(results: Path, model: dict) -> str:
    c = pd.read_csv(results / "model_capacity.csv")
    k1 = model["kill_criteria"]["K1"]
    out = []
    for reg, dr in model["figure_channels"]:
        g = c[(c.region == reg) & (c.dr == dr) & (c.depth == 0) & (c.window_min == k1["window_min"])]
        p = g.pivot_table(index=["scheme", "algorithm"], columns="devices", values="cmds_gateway", sort=False)
        p.columns = [f"N={n}" for n in p.columns]
        out.append(f"**{reg} DR{dr}**, W = {k1['window_min']} min, depth 0 - commands per gateway:\n\n"
                   + md_table(p.reset_index(), {col: lambda v: f"{int(v):,}" for col in p.columns}))
    return "\n\n".join(out)


def section_crc(results: Path, config: Path, model: dict) -> str:
    p = results / "model_sensitivity_crc.csv"
    if not p.exists():
        return "_no CRC sensitivity file_"
    phy = load_yaml(config / "radio.yaml")["phy"]
    d = pd.read_csv(p)
    alt = bool(d.alt_crc_on_downlink.iloc[0])
    k = json.loads((results / "kill_criteria.json").read_text())
    k1, k1a = k["K1"], k.get("K1_crc_sensitivity", {})
    head = (f"Primary setting: downlink payload CRC **{'on' if phy['crc_on_downlink'] else 'off'}** "
            f"(RP002-1.0.3 Table 109). Sensitivity row: downlink CRC **{'on' if alt else 'off'}**. "
            "Frame counts depend only on payload sizes, so CRC changes airtime, time to deliver and the "
            "airtime-limited gateway capacity, never the number of frames.")
    if k1.get("answer") not in (None, "n/a") and k1a.get("answer") not in (None, "n/a"):
        head += (f"\n\nK1 under primary vs sensitivity: answer {k1['answer']} vs {k1a['answer']}; "
                 f"airtime per command {k1['airtime_per_cmd_s']:.3f} s vs {k1a['airtime_per_cmd_s']:.3f} s; "
                 f"worst-case time to deliver {k1['ttd_worst_s'] / 60:,.2f} min vs {k1a['ttd_worst_s'] / 60:,.2f} min.")
    out = [head, f"Relative airtime change with downlink CRC {'on' if alt else 'off'} (depth 0, all LoRa channels): "
           f"min {d.airtime_delta_rel.min():+.2%}, max {d.airtime_delta_rel.max():+.2%}."]
    for reg, dr in model["figure_channels"]:
        g = d[(d.region == reg) & (d.dr == dr)].sort_values("token_bytes")
        out.append(f"**{reg} DR{dr}** (W = {model['kill_criteria']['K1']['window_min']} min, "
                   f"N = {model['kill_criteria']['K1']['devices']} for commands per gateway):\n\n" + md_table(
            g[["scheme", "algorithm", "frames", "airtime_s", "airtime_s_alt", "airtime_delta_rel",
               "ttd_worst_s", "ttd_worst_s_alt", "cmds_gateway", "cmds_gateway_alt"]],
            {"frames": lambda v: f"{int(v)}", "airtime_s": lambda v: f"{v:,.3f}", "airtime_s_alt": lambda v: f"{v:,.3f}",
             "airtime_delta_rel": lambda v: f"{v:+.2%}", "ttd_worst_s": hrs, "ttd_worst_s_alt": hrs,
             "cmds_gateway": lambda v: f"{int(v):,}", "cmds_gateway_alt": lambda v: f"{int(v):,}"}))
    return "\n\n".join(out) + "\n\n_ttd columns in hours; `_alt` = sensitivity setting._"


def section_s6_explain(crisis: pd.DataFrame, model: dict) -> str:
    """Why S6 and S4 differ in crisis capacity at the K1 reference point - every number read from the rows."""
    k1 = model["kill_criteria"]["K1"]
    g = crisis[(crisis.region == k1["region"]) & (crisis.dr == k1["dr"]) & (crisis.window_min == k1["window_min"])
               & (crisis.devices == k1["devices"])]
    if g.empty:
        return ""
    r0 = g.iloc[0]
    lines = [f"**Why the crisis capacities differ at {k1['region']} DR{k1['dr']}, W = {k1['window_min']} min, "
             f"N = {k1['devices']}.** Class A gives each device one downlink per uplink: "
             f"{k1['window_min'] * 60} s / {model['uplink_interval_s']} s = {int(r0.downlink_opportunities)} downlink "
             f"opportunities per device in the window; the DR carries at most {int(r0.max_app_payload)} B per frame. "
             "Commands per gateway = N x floor(opportunities / frames per command), unless the gateway airtime "
             "budget binds first. The difference is therefore the **command size**, not the cryptography:", ""]
    for r in g.itertuples():
        lines.append(f"- {r.scheme} {r.algorithm}: {r.cmd_bytes} B -> {r.frames} frame(s) -> "
                     f"{int(r.downlink_opportunities)} // {r.frames} = {r.cmds_per_device} per device x "
                     f"{r.devices} = {r.cmds_gateway} per gateway (binding: {r.binding_limit})")
    s4 = g[g.scheme == "S4"]
    body = int((s4.cmd_bytes - s4.tag_bytes).iloc[0]) if not s4.empty else None
    ref = sum(model["s6"]["crisis_fields"].values())
    by = g.set_index(["scheme", "tag_bytes"]).cmds_gateway
    same = all(by.get(("S4c", t)) == by.get(("S6", t)) for t in model["s6"]["tag_bytes"])
    if body is not None:
        lines += ["", f"S4 sends the full {body}-B capability body with every command; S6 sends a {ref}-B reference "
                  "to a body already pre-positioned (and PQ-signed) during the calm phase. S4c sends the S6 wire format "
                  "with no envelope behind it: "
                  + ("its capacity equals S6 at every tag length, so the gain comes from pre-positioning the body, and "
                     "what S6 adds over S4c is bounded authority (K5/K6), not capacity."
                     if same else "its capacity differs from S6 here; see the table above.")]
    return "\n".join(lines)


def section_s6(results: Path, model: dict) -> str:
    p = results / "model_s6_calm.csv"
    if not p.exists():
        return "_S6 not configured_"
    if p.stat().st_size <= 1:
        return "_S6: none of the configured envelope signers was measured (see results/algorithms.csv)._"
    calm, crisis = pd.read_csv(p), pd.read_csv(results / "model_s6_crisis.csv")
    cmp_ = pd.read_csv(results / "model_s6_compare.csv")
    ints = lambda v: f"{int(v):,}"  # noqa: E731
    env = calm.drop_duplicates(["signer", "region", "dr"])
    t_env = env.pivot_table(index=["signer", "envelope_bytes"], columns=["region", "dr"], values="envelope_frames",
                            sort=False)
    t_env.columns = [f"{r} DR{d}" for r, d in t_env.columns]
    feas = (calm.groupby(["signer", "calm_hours", "devices", "region"], sort=False)
            .apply(lambda g: pd.Series({
                "feasible_drs": ", ".join(f"DR{d}" for d in g[g.feasible].dr) or "none",
                "infeasible_drs": ", ".join(f"DR{d}" for d in g[~g.feasible].dr) or "-",
                "max_gateway_utilisation": g.gateway_utilisation.max()}), include_groups=False).reset_index())
    cr = crisis.drop_duplicates(["scheme", "algorithm", "region", "dr"])
    t_cr = cr.pivot_table(index=["scheme", "algorithm", "cmd_bytes"], columns=["region", "dr"], values="frames",
                          sort=False)
    t_cr.columns = [f"{r} DR{d}" for r, d in t_cr.columns]
    n_ref = model["kill_criteria"]["K1"]["devices"]
    out = [
        "Envelope = " + " + ".join(f"{k} {v} B" for k, v in model["s6"]["envelope_fields"].items())
        + " + signature (measured). Crisis command = "
        + " + ".join(f"{k} {v} B" for k, v in model["s6"]["crisis_fields"].items())
        + " + truncated HMAC-SHA256 tag. Assumes the crisis HMAC key is already provisioned (as in S4); "
          "envelope verification (one PQ verify per device per calm period) happens before the event.",
        "**Calm phase: envelope frames per DR**\n\n" + md_table(t_env.reset_index(), {c: ints for c in t_env.columns}),
        "**Calm phase feasibility** (feasible = envelope frames <= Class A downlink opportunities in P, and "
        "N x envelope airtime <= gateway airtime budget in P):\n\n"
        + md_table(feas, {"devices": ints, "max_gateway_utilisation": lambda v: f"{v:.2%}"}),
        "**Crisis phase: frames per command** (1 = fits one frame; S4 / S4c use the same tag lengths as S6):\n\n"
        + md_table(t_cr.reset_index(), {c: ints for c in list(t_cr.columns) + ["cmd_bytes"]}),
        section_s6_explain(crisis, model),
    ]
    for reg, dr in model["figure_channels"]:
        g = cmp_[(cmp_.region == reg) & (cmp_.dr == dr) & (cmp_.devices == n_ref)]
        p2 = g.pivot_table(index=["scheme", "algorithm", "cmd_bytes", "frames"], columns="window_min",
                           values="cmds_gateway", sort=False)
        p2.columns = [f"W={w} min" for w in p2.columns]
        out.append(f"**Crisis commands per gateway, {reg} DR{dr}, N = {n_ref}** "
                   "(S1/S2/S4 at depth 0; S2 per-command cost only, epoch message excluded):\n\n"
                   + md_table(p2.reset_index(), {c: ints for c in list(p2.columns) + ["cmd_bytes", "frames"]}))
    return "\n\n".join(out)


def section_k5(k5: dict) -> str:
    df = pd.DataFrame(k5["rows"])
    ints = lambda v: f"{int(v):,}"  # noqa: E731
    return ("> **SUPERSEDED** by Sec. 8a (manufacturer catalogue): the K5/K6 numbers below use the ASSUMED catalogue "
            "of `config/actions.yaml` and are kept for traceability only.\n\n"
            "**K5 - Blast radius under cloud-side session-key compromise: how many catalogue commands would a "
            f"device accept from an attacker holding the per-command HMAC key? -> {k5['answer']}.**\n\n"
            "Counted by running every (action, target, value) in `config/actions.yaml` through the device-side check "
            "(`pqcap.envelope`) with a valid tag and fresh counter, in the stated device state (all states are in "
            "`results/model_blast_radius.csv`). Action types follow Kerkez et al. 2026; every bound and invariant is "
            "**assumed - pending field profile**, so the ratio is only as meaningful as those values.\n\n"
            + md_table(df, {c: ints for c in df.columns if c not in ("action", "ratio_s6_s4")}
                       | {"ratio_s6_s4": lambda v: f"{v:.4f}"}))


def section_k5_matrix(k5: dict) -> str:
    if "matrix" not in k5:
        return ""
    m = pd.DataFrame(k5["matrix"])
    labels = k5.get("matrix_labels", {})
    m.insert(1, "level (Étape 2)", m.compromise.map(lambda c: labels.get(c, "")))
    return ("\n\n**K5 - blast radius per compromise level** (accepted catalogue commands, state "
            f"{k5['state']}; key custody in `config/threat.yaml`, assumed; C4 counts commands for the ONE "
            "extracted device):\n\n"
            + md_table(m, {c: (lambda v: f"{int(v):,}") for c in m.columns if c not in ("compromise", "level (Étape 2)")}))


def section_k6(k6: dict) -> str:
    r = pd.DataFrame(k6["rows"])
    p = pd.DataFrame(k6["properties"])
    return (f"**K6 - blast(S4-E) / blast(S6) per compromise -> {k6['answer']}.**\n\n"
            + md_table(r, {c: (lambda v: f"{int(v):,}") for c in ("S4", "S4-F", "S4-E", "S6")}
                       | {"ratio_s4e_s6": lambda v: f"{v:.3f}"})
            + "\n\nProperties that differ (blast radius does not separate S4-E from S6; these do):\n\n"
            + md_table(p))


def section_d1(e: pd.DataFrame, model: dict) -> str:
    """D1: active-revocation time for S6-R vs S6 vs S4-E at every US915 downlink DR (validity-independent)."""
    V = min(model["revocation"]["validity_hours"])
    a = e[(e.region == "US915") & (e.validity_h == V) & e.mechanism.str.startswith(("active push", "reveal"))].copy()
    a["variant"] = a.scheme + " / " + a.mechanism
    p = a.pivot_table(index=["devices", "dr"], columns="variant", values="push_time_h", sort=False)
    f = a.pivot_table(index="variant", columns="dr", values="envelope_frames", aggfunc="first", sort=False)
    f.columns = [f"DR{c} frames" for c in f.columns]
    hh = lambda v: f"{v:,.3f}"  # noqa: E731
    return ("**D1 - active revocation time (hours) at every US915 downlink DR: S6-R reveals r_rev in one message; "
            "S6 and S4-E push a replacement envelope.** Time = max(per-device Class A delivery, gateway airtime). "
            "Exposure after revocation = min(V, this time).\n\n"
            + md_table(p.reset_index(), {c: hh for c in p.columns} | {"devices": lambda v: f"{int(v)}", "dr": lambda v: f"DR{int(v)}"})
            + "\n\nMessage size in frames per DR:\n\n" + md_table(f.reset_index(), {c: lambda v: f"{int(v)}" for c in f.columns}))


def section_revocation(results: Path, model: dict) -> str:
    pe, pr = results / "model_revocation_exposure.csv", results / "model_renewal_cost.csv"
    if not pe.exists():
        return "_revocation not configured_"
    e, r = pd.read_csv(pe), pd.read_csv(pr)
    k1 = model["kill_criteria"]["K1"]
    h = lambda v: "unbounded" if v == float("inf") else f"{v:,.2f}"  # noqa: E731
    fixed = e[~e.mechanism.str.startswith(("active push", "reveal"))][["scheme", "compromise", "validity_h", "mechanism", "exposure_worst_h",
                                             "exposure_expected_h"]]
    push = e[(e.mechanism.str.startswith(("active push", "reveal"))) & (e.region == k1["region"]) & (e.dr == k1["dr"])]
    push = push[["scheme", "validity_h", "devices", "envelope_bytes", "envelope_frames", "push_time_h",
                 "exposure_worst_h", "exposure_expected_h"]]
    out = ["Exposure window after revocation starts (hours; detection delay excluded, identical for all schemes). "
           "Firmware caps every envelope - including an attacker-minted one - at the validity V "
           "(`pqcap.envelope.validity_ok`).",
           md_table(fixed, {"exposure_worst_h": h, "exposure_expected_h": h}),
           f"**Active push at {k1['region']} DR{k1['dr']}** (replacement envelope delivered to all N devices; "
           "exposure = min(V, push time)):",
           md_table(push, {"envelope_bytes": lambda v: f"{int(v):,}", "envelope_frames": lambda v: f"{int(v)}",
                           "push_time_h": h, "exposure_worst_h": h, "exposure_expected_h": h})]
    out.append(section_d1(e, model))
    for reg, dr in model["figure_channels"]:
        g = r[(r.region == reg) & (r.dr == dr)]
        p = g.pivot_table(index=["scheme", "envelope_bytes", "devices"], columns="validity_h",
                          values="gateway_utilisation", sort=False)
        p.columns = [f"V={v} h" for v in p.columns]
        f = g.groupby(["scheme", "devices"], sort=False).feasible.all()
        out.append(f"**Routine-renewal gateway airtime, {reg} DR{dr}** (share of the daily gateway budget; "
                   f">100 % = infeasible; all feasible for every V: "
                   + ", ".join(f"{s} N={n}: {'yes' if v else 'no'}" for (s, n), v in f.items()) + "):\n\n"
                   + md_table(p.reset_index(), {c: (lambda v: f"{v:.2%}") for c in p.columns}
                              | {"envelope_bytes": lambda v: f"{int(v):,}", "devices": lambda v: f"{int(v)}"}))
    return "\n\n".join(out)


def section_harm(results: Path, config: Path) -> str:
    p = results / "model_harm.csv"
    if not p.exists():
        return "_harm replay not run (config/harm.yaml or cached series missing)_"
    d, m = pd.read_csv(p), json.loads((results / "harm_meta.json").read_text())
    cfg = load_yaml(config / "harm.yaml")
    src = m.get("source", {})
    gaps = "; ".join(f"{g['after']} -> {g['before']} ({g['minutes']:.0f} min)" for g in m["gaps_over_60_min"]) or "none"
    lv = ", ".join(f"{x} ft" for x in cfg["harm"]["reference_levels_ft"])
    head = [f"Series: `{cfg['series']['file']}` - query `{src.get('query_url', '?')}` (served from "
            f"`{src.get('final_url', '?')}`), retrieved {src.get('retrieved_utc', '?')}, SHA-256 "
            f"`{src.get('sha256', '?')[:16]}...`. {m['n_readings']} readings, {m['first']} to {m['last']}; "
            f"peak {m['peak_cm'] / cfg['series']['ft_to_cm']:.2f} ft at {m['peak_time']}.",
            f"**Data gaps > 60 min (filled by {cfg['series']['interpolation']} interpolation - crossing times inside "
            f"them are interpolation-dependent):** {gaps}.",
            f"Reference levels {lv}; a crossing is *delayed* if first reported more than "
            f"{cfg['harm']['delay_tolerance_min']} min after it occurs. Per-uplink charge "
            f"{m['uplink_charge_mAh']:.2f} mAh, derived from the paper's 'drains a battery in a week' statement under the "
            "interpretation in `config/harm.yaml` (assumed). A *floor violation* is an uplink below the battery floor at a "
            "rate the profile's battery invariant forbids (firmware alert uplinks exempt), scored against the same profile "
            "for every scheme, including S4. All device, battery, policy and threshold values are assumed - pending "
            "field profile, except those marked [K26] in the config."]
    cols = ["scheme", "compromise", "strategy", "crossings", "missed", "delayed", "on_time", "max_delay_min",
            "floor_violating_uplinks", "died", "died_h", "min_soc_pct", "attacker_accepted"]
    num = lambda v: f"{v:,.1f}"  # noqa: E731
    t1 = md_table(d[d.compromise != "none"][[c for c in cols]], {"max_delay_min": num, "died_h": num, "min_soc_pct": num})
    leg = d[d.compromise == "none"][["scheme", "legit_policy", "crossings", "missed", "delayed", "max_delay_min",
                                     "floor_violating_uplinks", "min_soc_pct", "legit_intents", "legit_intents_rejected",
                                     "legit_unique_rejection_rate", "legit_sent", "legit_rejected", "legit_reject_reasons"]]
    t2 = md_table(leg, {"max_delay_min": num, "min_soc_pct": num, "legit_unique_rejection_rate": lambda v: f"{v:.1%}"})
    return "\n\n".join(head + ["**Under attack** (attacker holds the session key; C1+C3 also replaces envelopes):",
                                 t1, "**Legitimate operation (D3)** - no compromise; rule-based adaptive-reporting policy. "
                                 "The metric is the share of **unique requests** rejected (`legit_unique_rejection_rate`); "
                                 "`legit_sent`/`legit_rejected` include retries (a rejected request is retried at every "
                                 "opportunity) and are shown only for traceability - the earlier raw-retry rate is "
                                 "**superseded**. `limit_aware` knows the public envelope limits and the invariants in the "
                                 "current state and asks for the closest accepted value:", t2])


def section_traceability(config: Path) -> str:
    p = config / "traceability.yaml"
    if not p.exists():
        return "_no traceability map_"
    t = load_yaml(p)
    props = pd.DataFrame([{"id": k, **v, "artefacts": "; ".join(v["artefacts"]) or "-"} for k, v in t["properties"].items()])
    atk = pd.DataFrame([{"id": k, **v} for k, v in t["attacks"].items()])
    return ("Naming follows *Étape 2 — Modèle de menace et propriétés de sécurité* v0.1 (adversaries A1-A5, "
            "compromise levels C0-C4, properties P1-P8, attacks T1-T10). Status per `config/traceability.yaml`.\n\n"
            + md_table(props[["id", "name", "status", "artefacts"]]) + "\n\n"
            + md_table(atk[["id", "name", "adversary", "covered_by", "status"]]))


def section_mcu(results: Path, config: Path) -> str:
    p = results / "mcu_verify_cost.csv"
    if not p.exists():
        return "_no pqm4 data_"
    d, cfg = pd.read_csv(p), load_yaml(config / "mcu.yaml")
    ints = lambda v: f"{int(v):,}"  # noqa: E731
    ms = lambda v: f"{v:,.2f}"  # noqa: E731
    d = d.assign(pqm4_commit=d.pqm4_commit.str[:12])
    cols = [c for c in d.columns if c not in ("source_label", "pqm4_scheme")]
    energy = ("Energy is **not reported**: no cited current-draw figure for the board at the measurement clock is "
              "stored in this repository (`config/mcu.yaml: energy`)." if not cfg.get("energy") else "")
    return (f"**{cfg['label']}** - no hardware was run for this project. Envelope verification = one signature "
            f"verify per envelope (S6). Times are at the pqm4 measurement clock ({cfg['measurement_clock_mhz']} MHz, "
            "stated in pqm4's README) and are not scaled to other clocks (flash wait states above it). "
            "Falcon-512 m4-ct was removed from pqm4 in commit dfc3a754, so it is read from that commit's parent; its "
            "successor fndsa_provisional-512 is shown from the head pin. `verify_ms_per_day_V*` = one verification per "
            "renewal of validity V. " + energy + " Provenance: `data/pqm4/SOURCE.json`.\n\n"
            + md_table(d[cols], {c: ints for c in ("executions", "verify_cycles_avg", "verify_cycles_min",
                                                   "verify_cycles_max", "verify_stack_bytes", "clock_mhz")}
                       | {c: ms for c in cols if c.startswith("verify_ms")}))


def section_repo_state(config: Path) -> str:
    p = config / "repo_state.yaml"
    if not p.exists():
        return "_no repository state record_"
    r = load_yaml(p)
    lines = [f"- kept `{k['commit']}` - {k['subject']} ({k['check']})" for k in r["kept"]]
    lines += [f"- discarded (uncommitted): {x}" for x in r["discarded_uncommitted"]]
    lines += [f"- redone: {x}" for x in r["redone"]]
    return "\n".join(lines)


def section_catalogue(results: Path, config: Path) -> str:
    p = results / "catalogue_k5_ranges.csv"
    if not p.exists():
        return "_no manufacturer catalogue_"
    df, k5, k6 = pd.read_csv(results / "catalogue_blast.csv"), pd.read_csv(p), pd.read_csv(results / "catalogue_k6_ranges.csv")
    devs = sorted(df.device.unique())
    pols = list(dict.fromkeys(df.policy))
    e = lambda v: f"{v:.3g}"  # noqa: E731
    ints = lambda v: f"{int(v):,}"  # noqa: E731
    head = (f"Devices ({len(devs)}): {', '.join(devs)} - downlink commands, payload lengths and parameter ranges from the "
            "official manuals (`config/devices/*.yaml`; every quote and document SHA-256 re-checked by "
            "`scripts/verify_device_docs.py`, result in `data/devices/verification.json`). Envelope bounds are POLICY "
            f"levels {', '.join(pols)} (`config/policies.yaml`). K5/K6 are reported as **ranges over "
            f"{len(devs)} devices x {len(pols)} policies**, never as a single number. `fraction` = accepted payloads / "
            "catalogue payloads (dominated by multi-field threshold commands whose ranges are encoding ranges); "
            "`type_coverage` = share of the device's command types an attacker can get accepted. Invariants (ASSUMED) "
            "are applied in the reference state of `config/actions.yaml`; S4c accepts exactly what S4 accepts.")
    t5 = md_table(k5, {"fraction_min": e, "fraction_max": e, "type_coverage_min": lambda v: f"{v:.2f}",
                       "type_coverage_max": lambda v: f"{v:.2f}", "accepted_min": ints, "accepted_max": ints,
                       "cases": ints})
    t6 = md_table(k6, {"ratio_min": e, "ratio_max": e, "both_zero_cases": ints, "cases": ints})
    return "\n\n".join([head, "**K5 ranges (manufacturer catalogue)**", t5,
                         "**K6 = blast(S4-E)/blast(S6), ranges (cases where both are 0 are counted, not divided)**", t6])


def section_kill(results: Path) -> str:
    k = json.loads((results / "kill_criteria.json").read_text())
    k1 = k["K1"]
    if k1["answer"] == "n/a":
        s1 = f"**K1: n/a** - {k1['reason']}"
    else:
        s1 = (f"**K1 - Is S1 with {k1['algorithm']} deliverable within W = {k1['window_min']} min for N = {k1['devices']} "
              f"at {k1['region']} DR{k1['dr']}? -> {k1['answer'].upper()}.**\n\n"
              f"Token {k1['token_bytes']:,} B -> {k1['frames']} frames, {k1['airtime_per_cmd_s']:.2f} s airtime per command. "
              f"Worst-case time to deliver {k1['ttd_worst_s'] / 60:,.1f} min (expected {k1['ttd_expected_s'] / 60:,.1f} min) "
              f"vs window {k1['window_s'] / 60:.0f} min; commands per device in window = {k1['cmds_per_device']}, "
              f"per gateway = {k1['cmds_gateway']} (binding limit: {k1['binding_limit']}).")
    k2 = k["K2"]
    if k2["answer"] == "n/a":
        s2 = f"**K2: n/a** - {k2['reason']}"
    else:
        r3 = lambda v: f"{v:,.3f}"  # noqa: E731
        ints = lambda v: f"{int(v):,}"  # noqa: E731
        fx = pd.DataFrame(k2["fixed"])
        cm = pd.DataFrame(k2["class_a_max"])
        s2 = (f"**K2 - Is PQ cost amortisable to near-symmetric cost? S2/S4 per-command overhead ratio "
              f"(threshold <= {k2['threshold']}) -> {k2['answer']}.**\n\n"
              "At configured commands-per-epoch points (min-max over the LoRa channels where the point is feasible):\n\n"
              + md_table(fx, {"cmds_per_epoch": ints, "n_channels": ints} | {c: r3 for c in fx.columns if c.startswith("ratio")})
              + "\n\nAt the Class A maximum commands per epoch (every downlink opportunity used; "
              "infeasible = epoch message alone exceeds the epoch's downlink opportunities):\n\n"
              + md_table(cm, {c: (r3 if c.startswith("ratio") else ints) for c in cm.columns
                              if c not in ("kem", "epoch_hours")}))
    s3 = ("**K3 - Smallest PQ scheme (S1 or S3, depth 0) whose token fits in one frame, per DR:**\n\n"
          + md_table(pd.DataFrame(k["K3"]), {"fit_token_bytes": lambda v: f"{int(v):,}"}))
    k4 = k.get("K4", {"answer": "n/a", "reason": "not computed"})
    if k4["answer"] == "n/a":
        s4 = f"**K4: n/a** - {k4['reason']}"
    else:
        s4 = (f"**K4 - Does every S6 crisis command fit in one frame at every {k4['region']} downlink DR? "
              f"-> {k4['answer'].upper()}.**\n\n"
              + md_table(pd.DataFrame(k4["rows"]), {"cmd_bytes": lambda v: f"{int(v)}",
                                                    "min_max_app_payload": lambda v: f"{int(v)}"}))
    parts = [s1, s2, s3, s4,
             (section_k5(k["K5"]) + section_k5_matrix(k["K5"])) if "K5" in k
             else "**K5: n/a** - no action catalogue (config/actions.yaml)",
             section_k6(k["K6"]) if "K6" in k else "**K6: n/a** - no threat model (config/threat.yaml)"]
    return "\n\n".join(parts)


def run(config: Path, results: Path, figures: Path) -> None:
    model = load_yaml(config / "model.yaml")
    figs = sorted(p.name for p in figures.glob("*.png"))
    parts = [
        "# pq-cap-bench report",
        "_Generated by `make report` from `results/`. Do not edit by hand: every number below is read from a CSV/JSON "
        "produced by an actual run (`make bench`, `make model`) or from the cited specification tables in `config/radio.yaml`._",
        f"> **All timings: {timing_label(results)}.** They rank algorithms on a general-purpose CPU; "
        "they do not predict MCU cycles or energy. An x86 re-run is optional (`make bench` on that host).",
        "## 0. Repository state", section_repo_state(config),
        "## 1. Environment", section_env(results),
        "## 2. Algorithm resolution", section_algorithms(results),
        f"## 3. Sizes (observed; model uses `{model['signature_size_statistic']}`)", section_sizes(results),
        f"## 4. Host timings ({timing_label(results)})", section_timing(results),
        "## 5. Capability token sizes (bytes)", section_tokens(results),
        "## 6. LoRaWAN / NB-IoT delivery", section_delivery(results, model),
        "## 7. Commands within window", section_capacity(results, model),
        "## 7b. Sensitivity: downlink CRC", section_crc(results, config, model),
        "## 7c. S6 pre-positioned capability envelopes", section_s6(results, model),
        "## 7d. Revocation: envelope validity and renewal", section_revocation(results, model),
        "## 7e. Harm-weighted replay: USGS Buffalo Bayou, Hurricane Harvey", section_harm(results, config),
        "## 7f. Device-side envelope verification (pqm4, published)", section_mcu(results, config),
        "## 8. Kill criteria", section_kill(results),
        "## 8a. K5/K6 on the manufacturer device catalogue (supersedes the K5/K6 of Sec. 8)",
        section_catalogue(results, config),
        "## 8b. Traceability to the Étape 2 threat model", section_traceability(config),
        "## 9. Figures", "\n".join(f"- [{f}](figures/{f}) ([pdf](figures/{f[:-4]}.pdf))" for f in figs),
    ]
    (results.parent / "REPORT.md").write_text("\n\n".join(parts) + "\n")
