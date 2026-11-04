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
    return (f"Median per operation, microseconds (all runs pooled):\n\n{t1}\n\n"
            f"Dispersion at keygen and the {mid}-byte message (microseconds; run-to-run = CV and relative range of the per-run medians):\n\n{t2}")


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
    return "\n\n".join([s1, s2, s3])


def run(config: Path, results: Path, figures: Path) -> None:
    model = load_yaml(config / "model.yaml")
    figs = sorted(p.name for p in figures.glob("*.png"))
    parts = [
        "# pq-cap-bench report",
        "_Generated by `make report` from `results/`. Do not edit by hand: every number below is read from a CSV/JSON "
        "produced by an actual run (`make bench`, `make model`) or from the cited specification tables in `config/radio.yaml`._",
        "> **Timings are HOST measurements on a general-purpose CPU, not microcontroller measurements.** "
        "They rank algorithms; they do not predict MCU cycles or energy.",
        "## 1. Environment", section_env(results),
        "## 2. Algorithm resolution", section_algorithms(results),
        f"## 3. Sizes (observed; model uses `{model['signature_size_statistic']}`)", section_sizes(results),
        "## 4. Host timings", section_timing(results),
        "## 5. Capability token sizes (bytes)", section_tokens(results),
        "## 6. LoRaWAN / NB-IoT delivery", section_delivery(results, model),
        "## 7. Commands within window", section_capacity(results, model),
        "## 8. Kill criteria", section_kill(results),
        "## 9. Figures", "\n".join(f"- [{f}](figures/{f}) ([pdf](figures/{f[:-4]}.pdf))" for f in figs),
    ]
    (results.parent / "REPORT.md").write_text("\n\n".join(parts) + "\n")
