"""Figures from results/model_*.csv (vector PDF + PNG). No values are computed here."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from .config import CONFIG, load_yaml  # noqa: E402

# Fixed-order categorical palette (dataviz reference palette, light mode, slots 1-8).
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SCHEME_COLOR = {"S1": CAT[0], "S2": CAT[1], "S3": CAT[2], "S4": CAT[3], "S5": CAT[4]}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.size": 9, "axes.titlesize": 10, "axes.labelsize": 9, "axes.edgecolor": INK2,
    "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
    "pdf.fonttype": 42, "savefig.bbox": "tight",
})


def _save(fig, out: Path, name: str) -> None:
    fig.savefig(out / f"{name}.pdf", metadata={"CreationDate": None, "ModDate": None})  # reproducible bytes
    fig.savefig(out / f"{name}.png", dpi=200, metadata={"Software": None})
    plt.close(fig)


def _label(r) -> str:
    return f"{r.scheme} {r.algorithm}"


def fig_sig_frames(d: pd.DataFrame, out: Path) -> None:
    """Heatmap: frames needed for a depth-0 token, per algorithm x DR (one panel per region)."""
    d0 = d[(d.depth == 0) & (d.region != "NB-IoT")].copy()
    d0["label"] = d0.apply(_label, axis=1)
    order = d0.drop_duplicates("label").sort_values("token_bytes")
    regions = list(dict.fromkeys(d0.region))
    fig, axes = plt.subplots(1, len(regions), figsize=(4.2 * len(regions), 0.32 * len(order) + 1.6),
                             sharey=True, constrained_layout=True)
    vmax = d0.frames.max()
    for ax, reg in zip(np.atleast_1d(axes), regions):
        p = d0[d0.region == reg].pivot(index="label", columns="dr", values="frames").loc[order.label]
        im = ax.imshow(np.log10(p.values), cmap="Blues", vmin=0, vmax=np.log10(vmax), aspect="auto")
        for (i, j), v in np.ndenumerate(p.values):
            ax.text(j, i, f"{v:d}", ha="center", va="center", fontsize=7,
                    color="white" if np.log10(v) > 0.6 * np.log10(vmax) else INK)
        ax.set_xticks(range(len(p.columns)), [f"DR{c}" for c in p.columns])
        ax.set_yticks(range(len(p.index)), [f"{lbl} ({b} B)" for lbl, b in zip(p.index, order.token_bytes)])
        ax.set_title(reg)
        ax.set_xlabel("downlink data rate")
        ax.grid(False)
    fig.colorbar(im, ax=axes, label="frames (log10 colour scale; cell = count)", shrink=0.8)
    fig.suptitle("Downlink frames needed per depth-0 token (token bytes in brackets)")
    _save(fig, out, "fig1_token_frames_per_dr")


def _bar_panels(df, channels, value, xlabel, title, out, name, log=True):
    fig, axes = plt.subplots(1, len(channels), figsize=(3.3 * len(channels), 4.2), sharey=True,
                             constrained_layout=True)
    for ax, (reg, dr) in zip(np.atleast_1d(axes), channels):
        g = df[(df.region == reg) & (df.dr == dr)].sort_values(value)
        y = np.arange(len(g))
        ax.barh(y, g[value], color=[SCHEME_COLOR[s] for s in g.scheme], height=0.7,
                edgecolor="white", linewidth=1)
        ax.set_yticks(y, g.apply(_label, axis=1))
        if log:
            ax.set_xscale("log")
        ax.set_title(f"{reg} DR{dr}")
        ax.set_xlabel(xlabel)
        ax.grid(axis="y", visible=False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in SCHEME_COLOR.values()]
    fig.legend(handles, list(SCHEME_COLOR), loc="outside lower center", ncol=5, title="scheme")
    fig.suptitle(title)
    _save(fig, out, name)


def fig_ttd(d, channels, out):
    g = d[(d.depth == 0) & (d.region != "NB-IoT")].copy()
    g["ttd_worst_h"] = g.ttd_worst_s / 3600
    _bar_panels(g, channels, "ttd_worst_h", "worst-case time to deliver (h, log)",
                "Class A time to deliver one depth-0 command (uplink every 300 s)", out, "fig2_time_to_deliver")


def fig_capacity(c, channels, model, out):
    c0 = c[c.depth == 0].copy()
    c0["label"] = c0.apply(_label, axis=1)
    Ns = model["devices_per_gateway"]
    for reg, dr in channels:
        g = c0[(c0.region == reg) & (c0.dr == dr)]
        Ws = model["windows_min"]
        fig, axes = plt.subplots(1, len(Ws), figsize=(3.0 * len(Ws), 4.4), sharey=True, constrained_layout=True)
        order = g[(g.window_min == Ws[-1]) & (g.devices == Ns[-1])].sort_values("cmds_gateway").label.tolist()
        for ax, W in zip(axes, Ws):
            h = 0.8 / len(Ns)
            for k, N in enumerate(Ns):
                s = g[(g.window_min == W) & (g.devices == N)].set_index("label").loc[order]
                yy = np.arange(len(order)) + (k - (len(Ns) - 1) / 2) * h
                v = s.cmds_gateway.to_numpy()
                ax.barh(yy[v > 0], v[v > 0], height=h, color=CAT[k], edgecolor="white", linewidth=0.8,
                        label=f"N = {N}")
            ax.set_xscale("log")
            ax.set_xlim(left=0.8)
            zero = g[(g.window_min == W) & (g.devices == Ns[0])].set_index("label").loc[order].cmds_gateway.to_numpy() == 0
            for i in np.flatnonzero(zero):
                ax.text(0.85, i, "0", va="center", fontsize=7, color=INK2)
            ax.set_ylim(-0.8, len(order) - 0.2)
            ax.set_xlabel("commands / gateway (log)")
            ax.set_yticks(range(len(order)), order)
            ax.set_title(f"W = {W} min")
            ax.grid(axis="y", visible=False)
        h_, l_ = axes[0].get_legend_handles_labels()
        fig.legend(h_, l_, loc="outside lower center", ncol=len(Ns), title="devices per gateway")
        fig.suptitle(f"{reg} DR{dr}: depth-0 commands deliverable per gateway within window W ('0' = none)")
        _save(fig, out, f"fig3_commands_in_window_{reg}_DR{dr}")


def fig_depth(d, model, out):
    pick = d[((d.scheme == "S1") & d.algorithm.isin(model["figure_depth_algorithms"])) | (d.scheme != "S1")]
    reg, dr = model["figure_channels"][0]
    tok = pick.drop_duplicates(["scheme", "algorithm", "depth"])
    frm = pick[(pick.region == reg) & (pick.dr == dr)]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.8), constrained_layout=True)
    for i, ((s, a), g) in enumerate(tok.groupby(["scheme", "algorithm"], sort=False)):
        lbl = f"{s} {a}" + (" (per-command token = S4)" if s == "S2" else "")
        kw = dict(color=CAT[i % len(CAT)], lw=2, marker="o", ms=5, label=lbl,
                  ls="--" if s == "S2" else "-", zorder=3 if s == "S2" else 2)
        a1.plot(g.depth, g.token_bytes, **kw)
        f = frm[(frm.scheme == s) & (frm.algorithm == a)]
        a2.plot(f.depth, f.frames, **kw)
    for ax, yl, t in [(a1, "token size (bytes, log)", "Token size"),
                      (a2, "downlink frames (log)", f"Frames at {reg} DR{dr}")]:
        ax.set_yscale("log")
        ax.set_xlabel("delegation depth d")
        ax.set_xticks(sorted(tok.depth.unique()))
        ax.set_ylabel(yl)
        ax.set_title(t)
    h, l = a1.get_legend_handles_labels()
    fig.legend(h, l, loc="outside right center")
    _save(fig, out, "fig4_delegation_depth")


def run(results: Path, out: Path, config: Path = CONFIG) -> None:
    out.mkdir(parents=True, exist_ok=True)
    model = load_yaml(config / "model.yaml")
    d = pd.read_csv(results / "model_delivery.csv")
    c = pd.read_csv(results / "model_capacity.csv")
    ch = [tuple(x) for x in model["figure_channels"]]
    fig_sig_frames(d, out)
    fig_ttd(d, ch, out)
    fig_capacity(c, ch, model, out)
    fig_depth(d, model, out)
