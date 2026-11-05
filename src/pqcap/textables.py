"""Manuscript tables as booktabs LaTeX fragments, straight from results/*.csv (no hand-copied numbers).

Each fragment is a `tabular` (the manuscript wraps it in its own `table` float and caption) preceded by a comment
naming the source CSV(s), the selection applied and the commit the results came from. Run by
`make paper-tables` (scripts/export_tex.py). A table whose source CSV is missing is skipped and listed.
"""

from __future__ import annotations

import math
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

_ESC = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_", "{": r"\{",
        "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}"}


def esc(v) -> str:
    return "".join(_ESC.get(c, c) for c in str(v))


def num(v, fmt: str = "{:,.0f}") -> str:
    """Number cell: '--' for missing, '$\\infty$' for infinity, otherwise `fmt` (thousands separator as {,})."""
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "--"
    if isinstance(v, float) and math.isinf(v):
        return r"$\infty$"
    return fmt.format(v).replace(",", "{,}")


def ci(v, lo, hi, fmt: str = "{:.2f}") -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "--"
    return f"{num(v, fmt)} [{num(lo, fmt)}, {num(hi, fmt)}]"


def rng(lo, hi, fmt: str = "{:.3g}") -> str:
    a, b = num(lo, fmt), num(hi, fmt)
    return a if a == b else f"{a}--{b}"


def yn(v) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "--"
    return "yes" if bool(v) else "no"


def tabular(df: pd.DataFrame, header: list[str], align: str, comment: list[str]) -> str:
    """booktabs tabular; cells are already-formatted strings (numbers) or raw values (escaped here)."""
    lines = [f"% {c}" for c in comment]
    lines += [rf"\begin{{tabular}}{{{align}}}", r"\toprule", " & ".join(esc(h) for h in header) + r" \\", r"\midrule"]
    for row in df.itertuples(index=False):
        lines.append(" & ".join(c if isinstance(c, _Tex) else esc(c) for c in row) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", ""]
    return "\n".join(lines)


class _Tex(str):
    """A cell that is already LaTeX (not escaped again)."""


def T(s: str) -> _Tex:  # noqa: N802
    return _Tex(s)


@dataclass
class Spec:
    name: str
    sources: list[str]
    build: Callable[[dict[str, pd.DataFrame]], tuple[pd.DataFrame, list[str], str, str]]


# ---------------------------------------------------------------- table builders (each: frame, header, align, note)
def _sizes(d):
    s = d["sizes.csv"]
    t = pd.DataFrame({"a": s.algorithm, "k": s.kind, "pk": [T(num(v)) for v in s.pk_bytes],
                      "sig": [T(num(v)) for v in s.sig_max]})
    return t, ["Algorithm", "Kind", "Public key (B)", "Signature, max observed (B)"], "llrr", "all rows"


def _tokens(d):
    s = d["model_tokens.csv"]
    s = s[s.depth == 0]
    t = pd.DataFrame({"s": s.scheme, "a": s.algorithm, "b": [T(num(v)) for v in s.token_bytes]})
    return t, ["Scheme", "Algorithm", "Token (B)"], "llr", "depth 0"


def _blast(d):
    s = d["catalogue_k5_ranges.csv"]
    t = pd.DataFrame({"c": s.compromise, "s": s.scheme,
                      "f": [T(rng(a, b)) for a, b in zip(s.fraction_min, s.fraction_max)],
                      "n": [T(num(v)) for v in s.cases]})
    return t, ["Compromise", "Scheme", "Blast radius (fraction of catalogue)", "Cases"], "llrr", "all rows"


def _replay(d, strategy: str, profile_rule: str):
    s = d["model_harm_delays.csv"]
    s = s[(s.energy_budget == "off") if "energy_budget" in s else s.index == s.index]
    prof = s.battery_profile.iloc[0] if profile_rule == "first" else profile_rule
    s = s[(s.battery_profile == prof) & ((s.strategy == strategy) | ((s.compromise == "none") & (s.legit_policy == "naive")))]
    t = pd.DataFrame({"s": s.scheme, "c": s.compromise, "n": [T(num(v)) for v in s.crossings],
                      "l": [T(ci(*r)) for r in zip(s.late_or_missed_share, s.late_or_missed_share_ci_lo,
                                                   s.late_or_missed_share_ci_hi)],
                      "p": [T(ci(*r, fmt="{:,.0f}")) for r in zip(s.p90_delay_min, s.p90_delay_min_ci_lo,
                                                                 s.p90_delay_min_ci_hi)]})
    return (t, ["Scheme", "Compromise", "Crossings", "Late or missed [95% CI]", "p90 delay, min [95% CI]"], "llrrr",
            f"strategy {strategy} and the legitimate naive baseline (compromise none), battery profile {prof}, "
            "energy budget off; CIs: storm-cluster bootstrap")


def _excess(d):
    s = d["model_harm_excess.csv"]
    s = s[(s.energy_budget == "off") if "energy_budget" in s else s.index == s.index]
    t = pd.DataFrame({"b": s.battery_profile, "s": s.scheme, "c": s.compromise, "x": s.strategy,
                      "e": [T(ci(*r, fmt="{:.3f}")) for r in zip(s.excess, s.excess_ci_lo, s.excess_ci_hi)]})
    return (t, ["Battery profile", "Scheme", "Compromise", "Strategy", "Excess late or missed [95% CI]"], "llllr",
            "energy budget off; excess over the paired legitimate baseline")


def _sweep(d):
    s = d["g3_budget_sweep.csv"].sort_values("budget_per_epoch", na_position="last")
    t = pd.DataFrame({"b": ["none" if pd.isna(v) else T(num(v)) for v in s.budget_per_epoch],
                      "p": [T(ci(*r, fmt="{:,.0f}")) for r in zip(s.legit_p90_delay_min, s.legit_p90_delay_min_ci_lo,
                                                                 s.legit_p90_delay_min_ci_hi)],
                      "e": [T(ci(*r, fmt="{:.3f}")) for r in zip(s.excess, s.excess_ci_lo, s.excess_ci_hi)]})
    r = s.iloc[0]
    return (t, ["Budget per day (POLICY)", "Legitimate p90 delay, min [95% CI]", "Attack excess [95% CI]"], "rrr",
            f"{r.scheme} under {r.compromise} {r.strategy}, {r.battery_profile}, initial SOC {r.initial_soc_pct:g}%")


def _soc(d):
    s = d["g3_soc_sensitivity.csv"]
    t = pd.DataFrame({"s": [T(num(v, "{:g}")) for v in s.initial_soc_pct], "d": [T(num(v)) for v in s.derived_budget],
                      "u": [T(num(v)) for v in s.largest_budget_at_or_below],
                      "ue": [T(ci(*r, fmt="{:.3f}")) for r in zip(s.its_excess_below, s.its_excess_below_ci_lo,
                                                                 s.its_excess_below_ci_hi)],
                      "o": [T(num(v)) for v in s.smallest_budget_excess_over],
                      "oe": [T(ci(*r, fmt="{:.3f}")) for r in zip(s.its_excess, s.its_excess_ci_lo, s.its_excess_ci_hi)]})
    th = s.threshold.iloc[0]
    return (t, ["Initial SOC (%)", "Derived budget", f"Largest budget, excess <= {th:g}", "Its excess",
                f"Smallest budget, excess > {th:g}", "Its excess"], "rrrrrr", "SOC values CHOICE; grid resolution")


def _floor(d):
    s = d["g3_floor_timing.csv"]
    t = pd.DataFrame({"b": [T(num(v)) for v in s.budget_per_epoch],
                      "n": [T(f"{num(a)}/{num(b)}") for a, b in zip(s.events_reaching_floor, s.events)],
                      "m": [T(num(v, "{:.1f}")) for v in s.median_floor_day],
                      "r": [T(num(v, "{:+.1f}")) for v in s.median_floor_day_rel_peak],
                      "f": [T(num(v)) for v in s.floor_before_first_crossing]})
    return (t, ["Budget per day", "Events reaching floor", "Median day", "Median day from peak",
                "Floor before first crossing"], "rrrrr", "drain attack, headline SOC")


def _f3(d):
    s = d["f3_ablation_clusters.csv"]
    t = pd.DataFrame({"b": s.commissioning_bound, "c": s.compromise,
                      "l": [T(ci(*r)) for r in zip(s.late_or_missed_share, s.late_or_missed_share_ci_lo,
                                                   s.late_or_missed_share_ci_hi)],
                      "e": [T(ci(*r, fmt="{:.3f}")) for r in zip(s.excess, s.excess_ci_lo, s.excess_ci_hi)]})
    return (t, ["Commissioning bound", "Compromise", "Late or missed [95% CI]", "Excess [95% CI]"], "llrr",
            "S6+F, suppress; storm-cluster bootstrap")


def _revocation(d):
    s = d["model_revocation_exposure.csv"]
    s = s[s.region.isin(["-", "US915"]) & s.dr.isin([-1, 8]) & s.devices.isin([-1, 50])]
    t = pd.DataFrame({"s": s.scheme, "c": s.compromise, "v": [T(num(v)) for v in s.validity_h], "m": s.mechanism,
                      "w": [T(num(v, "{:,.2f}")) for v in s.exposure_worst_h],
                      "e": [T(num(v, "{:,.2f}")) for v in s.exposure_expected_h]})
    return (t, ["Scheme", "Compromise", "Validity (h)", "Mechanism", "Worst exposure (h)", "Expected exposure (h)"],
            "llrlrr", "US915 DR8, 50 devices (or not applicable)")


def _approvals(d):
    s = d["f6_op_approval.csv"]
    s = s[(s.region == "US915") & (s.dr == 8)]
    t = pd.DataFrame({"a": s.approval, "b": [T(num(v)) for v in s.message_bytes], "f": [T(num(v)) for v in s.frames],
                      "x": [T(num(v, "{:.2f}")) for v in s.airtime_s],
                      "l": [T(num(v, "{:,.0f}")) for v in s.latency_worst_s]})
    return (t, ["Approval", "Message (B)", "Frames", "Airtime (s)", "Worst latency (s)"], "lrrrr", "US915 DR8")


def _pqm4(d):
    s = d["mcu_verify_cost.csv"]
    t = pd.DataFrame({"l": s.label, "i": s.impl, "c": [T(num(v)) for v in s.verify_cycles_avg],
                      "m": [T(num(v, "{:.1f}")) for v in s.verify_ms_avg], "k": [T(num(v)) for v in s.verify_stack_bytes]})
    return (t, ["Scheme", "Implementation", "Verify cycles (avg)", "Verify ms (avg)", "Stack (B)"], "llrrr",
            f"pqm4 published measurements at {s.clock_mhz.iloc[0]} MHz, commit {s.pqm4_commit.iloc[0]}")


def _filtering(d):
    s = d["g1_bounds_source.csv"]
    t = pd.DataFrame({"p": s.filter_point, "s": s.scheme, "b": s.bounds_source, "f": [yn(v) for v in s.forging_power],
                      "n": [yn(v) for v in s.ns_checks_installed], "a": [yn(v) for v in s.aud_verifiable],
                      "x": [T(rng(a, b, "{:,.0f}")) for a, b in zip(s.saved_s_per_h_min, s.saved_s_per_h_max)]})
    return (t, ["Filter point", "Scheme", "Bounds source", "Forging power", "NS checks installed", "AUD verifiable",
                "Airtime saved (s/h)"], "lllllll", "model.yaml d6.bounds_source setting")


def _tamarin(d):
    s = d["formal_lemmas.csv"]
    t = pd.DataFrame({"m": s.model, "l": s.lemma, "k": s.kind, "r": s.result,
                      "n": [T(num(v)) for v in s.steps]})
    return t, ["Model", "Lemma", "Kind", "Result", "Steps"], "llllr", "all lemmas; prover version in formal/proofs/VERSION.txt"


def _agents_primary(d):
    s = d["agents/static_primary_hb.csv"]
    t = pd.DataFrame({"g": s.goal, "k": [T(f"{num(a)}/{num(b)}") for a, b in zip(s.k, s.n)],
                      "u": [T(num(v, "{:.4f}")) for v in s.upper95_one_sided]})
    return t, ["Goal", "Executed outside envelope (k/n)", "One-sided 95% upper bound"], "lrr", "S6+F, test split"


def _agents_rates(d, file: str, label: str):
    s = d[f"agents/{file}"]
    t = pd.DataFrame({"c": s.condition, "p": s.prompt,
                      "r": [T(ci(*r) + f" ({num(k)}/{num(n)})") for r, k, n in
                            zip(zip(s.rate, s.ci_lo, s.ci_hi), s.k, s.n)]})
    return t, ["Condition", "Prompt", f"{label} [Wilson 95% CI]"], "llr", "pooled over models"


def _agents_outcomes(d):
    s = d["agents/static_outcomes.csv"]
    t = s.copy()
    for c in t.columns[2:]:
        t[c] = [T(num(v)) for v in t[c]]
    return t, list(s.columns), "ll" + "r" * (len(s.columns) - 2), "per model and condition; judge-based classes PROVISIONAL until validated"


SPECS = [
    Spec("sizes", ["sizes.csv"], _sizes),
    Spec("tokens", ["model_tokens.csv"], _tokens),
    Spec("blast_radius", ["catalogue_k5_ranges.csv"], _blast),
    Spec("replay_suppress", ["model_harm_delays.csv"], lambda d: _replay(d, "suppress", "first")),
    Spec("replay_drain", ["model_harm_delays.csv"], lambda d: _replay(d, "drain", "LWL01/poor")),
    Spec("replay_excess", ["model_harm_excess.csv"], _excess),
    Spec("budget_sweep", ["g3_budget_sweep.csv"], _sweep),
    Spec("budget_soc", ["g3_soc_sensitivity.csv"], _soc),
    Spec("budget_floor", ["g3_floor_timing.csv"], _floor),
    Spec("f3_bound", ["f3_ablation_clusters.csv"], _f3),
    Spec("revocation", ["model_revocation_exposure.csv"], _revocation),
    Spec("approvals", ["f6_op_approval.csv"], _approvals),
    Spec("pqm4", ["mcu_verify_cost.csv"], _pqm4),
    Spec("filtering", ["g1_bounds_source.csv"], _filtering),
    Spec("tamarin", ["formal_lemmas.csv"], _tamarin),
    Spec("agents_primary", ["agents/static_primary_hb.csv"], _agents_primary),
    Spec("agents_executed", ["agents/static_executed_pooled.csv"],
         lambda d: _agents_rates(d, "static_executed_pooled.csv", "Executed-ASR")),
    Spec("agents_attempted", ["agents/static_attempted_pooled.csv"],
         lambda d: _agents_rates(d, "static_attempted_pooled.csv", "Attempted-ASR")),
    Spec("agents_false_report", ["agents/static_false_report.csv"],
         lambda d: _agents_rates(d, "static_false_report.csv", "False-report rate")),
    Spec("agents_outcomes", ["agents/static_outcomes.csv"], _agents_outcomes),
]


def commit(root: Path) -> str:
    def git(*a):
        return subprocess.run(["git", *a], capture_output=True, text=True, cwd=root).stdout.strip()
    h = git("rev-parse", "HEAD") or "unknown"
    return h + ("-dirty" if git("status", "--porcelain", "--untracked-files=no", "--", "results", "experiments/agents/results") else "")


def export(results: Path, agents_results: Path, out: Path, rev: str, root: Path) -> tuple[list[str], list[str]]:
    """Write every table whose sources exist; return (written, skipped)."""
    out.mkdir(parents=True, exist_ok=True)
    written, skipped = [], []
    for sp in SPECS:
        paths = {s: (agents_results / s.split("/", 1)[1] if s.startswith("agents/") else results / s)
                 for s in sp.sources}
        if not all(p.exists() for p in paths.values()):
            skipped.append(sp.name)
            continue
        frames = {s: pd.read_csv(p) for s, p in paths.items()}
        df, header, align, note = sp.build(frames)
        src = ", ".join(str(p.resolve().relative_to(root.resolve())) for p in paths.values())
        (out / f"{sp.name}.tex").write_text(tabular(df, header, align, [
            "Generated by scripts/export_tex.py (pqcap.textables); do not edit by hand.",
            f"Source: {src}; selection: {note}.", f"Results commit: {rev}"]))
        written.append(sp.name)
    return written, skipped
