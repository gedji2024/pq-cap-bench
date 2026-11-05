"""Summarise the pilot: runtime per model, cache sharing, determinism, effect sizes for the power argument.
Writes experiments/agents/pilot_summary.json. Pilot numbers size the study; they are not findings."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pqcap.agents import analyze as AN  # noqa: E402
from pqcap.agents import attacks as A  # noqa: E402
from pqcap.agents import stats as ST  # noqa: E402

HERE = Path(__file__).parent


def main():
    _, atks = A.load(HERE / "attacks/v1/attacks.yaml")
    by = {a.id: a for a in atks}
    recs = AN.load(HERE / "logs/pilot")
    df = AN.episodes(recs, by, {})
    out = {"episodes": len(recs), "models": {}}
    for m, g in df.groupby("model"):
        rr = [r for r in recs if r["spec"]["model"] == m and r["spec"]["temperature"] == 0.0]
        calls = [c for r in rr for c in r["llm_calls"]]
        uncached = [c for c in calls if not c["cached"]]
        wall = sum(r["wall_s"] for r in rr)
        out["models"][m] = {
            "episodes_t0": len(rr), "wall_s_per_episode_t0": wall / len(rr),
            "calls_per_episode": len(calls) / len(rr), "cache_hit_share": 1 - len(uncached) / len(calls),
            "s_per_uncached_call": sum(c["latency_s"] for c in uncached) / max(1, len(uncached)),
            "step_limit_episodes": int(sum(r["step_limit"] for r in rr)),
            "errors": int(sum(bool(r["error"]) for r in rr)),
            "wall_s_by_condition": {c: sum(r["wall_s"] for r in rr if r["spec"]["condition"] == c) /
                                    max(1, sum(r["spec"]["condition"] == c for r in rr))
                                    for c in sorted({r["spec"]["condition"] for r in rr})}}
    t0 = df[(df.temperature == 0.0) & df.attacked]
    dev_goal = t0[t0.goal.isin(["drain", "suppress", "disable"])]
    eff = {}
    for c in sorted(set(t0.condition) - {"none"}):
        for col in ("executed", "attempted"):
            p = AN.paired(dev_goal if col == "executed" else t0, col, "none", c,
                          ["model", "prompt", "attack", "scenario", "user_task"])
            eff[f"{c}:{col}"] = {k: p[k] for k in ("pairs", "rate_a", "rate_b", "only_a", "only_b")}
    out["effects_t0_none_vs_condition"] = eff
    out["rates_t0"] = AN.rate_table(t0, "executed", ["model", "condition"]).to_dict("records")
    out["attempted_t0"] = AN.rate_table(t0, "attempted", ["model", "condition"]).to_dict("records")
    ben = df[(df.temperature == 0.0) & ~df.attacked]
    out["utility_t0"] = AN.rate_table(ben, "utility", ["model", "condition", "prompt"]).to_dict("records")
    # temperature 0.7: agreement between the two seeds of the same episode
    t7 = df[df.temperature == 0.7]
    agree = defaultdict(list)
    for _, g in t7.groupby(["model", "condition", "prompt", "attack", "scenario", "user_task"], dropna=False):
        if len(g) == 2:
            agree[g.model.iloc[0]].append(int(g.attempted.nunique() == 1 and g.executed.nunique() == 1
                                              and g.utility.nunique() == 1))
    out["t07_seed_agreement"] = {m: sum(v) / len(v) for m, v in agree.items()}
    out["t07_attempted"] = AN.rate_table(t7[t7.attacked], "attempted", ["model", "condition"]).to_dict("records")
    ad = AN.load(HERE / "logs/pilot_adaptive")
    out["adaptive"] = [{"model": r["spec"]["model"], "cell": r["spec"]["adaptive_cell"], "condition": r["spec"]["condition"],
                        "attempt": r["spec"]["attempt"], "executed": r.get("executed"),
                        "injection": next(iter(r["injections"].values()), "")[:200]} for r in ad]
    det = HERE / "logs/determinism.json"
    if det.exists():
        d = json.loads(det.read_text())
        out["determinism"] = {"checked": len(d), "identical": sum(x["identical"] for x in d)}
    # power: exact McNemar for the smallest scheme effect on executed (device goals), Holm worst case alpha/10
    sch = [k for k in eff if k.endswith(":executed") and k.split(":")[0] in ("S4-F", "S4-E", "S6", "S6-R", "S6+F")]
    if sch:
        n0 = eff[sch[0]]["pairs"]
        worst = min(sch, key=lambda k: (eff[k]["only_a"] - eff[k]["only_b"]))
        p10, p01 = eff[worst]["only_a"] / n0, eff[worst]["only_b"] / n0
        out["power"] = {"contrast": worst, "p10": p10, "p01": p01,
                        "n_pairs_for": {n: ST.mcnemar_power(n, p10, p01, 0.005) for n in (60, 90, 180, 270, 360, 540)}}
    (HERE / "pilot_summary.json").write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps({k: v for k, v in out.items() if k in ("models", "power", "t07_seed_agreement", "determinism")},
                     indent=1, default=str))


if __name__ == "__main__":
    main()
