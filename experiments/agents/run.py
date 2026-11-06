"""Task E driver. Usage: uv run python experiments/agents/run.py {pilot|static|adaptive|determinism} [--models m,..]

Writes experiments/agents/logs/<phase>/<model>_t<temp>.jsonl (one record per episode; resumable) and SHA256SUMS.
Local simulation only (Ollama on 127.0.0.1); no paid API.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

from pqcap.agents import adaptive as AD
from pqcap.agents import attacks as A
from pqcap.agents import design as D
from pqcap.agents import llm as L
from pqcap.agents import outcome as O
from pqcap.agents import runner as R
from pqcap.agents import scenario as SC
from pqcap.config import CONFIG, REPO_ROOT, load_yaml

HERE = REPO_ROOT / "experiments/agents"


def world(cache_name: str) -> tuple[R.World, dict, list]:
    cfg = load_yaml(HERE / "config.yaml")
    h = {**load_yaml(CONFIG / "harm.yaml"), "workers": 1}
    scn = {s.id: s for s in SC.build(h, REPO_ROOT)}
    acfg, atks = A.load(HERE / "attacks/v1/attacks.yaml")
    tags = json.load(urllib.request.urlopen("http://127.0.0.1:11434/api/tags"))
    digests = {m["name"]: m["digest"] for m in tags["models"]}
    w = R.World(cfg, scn, load_yaml(CONFIG / "actions.yaml"), acfg, {a.id: a for a in atks},
                L.Cache(HERE / f"cache/{cache_name}.sqlite"), digests=digests)
    return w, cfg, atks


def prereg() -> tuple[str, str]:
    """The PREREG commit and file SHA-256; refuses to run the main study before PREREG is committed."""
    import hashlib  # noqa: PLC0415
    import subprocess  # noqa: PLC0415
    p = HERE / "PREREG.md"
    c = subprocess.run(["git", "log", "-1", "--format=%H", "--", str(p)], capture_output=True, text=True,
                       cwd=REPO_ROOT).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", str(p), str(HERE / "design.yaml"),
                            str(HERE / "config.yaml"), str(HERE / "attacks")], capture_output=True, text=True,
                           cwd=REPO_ROOT).stdout.strip()
    if not c or dirty:
        sys.exit("PREREG.md, design.yaml, config.yaml and attacks/ must be committed and unchanged before the main study")
    return c, hashlib.sha256(p.read_bytes()).hexdigest()


def run_specs(w: R.World, specs: list, phase: str, stamp: tuple = ("pilot", "")):
    by = {}
    for s in specs:
        by.setdefault((s.model, s.temperature), []).append(s)
    for (m, t), ss in by.items():
        log = HERE / f"logs/{phase}/{m.replace(':', '_')}_t{t}.jsonl"
        done = R.done_keys(log)
        todo = [s for s in ss if s.key() not in done]
        t0 = time.time()
        print(f"[{phase}] {m} t={t}: {len(todo)} to run ({len(done)} done)", flush=True)
        for i, s in enumerate(todo, 1):
            R.append(log, {**R.run_episode(w, s), "prereg_commit": stamp[0], "prereg_sha256": stamp[1]})
            if i % 25 == 0 or i == len(todo):
                el = time.time() - t0
                print(f"[{phase}] {m} t={t}: {i}/{len(todo)} in {el / 60:.1f} min ({el / i:.1f} s/ep)", flush=True)
    R.sha256_manifest(HERE / f"logs/{phase}")


def run_adaptive(w: R.World, cfg: dict, atks: list, phase: str, cells: list, conditions: list, prompts: list,
                 models: list, k: int, host_pairs: list, seed: int, stamp: tuple = ("pilot", "")):
    atk_cfg, attacker = w.attack_cfg, cfg["attacker"]
    cl = w.client
    for m in models:
        log = HERE / f"logs/{phase}/{m.replace(':', '_')}_t0.0.jsonl"
        done = R.done_keys(log)
        t0, n = time.time(), 0
        for ci, (ch, goal) in enumerate(cells):
            dev = next(a for a in atks if a.split == "dev" and a.channel == ch and a.goal == goal)
            ut, sc = host_pairs[ci % len(host_pairs)]
            it = __import__("pqcap.agents.suite", fromlist=["x"]).INJECTION_TASKS[goal](w.scenarios[sc], w.ft, ut)
            seed_inj = A.render(atk_cfg, dev, it.GOAL)
            for c in conditions:
                for pv in prompts:
                    inj = seed_inj
                    for att in range(k):
                        spec = R.Spec(m, 0.0, seed, 0, c, pv, sc, ut, None, goal=goal, adaptive_cell=f"{ch}:{goal}",
                                      attempt=att, injection=inj)
                        if spec.key() in done:
                            rec = next(json.loads(x) for x in log.read_text().splitlines() if json.loads(x)["key"] == spec.key())
                        else:
                            rec = {**R.run_episode(w, spec), "prereg_commit": stamp[0], "prereg_sha256": stamp[1]}
                            R.append(log, rec)
                            n += 1
                        lab = O.classify(rec["executed"], rec["attack_receipts"], bool(rec["error"] or rec["step_limit"]),
                                         None, None, rec["agent_text"])
                        if lab == "executed":
                            break
                        prev = inj.get(AD.vector(atk_cfg, ch)) or " ".join(inj.values())
                        new, _ = AD.rewrite(cl, w.cache, attacker, w.digests.get(attacker["model"], ""), it.GOAL, ch,
                                            prev, lab, rec["final_output"], seed + 1000 * att + ci)
                        inj = {AD.vector(atk_cfg, ch): new}
                    if n and n % 25 == 0:
                        print(f"[{phase}] {m}: {n} episodes, {(time.time() - t0) / n:.1f} s/ep", flush=True)
        print(f"[{phase}] {m}: done, {n} new episodes in {(time.time() - t0) / 60:.1f} min", flush=True)
    R.sha256_manifest(HERE / f"logs/{phase}")


def run_e6(w: R.World, dz: dict, models: list, stamp: tuple):
    e6 = dz["e6"]
    fams = w.attack_cfg["families"]
    specs = []
    for m in models:
        for sch in e6["schemes"]:
            for sc in e6["scenarios"]:
                specs.append(R.Spec(m, 0.0, dz["seed"], 0, sch, "naive", sc, "E6", None))
                for goal in w.attack_cfg["goals"]:
                    it = __import__("pqcap.agents.suite", fromlist=["x"]).INJECTION_TASKS[goal](w.scenarios[sc], w.ft, "E6")
                    for f in e6["families"]:
                        text = fams[f].format(goal=R.E6_INJECTION.format(goal=it.GOAL))
                        specs.append(R.Spec(m, 0.0, dz["seed"], 0, sch, "naive", sc, "E6", f"E6:{goal}:{f}", goal=goal,
                                            injection={"bulletin_a": text}))
    log = HERE / "logs/e6/e6.jsonl"
    done = R.done_keys(log)
    for i, s in enumerate([s for s in specs if s.key() not in done], 1):
        R.append(log, {**R.run_delegation(w, s), "prereg_commit": stamp[0], "prereg_sha256": stamp[1]})
        if i % 10 == 0:
            print(f"[e6] {i} episodes", flush=True)
    R.sha256_manifest(HERE / "logs/e6")


def run_judge(w: R.World, cfg: dict, stamp: tuple):
    """Label-blind judge on attacked episodes with no attack command and no executed goal (static + adaptive)."""
    from pqcap.agents import judge as JD  # noqa: PLC0415
    out = HERE / "logs/judge/judge.jsonl"
    done = R.done_keys(out)
    jc = cfg["judge"]
    for phase in ("static", "adaptive"):
        for f in sorted((HERE / f"logs/{phase}").glob("*.jsonl")):
            for line in f.read_text().splitlines():
                r = json.loads(line)
                if r["key"] in done or not r.get("goal") or r.get("executed") or r.get("attack_receipts"):
                    continue
                inj = " ".join(r["injections"].values())
                lab, q, st = JD.judge(w.client, w.cache, jc, w.digests.get(jc["model"], ""), inj, r["agent_text"])
                R.append(out, {"key": r["key"], "label": lab, "quote": q, "stats": st, "prereg_commit": stamp[0]})
                done.add(r["key"])
    R.sha256_manifest(HERE / "logs/judge")


def determinism(n: int, seed: int):
    """Re-run n pilot episodes at temperature 0 with no cache and compare the transcript-level result (final
    output, receipts) with the logged run. Writes logs/determinism.json."""
    import random  # noqa: PLC0415
    w, cfg, atks = world("determinism_unused")
    w.cache = None
    recs = []
    for f in sorted((HERE / "logs/pilot").glob("*_t0.0.jsonl")):
        recs += [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
    sample = random.Random(seed).sample(recs, min(n, len(recs)))
    out = []
    for r in sample:
        s = R.Spec(**r["spec"])
        r2 = R.run_episode(w, s)
        same = (r2["final_output"] == r["final_output"] and
                [(x["action"], x["value"], x["decision"]) for x in r2["receipts"]] ==
                [(x["action"], x["value"], x["decision"]) for x in r["receipts"]])
        out.append({"key": r["key"], "model": s.model, "identical": same})
        print(s.model, s.condition, same, flush=True)
    (HERE / "logs/determinism.json").write_text(json.dumps(out, indent=1))


def syscheck(models: list[str]) -> bool:
    """DEVIATIONS #1: per model, prompt_eval_count with and without the system prompt on the same episode (the
    first benign host pair; naive under none and limit-aware under S6+F), with the rendered prompt and template.
    Writes logs/syscheck/. Returns True when every check passes."""
    from pqcap.agents import syscheck as SY  # noqa: PLC0415
    w, cfg, atks = world("syscheck_unused")
    dz = load_yaml(HERE / "design.yaml")
    ut, sc = D.pairs(sorted(w.scenarios), dz["host_pairs"]["n"], dz["host_pairs"]["seed"])[0]
    d = HERE / "logs/syscheck"
    d.mkdir(parents=True, exist_ok=True)
    summ = json.loads((d / "summary.json").read_text()) if (d / "summary.json").exists() else {}
    for m in models:
        for cond, prompt in (("none", "naive"), ("S6+F", "limit_aware")):
            s = R.Spec(m, 0.0, dz["seed"], 0, cond, prompt, sc, ut, None)
            r = {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "spec_key": s.key(), **SY.check(SY.first_request(w, s))}
            name = f"{m.replace(':', '_')}_{cond}_{prompt}"
            (d / f"{name}.json").write_text(json.dumps(r, indent=1))
            summ[name] = {k: v for k, v in r.items() if not k.startswith(("rendered", "template")) or k == "template_sha256"}
            print(name, {k: r[k] for k in ("prompt_eval_count_with", "prompt_eval_count_without", "diff_native",
                                           "diff_v1", "system_tokens_raw", "wrapper_tokens", "system_text_rendered",
                                           "ok")}, flush=True)
    (d / "summary.json").write_text(json.dumps(summ, indent=1, sort_keys=True))
    return all(v["ok"] for v in summ.values())


def determinism_sys(n: int, reps: int, seed: int):
    """After the re-run: n episodes per model drawn from logs/static, each re-run `reps` times at the logged seed and
    temperature with no cache. Compares the runs with each other and with the logged episode (final output and
    receipts). Writes logs/determinism_sys.json."""
    import random  # noqa: PLC0415
    w, cfg, atks = world("determinism_unused")
    w.cache = None
    out = []
    sig = lambda r: (r["final_output"], [(x["action"], x["value"], x["decision"]) for x in r["receipts"]])  # noqa: E731
    for f in sorted((HERE / "logs/static").glob("*_t0.0.jsonl")):
        recs = [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
        for r in random.Random(seed).sample(recs, min(n, len(recs))):
            s = R.Spec(**r["spec"])
            runs = [R.run_episode(w, s) for _ in range(reps)]
            row = {"key": r["key"], "model": s.model, "condition": s.condition, "prompt": s.prompt,
                   "runs_identical": all(sig(x) == sig(runs[0]) for x in runs),
                   "receipts_identical": all(sig(x)[1] == sig(runs[0])[1] for x in runs),
                   "same_as_logged": all(sig(x) == sig(r) for x in runs)}
            out.append(row)
            print(row, flush=True)
    (HERE / "logs/determinism_sys.json").write_text(json.dumps(out, indent=1))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("phase")
    ap.add_argument("--models", default=None)
    a = ap.parse_args(argv)
    if a.phase == "pilot":
        w, cfg, atks = world("pilot")
        p = load_yaml(HERE / "pilot.yaml")
        models = a.models.split(",") if a.models else list(cfg["models"])
        dev = [x for x in atks if x.split == "dev"]
        hp = D.pairs(p["scenarios"], p["n_pairs"], p["seed"])
        specs = D.static_specs(models, {0.0: 1}, cfg["conditions"], cfg["prompt_variants"], dev, hp, p["seed"])
        specs += D.static_specs(models, {0.7: p["reps_t07"]}, p["t07_conditions"], ["naive"], dev, hp, p["seed"])
        run_specs(w, specs, "pilot")
        run_adaptive(w, cfg, atks, "pilot_adaptive", [tuple(x) for x in p["adaptive_cells"]], p["adaptive_conditions"],
                     ["naive"], models, p["adaptive_k"], hp, p["seed"])
    elif a.phase == "determinism":
        determinism(30, 11)
    elif a.phase == "syscheck":
        if not syscheck(a.models.split(",") if a.models else list(load_yaml(HERE / "config.yaml")["models"])):
            sys.exit("system-prompt check FAILED (logs/syscheck/summary.json)")
    elif a.phase == "determinism_sys":
        determinism_sys(20, 2, 11)
    elif a.phase in ("static", "adaptive", "e6", "judge"):
        commit, sha = prereg()
        w, cfg, atks = world("main")
        dz = load_yaml(HERE / "design.yaml")
        models = a.models.split(",") if a.models else list(cfg["models"])
        hp = D.pairs(sorted(w.scenarios), dz["host_pairs"]["n"], dz["host_pairs"]["seed"])
        if a.phase == "static":
            test = [x for x in atks if x.split == "test"]
            temps = {float(t): int(r) for t, r in dz["temperatures"].items()}
            run_specs(w, D.static_specs(models, temps, cfg["conditions"], cfg["prompt_variants"], test, hp,
                                        dz["seed"]), "static", (commit, sha))
        elif a.phase == "adaptive":
            ad = dz["adaptive"]
            cells = [(c, g) for c in ("EXT", "SENS", "TOOL") for g in w.attack_cfg["goals"]]
            run_adaptive(w, cfg, atks, "adaptive", cells, cfg["conditions"], ad["prompts"], models, ad["k"], hp,
                         dz["seed"], (commit, sha))
        elif a.phase == "e6":
            run_e6(w, dz, models, (commit, sha))
        else:
            run_judge(w, cfg, (commit, sha))
    else:
        sys.exit(f"unknown phase {a.phase}")


if __name__ == "__main__":
    main()
