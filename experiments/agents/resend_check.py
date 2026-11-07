"""Resend check (DEVIATIONS 4, FINAL_BATCH 2.1; reporting only, no rule change): are same-run cache hits what the
model would have answered? 30 cached agent calls and 30 cached judge calls of the re-run (random, seed 0) are
resent to the local Ollama server with the cache off, and the fresh answer is compared with the cached one.

Agent calls: the request is not logged, so the episode is replayed against a COPY of the request cache (every
call is a cache hit, nothing is generated) and the request whose key matches the sampled hit is captured and
resent uncached. Judge calls: the request is rebuilt from the episode record exactly as `run_judge` builds it,
its key checked against the logged key, and resent uncached. Compared: exact message equality, and equality of
content + tool-call names/arguments (ignoring tool-call ids). Writes logs/resend_check.json.

Usage: uv run python experiments/agents/resend_check.py
"""

from __future__ import annotations

import hashlib
import json
import random
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run as RUN  # noqa: E402

from pqcap.agents import judge as JD  # noqa: E402
from pqcap.agents import llm as L  # noqa: E402
from pqcap.agents import runner as R  # noqa: E402

N, SEED = 30, 0


def sig(m: dict) -> tuple:
    calls = tuple((c.get("function", {}).get("name"), c.get("function", {}).get("arguments"))
                  for c in (m.get("tool_calls") or []))
    return (m.get("content") or "", calls)


def fresh(cl, req: dict) -> dict:
    return cl.chat.completions.create(**req).choices[0].message.model_dump(exclude_none=True)


def main(cache_copy: Path) -> dict:
    shutil.copy(HERE / "cache/main.sqlite", cache_copy)
    w, cfg, _ = RUN.world("main")
    w.cache = L.Cache(cache_copy)
    rng = random.Random(SEED)
    recs = {}
    hits = []
    for f in sorted((HERE / "logs/static").glob("*_t0.0.jsonl")):
        for x in f.read_text().splitlines():
            r = json.loads(x)
            recs[r["key"]] = r
            seen = set()
            for i, c in enumerate(r["llm_calls"]):
                if c.get("cached") and c["key"] not in seen:
                    hits.append((r["key"], i, c["key"]))
                seen.add(c["key"])
    out = {"agent": [], "judge": []}
    real_chat = L.chat
    for ep, i, key in rng.sample(hits, N):
        box = {}

        def spy(cl, cache, digest, **req):
            k = hashlib.sha256(json.dumps({"digest": digest, **req}, sort_keys=True, default=str).encode()).hexdigest()
            if k == key and "req" not in box:
                box["req"] = req
            return real_chat(cl, cache, digest, **req)
        L.chat = spy
        try:
            R.run_episode(w, R.Spec(**recs[ep]["spec"]))
        finally:
            L.chat = real_chat
        cached = w.cache.get(key)["message"]
        new = fresh(w.client, box["req"]) if "req" in box else None
        out["agent"].append({"episode": ep, "call": i, "key": key, "model": recs[ep]["spec"]["model"],
                             "captured": "req" in box, "identical": new == cached,
                             "identical_ignoring_ids": new is not None and sig(new) == sig(cached)})
        print("agent", out["agent"][-1], flush=True)
    jrecs = [json.loads(x) for x in (HERE / "logs/judge/judge.jsonl").read_text().splitlines() if x.strip()]
    jhits = [j for j in jrecs if j["stats"].get("cached")]
    jc = cfg["judge"]
    digest = w.digests.get(jc["model"], "")
    for j in rng.sample(jhits, min(N, len(jhits))):
        r = recs[j["key"]]
        inj = " ".join(r["injections"].values())
        req = {"model": jc["model"], "temperature": jc["temperature"], "seed": jc["seed"],
               "messages": [{"role": "user", "content": JD.PROMPT.format(injected=inj[:2000], agent=r["agent_text"][:6000])}]}
        k = hashlib.sha256(json.dumps({"digest": digest, **req}, sort_keys=True, default=str).encode()).hexdigest()
        cached = w.cache.get(k)
        new = fresh(w.client, req)
        out["judge"].append({"episode": j["key"], "key_matches_log": k == j["stats"]["key"],
                             "identical": cached is not None and new == cached["message"],
                             "label_identical": cached is not None
                             and JD.parse(new.get("content") or "")[0] == JD.parse(cached["message"].get("content") or "")[0]})
        print("judge", out["judge"][-1], flush=True)
    summ = {k: {"n": len(v), "identical": sum(x["identical"] for x in v),
                **({"identical_ignoring_ids": sum(x["identical_ignoring_ids"] for x in v),
                    "captured": sum(x["captured"] for x in v)} if k == "agent" else
                   {"label_identical": sum(x["label_identical"] for x in v),
                    "key_matches_log": sum(x["key_matches_log"] for x in v)})} for k, v in out.items()}
    summ["judge"]["same_run_hits_available"] = len(jhits)
    res = {"seed": SEED, "summary": summ, **out}
    (HERE / "logs/resend_check.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(summ), flush=True)
    return res


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "cache/resend_copy.sqlite")
