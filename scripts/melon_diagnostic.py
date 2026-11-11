"""MELON diagnostic (DEVIATIONS 6b): per detection step of every melon episode, whether the original-run reply and the
masked-run reply proposed a tool call. Each episode's `llm_calls` lists the agent's first call per user turn, then one
(original, masked) pair per detection step; the replies are read read-only from the run's request cache by the logged
keys. Writes results/static_ext_melon_diagnostic.csv (one row per step) so the counts are reproducible without the
cache, and prints the totals. Usage: uv run python scripts/melon_diagnostic.py [cache path]"""
import csv
import glob
import json
import sqlite3
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
ag = root / "experiments/agents"
cache = sys.argv[1] if len(sys.argv) > 1 else str(ag / "cache/ext_melon.sqlite")
db = sqlite3.connect(f"file:{cache}?mode=ro", uri=True)


def reply(k):
    return json.loads(db.execute("SELECT v FROM c WHERE k = ?", (k,)).fetchone()[0])["message"]


rows = []
for f in sorted(glob.glob(str(ag / "logs/static_ext_melon/*.jsonl"))):
    for line in open(f):
        r = json.loads(line)
        per, prev = [], None                       # detection steps per user turn
        for m in r["messages"]:
            if m["role"] == "user":
                per.append(0)
            if m["role"] == "tool" and prev != "tool":
                per[-1] += 1
            prev = m["role"]
        calls = r["llm_calls"]
        assert len(calls) == len(per) + 2 * sum(per), r["key"]
        i = 0
        for turn, k in enumerate(per):
            i += 1
            for step in range(k):
                o, mk = reply(calls[i]["key"]), reply(calls[i + 1]["key"])
                i += 2
                rows.append({"key": r["key"], "model": r["spec"]["model"], "prompt": r["spec"]["prompt"],
                             "attack": r["spec"]["attack"], "turn": turn + 1, "step": step + 1,
                             "original_tool_calls": len(o.get("tool_calls") or []),
                             "masked_tool_calls": len(mk.get("tool_calls") or [])})
out = root / "results/static_ext_melon_diagnostic.csv"
with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
print(f"steps (detector invocations = masked runs) {len(rows)}; original reply with a tool call "
      f"{sum(x['original_tool_calls'] > 0 for x in rows)}; masked run with a tool call "
      f"{sum(x['masked_tool_calls'] > 0 for x in rows)}; original tool calls {sum(x['original_tool_calls'] for x in rows)}")
