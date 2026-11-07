"""Host-sleep gap watcher for the static re-run and the judge (user instruction of 2026-11-06).

Runs beside watch_cap.py (which is not restarted). Every POLL s it counts the records of logs/static/*.jsonl and
logs/judge/judge.jsonl; a record's end time is the poll at which it is first seen (resolution POLL s). If two
consecutive end times are more than GAP_MIN apart and the later episode is not a logged timeout
(error APITimeoutError), the gap is a possible host sleep: it is logged to logs/static_watch.log and
logs/host_gaps.jsonl, with the macOS power-log Sleep/Wake events inside the gap, and a row 2.<n> listing the
affected episode is appended to DEVIATIONS.md. Resume rule (DEVIATIONS 4): any macOS Sleep / Wake / DarkWake
event that overlaps an episode (between its start, end - wall time, or the previous end when the record has no
wall time, and its end, +- POLL s) is flagged the same way, whatever the gap length. Exits when the judge has finished (SHA256SUMS written in
logs/judge after the run started) and no run.py process is left.

Usage: python experiments/agents/gap_watch.py "<run start, e.g. 2026-11-06 07:28:33>"
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GAP_MIN = 15.0   # user instruction of 2026-11-06
POLL = 5         # s, CHOICE (end-time resolution)
OUT = HERE / "logs/static_watch.log"
GAPS = HERE / "logs/host_gaps.jsonl"
DEV = HERE / "DEVIATIONS.md"


def files() -> list[Path]:
    return sorted((HERE / "logs/static").glob("*_t0.0.jsonl")) + [HERE / "logs/judge/judge.jsonl"]


def records(f: Path) -> list[str]:
    return [x for x in f.read_text().splitlines() if x.strip()] if f.exists() else []


def power_events(a: dt.datetime, b: dt.datetime) -> list[str]:
    log = subprocess.run(["pmset", "-g", "log"], capture_output=True, text=True).stdout.splitlines()
    out = []
    for line in log:
        p = line.split()
        if len(p) > 4 and p[3] in ("Sleep", "Wake", "DarkWake") and p[4] != "Requests":
            try:
                t = dt.datetime.strptime(f"{p[0]} {p[1]}", "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            if a - dt.timedelta(minutes=1) <= t <= b:
                out.append(" ".join(p[:4]) + " " + " ".join(p[4:9]))
    return out


def note(msg: str) -> None:
    line = f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} EST  {msg}"
    with OUT.open("a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def main(start: str) -> int:
    t_start = dt.datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
    seen = {f: len(records(f)) for f in files()}
    last = dt.datetime.now()
    n_gap = sum(1 for _ in GAPS.open()) if GAPS.exists() else 0
    note(f"gap watcher started (gap > {GAP_MIN} min outside a logged timeout; end-time resolution {POLL} s)")
    while True:
        now = dt.datetime.now()
        for f in files():
            rs = records(f)
            for x in rs[seen.get(f, 0):]:
                r = json.loads(x)
                gap = (now - last).total_seconds() / 60
                err = r.get("error") or ""
                wall = r.get("wall_s")
                ep_start = now - dt.timedelta(seconds=wall) if wall else last
                sleeps = power_events(ep_start - dt.timedelta(seconds=POLL), now + dt.timedelta(seconds=POLL))
                if sleeps or (gap > GAP_MIN and not err.startswith("APITimeoutError")):
                    n_gap += 1
                    spec = r.get("spec", {})
                    ev = sleeps or power_events(last, now)
                    g = {"n": n_gap, "file": f.name, "key": r["key"], "model": spec.get("model"),
                         "condition": spec.get("condition"), "prompt": spec.get("prompt"),
                         "attack": spec.get("attack"), "previous_end": f"{last:%Y-%m-%d %H:%M:%S}",
                         "end": f"{now:%Y-%m-%d %H:%M:%S}", "gap_min": round(gap, 1),
                         "episode_wall_min": round(r.get("wall_s", 0) / 60, 1), "power_log": ev}
                    with GAPS.open("a") as h:
                        h.write(json.dumps(g) + "\n")
                    note(f"POSSIBLE HOST SLEEP: {json.dumps(g)}")
                    with DEV.open("a") as h:
                        h.write(f"| 2.{n_gap} | {now:%Y-%m-%d} | {'Host sleep overlapping an episode' if sleeps else 'Possible host sleep'} (gap_watch.py): {g['gap_min']} min "
                                f"between episode ends {g['previous_end']} and {g['end']} EST, not a logged timeout. "
                                f"Affected episode: `{g['key']}` ({g['model']}, {g['condition']}, {g['prompt']}, "
                                f"attack {g['attack']}; episode wall time {g['episode_wall_min']} min; {f.name}). "
                                f"Power log in the gap: {'; '.join(ev) or 'no Sleep/Wake event'}. | Watcher rule "
                                "(user instruction of 2026-11-06). | Episode kept as run (no rule changed); "
                                "listed for review. |\n")
                last = now
            seen[f] = len(rs)
        judge_done = (HERE / "logs/judge/SHA256SUMS").exists() and \
            dt.datetime.fromtimestamp((HERE / "logs/judge/SHA256SUMS").stat().st_mtime) > t_start
        alive = subprocess.run(["pgrep", "-f", "run.py (static|judge)"], capture_output=True).returncode == 0
        if not alive and (judge_done or (now - last).total_seconds() > 600):
            note(f"gap watcher stopped ({n_gap} possible host-sleep gaps; judge finished: {judge_done})")
            return 0
        time.sleep(POLL)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
