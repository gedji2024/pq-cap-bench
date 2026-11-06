"""Cap watcher for the static re-run (user instruction of 2026-11-06; the timeout and breakdown rule stay as registered).

After each model finishes, appends to logs/static_watch.log: its episode count, breakdowns (registered flag:
error or step limit; timeouts listed apart), its wall time, and the projected end of static + judge. If the
projection exceeds the 30 h cap of design.yaml, the run is stopped before the next model (or the judge) starts.

Projection (CHOICE): now + sum of the design.yaml estimates of the remaining models and the judge, each scaled
by the ratio observed / estimated of the models finished so far; the unscaled projection is logged too and the
later of the two is compared with the cap.

Usage: python experiments/agents/watch_cap.py "<start, e.g. 2026-11-06 07:28:33>"
"""

from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
PROG = HERE / "static_progress.log"
OUT = HERE / "logs/static_watch.log"
DONE = re.compile(r"^\[static\] (\S+) t=0\.0: (\d+)/(\d+) in ([\d.]+) min")


def log(msg: str) -> None:
    line = f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} EST  {msg}"
    with OUT.open("a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def breakdowns(model: str) -> dict:
    f = HERE / f"logs/static/{model.replace(':', '_')}_t0.0.jsonl"
    rs = [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
    brk = [r for r in rs if r["error"] or r["step_limit"]]
    return {"episodes": len(rs), "breakdowns": len(brk),
            "timeouts": sum(1 for r in brk if r["error"] and r["error"].startswith("APITimeoutError")),
            "step_limit": sum(1 for r in brk if r["step_limit"]),
            "other_errors": sum(1 for r in brk if r["error"] and not r["error"].startswith("APITimeoutError")),
            "breakdowns_attacked": sum(1 for r in brk if r["spec"].get("attack"))}


def kill(pattern: str) -> None:
    subprocess.run(["pkill", "-TERM", "-f", pattern], check=False)


def main(start: str) -> int:
    dz = yaml.safe_load((HERE / "design.yaml").read_text())
    order, est, cap = dz["order"], dz["runtime"]["estimate_h"], float(dz["runtime"]["cap_h"])
    t0 = dt.datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
    finished: dict[str, float] = {}
    log(f"watcher started; run start {t0}; cap {cap} h -> {t0 + dt.timedelta(hours=cap)}")
    while len(finished) < len(order):
        for line in PROG.read_text().splitlines() if PROG.exists() else []:
            m = DONE.match(line)
            if m and m.group(2) == m.group(3) and m.group(1) not in finished:
                finished[m.group(1)] = float(m.group(4)) / 60
                model, now = m.group(1), dt.datetime.now()
                rest = [x for x in order if x not in finished]
                ratio = sum(finished.values()) / sum(est[x] for x in finished)
                rem = sum(est[x] for x in rest) + est["judge"]
                proj_raw, proj_sc = now + dt.timedelta(hours=rem), now + dt.timedelta(hours=rem * ratio)
                proj = max(proj_raw, proj_sc)
                total_h = (proj - t0).total_seconds() / 3600
                log(f"{model} done in {finished[model]:.2f} h (estimate {est[model]} h); {json.dumps(breakdowns(model))}")
                log(f"projected end {proj:%Y-%m-%d %H:%M} (unscaled {proj_raw:%H:%M}, scaled x{ratio:.2f} "
                    f"{proj_sc:%H:%M}); total {total_h:.1f} h vs cap {cap} h; next: {rest[0] if rest else 'judge'}")
                if total_h > cap:
                    for _ in range(30):          # the judge may start a moment after the last model ends
                        kill("run.py static")
                        kill("run.py judge")
                        time.sleep(1)
                    log(f"STOPPED before {rest[0] if rest else 'judge'}: projection {total_h:.1f} h > cap {cap} h")
                    return 3
        time.sleep(1)
    log("all models finished within the projection; judge proceeds")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
