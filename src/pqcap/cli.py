"""pqcap CLI: bench | env | model | figures | report."""

from __future__ import annotations

import argparse

from .config import CONFIG, FIGURES, RESULTS


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="pqcap")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bench", help="host timing + size benchmark (slow)")
    b.add_argument("--config", default=str(CONFIG / "bench.yaml"))
    sub.add_parser("env", help="write results/env.json")
    sub.add_parser("model", help="radio / token / delivery model from measured sizes")
    sub.add_parser("figures", help="render figures/*.pdf|png")
    sub.add_parser("report", help="render REPORT.md from results/*.csv")
    a = ap.parse_args(argv)

    if a.cmd == "bench":
        from pathlib import Path

        from . import bench, env
        bench.run(Path(a.config), RESULTS)
        env.capture(RESULTS / "env.json")
    elif a.cmd == "env":
        from . import env
        env.capture(RESULTS / "env.json")
    elif a.cmd == "model":
        from . import model
        model.run(CONFIG, RESULTS)
    elif a.cmd == "figures":
        from . import figures
        figures.run(RESULTS, FIGURES)
    elif a.cmd == "report":
        from . import report
        report.run(CONFIG, RESULTS, FIGURES)


if __name__ == "__main__":
    main()
