"""Parse pqm4 benchmarks.md (published Cortex-M4 measurements) and derive envelope-verification cost.

benchmarks.md layout (mupq/pqm4): top-level sections "# Speed Evaluation", "# Memory Evaluation",
"# Hashing Evaluation", "# Size Evaluation", each with "## Key Encapsulation Schemes" and
"## Signature Schemes" markdown tables. Speed cells look like
"AVG: 1,421,623 <br /> MIN: 1,420,738 <br /> MAX: 1,422,362"; memory cells are plain byte counts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd

from .config import load_yaml

_EXEC = re.compile(r"\((\d[\d,]*) executions?\)")


def _num(s: str) -> int:
    return int(s.replace(",", "").strip())


def parse_speed_cell(cell: str) -> dict:
    out = {}
    for part in cell.split("<br />"):
        k, _, v = part.strip().partition(":")
        if k.strip() in ("AVG", "MIN", "MAX"):
            out[k.strip().lower()] = _num(v)
    if set(out) != {"avg", "min", "max"}:
        raise ValueError(f"unparsable speed cell: {cell!r}")
    return out


def tables(md: str) -> dict[tuple[str, str], list[list[str]]]:
    """{(top-level section, subsection): data rows (header and separator rows removed)}."""
    out, top, rows = {}, None, None
    for line in md.splitlines():
        if line.startswith("# "):
            top, rows = line[2:].strip(), None
        elif line.startswith("## "):
            rows = out.setdefault((top, line[3:].strip()), [])
        elif line.startswith("|") and rows is not None:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not set(cells[0]) <= set("- ") and cells[0].lower() != "scheme":
                rows.append(cells)
    return out


def signature_benchmarks(md: str) -> pd.DataFrame:
    t = tables(md)
    speed = {}
    for cells in t.get(("Speed Evaluation", "Signature Schemes"), []):
        m = _EXEC.search(cells[0])
        kg, sg, vf = (parse_speed_cell(c) for c in cells[2:5])
        speed[(_EXEC.sub("", cells[0]).strip(), cells[1])] = {
            "executions": _num(m.group(1)) if m else None,
            **{f"keygen_{k}": v for k, v in kg.items()}, **{f"sign_{k}": v for k, v in sg.items()},
            **{f"verify_{k}": v for k, v in vf.items()}}
    mem = {(c[0], c[1]): {"keygen_stack_bytes": _num(c[2]), "sign_stack_bytes": _num(c[3]),
                          "verify_stack_bytes": _num(c[4])}
           for c in t.get(("Memory Evaluation", "Signature Schemes"), [])}
    size = {(c[0], c[1]): {"code_text_bytes": _num(c[2]), "code_total_bytes": _num(c[-1])}
            for c in t.get(("Size Evaluation", "Signature Schemes"), [])}
    return pd.DataFrame([{"scheme": s, "impl": i, **v, **mem.get((s, i), {}), **size.get((s, i), {})}
                         for (s, i), v in speed.items()])


def verification_cost(config: Path, repo: Path) -> pd.DataFrame:
    cfg = load_yaml(config / "mcu.yaml")
    src = json.loads((repo / "data/pqm4/SOURCE.json").read_text())
    parsed = {pin: signature_benchmarks((repo / p["files"]["benchmarks.md"]["path"]).read_text())
              for pin, p in src["pins"].items()}
    f = cfg["measurement_clock_mhz"] * 1e6
    rows = []
    for sel in cfg["selections"]:
        df = parsed[sel["pin"]]
        r = df[(df.scheme == sel["scheme"]) & (df.impl == sel["impl"])]
        if r.empty:
            raise KeyError(f"{sel['scheme']}/{sel['impl']} not in pqm4 pin {sel['pin']}")
        r = r.iloc[0]
        rows.append({"label": sel["label"], "pqm4_scheme": sel["scheme"], "impl": sel["impl"],
                     "pqm4_commit": src["pins"][sel["pin"]]["commit"], "executions": r.executions,
                     "verify_cycles_avg": int(r.verify_avg), "verify_cycles_min": int(r.verify_min),
                     "verify_cycles_max": int(r.verify_max), "verify_stack_bytes": int(r.verify_stack_bytes),
                     "clock_mhz": cfg["measurement_clock_mhz"], "verify_ms_avg": r.verify_avg / f * 1e3,
                     "verify_ms_max": r.verify_max / f * 1e3, "source_label": cfg["label"]})
    return pd.DataFrame(rows)


def falcon_removal(repo: Path) -> dict | None:
    """F8: why Falcon left pqm4, quoted verbatim from the cached GitHub API responses (data/pqm4/SOURCE.json)."""
    src = json.loads((Path(repo) / "data/pqm4/SOURCE.json").read_text()).get("falcon_removal")
    if not src:
        return None
    c = json.loads((Path(repo) / src["commit"]["path"]).read_text())
    pr = json.loads((Path(repo) / src["pull_request"]["path"]).read_text())
    return {"commit_sha": c["sha"], "commit_url": src["commit"]["html_url"], "author": c["commit"]["author"]["name"],
            "date": c["commit"]["author"]["date"], "message": c["commit"]["message"],
            "pr_url": src["pull_request"]["html_url"], "pr_title": pr["title"], "pr_merged_at": pr["merged_at"],
            "retrieved_utc": src["commit"]["retrieved_utc"], "note": src["note"]}
