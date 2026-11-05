"""Parse Tamarin proof outputs (formal/proofs/*.txt) into a lemma table for REPORT.md."""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

# summary lines, e.g. "  P4_no_replay (all-traces): verified (4 steps)"
_LEMMA = re.compile(r"^\s+(?P<lemma>[A-Za-z0-9_]+) \((?P<kind>all-traces|exists-trace)\): "
                    r"(?P<result>verified|falsified - found trace|analysis incomplete) \((?P<steps>\d+) steps\)\s*$")
_VERSION = re.compile(r"tamarin-prover (\d+\.\d+\.\d+)")
_TIMEOUT = re.compile(r"^TIMEOUT after (?P<cap>\d+) s", re.M)


def parse_summary(text: str) -> list[dict]:
    """Lemma results from the 'summary of summaries' block of a `tamarin-prover --prove` run."""
    block = text.split("summary of summaries:", 1)[-1] if "summary of summaries:" in text else text
    out = []
    for line in block.splitlines():
        m = _LEMMA.match(line)
        if m:
            out.append({"lemma": m["lemma"], "kind": m["kind"], "result": m["result"].split(" -")[0],
                        "steps": int(m["steps"])})
    return out


def lemma_file(lemma: str, text: str) -> dict:
    """Result of a single-lemma run written by formal/prove.sh: the summary line of that lemma, or a
    timeout record if the run was killed at the wall-clock cap."""
    t = _TIMEOUT.search(text)
    if t:
        return {"lemma": lemma, "kind": None, "result": f"timeout ({t['cap']} s)", "steps": None}
    hit = [r for r in parse_summary(text) if r["lemma"] == lemma]
    if not hit:
        raise ValueError(f"no summary line for {lemma}")
    return hit[0]


def results(proofs_dir: Path) -> pd.DataFrame:
    """proofs/<model>.txt holds a whole-theory run; proofs/<model>/<lemma>.txt holds per-lemma runs."""
    rows = []
    for p in sorted(Path(proofs_dir).glob("*.txt")):
        for r in parse_summary(p.read_text(errors="replace")):
            rows.append({"model": p.stem, **r})
    for p in sorted(Path(proofs_dir).glob("*/*.txt")):
        rows.append({"model": p.parent.name, **lemma_file(p.stem, p.read_text(errors="replace"))})
    return pd.DataFrame(rows, columns=["model", "lemma", "kind", "result", "steps"])


def version(text: str) -> str | None:
    m = _VERSION.search(text)
    return m.group(1) if m else None
