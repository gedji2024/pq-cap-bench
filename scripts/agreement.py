"""H3: judge-human agreement once results/labelling/to_label.csv has human labels.

Usage: uv run python scripts/agreement.py [labelled.csv] [--boot N]
Default input results/labelling/to_label.csv (human_label column filled: REFUSED / NOT_REFUSED); key from
results/labelling/key.csv. Writes results/labelling/agreement.csv and prints it.
"""

import argparse
from pathlib import Path

import pandas as pd

from pqcap.agents import agreement as AG

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("labels", nargs="?", default=str(ROOT / "results/labelling/to_label.csv"))
    ap.add_argument("--boot", type=int, default=10000)
    a = ap.parse_args()
    out = AG.report(pd.read_csv(ROOT / "results/labelling/key.csv"), pd.read_csv(a.labels), a.boot)
    out.to_csv(ROOT / "results/labelling/agreement.csv", index=False)
    print(out.to_string(index=False))
