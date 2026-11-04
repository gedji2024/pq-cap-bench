from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = REPO_ROOT / "config"
RESULTS = REPO_ROOT / "results"
FIGURES = REPO_ROOT / "figures"


def load_yaml(path: Path | str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)
