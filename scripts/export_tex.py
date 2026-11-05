"""Write every manuscript table as a booktabs LaTeX fragment in paper/tables/*.tex, straight from results/*.csv
and experiments/agents/results/*.csv (see pqcap.textables). Usage: uv run python scripts/export_tex.py"""

from __future__ import annotations

from pqcap.config import REPO_ROOT
from pqcap.textables import commit, export

if __name__ == "__main__":
    rev = commit(REPO_ROOT)
    w, s = export(REPO_ROOT / "results", REPO_ROOT / "experiments/agents/results", REPO_ROOT / "paper/tables", rev,
                  REPO_ROOT)
    print(f"results commit {rev}: wrote {len(w)} tables ({', '.join(w)})" + (f"; skipped (no source yet): {', '.join(s)}" if s else ""))
