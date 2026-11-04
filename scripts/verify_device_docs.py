"""Verify config/devices/*.yaml against locally downloaded manufacturer documents.

For every document: recompute SHA-256 of the downloaded file and compare with the YAML.
For every quote: check it appears verbatim (whitespace-normalised) in the document's text rendering.
Writes data/devices/verification.json (no document text is stored in the repository).

Usage: python scripts/verify_device_docs.py DOCS_DIR
  DOCS_DIR holds the downloaded files named in FILES below plus their text renderings (*.txt,
  produced with `pdftotext -layout` for PDFs, and an HTML-to-text dump for HTML pages).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = {  # (device file, doc key) -> (downloaded file, text rendering)
    ("em400-udl", "main"): ("milesight/em400-udl-user-guide-en.pdf", "milesight/em400-udl-user-guide-en.txt"),
    ("em410-rdl", "main"): ("milesight/em410-rdl-lora-user-guide-en.pdf", "milesight/em410-rdl.txt"),
    ("ps-lb", "main"): ("dragino/ps-lb.html", "dragino/ps-lb.txt"),
    ("ps-lb", "general"): ("dragino/dragino-at-commands-downlink.html", "dragino/dragino-at-commands-downlink.txt"),
    ("lwl01", "main"): ("dragino/lwl01_manual_v1.3.1.pdf", "dragino/lwl01_manual_v1.3.1.txt"),
    ("lwl01", "at"): ("dragino/AT_Commands_LDS01_LWL01_v1.2.pdf", "dragino/AT_Commands_LDS01_LWL01_v1.2.txt"),
}


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.replace("­", "").replace("​", "")).strip()


def quotes(node, path=""):
    if isinstance(node, dict):
        if "quote" in node:
            yield path, node.get("doc", "main"), node["quote"]
        for k, v in node.items():
            yield from quotes(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from quotes(v, f"{path}[{i}]")


def verify(docs_dir: Path) -> dict:
    out = {"checked_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "devices": {}}
    for f in sorted((ROOT / "config/devices").glob("*.yaml")):
        dev, y = f.stem, yaml.safe_load(f.read_text())
        rep = {"docs": {}, "quotes": []}
        texts = {}
        for key, d in y["docs"].items():
            raw, txt = FILES[(dev, key)]
            h = hashlib.sha256((docs_dir / raw).read_bytes()).hexdigest()
            rep["docs"][key] = {"sha256_match": h == d["sha256"], "sha256": h}
            texts[key] = norm((docs_dir / txt).read_text(errors="replace"))
        for path, doc, q in quotes(y):
            frags = q if isinstance(q, list) else [q]  # table rows: list of verbatim fragments, all must occur
            rep["quotes"].append({"path": path, "doc": doc, "found": all(norm(x) in texts[doc] for x in frags)})
        out["devices"][dev] = rep
    return out


if __name__ == "__main__":
    r = verify(Path(sys.argv[1]))
    (ROOT / "data/devices").mkdir(parents=True, exist_ok=True)
    (ROOT / "data/devices/verification.json").write_text(json.dumps(r, indent=2))
    bad = [(d, q["path"]) for d, v in r["devices"].items() for q in v["quotes"] if not q["found"]]
    bad += [(d, k) for d, v in r["devices"].items() for k, x in v["docs"].items() if not x["sha256_match"]]
    print("all verified" if not bad else "\n".join(f"FAIL {d} {p}" for d, p in bad))
    sys.exit(1 if bad else 0)
