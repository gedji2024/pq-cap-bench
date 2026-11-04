"""Import liboqs-python against the liboqs built by scripts/build_liboqs.sh.

liboqs-python locates the shared library through OQS_INSTALL_PATH; without it,
it would try to download and build liboqs itself, which would make the
recorded commit meaningless. We therefore point it at ./vendor explicitly and
fail loudly if the build is missing.
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDOR = REPO_ROOT / "vendor"
INSTALL = VENDOR / "liboqs-install"


def load_oqs():
    if "OQS_INSTALL_PATH" not in os.environ:
        if not INSTALL.exists():
            raise RuntimeError(
                f"liboqs not built at {INSTALL}. Run `make liboqs` (scripts/build_liboqs.sh) first."
            )
        os.environ["OQS_INSTALL_PATH"] = str(INSTALL)
    import oqs  # noqa: PLC0415  (import after env is set)

    return oqs
