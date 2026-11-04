"""Capture the measurement environment into results/env.json."""

from __future__ import annotations

import datetime as dt
import json
import os
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path

from .oqs_loader import VENDOR, load_oqs


def _sh(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return f"unavailable ({exc.__class__.__name__})"


def cpu_info() -> dict:
    if sys.platform == "darwin":
        return {
            "model": _sh(["sysctl", "-n", "machdep.cpu.brand_string"]),
            "cores_logical": _sh(["sysctl", "-n", "hw.logicalcpu"]),
            "cores_physical": _sh(["sysctl", "-n", "hw.physicalcpu"]),
            "perf_levels": {
                lvl: {"name": _sh(["sysctl", "-n", f"hw.perflevel{lvl}.name"]),
                      "cores": _sh(["sysctl", "-n", f"hw.perflevel{lvl}.physicalcpu"])}
                for lvl in (0, 1)
            },
            "frequency_hz": _sh(["sysctl", "-n", "hw.cpufrequency"]) or "not exposed by macOS on Apple silicon",
            "frequency_governor": "not applicable: macOS has no cpufreq governor; DVFS is OS-managed",
            "arch": platform.machine(),
        }
    gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    model = next((ln.split(":", 1)[1].strip() for ln in Path("/proc/cpuinfo").read_text().splitlines()
                  if ln.startswith("model name")), platform.processor()) if Path("/proc/cpuinfo").exists() else platform.processor()
    return {
        "model": model,
        "cores_logical": os.cpu_count(),
        "frequency_governor": gov.read_text().strip() if gov.exists() else "unavailable",
        "frequency_khz_cur": _sh(["cat", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"]),
        "arch": platform.machine(),
    }


def capture(out: Path) -> dict:
    oqs = load_oqs()
    build_info_path = VENDOR / "liboqs-build-info.json"
    build = json.loads(build_info_path.read_text()) if build_info_path.exists() else {}
    pkgs = {p: metadata.version(p) for p in
            ("liboqs-python", "cryptography", "numpy", "pandas", "matplotlib", "PyYAML")}
    meta_note = (out.parent / "bench_meta.txt")
    from cryptography.hazmat.backends.openssl import backend as ossl  # noqa: PLC0415

    env = {
        "label": "HOST measurement (general-purpose CPU) - NOT a microcontroller measurement",
        "date_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "cpu": cpu_info(),
        "os": {"system": platform.system(), "release": platform.release(),
               "version": platform.version(), "platform": platform.platform()},
        "kernel": _sh(["uname", "-a"]),
        "python": {"version": sys.version, "implementation": platform.python_implementation()},
        "liboqs": {"version_runtime": oqs.oqs_version(), "liboqs_python": oqs.oqs_python_version(),
                   **build},
        "openssl_for_cryptography": ossl.openssl_version_text(),
        "python_packages": pkgs,
        "cpu_pinning": meta_note.read_text().strip() if meta_note.exists() else "bench not yet run",
    }
    out.write_text(json.dumps(env, indent=2))
    return env
