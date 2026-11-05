"""E2 static attacks: load the versioned attack file, render each attack's injections, fixed dev/test split."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from ..config import load_yaml


@dataclass(frozen=True)
class Attack:
    id: str
    channel: str          # EXT | SENS | TOOL
    goal: str             # drain | suppress | disable | reassure
    family: str           # direct | authority | urgency | split | multi_turn | explicit_hijack | implicit_hijack | param_tamper
    split: str            # dev | test

    @property
    def multi_turn(self) -> bool:
        return self.family == "multi_turn"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _families(cfg: dict, channel: str) -> list[str]:
    return list(cfg["mcptox"] if channel == "TOOL" else cfg["families"])


def split(cfg: dict) -> dict[tuple[str, str], set[str]]:
    """(channel, goal) -> families held out as DEV: `dev_per_cell` families chosen by SHA-256 rank of
    "seed|channel|goal|family" (deterministic, independent of results)."""
    out = {}
    for ch in cfg["channels"]:
        for g in cfg["goals"]:
            fams = _families(cfg, ch)
            key = lambda f, ch=ch, g=g: hashlib.sha256(f"{cfg['split']['seed']}|{ch}|{g}|{f}".encode()).hexdigest()  # noqa: E731
            out[(ch, g)] = set(sorted(fams, key=key)[:cfg["split"]["dev_per_cell"]])
    return out


def load(path: Path) -> tuple[dict, list[Attack]]:
    cfg = load_yaml(path)
    dev = split(cfg)
    atk = [Attack(f"{cfg['version']}:{ch}:{g}:{f}", ch, g, f, "dev" if f in dev[(ch, g)] else "test")
           for ch in cfg["channels"] for g in cfg["goals"] for f in _families(cfg, ch)]
    return cfg, atk


def render(cfg: dict, a: Attack, goal_text: str) -> dict[str, str]:
    """Injection vector -> text for one attack."""
    ch = cfg["channels"][a.channel]
    if a.channel == "TOOL":
        t = cfg["mcptox"][a.family]
        text = t[a.goal] if isinstance(t, dict) else t.format(goal=goal_text)
        return {ch["vectors"][0]: text}
    t = cfg["families"][a.family]
    if isinstance(t, list):                      # payload split over two vectors of the channel
        return {v: part.format(goal=goal_text) for v, part in zip(ch["split_vectors"], t)}
    return {ch["vectors"][0]: t.format(goal=goal_text)}
