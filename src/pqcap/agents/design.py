"""E design: the episode list, fixed before any test run (PREREG). Deterministic from the config and seeds."""

from __future__ import annotations

import hashlib

from . import suite as S
from .runner import Spec


def _rank(seed: int, tag: str) -> str:
    return hashlib.sha256(f"{seed}|{tag}".encode()).hexdigest()


def pairs(scenario_ids: list[str], n_pairs: int, seed: int) -> list[tuple[str, str]]:
    """(user task, scenario) pairs hosting the episodes: user tasks cycle in order; scenarios are the first n_pairs
    of the scenario list ranked by SHA-256 of seed|id."""
    sc = sorted(scenario_ids, key=lambda s: _rank(seed, s))[:n_pairs]
    kinds = [c.KIND for c in S.USER_TASKS]
    return [(kinds[i % len(kinds)], sc[i]) for i in range(n_pairs)]


def static_specs(models: list[str], temps: dict, conditions: list[str], prompts: list[str], attacks: list,
                 host_pairs: list[tuple[str, str]], base_seed: int) -> list[Spec]:
    """temps: temperature -> repetitions. Each attack i is hosted by pair i mod len(host_pairs); every pair also
    runs benign (no attack). seed = base_seed + rep, the same for every condition (paired design)."""
    out = []
    for m in models:
        for t, reps in temps.items():
            for rep in range(reps):
                for c in conditions:
                    for pv in prompts:
                        for ut, sc in host_pairs:
                            out.append(Spec(m, t, base_seed + rep, rep, c, pv, sc, ut, None))
                        for i, a in enumerate(attacks):
                            ut, sc = host_pairs[i % len(host_pairs)]
                            out.append(Spec(m, t, base_seed + rep, rep, c, pv, sc, ut, a.id))
    return out
