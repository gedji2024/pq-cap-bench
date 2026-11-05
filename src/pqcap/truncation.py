"""F7: computational note on truncated-HMAC crisis commands (Étape 2 H4, T9).

Assumption: HMAC-SHA256 is a PRF; the tag is its first t bits. A forger who never saw a valid tag for the target
message succeeds per attempt with probability 2^-t (the PRF distinguishing advantage is ignored here, i.e. this is
the ideal-PRF bound). A failed attempt does not advance the device counter (the device accepts any ctr > ctr_D),
so attempts are limited by the radio, not by the counter: q attempts succeed with probability <= q * 2^-t
(union bound). Two radio-limited attacker budgets are evaluated:
  - per device: one Class A downlink opportunity per uplink, i.e. 3600 / U attempts per hour;
  - counter window: one attempt for every counter value of the c-byte counter field (2^(8c) attempts), the most a
    device can ever process before its counter wraps (a key/epoch change is required at wrap).
"""

from __future__ import annotations

import math

import pandas as pd

HOURS_PER_YEAR = 24 * 365


def forgery_bound(tag_bytes: int, attempts: float) -> float:
    """Union bound q * 2^-t, capped at 1."""
    return min(1.0, attempts * 2.0 ** (-8 * tag_bytes))


def table(tag_bytes: list[int], counter_bytes: int, uplink_interval_s: float, devices: list[int]) -> pd.DataFrame:
    per_h = 3600 / uplink_interval_s
    rows = []
    for t in tag_bytes:
        rows.append({"tag_bytes": t, "budget": "one attempt", "attempts": 1.0, "p_forge": forgery_bound(t, 1),
                     "log2_p": -8 * t})
        for n in devices:
            q = n * per_h * HOURS_PER_YEAR
            p = forgery_bound(t, q)
            rows.append({"tag_bytes": t, "budget": f"every Class A slot of {n} devices for 1 year", "attempts": q,
                         "p_forge": p, "log2_p": math.log2(p)})
        q = 2.0 ** (8 * counter_bytes)
        p = forgery_bound(t, q)
        rows.append({"tag_bytes": t, "budget": f"whole {counter_bytes}-byte counter window, one device", "attempts": q,
                     "p_forge": p, "log2_p": math.log2(p)})
    return pd.DataFrame(rows)
