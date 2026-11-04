"""Device-side command checking for S4, S4-F, S4-E and S6, as pure functions.

Wire formats (big-endian):
  crisis message = handle u32 | counter u32 | params[8] | tag[t]
  params         = action_id u8 | target u8 | value i32 | reserved u16 (must be 0)
  tag            = HMAC-SHA256(session key, handle | counter | params)[:t]
  envelope (112 B, S6 / S4-E):
    header[16]     = handle u32 | not_before u32 | not_after u32 | version u8 | alg u8 | reserved u16
    bounds[64]     = rules, each action_id u8 | target_bitmap u8 | lo i32 | hi i32 (10 B), zero-padded
    invariants[32] = alert_max_interval u16 | flags u8 | battery_floor_pct u8 | low_batt_min_interval u16 | 0-pad
  S6 envelope authenticator   = PQ signature over the 112 B (verified with a public key)
  S4-E envelope authenticator = HMAC-SHA256(per-device policy key, 112 B)

Device state is passed in and a new state is returned; nothing is mutated.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field, replace

PARAMS = struct.Struct(">BBiH")
HEADER = struct.Struct(">II")
RULE = struct.Struct(">BBii")
ENV_HEADER = struct.Struct(">IIIBBH")
INVARIANTS = struct.Struct(">HBBH")
BOUNDS_FIELD_BYTES = 64
INVARIANTS_FIELD_BYTES = 32
ENVELOPE_BYTES = ENV_HEADER.size + BOUNDS_FIELD_BYTES + INVARIANTS_FIELD_BYTES  # 112

F_ALERT_FORBID_DISABLE = 1
F_LOW_BATT_BLOCK_IMMEDIATE = 2

A_INTERVAL, A_IMMEDIATE, A_ENABLE, A_THRESHOLD = 1, 2, 3, 4


@dataclass(frozen=True)
class Action:
    name: str
    id: int
    targets: int
    min: int
    max: int


@dataclass(frozen=True)
class Rule:
    action_id: int
    targets: frozenset[int]
    lo: int
    hi: int


@dataclass(frozen=True)
class Invariants:
    alert_max_interval: int = 0          # 0 = no constraint
    alert_forbid_disable: bool = False
    battery_floor_pct: int = 0           # 0 = no floor
    low_batt_min_interval: int = 0
    low_batt_block_immediate: bool = False


NO_INVARIANTS = Invariants()


@dataclass(frozen=True)
class Policy:
    """Bounds + invariants + validity. Used for S6/S4-E envelopes and S4-F firmware bounds."""

    handle: int
    rules: dict[int, Rule] = field(default_factory=dict)  # action_id -> rule
    invariants: Invariants = NO_INVARIANTS
    not_before: int = 0
    not_after: int = 2**32 - 1


Envelope = Policy  # an S6 / S4-E envelope is a Policy delivered over the air


@dataclass(frozen=True)
class DeviceState:
    last_counter: int = 0
    alert_active: bool = False
    soc_pct: float = 100.0
    now: int = 0                          # seconds, same clock as envelope validity
    revoked: frozenset[int] = frozenset()  # S6-R: handles revoked by a revealed r_rev


@dataclass(frozen=True)
class Decision:
    accepted: bool
    reason: str


# ---------------------------------------------------------------- config
def catalogue_from_config(cfg: dict) -> dict[int, Action]:
    return {a["id"]: Action(name, a["id"], a["targets"], a["min"], a["max"]) for name, a in cfg["catalogue"].items()}


def invariants_from_config(cfg: dict) -> Invariants:
    i = cfg.get("invariants") or {}
    return Invariants(i.get("alert_max_interval_min", 0), bool(i.get("alert_forbid_disable", False)),
                      i.get("battery_floor_soc_pct", 0), i.get("low_battery_min_interval_min", 0),
                      bool(i.get("low_battery_block_immediate_uplink", False)))


def _rules(cfg: dict, section: dict) -> dict[int, Rule]:
    ids = {name: a["id"] for name, a in cfg["catalogue"].items()}
    return {ids[n]: Rule(ids[n], frozenset(r["targets"]), r["lo"], r["hi"]) for n, r in section["rules"].items()}


def envelope_from_config(cfg: dict, not_before: int = 0, not_after: int = 2**32 - 1) -> Policy:
    return Policy(int(cfg["envelope"]["handle"]), _rules(cfg, cfg["envelope"]), invariants_from_config(cfg),
                  not_before, not_after)


def firmware_policy_from_config(cfg: dict) -> Policy:
    return Policy(0, _rules(cfg, cfg["firmware_bounds"]), invariants_from_config(cfg))


def permissive_policy(catalogue: dict[int, Action], handle: int = 0) -> Policy:
    """What an attacker able to mint envelopes would issue: whole catalogue, no invariants."""
    return Policy(handle, {a.id: Rule(a.id, frozenset(range(a.targets)), a.min, a.max) for a in catalogue.values()})


# ---------------------------------------------------------------- envelope encoding
def encode_bounds(env: Policy) -> bytes:
    """Serialise rules into the 64-byte envelope bounds field (zero-padded); raises if they do not fit."""
    if any(not 0 <= t <= 7 for r in env.rules.values() for t in r.targets):
        raise ValueError("target index must fit the 8-bit target bitmap")
    out = b"".join(RULE.pack(r.action_id, sum(1 << t for t in r.targets), r.lo, r.hi)
                   for r in sorted(env.rules.values(), key=lambda r: r.action_id))
    if len(out) > BOUNDS_FIELD_BYTES:
        raise ValueError(f"{len(env.rules)} rules need {len(out)} B > {BOUNDS_FIELD_BYTES} B bounds field")
    return out.ljust(BOUNDS_FIELD_BYTES, b"\0")


def decode_bounds(handle: int, blob: bytes) -> Policy:
    rules = {}
    for i in range(0, len(blob) - RULE.size + 1, RULE.size):
        aid, bm, lo, hi = RULE.unpack_from(blob, i)
        if aid == 0:
            break
        rules[aid] = Rule(aid, frozenset(t for t in range(8) if bm >> t & 1), lo, hi)
    return Policy(handle, rules)


def encode_invariants(inv: Invariants) -> bytes:
    flags = (F_ALERT_FORBID_DISABLE if inv.alert_forbid_disable else 0) | \
            (F_LOW_BATT_BLOCK_IMMEDIATE if inv.low_batt_block_immediate else 0)
    return INVARIANTS.pack(inv.alert_max_interval, flags, inv.battery_floor_pct,
                           inv.low_batt_min_interval).ljust(INVARIANTS_FIELD_BYTES, b"\0")


def decode_invariants(b: bytes) -> Invariants:
    amax, flags, floor, lmin = INVARIANTS.unpack_from(b)
    return Invariants(amax, bool(flags & F_ALERT_FORBID_DISABLE), floor, lmin, bool(flags & F_LOW_BATT_BLOCK_IMMEDIATE))


def encode_envelope(env: Policy, version: int = 1, alg: int = 0) -> bytes:
    return (ENV_HEADER.pack(env.handle, env.not_before, env.not_after, version, alg, 0)
            + encode_bounds(env) + encode_invariants(env.invariants))


def decode_envelope(b: bytes) -> Policy:
    if len(b) != ENVELOPE_BYTES:
        raise ValueError(f"envelope must be {ENVELOPE_BYTES} B")
    handle, nb, na, _, _, _ = ENV_HEADER.unpack_from(b)
    p = decode_bounds(handle, b[ENV_HEADER.size:ENV_HEADER.size + BOUNDS_FIELD_BYTES])
    inv = decode_invariants(b[ENV_HEADER.size + BOUNDS_FIELD_BYTES:])
    return replace(p, invariants=inv, not_before=nb, not_after=na)


# ---------------------------------------------------------------- messages
def encode_params(action_id: int, target: int, value: int) -> bytes:
    return PARAMS.pack(action_id, target, value, 0)


def decode_params(b: bytes) -> tuple[int, int, int, int]:
    return PARAMS.unpack(b)


def tag(key: bytes, body: bytes, tag_len: int) -> bytes:
    return hmac.new(key, body, hashlib.sha256).digest()[:tag_len]


def make_command(key: bytes, handle: int, counter: int, action_id: int, target: int, value: int,
                 tag_len: int) -> bytes:
    body = HEADER.pack(handle, counter) + encode_params(action_id, target, value)
    return body + tag(key, body, tag_len)


def _authenticate(msg: bytes, key: bytes, tag_len: int, state: DeviceState):
    body_len = HEADER.size + PARAMS.size
    if len(msg) != body_len + tag_len:
        return None, Decision(False, "length")
    body, t = msg[:body_len], msg[body_len:]
    if not hmac.compare_digest(tag(key, body, tag_len), t):
        return None, Decision(False, "tag")
    handle, counter = HEADER.unpack_from(body)
    if counter <= state.last_counter:
        return None, Decision(False, "replay")
    return (handle, counter, decode_params(body[HEADER.size:])), None


def in_catalogue(catalogue: dict[int, Action], action_id: int, target: int, value: int) -> bool:
    a = catalogue.get(action_id)
    return a is not None and 0 <= target < a.targets and a.min <= value <= a.max


def within_bounds(p: Policy, action_id: int, target: int, value: int) -> bool:
    r = p.rules.get(action_id)
    return r is not None and target in r.targets and r.lo <= value <= r.hi


def invariant_violation(inv: Invariants, state: DeviceState, action_id: int, value: int) -> str | None:
    """Name of the physical invariant the command would violate in this state, or None."""
    low = inv.battery_floor_pct > 0 and state.soc_pct < inv.battery_floor_pct
    if action_id == A_INTERVAL:
        if state.alert_active and inv.alert_max_interval and value > inv.alert_max_interval:
            return "invariant:alert_min_rate"
        if low and value < inv.low_batt_min_interval:
            return "invariant:battery_floor"
    if action_id == A_IMMEDIATE and low and inv.low_batt_block_immediate:
        return "invariant:battery_floor"
    if action_id == A_ENABLE and value == 0 and state.alert_active and inv.alert_forbid_disable:
        return "invariant:alert_min_rate"
    return None


def _check_policy(p: Policy, catalogue, state, aid, target, value, reserved, counter):
    if reserved != 0 or not in_catalogue(catalogue, aid, target, value):
        return Decision(False, "catalogue"), state
    if not p.not_before <= state.now <= p.not_after:
        return Decision(False, "expired"), state
    if not within_bounds(p, aid, target, value):
        return Decision(False, "bounds"), state
    v = invariant_violation(p.invariants, state, aid, value)
    if v:
        return Decision(False, v), state
    return Decision(True, "ok"), replace(state, last_counter=counter)


def check_s4(catalogue: dict[int, Action], state: DeviceState, msg: bytes, key: bytes,
             tag_len: int) -> tuple[Decision, DeviceState]:
    """S4: a valid MAC + fresh counter + syntactically valid command is accepted. No bounds, no invariants."""
    parsed, bad = _authenticate(msg, key, tag_len, state)
    if bad:
        return bad, state
    _, counter, (aid, target, value, reserved) = parsed
    if reserved != 0 or not in_catalogue(catalogue, aid, target, value):
        return Decision(False, "catalogue"), state
    return Decision(True, "ok"), replace(state, last_counter=counter)


def check_s4f(firmware: Policy, catalogue, state, msg, key, tag_len):
    """S4-F: per-command HMAC, checked against static bounds + invariants compiled into firmware."""
    parsed, bad = _authenticate(msg, key, tag_len, state)
    if bad:
        return bad, state
    _, counter, (aid, target, value, reserved) = parsed
    return _check_policy(firmware, catalogue, state, aid, target, value, reserved, counter)


def check_enveloped(env: Policy, catalogue, state, msg, key, tag_len):
    """S6 and S4-E crisis commands (identical once the envelope is installed): per-command HMAC,
    envelope handle, validity window, bounds and invariants."""
    parsed, bad = _authenticate(msg, key, tag_len, state)
    if bad:
        return bad, state
    handle, counter, (aid, target, value, reserved) = parsed
    if handle != env.handle:
        return Decision(False, "handle"), state
    if handle in state.revoked:
        return Decision(False, "revoked"), state
    return _check_policy(env, catalogue, state, aid, target, value, reserved, counter)


check_s6 = check_enveloped
check_s4e = check_enveloped


# ---------------------------------------------------------------- S6-R: revocation committed in advance (D1)
REV_COMMIT_BYTES = 32  # SHA-256 output
REVOCATION = struct.Struct(">I")


def rev_commitment(r_rev: bytes) -> bytes:
    """H(r_rev), carried inside the PQ-signed S6-R envelope."""
    return hashlib.sha256(r_rev).digest()


def make_revocation(handle: int, r_rev: bytes) -> bytes:
    """Single-frame revocation message: handle u32 | r_rev (16 or 32 B). Needs no signature: only the
    PA knows a preimage of the commitment signed into the envelope."""
    if len(r_rev) not in (16, 32):
        raise ValueError("r_rev must be 16 or 32 bytes")
    return REVOCATION.pack(handle) + r_rev


def apply_revocation(commitments: dict[int, bytes], state: DeviceState, msg: bytes) -> tuple[Decision, DeviceState]:
    """commitments: handle -> H(r_rev) of each installed S6-R envelope."""
    if len(msg) not in (REVOCATION.size + 16, REVOCATION.size + 32):
        return Decision(False, "length"), state
    (handle,) = REVOCATION.unpack_from(msg)
    c = commitments.get(handle)
    if c is None or not hmac.compare_digest(rev_commitment(msg[REVOCATION.size:]), c):
        return Decision(False, "bad_reveal"), state
    return Decision(True, "revoked"), replace(state, revoked=state.revoked | {handle})


# ---------------------------------------------------------------- envelope installation
def validity_ok(env: Policy, max_validity_s: int | None) -> bool:
    """Firmware cap: an envelope may not be valid for longer than max_validity_s (None = no cap).
    This bounds the exposure window of any envelope, including one minted by an attacker."""
    return env.not_before <= env.not_after and (max_validity_s is None
                                                or env.not_after - env.not_before <= max_validity_s)


def install_envelope_s4e(blob: bytes, mac: bytes, policy_key: bytes, max_validity_s: int | None = None) -> Policy | None:
    """S4-E: the device holds the per-device policy key, so it (and anyone holding it) could also forge."""
    if not hmac.compare_digest(hmac.new(policy_key, blob, hashlib.sha256).digest(), mac):
        return None
    env = decode_envelope(blob)
    return env if validity_ok(env, max_validity_s) else None


def install_envelope_s6(blob: bytes, sig: bytes, verify, max_validity_s: int | None = None) -> Policy | None:
    """S6: `verify(blob, sig) -> bool` uses only the policy authority's PUBLIC key (e.g. ML-DSA-44)."""
    if not verify(blob, sig):
        return None
    env = decode_envelope(blob)
    return env if validity_ok(env, max_validity_s) else None
