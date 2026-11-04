"""S6 envelope checking and S4 baseline checking as pure functions.

Wire formats (big-endian):
  crisis message = handle u32 | counter u32 | params[8] | tag[t]
  params         = action_id u8 | target u8 | value i32 | reserved u16 (must be 0)
  tag            = HMAC-SHA256(key, handle | counter | params)[:t]
  envelope bounds (64 B field) = rules, each: action_id u8 | target_bitmap u8 | lo i32 | hi i32 (10 B)

Device state is passed in and a new state is returned; nothing is mutated. The envelope's
PQ signature is verified once in the calm phase and is out of scope here (an `Envelope`
value is assumed already verified).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field

PARAMS = struct.Struct(">BBiH")
HEADER = struct.Struct(">II")
RULE = struct.Struct(">BBii")
BOUNDS_FIELD_BYTES = 64


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
class Envelope:
    handle: int
    rules: dict[int, Rule] = field(default_factory=dict)  # action_id -> rule


@dataclass(frozen=True)
class DeviceState:
    last_counter: int = 0


@dataclass(frozen=True)
class Decision:
    accepted: bool
    reason: str


# ---------------------------------------------------------------- config
def catalogue_from_config(cfg: dict) -> dict[int, Action]:
    return {a["id"]: Action(name, a["id"], a["targets"], a["min"], a["max"]) for name, a in cfg["catalogue"].items()}


def envelope_from_config(cfg: dict) -> Envelope:
    ids = {name: a["id"] for name, a in cfg["catalogue"].items()}
    rules = {ids[n]: Rule(ids[n], frozenset(r["targets"]), r["lo"], r["hi"]) for n, r in cfg["envelope"]["rules"].items()}
    return Envelope(int(cfg["envelope"]["handle"]), rules)


def encode_bounds(env: Envelope) -> bytes:
    """Serialise rules into the 64-byte envelope bounds field (zero-padded); raises if they do not fit."""
    if any(not 0 <= t <= 7 for r in env.rules.values() for t in r.targets):
        raise ValueError("target index must fit the 8-bit target bitmap")
    out = b"".join(RULE.pack(r.action_id, sum(1 << t for t in r.targets), r.lo, r.hi)
                   for r in sorted(env.rules.values(), key=lambda r: r.action_id))
    if len(out) > BOUNDS_FIELD_BYTES:
        raise ValueError(f"{len(env.rules)} rules need {len(out)} B > {BOUNDS_FIELD_BYTES} B bounds field")
    return out.ljust(BOUNDS_FIELD_BYTES, b"\0")


def decode_bounds(handle: int, blob: bytes) -> Envelope:
    rules = {}
    for i in range(0, len(blob) - RULE.size + 1, RULE.size):
        aid, bm, lo, hi = RULE.unpack_from(blob, i)
        if aid == 0:
            break
        rules[aid] = Rule(aid, frozenset(t for t in range(8) if bm >> t & 1), lo, hi)
    return Envelope(handle, rules)


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


def within_envelope(env: Envelope, action_id: int, target: int, value: int) -> bool:
    r = env.rules.get(action_id)
    return r is not None and target in r.targets and r.lo <= value <= r.hi


def check_s6(env: Envelope, catalogue: dict[int, Action], state: DeviceState, msg: bytes, key: bytes,
             tag_len: int) -> tuple[Decision, DeviceState]:
    parsed, bad = _authenticate(msg, key, tag_len, state)
    if bad:
        return bad, state
    handle, counter, (aid, target, value, reserved) = parsed
    if handle != env.handle:
        return Decision(False, "handle"), state
    if reserved != 0:
        return Decision(False, "reserved"), state
    if not in_catalogue(catalogue, aid, target, value):
        return Decision(False, "catalogue"), state
    if not within_envelope(env, aid, target, value):
        return Decision(False, "envelope"), state
    return Decision(True, "ok"), DeviceState(counter)


def check_s4(catalogue: dict[int, Action], state: DeviceState, msg: bytes, key: bytes,
             tag_len: int) -> tuple[Decision, DeviceState]:
    """S4 baseline: a valid MAC + fresh counter + syntactically valid command is accepted."""
    parsed, bad = _authenticate(msg, key, tag_len, state)
    if bad:
        return bad, state
    _, counter, (aid, target, value, reserved) = parsed
    if reserved != 0 or not in_catalogue(catalogue, aid, target, value):
        return Decision(False, "catalogue"), state
    return Decision(True, "ok"), DeviceState(counter)
