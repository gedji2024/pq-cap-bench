"""LoRa PHY time-on-air, LoRaWAN fragmentation, duty-cycle accounting."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class LoraPhy:
    sf: int
    bw_hz: float
    cr: int = 1                 # 1 => 4/5 ... 4 => 4/8
    preamble: int = 8
    explicit_header: bool = True
    crc_on: bool = True
    ldro: bool | None = None    # None => automatic (T_sym > ldro_threshold_ms)
    ldro_threshold_ms: float = 16.0

    def __post_init__(self):
        if not 6 <= self.sf <= 12:
            raise ValueError(f"SF must be 6..12, got {self.sf}")
        if self.cr not in (1, 2, 3, 4):
            raise ValueError(f"CR index must be 1..4, got {self.cr}")
        if self.bw_hz <= 0:
            raise ValueError("bandwidth must be positive")

    @property
    def t_sym_s(self) -> float:
        return (2 ** self.sf) / self.bw_hz

    @property
    def de(self) -> int:
        if self.ldro is not None:
            return int(self.ldro)
        return int(self.t_sym_s * 1e3 > self.ldro_threshold_ms)


def payload_symbols(pl: int, phy: LoraPhy) -> int:
    """n_payload per Semtech SX1276 datasheet Rev.7 Sec. 4.1.1.7 (p. 31)."""
    if not 0 <= pl <= 255:
        raise ValueError(f"PHY payload must be 0..255 bytes, got {pl}")
    ih = 0 if phy.explicit_header else 1
    crc = 1 if phy.crc_on else 0
    num = 8 * pl - 4 * phy.sf + 28 + 16 * crc - 20 * ih
    den = 4 * (phy.sf - 2 * phy.de)
    return 8 + max(math.ceil(num / den) * (phy.cr + 4), 0)


def time_on_air_s(pl: int, phy: LoraPhy) -> float:
    t_pre = (phy.preamble + 4.25) * phy.t_sym_s
    return t_pre + payload_symbols(pl, phy) * phy.t_sym_s


@dataclass(frozen=True)
class Fragmentation:
    frames: int
    app_payloads: tuple[int, ...]   # FRMPayload bytes per frame (incl. fragment header)


def fragment(message_bytes: int, max_app_payload: int, frag_header: int) -> Fragmentation:
    """Split a message over LoRaWAN downlinks.

    A message that fits in one FRMPayload is sent unfragmented (no fragment header).
    Otherwise every frame carries `frag_header` bytes plus up to (N - frag_header) data bytes.
    """
    if message_bytes < 0:
        raise ValueError("message size must be >= 0")
    if message_bytes <= max_app_payload:
        return Fragmentation(1, (message_bytes,))
    per = max_app_payload - frag_header
    if per <= 0:
        raise ValueError("fragment header leaves no room for data")
    n = math.ceil(message_bytes / per)
    sizes = [per + frag_header] * (n - 1) + [message_bytes - per * (n - 1) + frag_header]
    return Fragmentation(n, tuple(sizes))


def frames_airtime_s(frag: Fragmentation, phy: LoraPhy, phy_overhead: int) -> float:
    return sum(time_on_air_s(app + phy_overhead, phy) for app in frag.app_payloads)


def duty_cycle_off_time_s(airtime_s: float, duty: float | None) -> float:
    """Mandatory silence after transmitting `airtime_s` under duty cycle `duty` (0<d<=1)."""
    if duty is None:
        return 0.0
    if not 0 < duty <= 1:
        raise ValueError("duty cycle must be in (0, 1]")
    return airtime_s * (1.0 / duty - 1.0)
