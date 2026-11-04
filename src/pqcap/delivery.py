"""LoRaWAN Class A delivery accounting (pure functions)."""

from __future__ import annotations

import math


def time_to_deliver_s(frames: int, uplink_interval_s: float, rx_delay_s: float,
                      last_frame_toa_s: float) -> dict:
    """Class A: one downlink per uplink, so an F-frame command needs F uplinks.

    worst:    command issued just after an uplink -> F full intervals
    expected: issue time uniform over the interval  -> (F - 0.5) intervals
    Both add the RX window delay and the airtime of the last frame.
    """
    if frames < 1:
        raise ValueError("frames must be >= 1")
    tail = rx_delay_s + last_frame_toa_s
    return {"ttd_worst_s": frames * uplink_interval_s + tail,
            "ttd_expected_s": (frames - 0.5) * uplink_interval_s + tail}


def downlink_opportunities(window_s: float, uplink_interval_s: float) -> int:
    return int(window_s // uplink_interval_s)


def commands_per_device(window_s: float, uplink_interval_s: float, frames: int) -> int:
    """Commands one device can receive in the window (opportunity-limited)."""
    return downlink_opportunities(window_s, uplink_interval_s) // frames


def gateway_airtime_budget_s(window_s: float, duty: float | None) -> float:
    """Transmit time available to one gateway in the window. Without a duty-cycle
    limit the bound is 100 % utilisation of a single half-duplex downlink radio."""
    return window_s * (1.0 if duty is None else duty)


def commands_per_gateway(n_devices: int, window_s: float, uplink_interval_s: float,
                         frames: int, airtime_per_cmd_s: float, duty: float | None) -> dict:
    """Commands a gateway can deliver in the window to n_devices.

    min(device-opportunity limit, gateway airtime/duty-cycle limit).
    """
    dev = n_devices * commands_per_device(window_s, uplink_interval_s, frames)
    budget = gateway_airtime_budget_s(window_s, duty)
    air = math.floor(budget / airtime_per_cmd_s) if airtime_per_cmd_s > 0 else dev
    limit = "device_opportunities" if dev <= air else "gateway_airtime"
    return {"cmds_gateway": min(dev, air), "cmds_device_limit": dev,
            "cmds_airtime_limit": air, "binding_limit": limit}
