"""Time-on-air and fragmentation tests.

ToA oracles (published values, reproduced from the cited tables):
  [H17] Haxhibeqiri, Van den Abeele, Moerman, Hoebeke, "LoRa Scalability: A Simulation
        Model Based on Interference Measurements", Sensors 17(6):1193, 2017,
        doi:10.3390/s17061193, Table 1 (all PHY parameters stated).
  [Y20] Yasmin, Mikhaylov et al., "LoRaWAN for Smart Campus: Deployment and Long-Term
        Operation Analysis", Sensors 20(23):6721, 2020, doi:10.3390/s20236721, Table 2.
        Paper states 24-byte payload and CR 4/5 only; preamble 8, explicit header, CRC on
        and LDRO for SF11/12@125 kHz are inferred LoRaWAN defaults (see README).
Formula: Semtech SX1276/77/78/79 datasheet Rev. 7 (2020), Sec. 4.1.1.7, p. 31.
"""

import math

import pytest

from pqcap.radio import (
    Fragmentation,
    LoraPhy,
    duty_cycle_off_time_s,
    fragment,
    frames_airtime_s,
    payload_symbols,
    time_on_air_s,
)

H17 = [  # (sf, bw_hz, cr, preamble, ldro, pl, toa_ms)
    (12, 125e3, 4, 8, True, 17, 1712.13),
    (7, 125e3, 4, 14, False, 17, 76.03),
]
Y20 = [  # (sf, bw_hz, toa_ms) with PL=24, CR 4/5, preamble 8, explicit header, CRC on, auto LDRO
    (12, 125e3, 1482.75),
    (11, 125e3, 823.30),
    (10, 125e3, 370.69),
    (9, 125e3, 205.82),
    (8, 125e3, 113.15),
    (7, 125e3, 61.70),
    (7, 250e3, 30.85),
]


@pytest.mark.parametrize("sf,bw,cr,pre,ldro,pl,ms", H17)
def test_toa_haxhibeqiri2017(sf, bw, cr, pre, ldro, pl, ms):
    phy = LoraPhy(sf=sf, bw_hz=bw, cr=cr, preamble=pre, explicit_header=True, crc_on=True, ldro=ldro)
    assert time_on_air_s(pl, phy) * 1e3 == pytest.approx(ms, abs=0.01)


@pytest.mark.parametrize("sf,bw,ms", Y20)
def test_toa_yasmin2020(sf, bw, ms):
    phy = LoraPhy(sf=sf, bw_hz=bw, cr=1, preamble=8)
    assert time_on_air_s(24, phy) * 1e3 == pytest.approx(ms, abs=0.01)


def test_haxhibeqiri_symbol_and_preamble_times():
    phy = LoraPhy(sf=12, bw_hz=125e3, cr=4, preamble=8, ldro=True)
    assert phy.t_sym_s * 1e3 == pytest.approx(32.77, abs=0.01)
    assert (8 + 4.25) * phy.t_sym_s * 1e3 == pytest.approx(401.41, abs=0.01)


def test_auto_ldro_threshold():
    assert LoraPhy(sf=12, bw_hz=125e3).de == 1     # 32.8 ms
    assert LoraPhy(sf=11, bw_hz=125e3).de == 1     # 16.4 ms
    assert LoraPhy(sf=10, bw_hz=125e3).de == 0     # 8.2 ms
    assert LoraPhy(sf=12, bw_hz=500e3).de == 0     # 8.2 ms (US915 DR8)
    assert LoraPhy(sf=12, bw_hz=125e3, ldro=False).de == 0


def test_crc_and_header_effects_monotone():
    base = LoraPhy(sf=9, bw_hz=125e3)
    no_crc = LoraPhy(sf=9, bw_hz=125e3, crc_on=False)
    implicit = LoraPhy(sf=9, bw_hz=125e3, explicit_header=False)
    for pl in (10, 50, 120):
        assert payload_symbols(pl, no_crc) <= payload_symbols(pl, base)
        assert payload_symbols(pl, implicit) <= payload_symbols(pl, base)


def test_toa_monotone_in_payload_and_sf():
    for sf in range(7, 13):
        phy = LoraPhy(sf=sf, bw_hz=125e3)
        t = [time_on_air_s(pl, phy) for pl in range(0, 256)]
        assert all(b >= a for a, b in zip(t, t[1:]))
    t_sf = [time_on_air_s(50, LoraPhy(sf=sf, bw_hz=125e3)) for sf in range(7, 13)]
    assert all(b > a for a, b in zip(t_sf, t_sf[1:]))


def test_toa_bandwidth_scaling():
    a = time_on_air_s(40, LoraPhy(sf=9, bw_hz=125e3))
    b = time_on_air_s(40, LoraPhy(sf=9, bw_hz=500e3))
    assert a / b == pytest.approx(4.0)


def test_payload_symbols_floor_at_8():
    # SF12 implicit header, no CRC, zero payload: numerator negative -> 8 symbols
    assert payload_symbols(0, LoraPhy(sf=12, bw_hz=125e3, explicit_header=False, crc_on=False)) == 8


@pytest.mark.parametrize("kw", [{"sf": 5}, {"sf": 13}, {"cr": 0}, {"cr": 5}, {"bw_hz": 0}])
def test_phy_validation(kw):
    args = {"sf": 7, "bw_hz": 125e3, **kw}
    with pytest.raises(ValueError):
        LoraPhy(**args)


@pytest.mark.parametrize("pl", [-1, 256])
def test_payload_range(pl):
    with pytest.raises(ValueError):
        payload_symbols(pl, LoraPhy(sf=7, bw_hz=125e3))


# ---------------------------------------------------------------- fragmentation
def test_fragment_single_frame_no_header():
    assert fragment(53, 53, 2) == Fragmentation(1, (53,))
    assert fragment(0, 53, 2) == Fragmentation(1, (0,))


def test_fragment_multi_frame_counts_and_conservation():
    f = fragment(54, 53, 2)            # 51 data bytes per frame
    assert f.frames == 2
    assert f.app_payloads == (53, 5)   # 51+2, 3+2
    for n, cap, h in [(2500, 53, 2), (2500, 242, 2), (17168, 51, 3), (1000, 129, 0)]:
        f = fragment(n, cap, h)
        assert f.frames == math.ceil(n / (cap - h))
        assert sum(f.app_payloads) == n + h * f.frames
        assert max(f.app_payloads) <= cap


def test_fragment_errors():
    with pytest.raises(ValueError):
        fragment(-1, 53, 2)
    with pytest.raises(ValueError):
        fragment(100, 2, 2)


def test_frames_airtime_sums_per_frame_toa():
    phy = LoraPhy(sf=12, bw_hz=500e3)
    f = fragment(200, 53, 2)
    assert frames_airtime_s(f, phy, 13) == pytest.approx(sum(time_on_air_s(p + 13, phy) for p in f.app_payloads))


def test_duty_cycle_off_time():
    assert duty_cycle_off_time_s(1.0, 0.01) == pytest.approx(99.0)
    assert duty_cycle_off_time_s(2.0, 0.10) == pytest.approx(18.0)
    assert duty_cycle_off_time_s(1.0, 1.0) == 0.0
    assert duty_cycle_off_time_s(1.0, None) == 0.0
    with pytest.raises(ValueError):
        duty_cycle_off_time_s(1.0, 0.0)
