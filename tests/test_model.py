"""Token sizing, Class A delivery, scheme accounting, kill criteria.

Signature/KEM sizes below are TEST FIXTURES only (round, obviously synthetic numbers);
real outputs always read results/sizes.csv produced by `make bench`.
"""

import json

import pandas as pd
import pytest

from pqcap import delivery as dl
from pqcap import kill
from pqcap import model as M
from pqcap.config import CONFIG, load_yaml
from pqcap.radio import fragment
from pqcap.token import TokenModel, epoch_message_bytes

FIX_SIG = {"PQ-A": 1000, "PQ-B": 30, "HMAC-SHA256-T16": 16, "HMAC-SHA256-T32": 32, "ECDSA-P256": 64,
           "HYB": 1064}
FIX_KEM = {"KEM-X": 500}


@pytest.fixture
def cfgs():
    token = load_yaml(CONFIG / "token.yaml")
    radio = load_yaml(CONFIG / "radio.yaml")
    model = load_yaml(CONFIG / "model.yaml")
    model.update(s1_algorithms=["PQ-A", "PQ-B", "MISSING"], s2_cert_signer="PQ-A", s2_kem=["KEM-X", "NOPE"],
                 hybrid_label="HYB")
    model["kill_criteria"]["K1"]["algorithm"] = "PQ-A"
    model["s6"] = {**model["s6"], "signers": ["PQ-A"], "compare": [["S1", "PQ-A"], ["S4", "HMAC-SHA256-T16"]]}
    return token, radio, model


# ---------------------------------------------------------------- token
def test_token_defaults_match_brief():
    tm = TokenModel.from_config(load_yaml(CONFIG / "token.yaml"))
    assert (tm.header, tm.constraints, tm.hop_constraints, tm.hop_key_id) == (16, 64, 32, 8)


@pytest.mark.parametrize("d", [0, 1, 2, 3])
def test_token_size_formula(d):
    tm = TokenModel(16, 64, 32, 8)
    assert tm.size(100, d) == 80 + 100 + d * (32 + 8 + 100)
    assert tm.auth_overhead(100, d) == tm.size(100, d) - 80


def test_token_validation():
    tm = TokenModel(16, 64, 32, 8)
    with pytest.raises(ValueError):
        tm.size(10, -1)
    with pytest.raises(ValueError):
        tm.size(-1, 0)


def test_epoch_message_bytes():
    assert epoch_message_bytes({"a": 10, "b": 6}, 100, 50) == 166


# ---------------------------------------------------------------- delivery
def test_ttd():
    t = dl.time_to_deliver_s(3, 300, 1.0, 0.5)
    assert t["ttd_worst_s"] == pytest.approx(901.5)
    assert t["ttd_expected_s"] == pytest.approx(751.5)
    with pytest.raises(ValueError):
        dl.time_to_deliver_s(0, 300, 1, 0)


def test_commands_per_device_and_gateway():
    assert dl.downlink_opportunities(1800, 300) == 6
    assert dl.commands_per_device(1800, 300, 2) == 3
    assert dl.commands_per_device(1800, 300, 7) == 0
    g = dl.commands_per_gateway(10, 1800, 300, 2, 1.0, None)       # device-limited
    assert g == {"cmds_gateway": 30, "cmds_device_limit": 30, "cmds_airtime_limit": 1800,
                 "binding_limit": "device_opportunities"}
    g = dl.commands_per_gateway(10, 1800, 300, 2, 1.0, 0.01)       # duty-cycle-limited: 18 s budget
    assert g["cmds_gateway"] == 18 and g["binding_limit"] == "gateway_airtime"
    assert dl.commands_per_gateway(1, 600, 300, 1, 0.0, None)["cmds_gateway"] == 2
    assert dl.gateway_airtime_budget_s(3600, 0.01) == pytest.approx(36.0)


# ---------------------------------------------------------------- radio config sanity
def test_radio_tables_consistent():
    radio = load_yaml(CONFIG / "radio.yaml")
    for region in radio["regions"].values():
        for d in region["downlink_drs"].values():
            for v in ("rep", "norep"):
                assert d[v]["M"] - d[v]["N"] == 8          # FHDR(7) + FPort(1), RP002 tables
            assert d["rep"]["N"] <= d["norep"]["N"]


def test_channels(cfgs):
    _, radio, model = cfgs
    ch = M.channels(radio, model)
    us = {c.dr: c for c in ch if c.region == "US915"}
    eu = {c.dr: c for c in ch if c.region == "EU868"}
    assert sorted(us) == [8, 9, 10, 11, 12, 13] and sorted(eu) == list(range(7))
    assert us[8].max_app == 53 and us[8].duty is None and us[8].phy.sf == 12 and us[8].phy.bw_hz == 500e3
    assert eu[0].duty == model["eu868_duty_cycle"] and eu[5].max_app == 242
    assert ch[-1].region == "NB-IoT" and ch[-1].phy is None
    assert us[8].mac.phy_payload(53) == 66 and ch[-1].mac is None
    radio2 = {**radio, "lorawan_overhead": {**radio["lorawan_overhead"], "fopts_bytes": 5}}
    assert {c.dr: c for c in M.channels(radio2, model) if c.region == "US915"}[8].max_app == 48
    radio["payload_table_variant"] = "repeater_compatible"
    assert {c.dr: c for c in M.channels(radio, model) if c.region == "EU868"}[5].max_app == 222


# ---------------------------------------------------------------- scheme accounting
def test_scheme_rows(cfgs):
    _, _, model = cfgs
    rows = M.scheme_rows(model, FIX_SIG)
    by = {(r["scheme"], r["algorithm"]): r["auth_bytes"] for r in rows}
    assert by[("S1", "PQ-A")] == 1000 and by[("S1", "PQ-B")] == 30
    assert ("S1", "MISSING") not in by                       # unavailable -> skipped, not substituted
    assert by[("S4", "HMAC-SHA256-T16")] == 16
    assert by[("S2", "PQ-A+KEM/HMAC-SHA256-T16")] == 16
    assert by[("S3", "HYB")] == 1064 and by[("S5", "ECDSA-P256")] == 64


def test_build_outputs(cfgs):
    token, radio, model = cfgs
    out = M.build(token, radio, model, FIX_SIG, FIX_KEM)
    t, d, c, a = (out[k] for k in ("model_tokens", "model_delivery", "model_capacity", "model_s2_amortization"))
    s1a0 = t[(t.scheme == "S1") & (t.algorithm == "PQ-A") & (t.depth == 0)].iloc[0]
    assert s1a0.token_bytes == 1080
    row = d[(d.scheme == "S1") & (d.algorithm == "PQ-A") & (d.depth == 0) & (d.region == "US915") & (d.dr == 8)].iloc[0]
    assert row.frames == fragment(1080, 53, 2).frames == 22
    assert row.ttd_worst_s == pytest.approx(22 * 300 + 1.0 + row.last_frame_toa_s)
    assert row.duty_off_time_s == 0
    eu = d[(d.scheme == "S4") & (d.depth == 0) & (d.region == "EU868") & (d.dr == 0)].iloc[0]
    assert eu.frames == 2 and eu.duty_off_time_s == pytest.approx(eu.airtime_s * 99)
    nb = d[(d.scheme == "S1") & (d.algorithm == "PQ-A") & (d.depth == 3) & (d.region == "NB-IoT")].iloc[0]
    assert nb.frames == fragment(80 + 1000 + 3 * 1040, 1280, 2).frames
    assert len(c) == len(d[d.region != "NB-IoT"]) * 4 * 3
    # S2 amortisation: ratio decreases with commands per epoch, bytes ratio exact
    s = a[(a.region == "US915") & (a.dr == 8) & (a.epoch_hours == 24)].sort_values("cmds_per_epoch")
    assert s.ratio_airtime_s2_s4.is_monotonic_decreasing
    ep = sum(model["s2_epoch_cert_fields"].values()) + 1000 + 500
    r1 = s[s.cmds_per_epoch == 1].iloc[0]
    assert r1.epoch_bytes == ep and r1.ratio_bytes_s2_s4 == pytest.approx((96 + ep) / 96)
    assert s.is_class_a_max.sum() == 1
    # 1 h epoch at EU868 DR0: epoch message needs more frames than the 12 downlink opportunities
    inf = a[(a.region == "EU868") & (a.dr == 0) & (a.epoch_hours == 1)]
    assert len(inf) == 1 and not inf.iloc[0].feasible and inf.iloc[0].epoch_frames > 12
    assert set(a.kem) == {"KEM-X"}                           # unavailable KEM skipped


def test_downlink_crc_follows_rp002(cfgs):
    _, radio, model = cfgs
    assert radio["phy"]["crc_on_downlink"] is False and radio["phy"]["crc_on_uplink"] is True
    assert all(c.phy.crc_on is False for c in M.channels(radio, model) if c.phy is not None)


def test_crc_sensitivity_frames_invariant(cfgs):
    token, radio, model = cfgs
    base = M.build(token, radio, model, FIX_SIG, FIX_KEM)
    alt = M.build(token, {**radio, "phy": {**radio["phy"], "crc_on_downlink": True}}, model, FIX_SIG, FIX_KEM)
    s = M.crc_sensitivity(base, alt, model, True)
    assert (s.frames == s.frames_alt).all()                  # CRC never changes frame counts
    assert (s.airtime_delta_rel >= 0).all() and (s.airtime_delta_rel > 0).any()
    assert (s.cmds_gateway_alt <= s.cmds_gateway).all()


def test_s2_amortization_empty_without_signer(cfgs):
    token, radio, model = cfgs
    out = M.build(token, radio, model, {"HMAC-SHA256-T16": 16}, FIX_KEM)
    assert out["model_s2_amortization"].empty
    assert kill.k2(out, 2.0)["answer"] == "n/a"


# ---------------------------------------------------------------- kill criteria
def test_kill_criteria(cfgs):
    token, radio, model = cfgs
    out = M.build(token, radio, model, FIX_SIG, FIX_KEM)
    k = kill.evaluate(out, model)
    assert k["K1"]["answer"] == "no" and k["K1"]["frames"] == 22      # 22 x 300 s > 30 min
    spec = dict(model["kill_criteria"]["K1"], algorithm="PQ-B")
    k1b = kill.k1(out, spec)                                          # 110 B -> 3 frames @ DR8
    assert k1b["frames"] == 3 and k1b["answer"] == "yes"
    assert kill.k1(out, dict(spec, algorithm="NONE"))["answer"] == "n/a"
    k2 = k["K2"]
    assert k2["answer"].startswith("yes")                             # fixture: 100 cmds/epoch amortises
    cm = {(r["kem"], r["epoch_hours"]): r for r in k2["class_a_max"]}
    assert cm[("KEM-X", 1)]["n_infeasible_channels"] >= 1
    assert kill.k2(out, 1.0)["answer"].startswith("no")
    k3 = {(r["region"], r["dr"]): r for r in k["K3"]}
    assert k3[("US915", 8)]["fits_one_frame"] == "none"               # 110 B > 53 B
    assert k3[("US915", 10)]["fits_one_frame"] == "S1/PQ-B"           # 110 B <= 242 B
    assert k3[("NB-IoT", 0)]["fits_one_frame"] == "S1/PQ-B"


def test_run_end_to_end(tmp_path, cfgs):
    pd.DataFrame([{"algorithm": a, "sig_min": v, "sig_median": v, "sig_max": v} for a, v in FIX_SIG.items()]
                 ).to_csv(tmp_path / "sizes.csv", index=False)
    pd.DataFrame([{"algorithm": "ML-KEM-512", "ct_bytes": 500}]).to_csv(tmp_path / "kem_sizes.csv", index=False)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    token, radio, model = cfgs
    model["s2_kem"] = ["ML-KEM-512"]
    for name, obj in {"token": token, "radio": radio, "model": model}.items():
        (cfg / f"{name}.yaml").write_text(json.dumps(obj))           # JSON is valid YAML
    (cfg / "actions.yaml").write_text((CONFIG / "actions.yaml").read_text())
    (cfg / "threat.yaml").write_text((CONFIG / "threat.yaml").read_text())
    (cfg / "mcu.yaml").write_text((CONFIG / "mcu.yaml").read_text())
    h = load_yaml(CONFIG / "harm.yaml")
    h.update(schemes=["S4", "S6"], compromises=["none", "C1"], attacker={"strategies": ["drain"]})
    (cfg / "harm.yaml").write_text(json.dumps(h))
    M.run(cfg, tmp_path)
    for f in ("model_tokens", "model_delivery", "model_capacity", "model_s2_amortization"):
        assert (tmp_path / f"{f}.csv").exists()
    kc = json.loads((tmp_path / "kill_criteria.json").read_text())
    assert kc["K1"]["answer"] == "no" and kc["K1_crc_sensitivity"]["frames"] == kc["K1"]["frames"]
    assert (tmp_path / "model_sensitivity_crc.csv").exists() and (tmp_path / "model_blast_radius.csv").exists()
    mc = pd.read_csv(tmp_path / "mcu_verify_cost.csv")
    assert (mc.verify_ms_per_day_V6h > mc.verify_ms_per_day_V72h).all()
    assert (tmp_path / "model_harm.csv").exists() and "source" in json.loads((tmp_path / "harm_meta.json").read_text())
    assert 0 < kc["K5"]["ratio"] < 1 and "K6" in kc and (tmp_path / "model_blast_compromise.csv").exists()
