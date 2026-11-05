"""REPORT.md rendering from synthetic result files (fixtures, not measurements)."""

import json

import pandas as pd

from pqcap import model as M
from pqcap import report
from pqcap.config import CONFIG, REPO_ROOT
from tests.test_model import FIX_SIG, cfgs  # noqa: F401  (fixture re-export)


def _fake_results(tmp_path, cfgs):  # noqa: F811
    r = tmp_path / "results"
    r.mkdir()
    pd.DataFrame([{"algorithm": a, "kind": "pq", "pk_bytes": 1, "sk_bytes": 2, "sig_min": v, "sig_median": v,
                   "sig_max": v, "sig_n_observed": 3, "sig_liboqs_nominal_max": ""} for a, v in FIX_SIG.items()]
                 ).to_csv(r / "sizes.csv", index=False)
    pd.DataFrame([{"algorithm": "KEM-X", "pk_bytes": 1, "sk_bytes": 2, "ct_bytes": 500, "ss_bytes": 32}]
                 ).to_csv(r / "kem_sizes.csv", index=False)
    pd.DataFrame([{"label": "PQ-A", "kind": "pq", "status": "ok", "impl_name": "PQ-A", "reason": ""},
                  {"label": "Ghost", "kind": "pq", "status": "unavailable", "impl_name": "", "reason": "absent"}]
                 ).to_csv(r / "algorithms.csv", index=False)
    rows = []
    for alg in ("PQ-A", "KEM-X"):
        for op, m in [("keygen", 0), ("sign", 32), ("verify", 32), ("sign", 96), ("verify", 96), ("sign", 160)]:
            rows.append({"algorithm": alg, "op": op, "msg_len": m, "kind": "kem" if alg == "KEM-X" else "pq",
                         "pooled_median_ns": 1000.0, "pooled_iqr_ns": 10.0, "pooled_p95_ns": 1200.0,
                         "pooled_n": 3000, "run_to_run_cv": 0.01, "run_to_run_range_rel": 0.02})
    pd.DataFrame(rows).to_csv(r / "bench_summary.csv", index=False)
    token, radio, mdl = cfgs
    out = M.build(token, radio, mdl, FIX_SIG, {"KEM-X": 500})
    alt = M.build(token, {**radio, "phy": {**radio["phy"], "crc_on_downlink": True}}, mdl, FIX_SIG, {"KEM-X": 500})
    out["model_sensitivity_crc"] = M.crc_sensitivity(out, alt, mdl, True)
    for name, df in out.items():
        df.to_csv(r / f"{name}.csv", index=False)
    from pqcap.kill import evaluate
    k = evaluate(out, mdl)
    k["K1_crc_sensitivity"] = evaluate(alt, mdl)["K1"]
    from pqcap import blast
    from pqcap import envelope as ev
    from pqcap.config import load_yaml
    acfg = load_yaml(CONFIG / "actions.yaml")
    br = blast.blast_s4_s6(ev.catalogue_from_config(acfg), ev.envelope_from_config(acfg),
                           ev.invariants_from_config(acfg), 8)
    k["K5"] = blast.k5(br, blast.reference_state_name(acfg))
    thr = load_yaml(CONFIG / "threat.yaml")
    bc = blast.blast_compromise(ev.catalogue_from_config(acfg), ev.envelope_from_config(acfg),
                                ev.firmware_policy_from_config(acfg), ev.invariants_from_config(acfg), thr, 8)
    ref = blast.reference_state_name(acfg)
    k["K5"]["matrix"] = (bc[bc.state == ref].groupby(["compromise", "scheme"], sort=False).accepted.sum()
                         .unstack().reset_index().to_dict("records"))
    k["K6"] = blast.k6(bc, ref, {"S4-E": 144, "S6": 2532})
    bc[bc.compromise.isin(["C1", "C1+C3", "C1+C3+OP"])].groupby(["state", "compromise", "scheme"], sort=False) \
        .accepted.sum().unstack().reset_index().to_csv(r / "d2_blast_s6f.csv", index=False)
    pd.DataFrame([{"op_token_alg": "Ed25519", "token_bytes": 64, "region": "US915", "dr": 8, "frames": 2,
                   "airtime_s": 0.5}]).to_csv(r / "d2_op_token_cost.csv", index=False)
    from pqcap import revocation as rv
    chans = M.channels(radio, mdl)
    lc = lambda n, ch: M.link_cost(n, ch, 2)  # noqa: E731
    rv.exposure(chans, {"S4-E": 144, "S6": 2532, "S6-R": 2564}, mdl["revocation"], 300, lc,
                {"S6-R": [20, 36]}).to_csv(
        r / "model_revocation_exposure.csv", index=False)
    rv.renewal_cost(chans, {"S4-E": 144, "S6": 2532}, mdl["revocation"], 300, lc).to_csv(
        r / "model_renewal_cost.csv", index=False)
    (r / "kill_criteria.json").write_text(json.dumps(k, default=str))
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "model.yaml").write_text(json.dumps(mdl))
    (cfg / "radio.yaml").write_text(json.dumps(radio))
    (cfg / "traceability.yaml").write_text((CONFIG / "traceability.yaml").read_text())
    for f in ("mcu.yaml", "repo_state.yaml", "policies.yaml", "threat.yaml", "actions.yaml"):
        (cfg / f).write_text((CONFIG / f).read_text())
    from pqcap import devices as _d
    cdf, ck5, ck6 = _d.run(CONFIG)
    cdf.to_csv(r / "catalogue_blast.csv", index=False)
    from pqcap import gateway as _g
    import pqcap.model as _m
    _devs = _d.load_catalogue(CONFIG / "devices")
    _pol = load_yaml(CONFIG / "policies.yaml")
    _g.filter_savings(_devs, _pol, _m.channels(radio, mdl), 300, [50], lambda n, c: _m.link_cost(n, c, 2),
                      ["uniform_type"], _g.FILTER_POINTS).to_csv(r / "d6_gateway_filter.csv", index=False)
    _g.forging_power(_devs, _pol, load_yaml(CONFIG / "threat.yaml"), acfg["invariants"],
                     {"alert_active": True, "battery_below_floor": False}).to_csv(r / "d6_forging_power.csv", index=False)
    ck5.to_csv(r / "catalogue_k5_ranges.csv", index=False)
    ck6.to_csv(r / "catalogue_k6_ranges.csv", index=False)
    _ks = _d.c4_key_scope(_devs, _pol, load_yaml(CONFIG / "threat.yaml"), acfg["invariants"],
                          {"alert_active": True, "battery_below_floor": False})
    _d.c4_k6(_ks).to_csv(r / "f1_c4_k6.csv", index=False)
    from pqcap import pqm4 as _p
    _p.verification_cost(CONFIG, REPO_ROOT).to_csv(r / "mcu_verify_cost.csv", index=False)
    from pqcap import harm
    h = {**load_yaml(CONFIG / "harm.yaml"), "workers": 1}
    h.update(schemes=["S4", "S6"], compromises=["none", "C1"], attacker={"strategies": ["drain"]}, events_rule=None, events_prereg=None,
             battery={**h["battery"], "profiles": h["battery"]["profiles"][-1:]})
    (cfg / "harm.yaml").write_text(json.dumps(h))
    hd, he, hm = harm.run(h, acfg, REPO_ROOT)
    hd.to_csv(r / "model_harm.csv", index=False)
    harm.delay_distribution(he.assign(scheme="S6+F", strategy="suppress"), 30, 50, 1).to_csv(
        r / "model_harm_delays.csv", index=False)
    (r / "harm_meta.json").write_text(json.dumps({**hm, "source": {"query_url": "q"}}, default=str))
    return r, cfg


def test_report_renders(tmp_path, cfgs):  # noqa: F811
    r, cfg = _fake_results(tmp_path, cfgs)
    figs = tmp_path / "figures"
    figs.mkdir()
    (figs / "fig1_x.png").write_bytes(b"")
    report.run(cfg, r, figs)
    md = (tmp_path / "REPORT.md").read_text()
    for h in ("## 1. Environment", "## 4. Host timings", "## 8. Kill criteria", "**K1", "**K2", "**K3", "**K4", "**K5 - Blast radius", "**K5 - blast radius per compromise", "## 7d. Revocation", "**D2 - S6+F", "**D6 - an untrusted gateway", "**Forging power of a filtering gateway**", "**OP token cost**", "**D1 - active revocation time", "## 8b. Traceability", "## 8a. K5/K6 on the manufacturer", "**SUPERSEDED**", "## 7f. Device-side", "Energy is **not reported**", "## 0. Repository state", "kept `7df90f4`", "T10", "## 7e. Harm-weighted replay", "Gaps > 60 min", "**Battery profiles (D5)**", "**K6 - blast(S4-E)", "**F1 - C4 fairness", "**F2 - realistic filtering points**", "**Gateway given AppSKey (upper bound)**",
              "## 7c. S6", "Crisis commands per gateway", "**Why the crisis capacities differ", "its capacity equals S6", "fig1_x.png"):
        assert h in md
    assert "env.json missing" in md
    assert "host (unrecorded CPU), not MCU" in md
    assert "## 7b. Sensitivity: downlink CRC" in md and "K1 under primary vs sensitivity" in md


def test_report_without_crc_file(tmp_path, cfgs):  # noqa: F811
    r, cfg = _fake_results(tmp_path, cfgs)
    (r / "model_sensitivity_crc.csv").unlink()
    report.run(cfg, r, tmp_path)
    assert "_no CRC sensitivity file_" in (tmp_path / "REPORT.md").read_text()


def test_report_env_and_na(tmp_path, cfgs):  # noqa: F811
    r, cfg = _fake_results(tmp_path, cfgs)
    (r / "env.json").write_text(json.dumps({
        "label": "HOST", "date_utc": "d", "cpu": {"model": "cpu", "arch": "a", "cores_logical": 1,
                                                  "frequency_governor": "g"},
        "os": {"platform": "p"}, "python": {"version": "3.12 x"},
        "liboqs": {"version_runtime": "0", "liboqs_commit": "c", "liboqs_python": "0",
                   "c_compiler_version": "cc", "cmake_c_flags_release": "-O3"},
        "python_packages": {"cryptography": "1"}, "openssl_for_cryptography": "o", "cpu_pinning": "none"}))
    k = json.loads((r / "kill_criteria.json").read_text())
    k["K1"] = {"answer": "n/a", "reason": "missing"}
    k["K2"] = {"answer": "n/a", "reason": "missing"}
    k["K4"] = {"answer": "n/a", "reason": "missing"}
    k.pop("K5")
    k.pop("K6")
    (r / "model_revocation_exposure.csv").unlink()
    (r / "model_harm.csv").unlink()
    (r / "d2_blast_s6f.csv").unlink()
    (r / "d6_gateway_filter.csv").unlink()
    (cfg / "traceability.yaml").unlink()
    (cfg / "repo_state.yaml").unlink()
    (r / "catalogue_k5_ranges.csv").unlink()
    (r / "mcu_verify_cost.csv").unlink()
    (r / "model_s6_calm.csv").unlink()
    (r / "kill_criteria.json").write_text(json.dumps(k))
    report.run(cfg, r, tmp_path)
    md = (tmp_path / "REPORT.md").read_text()
    assert "## 4. Host timings (cpu host, not MCU)" in md and "**All timings: cpu host, not MCU.**" in md
    assert "**K1: n/a**" in md and "**K2: n/a**" in md and "**K4: n/a**" in md and "**K5: n/a**" in md and "**K6: n/a**" in md and "_revocation not configured_" in md and "_harm replay not run" in md and "_D2 not run_" in md and "_D6 not run_" in md and "_no traceability map_" in md and "_no pqm4 data_" in md and "_no repository state record_" in md and "_no manufacturer catalogue_" in md and "_S6 not configured_" in md and "| CPU | cpu |" in md


def test_report_s6_no_signer(tmp_path, cfgs):  # noqa: F811
    r, cfg = _fake_results(tmp_path, cfgs)
    (r / "model_s6_calm.csv").write_text("\n")
    report.run(cfg, r, tmp_path)
    assert "none of the configured envelope signers" in (tmp_path / "REPORT.md").read_text()


def test_md_table_formats():
    t = report.md_table(pd.DataFrame({"a": [1.234, None], "b": ["x", ""]}))
    assert "1.23" in t and "| - | - |" in t


def test_s6_explain_branches(tmp_path, cfgs):  # noqa: F811
    r, _ = _fake_results(tmp_path, cfgs)
    _, _, mdl = cfgs
    crisis = pd.read_csv(r / "model_s6_crisis.csv")
    assert "its capacity equals S6" in report.section_s6_explain(crisis, mdl)
    crisis.loc[crisis.scheme == "S4c", "cmds_gateway"] = -1
    assert "differs from S6" in report.section_s6_explain(crisis, mdl)
    assert report.section_s6_explain(crisis.iloc[0:0], mdl) == ""


def test_k5_matrix_absent():
    assert report.section_k5_matrix({"state": "x"}) == ""


def test_harm_multi_event_tables(tmp_path):
    d = pd.DataFrame([{"event": e, "battery_profile": "b", "scheme": "S6", "compromise": c, "strategy": "drain",
                       "legit_policy": "-", "crossings": 4, "missed": 1, "delayed": 0, "max_delay_min": 5.0,
                       "floor_violating_uplinks": 0, "died": False, "legit_unique_rejection_rate": 0.0}
                      for e in ("e1", "e2") for c in ("none", "C1")])
    from pqcap import harm
    harm.summarize_events(d, 100, 1).to_csv(tmp_path / "model_harm_summary.csv", index=False)
    out = report.harm_summary_tables(d, tmp_path, lambda v: f"{v:.1f}")
    assert "statistics over 2 events" in out[0] and "0.25 [0.25, 0.25]" in out[2]


def test_harm_delay_table(tmp_path):
    d = pd.DataFrame([{"event": e, "battery_profile": "b", "scheme": "S6", "compromise": "C1", "strategy": "drain",
                       "legit_policy": "-", "crossings": 2, "missed": 0, "delayed": 0, "max_delay_min": 5.0,
                       "floor_violating_uplinks": 0, "died": False, "legit_unique_rejection_rate": 0.0}
                      for e in ("e1", "e2")])
    from pqcap import harm
    harm.summarize_events(d, 100, 1).to_csv(tmp_path / "model_harm_summary.csv", index=False)
    ev = pd.DataFrame([{"event": e, "battery_profile": "b", "scheme": "S6", "compromise": "C1", "strategy": "drain",
                        "legit_policy": "-", "delay_min": x} for e, x in (("e1", 5.0), ("e1", None), ("e2", 40.0))])
    harm.delay_distribution(ev, 30, 200, 1).to_csv(tmp_path / "model_harm_delays.csv", index=False)
    out = report.harm_summary_tables(d, tmp_path, lambda v: f"{v:.1f}")
    assert "F5 - detection-delay distribution" in out[0] and "inf (missed)" in out[1] and "statistics over 2" in out[2]
