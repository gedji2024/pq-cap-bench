"""REPORT.md rendering from synthetic result files (fixtures, not measurements)."""

import json

import pandas as pd

from pqcap import model as M
from pqcap import report
from pqcap.config import CONFIG
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
    k["K5"] = blast.k5(blast.blast_radius(ev.catalogue_from_config(acfg), ev.envelope_from_config(acfg), 8))
    (r / "kill_criteria.json").write_text(json.dumps(k, default=str))
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "model.yaml").write_text(json.dumps(mdl))
    (cfg / "radio.yaml").write_text(json.dumps(radio))
    return r, cfg


def test_report_renders(tmp_path, cfgs):  # noqa: F811
    r, cfg = _fake_results(tmp_path, cfgs)
    figs = tmp_path / "figures"
    figs.mkdir()
    (figs / "fig1_x.png").write_bytes(b"")
    report.run(cfg, r, figs)
    md = (tmp_path / "REPORT.md").read_text()
    for h in ("## 1. Environment", "## 4. Host timings", "## 8. Kill criteria", "**K1", "**K2", "**K3", "**K4", "**K5 - Blast radius",
              "## 7c. S6", "Crisis commands per gateway", "fig1_x.png"):
        assert h in md
    assert "env.json missing" in md
    assert "HOST measurements" in md
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
    (r / "model_s6_calm.csv").unlink()
    (r / "kill_criteria.json").write_text(json.dumps(k))
    report.run(cfg, r, tmp_path)
    md = (tmp_path / "REPORT.md").read_text()
    assert "**K1: n/a**" in md and "**K2: n/a**" in md and "**K4: n/a**" in md and "**K5: n/a**" in md and "_S6 not configured_" in md and "| CPU | cpu |" in md


def test_report_s6_no_signer(tmp_path, cfgs):  # noqa: F811
    r, cfg = _fake_results(tmp_path, cfgs)
    (r / "model_s6_calm.csv").write_text("\n")
    report.run(cfg, r, tmp_path)
    assert "none of the configured envelope signers" in (tmp_path / "REPORT.md").read_text()


def test_md_table_formats():
    t = report.md_table(pd.DataFrame({"a": [1.234, None], "b": ["x", ""]}))
    assert "1.23" in t and "| - | - |" in t
