"""Tamarin proof-output parser."""

from pqcap import formal
from pqcap.config import REPO_ROOT

SAMPLE = """theory Probe
==============================================================================
summary of summaries:

analyzed: probe.spthy

  processing time: 0.12s

  ctr_mono (all-traces): verified (28 steps)
  no_replay (all-traces): falsified - found trace (5 steps)
  exec (exists-trace): verified (9 steps)
  slow (all-traces): analysis incomplete (1 steps)

==============================================================================
"""


def test_parse_summary():
    r = formal.parse_summary(SAMPLE)
    assert [x["lemma"] for x in r] == ["ctr_mono", "no_replay", "exec", "slow"]
    assert r[1]["result"] == "falsified" and r[2]["kind"] == "exists-trace" and r[0]["steps"] == 28
    assert r[3]["result"] == "analysis incomplete"
    assert formal.parse_summary("  rule (modulo AC) X:\n") == []


def test_version_and_committed_proofs():
    assert formal.version("checking version: tamarin-prover 1.12.0, (C) David") == "1.12.0"
    assert formal.version("nothing") is None
    v = (REPO_ROOT / "formal/proofs/VERSION.txt").read_text()
    assert formal.version(v) == "1.12.0"
    d = formal.results(REPO_ROOT / "formal/proofs")
    assert set(d.model) == {"crisis", "delegation", "freshness"}
    res = {(m, x): r for m, x, r in zip(d.model, d.lemma, d.result)}
    need = {("freshness", "ctr_monotone"), ("freshness", "P4_no_replay"), ("freshness", "P4_injective_agreement"),
            ("crisis", "P1_confinement"), ("crisis", "revocation"), ("crisis", "revocation_needs_PA"),
            ("crisis", "disable_needs_OP"), ("crisis", "exec_accept"), ("crisis", "exec_disable"),
            ("crisis", "exec_revoke"), ("delegation", "P2_attenuation_only"),
            ("delegation", "exec_attenuated_child")}
    assert need <= set(res) and all(res[k] == "verified" for k in need)
    assert (d.result == "verified").all()


def test_freshness_is_generated_from_crisis(tmp_path):
    """formal/freshness.spthy must be exactly what make_freshness.py derives from the committed crisis.spthy."""
    import subprocess
    import sys
    f = REPO_ROOT / "formal"
    out = tmp_path / "freshness.spthy"
    subprocess.run([sys.executable, "-I", str(f / "make_freshness.py"), str(f / "crisis.spthy"), str(out)],
                   check=True)
    assert out.read_text() == (f / "freshness.spthy").read_text()
    assert "Hnd(" not in out.read_text().split("rule Device_Accept:")[1].split("rule OP_Approve")[0]


def test_lemma_file(tmp_path):
    assert formal.lemma_file("exec", SAMPLE)["steps"] == 9
    t = formal.lemma_file("slow", "partial\nTIMEOUT after 900 s (heuristic s)\n")
    assert t["result"] == "timeout (900 s)" and t["steps"] is None
    import pytest
    with pytest.raises(ValueError):
        formal.lemma_file("missing", SAMPLE)
    (tmp_path / "m").mkdir()
    (tmp_path / "m" / "exec.txt").write_text(SAMPLE)
    (tmp_path / "w.txt").write_text(SAMPLE)
    d = formal.results(tmp_path)
    assert list(d[d.model == "m"].lemma) == ["exec"] and len(d[d.model == "w"]) == 4


def test_section_formal(tmp_path):
    import pandas as pd

    from pqcap.report import section_formal
    assert section_formal(tmp_path) == "_no Tamarin proofs_"
    p = tmp_path / "formal_lemmas.csv"
    pd.DataFrame(columns=["model", "lemma", "kind", "result", "steps"]).to_csv(p, index=False)
    assert section_formal(tmp_path) == "_no Tamarin proofs_"
    pd.DataFrame([{"model": "m", "lemma": "a", "kind": "all-traces", "result": "verified", "steps": 4}]).to_csv(p, index=False)
    assert "**all verified**" in section_formal(tmp_path)
    pd.DataFrame([{"model": "m", "lemma": "a", "kind": "all-traces", "result": "verified", "steps": 4},
                  {"model": "m", "lemma": "b", "kind": None, "result": "timeout (900 s)", "steps": None}]
                 ).to_csv(p, index=False)
    out = section_formal(tmp_path)
    assert "1 verified; NOT verified: `b` (timeout (900 s))" in out and "| - |" in out.replace("|  - |", "| - |")
