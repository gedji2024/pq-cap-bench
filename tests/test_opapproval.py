"""F6 approval cost."""

from pqcap import model as M
from pqcap import opapproval as oa
from pqcap.config import CONFIG, load_yaml

MODEL = load_yaml(CONFIG / "model.yaml")
CH = M.channels(load_yaml(CONFIG / "radio.yaml"), MODEL)
LC = lambda n, c: M.link_cost(n, c, MODEL["fragment_header_bytes"])  # noqa: E731


def test_approval_rows():
    pc, cm = oa.approval_rows(CH, 24, {"chain reveal 16 B": 16, "big": 2420}, 39, {"X": 64}, 300, LC)
    us8 = pc[(pc.region == "US915") & (pc.dr == 8)].set_index("approval")
    assert us8.loc["chain reveal 16 B", "frames"] == 1 and us8.loc["big", "frames"] > 1
    assert us8.loc["big", "latency_worst_s"] > us8.loc["chain reveal 16 B", "latency_worst_s"] >= 300
    assert (pc.message_bytes == pc.approval_bytes + 24).all()
    assert set(cm.commit_signer) == {"X"} and (cm.commit_bytes == 39 + 64).all()
    assert pc.region.notna().all() and "NB-IoT" not in set(pc.region)


def test_section_f6_absent(tmp_path):
    from pqcap.report import section_f6
    assert section_f6(tmp_path) == "_F6 not run_"
