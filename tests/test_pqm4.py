"""pqm4 benchmarks.md parser and verification-cost extraction."""

import hashlib
import json

import pytest

from pqcap import pqm4
from pqcap.config import CONFIG, REPO_ROOT

MD = """# Speed Evaluation
## Signature Schemes
| scheme | implementation | key generation [cycles] | sign [cycles] | verify [cycles] |
| ------ | -------------- | ----------------------- | ------------- | --------------- |
| toy-1 (10 executions) | ref | AVG: 1,000 <br /> MIN: 900 <br /> MAX: 1,100 | AVG: 2,000 <br /> MIN: 1,900 <br /> MAX: 2,100 | AVG: 30 <br /> MIN: 29 <br /> MAX: 31 |
| toy-2 | m4f | AVG: 5 <br /> MIN: 4 <br /> MAX: 6 | AVG: 7 <br /> MIN: 7 <br /> MAX: 7 | AVG: 8 <br /> MIN: 8 <br /> MAX: 9 |
# Memory Evaluation
## Signature Schemes
| Scheme | Implementation | Key Generation [bytes] | Sign [bytes] | Verify [bytes] |
| ------ | -------------- | ---------------------- | ------------ | -------------- |
| toy-1 | ref | 1,148 | 2,428 | 376 |
# Size Evaluation
## Signature Schemes
| Scheme | Implementation | .text [bytes] | .data [bytes] | .bss [bytes] | Total [bytes] |
| toy-1 | ref | 81,825 | 0 | 39,936 | 121,761 |
"""


def test_parse_cell_and_errors():
    assert pqm4.parse_speed_cell("AVG: 1,421,623 <br /> MIN: 1,420,738 <br /> MAX: 1,422,362") == \
        {"avg": 1421623, "min": 1420738, "max": 1422362}
    with pytest.raises(ValueError):
        pqm4.parse_speed_cell("AVG: 1")


def test_parse_tables():
    d = pqm4.signature_benchmarks(MD).set_index(["scheme", "impl"])
    a = d.loc[("toy-1", "ref")]
    assert a.executions == 10 and a.verify_avg == 30 and a.verify_stack_bytes == 376
    assert a.code_total_bytes == 121761 and a.code_text_bytes == 81825
    b = d.loc[("toy-2", "m4f")]
    assert b.sign_max == 7 and b.verify_max == 9


def test_pinned_files_match_source_and_known_rows():
    src = json.loads((REPO_ROOT / "data/pqm4/SOURCE.json").read_text())
    for pin in src["pins"].values():
        for f in pin["files"].values():
            assert hashlib.sha256((REPO_ROOT / f["path"]).read_bytes()).hexdigest() == f["sha256"]
        assert "24MHz" in (REPO_ROOT / pin["files"]["README.md"]["path"]).read_text()
    c = pqm4.verification_cost(CONFIG, REPO_ROOT).set_index(["pqm4_scheme", "impl"])
    assert c.loc[("ml-dsa-44", "m4f"), "verify_cycles_avg"] == 1421623
    assert c.loc[("ml-dsa-44", "m4f"), "verify_stack_bytes"] == 8912
    assert c.loc[("ml-dsa-44", "m4fstack"), "verify_stack_bytes"] == 2712
    assert c.loc[("falcon-512", "m4-ct"), "verify_cycles_avg"] == 482280
    assert c.loc[("falcon-512", "m4-ct"), "pqm4_commit"].startswith("94435189")
    assert c.loc[("ml-dsa-44", "m4f"), "verify_ms_avg"] == pytest.approx(1421623 / 24e6 * 1e3)


def test_missing_selection(tmp_path):
    (tmp_path / "mcu.yaml").write_text(json.dumps({"label": "x", "measurement_clock_mhz": 24, "selections": [
        {"label": "n", "scheme": "nope", "impl": "m4f", "pin": "head"}]}))
    with pytest.raises(KeyError):
        pqm4.verification_cost(tmp_path, REPO_ROOT)
