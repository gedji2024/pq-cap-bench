"""F7 truncated-tag forgery bounds."""

import math

from pqcap import truncation as tr


def test_bound():
    assert tr.forgery_bound(8, 1) == 2.0 ** -64
    assert tr.forgery_bound(1, 1000) == 1.0                         # capped
    t = tr.table([8, 16], 4, 300, [1, 200])
    one = t[(t.tag_bytes == 8) & (t.budget == "one attempt")].iloc[0]
    assert one.log2_p == -64
    w = t[(t.tag_bytes == 8) & t.budget.str.contains("counter window")].iloc[0]
    assert w.attempts == 2.0 ** 32 and math.isclose(w.log2_p, -32)
    y = t[(t.tag_bytes == 16) & t.budget.str.contains("1 devices")].iloc[0]
    assert math.isclose(y.attempts, 12 * 24 * 365) and y.p_forge < 2.0 ** -100


def test_section_truncation(tmp_path):
    from pqcap.report import section_truncation
    assert section_truncation(tmp_path) == ""
    tr.table([8], 4, 300, [1]).to_csv(tmp_path / "f7_truncation.csv", index=False)
    assert "**F7 - computational note" in section_truncation(tmp_path) and "-64.0" in section_truncation(tmp_path)
