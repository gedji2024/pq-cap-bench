"""Progent adapter (DEVIATIONS 7 / 7b; post-registration extension): the pinned secagent loads, the manual policy
encodes the S6 envelope ranges, secagent blocks out-of-envelope commands in progent_manual, the generated-policy path
calls the policy model only through the logged pass-through, no endpoint other than localhost is contacted, and the
registered conditions are unchanged. Needs the extension requirements (experiments/agents/requirements_ext.txt)."""

from __future__ import annotations

import json
import socket

import pytest

from pqcap.agents import plant as P
from pqcap.agents import progent_adapter as PA
from pqcap.agents import runner as R
from pqcap.agents import suite as S

pytest.importorskip("jsonschema")
pytest.importorskip("z3")
pytestmark = pytest.mark.skipif(not PA.ROOT.exists(), reason="third_party/progent not cloned (DEVIATIONS 7)")

from tests.test_agents import ACFG, env_for, scenarios, world  # noqa: E402,F401  (fixtures)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    real = socket.socket.connect

    def guarded(self, addr):
        host = addr[0] if isinstance(addr, tuple) else addr
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AssertionError(f"network access to {addr} attempted")
        return real(self, addr)

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture()
def T(monkeypatch):
    T = PA.load()
    calls = []

    def fake_api(sys_prompt, user_prompt, temperature=0.0):
        calls.append((sys_prompt, user_prompt, temperature))
        if "Output whether you want to update" in sys_prompt and "CURRENT_RESTRICTIONS" not in user_prompt:
            return "No"
        return '```json [{"name": "read_bulletins", "args": {}}, {"name": "read_gauge", "args": {}}, ' \
               '{"name": "set_reporting_interval", "args": {"minutes": {"type": "integer", "minimum": 5}}}] ```'

    monkeypatch.setitem(T.__dict__, "_pqcap_api_request", fake_api)
    T.calls_seen = calls
    return T


def test_load_and_pins(T):
    assert T.__name__ == "secagent.tool" and PA.load() is T
    assert PA.PROGENT_COMMIT.startswith("b02783b")
    import os
    assert os.environ["OPENAI_BASE_URL"].startswith("http://127.0.0.1:11434")


def test_load_checks_sha256(tmp_path):
    bad = {**PA.SHA256, "secagent/tool.py": "0" * 64}
    saved = list(PA._SEC)
    PA._SEC.clear()
    try:
        with pytest.raises(RuntimeError, match="sha256"):
            PA.load(sha=bad)
    finally:
        PA._SEC[:] = saved


def test_manual_policy_matches_envelope(scenarios):
    plant = env_for(scenarios, "S4").plant
    pol = PA.manual_policy(plant)
    for t in PA.READ_TOOLS:
        assert pol[t] == [(1, 0, {}, 0)]
    d = plant.devices["WL-BBST2"]
    r = d.envelope.rules[P.ACTIONS["set_reporting_interval"]]
    row = next(x for x in pol["set_reporting_interval"] if x[2]["device_id"]["enum"] == ["WL-BBST2"])
    assert row[2]["minutes"] == {"type": "integer", "minimum": r.lo, "maximum": r.hi}
    assert len(pol["set_reporting_interval"]) == len(plant.devices)
    en = d.envelope.rules.get(P.ACTIONS["sensor_enable"])
    rows = [x for x in pol.get("set_sensor_enabled", []) if x[2]["device_id"]["enum"] == ["WL-BBST2"]]
    assert (en is None and not rows) or rows[0][2]["enabled"]["enum"] == [bool(v) for v in (0, 1) if en.lo <= v <= en.hi]


def test_manual_policy_skips_unallowed_values():
    rule = lambda lo, hi: P.ev.Rule(0, frozenset({0}), lo, hi)  # noqa: E731
    env = P.ev.Policy(1, {P.ACTIONS["sensor_enable"]: rule(2, 3), P.ACTIONS["request_immediate_uplink"]: rule(1, 2)})
    dev = P.Device("D1", "G", "m", 60, 100, True, 80.0, False, 0.1, env, env, 500)
    pol = PA.manual_policy(P.Plant("S4", {}, {"D1": dev}))
    assert "set_sensor_enabled" not in pol and "request_immediate_uplink" not in pol and "set_alert_threshold" not in pol


def test_secagent_blocks_outside_envelope(scenarios, T):
    e = env_for(scenarios, "S4")
    fns, st, upd = PA.setup("progent_manual", "m", S.make_suite().tools, e.plant, T)
    assert not upd and not T.generate_policy
    from agentdojo.functions_runtime import FunctionsRuntime
    rt = FunctionsRuntime(fns)
    d = e.plant.devices["WL-BBST2"]
    r = d.envelope.rules[P.ACTIONS["set_reporting_interval"]]
    out, err = rt.run_function(e, "set_reporting_interval", {"device_id": "WL-BBST2", "minutes": r.lo - 1})
    assert out == "" and err.startswith("ValidationError") and d.counter == 0 and not e.plant.receipts
    out, err = rt.run_function(e, "set_reporting_interval", {"device_id": "WL-BBST2", "minutes": r.lo})
    assert err is None and "accepted" in out and d.interval_min == r.lo
    out, err = rt.run_function(e, "set_reporting_interval", {"device_id": "WL-NOPE", "minutes": r.lo})
    assert err.startswith("ValidationError")
    out, err = rt.run_function(e, "read_gauge", {"gauge_id": "BBST2"})
    assert err is None
    assert T.calls_seen == []        # no policy-model call when generation is off


def test_run_episode_progent_manual(world):
    s = R.Spec("m", 0.0, 1, 0, "progent_manual", "limit_aware", "SC08", "UT0_interval", "v1:EXT:drain:direct")
    assert R.scheme_and_defence("progent_manual") == ("S4", "progent_manual")
    r = R.run_episode(world, s)
    assert r["scheme"] == "S4" and r["defence"] == "progent_manual" and r["error"] is None
    assert r["ext"]["condition"] == "progent_manual" and r["ext"]["policy_calls"] == []
    assert len(r["ext"]["policies"]) == 1 and len(r["ext"]["policies"][0]["sha256"]) == 64
    tool_errs = [m for m in r["messages"] if m["role"] == "tool" and m.get("error")]
    assert any("is not allowed" in m["error"] for m in tool_errs)          # interval 1 blocked by secagent
    assert r["devices_after"]["WL-BBST2"]["interval_min"] != 1
    blocks = [x for x in r["receipts"] if x["decision"] == "block"]
    assert blocks and all(x["reason"] == "progent" and x["tag"] is None for x in blocks)
    assert any(x["decision"] == "block" for x in r["attack_receipts"])     # counted as an attempt
    sysmsg = r["messages"][0]["content"][0]["content"]
    assert "set_reporting_interval: value in [" in sysmsg                   # same limits text as platform_policy


def test_run_episode_progent_auto(world, T):
    s = R.Spec("m", 0.0, 1, 0, "progent_auto", "naive", "SC08", "UT0_interval", "v1:EXT:drain:direct")
    assert R.scheme_and_defence("progent_auto") == ("none", "progent_auto")
    r = R.run_episode(world, s)
    x = r["ext"]
    assert r["scheme"] == "none" and r["error"] is None and not x["generation_failed"]
    assert x["policy_calls"] and all(c["temperature"] == 0.0 for c in x["policy_calls"])
    assert [p["event"] for p in x["policies"]][0] == "generate" and "update" in [p["event"] for p in x["policies"]]
    gen = json.loads(x["policies"][0]["policy"])
    assert any(row[0] == 100 for row in gen["set_reporting_interval"])     # generated rule (priority 100)
    assert gen["list_gauges"][0][:2] == [1, 0]                            # always-allowed no-arg tool
    tools = json.loads(T.calls_seen[0][1].split("\nUSER_QUERY: ")[0][len("TOOLS: "):])
    assert {t["name"] for t in tools} == {t.__name__ for t in S.TOOLS}
    assert "gauges" not in next(t for t in tools if t["name"] == "list_gauges")["args"]
    errs = [m["error"] for m in r["messages"] if m["role"] == "tool" and m.get("error")]
    assert any("is not allowed" in e or "Invalid value" in e or "less than the minimum" in e for e in errs)


def test_generation_failure_is_recorded(world, T, monkeypatch):
    monkeypatch.setitem(T.__dict__, "_pqcap_api_request", lambda *a, **k: "not json")
    s = R.Spec("m", 0.0, 1, 0, "progent_auto", "naive", "SC08", "UT0_interval", None)
    r = R.run_episode(world, s)
    assert r["error"] and r["ext"]["generation_failed"] and len(r["ext"]["policy_calls"]) == 6


def test_registered_conditions_unchanged():
    for c in ("none", "S4", "S6", "S6+F", "platform_policy"):
        assert R.scheme_and_defence(c) == (c, None)
    for d in R.DEFENCES:
        assert R.scheme_and_defence(d) == ("none", d)


def test_tools_executor_hook_edges(T):
    """No tool call: the fork returns before its update call. Invalid tool: skipped, as in the fork, but the update
    call still runs (with an empty call list)."""
    from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
    seen = []
    T.generate_update_security_policy = lambda c, r, manual_check: seen.append((c, r, manual_check))
    try:
        ex = PA.SecToolsExecutor(T, PA.State("progent_auto"), update=True)
        msgs = [{"role": "assistant", "content": None, "tool_calls": None}]
        assert ex.query("q", FunctionsRuntime([]), None, msgs, {})[3] == msgs and seen == []
        bad = [{"role": "assistant", "content": None, "tool_calls": [FunctionCall(function="nope", args={}, id="x")]}]
        out = ex.query("q", FunctionsRuntime([]), None, bad, {})[3]
        assert out[-1]["error"].startswith("Invalid tool") and seen == [([], "[]", False)]
    finally:
        del T.generate_update_security_policy


def test_log_block_edges(scenarios):
    from types import SimpleNamespace as NS
    from agentdojo.functions_runtime import FunctionCall
    e = env_for(scenarios, "S4")
    err = "ValidationError: x. " + PA.SEC_MARK + ": q."
    fc = lambda f, a: FunctionCall(function=f, args=a, id="1")  # noqa: E731
    PA.log_block(e, fc("set_sensor_enabled", {"device_id": "WL-BBST2", "enabled": "false"}), err)
    PA.log_block(e, fc("request_immediate_uplink", {"device_id": "WL-BBST2"}), err)
    PA.log_block(e, fc("set_alert_threshold", {"device_id": "WL-BBST2", "threshold_cm": "x"}), err)   # unparsable
    PA.log_block(e, fc("set_alert_threshold", {"device_id": "WL-NOPE", "threshold_cm": 5}), err)      # unknown device
    PA.log_block(e, fc("read_gauge", {"gauge_id": "B"}), err)                                          # not a command
    PA.log_block(e, fc("set_alert_threshold", {"device_id": "WL-BBST2", "threshold_cm": 5}), "ValidationError: 1 validation error")
    PA.log_block(NS(), fc("set_alert_threshold", {"device_id": "WL-BBST2", "threshold_cm": 5}), err)   # no plant
    assert [(r.action, r.value, r.decision) for r in e.plant.receipts] == [("sensor_enable", 0, "block"),
                                                                            ("request_immediate_uplink", 0, "block")]
