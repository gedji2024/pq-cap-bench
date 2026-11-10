"""Post-registration extension (DEVIATIONS 7 / 7b): Progent (Shi et al., `shi2025progent`) from its authors' code.

Only the `secagent` library of https://github.com/sunblaze-ucb/progent (commit b02783b, MIT; pinned clone in
`third_party/progent/`, not committed) is used: policy checker, policy generation and policy update. Every loaded
file's SHA-256 is checked first. `secagent` is not edited. Its two extra dependencies (jsonschema, z3-solver) come
from `experiments/agents/requirements_ext.txt` (hashed), loaded with `uv run --with-requirements`; uv.lock unchanged.

The authors' AgentDojo fork hooks `secagent` in at four places; the same calls are made here at AgentDojo 089ed468:
  default_suites/v1/<suite>/task_suite.py:39-44   tools wrapped with `apply_secure_tool_wrapper` before AgentDojo
                                                  builds them; `update_always_allowed_tools([...], allow_all_no_arg_tools=True)`
  agent_pipeline/basic_elements.py:25             `generate_security_policy(query)` in InitQuery
  agent_pipeline/tool_execution.py:121-123        `generate_update_security_policy(intermediate_calls,
                                                  str(intermediate_results), manual_check=False)` if SECAGENT_UPDATE
  benchmark.py:197,205                            policy reset before each task
A blocked call raises secagent's ValidationError inside the tool; AgentDojo returns it as its normal tool error.

Conditions:
  progent_manual  device scheme S4 (as platform_policy, of which it is the authentic twin). Hand-written policy in
                  secagent's format: the read tools allowed; each command tool allowed only for the actions and
                  argument ranges of that device's S6 envelope rules; anything else falls through to secagent's
                  fallback 0 (tool error). Generation and update off. The S6 *invariants* (alert / battery state) are
                  not per-argument ranges and are left out (CHOICE, DEVIATIONS 7); nothing outside secagent enforces them.
  progent_auto    device scheme none. Generation and update on, with the values of the authors' run.sh
                  (SECAGENT_UPDATE=True, SECAGENT_IGNORE_UPDATE_ERROR=True, SECAGENT_GENERATE default True,
                  SECAGENT_ONLY_ALLOW_NARROW unset); policy model = the agent's own local model through Ollama's
                  OpenAI-compatible endpoint (CHOICE; the paper uses gpt-4o-2024-08-06); authors' prompts verbatim.

CHOICES of the adaptation (DEVIATIONS 7 / 7b):
  - secagent reads SECAGENT_* at import; the process runs several models, so the same values are set as the module
    attributes those variables initialise (`policy_model`, `generate_policy`, `ignore_update_error`).
  - OpenAI() in secagent reads OPENAI_BASE_URL / OPENAI_API_KEY: set to Ollama (http://127.0.0.1:11434/v1, "ollama").
  - The tool list the policy model sees (`available_tools`) is set to the tools as the agent sees them (AgentDojo's
    name, description and argument schema, including a poisoned description on the TOOL channel). secagent's own
    wrapper would derive it from the Python docstring and, for our tools without documented parameters, would list
    the dict / list dependency arguments AgentDojo hides; the fork's suites have no such arguments.
  - Always-allowed tools (progent_auto): the tools with no agent-visible argument (list_gauges, read_bulletins,
    list_devices), the effect of the fork's allow_all_no_arg_tools on its own suites.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import contextlib
from pathlib import Path

from agentdojo.agent_pipeline.basic_elements import InitQuery
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.types import get_text_content_as_str

from ..config import REPO_ROOT
from . import llm as L
from . import plant as P

PROGENT_COMMIT = "b02783b896d4bf01a2adf24738015e258db8d35b"
ROOT = REPO_ROOT / "third_party/progent"
SHA256 = {
    "secagent/__init__.py": "edd5b4df72a48e671a89aad5365a90aaf21b828802434bc79a2d1f5fe4f70cf9",
    "secagent/tool.py": "59b2cd642a9c29f2459e919720fae935a5f6f99a2a5fa0c17f1ea95e9efbcd52",
    "secagent/utils.py": "6b185684f5255acc33fcbaa615ec408368981f2a1f2902b4b28803fa188338e1",
    "secagent/policy_analysis.py": "9d39f97ef74363e5489632a7d2bc7531c61e0ce2e76a0cec563e4a12b204b751",
    "secagent/role_analyzer.py": "19b0bc3d0c750602abf348372f97a998e57222aecdcd5e1a87880686d732a0cc",
}
RUN_SH = {"SECAGENT_UPDATE": "True", "SECAGENT_IGNORE_UPDATE_ERROR": "True", "SECAGENT_GENERATE": "True"}
READ_TOOLS = ("list_gauges", "read_gauge", "read_bulletins", "list_devices", "read_device_status",
              "get_rainfall_forecast")
NO_ARG_TOOLS = ("list_gauges", "read_bulletins", "list_devices")
CMD_ARG = {"set_reporting_interval": ("set_reporting_interval", "minutes"),
           "request_immediate_uplink": ("request_immediate_uplink", None),
           "set_sensor_enabled": ("sensor_enable", "enabled"),
           "set_alert_threshold": ("set_alert_threshold", "threshold_cm")}
_SEC: list = []


def load(root: Path = ROOT, sha: dict = SHA256):
    """secagent's `tool` module from the pinned clone (every loaded file's SHA-256 checked first)."""
    if not _SEC:
        for rel, want in sha.items():
            h = hashlib.sha256((Path(root) / rel).read_bytes()).hexdigest()
            if h != want:
                raise RuntimeError(f"{rel}: sha256 {h} != pinned {want}")
        os.environ["OPENAI_BASE_URL"] = L.BASE_URL
        os.environ["OPENAI_API_KEY"] = "ollama"
        for k, v in RUN_SH.items():
            os.environ.setdefault(k, v)
        sys.path.insert(0, str(root))
        with contextlib.redirect_stderr(io.StringIO()):
            import secagent.tool as T  # noqa: PLC0415
        sys.path.remove(str(root))
        _SEC.append(T)
    return _SEC[0]


def manual_policy(plant: P.Plant) -> dict:
    """secagent policy {tool: [(priority, effect 0=allow, {arg: JSON schema}, fallback 0=tool error)]} from each
    device's S6 envelope rules (per-argument ranges only)."""
    pol = {t: [(1, 0, {}, 0)] for t in READ_TOOLS}
    for tool, (action, arg) in CMD_ARG.items():
        rows = []
        for d in plant.devices.values():
            r = d.envelope.rules.get(P.ACTIONS[action])
            if r is None:
                continue
            cond = {"device_id": {"type": "string", "enum": [d.id]}}
            if arg == "enabled":
                vals = [bool(v) for v in (0, 1) if r.lo <= v <= r.hi]
                if not vals:
                    continue
                cond[arg] = {"type": "boolean", "enum": vals}
            elif arg is not None:
                cond[arg] = {"type": "integer", "minimum": r.lo, "maximum": r.hi}
            elif not r.lo <= 0 <= r.hi:
                continue
            rows.append((1, 0, cond, 0))
        if rows:
            pol[tool] = rows
    return pol


class State:
    """Per-episode record: policies in force (with SHA-256), policy-model calls, generation failures, blocks."""

    def __init__(self, condition: str):
        self.condition, self.policies, self.calls, self.generation_failed = condition, [], [], False

    def snap(self, T, event: str):
        p = json.dumps(T.get_current_config(), sort_keys=True, default=str)
        self.policies.append({"event": event, "policy": p, "sha256": hashlib.sha256(p.encode()).hexdigest()})

    def record(self) -> dict:
        return {"condition": self.condition, "policies": self.policies, "policy_calls": self.calls,
                "generation_failed": self.generation_failed}


class SecInitQuery(InitQuery):
    """InitQuery with the fork's `generate_security_policy(query)` (basic_elements.py:25)."""

    def __init__(self, T, state: State):
        self.T, self.state = T, state

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        try:
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.T.generate_security_policy(query)
        except Exception:
            self.state.generation_failed = True
            raise
        self.state.snap(self.T, "generate")
        return super().query(query, runtime, env, messages, {} if extra_args is None else extra_args)


class SecToolsExecutor(ToolsExecutor):
    """ToolsExecutor with the fork's update call (tool_execution.py:121-123) on the executed calls of this step."""

    def __init__(self, T, state: State, update: bool):
        super().__init__()
        self.T, self.state, self.update = T, state, update

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        extra_args = {} if extra_args is None else extra_args
        n = len(messages)
        q, rt, e, out, ea = super().query(query, runtime, env, messages, extra_args)
        if len(out) == n:          # the fork returns early (no tool call) before its update call
            return q, rt, e, out, ea
        calls, results = [], []
        for m in out[n:]:
            err = m.get("error") or ""
            if err.startswith(("Empty function name", "Invalid tool")):
                continue            # the fork skips these before appending to intermediate_calls
            log_block(e, m["tool_call"], err)
            calls.append({"name": m["tool_call"].function, "args": m["tool_call"].args})
            results.append(get_text_content_as_str(m["content"]))
        if self.update:
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.T.generate_update_security_policy(calls, str(results), manual_check=False)
            self.state.snap(self.T, "update")
        return q, rt, e, out, ea


SEC_MARK = "Please try other tools or arguments and continue to finish the user task"   # secagent's check_tool_call


def log_block(env, tool_call, err: str):
    """Logging only (as platform_policy logs its blocks): a device command that secagent refused is recorded as a
    plant receipt with decision `block`, reason `progent`, no tag, so the registered outcome classes see the attempt
    (blocked_by_scheme). Nothing is sent and no device state changes; enforcement stays in secagent."""
    if not err.startswith("ValidationError") or SEC_MARK not in err or tool_call.function not in CMD_ARG:
        return
    plant = getattr(env, "plant", None)
    action, arg = CMD_ARG[tool_call.function]
    dev = tool_call.args.get("device_id")
    if plant is None or dev not in plant.devices:
        return
    try:
        v = None if arg is None else tool_call.args[arg]
        if arg == "enabled" and isinstance(v, str):      # as AgentDojo's (pydantic) validation reads it
            v = v.strip().lower() in ("true", "1", "yes", "on")
        value = 0 if arg is None else int(v)
    except (KeyError, TypeError, ValueError):
        return
    plant.receipts.append(P.Receipt(len(plant.receipts) + 1, dev, action, value, "block", "progent", None))


def _logged(T, state: State):
    """Pass-through around secagent's api_request recording each policy-model call (no change to its result)."""
    base = T.__dict__.setdefault("_pqcap_api_request", T.api_request)

    def api_request(sys_prompt, user_prompt, temperature=0.0):
        r = base(sys_prompt, user_prompt, temperature)
        state.calls.append({"temperature": temperature, "sys_prompt_sha256": hashlib.sha256(sys_prompt.encode()).hexdigest()[:16],
                            "response": r})
        return r
    return api_request


def setup(condition: str, model: str, suite_fns: list, plant: P.Plant, T=None):
    """Fresh secagent state for one episode; returns (wrapped AgentDojo functions, State, update flag)."""
    T = T or load()
    state = State(condition)
    with contextlib.redirect_stderr(io.StringIO()):
        T.update_security_policy(None)
        T.update_available_tools([])
    T.api_request = _logged(T, state)
    T.policy_model = model
    T.ignore_update_error = RUN_SH["SECAGENT_IGNORE_UPDATE_ERROR"] == "True"
    auto = condition == "progent_auto"
    T.generate_policy = auto
    with contextlib.redirect_stderr(io.StringIO()):
        wrapped = [f.model_copy(update={"run": T.apply_secure_tool_wrapper(f.run)}) for f in suite_fns]
        T.update_available_tools([{"name": f.name, "description": f.description,
                                   "args": f.parameters.model_json_schema().get("properties", {})} for f in suite_fns])
        if auto:
            T.update_always_allowed_tools(list(NO_ARG_TOOLS), allow_all_no_arg_tools=True)
        else:
            T.update_security_policy(manual_policy(plant))
    return wrapped, state, auto


def build(condition: str, llm, system_message: str, suite_fns: list, plant: P.Plant, T=None):
    """Pipeline: AgentDojo's default (SystemMessage, InitQuery, llm, ToolsExecutionLoop([ToolsExecutor, llm])) with
    the fork's two hooks. Returns (pipeline, wrapped functions, State)."""
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline  # noqa: PLC0415
    from agentdojo.agent_pipeline.basic_elements import SystemMessage  # noqa: PLC0415
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop  # noqa: PLC0415
    T = T or load()
    fns, state, update = setup(condition, llm.name, suite_fns, plant, T)
    pipe = AgentPipeline([SystemMessage(system_message), SecInitQuery(T, state), llm,
                          ToolsExecutionLoop([SecToolsExecutor(T, state, update), llm])])
    pipe.name = f"{llm.name}-{condition}"
    return pipe, fns, state
