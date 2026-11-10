"""Post-registration extension (DEVIATIONS 6): MELON (Zhu et al., ICML 2025) from its authors' code.

The class `MELON` is loaded from the pinned clone `third_party/melon/pi_detector.py` (commit 4d3cc9c; not committed,
the repository states no licence) after its SHA-256 is checked. Its detection logic is not edited: the masked run,
`transform_tool_calls`, the tool-call bank, the cosine cutoff `> 0.8` hard-coded in `detect`, the replacement of tool
outputs and the stop message all run as written.

MELON was written for an AgentDojo whose message `content` was a plain string; at the pinned AgentDojo 089ed468 it is
a list of content blocks. The decision of 2026-11-10 (manuscript/MELON_BATCH_DECISION.md, D2) allows representation
conversions at the boundary only, and nothing else:
  (a) content read by MELON: AgentDojo's block list -> the plain text, joined as AgentDojo renders it
      (`get_text_content_as_str`: non-None blocks in order, joined by a newline);
  (b) content built by MELON (masked conversation, synthetic read_file call and result, stop message, replaced tool
      output) -> wrapped in AgentDojo's block format (`text_content_block_from_string`), text unchanged;
  (c) FunctionCall / tool-call objects: none needed (089ed468's FunctionCall has every field MELON sets).
The conversions are applied around MELON, never inside it: the messages handed to `MELON.query` are converted with
(a); the agent LLM that MELON calls is wrapped so that MELON's string-content messages go to it as blocks (b) and its
reply comes back as a string message (a); the messages MELON returns are converted back with (b). A message MELON did
not change is returned as the original object.

Embeddings (CHOICE, DEVIATIONS 6): `self.detection_model` is replaced by `OllamaEmbeddings`, whose
`embeddings.create(input, model)` ignores `model` (MELON asks for OpenAI's text-embedding-3-large) and returns Ollama's
`nomic-embed-text` embedding from the local OpenAI-compatible endpoint (api_key "ollama"). The 0.8 cutoff was set by
MELON's authors for OpenAI embeddings and is not recalibrated.

Logging: `detect` prints every cosine it computes (`cosine_sim: <value>`); the adapter captures that output and keeps
(step, comparison, value, value > 0.8, detection of the step) per episode. Nothing in the computation changes.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import re
from pathlib import Path

import openai
from agentdojo.functions_runtime import EmptyEnv
from agentdojo.types import get_text_content_as_str, text_content_block_from_string

from ..config import REPO_ROOT
from . import llm as L

MELON_COMMIT = "4d3cc9c0175cc26332aac696ac5556c3f85a5e8e"
MELON_PATH = REPO_ROOT / "third_party/melon/pi_detector.py"
MELON_SHA256 = "5a7f6b28228545e0d4ad9e98c9080ad819bb1cf471a67a31c8c4466b199a9017"
EMBED_MODEL = "nomic-embed-text"
CUTOFF = 0.8                     # MELON's hard-coded cutoff, used here only to label logged values
_COS = re.compile(r"^cosine_sim: (\S+)$", re.M)
_MOD: dict = {}


def load(path: Path = MELON_PATH, sha256: str = MELON_SHA256):
    """MELON's module from the pinned file (SHA-256 checked); loaded once per process."""
    key = str(path)
    if key not in _MOD:
        h = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if h != sha256:
            raise RuntimeError(f"{path}: sha256 {h} != pinned {sha256}")
        spec = importlib.util.spec_from_file_location("melon_pi_detector", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MOD[key] = mod
    return _MOD[key]


# ---------------------------------------------------------------- (a) / (b): representation conversions only
def to_text(m: dict) -> dict:
    """(a) AgentDojo message -> the same message with plain-string content."""
    if isinstance(m.get("content"), list):
        return {**m, "content": get_text_content_as_str(m["content"])}
    return m


def to_blocks(m: dict) -> dict:
    """(b) message with plain-string content -> AgentDojo's block format, text unchanged."""
    if isinstance(m.get("content"), str):
        return {**m, "content": [text_content_block_from_string(m["content"])]}
    return m


class TextLLM:
    """The agent LLM as MELON sees it: string-content messages in, string-content reply out."""

    def __init__(self, llm):
        self.llm, self.name = llm, getattr(llm, "name", "llm")
        self.replies: dict = {}          # id(string-content reply) -> (AgentDojo reply, its text)

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
        q, rt, e, out, ea = self.llm.query(query, runtime, env, [to_blocks(m) for m in messages], extra_args)
        t = to_text(out[-1])
        self.replies[id(t)] = (out[-1], t.get("content"), t)   # t kept alive so its id is not reused
        return q, rt, e, [*messages, t], ea


class OllamaEmbeddings:
    """Stand-in for MELON's OpenAI client: only `embeddings.create(input, model)` is used; `model` is ignored."""

    def __init__(self, cl=None, model: str = EMBED_MODEL):
        self.client = cl or openai.OpenAI(base_url=L.BASE_URL, api_key="ollama", timeout=600)
        self.model, self.calls, self.embeddings = model, 0, self

    def create(self, input, model=None):  # noqa: A002 - MELON's keyword
        self.calls += 1
        return self.client.embeddings.create(input=input, model=self.model)


def adapted_class(mod):
    """MELON's class with the boundary conversions and the cosine log around it (logic untouched)."""

    class AdaptedMELON(mod.MELON):
        def __init__(self, llm, threshold: float = 0.1, mode: str = "full_conversation",
                     raise_on_injection: bool = False, embeddings=None):
            super().__init__(TextLLM(llm), threshold=threshold, mode=mode, raise_on_injection=raise_on_injection)
            self.detection_model = embeddings if embeddings is not None else OllamaEmbeddings()
            self.cosines: list[dict] = []
            self.step = 0

        def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
            extra_args = {} if extra_args is None else extra_args
            text = [to_text(m) for m in messages]
            orig = {id(t): (m, t.get("content")) for t, m in zip(text, messages)}
            q, rt, e, out, ea = super().query(query, runtime, env, text, extra_args)
            orig.update(self.llm.replies)
            back = []
            for m in out:
                o = orig.get(id(m))
                back.append(o[0] if o is not None and m.get("content") == o[1] else to_blocks(m))
            self.llm.replies.clear()
            return q, rt, e, back, ea

        def detect(self, tool_output):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                res = super().detect(tool_output)
            self.step += 1
            detected = bool(res[1][0])
            for i, v in enumerate(_COS.findall(buf.getvalue())):
                x = float(v)
                self.cosines.append({"step": self.step, "comparison": i + 1, "cosine": x, "above_cutoff": x > CUTOFF,
                                     "step_detected": detected})
            return res

    return AdaptedMELON


def build(llm, system_message: str, embeddings=None):
    """The pipeline of MELON's README `from_config` branch:
    cls([SystemMessage(system_message), InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), MELON(llm, threshold=0.1)])])
    with the defaults mode="full_conversation", raise_on_injection=False. Returns (pipeline, detector)."""
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline  # noqa: PLC0415
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: PLC0415
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor  # noqa: PLC0415
    det = adapted_class(load())(llm, threshold=0.1, embeddings=embeddings)
    pipe = AgentPipeline([SystemMessage(system_message), InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), det])])
    pipe.name = f"{llm.name}-melon"
    return pipe, det
