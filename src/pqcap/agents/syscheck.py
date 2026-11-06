"""Per-model system-prompt check (DEVIATIONS #1): is the system prompt in the prompt the model is given?

For one episode, the agent's first chat request is captured exactly as the runner builds it (no LLM call), then
sent to the local Ollama server with and without its system message. Recorded per request:
  prompt_eval_count     native /api/chat (num_predict 1);
  v1 prompt_tokens      the OpenAI-compatible endpoint the runner uses (max_tokens 1);
  rendered prompt       /api/chat with `_debug_render_only` (the template Ollama applied, filled in).
The system text alone is counted with /api/generate raw (no template). The check passes when both differences
(with - without) are > 0, the v1 difference is within TOL tokens of the system text's own count, and the system
text occurs in the rendered prompt with it and not in the one without it.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from types import SimpleNamespace

from pqcap.agents import runner as R

BASE = "http://127.0.0.1:11434"
TOL = 10   # CHOICE: template tokens around a system message (role header, separators, BOS)


class _Captured(Exception):
    pass


def post(path: str, body: dict) -> dict:  # pragma: no cover - local Ollama HTTP call
    rq = urllib.request.Request(BASE + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(rq, timeout=600) as r:
        return json.load(r)


def first_request(world: R.World, spec: R.Spec) -> dict:
    """The first chat request of `spec` as the runner sends it; the call is intercepted, nothing is generated."""
    box: dict = {}

    def create(**req):
        box.update(req)
        raise _Captured

    real, cache = world.client, world.cache
    world.client, world.cache = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))), None
    try:
        R.run_episode(world, spec)
    finally:
        world.client, world.cache = real, cache
    return box


def text(content) -> str:
    if isinstance(content, str):
        return content
    return "".join(b.get("text", "") for b in content or [])


def native(req: dict) -> dict:
    b = {"model": req["model"], "stream": False,
         "messages": [{"role": m["role"], "content": text(m.get("content"))} for m in req["messages"]],
         "options": {"temperature": req.get("temperature", 0.0), "seed": req.get("seed", 0), "num_predict": 1}}
    if req.get("tools"):
        b["tools"] = req["tools"]
    if req.get("reasoning_effort") == "none":
        b["think"] = False
    return b


def check(req: dict, post=post) -> dict:
    sysmsgs = [m for m in req["messages"] if m["role"] == "system"]
    s = text(sysmsgs[0]["content"]).strip() if sysmsgs else ""
    variants = {"with": req, "without": {**req, "messages": [m for m in req["messages"] if m["role"] != "system"]}}
    out: dict = {"model": req["model"], "system_chars": len(s)}
    for k, r in variants.items():
        b = native(r)
        out[f"prompt_eval_count_{k}"] = post("/api/chat", b)["prompt_eval_count"]
        out[f"v1_prompt_tokens_{k}"] = post("/v1/chat/completions", {**r, "max_tokens": 1})["usage"]["prompt_tokens"]
        out[f"rendered_{k}"] = post("/api/chat", {**b, "_debug_render_only": True})["_debug_info"]["rendered_template"]
    tpl = post("/api/show", {"model": req["model"]}).get("template", "")
    out["template_sha256"] = hashlib.sha256(tpl.encode()).hexdigest()
    out["template"] = tpl
    out["system_tokens_raw"] = post("/api/generate", {"model": req["model"], "prompt": s, "raw": True, "stream": False,
                                                       "options": {"num_predict": 1}})["prompt_eval_count"]
    out["diff_native"] = out["prompt_eval_count_with"] - out["prompt_eval_count_without"]
    out["diff_v1"] = out["v1_prompt_tokens_with"] - out["v1_prompt_tokens_without"]
    out["wrapper_tokens"] = out["diff_v1"] - out["system_tokens_raw"]
    out["system_text_rendered"] = bool(s) and s in out["rendered_with"] and s not in out["rendered_without"]
    out["ok"] = bool(out["diff_native"] > 0 and out["diff_v1"] > 0 and abs(out["wrapper_tokens"]) <= TOL
                     and out["system_text_rendered"])
    return out
