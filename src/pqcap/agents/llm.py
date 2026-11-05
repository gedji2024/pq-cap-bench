"""LLM access for Task E: local Ollama through its OpenAI-compatible endpoint (no paid API).

`CachedLLM` is AgentDojo's OpenAILLM with a fixed sampling seed, optional thinking switch and a request cache.
Inference with a fixed seed is deterministic on this host (checked in the pilot, PREREG Sec. 5), so a cached
response is the response a re-query would give; conditions that share a conversation prefix reuse it. Every
call records latency and token counts, and whether it was served from the cache.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

import openai
from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLM,
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from openai.types.chat import ChatCompletionMessage

BASE_URL = "http://127.0.0.1:11434/v1"


def client() -> openai.OpenAI:
    return openai.OpenAI(base_url=BASE_URL, api_key="ollama", timeout=600)


class Cache:
    def __init__(self, path: Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.execute("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT)")

    def get(self, k: str):
        r = self.db.execute("SELECT v FROM c WHERE k = ?", (k,)).fetchone()
        return json.loads(r[0]) if r else None

    def put(self, k: str, v: dict):
        self.db.execute("INSERT OR REPLACE INTO c VALUES (?, ?)", (k, json.dumps(v)))
        self.db.commit()


def chat(cl, cache: Cache | None, digest: str, **req) -> tuple[dict, dict]:
    """One chat completion (cached). Returns (message dict, call stats)."""
    key = hashlib.sha256(json.dumps({"digest": digest, **req}, sort_keys=True, default=str).encode()).hexdigest()
    hit = cache.get(key) if cache else None
    if hit is not None:
        return hit["message"], {**hit["stats"], "cached": True, "key": key}
    t = time.time()
    r = cl.chat.completions.create(**req)
    st = {"latency_s": time.time() - t, "prompt_tokens": r.usage.prompt_tokens,
          "completion_tokens": r.usage.completion_tokens, "cached": False, "key": key}
    msg = r.choices[0].message.model_dump(exclude_none=True)
    if cache:
        cache.put(key, {"message": msg, "stats": st})
    return msg, st


class CachedLLM(OpenAILLM):
    def __init__(self, cl, model: str, digest: str, temperature: float, seed: int, cache: Cache | None,
                 think: bool | None = None):
        super().__init__(cl, model, temperature=temperature)
        self.name, self.digest, self.seed, self.cache, self.think = model, digest, seed, cache, think
        self.calls: list[dict] = []

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        extra_args = extra_args or {}
        req = {"model": self.model, "messages": [_message_to_openai(m, self.model) for m in messages],
               "temperature": self.temperature, "seed": self.seed}
        tools = [_function_to_openai(t) for t in runtime.functions.values()]
        if tools:
            req.update(tools=tools, tool_choice="auto")
        if self.think is False:
            req["reasoning_effort"] = "none"
        msg, st = chat(self.client, self.cache, self.digest, **req)
        self.calls.append(st)
        out = _openai_to_assistant_message(ChatCompletionMessage.model_validate(msg))
        return query, runtime, env, [*messages, out], extra_args


class CachedToolFilter:
    """AgentDojo's OpenAILLMToolFilter (same prompt, same tool_choice="none", same name-matching rule), with the
    call made through `chat` so it uses the same seed, thinking switch and cache as the agent LLM."""

    def __init__(self, base, llm: CachedLLM):
        self.prompt, self.llm = base.prompt, llm

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        from agentdojo.functions_runtime import FunctionCall  # noqa: F401,PLC0415  (import keeps agentdojo types loaded)
        from agentdojo.types import ChatUserMessage, get_text_content_as_str, text_content_block_from_string  # noqa: PLC0415
        msgs = [*messages, ChatUserMessage(role="user", content=[text_content_block_from_string(self.prompt)])]
        L = self.llm
        req = {"model": L.model, "messages": [_message_to_openai(m, L.model) for m in msgs], "temperature": L.temperature,
               "seed": L.seed, "tools": [_function_to_openai(t) for t in runtime.functions.values()], "tool_choice": "none"}
        if L.think is False:
            req["reasoning_effort"] = "none"
        msg, st = chat(L.client, L.cache, L.digest, **req)
        L.calls.append({**st, "element": "tool_filter"})
        out = _openai_to_assistant_message(ChatCompletionMessage.model_validate(msg))
        text = get_text_content_as_str(out["content"]) if out["content"] is not None else ""
        runtime.update_functions({n: t for n, t in runtime.functions.items() if n in text})
        return query, runtime, env, [*msgs, out], extra_args or {}
