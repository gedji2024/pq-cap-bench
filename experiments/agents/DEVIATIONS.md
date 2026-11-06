# Task E deviations from PREREG.md

Every change made after PREREG.md was committed is listed here with its date, reason and effect. Nothing is
removed from this file.

| # | Date | Change | Reason | Effect on results |
|---|---|---|---|---|
| 1 | 2026-11-06 | System prompt sent as role `system` instead of AgentDojo's `developer` (`pqcap.agents.llm.to_ollama`, test in `tests/test_agents.py`); the static phase (3432 episodes) and judge re-run with the registered design, seed and attacks unchanged. The first run is kept as `logs/static_v0_sysdrop/`, `logs/judge_v0_sysdrop/`, `results_v0_sysdrop/`, `RESULTS_v0_sysdrop.md`, `results/labelling_v0_sysdrop/` (SUPERSEDED). | Found after the v0 run because naive and limit-aware episodes had identical answers in 571/572 (qwen3) and 536/572 (mistral-nemo) pairs. Ollama 0.40.14 chat templates drop `developer` messages: on 2026-11-06, with a codeword placed in the system prompt, all three models recalled it with role `system` and not with role `developer` (prompt tokens 63/56/41 vs 31/25/16). The pilot, the determinism check and the power and runtime figures in PREREG Sec. 5 therefore also ran without the system prompt; they are not re-done. | v0 agent-behaviour results are void: the registered prompts were never applied. H-b (device-side) was 0/240 in v0 too. Runtime per episode may rise (longer prompts); the 30 h cap of design.yaml applies to the re-run. |
