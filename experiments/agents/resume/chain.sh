#!/bin/bash
# Task E resume (DEVIATIONS 4): mistral-nemo:12b static (qwen3:8b and llama3.1:8b are complete and skipped by key),
# then the judge, then the post-judge determinism re-check. Each step runs only if the previous one exited 0.
# Started detached (resume/detach.py: setsid + nohup-style redirection); caffeinate covers this shell's lifetime.
cd "$(dirname "$0")/../../.." || exit 1
echo "chain start $(date '+%Y-%m-%d %H:%M:%S %Z') pid $$"
/usr/bin/caffeinate -i -w $$ &
echo "caffeinate pid $!"
env -u VIRTUAL_ENV uv run --frozen python experiments/agents/run.py static > experiments/agents/static_progress.log 2>&1 &&
  { echo "static done $(date '+%F %T')"; env -u VIRTUAL_ENV uv run --frozen python experiments/agents/run.py judge > experiments/agents/judge_progress.log 2>&1; } &&
  { echo "judge done $(date '+%F %T')"; env -u VIRTUAL_ENV uv run --frozen python experiments/agents/run.py determinism_sys > experiments/agents/determinism_sys_progress.log 2>&1; }
echo "chain end exit=$? $(date '+%Y-%m-%d %H:%M:%S %Z')"
