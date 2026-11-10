#!/bin/bash
# DEVIATIONS 5: post-registration extension platform_policy: static_ext then judge_ext (active time logged here).
cd "$(dirname "$0")/../../.." || exit 1
export OQS_INSTALL_PATH=$PWD/vendor/liboqs-install
echo "ext chain start $(date '+%F %T %Z')"
env -u VIRTUAL_ENV uv run --frozen python experiments/agents/run.py static_ext || { echo "static_ext FAILED $(date '+%F %T')"; exit 1; }
echo "static_ext done $(date '+%F %T %Z')"
env -u VIRTUAL_ENV uv run --frozen python experiments/agents/run.py judge_ext || { echo "judge_ext FAILED $(date '+%F %T')"; exit 1; }
echo "ext chain end $(date '+%F %T %Z')"
