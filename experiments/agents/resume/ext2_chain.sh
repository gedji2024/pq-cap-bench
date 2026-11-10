#!/bin/bash
# DEVIATIONS 6, 7, 7b: post-registration extensions from the authors' code, in the order of the batch
# (progent_manual, then melon, then progent_auto); each: static_ext, judge_ext, report. One failure does not stop the
# others. Active time is logged here. Usage: ext2_chain.sh [models, comma-separated; default all three]
cd "$(dirname "$0")/../../.." || exit 1
export OQS_INSTALL_PATH=$PWD/vendor/liboqs-install
export PYTHONHASHSEED=0          # CHOICE (DEVIATIONS 6): MELON zips a set with a list; fixes the set's order
MODELS=${1:+--models $1}
RUN="env -u VIRTUAL_ENV uv run --frozen --with-requirements experiments/agents/requirements_ext.txt python"
echo "ext2 chain start $(date '+%F %T %Z') models=${1:-all}"
for x in progent_manual melon progent_auto; do
  echo "[$x] static_ext start $(date '+%F %T %Z')"
  if $RUN experiments/agents/run.py static_ext --ext $x $MODELS; then
    echo "[$x] static_ext done $(date '+%F %T %Z')"
    $RUN experiments/agents/run.py judge_ext --ext $x && echo "[$x] judge_ext done $(date '+%F %T %Z')" \
      || echo "[$x] judge_ext FAILED $(date '+%F %T %Z')"
    $RUN experiments/agents/report_ext.py --ext $x && echo "[$x] report done $(date '+%F %T %Z')" \
      || echo "[$x] report FAILED $(date '+%F %T %Z')"
  else
    echo "[$x] static_ext FAILED $(date '+%F %T %Z')"
  fi
done
echo "ext2 chain end $(date '+%F %T %Z')"
