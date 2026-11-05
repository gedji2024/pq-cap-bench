#!/usr/bin/env bash
# Prove each lemma of a Tamarin theory in its own run, with a wall-clock cap, so that one non-terminating
# lemma cannot hide the results of the others.
# Usage: formal/prove.sh THEORY.spthy HEURISTIC CAP_SECONDS LEMMA...
# Writes formal/proofs/<theory>/<lemma>.txt; a killed run ends with the line "TIMEOUT after <CAP> s".
set -u
theory=$1; heur=$2; cap=$3; shift 3
out="$(dirname "$0")/proofs/$(basename "$theory" .spthy)"
mkdir -p "$out"
for lemma in "$@"; do
  (
    f="$out/$lemma.txt"
    tamarin-prover --heuristic="$heur" --prove="$lemma" "$theory" > "$f" 2>&1 &
    pid=$!
    for _ in $(seq 1 "$cap"); do kill -0 "$pid" 2>/dev/null || exit 0; sleep 1; done
    kill "$pid" 2>/dev/null; pkill -P "$pid" 2>/dev/null
    echo "TIMEOUT after $cap s (heuristic $heur)" >> "$f"
  ) &
done
wait
