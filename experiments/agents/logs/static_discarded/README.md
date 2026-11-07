# DISCARDED - not analysed

`mistral-nemo_12b_t0.0_partial_20261106.jsonl`: the first 54 of 1144 mistral-nemo:12b static re-run episodes,
written between 22:23 and 22:38:37 EST on 2026-11-06, when the run was stopped because the host was unavailable
until Saturday (DEVIATIONS 3). They are kept for transparency only. They are not read by `report.py` or any
analysis (which read `logs/static/`), and mistral-nemo:12b is re-run from scratch.

`mistral-nemo_12b_t0.0_partial_20261107_cachereplay.jsonl`: 56 episodes from the first resume start, 2026-11-07
09:17:33-09:18:45 EST. Stopped because the request cache still held the 2026-11-06 partial run's responses, so
these episodes replayed them instead of running from scratch (DEVIATIONS 4). The 111 cache rows written by both
mistral-nemo:12b starts (rowid > 10574, all after llama3.1:8b's last entry) were deleted before the restart.
DISCARDED, not analysed.
