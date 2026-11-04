"""Host timing and size benchmark.

Protocol (config/bench.yaml): for each run r in 1..runs, each algorithm, each op:
  `warmup` untimed calls, then `iterations` calls each timed with
  time.perf_counter_ns(). keygen is message-independent; sign/verify are run
  for every message size. Every signature produced in the timed sign loop has
  its length recorded (Falcon signatures are variable-length).

Outputs:
  results/bench_raw.csv.gz      one row per timed call (run, alg, op, msg_len, iter, ns, sig_len)
  results/bench_runs.csv        per-run statistics (median, q1, q3, iqr, p95, mean)
  results/bench_summary.csv     across-run summary + run-to-run variation
  results/sizes.csv             pk / sk / signature min/median/max (observed)
  results/kem_sizes.csv         ML-KEM pk / sk / ciphertext / shared secret (observed)
  results/algorithms.csv        requested -> resolved liboqs name, or reason unavailable
"""

from __future__ import annotations

import csv
import gc
import gzip
import os
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from .algorithms import build_algorithms
from .config import load_yaml
from .oqs_loader import load_oqs

pc = time.perf_counter_ns


def pin_cpu(core: int) -> str:
    if hasattr(os, "sched_setaffinity"):
        try:
            os.sched_setaffinity(0, {core})
            return f"pinned to core {core} via sched_setaffinity"
        except OSError as exc:
            return f"pinning failed: {exc}"
    return f"pinning unsupported on {sys.platform} (no sched_setaffinity); process not pinned"


def stats(ns: np.ndarray) -> dict:
    q1, med, q3, p95 = np.percentile(ns, [25, 50, 75, 95])
    return {"n": int(ns.size), "median_ns": float(med), "q1_ns": float(q1), "q3_ns": float(q3),
            "iqr_ns": float(q3 - q1), "p95_ns": float(p95), "mean_ns": float(ns.mean()),
            "min_ns": float(ns.min()), "max_ns": float(ns.max())}


def _timed(fn, n_warm, n_iter, gc_off, pre=None):
    """Time `fn` n_iter times after n_warm warm-up calls. `pre` (untimed) runs before each call."""
    for _ in range(n_warm):
        if pre:
            pre()
        fn()
    out = np.empty(n_iter, dtype=np.int64)
    rets = [None] * n_iter
    if gc_off:
        gc.disable()
    try:
        for i in range(n_iter):
            if pre:
                pre()
            t0 = pc()
            rets[i] = fn()
            out[i] = pc() - t0
    finally:
        if gc_off:
            gc.enable()
    return out, rets


def bench_sig(alg, msgs, cfg, run, writer, sig_obs):
    W, N, gc_off = cfg["warmup"], cfg["iterations"], cfg["disable_gc_during_timing"]
    stateful = alg.kind == "stateful"
    rows = []

    ns, _ = _timed(alg.keygen, W, N, gc_off)
    rows.append(("keygen", 0, ns, None))

    for m in msgs:
        # Stateful: untimed re-key whenever the one-time-signature budget is exhausted.
        pre = (lambda: alg.ensure_budget(2)) if stateful else None
        ns, sigs = _timed(lambda m=m: alg.sign(m), W, N, gc_off, pre)
        lens = np.fromiter((len(s) for s in sigs), dtype=np.int64, count=N)
        sig_obs.setdefault(alg.name, []).extend(lens.tolist())
        rows.append(("sign", len(m), ns, lens))

        sig = sigs[-1]
        assert alg.verify(m, sig), f"{alg.name}: verification failed"
        ns, oks = _timed(lambda m=m, s=sig: alg.verify(m, s), W, N, gc_off)
        assert all(oks), f"{alg.name}: verification failed in timed loop"
        rows.append(("verify", len(m), ns, None))

    for op, mlen, ns, lens in rows:
        for i in range(ns.size):
            writer.writerow([run, alg.name, alg.impl_name, alg.kind, op, mlen, i, int(ns[i]),
                             "" if lens is None else int(lens[i])])
    return [(op, mlen, ns) for op, mlen, ns, _ in rows]


def bench_kem(kem, cfg, run, writer):
    W, N, gc_off = cfg["warmup"], cfg["iterations"], cfg["disable_gc_during_timing"]
    rows = []
    ns, _ = _timed(kem.keygen, W, N, gc_off)
    rows.append(("keygen", ns))
    ns, encs = _timed(kem.encaps, W, N, gc_off)
    rows.append(("encaps", ns))
    ct, ss = encs[-1]
    ns, decs = _timed(lambda: kem.decaps(ct), W, N, gc_off)
    assert decs[-1] == ss, f"{kem.name}: decapsulation mismatch"
    rows.append(("decaps", ns))
    for op, ns in rows:
        for i in range(ns.size):
            writer.writerow([run, kem.name, kem.impl_name, "kem", op, 0, i, int(ns[i]), ""])
    sizes = {"algorithm": kem.name, "impl_name": kem.impl_name, "pk_bytes": kem.pk_bytes,
             "sk_bytes": kem.sk_bytes, "ct_bytes": len(ct), "ss_bytes": len(ss)}
    return [(op, 0, ns) for op, ns in rows], sizes


def run(bench_cfg_path: Path, results: Path) -> None:
    cfg = load_yaml(bench_cfg_path)
    results.mkdir(parents=True, exist_ok=True)
    pin_note = pin_cpu(cfg["pin_cpu"])
    print(f"[bench] {pin_note}", flush=True)

    oqs = load_oqs()
    algs, kems, resolutions = build_algorithms(cfg, oqs)
    pd.DataFrame([r.__dict__ for r in resolutions]).assign(
        candidates=lambda d: d["candidates"].map(lambda c: ";".join(c))
    ).to_csv(results / "algorithms.csv", index=False)

    rng = random.Random(cfg["seed"])
    msgs = [bytes(rng.getrandbits(8) for _ in range(n)) for n in cfg["message_sizes"]]

    per_run, sig_obs, kem_sizes, key_sizes = [], {}, {}, {}
    with gzip.open(results / "bench_raw.csv.gz", "wt", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run", "algorithm", "impl_name", "kind", "op", "msg_len", "iter", "ns", "sig_len"])
        for r in range(1, cfg["runs"] + 1):
            for alg in algs:
                t0 = time.time()
                for op, mlen, ns in bench_sig(alg, msgs, cfg, r, w, sig_obs):
                    per_run.append({"run": r, "algorithm": alg.name, "impl_name": alg.impl_name,
                                    "kind": alg.kind, "op": op, "msg_len": mlen, **stats(ns)})
                key_sizes[alg.name] = (alg.impl_name, alg.kind, alg.pk_bytes, alg.sk_bytes,
                                       getattr(alg, "nominal_sig_bytes", lambda: None)())
                print(f"[bench] run {r} {alg.name:24s} {time.time() - t0:7.1f}s", flush=True)
            for kem in kems:
                rows, kem_sizes[kem.name] = bench_kem(kem, cfg, r, w)
                for op, mlen, ns in rows:
                    per_run.append({"run": r, "algorithm": kem.name, "impl_name": kem.impl_name,
                                    "kind": "kem", "op": op, "msg_len": mlen, **stats(ns)})
                print(f"[bench] run {r} {kem.name}", flush=True)

    runs = pd.DataFrame(per_run)
    runs.to_csv(results / "bench_runs.csv", index=False)
    summarize(results / "bench_raw.csv.gz", runs).to_csv(results / "bench_summary.csv", index=False)

    size_rows = []
    for name, (impl, kind, pk, sk, nominal) in key_sizes.items():
        obs = np.asarray(sig_obs[name])
        size_rows.append({"algorithm": name, "impl_name": impl, "kind": kind, "pk_bytes": pk,
                          "sk_bytes": sk, "sig_min": int(obs.min()), "sig_median": float(np.median(obs)),
                          "sig_max": int(obs.max()), "sig_n_observed": int(obs.size),
                          "sig_liboqs_nominal_max": nominal if nominal is not None else ""})
    pd.DataFrame(size_rows).to_csv(results / "sizes.csv", index=False)
    pd.DataFrame(list(kem_sizes.values())).to_csv(results / "kem_sizes.csv", index=False)
    (results / "bench_meta.txt").write_text(f"{pin_note}\n")


def summarize(raw_path: Path, runs: pd.DataFrame) -> pd.DataFrame:
    """Pooled statistics over all runs + run-to-run variation of the per-run medians."""
    raw = pd.read_csv(raw_path, usecols=["algorithm", "op", "msg_len", "ns"])
    keys = ["algorithm", "op", "msg_len"]
    pooled = raw.groupby(keys, sort=False)["ns"].apply(lambda s: pd.Series(stats(s.to_numpy()))).unstack()
    pooled.columns = [f"pooled_{c}" for c in pooled.columns]
    rr = runs.groupby(keys, sort=False)["median_ns"].agg(
        run_median_min_ns="min", run_median_max_ns="max", run_median_mean_ns="mean",
        run_median_std_ns="std", n_runs="count")
    rr["run_to_run_cv"] = rr["run_median_std_ns"] / rr["run_median_mean_ns"]
    rr["run_to_run_range_rel"] = (rr["run_median_max_ns"] - rr["run_median_min_ns"]) / rr["run_median_mean_ns"]
    meta = runs.groupby(keys, sort=False)[["impl_name", "kind"]].first()
    return meta.join(pooled).join(rr).reset_index()
