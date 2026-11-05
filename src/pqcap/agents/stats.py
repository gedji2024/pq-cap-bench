"""E5 statistics: Wilson CIs, cluster bootstrap for times, exact McNemar for paired binary outcomes, Holm, power."""

from __future__ import annotations

import math

import numpy as np
from scipy import stats as sps


def wilson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    z = sps.norm.ppf(1 - alpha / 2)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def cluster_bootstrap(values: np.ndarray, clusters: np.ndarray, stat, n_boot: int, seed: int,
                      alpha: float = 0.05) -> tuple[float, float, float]:
    """Statistic and percentile CI resampling whole clusters (G4 storm clusters)."""
    v, c = np.asarray(values, dtype=float), np.asarray(clusters)
    if v.size == 0:
        return (math.nan, math.nan, math.nan)
    codes, idx = np.unique(c, return_inverse=True)
    rng = np.random.default_rng(seed)
    boots = []
    for _ in range(n_boot):
        w = rng.multinomial(len(codes), np.full(len(codes), 1 / len(codes)))[idx]
        boots.append(stat(np.repeat(v, w)) if w.sum() else math.nan)
    lo, hi = np.nanquantile(boots, [alpha / 2, 1 - alpha / 2])
    return float(stat(v)), float(lo), float(hi)


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the discordant counts b (only A) and c (only B)."""
    n = b + c
    if n == 0:
        return 1.0
    return float(min(1.0, 2 * sps.binom.cdf(min(b, c), n, 0.5)))


def holm(pvals: list[float]) -> list[float]:
    """Holm step-down adjusted p-values, in the input order."""
    m = len(pvals)
    order = sorted(range(m), key=lambda i: pvals[i])
    adj, run = [0.0] * m, 0.0
    for rank, i in enumerate(order):
        run = max(run, min(1.0, (m - rank) * pvals[i]))
        adj[i] = run
    return adj


def mcnemar_power(n_pairs: int, p10: float, p01: float, alpha: float) -> float:
    """Exact power of the two-sided exact McNemar test with n_pairs pairs, discordance probabilities p10 (only A)
    and p01 (only B): sum over the number of discordant pairs D ~ Bin(n, p10 + p01) and B | D ~ Bin(D, p10/(p10+p01))
    of P(reject)."""
    pd_ = p10 + p01
    if pd_ <= 0:
        return 0.0
    q = p10 / pd_
    power = 0.0
    for d in range(n_pairs + 1):
        pdisc = sps.binom.pmf(d, n_pairs, pd_)
        if pdisc < 1e-15 or d == 0:
            continue
        ks = np.arange(d + 1)
        p = np.minimum(1.0, 2 * sps.binom.cdf(np.minimum(ks, d - ks), d, 0.5))
        power += pdisc * float(sps.binom.pmf(ks, d, q)[p <= alpha].sum())
    return power


def clopper_pearson_upper(k: int, n: int, alpha: float = 0.05) -> float:
    """Exact one-sided (1 - alpha) upper confidence bound for a binomial proportion (Clopper-Pearson). For k = 0 it
    equals 1 - alpha**(1/n), about 3/n for alpha = 0.05 (the rule of three)."""
    if n == 0:
        return math.nan
    if k >= n:
        return 1.0
    return float(sps.beta.ppf(1 - alpha, k + 1, n - k))


def cohen_kappa(a: list, b: list) -> dict:
    """Cohen's kappa between two raters on the same items (nominal labels)."""
    if len(a) != len(b) or not a:
        raise ValueError("need two equal-length, non-empty label lists")
    n = len(a)
    cats = sorted(set(a) | set(b), key=str)
    po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    kappa = 1.0 if pe == 1 else (po - pe) / (1 - pe)
    return {"n": n, "observed_agreement": po, "expected_agreement": pe, "kappa": kappa}


def tost_cluster_bootstrap(diff: np.ndarray, clusters: np.ndarray, margin: float, n_boot: int, seed: int) -> dict:
    """Equivalence (TOST) of a paired mean difference within +-margin, by a bootstrap over clusters: p = max of the
    bootstrap shares at or below -margin and at or above +margin (one-sided tests, alpha each)."""
    v, c = np.asarray(diff, dtype=float), np.asarray(clusters)
    if v.size == 0:
        return {"estimate": math.nan, "p": math.nan, "ci90_lo": math.nan, "ci90_hi": math.nan}
    codes, idx = np.unique(c, return_inverse=True)
    rng = np.random.default_rng(seed)
    w = rng.multinomial(len(codes), np.full(len(codes), 1 / len(codes)), size=n_boot)[:, idx].astype(float)
    boot = (w * v).sum(axis=1) / w.sum(axis=1)
    lo, hi = np.quantile(boot, [0.05, 0.95])
    return {"estimate": float(v.mean()), "p": float(max((boot <= -margin).mean(), (boot >= margin).mean())),
            "ci90_lo": float(lo), "ci90_hi": float(hi)}


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact two-sided (1 - alpha) Clopper-Pearson interval."""
    if n == 0:
        return (math.nan, math.nan)
    lo = 0.0 if k == 0 else float(sps.beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(sps.beta.ppf(1 - alpha / 2, k + 1, n - k))
    return (lo, hi)
