"""Plain-Python statistics for NetSum benchmarks (no NumPy/SciPy): percentiles,
bootstrap confidence intervals, a permutation test with Cliff's delta as the
statistic, Holm-Bonferroni correction, and a bootstrap CI for a ratio of
medians. All resampling takes an explicit random.Random so results are
reproducible from the recorded seed. See docs/DESIGN_NOTES.md §Benchmark
methodology."""

BOOTSTRAP_RESAMPLES = 2000
PERMUTATION_ITERS = 2000
RNG_SEED = 1234


def percentile(sorted_vals, p):
    """Linear interpolation (NumPy's default) over a sorted list, p in [0, 100]."""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def median(vals):
    return percentile(sorted(vals), 50)


def bootstrap_ci(vals, rng, stat=median, resamples=BOOTSTRAP_RESAMPLES, alpha=0.05):
    """Percentile-bootstrap CI of stat(vals), resampling the given units."""
    n = len(vals)
    if n == 0:
        return (float("nan"), float("nan"))
    draws = sorted(stat([vals[rng.randrange(n)] for _ in range(n)]) for _ in range(resamples))
    return (percentile(draws, 100 * alpha / 2), percentile(draws, 100 * (1 - alpha / 2)))


def ratio_of_medians_ci(a, b, rng, resamples=BOOTSTRAP_RESAMPLES, alpha=0.05):
    """Bootstrap CI for median(a) / median(b), resampling each group independently."""
    if not a or not b:
        return (float("nan"), float("nan"))
    draws = []
    for _ in range(resamples):
        ra = median([a[rng.randrange(len(a))] for _ in a])
        rb = median([b[rng.randrange(len(b))] for _ in b])
        draws.append(ra / rb if rb else float("inf"))
    draws.sort()
    return (percentile(draws, 100 * alpha / 2), percentile(draws, 100 * (1 - alpha / 2)))


def cliffs_delta(a, b):
    """P(a > b) - P(a < b) over all pairs, in [-1, 1]."""
    if not a or not b:
        return 0.0
    gt = lt = 0
    for x in a:
        for y in b:
            gt += x > y
            lt += x < y
    return (gt - lt) / (len(a) * len(b))


def permutation_test(a, b, rng, iters=PERMUTATION_ITERS):
    """Two-sided permutation test with |Cliff's delta| as the statistic.
    Returns (observed delta, p-value with add-one smoothing)."""
    observed = cliffs_delta(a, b)
    pooled = list(a) + list(b)
    n_a = len(a)
    extreme = 0
    for _ in range(iters):
        rng.shuffle(pooled)
        if abs(cliffs_delta(pooled[:n_a], pooled[n_a:])) >= abs(observed):
            extreme += 1
    return observed, (extreme + 1) / (iters + 1)


def holm(pvals):
    """Holm-Bonferroni adjusted p-values, in the input order."""
    m = len(pvals)
    order = sorted(range(m), key=lambda i: pvals[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvals[i]))
        adjusted[i] = running
    return adjusted
