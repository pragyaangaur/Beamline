"""NIST SP 800-22 Rev. 1a -- Statistical Test Suite for Random Number Generators.

All fifteen tests, with the parameter choices and constants from the publication.

What this suite does and does not tell you, because the distinction is routinely
overstated in RNG marketing:

  * Passing means no test found structure it was designed to detect. It is evidence of
    the ABSENCE of specific defects, not evidence of unpredictability. A counter
    encrypted with AES passes every test here and is completely predictable to anyone
    holding the key.
  * Each test returns a p-value that is uniform on [0,1] for ideal input. At the
    standard alpha = 0.01, roughly 1% of tests on a perfect generator are EXPECTED to
    fail. A run with zero failures across hundreds of p-values is itself suspicious.
  * So the suite reports two things per test: the proportion of bitstreams passing,
    checked against a binomial confidence interval, and the uniformity of the p-values
    themselves via a chi-square goodness-of-fit over ten bins. The second catches
    generators that pass individually but cluster their p-values.

For Beamline this is applied to two distinct things, and they answer different
questions: the raw harvested ANU stream (is the physical source behaving?) and the
DRBG output (is the delivery path sound?).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from .special import erfc, igamc, normal_cdf

ALPHA = 0.01


@dataclass
class TestResult:
    name: str
    p_values: list[float]
    passed: bool
    detail: str = ""
    skipped: bool = False
    reason: str = ""

    @property
    def p_value(self) -> float:
        return min(self.p_values) if self.p_values else float("nan")


def _ok(name: str, p, detail: str = "") -> TestResult:
    ps = [p] if isinstance(p, float) else list(p)
    ps = [x for x in ps if not math.isnan(x)]
    return TestResult(name, ps, all(x >= ALPHA for x in ps), detail)


def _skip(name: str, reason: str) -> TestResult:
    return TestResult(name, [], True, skipped=True, reason=reason)


# ---------------------------------------------------------------------------
# 2.1 Frequency (Monobit) Test
# ---------------------------------------------------------------------------
def frequency(bits: np.ndarray) -> TestResult:
    n = len(bits)
    s = int(np.sum(2 * bits.astype(np.int64) - 1))
    s_obs = abs(s) / math.sqrt(n)
    p = erfc(s_obs / math.sqrt(2))
    return _ok("Frequency (Monobit)", p, f"ones={int(bits.sum())}/{n} S={s}")


# ---------------------------------------------------------------------------
# 2.2 Frequency Test within a Block
# ---------------------------------------------------------------------------
def block_frequency(bits: np.ndarray, M: int = 128) -> TestResult:
    n = len(bits)
    N = n // M
    if N == 0:
        return _skip("Block Frequency", f"need >= {M} bits")
    blocks = bits[:N * M].reshape(N, M)
    pi = blocks.mean(axis=1)
    chi2 = 4.0 * M * float(np.sum((pi - 0.5) ** 2))
    p = igamc(N / 2.0, chi2 / 2.0)
    return _ok("Block Frequency", p, f"M={M} N={N} chi2={chi2:.3f}")


# ---------------------------------------------------------------------------
# 2.3 Runs Test
# ---------------------------------------------------------------------------
def runs(bits: np.ndarray) -> TestResult:
    n = len(bits)
    pi = float(bits.mean())
    # The publication's prerequisite: if the sequence fails monobit badly, the runs
    # statistic is not meaningful, so it is not computed.
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return TestResult("Runs", [0.0], False, f"failed monobit prerequisite (pi={pi:.4f})")
    v = 1 + int(np.count_nonzero(bits[1:] != bits[:-1]))
    num = abs(v - 2.0 * n * pi * (1 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)
    p = erfc(num / den)
    return _ok("Runs", p, f"runs={v} pi={pi:.5f}")


# ---------------------------------------------------------------------------
# 2.4 Test for the Longest Run of Ones in a Block
# ---------------------------------------------------------------------------
_LONGEST_RUN_PARAMS = [
    # (min_n, M, K, N, v_classes, probabilities)
    (750000, 10000, 6, 75, [10, 11, 12, 13, 14, 15, 16],
     [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]),
    (6272, 128, 5, 49, [4, 5, 6, 7, 8, 9],
     [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]),
    (128, 8, 3, 16, [1, 2, 3, 4],
     [0.2148, 0.3672, 0.2305, 0.1875]),
]


def longest_run_of_ones(bits: np.ndarray) -> TestResult:
    n = len(bits)
    for min_n, M, K, N, classes, probs in _LONGEST_RUN_PARAMS:
        if n >= min_n:
            break
    else:
        return _skip("Longest Run of Ones", "need >= 128 bits")

    blocks = bits[:N * M].reshape(N, M)
    counts = [0] * (K + 1)
    for blk in blocks:
        longest = cur = 0
        for b in blk:
            if b:
                cur += 1
                if cur > longest:
                    longest = cur
            else:
                cur = 0
        # Clamp into the first/last class, per the publication's v_i binning.
        if longest <= classes[0]:
            counts[0] += 1
        elif longest >= classes[-1]:
            counts[K] += 1
        else:
            counts[longest - classes[0]] += 1

    chi2 = sum((counts[i] - N * probs[i]) ** 2 / (N * probs[i]) for i in range(K + 1))
    p = igamc(K / 2.0, chi2 / 2.0)
    return _ok("Longest Run of Ones", p, f"M={M} N={N} chi2={chi2:.3f}")


# ---------------------------------------------------------------------------
# 2.5 Binary Matrix Rank Test
# ---------------------------------------------------------------------------
def _gf2_rank(mat: np.ndarray) -> int:
    """Rank over GF(2) by Gaussian elimination."""
    m = mat.copy().astype(np.uint8)
    rows, cols = m.shape
    rank = 0
    for c in range(cols):
        pivot = None
        for r in range(rank, rows):
            if m[r, c]:
                pivot = r
                break
        if pivot is None:
            continue
        if pivot != rank:
            m[[rank, pivot]] = m[[pivot, rank]]
        # XOR-eliminate this column from every other row that has a 1 there.
        mask = m[:, c].copy().astype(bool)
        mask[rank] = False
        m[mask] ^= m[rank]
        rank += 1
        if rank == rows:
            break
    return rank


def binary_matrix_rank(bits: np.ndarray, M: int = 32, Q: int = 32) -> TestResult:
    n = len(bits)
    N = n // (M * Q)
    if N < 38:
        return _skip("Binary Matrix Rank", f"need >= {38 * M * Q} bits for N>=38 (have N={N})")
    full = deficient1 = rest = 0
    for i in range(N):
        blk = bits[i * M * Q:(i + 1) * M * Q].reshape(M, Q)
        r = _gf2_rank(blk)
        if r == M:
            full += 1
        elif r == M - 1:
            deficient1 += 1
        else:
            rest += 1
    p_full, p_def1 = 0.2888, 0.5776
    p_rest = 1.0 - p_full - p_def1
    chi2 = ((full - N * p_full) ** 2 / (N * p_full)
            + (deficient1 - N * p_def1) ** 2 / (N * p_def1)
            + (rest - N * p_rest) ** 2 / (N * p_rest))
    p = math.exp(-chi2 / 2.0)
    return _ok("Binary Matrix Rank", p,
               f"N={N} full={full} rank-1={deficient1} lower={rest}")


# ---------------------------------------------------------------------------
# 2.6 Discrete Fourier Transform (Spectral) Test
# ---------------------------------------------------------------------------
def spectral(bits: np.ndarray) -> TestResult:
    n = len(bits)
    if n < 1000:
        return _skip("Spectral (DFT)", "need >= 1000 bits")
    n = n - (n % 2)
    x = 2.0 * bits[:n].astype(np.float64) - 1.0
    s = np.abs(np.fft.rfft(x)[:n // 2])
    threshold = math.sqrt(math.log(1.0 / 0.05) * n)
    n0 = 0.95 * n / 2.0
    n1 = float(np.count_nonzero(s < threshold))
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    p = erfc(abs(d) / math.sqrt(2))
    return _ok("Spectral (DFT)", p, f"peaks_below={int(n1)} expected={n0:.1f}")


# ---------------------------------------------------------------------------
# 2.7 Non-overlapping Template Matching Test
# ---------------------------------------------------------------------------
def _aperiodic_templates(m: int) -> list[np.ndarray]:
    """All m-bit patterns that cannot overlap a shifted copy of themselves.

    NIST ships these as static files; generating them keeps the suite self-contained.
    For m=9 this yields the standard 148 templates.
    """
    out = []
    for value in range(1 << m):
        pat = [(value >> (m - 1 - i)) & 1 for i in range(m)]
        periodic = False
        for shift in range(1, m):
            if pat[shift:] == pat[:m - shift]:
                periodic = True
                break
        if not periodic:
            out.append(np.array(pat, dtype=np.uint8))
    return out


def non_overlapping_template(bits: np.ndarray, m: int = 9, N: int = 8,
                             max_templates: int | None = None) -> TestResult:
    n = len(bits)
    M = n // N
    if M < m:
        return _skip("Non-overlapping Template", "sequence too short")

    templates = _aperiodic_templates(m)
    if max_templates:
        templates = templates[:max_templates]

    mu = (M - m + 1) / (2.0 ** m)
    var = M * (1.0 / 2.0 ** m - (2.0 * m - 1.0) / 2.0 ** (2 * m))
    if var <= 0:
        return _skip("Non-overlapping Template", "degenerate variance")

    blocks = [bits[i * M:(i + 1) * M] for i in range(N)]
    # Pack each block's m-windows into integers once, then compare against every
    # template numerically. Doing this per template with slicing is ~100x slower.
    packed_blocks = []
    weights = (1 << np.arange(m - 1, -1, -1)).astype(np.int64)
    for blk in blocks:
        w = np.lib.stride_tricks.sliding_window_view(blk.astype(np.int64), m)
        packed_blocks.append(w @ weights)

    p_values = []
    for tpl in templates:
        tval = int(tpl @ (1 << np.arange(m - 1, -1, -1)))
        counts = []
        for packed in packed_blocks:
            # Non-overlapping: after a hit, skip forward m positions.
            hits = np.flatnonzero(packed == tval)
            w = 0
            last = -m
            for h in hits:
                if h >= last + m:
                    w += 1
                    last = h
            counts.append(w)
        chi2 = sum((c - mu) ** 2 / var for c in counts)
        p_values.append(igamc(N / 2.0, chi2 / 2.0))

    failures = sum(1 for p in p_values if p < ALPHA)
    passed = failures <= max(1, int(0.02 * len(p_values)))
    return TestResult(
        "Non-overlapping Template", p_values, passed,
        f"{len(templates)} templates (m={m}), {failures} below alpha",
    )


# ---------------------------------------------------------------------------
# 2.8 Overlapping Template Matching Test
# ---------------------------------------------------------------------------
def _overlapping_pi(m: int, M: int, K: int = 5) -> list[float]:
    """Probabilities for the overlapping-template occupancy classes."""
    lam = (M - m + 1) / (2.0 ** m)
    eta = lam / 2.0
    pi = []
    for u in range(K):
        if u == 0:
            pi.append(math.exp(-eta))
        else:
            total = 0.0
            for l in range(1, u + 1):
                total += (math.exp(-eta - u * math.log(2) + l * math.log(eta)
                                   - math.lgamma(l + 1) + math.lgamma(u)
                                   - math.lgamma(l) - math.lgamma(u - l + 1)))
            pi.append(total)
    pi.append(max(0.0, 1.0 - sum(pi)))
    return pi


def overlapping_template(bits: np.ndarray, m: int = 9, M: int = 1032, K: int = 5) -> TestResult:
    n = len(bits)
    N = n // M
    if N < 1:
        return _skip("Overlapping Template", f"need >= {M} bits")

    pi = _overlapping_pi(m, M, K)
    counts = [0] * (K + 1)
    template = np.ones(m, dtype=np.int64)
    weights = (1 << np.arange(m - 1, -1, -1)).astype(np.int64)
    tval = int(template @ weights)

    for i in range(N):
        blk = bits[i * M:(i + 1) * M].astype(np.int64)
        w = np.lib.stride_tricks.sliding_window_view(blk, m)
        v = int(np.count_nonzero((w @ weights) == tval))
        counts[min(v, K)] += 1

    chi2 = 0.0
    for i in range(K + 1):
        expected = N * pi[i]
        if expected > 0:
            chi2 += (counts[i] - expected) ** 2 / expected
    p = igamc(K / 2.0, chi2 / 2.0)
    return _ok("Overlapping Template", p, f"N={N} chi2={chi2:.3f} counts={counts}")


# ---------------------------------------------------------------------------
# 2.9 Maurer's "Universal Statistical" Test
# ---------------------------------------------------------------------------
_MAURER = {
    6: (5.2177052, 2.954), 7: (6.1962507, 3.125), 8: (7.1836656, 3.238),
    9: (8.1764248, 3.311), 10: (9.1723243, 3.356), 11: (10.170032, 3.384),
    12: (11.168765, 3.401), 13: (12.168070, 3.410), 14: (13.167693, 3.416),
    15: (14.167488, 3.419), 16: (15.167379, 3.421),
}
_MAURER_MIN_N = {
    6: 387840, 7: 904960, 8: 2068480, 9: 4654080, 10: 10342400,
    11: 22753280, 12: 49643520, 13: 107560960, 14: 231669760,
    15: 496435200, 16: 1059061760,
}


def universal(bits: np.ndarray) -> TestResult:
    n = len(bits)
    L = None
    for cand in range(16, 5, -1):
        if n >= _MAURER_MIN_N[cand]:
            L = cand
            break
    if L is None:
        return _skip("Maurer Universal", f"need >= {_MAURER_MIN_N[6]:,} bits (have {n:,})")

    Q = 10 * (1 << L)
    K = n // L - Q
    expected, variance = _MAURER[L]

    weights = (1 << np.arange(L - 1, -1, -1)).astype(np.int64)
    words = bits[:(Q + K) * L].reshape(-1, L).astype(np.int64) @ weights

    table = np.zeros(1 << L, dtype=np.int64)
    for i in range(Q):
        table[words[i]] = i + 1

    total = 0.0
    for i in range(Q, Q + K):
        w = words[i]
        total += math.log2(i + 1 - table[w])
        table[w] = i + 1
    fn = total / K

    c = 0.7 - 0.8 / L + (4 + 32.0 / L) * (K ** (-3.0 / L)) / 15
    sigma = c * math.sqrt(variance / K)
    p = erfc(abs((fn - expected) / (math.sqrt(2) * sigma)))
    return _ok("Maurer Universal", p, f"L={L} K={K} fn={fn:.6f} expected={expected:.6f}")


# ---------------------------------------------------------------------------
# 2.10 Linear Complexity Test
# ---------------------------------------------------------------------------
def _berlekamp_massey(seq: np.ndarray) -> int:
    """Linear complexity of a binary sequence over GF(2).

    The discrepancy step is the O(M^2) part of this algorithm; computing it as a
    vector dot product rather than a Python loop is what makes the Linear Complexity
    test tractable (it runs Berlekamp-Massey once per 500-bit block, thousands of
    times per megabit stream).
    """
    n = len(seq)
    seq = seq.astype(np.uint8)
    c = np.zeros(n + 1, dtype=np.uint8)
    b = np.zeros(n + 1, dtype=np.uint8)
    c[0] = b[0] = 1
    l = 0
    m = -1
    for i in range(n):
        if l > 0:
            # d = seq[i] XOR sum_{j=1..l} c[j] & seq[i-j]   (mod 2)
            # seq[i-1], seq[i-2], ..., seq[i-l] paired against c[1..l]
            window = seq[i - l:i][::-1]
            d = int(seq[i]) ^ (int(np.dot(c[1:l + 1], window)) & 1)
        else:
            d = int(seq[i])
        if d:
            t = c.copy()
            shift = i - m
            if shift < n + 1:
                c[shift:] ^= b[:n + 1 - shift]
            if 2 * l <= i:
                l = i + 1 - l
                m = i
                b = t
    return l


def linear_complexity(bits: np.ndarray, M: int = 500) -> TestResult:
    n = len(bits)
    N = n // M
    if N < 1:
        return _skip("Linear Complexity", f"need >= {M} bits")
    # The publication recommends N >= 200 for the chi-square to be meaningful.
    if N < 200:
        return _skip("Linear Complexity", f"need N>=200 blocks of {M} bits (have {N})")

    mu = (M / 2.0 + (9.0 + (-1) ** (M + 1)) / 36.0 - (M / 3.0 + 2.0 / 9.0) / (2.0 ** M))
    pi = [0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833]
    counts = [0] * 7
    for i in range(N):
        li = _berlekamp_massey(bits[i * M:(i + 1) * M])
        t = ((-1) ** M) * (li - mu) + 2.0 / 9.0
        if t <= -2.5: counts[0] += 1
        elif t <= -1.5: counts[1] += 1
        elif t <= -0.5: counts[2] += 1
        elif t <= 0.5: counts[3] += 1
        elif t <= 1.5: counts[4] += 1
        elif t <= 2.5: counts[5] += 1
        else: counts[6] += 1

    chi2 = sum((counts[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(7))
    p = igamc(3.0, chi2 / 2.0)
    return _ok("Linear Complexity", p, f"M={M} N={N} chi2={chi2:.3f}")


# ---------------------------------------------------------------------------
# 2.11 Serial Test
# ---------------------------------------------------------------------------
def _psi2(bits: np.ndarray, m: int) -> float:
    n = len(bits)
    if m <= 0:
        return 0.0
    extended = np.concatenate([bits, bits[:m - 1]]) if m > 1 else bits
    weights = (1 << np.arange(m - 1, -1, -1)).astype(np.int64)
    w = np.lib.stride_tricks.sliding_window_view(extended.astype(np.int64), m)[:n]
    vals = w @ weights
    counts = np.bincount(vals, minlength=1 << m).astype(np.float64)
    return float((counts ** 2).sum()) * (2 ** m) / n - n


def serial(bits: np.ndarray, m: int = 16) -> TestResult:
    n = len(bits)
    while m > 2 and (1 << m) > n / 10:
        m -= 1                       # keep expected cell counts meaningful
    if m < 3:
        return _skip("Serial", "sequence too short")
    p0, p1, p2 = _psi2(bits, m), _psi2(bits, m - 1), _psi2(bits, m - 2)
    d1 = p0 - p1
    d2 = p0 - 2 * p1 + p2
    pa = igamc(2 ** (m - 2), d1 / 2.0)
    pb = igamc(2 ** (m - 3), d2 / 2.0)
    return _ok("Serial", [pa, pb], f"m={m} del1={d1:.3f} del2={d2:.3f}")


# ---------------------------------------------------------------------------
# 2.12 Approximate Entropy Test
# ---------------------------------------------------------------------------
def _phi(bits: np.ndarray, m: int) -> float:
    n = len(bits)
    extended = np.concatenate([bits, bits[:m - 1]]) if m > 1 else bits
    weights = (1 << np.arange(m - 1, -1, -1)).astype(np.int64)
    w = np.lib.stride_tricks.sliding_window_view(extended.astype(np.int64), m)[:n]
    counts = np.bincount(w @ weights, minlength=1 << m).astype(np.float64)
    probs = counts[counts > 0] / n
    return float(np.sum(probs * np.log(probs)))


def approximate_entropy(bits: np.ndarray, m: int = 10) -> TestResult:
    n = len(bits)
    while m > 2 and (1 << (m + 1)) > n / 10:
        m -= 1
    if m < 2:
        return _skip("Approximate Entropy", "sequence too short")
    ap_en = _phi(bits, m) - _phi(bits, m + 1)
    chi2 = 2.0 * n * (math.log(2) - ap_en)
    p = igamc(2 ** (m - 1), chi2 / 2.0)
    return _ok("Approximate Entropy", p, f"m={m} ApEn={ap_en:.6f}")


# ---------------------------------------------------------------------------
# 2.13 Cumulative Sums (Cusum) Test
# ---------------------------------------------------------------------------
def cumulative_sums(bits: np.ndarray) -> TestResult:
    n = len(bits)
    x = 2 * bits.astype(np.int64) - 1
    results = []
    for mode in (0, 1):
        s = np.cumsum(x if mode == 0 else x[::-1])
        z = int(np.max(np.abs(s)))
        if z == 0:
            results.append(1.0)
            continue
        total = 0.0
        start = int((-n / z + 1) // 4)
        for k in range(start, int((n / z - 1) // 4) + 1):
            total += (normal_cdf((4 * k + 1) * z / math.sqrt(n))
                      - normal_cdf((4 * k - 1) * z / math.sqrt(n)))
        sub = 0.0
        start = int((-n / z - 3) // 4)
        for k in range(start, int((n / z - 1) // 4) + 1):
            sub += (normal_cdf((4 * k + 3) * z / math.sqrt(n))
                    - normal_cdf((4 * k + 1) * z / math.sqrt(n)))
        results.append(max(0.0, min(1.0, 1.0 - total + sub)))
    return _ok("Cumulative Sums", results, "forward and backward")


# ---------------------------------------------------------------------------
# 2.14 / 2.15 Random Excursions and Random Excursions Variant
# ---------------------------------------------------------------------------
_EXCURSION_PI = {
    1: [0.5000, 0.2500, 0.1250, 0.0625, 0.0312, 0.0312],
    2: [0.7500, 0.0625, 0.0469, 0.0352, 0.0264, 0.0791],
    3: [0.8333, 0.0278, 0.0231, 0.0193, 0.0161, 0.0804],
    4: [0.8750, 0.0156, 0.0137, 0.0120, 0.0105, 0.0733],
    5: [0.9000, 0.0100, 0.0090, 0.0081, 0.0073, 0.0656],
    6: [0.9167, 0.0069, 0.0064, 0.0058, 0.0053, 0.0588],
    7: [0.9286, 0.0051, 0.0047, 0.0044, 0.0041, 0.0531],
}


def random_excursions(bits: np.ndarray) -> TestResult:
    x = 2 * bits.astype(np.int64) - 1
    s = np.concatenate([[0], np.cumsum(x), [0]])
    zero_positions = np.flatnonzero(s == 0)
    J = len(zero_positions) - 1
    if J < 500:
        return _skip("Random Excursions", f"need >= 500 cycles (have {J})")

    states = [-4, -3, -2, -1, 1, 2, 3, 4]
    counts = {st: [0] * 6 for st in states}
    for i in range(J):
        cycle = s[zero_positions[i]:zero_positions[i + 1] + 1]
        vals, cnts = np.unique(cycle, return_counts=True)
        seen = dict(zip(vals.tolist(), cnts.tolist()))
        for st in states:
            counts[st][min(seen.get(st, 0), 5)] += 1

    p_values = []
    for st in states:
        pi = _EXCURSION_PI[abs(st)]
        chi2 = sum((counts[st][k] - J * pi[k]) ** 2 / (J * pi[k]) for k in range(6))
        p_values.append(igamc(2.5, chi2 / 2.0))
    return _ok("Random Excursions", p_values, f"J={J} cycles, 8 states")


def random_excursions_variant(bits: np.ndarray) -> TestResult:
    x = 2 * bits.astype(np.int64) - 1
    s = np.concatenate([[0], np.cumsum(x), [0]])
    J = int(np.count_nonzero(s == 0)) - 1
    if J < 500:
        return _skip("Random Excursions Variant", f"need >= 500 cycles (have {J})")

    p_values = []
    for st in list(range(-9, 0)) + list(range(1, 10)):
        xi = int(np.count_nonzero(s == st))
        denom = math.sqrt(2.0 * J * (4.0 * abs(st) - 2.0))
        p_values.append(erfc(abs(xi - J) / denom))
    return _ok("Random Excursions Variant", p_values, f"J={J} cycles, 18 states")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
ALL_TESTS = [
    ("frequency", frequency),
    ("block_frequency", block_frequency),
    ("runs", runs),
    ("longest_run_of_ones", longest_run_of_ones),
    ("binary_matrix_rank", binary_matrix_rank),
    ("spectral", spectral),
    ("non_overlapping_template", non_overlapping_template),
    ("overlapping_template", overlapping_template),
    ("universal", universal),
    ("linear_complexity", linear_complexity),
    ("serial", serial),
    ("approximate_entropy", approximate_entropy),
    ("cumulative_sums", cumulative_sums),
    ("random_excursions", random_excursions),
    ("random_excursions_variant", random_excursions_variant),
]


def bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def run_all(bits: np.ndarray, skip: set[str] | None = None) -> list[TestResult]:
    skip = skip or set()
    out = []
    for name, fn in ALL_TESTS:
        if name in skip:
            continue
        try:
            out.append(fn(bits))
        except Exception as e:  # a crashing test must not hide the other fourteen
            out.append(TestResult(name, [], False, detail=f"error: {type(e).__name__}: {e}"))
    return out


def uniformity_of_pvalues(p_values: list[float]) -> tuple[float, bool]:
    """Chi-square goodness-of-fit of p-values against uniform, over 10 bins.

    This is the check that catches a generator whose individual tests all pass while
    its p-values cluster -- a real defect signature that per-test pass/fail misses.
    """
    if len(p_values) < 20:
        return float("nan"), True
    counts = [0] * 10
    for p in p_values:
        counts[min(9, int(p * 10))] += 1
    expected = len(p_values) / 10.0
    chi2 = sum((c - expected) ** 2 / expected for c in counts)
    p = igamc(4.5, chi2 / 2.0)
    return p, p >= 0.0001


def proportion_confidence_interval(n_streams: int, alpha: float = ALPHA) -> tuple[float, float]:
    """Acceptable pass-proportion range for `n_streams` bitstreams (SP 800-22 4.2.1)."""
    p_hat = 1.0 - alpha
    margin = 3.0 * math.sqrt(p_hat * alpha / n_streams)
    return (p_hat - margin, min(1.0, p_hat + margin))
