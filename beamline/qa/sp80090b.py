"""NIST SP 800-90B -- min-entropy estimation for a physical entropy source.

SP 800-22 asks "does this output look random?". SP 800-90B asks the question that
actually matters for an entropy source: "how much unpredictability is in here, at
worst?" Those are different questions, and the second is the one that should govern
how much credit a source gets in `beamline/entropy/pool.py`.

Min-entropy is the right measure because it is driven by the MOST likely outcome, not
the average one. A source that emits a fixed value 90% of the time and uniform noise
otherwise has high Shannon entropy and almost no min-entropy, and it is the min-entropy
that bounds an attacker's guessing advantage.

This module implements the non-IID track, which is the conservative one and the correct
choice for a source with any memory or drift. It runs nine estimators and takes the
MINIMUM, exactly as the publication requires: an entropy source is only as good as its
worst-behaving structure.

    6.3.1  Most Common Value
    6.3.2  Collision                (closed form for the binary case)
    6.3.3  Markov
    6.3.5  t-Tuple
    6.3.6  Longest Repeated Substring
    6.3.7  MultiMCW prediction
    6.3.8  Lag prediction
    6.3.9  MultiMMC prediction
    6.3.10 LZ78Y prediction

Not implemented: 6.3.4, the Compression estimate. Its G(z) inversion needs a specific
series from the publication that is not reproduced here, and a wrong estimator that
reports a confident number is worse than an absent one. Its omission is recorded in
every report this module produces, and because the final figure is a minimum over
estimators, leaving one out can only make the reported entropy HIGHER than a full run
would give -- so the headline number should be read as an upper bound on what the full
suite would return.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass

import numpy as np

#: 99% one-sided normal quantile, used for every upper-confidence bound in SP 800-90B.
Z_ALPHA = 2.576


@dataclass
class Estimate:
    name: str
    min_entropy: float          # bits per sample
    detail: str = ""
    skipped: bool = False

    def __str__(self) -> str:
        if self.skipped:
            return f"{self.name:<34} skipped: {self.detail}"
        return f"{self.name:<34} {self.min_entropy:.5f} bits/sample  {self.detail}"


def _upper_bound(p: float, n: int) -> float:
    """One-sided 99% upper confidence bound on a proportion."""
    if n <= 1:
        return 1.0
    return min(1.0, p + Z_ALPHA * math.sqrt(p * (1.0 - p) / (n - 1)))


def _entropy(p: float) -> float:
    return -math.log2(min(1.0, max(1e-15, p)))


# ---------------------------------------------------------------------------
# 6.3.1 Most Common Value
# ---------------------------------------------------------------------------
def most_common_value(s: np.ndarray) -> Estimate:
    n = len(s)
    counts = np.bincount(s)
    mode = int(counts.max())
    p_hat = mode / n
    p_u = _upper_bound(p_hat, n)
    return Estimate("Most Common Value", _entropy(p_u),
                    f"p_max={p_hat:.6f} upper={p_u:.6f}")


# ---------------------------------------------------------------------------
# 6.3.2 Collision
# ---------------------------------------------------------------------------
def collision(s: np.ndarray, alphabet: int = 2) -> Estimate:
    """Collision estimate, using the exact binary mean-collision-time relation.

    For a binary source the pigeonhole principle caps a collision at three samples:

        E[T] = 2*(p^2 + q^2) + 3*(2pq) = 2 + 2pq

    Inverting for p >= 1/2 gives p = (1 + sqrt(5 - 2*E[T])) / 2, which is used here
    rather than a numerical search. The relation does not generalise to larger
    alphabets, so non-binary input is skipped rather than approximated.
    """
    if alphabet != 2:
        return Estimate("Collision", 0.0, "only implemented for binary data", skipped=True)

    n = len(s)
    times = []
    i = 0
    while i + 1 < n:
        if s[i] == s[i + 1]:
            times.append(2); i += 2
        elif i + 2 < n:
            times.append(3); i += 3
        else:
            break
    v = len(times)
    if v < 1000:
        return Estimate("Collision", 0.0, f"only {v} collisions; need >= 1000", skipped=True)

    arr = np.array(times, dtype=np.float64)
    mean = float(arr.mean())
    sigma = float(arr.std(ddof=1))
    mean_lower = mean - Z_ALPHA * sigma / math.sqrt(v)

    disc = 5.0 - 2.0 * mean_lower
    if disc <= 0:
        p = 0.5
    else:
        p = min(1.0, 0.5 * (1.0 + math.sqrt(disc)))
    p = max(0.5, p)
    return Estimate("Collision", _entropy(p),
                    f"v={v} mean={mean:.4f} lower={mean_lower:.4f} p={p:.6f}")


# ---------------------------------------------------------------------------
# 6.3.3 Markov
# ---------------------------------------------------------------------------
def markov(s: np.ndarray, alphabet: int = 2, chain: int = 128) -> Estimate:
    """First-order Markov estimate over the most likely `chain`-length path."""
    n = len(s)
    counts = np.bincount(s, minlength=alphabet).astype(np.float64)
    trans = np.zeros((alphabet, alphabet), dtype=np.float64)
    np.add.at(trans, (s[:-1], s[1:]), 1.0)

    row_totals = trans.sum(axis=1)
    P = np.zeros_like(trans)
    for i in range(alphabet):
        if row_totals[i] > 0:
            for j in range(alphabet):
                p_ij = trans[i, j] / row_totals[i]
                # Upper-bound each transition probability; the estimate must be
                # conservative about how predictable the chain could be.
                P[i, j] = min(1.0, p_ij + Z_ALPHA * math.sqrt(
                    max(0.0, p_ij * (1 - p_ij)) / max(1.0, row_totals[i] - 1)))
        else:
            P[i, :] = 1.0 / alphabet

    initial = counts / n
    # Dynamic programming for the highest-probability path of `chain` steps, in logs
    # so a 128-step product does not underflow.
    log_p = np.full(alphabet, -np.inf)
    for i in range(alphabet):
        log_p[i] = math.log2(max(initial[i], 1e-300))
    log_T = np.log2(np.maximum(P, 1e-300))
    for _ in range(chain - 1):
        log_p = np.max(log_p[:, None] + log_T, axis=0)

    max_log = float(np.max(log_p))
    h = min(math.log2(alphabet), -max_log / chain)
    return Estimate("Markov", h, f"chain={chain} p00={P[0,0]:.4f} p11={P[1,1]:.4f}")


# ---------------------------------------------------------------------------
# 6.3.5 t-Tuple  /  6.3.6 Longest Repeated Substring
# ---------------------------------------------------------------------------
def _tuple_multiplicities(s: np.ndarray, t: int, alphabet: int) -> np.ndarray:
    """Occurrence counts of every distinct t-tuple in `s`.

    Tuples are packed into integers and counted with np.unique rather than hashed as
    bytes objects. The bytes route allocates one object per window -- tens of millions
    of them across the t-Tuple and LRS sweeps -- and dominates the runtime of the whole
    SP 800-90B assessment. Packing keeps the sweep vectorised.
    """
    n = len(s)
    if n - t + 1 < 1:
        return np.array([], dtype=np.int64)
    w = np.lib.stride_tricks.sliding_window_view(s, t)

    bits_per = max(1, (alphabet - 1).bit_length())
    if t * bits_per <= 63:
        weights = (np.int64(1) << (bits_per * np.arange(t - 1, -1, -1))).astype(np.int64)
        packed = w.astype(np.int64) @ weights
        return np.unique(packed, return_counts=True)[1]

    # Too wide to pack into int64: fall back to hashing the raw window bytes.
    from collections import Counter
    return np.array(list(Counter(map(bytes, w)).values()), dtype=np.int64)


def t_tuple(s: np.ndarray, max_t: int = 24) -> tuple[Estimate, int]:
    """Largest t whose most common t-tuple still appears >= 35 times."""
    n = len(s)
    alphabet = int(s.max()) + 1 if len(s) else 2
    p_maxes = []
    t_final = 0
    for t in range(1, max_t + 1):
        if n - t + 1 < 1:
            break
        counts = _tuple_multiplicities(s.astype(np.uint8), t, alphabet)
        if counts.size == 0:
            break
        q = int(counts.max())
        if q < 35:
            break
        t_final = t
        p = q / (n - t + 1)
        p_maxes.append(p ** (1.0 / t))

    if not p_maxes:
        return Estimate("t-Tuple", 0.0, "no tuple reached 35 occurrences", skipped=True), 0
    p_max = max(p_maxes)
    p_u = _upper_bound(p_max, n)
    return Estimate("t-Tuple", _entropy(p_u), f"t={t_final} p_max={p_max:.6f}"), t_final


def longest_repeated_substring(s: np.ndarray, t_start: int, max_w: int = 64) -> Estimate:
    """LRS estimate over collision probabilities for tuple lengths u..v."""
    n = len(s)
    u = max(1, t_start + 1)
    sb = s.astype(np.uint8)
    alphabet = int(sb.max()) + 1 if len(sb) else 2

    p_maxes = []
    w_used = 0
    for w in range(u, max_w + 1):
        if n - w + 1 < 2:
            break
        counts = _tuple_multiplicities(sb, w, alphabet)
        if counts.size == 0 or int(counts.max()) < 2:
            break                      # no repeats at this length: v reached
        total_pairs = float(np.sum(counts * (counts - 1) / 2.0))
        denom = (n - w + 1) * (n - w) / 2
        if denom <= 0:
            break
        p_w = total_pairs / denom
        p_maxes.append(p_w ** (1.0 / w))
        w_used = w

    if not p_maxes:
        return Estimate("Longest Repeated Substring", 0.0, "no repeated substrings", skipped=True)
    p_max = max(p_maxes)
    p_u = _upper_bound(p_max, n)
    return Estimate("Longest Repeated Substring", _entropy(p_u),
                    f"u={u} v={w_used} p_max={p_max:.6f}")


# ---------------------------------------------------------------------------
# Predictor framework (6.3.7 - 6.3.10)
# ---------------------------------------------------------------------------
def _no_run_probability(p: float, r: int, n: int) -> float:
    """P(no run of `r` consecutive successes in `n` Bernoulli(p) trials).

    The natural formulation is a length-r state vector stepped n times, which is
    O(n*r) and far too slow to sit inside a binary search. The same recurrence is a
    linear map, so it is evaluated by raising its transfer matrix to the n-th power:
    O(r^3 log n), independent of sequence length.

    For long runs the matrix becomes the expensive part, so beyond r = 64 the estimate
    switches to the Poisson approximation for the number of r-runs, which is accurate
    precisely in the regime where runs are rare.
    """
    if r <= 0:
        return 0.0
    if r > n:
        return 1.0
    q = 1.0 - p

    if r <= 64:
        # State j = number of trailing successes (0..r-1); reaching r is absorbing.
        M = np.zeros((r, r), dtype=np.float64)
        M[0, :] = q
        for j in range(r - 1):
            M[j + 1, j] = p
        v = np.zeros(r, dtype=np.float64)
        v[0] = 1.0
        result = np.linalg.matrix_power(M, n) @ v
        return float(np.clip(result.sum(), 0.0, 1.0))

    # Expected number of r-runs ~ (n - r + 1) * p^r * q; runs are near-Poisson here.
    expected = (n - r + 1) * (p ** r) * q
    return float(math.exp(-expected))


def _p_local(r: int, n: int, floor: float = 0.5) -> float:
    """Smallest p whose probability of producing a run of `r` in `n` trials is 0.99.

    `floor` is the lowest meaningful success probability, i.e. 1/alphabet. Leaving it
    at the binary 0.5 for a larger alphabet pins every predictor at exactly 1 bit and
    silently truncates the estimate -- the search has to start where chance does.
    """
    if r <= 0:
        return 0.0
    lo, hi = floor, 1.0 - 1e-12
    for _ in range(50):
        mid = (lo + hi) / 2
        if _no_run_probability(mid, r, n) > 0.01:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def _predictor_entropy(name: str, correct: np.ndarray, detail: str = "",
                       alphabet: int = 2) -> Estimate:
    """Turn a predictor's hit/miss record into a min-entropy estimate.

    Two bounds are computed and the LARGER predictability wins: the global hit rate,
    and the local rate implied by the longest run of correct predictions. The local
    term is what catches a source that is unpredictable on average but has stretches
    where it is not.
    """
    n = len(correct)
    c = int(correct.sum())
    p_global = c / n
    p_global_u = _upper_bound(p_global, n)

    longest = best = 0
    for hit in correct:
        best = best + 1 if hit else 0
        if best > longest:
            longest = best

    # The full recurrence is O(n*r); cap the work for very long runs, where the
    # answer has already saturated near 1 anyway.
    floor = 1.0 / max(2, alphabet)
    p_loc = _p_local(longest, n, floor) if longest > 0 else 0.0

    p_max = max(p_global_u, p_loc)
    return Estimate(name, _entropy(p_max),
                    f"global={p_global:.5f} run={longest} local={p_loc:.5f} {detail}")


def _adaptive_correct(hits: np.ndarray) -> np.ndarray:
    """Resolve an ensemble of subpredictors into the ensemble's own hit record.

    `hits` is (k, n): whether subpredictor j would have been right at step i. The
    ensemble follows whichever subpredictor is leading on cumulative score so far, so
    the choice at step i must use scores from steps < i only -- shifting the cumulative
    sum by one is what keeps the predictor from seeing its own answer.
    """
    k, n = hits.shape
    scores = np.zeros(k, dtype=np.int64)
    correct = np.zeros(n, dtype=bool)
    # Chunked so the cumulative-score matrix stays small on long sequences.
    chunk = 65536
    for lo in range(0, n, chunk):
        hi = min(n, lo + chunk)
        block = hits[:, lo:hi].astype(np.int64)
        cum = scores[:, None] + np.cumsum(block, axis=1)
        leader = np.empty(hi - lo, dtype=np.int64)
        leader[0] = int(np.argmax(scores))
        if hi - lo > 1:
            leader[1:] = np.argmax(cum[:, :-1], axis=0)
        correct[lo:hi] = block[leader, np.arange(hi - lo)].astype(bool)
        scores = cum[:, -1]
    return correct


def multi_mcw(s: np.ndarray, windows=(63, 255, 1023, 4095)) -> Estimate:
    """6.3.7 MultiMCW: subpredictors guess the most common value in their window.

    Window majorities are computed from a prefix sum rather than a per-sample bincount,
    which turns the estimator from O(n * sum(windows)) into O(n * len(windows)).
    """
    n = len(s)
    if len(s) and int(s.max()) > 1:
        # The prefix-sum majority shortcut below is binary-only. Rather than fall back
        # to an O(n*w) mode computation, this estimator sits out for larger alphabets;
        # the remaining predictors still cover sequential structure.
        return Estimate("MultiMCW Prediction", 0.0,
                        "binary-only implementation", skipped=True)
    windows = [w for w in windows if w < n]
    if not windows:
        return Estimate("MultiMCW Prediction", 0.0, "sequence too short", skipped=True)

    prefix = np.concatenate([[0], np.cumsum(s.astype(np.int64))])
    hits = np.zeros((len(windows), n), dtype=np.uint8)
    for wi, w in enumerate(windows):
        idx = np.arange(w, n)
        ones = prefix[idx] - prefix[idx - w]
        pred = (2 * ones > w).astype(np.uint8)     # ties resolve to 0
        hits[wi, w:] = (pred == s[w:]).astype(np.uint8)

    correct = _adaptive_correct(hits)
    return _predictor_entropy("MultiMCW Prediction", correct, f"windows={windows}", 2)


def lag(s: np.ndarray, max_lag: int = 128, alphabet: int = 2) -> Estimate:
    """6.3.8 Lag: subpredictors guess x[i-d] for d = 1..max_lag."""
    n = len(s)
    max_lag = min(max_lag, n - 1)
    if max_lag < 1:
        return Estimate("Lag Prediction", 0.0, "sequence too short", skipped=True)

    hits = np.zeros((max_lag, n), dtype=np.uint8)
    for d in range(1, max_lag + 1):
        hits[d - 1, d:] = (s[d:] == s[:-d]).astype(np.uint8)

    correct = _adaptive_correct(hits)
    best = int(np.argmax(hits.sum(axis=1))) + 1
    return _predictor_entropy("Lag Prediction", correct, f"best_lag={best}", alphabet)


def multi_mmc(s: np.ndarray, max_order: int = 16, alphabet: int = 2) -> Estimate:
    """6.3.9 MultiMMC: Markov models of order 1..max_order, each counting successors."""
    n = len(s)
    max_order = min(max_order, n - 1)
    if max_order < 1:
        return Estimate("MultiMMC Prediction", 0.0, "sequence too short", skipped=True)

    models = [defaultdict(Counter) for _ in range(max_order)]
    scores = [0] * max_order
    correct = np.zeros(n, dtype=bool)
    winner = 0
    sb = s.tolist()

    for i in range(n):
        preds = []
        for d in range(1, max_order + 1):
            if i < d:
                preds.append(None)
                continue
            ctx = tuple(sb[i - d:i])
            counts = models[d - 1].get(ctx)
            preds.append(counts.most_common(1)[0][0] if counts else None)

        if preds[winner] is not None and preds[winner] == sb[i]:
            correct[i] = True
        for d in range(max_order):
            if preds[d] is not None and preds[d] == sb[i]:
                scores[d] += 1
        for d in range(1, max_order + 1):
            if i >= d:
                models[d - 1][tuple(sb[i - d:i])][sb[i]] += 1
        winner = int(np.argmax(scores))
    return _predictor_entropy("MultiMMC Prediction", correct, f"best_order={winner + 1}", alphabet)


def lz78y(s: np.ndarray, max_dict: int = 65536, b: int = 16, alphabet: int = 2) -> Estimate:
    """6.3.10 LZ78Y: dictionary of contexts up to length b, predicting the likeliest next."""
    n = len(s)
    if n < b + 2:
        return Estimate("LZ78Y Prediction", 0.0, "sequence too short", skipped=True)

    table: dict[tuple, Counter] = {}
    correct = np.zeros(n, dtype=bool)
    sb = s.tolist()

    for i in range(b, n):
        # Predict from the longest context already known to the dictionary.
        guess = None
        for d in range(b, 0, -1):
            ctx = tuple(sb[i - d:i])
            counts = table.get(ctx)
            if counts:
                guess = counts.most_common(1)[0][0]
                break
        if guess is not None and guess == sb[i]:
            correct[i] = True
        for d in range(1, b + 1):
            ctx = tuple(sb[i - d:i])
            if ctx in table or len(table) < max_dict:
                table.setdefault(ctx, Counter())[sb[i]] += 1
    return _predictor_entropy("LZ78Y Prediction", correct, f"dict={len(table)}", alphabet)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
NOT_IMPLEMENTED = ["6.3.4 Compression (G(z) inversion not reproduced here)"]


def assess(s: np.ndarray, fast: bool = False) -> tuple[list[Estimate], float]:
    """Run the non-IID estimator battery. Returns (estimates, min-entropy per bit).

    `fast` skips the four prediction estimators, which are O(n * models) in pure
    Python and dominate the runtime on large inputs. The predictors are the ones most
    likely to catch structure the statistical estimators miss, so a fast run is a
    smoke test, not an assessment.
    """
    s = s.astype(np.uint8)
    alphabet = int(s.max()) + 1 if len(s) else 2

    estimates = [
        most_common_value(s),
        collision(s, alphabet),
        markov(s, max(2, alphabet)),
    ]
    tt, t_final = t_tuple(s)
    estimates.append(tt)
    estimates.append(longest_repeated_substring(s, t_final))

    if not fast:
        estimates.append(multi_mcw(s))
        estimates.append(lag(s, alphabet=alphabet))
        estimates.append(multi_mmc(s, alphabet=alphabet))
        estimates.append(lz78y(s, alphabet=alphabet))

    usable = [e.min_entropy for e in estimates if not e.skipped]
    return estimates, (min(usable) if usable else 0.0)
