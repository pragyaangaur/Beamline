"""Validation of the NIST suite implementations.

The point of these tests is not to check that random data passes. Any suite passes
random data, including a suite that does nothing at all. What matters is that the
implementations DETECT defects, and that the min-entropy estimators never report more
entropy than a source actually has.

Marked slow where relevant; the whole file still runs in well under a minute.
"""

from __future__ import annotations

import hashlib
import math
import os

import pytest

np = pytest.importorskip("numpy")

from beamline.qa import sp80022 as S
from beamline.qa import sp80090b as B
from beamline.qa.special import igamc, normal_cdf

N = 200_000


def rand_bits(n_bytes: int) -> np.ndarray:
    return S.bytes_to_bits(os.urandom(n_bytes))


class TestSpecialFunctions:
    @pytest.mark.parametrize("a,x,expected", [
        (0.5, 0.5, 0.317311),    # chi2=1,  df=1
        (1.0, 1.0, 0.367879),    # chi2=2,  df=2
        (5.0, 5.0, 0.440493),    # chi2=10, df=10
        (1.5, 3.0, 0.111610),    # chi2=6,  df=3
        (2.0, 4.0, 0.091578),    # chi2=8,  df=4
    ])
    def test_igamc_matches_chi_square_tables(self, a, x, expected):
        assert igamc(a, x) == pytest.approx(expected, abs=2e-3)

    def test_igamc_boundaries(self):
        assert igamc(1.0, 0.0) == 1.0
        assert igamc(1.0, 100.0) < 1e-40

    def test_igamc_is_monotonic(self):
        vals = [igamc(2.0, x) for x in (0.5, 1.0, 2.0, 4.0, 8.0)]
        assert vals == sorted(vals, reverse=True)

    def test_normal_cdf(self):
        assert normal_cdf(0.0) == pytest.approx(0.5)
        assert normal_cdf(1.96) == pytest.approx(0.975, abs=1e-3)
        assert normal_cdf(-1.96) == pytest.approx(0.025, abs=1e-3)


class TestSp80022Structure:
    def test_all_fifteen_tests_present(self):
        assert len(S.ALL_TESTS) == 15

    def test_aperiodic_template_count(self):
        """NIST specifies 148 aperiodic templates for m=9."""
        assert len(S._aperiodic_templates(9)) == 148
        assert len(S._aperiodic_templates(2)) == 2

    def test_longest_run_parameter_tables_are_consistent(self):
        for _min_n, _M, K, _N, classes, probs in S._LONGEST_RUN_PARAMS:
            assert len(classes) == K + 1 == len(probs)
            assert sum(probs) == pytest.approx(1.0, abs=1e-3)

    def test_berlekamp_massey_recovers_lfsr_degree(self):
        for degree, tap in ((7, 5), (11, 8)):
            state = [1] * degree
            out = []
            for _ in range(degree * 80):
                bit = state[degree - 1] ^ state[tap]
                out.append(state[degree - 1])
                state = [bit] + state[:degree - 1]
            assert S._berlekamp_massey(np.array(out, dtype=np.uint8)) == degree

    def test_berlekamp_massey_on_random_is_about_half(self):
        seq = np.frombuffer(os.urandom(64), dtype=np.uint8)
        bits = np.unpackbits(seq)[:500]
        assert 200 < S._berlekamp_massey(bits) < 300

    def test_gf2_rank(self):
        identity = np.eye(8, dtype=np.uint8)
        assert S._gf2_rank(identity) == 8
        singular = identity.copy()
        singular[7] = singular[6]
        assert S._gf2_rank(singular) == 7
        assert S._gf2_rank(np.zeros((8, 8), dtype=np.uint8)) == 0


class TestSp80022DetectsDefects:
    """Each of these must fire. A suite that misses them is decorative."""

    def _failures(self, bits) -> list[str]:
        skip = {"universal", "linear_complexity", "non_overlapping_template"}
        return [r.name for r in S.run_all(bits, skip=skip)
                if not r.skipped and not r.passed]

    @pytest.mark.parametrize("label,bits", [
        ("all zeros", np.zeros(N, dtype=np.uint8)),
        ("all ones", np.ones(N, dtype=np.uint8)),
        ("alternating", np.tile([0, 1], N // 2).astype(np.uint8)),
        ("period-8", np.tile([1, 1, 0, 1, 0, 0, 0, 1], N // 8).astype(np.uint8)),
    ])
    def test_degenerate_sequences_are_caught(self, label, bits):
        assert self._failures(bits), f"{label} went undetected"

    @pytest.mark.parametrize("p", [0.51, 0.505])
    def test_small_bias_is_caught(self, p):
        rng = np.random.default_rng(4)
        bits = (rng.random(N) < p).astype(np.uint8)
        failures = self._failures(bits)
        assert "Frequency (Monobit)" in failures, f"a {abs(p-0.5):.1%} bias slipped through"

    def test_counter_is_caught(self):
        ctr = np.frombuffer(np.arange(N // 32, dtype="<u4").tobytes(), dtype=np.uint8)
        assert self._failures(np.unpackbits(ctr))

    def test_weak_lcg_is_caught(self):
        x, out = 12345, []
        for _ in range(N // 8):
            x = (65539 * x) % (2 ** 31)
            out.append(x & 0xFF)
        assert self._failures(np.unpackbits(np.array(out, dtype=np.uint8)))

    def test_good_sources_pass(self):
        """A good source may fire one test by chance; it must not fire two.

        Demanding zero failures here would be wrong, and flaky: at alpha = 0.01 across
        roughly twelve tests, a perfect source trips at least one about 11% of the time,
        which was measured at 2 of 12 trials before this tolerance was added. Allowing
        one failure keeps the real signal (a broken generator fires many tests at once,
        as the cases above do) while giving a false alarm probability under 1%.
        """
        for label, bits in (
            ("os.urandom", rand_bits(N // 8)),
            ("SHA-256 counter", S.bytes_to_bits(
                b"".join(hashlib.sha256(i.to_bytes(8, "big")).digest()
                         for i in range(N // 8 // 32)))),
        ):
            failures = self._failures(bits)
            assert len(failures) <= 1, f"{label} fired {len(failures)} tests: {failures}"


class TestSp80090B:
    def test_never_overestimates_a_biased_source(self):
        """The property that makes the estimator safe to credit a source with."""
        rng = np.random.default_rng(11)
        for p in (0.75, 0.90):
            data = (rng.random(N) < p).astype(np.uint8)
            _, h = B.assess(data)
            assert h <= -math.log2(p) + 0.05, f"over-estimated a p={p} source"

    @pytest.mark.parametrize("data_fn", [
        lambda n: np.ones(n, dtype=np.uint8),
        lambda n: np.zeros(n, dtype=np.uint8),
        lambda n: np.tile([0, 1], n // 2).astype(np.uint8),
    ])
    def test_degenerate_sources_score_zero(self, data_fn):
        _, h = B.assess(data_fn(N))
        assert h < 0.05

    def test_uniform_binary_is_below_one_bit(self):
        """SP 800-90B is conservative by design; it must not report the maximum."""
        _, h = B.assess(rand_bits(N // 8))
        assert 0.4 < h < 1.0

    def test_min_is_taken_over_estimators(self):
        estimates, h = B.assess(rand_bits(N // 8))
        usable = [e.min_entropy for e in estimates if not e.skipped]
        assert h == min(usable)

    def test_larger_alphabets_are_not_pinned_at_one_bit(self):
        """A 63-symbol source must be able to score above 1 bit/symbol."""
        rng = np.random.default_rng(7)
        s = rng.integers(0, 63, N).astype(np.uint8)
        _, h = B.assess(s)
        assert h > 4.0, "alphabet size is not being threaded through the estimators"
        assert h <= math.log2(63)

    def test_tuple_counting_paths_agree(self):
        """The packed fast path must be exactly equivalent to hashing raw windows."""
        from collections import Counter
        rng = np.random.default_rng(5)
        for alphabet in (2, 63):
            s = rng.integers(0, alphabet, 5000).astype(np.uint8)
            for t in (1, 2, 5, 10, 11, 16):
                fast = np.sort(B._tuple_multiplicities(s, t, alphabet))
                w = np.lib.stride_tricks.sliding_window_view(s, t)
                ref = np.sort(np.array(list(Counter(map(bytes, w)).values())))
                assert fast.shape == ref.shape and (fast == ref).all()

    def test_run_probability_is_sane(self):
        # Longest run of heads in n fair flips is about log2(n).
        assert B._no_run_probability(0.5, 30, 1000) > 0.99
        assert B._no_run_probability(0.5, 2, 1000) < 0.01
        assert B._no_run_probability(0.5, 20, 1_000_000) == pytest.approx(0.62, abs=0.1)

    def test_p_local_respects_alphabet_floor(self):
        """With a 63-symbol alphabet the search must start at 1/63, not 1/2."""
        assert B._p_local(3, 100_000, floor=0.5) >= 0.5
        assert B._p_local(3, 100_000, floor=1 / 63) < 0.5


class TestUniformityChecking:
    def test_uniform_p_values_pass(self):
        rng = np.random.default_rng(2)
        p, ok = S.uniformity_of_pvalues(list(rng.random(500)))
        assert ok and p > 0.0001

    def test_clustered_p_values_are_caught(self):
        """Catches a generator whose tests all pass but whose p-values bunch up."""
        clustered = [0.5 + 0.001 * i / 500 for i in range(500)]
        p, ok = S.uniformity_of_pvalues(clustered)
        assert not ok

    def test_proportion_interval_narrows_with_more_streams(self):
        lo10, _ = S.proportion_confidence_interval(10)
        lo100, _ = S.proportion_confidence_interval(100)
        assert lo100 > lo10


# ---------------------------------------------------------------------------
# Known-answer vectors from SP 800-22 Rev 1a
# ---------------------------------------------------------------------------
# The suite above checks behaviour: biased sources get caught, good ones pass. That is
# the property that matters, but it cannot tell a correct statistic from one that is
# merely monotonic in the right direction -- and a constant read off the wrong row of a
# NIST table is exactly the kind of error that stays invisible to a behavioural test.
# (`health.APT_CUTOFF` was such an error: 326, the binary row, where 31 was meant.)
#
# So each test is also pinned to the worked example printed in the standard.

class TestPublishedVectors:
    """Section 2.x "Example" blocks of SP 800-22 Rev 1a."""

    @staticmethod
    def _bits(s: str):
        import numpy as np
        return np.array([int(c) for c in s], dtype=np.uint8)

    def test_frequency_monobit(self):
        # 2.1.8: eps = 1011010101, n = 10
        r = S.frequency(self._bits("1011010101"))
        assert r.p_value == pytest.approx(0.527089, abs=1e-6)

    def test_block_frequency(self):
        # 2.2.8: eps = 0110011010, n = 10, M = 3
        r = S.block_frequency(self._bits("0110011010"), M=3)
        assert r.p_value == pytest.approx(0.801252, abs=1e-6)

    def test_runs(self):
        # 2.3.8: eps = 1001101011, n = 10
        r = S.runs(self._bits("1001101011"))
        assert r.p_value == pytest.approx(0.147232, abs=1e-6)

    def test_approximate_entropy(self):
        # 2.12.8: eps = 0100110101, n = 10, m = 3.
        #
        # m must be forced. The implementation reduces m until the expected cell counts
        # mean something, and at n = 10 that takes m to 2 -- correctly, since m = 3
        # wants a few hundred bits. NIST's example ignores its own guidance to keep the
        # arithmetic printable, so the vector only applies to the inner computation.
        import math

        from beamline.qa.special import igamc
        bits = self._bits("0100110101")
        m, n = 3, 10
        ap_en = S._phi(bits, m) - S._phi(bits, m + 1)
        chi2 = 2.0 * n * (math.log(2) - ap_en)
        assert igamc(2 ** (m - 1), chi2 / 2.0) == pytest.approx(0.261961, abs=1e-6)

    def test_cumulative_sums_follows_the_formula_not_the_printed_digits(self):
        """2.13.8: eps = 1011010111, n = 10. The document prints 0.4116588.

        Evaluating the standard's own series in double precision gives 0.41158472, and
        this implementation agrees with that to 2e-8. The printed value is the outlier
        by 7.4e-5, so it is the series that is pinned here, not the typo.
        """
        from math import erfc, floor, sqrt

        def phi(x):
            return 0.5 * erfc(-x / sqrt(2.0))

        n, z = 10, 4
        rn = sqrt(n)
        s1 = sum(phi(((4 * k + 1) * z) / rn) - phi(((4 * k - 1) * z) / rn)
                 for k in range(floor((-n / z + 1) / 4), floor((n / z - 1) / 4) + 1))
        s2 = sum(phi(((4 * k + 3) * z) / rn) - phi(((4 * k + 1) * z) / rn)
                 for k in range(floor((-n / z - 3) / 4), floor((n / z - 1) / 4) + 1))
        reference = 1.0 - s1 + s2

        r = S.cumulative_sums(self._bits("1011010111"))
        assert r.p_value == pytest.approx(reference, abs=1e-7)

    def test_tests_that_cannot_apply_are_skipped_not_guessed(self):
        """A ten-bit sequence is far too short for these two.

        A p-value computed anyway would be meaningless, and meaningless numbers in a
        published report are worse than an admitted gap. Both must say they skipped.
        """
        short = self._bits("1001010011")
        for result in (S.spectral(short), S.serial(short, m=3)):
            assert result.skipped and result.reason
