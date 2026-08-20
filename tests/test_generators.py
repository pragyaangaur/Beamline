"""Correctness and bias tests for the shaping layer.

These are the tests that matter commercially. A customer running a regulated draw is
relying on the claim that these functions are unbiased; that claim needs evidence.
"""

from __future__ import annotations

import collections
import math
import os

import pytest

from beamline import generators as gen


def rand(n: int) -> bytes:
    return os.urandom(n)


def many(fn, total: int, *args, **kwargs) -> list:
    """Collect `total` values from a generator capped at MAX_COUNT per call."""
    out: list = []
    while len(out) < total:
        out += fn(rand, min(gen.MAX_COUNT, total - len(out)), *args, **kwargs)
    return out


def chi2_uniform(counts: dict, categories: int, n: int) -> float:
    expected = n / categories
    return sum((counts.get(k, 0) - expected) ** 2 / expected for k in range(categories))


class TestBoundedInt:
    @pytest.mark.parametrize("span", [1, 2, 3, 5, 6, 7, 255, 256, 257, 1000, 2**20])
    def test_stays_in_range(self, span):
        assert all(0 <= gen.bounded_int(rand, span) < span for _ in range(2000))

    def test_rejects_zero_span(self):
        with pytest.raises(ValueError):
            gen.bounded_int(rand, 0)

    @pytest.mark.parametrize("span", [3, 6, 7, 10, 100])
    def test_no_modulo_bias(self, span):
        """Non-power-of-two spans are exactly where a naive `% span` would skew."""
        n = 60_000
        counts = collections.Counter(gen.bounded_int(rand, span) for _ in range(n))
        df = span - 1
        crit = df * (1 - 2 / (9 * df) + 3.09 * math.sqrt(2 / (9 * df))) ** 3
        assert chi2_uniform(counts, span, n) < crit
        assert len(counts) == span


class TestIntegers:
    def test_inclusive_bounds(self):
        vals = gen.integers(rand, 5000, 1, 6)
        assert min(vals) == 1 and max(vals) == 6

    def test_single_value_range(self):
        assert gen.integers(rand, 10, 7, 7) == [7] * 10

    def test_negative_range(self):
        vals = gen.integers(rand, 3000, -50, -10)
        assert all(-50 <= v <= -10 for v in vals)

    def test_unique_are_distinct(self):
        vals = gen.integers(rand, 6, 1, 49, unique=True)
        assert len(set(vals)) == 6

    def test_unique_exhaustive_range(self):
        vals = gen.integers(rand, 10, 1, 10, unique=True)
        assert sorted(vals) == list(range(1, 11))

    def test_unique_sparse_range(self):
        """Exercises the set-rejection branch rather than partial Fisher-Yates."""
        vals = gen.integers(rand, 50, 0, 10_000_000, unique=True)
        assert len(set(vals)) == 50

    def test_unique_rejects_impossible_request(self):
        with pytest.raises(ValueError, match="unique"):
            gen.integers(rand, 10, 1, 5, unique=True)

    def test_rejects_inverted_range(self):
        with pytest.raises(ValueError, match="min must be"):
            gen.integers(rand, 1, 10, 5)

    @pytest.mark.parametrize("count", [0, -1, gen.MAX_COUNT + 1])
    def test_rejects_bad_count(self, count):
        with pytest.raises(ValueError):
            gen.integers(rand, count, 0, 10)


class TestFloats:
    def test_half_open_unit_interval(self):
        vals = many(gen.floats, 20_000)
        assert all(0.0 <= v < 1.0 for v in vals), "1.0 must never be returned"

    def test_mean_and_variance(self):
        vals = many(gen.floats, 50_000)
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        assert abs(mean - 0.5) < 0.01
        assert abs(var - 1 / 12) < 0.005

    def test_precision_rounding(self):
        for v in gen.floats(rand, 200, precision=3):
            assert v == round(v, 3)

    def test_uniform_across_deciles(self):
        n = 40_000
        counts = collections.Counter(min(9, int(v * 10)) for v in many(gen.floats, n))
        assert chi2_uniform(counts, 10, n) < 27.9  # 99.9% crit, df=9


class TestGaussian:
    def test_moments(self):
        vals = many(gen.gaussian, 40_000, mean=5.0, stddev=2.0)
        mean = sum(vals) / len(vals)
        sd = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
        assert abs(mean - 5.0) < 0.06
        assert abs(sd - 2.0) < 0.06

    def test_odd_count_returns_exact_length(self):
        """Box-Muller produces pairs; an odd request must not over-return."""
        assert len(gen.gaussian(rand, 7)) == 7

    def test_rejects_bad_stddev(self):
        with pytest.raises(ValueError):
            gen.gaussian(rand, 10, stddev=0)


class TestShuffleAndSample:
    def test_shuffle_is_a_permutation(self):
        items = list(range(200))
        assert sorted(gen.shuffle(rand, items)) == items

    def test_shuffle_does_not_mutate_input(self):
        items = [1, 2, 3, 4, 5]
        gen.shuffle(rand, items)
        assert items == [1, 2, 3, 4, 5]

    def test_shuffle_is_uniform_over_permutations(self):
        """All 24 permutations of 4 elements must appear equally often."""
        n = 48_000
        counts = collections.Counter(tuple(gen.shuffle(rand, [0, 1, 2, 3])) for _ in range(n))
        assert len(counts) == 24
        expected = n / 24
        chi2 = sum((c - expected) ** 2 / expected for c in counts.values())
        assert chi2 < 51.2  # 99.9% crit, df=23

    def test_shuffle_empty_and_single(self):
        assert gen.shuffle(rand, []) == []
        assert gen.shuffle(rand, [9]) == [9]

    def test_sample_without_replacement(self):
        out = gen.sample(rand, list(range(100)), 30)
        assert len(out) == len(set(out)) == 30

    def test_sample_rejects_oversized_request(self):
        with pytest.raises(ValueError, match="exceeds"):
            gen.sample(rand, [1, 2, 3], 5)

    def test_sample_full_population(self):
        assert sorted(gen.sample(rand, list(range(20)), 20)) == list(range(20))


class TestWeighted:
    def test_zero_weight_never_selected(self):
        out = gen.weighted_choice(rand, ["a", "b", "c"], [1, 0, 1], 5000)
        assert "b" not in out

    def test_respects_proportions(self):
        n = 40_000
        out = gen.weighted_choice(rand, ["x", "y"], [0.25, 0.75], n)
        assert abs(out.count("y") / n - 0.75) < 0.01

    def test_skewed_proportions(self):
        n = 60_000
        out = gen.weighted_choice(rand, ["rare", "common"], [1, 999], n)
        assert abs(out.count("rare") / n - 0.001) < 0.0008

    def test_rejects_mismatched_lengths(self):
        with pytest.raises(ValueError, match="same length"):
            gen.weighted_choice(rand, ["a", "b"], [1.0], 5)

    def test_rejects_negative_and_zero_total(self):
        with pytest.raises(ValueError, match="non-negative"):
            gen.weighted_choice(rand, ["a", "b"], [1.0, -1.0], 5)
        with pytest.raises(ValueError, match="positive"):
            gen.weighted_choice(rand, ["a", "b"], [0.0, 0.0], 5)


class TestUuidAndPassword:
    def test_uuid_version_and_variant(self):
        for u in gen.uuid4(rand, 200):
            assert len(u) == 36 and u[14] == "4"
            assert u[19] in "89ab", "RFC 4122 variant bits must be set"

    def test_uuids_are_unique(self):
        assert len(set(gen.uuid4(rand, 5000))) == 5000

    def test_password_length_and_alphabet(self):
        pw = gen.password(rand, 1, length=32, charset="unambiguous")[0]
        assert len(pw["value"]) == 32
        assert set(pw["value"]) <= set(gen.PASSWORD_SETS["unambiguous"])

    def test_password_entropy_math(self):
        pw = gen.password(rand, 1, length=20, charset="digits")[0]
        assert abs(pw["entropy_bits"] - 20 * math.log2(10)) < 0.1

    def test_password_rejects_unknown_charset(self):
        with pytest.raises(ValueError, match="unknown charset"):
            gen.password(rand, 1, charset="klingon")

    @pytest.mark.parametrize("length", [7, 257])
    def test_password_rejects_bad_length(self, length):
        with pytest.raises(ValueError):
            gen.password(rand, 1, length=length)

    def test_dice_range(self):
        assert set(gen.dice(rand, 3000, 20)) <= set(range(1, 21))

    def test_dice_rejects_one_sided(self):
        with pytest.raises(ValueError):
            gen.dice(rand, 1, sides=1)
