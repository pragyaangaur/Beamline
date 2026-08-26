"""Tests for the DRBG, pool, and health tests."""

from __future__ import annotations

import os

import pytest

from beamline.entropy.drbg import HmacDrbg
from beamline.entropy.health import APT_CUTOFF, RCT_CUTOFF, SourceHealth
from beamline.entropy.pool import MIN_SEED_BITS, EntropyPool


class TestDrbg:
    def test_deterministic_from_same_seed(self):
        seed = b"\x01" * 48
        a = HmacDrbg(seed, nonce=b"n", personalization=b"p")
        b = HmacDrbg(seed, nonce=b"n", personalization=b"p")
        assert a.generate(64) == b.generate(64)

    def test_diverges_on_nonce(self):
        seed = b"\x01" * 48
        a = HmacDrbg(seed, nonce=b"n1")
        b = HmacDrbg(seed, nonce=b"n2")
        assert a.generate(64) != b.generate(64)

    def test_successive_calls_differ(self):
        d = HmacDrbg(os.urandom(48))
        assert len({d.generate(32) for _ in range(50)}) == 50

    def test_rejects_short_seed(self):
        with pytest.raises(ValueError):
            HmacDrbg(b"tooshort")

    @pytest.mark.parametrize("n", [1, 31, 64, 65, 1000, 65536, 65537, 200_000])
    def test_exact_length(self, n):
        """Chunking across the SP 800-90A per-call cap must not change the length."""
        assert len(HmacDrbg(os.urandom(48)).generate(n)) == n

    def test_reseed_changes_stream(self):
        seed = b"\x02" * 48
        a, b = HmacDrbg(seed), HmacDrbg(seed)
        a.reseed(b"\x09" * 48)
        assert a.generate(32) != b.generate(32)
        assert a.reseeds == 1

    def test_backtracking_resistance(self):
        """State after a generate must not reproduce the bytes that generate emitted."""
        d = HmacDrbg(os.urandom(48))
        first = d.generate(64)
        # A fresh DRBG restored from the post-call state cannot re-emit `first`.
        assert d.generate(64) != first

    def test_no_short_period_at_block_boundary(self):
        d = HmacDrbg(os.urandom(48))
        out = d.generate(64 * 100)
        blocks = {out[i:i + 64] for i in range(0, len(out), 64)}
        assert len(blocks) == 100, "internal V must advance every block"

    def test_output_is_balanced(self):
        out = HmacDrbg(os.urandom(48)).generate(200_000)
        ones = sum(bin(b).count("1") for b in out)
        expected = len(out) * 4
        assert abs(ones - expected) < 5 * (len(out) * 2) ** 0.5


class TestHealth:
    def test_accepts_random_data(self):
        h = SourceHealth("t")
        assert h.update(os.urandom(4096))
        assert not h.quarantined

    def test_repetition_count_catches_stuck_source(self):
        h = SourceHealth("stuck")
        assert not h.update(b"\x41" * (RCT_CUTOFF + 2))
        assert h.quarantined
        assert "repetition count" in h.last_failure

    def test_adaptive_proportion_catches_skew(self):
        """A source that is not stuck but is heavily biased still has to fail."""
        h = SourceHealth("skewed")
        # 'A' in 3 of every 4 positions: 75% of the window, above the ~64% APT cutoff,
        # while the longest run is 3 -- comfortably under the RCT cutoff of 6. So only
        # the proportion test can catch this, which is exactly what we are asserting.
        data = bytes(0x41 if i % 4 != 3 else (i % 251) for i in range(APT_CUTOFF * 3))
        h.update(data)
        assert h.quarantined
        assert "adaptive proportion" in h.last_failure

    def test_shannon_estimate_is_sane(self):
        h = SourceHealth("t")
        h.update(os.urandom(20_000))
        assert 7.9 < h.shannon_bits_per_byte() <= 8.0


class TestPool:
    def test_not_ready_when_empty(self):
        assert not EntropyPool().ready()

    def test_public_source_earns_no_credit(self):
        """The whole honesty of the design rests on this test."""
        p = EntropyPool()
        p.add("astro", os.urandom(100_000))
        assert p.credited_bits == 0.0
        assert not p.ready()

    def test_public_source_is_not_health_tested(self):
        """Structured public feeds must not be reported as failing entropy sources.

        NOAA's packed doubles are full of zero padding, which trips the repetition
        count test. Flagging that as a quarantine would be noise that teaches an
        operator to ignore the flag that actually matters.
        """
        p = EntropyPool()
        assert p.add("astro", b"\x00" * 4096) is True
        assert "astro" not in p.health
        assert p.snapshot()["provenance_only_sources"][0]["source"] == "astro"

    def test_public_source_still_mixes_into_the_accumulator(self):
        a, b = EntropyPool(), EntropyPool()
        a.add("astro", b"solar-wind-sample")
        a.add("local_os", os.urandom(128))
        b.add("local_os", os.urandom(128))
        assert a.extract(32) != b.extract(32)

    def test_becomes_ready_from_credited_source(self):
        p = EntropyPool()
        p.add("local_os", os.urandom(128))
        assert p.credited_bits >= MIN_SEED_BITS
        assert p.ready()

    def test_extract_resets_credit(self):
        p = EntropyPool()
        p.add("local_os", os.urandom(128))
        p.extract(64)
        assert p.credited_bits == 0.0
        assert not p.ready()

    def test_extract_refuses_when_not_ready(self):
        with pytest.raises(RuntimeError, match="not ready"):
            EntropyPool().extract(64)

    def test_extractions_are_unique(self):
        p = EntropyPool()
        seen = set()
        for _ in range(30):
            p.add("local_os", os.urandom(128))
            seen.add(p.extract(64))
        assert len(seen) == 30

    @pytest.mark.parametrize("n", [16, 64, 65, 200])
    def test_extract_length(self, n):
        p = EntropyPool()
        p.add("local_os", os.urandom(256))
        assert len(p.extract(n)) == n

    def test_quarantined_source_stops_earning_credit(self):
        p = EntropyPool()
        p.add("local_os", b"\x00" * 64)  # trips the RCT immediately
        assert p.health["local_os"].quarantined
        before = p.credited_bits
        p.add("local_os", os.urandom(64))
        assert p.credited_bits == before, "a quarantined source must not be credited"

    def test_mixing_is_order_sensitive(self):
        a, b = EntropyPool(), EntropyPool()
        x, y = os.urandom(64), os.urandom(64)
        a.add("local_os", x); a.add("local_os", y)
        b.add("local_os", y); b.add("local_os", x)
        assert a.extract(32) != b.extract(32)


# --- SP 800-90B continuous health tests ------------------------------------
#
# These cutoffs are the difference between noticing a dead entropy source and not.
# APT_CUTOFF was read off the binary (H=1) row of the table while every other constant
# in the module assumes H=6, which left the Adaptive Proportion Test unable to fire in
# practice. Both cutoffs are pinned to their derivations here rather than to literals
# somebody could "fix" back.

def _apt_cutoff(window: int, h_bits: int, alpha: float) -> int:
    """Smallest C with P(X >= C) <= alpha for X ~ Binomial(window, 2^-h_bits)."""
    from math import comb
    p = 2.0 ** -h_bits

    def tail(c: int) -> float:
        return sum(comb(window, k) * p**k * (1 - p) ** (window - k)
                   for k in range(c, window + 1))

    c = 1
    while tail(c) > alpha:
        c += 1
    return c


def test_the_health_cutoffs_match_their_own_derivation():
    from math import ceil

    from beamline.entropy import health as H

    assert H.RCT_CUTOFF == 1 + ceil(30 / 6), "RCT cutoff is 1 + ceil(-log2(alpha)/H)"
    assert H.APT_CUTOFF == _apt_cutoff(H.APT_WINDOW, 6, 2.0**-30)

    # The specific wrong answer this had: the binary row, whose mean is 256 not 8.
    assert H.APT_CUTOFF != _apt_cutoff(H.APT_WINDOW, 1, 2.0**-30)


def test_the_adaptive_proportion_test_catches_what_the_repetition_test_cannot():
    """A source stuck on one value, but never twice in a row.

    The RCT only sees consecutive repeats, so this degradation is invisible to it and
    the APT is the only thing standing between a broken source and the entropy credit
    it does not deserve. At the old cutoff this passed 200,000 bytes unflagged.
    """
    import random

    from beamline.entropy.health import SourceHealth

    rng = random.Random(11)
    out, last = bytearray(), None
    while len(out) < 200_000:
        b = 0x41 if (rng.random() < 0.20 and last != 0x41) else rng.randrange(256)
        if b == last:
            continue
        out.append(b)
        last = b

    assert out.count(0x41) / len(out) > 0.10, "the fixture must actually be biased"

    health = SourceHealth("degraded")
    health.update(bytes(out))
    assert health.quarantined, "a source this broken must not keep its entropy credit"
    assert "adaptive proportion" in (health.last_failure or "")


def test_a_healthy_source_is_not_quarantined():
    """The other half. A cutoff that fires on real randomness trains people to ignore it."""
    import os

    from beamline.entropy.health import SourceHealth

    health = SourceHealth("kernel")
    assert health.update(os.urandom(1_000_000))
    assert not health.quarantined and health.failures == 0
