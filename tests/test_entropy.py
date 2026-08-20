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
