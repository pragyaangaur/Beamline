"""Tests for the block alphabet, the archive store, and the harvest controller."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from beamline.entropy import blocks as B
from beamline.harvester import AdaptiveHarvester, AdjustableSemaphore, HarvestConfig
from beamline.store import EntropyStore

_SEED = ("iSiYRm87eA_2_5dQkrw7Td5hKNIm6oJEeNM82Jtwjeysu61fvZQXpDhrBpeq4vDj6fJR"
         "2aDySpa_ABZChB1p6LzzrQFceclrBpTJxwZmoOH7i8uiheuB9Vje3E1J6BkpX3Ige")
#: Exactly one block's worth, matching what the endpoint actually returns.
SAMPLE = (_SEED * 8)[:B.BLOCK_CHARS]


class TestBlocks:
    def test_alphabet_is_63_symbols(self):
        """Measured, not assumed. base64url would be 64; '-' is absent from the feed."""
        assert B.ALPHABET_SIZE == 63
        assert "-" not in B.ALPHABET
        assert len(set(B.ALPHABET)) == 63

    def test_bits_per_char_is_below_six(self):
        assert 5.97 < B.BITS_PER_CHAR < 5.98

    def test_pack_unpack_roundtrip(self):
        packed = B.pack(SAMPLE)
        assert B.unpack(packed, len(SAMPLE)) == SAMPLE

    def test_packing_saves_25_percent(self):
        assert len(B.pack(SAMPLE)) == pytest.approx(len(SAMPLE) * 6 / 8, abs=1)

    @pytest.mark.parametrize("n", [1, 2, 3, 7, 8, 1024])
    def test_pack_roundtrip_various_lengths(self, n):
        text = SAMPLE[:n]
        assert B.unpack(B.pack(text), n) == text

    def test_pack_rejects_foreign_characters(self):
        with pytest.raises(B.InvalidBlock):
            B.pack("hello-world")          # '-' is not in the alphabet

    def test_condition_length_uses_measured_entropy(self):
        """Conditioning must not claim more bytes than 5.977 bits/char justifies."""
        out = B.condition(SAMPLE)
        assert len(out) == int(len(SAMPLE) * B.BITS_PER_CHAR) // 8
        assert len(out) < len(SAMPLE) * 6 // 8   # strictly below the base64url assumption

    def test_condition_is_deterministic_and_input_sensitive(self):
        assert B.condition(SAMPLE) == B.condition(SAMPLE)
        assert B.condition(SAMPLE) != B.condition(SAMPLE[:-1] + "0")

    def test_validate_accepts_a_real_block(self):
        assert B.validate(SAMPLE) == SAMPLE

    @pytest.mark.parametrize("bad", [
        "<!DOCTYPE html><html><body>error page padding" * 20,
        "short",
        "A" * 1024,                       # degenerate: one symbol
        "AB" * 512,                       # degenerate: two symbols
    ])
    def test_validate_rejects_non_entropy(self, bad):
        with pytest.raises(B.InvalidBlock):
            B.validate(bad)

    def test_entropy_bits(self):
        assert B.entropy_bits(1024) == pytest.approx(6120.8, abs=1.0)


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as d:
        yield EntropyStore(Path(d))


class TestStore:
    def test_add_and_reserve(self, store):
        assert store.add_block(SAMPLE)
        assert store.reserve(1) == [SAMPLE]

    def test_duplicates_are_rejected(self, store):
        assert store.add_block(SAMPLE) is True
        assert store.add_block(SAMPLE) is False
        assert store.stats().total_blocks == 1
        assert store.stats().duplicates_rejected == 1

    def test_blocks_are_consume_once(self, store):
        """Replaying archived bytes adds no entropy, so reserve must not repeat."""
        store.add_block(SAMPLE)
        assert store.reserve(5) == [SAMPLE]
        assert store.reserve(5) == []
        assert store.unconsumed_count() == 0

    def test_reserve_returns_distinct_blocks(self, store):
        texts = [SAMPLE[:-1] + c for c in "0123456789"]
        for t in texts:
            store.add_block(t)
        got = store.reserve(10)
        assert len(got) == 10 and len(set(got)) == 10

    def test_iter_all_does_not_consume(self, store):
        store.add_block(SAMPLE)
        assert list(store.iter_all_chars()) == [SAMPLE]
        assert store.unconsumed_count() == 1

    def test_stats_track_entropy(self, store):
        store.add_block(SAMPLE)
        s = store.stats()
        assert s.total_blocks == 1
        assert s.entropy_bits_available == pytest.approx(
            B.entropy_bits(len(SAMPLE)), abs=1)

    def test_survives_reopen(self, store):
        store.add_block(SAMPLE)
        reopened = EntropyStore(store.root)
        assert reopened.unconsumed_count() == 1
        assert reopened.add_block(SAMPLE) is False   # dedup index persisted

    def test_import_legacy_skips_duplicates(self, store, tmp_path):
        p = tmp_path / "legacy.txt"
        p.write_text(SAMPLE + SAMPLE)                # same block twice
        added, skipped = store.import_legacy_text(p, block_chars=len(SAMPLE))
        assert added == 1 and skipped == 1

    def test_oversized_block_is_refused_not_truncated(self, store):
        """Silently truncating an oversized block would corrupt the archive."""
        with pytest.raises(ValueError, match="exceeds"):
            store.add_block((_SEED * 20)[:B.BLOCK_CHARS + 200])

    def test_shard_rollover(self, store, monkeypatch):
        import beamline.store as st
        monkeypatch.setattr(st, "SHARD_MAX_BLOCKS", 3)
        for i in range(7):
            store.add_block(SAMPLE[:-2] + f"{i:02d}")
        assert store.stats().shards >= 2
        assert store.stats().total_blocks == 7


class TestAdjustableSemaphore:
    async def test_limits_in_flight(self):
        sem = AdjustableSemaphore(2)
        await sem.acquire(); await sem.acquire()
        blocked = asyncio.create_task(sem.acquire())
        await asyncio.sleep(0.05)
        assert not blocked.done(), "third acquire must wait at capacity 2"
        await sem.release()
        await asyncio.wait_for(blocked, timeout=1.0)

    async def test_capacity_can_grow_while_waiting(self):
        """The controller must be able to raise the limit without restarting workers."""
        sem = AdjustableSemaphore(1)
        await sem.acquire()
        waiter = asyncio.create_task(sem.acquire())
        await asyncio.sleep(0.05)
        assert not waiter.done()
        await sem.set_capacity(2)
        await asyncio.wait_for(waiter, timeout=1.0)


class TestController:
    def _harvester(self, store, **kw):
        return AdaptiveHarvester(store, HarvestConfig(**kw))

    async def test_grows_when_latency_is_flat(self, store):
        h = self._harvester(store, start_concurrency=2, max_concurrency=8)
        await h._grow(1.0)
        assert h._sem.capacity == 3

    async def test_respects_ceiling(self, store):
        h = self._harvester(store, start_concurrency=7, max_concurrency=8)
        for _ in range(5):
            await h._grow(1.0)
        assert h._sem.capacity == 8

    async def test_backs_off_multiplicatively(self, store):
        h = self._harvester(store, start_concurrency=10, decrease_factor=0.5)
        await h._scale(0.5, "test")
        assert h._sem.capacity == 5

    async def test_never_drops_below_minimum(self, store):
        h = self._harvester(store, start_concurrency=2, min_concurrency=1,
                            decrease_factor=0.1)
        for _ in range(20):
            await h._scale(0.1, "test")
        assert h._sem.capacity >= 1

    async def test_latency_inflation_triggers_backoff(self, store):
        """The core control law: sustained latency above baseline reduces concurrency."""
        h = self._harvester(store, start_concurrency=8, latency_ratio_limit=1.5)
        h._baseline = 0.100
        h._recent.extend([0.400] * 40)        # 4x the baseline
        before = h._sem.capacity
        task = asyncio.create_task(h._control_loop())
        await asyncio.sleep(h.cfg.control_interval + 0.4)
        h.request_stop()
        await asyncio.wait_for(task, timeout=2.0)
        assert h._sem.capacity < before

    async def test_flat_latency_triggers_growth(self, store):
        h = self._harvester(store, start_concurrency=4, latency_ratio_limit=1.5)
        h._baseline = 0.100
        h._recent.extend([0.105] * 40)
        task = asyncio.create_task(h._control_loop())
        await asyncio.sleep(h.cfg.control_interval + 0.4)
        h.request_stop()
        await asyncio.wait_for(task, timeout=2.0)
        assert h._sem.capacity > 4

    async def test_baseline_tracks_the_fastest_observation(self, store):
        h = self._harvester(store)
        h._recent.extend([0.5, 0.4, 0.2, 0.45])
        task = asyncio.create_task(h._control_loop())
        await asyncio.sleep(h.cfg.control_interval + 0.4)
        h.request_stop()
        await asyncio.wait_for(task, timeout=2.0)
        assert h._baseline == pytest.approx(0.2, abs=1e-6)


# --- the live source must validate what it ingests --------------------------
#
# This is the path that feeds every published pulse, and it was the only ingestion
# point that did not validate. The bulk harvester validates, the archive reader
# validates, and the live source -- whose bytes actually reach the beacon -- did not.
# Its whole check was "at least 256 characters, no '<' in the first 64".

class _Resp:
    def __init__(self, text): self.text = text
    def raise_for_status(self): pass


class _Client:
    def __init__(self, text): self._text = text
    async def get(self, url): return _Resp(self._text)
    async def aclose(self): pass


def _source(text):
    from beamline.sources.anu import AnuSource
    src = AnuSource.__new__(AnuSource)
    AnuSource.__init__(src)
    src._client, src._api_key = _Client(text), None
    return src


def _genuine_block(n=1024, seed=5):
    import random
    rng = random.Random(seed)
    return "".join(rng.choice(B.ALPHABET) for _ in range(n))


async def test_a_genuine_block_is_still_ingested():
    """The fix must not cost the beacon its quantum source."""
    data, meta = await _source(_genuine_block())._poll_public()
    assert meta["provider"] == "anu_public_endpoint"
    assert meta["chars"] == 1024
    assert len(data) == 765          # the length published pulses actually record


@pytest.mark.parametrize("label,text", [
    ("1024 identical characters", "A" * 1024),
    ("a JSON error body",         '{"success":false,"message":"unavailable"}' * 10),
    ("a maintenance notice",      "The ANU QRNG service is under maintenance. " * 15),
    ("a repeated hex block",      ("deadbeef" * 8) * 16),
    ("an HTML page",              "<html><body>error</body></html>" * 20),
    ("a truncated response",      _genuine_block(100)),
])
async def test_things_that_are_not_entropy_are_refused(label, text):
    """Every one of these cleared the old check, was conditioned, and was credited at
    6 bits per byte as quantum entropy -- a constant string was worth 4590 bits -- with
    the pulse provenance recording it as `anu_public_endpoint`."""
    with pytest.raises(B.InvalidBlock):
        await _source(text)._poll_public()


async def test_a_refused_block_is_reported_not_silently_dropped():
    """The source must show as failing, so the published `sources` block says so."""
    src = _source("A" * 1024)
    assert await src.poll() is None
    assert src.consecutive_errors > 0 and src.last_error
