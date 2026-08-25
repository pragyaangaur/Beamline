"""The NOAA feeds, and the one property they are actually there for.

These feeds are credited zero secret entropy on purpose: the data is public, so anyone
can fetch the same bytes. What they buy is a lower bound on when a pulse was produced.
A pulse whose provenance names a NOAA reading could not have been generated before that
reading existed, and anyone can re-fetch it and check.

That argument is worth exactly as much as the timestamp is accurate, which is why these
tests exist. NOAA serves the two rtsw feeds as a rolling 24 hour window that is not in
chronological order: the newest row sits mid-array and the last row is a day old. Taking
the tail of the array published a timestamp 24 hours early, and a lower bound that is 24
hours early pins nothing.
"""

from __future__ import annotations

import asyncio

import pytest

from beamline.sources.astro import AstroSource


class FakeResponse:
    def __init__(self, rows):
        self._rows = rows

    def raise_for_status(self):
        return None

    def json(self):
        return self._rows


class FakeClient:
    """Serves the same unordered rows for every feed."""

    def __init__(self, rows):
        self._rows = rows

    async def get(self, url):
        return FakeResponse(self._rows)

    async def aclose(self):
        return None


#: The shape NOAA actually serves: newest in the middle, oldest last.
UNORDERED = (
    [{"time_tag": "2026-08-25T17:00:00", "speed": 400.0, "density": 5.0,
      "temperature": 1e5, "bx_gsm": 1.0, "by_gsm": 2.0, "bz_gsm": 3.0,
      "bt": 4.0, "flux": 1e-7}]
    + [{"time_tag": "2026-08-25T17:5%d:00" % i, "speed": 400.0 + i, "density": 5.0,
        "temperature": 1e5, "bx_gsm": 1.0, "by_gsm": 2.0, "bz_gsm": 3.0,
        "bt": 4.0, "flux": 1e-7} for i in range(9)]
    + [{"time_tag": "2026-08-24T17:59:00", "speed": 300.0, "density": 5.0,
        "temperature": 1e5, "bx_gsm": 1.0, "by_gsm": 2.0, "bz_gsm": 3.0,
        "bt": 4.0, "flux": 1e-7}]
)


def _poll(rows):
    src = AstroSource()
    src._client = FakeClient(rows)
    try:
        return asyncio.run(src.poll())
    finally:
        asyncio.run(src.aclose())


def test_the_newest_reading_is_reported_even_when_it_is_not_the_last_row():
    """The bug: the last row is a day old, and it was being published as the latest."""
    sample = _poll(UNORDERED)
    for feed, info in sample.meta["feeds"].items():
        assert info["latest_time_tag"] == "2026-08-25T17:58:00", feed


def test_the_day_old_row_is_not_what_gets_mixed_in():
    sample = _poll(UNORDERED)
    for info in sample.meta["feeds"].values():
        assert not info["latest_time_tag"].startswith("2026-08-24")


def test_an_ordered_feed_still_works():
    """goes_xray is served in order, and must be unaffected by the sort."""
    ordered = sorted(UNORDERED, key=lambda r: r["time_tag"])
    sample = _poll(ordered)
    for info in sample.meta["feeds"].values():
        assert info["latest_time_tag"] == "2026-08-25T17:58:00"


def test_rows_without_a_timestamp_are_not_mixed_in_as_if_they_were_readings():
    """An untimestamped row cannot support the lower bound, so it is not evidence."""
    sample = _poll([{"speed": 1.0}, {"density": 2.0}])
    assert sample is None or all(
        "error" in info for info in sample.meta["feeds"].values())


def test_a_feed_that_advances_is_reported_as_advanced():
    src = AstroSource()
    src._client = FakeClient(UNORDERED)
    try:
        first = asyncio.run(src.poll())
        second = asyncio.run(src.poll())
    finally:
        asyncio.run(src.aclose())
    assert first.meta["advanced"] is True
    # Same data second time, so nothing advanced, and the pulse should say so.
    assert second.meta["advanced"] is False
