"""Common shape for entropy sources.

A source is anything that can be polled for bytes on an interval. Adding a new
physical input (a cosmic-ray muon detector on a Raspberry Pi, a second QRNG vendor,
an SDR listening to a pulsar) means writing one subclass and registering it.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass


@dataclass
class Sample:
    data: bytes
    meta: dict


class Source(abc.ABC):
    #: Pool credit is keyed off this. Must match a key in `pool.CREDIT_BITS_PER_BYTE`.
    name: str = "unnamed"
    #: Seconds between polls.
    interval: float = 60.0
    #: Whether this source's data is public (and therefore credited zero secret entropy).
    public: bool = False

    def __init__(self) -> None:
        self.last_ok: float | None = None
        self.last_error: str | None = None
        self.consecutive_errors = 0

    @abc.abstractmethod
    async def poll(self) -> Sample | None:
        """Fetch one sample. Return None to skip this cycle without recording an error."""

    def backoff_seconds(self) -> float:
        """Exponential backoff after failures, capped, so a dead source stops hammering."""
        if self.consecutive_errors == 0:
            return self.interval
        return min(self.interval * (2 ** self.consecutive_errors), 900.0)

    def record_ok(self) -> None:
        self.last_ok = time.time()
        self.last_error = None
        self.consecutive_errors = 0

    def record_error(self, err: str) -> None:
        self.last_error = err
        self.consecutive_errors += 1

    def snapshot(self) -> dict:
        return {
            "name": self.name,
            "public_data": self.public,
            "interval_seconds": self.interval,
            "last_ok": self.last_ok,
            "last_error": self.last_error,
            "consecutive_errors": self.consecutive_errors,
        }
