"""Per-key token bucket.

In-process and therefore per-instance: two API instances behind a load balancer each
enforce the full limit, so the effective ceiling is N x the configured rate. That is
an acceptable and well-understood V1 tradeoff -- the monthly byte quota in SQLite is
the hard commercial limit, and this bucket exists to stop a single key from
monopolising a box. Move to Redis when you run more than one instance and care.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class Bucket:
    capacity: int
    refill_per_sec: float
    tokens: float = field(default=0.0)
    updated: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)

    def take(self, n: int = 1) -> tuple[bool, float]:
        """Try to spend `n` tokens. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill_per_sec)
        self.updated = now
        if self.tokens >= n:
            self.tokens -= n
            return True, 0.0
        deficit = n - self.tokens
        return False, deficit / self.refill_per_sec if self.refill_per_sec > 0 else 60.0


class RateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key_id: str, capacity: int, refill: float, cost: int = 1) -> tuple[bool, float]:
        with self._lock:
            b = self._buckets.get(key_id)
            if b is None or b.capacity != capacity or b.refill_per_sec != refill:
                b = Bucket(capacity, refill)  # tier changed -> fresh bucket
                self._buckets[key_id] = b
            return b.take(cost)

    def remaining(self, key_id: str) -> float:
        with self._lock:
            b = self._buckets.get(key_id)
            return b.tokens if b else 0.0
