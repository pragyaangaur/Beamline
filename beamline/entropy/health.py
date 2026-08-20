"""Continuous health tests for entropy sources.

Modelled on NIST SP 800-90B section 4.4: every source gets a Repetition Count Test
and an Adaptive Proportion Test running permanently over its output. A source that
fails is quarantined -- its contributions stop counting toward the "we have enough
fresh entropy" bookkeeping, and it is flagged in /v1/health.

These are *health* tests, not randomness certification. They catch a source that has
died stuck-at-a-value or collapsed to a narrow distribution, which is the realistic
failure mode for a scraped HTTP source (an error page, a cached response, a proxy
returning the same block over and over). They cannot tell you a source is "truly
random" and nothing can, so we don't pretend otherwise.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

# Cutoffs computed for alpha = 2^-30 assuming a conservative 6 bits of min-entropy
# per byte from a well-behaved source. See SP 800-90B 4.4.1 / 4.4.2.
RCT_CUTOFF = 6            # ceil(1 + 30/H) with H=6
APT_WINDOW = 512
APT_CUTOFF = 326          # binomial tail bound for p=2^-6 over 512 samples


@dataclass
class SourceHealth:
    """Rolling health state for one entropy source. Feed it every byte the source emits."""

    name: str
    # Repetition Count Test
    _rct_last: int | None = None
    _rct_run: int = 0
    # Adaptive Proportion Test
    _apt_ref: int | None = None
    _apt_seen: int = 0
    _apt_matches: int = 0

    total_bytes: int = 0
    failures: int = 0
    last_failure: str | None = None
    quarantined: bool = False
    # Recent-window byte histogram, used for the reported entropy estimate.
    _hist: Counter = field(default_factory=Counter)
    _hist_n: int = 0

    def update(self, data: bytes) -> bool:
        """Push observed bytes through the tests. Returns False if the source just failed."""
        ok = True
        for b in data:
            self.total_bytes += 1

            # --- Repetition Count Test ---
            if b == self._rct_last:
                self._rct_run += 1
                if self._rct_run >= RCT_CUTOFF:
                    ok = False
                    self._fail(f"repetition count: byte 0x{b:02x} repeated {self._rct_run}x")
                    self._rct_run = 0
            else:
                self._rct_last = b
                self._rct_run = 1

            # --- Adaptive Proportion Test ---
            if self._apt_ref is None or self._apt_seen >= APT_WINDOW:
                self._apt_ref, self._apt_seen, self._apt_matches = b, 1, 1
            else:
                self._apt_seen += 1
                if b == self._apt_ref:
                    self._apt_matches += 1
                    if self._apt_matches >= APT_CUTOFF:
                        ok = False
                        self._fail(
                            f"adaptive proportion: 0x{b:02x} seen "
                            f"{self._apt_matches}/{self._apt_seen} in window"
                        )
                        self._apt_ref = None

            self._hist[b] += 1
            self._hist_n += 1

        if self._hist_n > 1 << 16:  # decay the histogram so it tracks recent behaviour
            for k in list(self._hist):
                self._hist[k] //= 2
                if not self._hist[k]:
                    del self._hist[k]
            self._hist_n = sum(self._hist.values())

        return ok

    def _fail(self, reason: str) -> None:
        self.failures += 1
        self.last_failure = reason
        self.quarantined = True

    def clear_quarantine(self) -> None:
        """Called after a source produces a clean run again (operator or scheduler driven)."""
        self.quarantined = False

    def shannon_bits_per_byte(self) -> float:
        """Shannon entropy of the recent-window histogram.

        Reported for observability only. Shannon entropy *overestimates* the min-entropy
        that actually matters for security, so it is never used to credit the pool --
        see `pool.py`, which credits every source at a fixed conservative rate instead.
        """
        if self._hist_n < 256:
            return 0.0
        n = self._hist_n
        return -sum((c / n) * math.log2(c / n) for c in self._hist.values() if c)

    def snapshot(self) -> dict:
        return {
            "source": self.name,
            "total_bytes": self.total_bytes,
            "failures": self.failures,
            "last_failure": self.last_failure,
            "quarantined": self.quarantined,
            "shannon_bits_per_byte": round(self.shannon_bits_per_byte(), 3),
        }
