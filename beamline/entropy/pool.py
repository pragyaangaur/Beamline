"""The entropy accumulator.

Design: a set of independent sources each write into a SHA-512 accumulator. Seed
material is extracted by hashing the accumulator with a domain separator and a
counter, then folding in a fresh `os.urandom` read.

The `os.urandom` fold is not decoration. It is the reason this service is safe to
sell. The astrophysical inputs are *public data* -- anyone can fetch the same GOES
X-ray flux we do -- so they contribute zero secret entropy and we do not credit them
for any. The ANU stream is genuinely unpredictable but arrives over a third party's
TLS connection, so it is trustworthy only up to that third party. The kernel CSPRNG
is the one source an external adversary cannot observe. Mixing all three means an
attacker has to break the *union*, and the output is never worse than the best input.

Credit policy: each source is credited a fixed, conservative min-entropy rate rather
than a measured one. Measured estimates on a source you don't control are how people
talk themselves into overcrediting a dead source.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time

from .health import SourceHealth

# Conservative min-entropy credit, in bits per byte of source output.
CREDIT_BITS_PER_BYTE: dict[str, float] = {
    "anu_qrng": 6.0,   # base64url alphabet -> 6 bits/char ceiling; quantum origin
    "local_os": 8.0,   # kernel CSPRNG, full credit
    "astro": 0.0,      # PUBLIC data. Provenance and timing flavour only. Never secret.
}

# The pool refuses to hand out seed material until it has accumulated this much
# credited entropy since the last extraction.
MIN_SEED_BITS = 512


class EntropyPool:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._acc = hashlib.sha512()
        self._acc.update(b"beamline/pool/v1")
        self._acc.update(os.urandom(64))
        self._credited_bits = 0.0
        self._extractions = 0
        self.health: dict[str, SourceHealth] = {}
        # Latest raw sample per source, exposed in beacon provenance so a customer can
        # independently re-fetch the public inputs and confirm we used what we claim.
        self.last_sample: dict[str, dict] = {}

    def is_entropy_source(self, source: str) -> bool:
        """Whether this source is credited any entropy, and therefore health-tested.

        Zero-credit sources are public, structured data feeds. Running SP 800-90B
        health tests on them is a category error: NOAA's JSON is struct-packed doubles
        full of zero padding and repeated ASCII timestamps, so the repetition-count
        test trips immediately and the source shows up "quarantined". That verdict is
        meaningless -- the tests ask "has this entropy source degraded?", and a public
        data feed was never claiming to be one. Leaving it in place would train whoever
        is on call to ignore a quarantine flag, which is exactly the flag that matters
        when a real source dies.
        """
        return CREDIT_BITS_PER_BYTE.get(source, 0.0) > 0

    def add(self, source: str, data: bytes, meta: dict | None = None) -> bool:
        """Mix `data` from `source` into the pool.

        Returns False only if a credited entropy source failed its health tests.
        Zero-credit sources always return True: they are mixed for provenance and
        cannot fail a test they are not subject to.
        """
        if not data:
            return True

        healthy = True
        if self.is_entropy_source(source):
            h = self.health.setdefault(source, SourceHealth(source))
            healthy = h.update(data)
        else:
            h = None

        with self._lock:
            # Length-prefix and label every contribution so a source cannot forge
            # another source's framing by choosing its own bytes.
            self._acc.update(source.encode())
            self._acc.update(len(data).to_bytes(8, "big"))
            self._acc.update(data)
            self._acc.update(time.time_ns().to_bytes(16, "big"))
            if h is not None and healthy and not h.quarantined:
                self._credited_bits += len(data) * CREDIT_BITS_PER_BYTE[source]

        self.last_sample[source] = {
            # Integer milliseconds, never a float: this dict is published inside the
            # signed beacon body, and a float has no cross-language spelling. See
            # beamline/entropy/canonical.py.
            "at_ms": int(time.time() * 1000),
            "bytes": len(data),
            "digest": hashlib.sha256(data).hexdigest(),
            **(meta or {}),
        }
        return healthy

    @property
    def credited_bits(self) -> float:
        return self._credited_bits

    def ready(self) -> bool:
        return self._credited_bits >= MIN_SEED_BITS

    def extract(self, n: int = 64, *, require_ready: bool = True) -> bytes:
        """Pull `n` bytes of seed material. Always folds in a fresh kernel read.

        Extraction does not reset the accumulator -- the pool is a running hash, so
        past contributions keep protecting future seeds. It resets the *credit*
        counter, which is the thing that tracks "how much new unpredictability have
        we taken in since last time".
        """
        if require_ready and not self.ready():
            raise RuntimeError(
                f"entropy pool not ready: {self._credited_bits:.0f}/{MIN_SEED_BITS} bits credited"
            )
        with self._lock:
            self._extractions += 1
            fresh = os.urandom(64)
            self._acc.update(b"extract")
            self._acc.update(self._extractions.to_bytes(8, "big"))
            self._acc.update(fresh)
            state = self._acc.digest()
            self._credited_bits = 0.0

        out = bytearray()
        counter = 0
        while len(out) < n:
            out += hashlib.sha512(
                b"beamline/extract/v1" + state + counter.to_bytes(4, "big") + fresh
            ).digest()
            counter += 1
        return bytes(out[:n])

    def snapshot(self) -> dict:
        return {
            "credited_bits": round(self._credited_bits, 1),
            "min_seed_bits": MIN_SEED_BITS,
            "ready": self.ready(),
            "extractions": self._extractions,
            "sources": [h.snapshot() for h in self.health.values()],
            "provenance_only_sources": [
                {"source": name, "health_tested": False,
                 "reason": "public data, credited 0 bits", **sample}
                for name, sample in self.last_sample.items()
                if not self.is_entropy_source(name)
            ],
            "credit_policy_bits_per_byte": CREDIT_BITS_PER_BYTE,
        }
