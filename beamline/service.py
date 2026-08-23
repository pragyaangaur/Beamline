"""The Beamline service singleton: owns the pool, the sources, the DRBG and the beacon.

Lifecycle:

    sources --(async poll loops)--> EntropyPool --(reseed loop)--> HMAC_DRBG --> API
                                          \\
                                           `--(pulse loop)--> Beacon chain --> SQLite

Startup is deliberately blocking-until-seeded: the API refuses traffic until the pool
has produced a first seed. Serving randomness from an unseeded generator is the single
worst bug this kind of service can have, and it is always a startup-ordering bug, so
the ordering is enforced here rather than trusted to deployment.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time

from .challenge import ChallengeRegistry
from .config import CONFIG, TIERS
from .db import Database
from .entropy.beacon import Beacon
from .entropy.drbg import HmacDrbg
from .entropy.pool import EntropyPool
from .ratelimit import RateLimiter
from .sources import AnuSource, ArchiveSource, AstroSource, LocalSource

log = logging.getLogger("beamline")


class BeamlineService:
    def __init__(self) -> None:
        self.db = Database(CONFIG.db_path)
        self.pool = EntropyPool()
        self.limiter = RateLimiter()
        self.started_at = time.time()

        self.sources = [
            LocalSource(),
            ArchiveSource(),
            AnuSource(),
            AstroSource(interval=CONFIG.astro_poll_seconds),
        ]

        self.drbg: HmacDrbg | None = None
        self.beacon: Beacon | None = None
        self.challenge: ChallengeRegistry | None = None
        self._tasks: list[asyncio.Task] = []
        self._last_reseed = 0.0
        self._bytes_since_reseed = 0

    # --- startup ----------------------------------------------------------
    async def start(self) -> None:
        # Prime the pool synchronously from the always-available sources so the DRBG
        # can be instantiated before any request is accepted. Network sources join
        # the pool asynchronously and improve it from there.
        self.pool.add("local_os", os.urandom(128), {"provider": "startup prime"})
        archive = next(s for s in self.sources if isinstance(s, ArchiveSource))
        for _ in range(4):
            sample = await archive.poll()
            if sample is None:
                break
            self.pool.add(archive.name, sample.data, sample.meta)

        self.drbg = HmacDrbg(
            entropy=self.pool.extract(64, require_ready=False),
            nonce=time.time_ns().to_bytes(16, "big"),
            personalization=b"beamline/api/v1",
        )
        self._last_reseed = time.monotonic()

        signing_key = os.environ.get("BEAMLINE_BEACON_KEY", "")
        if not signing_key and not CONFIG.allow_unsigned_beacon:
            # This used to be a log line. A warning at startup is invisible to every
            # API client and to the entrant who is the whole reason the beacon exists,
            # and an unsigned deployment serves confident-looking pulses that cannot be
            # attributed to anybody. Refusing to start is the only version of this
            # message that reaches the person it needs to reach.
            raise RuntimeError(
                "BEAMLINE_BEACON_KEY is not set. Unsigned pulses are hash-chained but "
                "cannot be attributed to Beamline, so nobody can tell your chain from "
                "one an attacker generated this morning. Generate a key with "
                "`beamline beacon-key`, or set BEAMLINE_ALLOW_UNSIGNED_BEACON=1 if this "
                "is a development run nobody will rely on."
            )
        self.beacon = Beacon(self.db, self.pool, CONFIG.beacon_period_seconds, signing_key or None)
        if not signing_key:
            log.warning(
                "running with BEAMLINE_ALLOW_UNSIGNED_BEACON: pulses are chained but "
                "UNSIGNED and verification will report them as unattributed."
            )

        self.challenge = ChallengeRegistry(self.db, self.beacon)

        for src in self.sources:
            self._tasks.append(asyncio.create_task(self._poll_loop(src), name=f"poll:{src.name}"))
        self._tasks.append(asyncio.create_task(self._reseed_loop(), name="reseed"))
        self._tasks.append(asyncio.create_task(self._pulse_loop(), name="pulse"))
        log.info("beamline started with %d sources", len(self.sources))

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        for src in self.sources:
            if hasattr(src, "aclose"):
                await src.aclose()

    # --- background loops -------------------------------------------------
    async def _poll_loop(self, src) -> None:
        while True:
            try:
                sample = await src.poll()
                if sample is not None:
                    self.pool.add(src.name, sample.data, sample.meta)
            except asyncio.CancelledError:
                raise
            except Exception:
                # A source blowing up must never take down the loop that feeds every
                # other source. Log and keep the schedule.
                log.exception("source %s raised during poll", src.name)
                src.record_error("unhandled exception")

            await asyncio.sleep(src.backoff_seconds())

    async def _reseed_loop(self) -> None:
        while True:
            await asyncio.sleep(min(CONFIG.reseed_seconds, 15.0))
            try:
                self._maybe_reseed()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("reseed failed")

    def _maybe_reseed(self, force: bool = False) -> bool:
        if self.drbg is None:
            return False
        due = (
            force
            or (time.monotonic() - self._last_reseed) >= CONFIG.reseed_seconds
            or self._bytes_since_reseed >= CONFIG.reseed_bytes
        )
        if not due or not self.pool.ready():
            return False
        self.drbg.reseed(self.pool.extract(64), additional=time.time_ns().to_bytes(16, "big"))
        self._last_reseed = time.monotonic()
        self._bytes_since_reseed = 0
        return True

    async def _pulse_loop(self) -> None:
        # Align pulses to wall-clock period boundaries so round N always lands at a
        # predictable time. Customers deriving a draw from "the pulse at 14:00" need
        # that to mean something exact.
        while True:
            now = time.time()
            delay = CONFIG.beacon_period_seconds - (now % CONFIG.beacon_period_seconds)
            await asyncio.sleep(delay)
            try:
                pulse = self.beacon.emit()
                log.debug("pulse %d emitted", pulse["round"])
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("pulse emission failed")
                continue

            # Strictly after the pulse is emitted and persisted. The beacon never
            # reads the prediction registry while deciding what to publish, and this
            # ordering is the only reason a sceptic can confirm that from the source
            # rather than taking it on trust. Wrapped separately so that a fault in
            # scoring can never stop the chain: a beacon that skips a beat because of
            # a bookkeeping bug has damaged the thing it exists to provide.
            try:
                for outcome in self.challenge.resolve_due(pulse["round"]):
                    if outcome["winners"]:
                        log.warning(
                            "PREDICTION MATCHED at round %d by %s -- verify the receipt "
                            "and pay out", outcome["round"], ", ".join(outcome["winners"]))
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("resolving predictions for round %d failed; they stay "
                              "unresolved and will be retried next pulse", pulse["round"])

    # --- randomness -------------------------------------------------------
    def random_bytes(self, n: int) -> bytes:
        if self.drbg is None:
            raise RuntimeError("service not started")
        self._bytes_since_reseed += n
        if self._bytes_since_reseed >= CONFIG.reseed_bytes:
            self._maybe_reseed()
        return self.drbg.generate(n)

    def rand_fn(self):
        """A `rand(n) -> bytes` callable for `generators`, backed by the live DRBG."""
        return self.random_bytes

    # --- introspection ----------------------------------------------------
    def health(self) -> dict:
        seeded = self.drbg is not None
        source_states = [s.snapshot() for s in self.sources]
        live = [s for s in source_states if s["consecutive_errors"] == 0 and s["last_ok"]]
        return {
            "status": "ok" if seeded else "starting",
            "seeded": seeded,
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "sources_live": len(live),
            "sources": source_states,
            "pool": self.pool.snapshot(),
            "drbg": self.drbg.stats() if self.drbg else None,
            "beacon": {
                "period_seconds": CONFIG.beacon_period_seconds,
                "pulses": self.db.pulse_count(),
                "signed": bool(self.beacon and self.beacon.public_key_hex),
                "public_key": self.beacon.public_key_hex if self.beacon else None,
            },
            "challenge": {
                "enabled": CONFIG.challenge_enabled,
                "predictions": self.db.prediction_stats()["total"] if self.challenge else 0,
            },
            "tiers": {name: vars(t) for name, t in TIERS.items()},
        }


SERVICE = BeamlineService()
