"""Adaptive harvester for the public ANU QRNG endpoint.

Beamline runs without a paid ANU API key, so the public endpoint is the only source
of quantum entropy available to it. That makes sustained long-run yield the thing to
optimise -- not peak burst rate. The two are in direct conflict: the endpoint is a
single Apache host, and pushing past its service capacity buys queueing delay rather
than throughput, while raising the odds of an IP block that would take yield to zero
permanently.

Measured on the live endpoint (24 requests per level, HTTP/1.1 keep-alive):

    concurrency  1  ->   2.55 blocks/s   p50 326ms   2.55 blocks/s per connection
    concurrency  4  ->   8.53 blocks/s   p50 357ms   2.13 blocks/s per connection
    concurrency 12  ->  12.61 blocks/s   p50 693ms   1.05 blocks/s per connection

Throughput is still rising at 12, but latency has doubled and per-connection yield has
fallen 59%: past roughly 4-8 concurrent requests the extra load is being spent on the
server's queue, not on blocks. That is the classic congestion knee, and it moves with
time of day and network conditions, so it is found at runtime rather than hard-coded.

The controller is a latency-gradient limiter in the style of TCP Vegas: it holds a
long-run minimum RTT as the no-load baseline, and treats inflation above that baseline
as the signal to back off. Additive increase while latency is flat, multiplicative
decrease when it inflates or errors appear. This converges on the knee automatically
and retreats immediately when the endpoint is under strain.

Other things that matter more than raw concurrency:

  * **Connection reuse.** A fresh TLS handshake costs more than the request itself.
    The pool is kept warm; the number of sockets never exceeds the concurrency limit.
  * **Duplicate detection.** A repeated block carries no new entropy. The store rejects
    duplicates by hash, and a rising duplicate rate is treated as a signal that the
    endpoint has begun serving from cache -- at which point harvesting faster is
    actively counterproductive and the harvester slows down.
  * **Validation before archival.** An HTML error page is not entropy. Blocks are
    checked against the measured alphabet before they are written.
"""

from __future__ import annotations

import asyncio
import random
import signal
import statistics
import time
from collections import deque
from dataclasses import dataclass, field

import httpx

from .entropy import blocks as B
from .store import EntropyStore

DEFAULT_URL = "https://qrng.anu.edu.au/wp-content/plugins/colours-plugin/get_block_alpha.php"


@dataclass
class HarvestConfig:
    url: str = DEFAULT_URL
    #: Hard ceiling on in-flight requests. The controller usually settles below it.
    max_concurrency: int = 16
    min_concurrency: int = 1
    start_concurrency: int = 2
    #: Back off once sampled latency exceeds the no-load baseline by this factor.
    latency_ratio_limit: float = 1.6
    #: Multiplicative decrease applied on congestion or error.
    decrease_factor: float = 0.7
    #: Additive increase per healthy control interval.
    increase_step: float = 1.0
    #: How often the controller re-evaluates, in seconds.
    control_interval: float = 2.0
    timeout: float = 20.0
    #: Ease off if this share of recent blocks are duplicates.
    duplicate_alarm: float = 0.25
    max_consecutive_failures: int = 8
    user_agent: str = "beamline-harvester/1.0"


@dataclass
class HarvestStats:
    started: float = field(default_factory=time.time)
    requests: int = 0
    blocks_new: int = 0
    duplicates: int = 0
    invalid: int = 0
    errors: int = 0
    throttled: int = 0
    concurrency: float = 0.0
    baseline_rtt: float = 0.0
    last_rtt: float = 0.0
    last_adjustment: str = ""

    @property
    def elapsed(self) -> float:
        return max(1e-9, time.time() - self.started)

    @property
    def blocks_per_sec(self) -> float:
        return self.blocks_new / self.elapsed

    @property
    def bits_per_sec(self) -> float:
        """Entropy rate, using the measured 5.977 bits/char rather than a 6-bit assumption."""
        return B.entropy_bits(self.blocks_new * B.BLOCK_CHARS) / self.elapsed

    def as_dict(self) -> dict:
        return {
            "elapsed_seconds": round(self.elapsed, 1),
            "requests": self.requests,
            "blocks_new": self.blocks_new,
            "duplicates": self.duplicates,
            "invalid": self.invalid,
            "errors": self.errors,
            "throttled": self.throttled,
            "settled_concurrency": round(self.concurrency, 2),
            "baseline_rtt_ms": round(self.baseline_rtt * 1000),
            "last_rtt_ms": round(self.last_rtt * 1000),
            "last_adjustment": self.last_adjustment,
            "blocks_per_sec": round(self.blocks_per_sec, 2),
            "entropy_bits_per_sec": round(self.bits_per_sec),
            "entropy_kbit_per_sec": round(self.bits_per_sec / 1000, 1),
        }


class AdjustableSemaphore:
    """A semaphore whose capacity can change while tasks are waiting on it.

    asyncio.Semaphore has a fixed capacity, so the controller cannot shrink the number
    of in-flight requests without tearing down workers. This variant tracks capacity
    and in-flight count separately, letting the limit move up or down between requests
    without disturbing the worker pool.
    """

    def __init__(self, capacity: float):
        self._capacity = float(capacity)
        self._in_flight = 0
        self._cond = asyncio.Condition()

    @property
    def capacity(self) -> float:
        return self._capacity

    async def set_capacity(self, value: float) -> None:
        async with self._cond:
            self._capacity = value
            self._cond.notify_all()

    async def acquire(self) -> None:
        async with self._cond:
            await self._cond.wait_for(lambda: self._in_flight < self._capacity)
            self._in_flight += 1

    async def release(self) -> None:
        async with self._cond:
            self._in_flight -= 1
            self._cond.notify()


class AdaptiveHarvester:
    """Continuous-pipeline harvester with a latency-gradient concurrency controller.

    Workers run independently rather than in synchronised batches. A batched design
    has to wait for the slowest request in each round before starting the next, so a
    single 1-second tail request stalls every other connection -- head-of-line blocking
    that costs more throughput than any concurrency tuning can recover. Here each
    worker loops on its own and the controller adjusts the shared limit underneath them.
    """

    def __init__(self, store: EntropyStore, config: HarvestConfig | None = None):
        self.store = store
        self.cfg = config or HarvestConfig()
        self.stats = HarvestStats()
        self._sem = AdjustableSemaphore(self.cfg.start_concurrency)
        self._baseline: float | None = None
        self._recent: deque[float] = deque(maxlen=256)
        self._recent_dups: deque[int] = deque(maxlen=100)
        self._consecutive_failures = 0
        self._stop = asyncio.Event()
        self._target_blocks: int | None = None
        self.stats.concurrency = float(self.cfg.start_concurrency)

    # --- controller -------------------------------------------------------
    async def _control_loop(self) -> None:
        """Re-evaluate the concurrency limit on a fixed cadence."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.cfg.control_interval)
                return
            except asyncio.TimeoutError:
                pass

            if not self._recent:
                continue
            samples = list(self._recent)
            self._recent.clear()

            fastest = min(samples)
            if self._baseline is None or fastest < self._baseline:
                self._baseline = fastest
            else:
                # Drift the baseline up slowly so a genuinely slower network is not
                # mistaken for permanent congestion.
                self._baseline += (fastest - self._baseline) * 0.05
            self.stats.baseline_rtt = self._baseline

            rtt = statistics.median(samples)
            self.stats.last_rtt = rtt
            ratio = rtt / max(self._baseline, 1e-6)

            dups = sum(self._recent_dups)
            total = len(self._recent_dups)
            dup_rate = dups / total if total >= 20 else 0.0

            if ratio > self.cfg.latency_ratio_limit:
                await self._scale(self.cfg.decrease_factor, f"latency {ratio:.2f}x baseline")
            elif dup_rate > self.cfg.duplicate_alarm:
                # Duplicates mean the endpoint is repeating itself. Asking harder
                # cannot produce new entropy and only adds load.
                await self._scale(self.cfg.decrease_factor, f"duplicate rate {dup_rate:.0%}")
            else:
                await self._grow(self.cfg.increase_step)

    async def _scale(self, factor: float, why: str) -> None:
        new = max(self.cfg.min_concurrency, self._sem.capacity * factor)
        await self._sem.set_capacity(new)
        self.stats.concurrency = new
        self.stats.last_adjustment = why

    async def _grow(self, step: float) -> None:
        new = min(self.cfg.max_concurrency, self._sem.capacity + step)
        await self._sem.set_capacity(new)
        self.stats.concurrency = new

    # --- workers ----------------------------------------------------------
    async def _worker(self, client: httpx.AsyncClient) -> None:
        while not self._stop.is_set():
            if self._target_blocks and self.stats.blocks_new >= self._target_blocks:
                self._stop.set()
                return
            if self._consecutive_failures >= self.cfg.max_consecutive_failures:
                # Circuit breaker: something is durably wrong. Stop rather than
                # hammering a host that is already unhappy.
                self._stop.set()
                return

            await self._sem.acquire()
            try:
                t0 = time.perf_counter()
                try:
                    r = await client.get(self.cfg.url)
                except httpx.HTTPError as e:
                    self.stats.errors += 1
                    self._consecutive_failures += 1
                    await self._scale(self.cfg.decrease_factor, f"transport {type(e).__name__}")
                    await self._sleep(min(60.0, 2.0 ** self._consecutive_failures))
                    continue
                dt = time.perf_counter() - t0
                self.stats.requests += 1

                if r.status_code in (429, 503):
                    # An explicit slow-down outranks any latency measurement.
                    self.stats.throttled += 1
                    self._consecutive_failures += 1
                    await self._scale(0.5, f"server returned {r.status_code}")
                    retry = float(r.headers.get("Retry-After", 0) or 0)
                    await self._sleep(max(retry, min(60.0, 2.0 ** self._consecutive_failures)))
                    continue
                if r.status_code != 200:
                    self.stats.errors += 1
                    self._consecutive_failures += 1
                    await self._sleep(2.0)
                    continue

                self._consecutive_failures = 0
                self._recent.append(dt)

                try:
                    clean = B.validate(r.text)
                except B.InvalidBlock:
                    self.stats.invalid += 1
                    self.store.note_invalid()
                    continue

                # SQLite writes are synchronous; keep them off the event loop so a
                # disk stall does not look like network latency to the controller.
                added = await asyncio.to_thread(self.store.add_block, clean)
                if added:
                    self.stats.blocks_new += 1
                    self._recent_dups.append(0)
                else:
                    self.stats.duplicates += 1
                    self._recent_dups.append(1)
            finally:
                await self._sem.release()

    async def _sleep(self, seconds: float) -> None:
        # Jitter stops a restarted fleet from synchronising into a thundering herd.
        delay = seconds * (0.8 + 0.4 * random.random())
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    # --- public -----------------------------------------------------------
    def request_stop(self) -> None:
        self._stop.set()

    async def run(self, target_blocks: int | None = None, duration: float | None = None,
                  on_progress=None) -> HarvestStats:
        self._target_blocks = target_blocks
        self.stats = HarvestStats(concurrency=self._sem.capacity)

        limits = httpx.Limits(
            max_connections=self.cfg.max_concurrency,
            max_keepalive_connections=self.cfg.max_concurrency,
            keepalive_expiry=90.0,
        )
        async with httpx.AsyncClient(
            timeout=self.cfg.timeout,
            limits=limits,
            headers={"User-Agent": self.cfg.user_agent, "Accept-Encoding": "gzip"},
            follow_redirects=False,
        ) as client:
            tasks = [asyncio.create_task(self._worker(client))
                     for _ in range(self.cfg.max_concurrency)]
            tasks.append(asyncio.create_task(self._control_loop()))
            if duration:
                tasks.append(asyncio.create_task(self._deadline(duration)))
            if on_progress:
                tasks.append(asyncio.create_task(self._progress_loop(on_progress)))

            await self._stop.wait()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        return self.stats

    async def _deadline(self, duration: float) -> None:
        await self._sleep(duration)
        self._stop.set()

    async def _progress_loop(self, cb) -> None:
        while not self._stop.is_set():
            cb(self.stats)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=0.5)
                return
            except asyncio.TimeoutError:
                pass
