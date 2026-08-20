#!/usr/bin/env python3
"""Harvest entropy blocks from the public ANU QRNG endpoint into the local store.

    python scripts/harvest_anu.py --blocks 500
    python scripts/harvest_anu.py --duration 3600          # run for an hour
    python scripts/harvest_anu.py --stats                  # inspect the archive

Concurrency is adapted at runtime by a latency-gradient controller; there is no
thread-count to tune. See `beamline/harvester.py` for the measurements behind it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beamline.config import CONFIG
from beamline.harvester import AdaptiveHarvester, HarvestConfig
from beamline.store import EntropyStore


def _render(stats, store_stats) -> str:
    return (
        f"\rblocks +{stats.blocks_new:<6} dup {stats.duplicates:<4} "
        f"err {stats.errors:<3} thr {stats.throttled:<3} | "
        f"conc {stats.concurrency:4.1f} | rtt {stats.last_rtt * 1000:4.0f}ms "
        f"(base {stats.baseline_rtt * 1000:4.0f}ms) | "
        f"{stats.blocks_per_sec:5.2f} blk/s {stats.bits_per_sec / 1000:6.1f} kbit/s | "
        f"archive {store_stats.total_blocks}"
    )


async def _run(args) -> int:
    store = EntropyStore(CONFIG.pool_dir)

    if args.import_legacy:
        added, skipped = store.import_legacy_text(Path(args.import_legacy))
        print(f"imported {added} blocks, skipped {skipped} (duplicate or invalid)")
        return 0

    if args.stats:
        print(json.dumps(store.stats().as_dict(), indent=2))
        return 0

    cfg = HarvestConfig(max_concurrency=args.max_concurrency)
    h = AdaptiveHarvester(store, cfg)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, h.request_stop)

    last_print = 0.0

    def progress(stats):
        nonlocal last_print
        now = time.time()
        if now - last_print > 0.5:
            print(_render(stats, store.stats()), end="", flush=True)
            last_print = now

    print(f"harvesting into {CONFIG.pool_dir} (ctrl-c to stop cleanly)")
    stats = await h.run(target_blocks=args.blocks, duration=args.duration,
                        on_progress=progress)

    print("\n\n--- session ---")
    print(json.dumps(stats.as_dict(), indent=2))
    print("--- archive ---")
    print(json.dumps(store.stats().as_dict(), indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--blocks", type=int, default=None, help="stop after N new blocks")
    ap.add_argument("--duration", type=float, default=None, help="stop after N seconds")
    ap.add_argument("--max-concurrency", type=int, default=12,
                    help="ceiling on in-flight requests (the controller usually settles lower)")
    ap.add_argument("--stats", action="store_true", help="print archive stats and exit")
    ap.add_argument("--import-legacy", metavar="PATH",
                    help="import a flat ASCII archive from an older scraper")
    args = ap.parse_args()

    if not any([args.blocks, args.duration, args.stats, args.import_legacy]):
        args.blocks = 100
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
