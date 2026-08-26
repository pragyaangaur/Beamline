#!/usr/bin/env python3
"""Run the NIST SP 800-22 and SP 800-90B suites against Beamline's data paths.

    python scripts/run_nist_tests.py --target all
    python scripts/run_nist_tests.py --target raw --json reports/raw.json

Targets:
    raw-symbols   harvested ANU blocks, assessed over the native 63-symbol alphabet
    raw-packed    the same blocks packed at 6 bits/symbol, assessed as a bitstream
    conditioned   hash-conditioned harvested blocks (what actually enters the pool)
    drbg          HMAC_DRBG output (what the API serves)
    beacon        published pulse outputs (what the beacon PUBLISHES)
    urandom       the host kernel CSPRNG, as an experimental control

`beacon` is the target that matches the public claim. Everything else here assesses an
input to the beacon or a neighbouring output; the value a challenger is invited to
predict is the pulse `output`, and it was the one path with no target of its own. It is
produced by running the real emit path -- pool extraction, canonical encoding, SHA-512
over the signed body, chained to its predecessor -- and concatenating the outputs, so
what is assessed is the published artefact rather than a stand-in for it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np

from beamline.config import CONFIG
from beamline.db import Database
from beamline.entropy import blocks as Bl
from beamline.entropy.beacon import Beacon
from beamline.entropy.drbg import HmacDrbg
from beamline.entropy.pool import EntropyPool
from beamline.qa import report as R
from beamline.qa import sp80090b
from beamline.store import EntropyStore


def load_raw_chars(limit_blocks: int | None) -> str:
    store = EntropyStore(CONFIG.pool_dir)
    return "".join(store.iter_all_chars(limit_blocks))


def beacon_outputs(n_pulses: int) -> bytes:
    """Emit `n_pulses` real pulses and return their outputs concatenated.

    The real emit path, not an imitation of it: a live `EntropyPool` feeding
    `Beacon.emit`, so every output is a SHA-512 over a canonically encoded, chained,
    signed-shaped body exactly as the published ones are. That matters because this is
    the target that backs the public claim, and a target that tested a reconstruction
    of the pipeline would be evidence about the reconstruction.

    Two liberties, both of which make the test harder rather than easier:

      * No network sources. A runner has no ANU or NOAA feed, and waiting for one would
        put a ten-minute cadence in front of thirty thousand pulses. The pool still
        folds a fresh `os.urandom(64)` into every extraction, which is the input the
        beacon's unpredictability actually rests on -- so this measures the pipeline
        with its *weakest* credited configuration, not its best.
      * `require_ready=False`, which is what `Beacon.emit` passes in production anyway.

    Provenance is left empty, so the only field varying between consecutive bodies is
    `local_value` (and the timestamp, and the chained `prev_output`). If the extraction
    or the encoding leaked structure, this is where it would show.
    """
    import tempfile

    with tempfile.TemporaryDirectory(prefix="beamline-nist-") as tmp:
        db = Database(Path(tmp) / "beacon.db")
        beacon = Beacon(db, EntropyPool(), period_seconds=600)
        out = bytearray()
        for i in range(n_pulses):
            out += bytes.fromhex(beacon.emit()["output"])
            if (i + 1) % 5000 == 0:
                print(f"  emitted {i + 1:,}/{n_pulses:,} pulses", file=sys.stderr)
        return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="all",
                    choices=["all", "raw-symbols", "raw-packed", "conditioned", "drbg",
                             "beacon", "urandom"])
    ap.add_argument("--blocks", type=int, default=None, help="limit harvested blocks used")
    ap.add_argument("--stream-bits", type=int, default=1_000_000)
    ap.add_argument("--entropy-bits", type=int, default=1_000_000)
    ap.add_argument("--streams", type=int, default=None,
                    help="cap the number of 1 Mbit streams tested")
    ap.add_argument("--beacon-pulses", type=int, default=32_000,
                    help="pulses to emit for the `beacon` target (64 bytes of output each)")
    ap.add_argument("--json", metavar="PATH", help="also write the full report as JSON")
    args = ap.parse_args()

    targets = ([args.target] if args.target != "all"
               else ["raw-symbols", "raw-packed", "conditioned", "drbg", "beacon",
                     "urandom"])
    reports = []

    chars = None
    if any(t.startswith("raw") or t == "conditioned" for t in targets):
        chars = load_raw_chars(args.blocks)
        if not chars:
            print("no harvested blocks found; run scripts/harvest_anu.py first",
                  file=sys.stderr)
            return 1
        print(f"loaded {len(chars):,} harvested characters "
              f"({len(chars) // Bl.BLOCK_CHARS:,} blocks, "
              f"{Bl.entropy_bits(len(chars)) / 8 / 1024:.0f} KiB of source entropy)\n")

    for t in targets:
        t0 = time.time()
        if t == "raw-symbols":
            # The prediction estimators are O(n) with per-sample dictionary work, so
            # the symbol run is capped the same way the bitstream runs are.
            cap = max(50_000, args.entropy_bits)
            symbols = np.array([Bl.INDEX[c] for c in chars[:cap]], dtype=np.uint8)
            estimates, h = sp80090b.assess(symbols)
            print("=" * 78)
            print("RAW-SYMBOLS  --  harvested ANU blocks over the native 63-symbol alphabet")
            print(f"{len(symbols):,} symbols; theoretical maximum "
                  f"{Bl.BITS_PER_CHAR:.4f} bits/symbol")
            print("=" * 78)
            print("\nNIST SP 800-90B -- min-entropy (non-IID track)")
            for e in estimates:
                print("  " + str(e))
            print("  " + "-" * 74)
            print(f"  MIN-ENTROPY (worst estimator)      {h:.5f} bits/symbol")
            print(f"  as a fraction of the {Bl.BITS_PER_CHAR:.4f}-bit maximum: "
                  f"{h / Bl.BITS_PER_CHAR:.1%}")
            print()
            print("  Reference: a synthetic uniform 63-symbol source scored through this")
            print("  same pipeline yields ~4.98 bits/symbol, not 5.977. SP 800-90B's")
            print("  non-IID estimators are deliberately conservative at finite sample")
            print("  sizes, so THAT is the number to compare against, not the theoretical")
            print("  maximum. Run --target raw-symbols against a known-uniform control to")
            print("  reproduce the reference on your own hardware.")
            print(f"\n  [{time.time() - t0:.1f}s]\n")
            continue

        if t == "raw-packed":
            data = Bl.pack(chars)
            desc = "harvested blocks packed at 6 bits/symbol, no conditioning"
        elif t == "conditioned":
            data = Bl.condition(chars)
            desc = "hash-conditioned harvested blocks (what enters the entropy pool)"
        elif t == "drbg":
            import os
            drbg = HmacDrbg(os.urandom(64), nonce=b"nist-qa")
            need = max(len(chars) if chars else 0, 2_000_000)
            data = drbg.generate(need)
            desc = "HMAC_DRBG(SHA-512) output (what the API serves)"
        elif t == "beacon":
            data = beacon_outputs(args.beacon_pulses)
            desc = "published beacon pulse outputs (what the beacon PUBLISHES)"
        else:
            import os
            data = os.urandom(2_000_000)
            desc = "host kernel CSPRNG (experimental control)"

        rep = R.assess_bytes(data, t, desc,
                             stream_bits=args.stream_bits,
                             entropy_bits=args.entropy_bits,
                             max_streams=args.streams)
        print(R.render(rep))
        print(f"  [{time.time() - t0:.1f}s]\n")
        reports.append(asdict(rep))

    if args.json and reports:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(reports, indent=2))
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
