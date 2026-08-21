"""Generate the pulse chain embedded in the GitHub Pages site (`docs/index.html`).

The site is static, so its data has to be baked in -- but it is baked in from a real
run of the real service, not hand-written. This script starts a `BeamlineService`
against a throwaway database, lets the entropy sources poll, emits a short chain of
genuinely signed pulses, and writes them out as JSON.

    python scripts/build_site_data.py --rounds 10 --spacing 6

It writes `docs/chain.json` and injects the same bundle into the
`<script id="chain-data">` block of `docs/index.html`, so the page stays a single
self-contained file that works over file:// as well as over GitHub Pages.

    python scripts/build_site_data.py --inject-only    # re-inject existing chain.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


async def build(rounds: int, spacing: float, period: int) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    os.environ["BEAMLINE_BEACON_KEY"] = key.private_bytes_raw().hex()
    os.environ["BEAMLINE_DB"] = str(Path(tempfile.mkdtemp(prefix="beamline-site-")) / "site.db")
    os.environ["BEAMLINE_BEACON_PERIOD_SECONDS"] = str(period)

    # Imported after the environment is set: CONFIG is frozen at import time.
    from beamline.service import BeamlineService

    svc = BeamlineService()
    await svc.start()
    try:
        # Give the network sources a chance to land at least one sample each, so the
        # provenance blocks on the published pulses are real rather than local-only.
        await asyncio.sleep(spacing)
        for i in range(rounds):
            svc.beacon.emit()
            print(f"  round {i + 1}/{rounds}", file=sys.stderr)
            if i < rounds - 1:
                await asyncio.sleep(spacing)
        # Read the chain back from the database rather than collecting the return
        # values: the service's own pulse loop may have emitted alongside us, and a
        # chain with a hole in it would fail the consecutive-round check on the site.
        pulses = svc.db.pulse_range(1, rounds)
    finally:
        await svc.stop()

    return {
        "public_key": svc.beacon.public_key_hex,
        "period_seconds": period,
        "pulses": pulses,
    }


SITE = ROOT / "docs" / "index.html"
MARKER = re.compile(
    r'(<script id="chain-data" type="application/json">).*?(</script>)', re.S)


def inject(bundle: dict) -> None:
    """Replace the embedded JSON block in the site with `bundle`."""
    html = SITE.read_text()
    payload = json.dumps(bundle, separators=(",", ":"))
    if payload.find("</script") != -1:  # would terminate the block early
        raise SystemExit("refusing to inject: payload contains a closing script tag")
    new, n = MARKER.subn(lambda m: m.group(1) + payload + m.group(2), html, count=1)
    if n != 1:
        raise SystemExit('could not find the <script id="chain-data"> block in docs/index.html')
    SITE.write_text(new)
    print(f"injected {len(bundle['pulses'])} pulses into {SITE}", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--spacing", type=float, default=6.0, help="seconds between pulses")
    ap.add_argument("--period", type=int, default=60, help="declared pulse period")
    ap.add_argument("--out", default=str(ROOT / "docs" / "chain.json"))
    ap.add_argument("--inject-only", action="store_true",
                    help="skip generation; re-inject the existing chain.json")
    args = ap.parse_args()

    out = Path(args.out)
    if args.inject_only:
        bundle = json.loads(out.read_text())
    else:
        bundle = asyncio.run(build(args.rounds, args.spacing, args.period))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(bundle, indent=1) + "\n")
        print(f"wrote {len(bundle['pulses'])} pulses to {out}", file=sys.stderr)
    inject(bundle)


if __name__ == "__main__":
    main()
