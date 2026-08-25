"""Emit one live pulse, from a scheduled job, with no server to trust.

Beamline's claim is that a pulse cannot be predicted before it is published. Making
that claim testable in public needs two things a static site cannot normally have: a
chain that keeps growing, and an ordering between "this person guessed" and "this
value existed" that the operator cannot quietly reverse.

This script supplies the first. It runs from a GitHub Actions schedule, gathers live
entropy, emits exactly one signed pulse, and appends it to `beacon/chain.json`. The
second comes free from where it runs: the pulse arrives as a commit made by a public
Actions run, timestamped by GitHub rather than by us. A prediction lodged as an issue
is timestamped the same way. Neither clock is ours, which is the point -- the previous
design had the operator's own server stamping "I received your guess at time T", and
a challenger had no reason to believe it.

`beacon/chain.json` holds a bounded window of recent pulses so the page stays small.
Nothing is lost by that: every pulse this file has ever held is in its git history,
which is public and append-only, so the archive is the commit log.

    BEAMLINE_BEACON_KEY=<hex> python scripts/beacon_tick.py --gather 20

The chain restarts at round 1 if the signing key changes. That is deliberate. A key
change mid-chain is a rotation, and an unendorsed rotation is exactly the forgery
`verify_chain` exists to catch -- so rather than teach the live chain to wave one
through, a new key starts a new chain that verifies cleanly from its own genesis.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CHAIN = ROOT / "beacon" / "chain.json"

#: How many pulses stay in the served file. Enough that a visitor can see the chain
#: link up and check several rounds by hand; small enough that the page loads on a
#: phone. The rest live in this file's git history.
WINDOW = 250


def load_chain(public_key_hex: str) -> list[dict]:
    """Recover the chain this key is entitled to continue.

    Returns an empty list -- a fresh genesis -- if the file is missing, empty, or
    signed by a different key. The key check is what stops a redeployed secret from
    silently grafting new pulses onto a chain nobody can verify end to end.
    """
    if not CHAIN.exists():
        return []
    try:
        bundle = json.loads(CHAIN.read_text())
    except json.JSONDecodeError:
        print("chain.json is not valid JSON; starting a new chain", file=sys.stderr)
        return []
    if bundle.get("public_key") != public_key_hex:
        if bundle.get("pulses"):
            print(f"chain.json is signed by {bundle.get('public_key')!r}, not the key "
                  f"in use; starting a new chain at round 1", file=sys.stderr)
        return []
    return bundle.get("pulses") or []


async def tick(gather: float, period: int) -> dict:
    """Gather entropy, emit one pulse, and return the whole bundle to be written."""
    key_hex = os.environ.get("BEAMLINE_BEACON_KEY", "").strip()
    if not key_hex:
        raise SystemExit(
            "BEAMLINE_BEACON_KEY is not set, so nothing would sign this pulse.\n"
            "Generate one with `beamline beacon-key` and add it to the repository's\n"
            "Actions secrets. An unsigned chain is not evidence of anything."
        )

    db_path = Path(tempfile.mkdtemp(prefix="beamline-tick-")) / "tick.db"
    os.environ["BEAMLINE_DB"] = str(db_path)
    os.environ["BEAMLINE_BEACON_PERIOD_SECONDS"] = str(period)

    # Imported after the environment is set: CONFIG is frozen at import time.
    from beamline.service import BeamlineService

    svc = BeamlineService()
    await svc.start()

    # The service emits on its own timer. This job emits exactly one pulse per run,
    # so that timer is cancelled: a background pulse landing mid-run would take the
    # round number this tick is about to publish and resolve predictions against a
    # value nobody announced.
    for task in svc._tasks:
        if task.get_name() == "pulse":
            task.cancel()

    try:
        previous = load_chain(svc.beacon.public_key_hex)
        for pulse in previous:
            svc.db.insert_pulse(pulse)

        # Let the network sources land at least one sample each. Without this the
        # pulse is honest but local-only, and its provenance block says so -- which
        # would make the published chain look thinner than the service really is.
        await asyncio.sleep(gather)

        pulse = svc.beacon.emit()
        print(f"emitted round {pulse['round']}", file=sys.stderr)

        first = max(1, pulse["round"] - WINDOW + 1)
        pulses = svc.db.pulse_range(first, WINDOW)
        health = svc.health()
    finally:
        await svc.stop()

    return {
        "public_key": svc.beacon.public_key_hex,
        "period_seconds": period,
        "window": WINDOW,
        "latest_round": pulse["round"],
        # Which inputs were actually reachable on this run. Reported whether or not it
        # flatters the beacon: a tick where the quantum source was down is still a
        # valid pulse, and hiding that would misrepresent what went into it. The
        # per-pulse `provenance` block is the authoritative record; this is a summary.
        "sources": [
            {"name": s["name"], "public_data": s["public_data"],
             "ok": s["consecutive_errors"] == 0 and bool(s["last_ok"]),
             "last_error": s["last_error"]}
            for s in (health.get("sources") or [])
        ],
        "pulses": pulses,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gather", type=float, default=20.0,
                    help="seconds to let the entropy sources poll before emitting")
    ap.add_argument("--period", type=int, default=600,
                    help="the cadence this beacon declares, in seconds")
    args = ap.parse_args()

    bundle = asyncio.run(tick(args.gather, args.period))
    CHAIN.parent.mkdir(parents=True, exist_ok=True)
    CHAIN.write_text(json.dumps(bundle, indent=1, sort_keys=True) + "\n")
    print(f"wrote {CHAIN.relative_to(ROOT)} at round {bundle['latest_round']}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
