"""Generate the published draw record in `examples/draw_page.html`.

That page is the artifact a customer hands to entrants: a finished draw with a
"check this yourself" button. It carried a hand-baked record, which meant it drifted
out of step with the pulse format and, for a while, demonstrated a verifier passing
input it should have refused.

So it is generated the same way the site is -- from a real service run, against a real
signed pulse, with a real commitment made before the deciding round was emitted.

    python scripts/build_draw_page.py
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PAGE = ROOT / "examples" / "draw_page.html"
MARKER = re.compile(r'(<script id="draw-data" type="application/json">).*?(</script>)', re.S)

TAG = "midsummer-giveaway-2026"
ENTRANTS = 4820
WINNERS = 3


async def build() -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    os.environ["BEAMLINE_BEACON_KEY"] = key.private_bytes_raw().hex()
    os.environ["BEAMLINE_DB"] = str(Path(tempfile.mkdtemp(prefix="beamline-draw-")) / "d.db")

    from beamline.service import BeamlineService

    svc = BeamlineService()
    await svc.start()
    for task in svc._tasks:                      # emit on our schedule, not the clock's
        if task.get_name() == "pulse":
            task.cancel()
    try:
        await asyncio.sleep(6.0)                 # let the network sources land a sample
        for _ in range(7):
            svc.beacon.emit()
        # Announced while the chain stands at 7, decided by round 8.
        commitment = svc.beacon.commit(TAG, key_id="demo", kind="sample",
                                       count=WINNERS, minimum=1, maximum=ENTRANTS)
        pulse = svc.beacon.emit()

        sys.path.insert(0, str(ROOT / "sdk" / "python"))
        from beamline_client import verify as v

        winners = v.reproduce_unique_integers(pulse["output"], TAG, WINNERS, 1, ENTRANTS)
        ok, reason = v.check_draw(pulse, commitment, winners, svc.beacon.public_key_hex,
                                  kind="sample", count=WINNERS, minimum=1,
                                  maximum=ENTRANTS)
        if not ok:
            raise SystemExit(f"refusing to publish a record that does not verify: {reason}")
    finally:
        await svc.stop()

    return {
        "tag": TAG, "winners": winners, "entrants": ENTRANTS, "kind": "sample",
        "pulse": pulse, "commitment": commitment,
        # Every commitment registered against the deciding round, not just ours.
        # Publishing the record without this leaves "was this their only draw against
        # this pulse?" resting on our own receipt's sequence number, and a record that
        # is meant to be the example should not need that caveat.
        "sibling_commitments": svc.db.commitments_for_round(pulse["round"]),
        "publicKey": svc.beacon.public_key_hex,
        "min": 1, "max": ENTRANTS, "count": WINNERS,
    }


def main() -> None:
    bundle = asyncio.run(build())
    payload = json.dumps(bundle, separators=(",", ":"))
    if "</script" in payload:
        raise SystemExit("refusing to inject: payload contains a closing script tag")
    html, n = MARKER.subn(lambda m: m.group(1) + payload + m.group(2), PAGE.read_text(), count=1)
    if n != 1:
        raise SystemExit('could not find the <script id="draw-data"> block')
    PAGE.write_text(html)
    print(f"injected round {bundle['pulse']['round']} into {PAGE}", file=sys.stderr)


if __name__ == "__main__":
    main()
