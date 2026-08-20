"""ANU Quantum Random Number Generator.

The lab at the Australian National University measures vacuum fluctuations of the
electromagnetic field and publishes the result. It is a genuine quantum source and the
strongest physical input Beamline has.

Two access paths:

  * `BEAMLINE_ANU_API_KEY` set -> the official metered API at api.quantumnumbers.anu.edu.au,
    which comes with a contract and an SLA.
  * Otherwise -> the public endpoint that backs the site's colour demo.

Beamline currently runs on the public endpoint. Two components share it, with different
jobs:

  * `AnuSource` (this module) polls at a low rate to keep a trickle of live quantum
    entropy flowing into the pool while the service is up.
  * `AdaptiveHarvester` (`beamline/harvester.py`) does the bulk collection in the
    background, at a rate tuned at runtime to the endpoint's measured capacity.

The split matters because request latency on this endpoint rises sharply once its
service capacity is exceeded, and the extra load buys queueing rather than blocks. The
harvester finds that boundary and stays under it; the service never blocks on the
network for a customer request, because the DRBG stands between the two.
"""

from __future__ import annotations

import httpx

from ..config import CONFIG
from ..entropy import blocks as B
from ..store import EntropyStore
from .base import Sample, Source

from .. import USER_AGENT

OFFICIAL_API = "https://api.quantumnumbers.anu.edu.au/API/jsonI.php"


def _decode_alpha_block(text: str) -> bytes:
    """Condition a raw block into uniform bytes.

    Delegates to `entropy.blocks`, which derives the output length from the measured
    alphabet (63 symbols, 5.977 bits/char) rather than assuming base64url's 6.0.
    """
    return B.condition(text)


class AnuSource(Source):
    name = "anu_qrng"
    public = False

    def __init__(self) -> None:
        super().__init__()
        self.interval = CONFIG.anu_poll_seconds
        self._client = httpx.AsyncClient(
            timeout=15.0,
            headers={"User-Agent": USER_AGENT},
            limits=httpx.Limits(max_connections=2),
        )
        self._api_key = CONFIG.anu_api_key

    async def poll(self) -> Sample | None:
        try:
            if self._api_key:
                data, meta = await self._poll_official()
            else:
                data, meta = await self._poll_public()
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            self.record_error(f"HTTP {code}")
            if code in (429, 503):
                # Told to slow down. Escalate backoff hard rather than retrying at interval.
                self.consecutive_errors = max(self.consecutive_errors, 4)
            return None
        except Exception as e:
            self.record_error(f"{type(e).__name__}: {e}")
            return None

        if not data:
            self.record_error("empty response")
            return None
        self.record_ok()
        return Sample(data=data, meta=meta)

    async def _poll_public(self) -> tuple[bytes, dict]:
        r = await self._client.get(CONFIG.anu_url)
        r.raise_for_status()
        text = r.text.strip()
        if len(text) < 256 or "<" in text[:64]:
            raise ValueError("response does not look like an entropy block")
        return _decode_alpha_block(text), {"provider": "anu_public_endpoint", "chars": len(text)}

    async def _poll_official(self) -> tuple[bytes, dict]:
        r = await self._client.get(
            OFFICIAL_API,
            params={"length": 1024, "type": "hex16", "size": 2},
            headers={"x-api-key": self._api_key},
        )
        r.raise_for_status()
        payload = r.json()
        if not payload.get("success"):
            raise ValueError(f"ANU API error: {payload}")
        blob = "".join(payload["data"])
        return bytes.fromhex(blob), {"provider": "anu_official_api", "hex_chars": len(blob)}

    async def aclose(self) -> None:
        await self._client.aclose()


class ArchiveSource(Source):
    """Feeds the pool from blocks already harvested into the local store.

    This is what lets the service run at full rate without the API's demand being
    coupled to the endpoint's availability: `scripts/harvest_anu.py` fills the archive
    in the background, and the service drains it.

    Blocks are consume-once. `EntropyStore.reserve` marks what it hands out, so a block
    is never fed to the pool twice -- replaying archived bytes adds no unpredictability,
    and crediting them again would corrupt the pool's entropy accounting.
    """

    name = "anu_qrng"
    interval = 2.0
    public = False

    #: Blocks drawn per poll. Each carries ~6120 bits, so one block is already far
    #: more than the 512 bits the pool needs to consider itself reseedable.
    BLOCKS_PER_POLL = 2

    def __init__(self, store: EntropyStore | None = None) -> None:
        super().__init__()
        self.store = store or EntropyStore(CONFIG.pool_dir)
        self.exhausted = False

    async def poll(self) -> Sample | None:
        blocks = self.store.reserve(self.BLOCKS_PER_POLL)
        if not blocks:
            # Not an error: the archive is simply empty, and the live source plus the
            # kernel CSPRNG keep the pool healthy until the harvester refills it.
            self.exhausted = True
            return None

        self.exhausted = False
        joined = "".join(blocks)
        self.record_ok()
        return Sample(
            data=B.condition(joined),
            meta={
                "provider": "local_archive",
                "blocks": len(blocks),
                "chars": len(joined),
                "source_entropy_bits": round(B.entropy_bits(len(joined))),
                "remaining_blocks": self.store.unconsumed_count(),
            },
        )

    def snapshot(self) -> dict:
        return {**super().snapshot(),
                "archive_blocks_remaining": self.store.unconsumed_count(),
                "archive_empty": self.exhausted}
