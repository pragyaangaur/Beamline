"""Astrophysical input: NOAA SWPC real-time space weather.

Three feeds, all free, all keyless, all updating on the minute:

  * GOES-18/19 X-ray flux (0.05-0.4nm and 0.1-0.8nm) -- solar corona, measured from
    geostationary orbit.
  * DSCOVR/IMAP solar wind plasma at L1 -- proton speed, density, temperature of the
    solar wind roughly an hour upstream of Earth.
  * L1 magnetometer -- interplanetary magnetic field vector.

Why these and not a pulsar or a cosmic-ray monitor: they are the only genuinely
astrophysical measurements available in real time, keyless, with a minute cadence and
an institutional SLA. Pulsar timing and neutron-monitor archives publish on hour-to-day
delays and would make a poor live input. If Beamline later puts its own muon detector
on a Pi, it drops in as another `Source` subclass with no changes anywhere else.

THE IMPORTANT CAVEAT, stated here because it must not get lost in marketing:

    This data is public. NOAA serves the identical bytes to anyone who asks. It
    therefore contributes ZERO secret entropy, and `pool.CREDIT_BITS_PER_BYTE`
    credits it at 0.0 bits/byte. It is mixed in for provenance -- it timestamps the
    beacon against an independently observable physical record -- and because mixing
    a public value into a hash accumulator can never *reduce* the pool's entropy.

Any claim that Beamline's security rests on solar wind measurements would be false.
Its security rests on the ANU quantum stream and the kernel CSPRNG. The astrophysical
layer is what makes a beacon pulse *auditable*, which is a real and separate product
property. See `entropy/beacon.py`.
"""

from __future__ import annotations

import json
import struct

import httpx

from .base import Sample, Source

FEEDS = {
    "goes_xray": "https://services.swpc.noaa.gov/json/goes/primary/xrays-1-day.json",
    "solar_wind_plasma": "https://services.swpc.noaa.gov/json/rtsw/rtsw_wind_1m.json",
    "solar_wind_mag": "https://services.swpc.noaa.gov/json/rtsw/rtsw_mag_1m.json",
}

# Fields whose low-order digits carry instrument noise. We take the whole float and
# let the pool's hash conditioning handle it -- picking "the noisy digits" by hand is
# how you accidentally throw away the signal you meant to keep.
FIELDS = {
    "goes_xray": ("flux", "observed_flux", "electron_correction"),
    "solar_wind_plasma": ("proton_speed", "proton_density", "proton_temperature"),
    "solar_wind_mag": ("bt", "bx_gse", "by_gse", "bz_gse"),
}


class AstroSource(Source):
    name = "astro"
    interval = 60.0
    public = True  # <- public data. Credited zero secret entropy. See module docstring.

    def __init__(self, interval: float = 60.0) -> None:
        super().__init__()
        self.interval = interval
        self._client = httpx.AsyncClient(
            timeout=20.0,
            headers={"User-Agent": "beamline/0.1 (space weather client)"},
        )
        self._last_tags: dict[str, str] = {}

    async def poll(self) -> Sample | None:
        buf = bytearray()
        meta: dict = {"feeds": {}}
        fresh = False

        for feed, url in FEEDS.items():
            try:
                r = await self._client.get(url)
                r.raise_for_status()
                rows = r.json()
            except Exception as e:
                meta["feeds"][feed] = {"error": f"{type(e).__name__}"}
                continue

            if not isinstance(rows, list) or not rows:
                meta["feeds"][feed] = {"error": "empty"}
                continue

            # Take the newest few rows so a single stale sample doesn't dominate.
            recent = rows[-6:]
            tag = str(recent[-1].get("time_tag", ""))
            if tag and self._last_tags.get(feed) != tag:
                fresh = True
                self._last_tags[feed] = tag

            buf += feed.encode() + b"|"
            for row in recent:
                for field in FIELDS[feed]:
                    v = row.get(field)
                    if isinstance(v, (int, float)):
                        buf += struct.pack(">d", float(v))
                buf += str(row.get("time_tag", "")).encode()

            meta["feeds"][feed] = {"rows": len(recent), "latest_time_tag": tag}

        if not buf:
            self.record_error("all NOAA feeds unavailable")
            return None

        # `fresh` tracks whether NOAA actually advanced. If every feed served us the
        # same time_tag as last cycle we still mix (it costs nothing) but we say so,
        # because a beacon pulse whose provenance is stale should be visibly stale.
        meta["advanced"] = fresh
        self.record_ok()
        return Sample(data=bytes(buf), meta=meta)

    async def aclose(self) -> None:
        await self._client.aclose()
