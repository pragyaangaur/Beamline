"""The kernel CSPRNG.

Always present, always healthy, fully credited. This source is what guarantees the
service degrades to "as good as any well-built local RNG" when every network source
is down, rather than degrading to something worse. It runs fast because it is free.
"""

from __future__ import annotations

import os

from .base import Sample, Source


class LocalSource(Source):
    name = "local_os"
    interval = 5.0
    public = False

    async def poll(self) -> Sample | None:
        data = os.urandom(64)
        self.record_ok()
        return Sample(data=data, meta={"provider": "kernel getrandom(2)"})
