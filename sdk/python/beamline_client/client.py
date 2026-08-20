"""Beamline Python client.

    from beamline_client import Beamline

    bl = Beamline(api_key="bl_live_...")
    bl.integers(6, 1, 49, unique=True)
    bl.password(length=24)

    # A draw anyone can check afterwards:
    draw = bl.fair_draw("weekly-raffle-471", count=3, min=1, max=5000)
    assert draw.verify()          # recomputed locally from the published pulse
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from . import verify as _v

DEFAULT_BASE = "https://api.beamline.dev"


class BeamlineError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"[{status}] {message}")
        self.status = status
        self.message = message


class RateLimited(BeamlineError):
    def __init__(self, message: str, retry_after: float):
        super().__init__(429, message)
        self.retry_after = retry_after


class QuotaExceeded(BeamlineError):
    pass


@dataclass
class FairDraw:
    """A draw pinned to a published beacon pulse.

    `verify()` recomputes the result locally from the pulse alone. It does not call
    the server, so a passing check means the server could not have made the numbers up.
    """

    data: Any
    round: int
    tag: str
    pulse_output: str
    kind: str
    params: dict

    def verify(self) -> bool:
        if self.kind == "integers":
            return self.data == _v.reproduce_integers(
                self.pulse_output, self.tag, self.params["count"],
                self.params["min"], self.params["max"],
            )
        if self.kind == "shuffle":
            return self.data == _v.reproduce_shuffle(
                self.pulse_output, self.tag, self.params["items"]
            )
        raise NotImplementedError(f"no local verifier for kind={self.kind!r}")


class Beamline:
    def __init__(self, api_key: str, base_url: str = DEFAULT_BASE, timeout: float = 30.0,
                 max_retries: int = 3):
        if not api_key:
            raise ValueError("an API key is required")
        self._max_retries = max_retries
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers={"Authorization": f"Bearer {api_key}",
                     "User-Agent": "beamline-python/0.1"},
        )

    # --- transport --------------------------------------------------------
    def _request(self, method: str, path: str, **kw) -> Any:
        last: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                r = self._http.request(method, path, **kw)
            except httpx.HTTPError as e:
                last = e
                time.sleep(min(2 ** attempt, 8))
                continue

            if r.status_code == 429:
                retry = float(r.headers.get("Retry-After", 2 ** attempt))
                if attempt == self._max_retries - 1:
                    raise RateLimited(_msg(r), retry)
                # Respect the server's backoff rather than hammering. The whole
                # point of a token bucket is defeated by a client that ignores it.
                time.sleep(retry)
                continue
            if r.status_code == 402:
                raise QuotaExceeded(402, _msg(r))
            if r.status_code >= 500 and attempt < self._max_retries - 1:
                time.sleep(min(2 ** attempt, 8))
                continue
            if r.status_code >= 400:
                raise BeamlineError(r.status_code, _msg(r))
            return r.json() if r.headers.get("content-type", "").startswith("application/json") else r.content

        raise BeamlineError(0, f"request failed after {self._max_retries} attempts: {last}")

    def _data(self, method: str, path: str, **kw) -> Any:
        return self._request(method, path, **kw)["data"]

    # --- live randomness --------------------------------------------------
    def bytes(self, n: int = 32) -> bytes:
        return self._request("GET", "/v1/random/bytes",
                             params={"n": n, "format": "binary"})

    def integers(self, count: int = 1, min: int = 0, max: int = 100,
                 unique: bool = False) -> list[int]:
        return self._data("POST", "/v1/random/integers",
                          json={"count": count, "min": min, "max": max, "unique": unique})

    def floats(self, count: int = 1, precision: int = 17) -> list[float]:
        return self._data("POST", "/v1/random/floats",
                          json={"count": count, "precision": precision})

    def gaussian(self, count: int = 1, mean: float = 0.0, stddev: float = 1.0) -> list[float]:
        return self._data("POST", "/v1/random/gaussian",
                          json={"count": count, "mean": mean, "stddev": stddev})

    def shuffle(self, items: list) -> list:
        return self._data("POST", "/v1/random/shuffle", json={"items": items})

    def sample(self, items: list, count: int) -> list:
        return self._data("POST", "/v1/random/sample", json={"items": items, "count": count})

    def weighted(self, items: list, weights: list[float], count: int = 1) -> list:
        return self._data("POST", "/v1/random/weighted",
                          json={"items": items, "weights": weights, "count": count})

    def uuid(self, count: int = 1) -> list[str]:
        return self._data("GET", "/v1/random/uuid", params={"count": count})

    def dice(self, count: int = 1, sides: int = 6) -> list[int]:
        return self._data("GET", "/v1/random/dice", params={"count": count, "sides": sides})

    def password(self, count: int = 1, length: int = 20,
                 charset: str = "unambiguous") -> list[dict]:
        return self._data("GET", "/v1/random/password",
                          params={"count": count, "length": length, "charset": charset})

    # --- verifiable draws -------------------------------------------------
    def latest_pulse(self) -> dict:
        return self._request("GET", "/v1/beacon/latest")

    def public_key(self) -> str | None:
        return self._request("GET", "/v1/beacon/public-key")["public_key"]

    def verify_chain(self, start: int = 1, count: int = 100) -> tuple[bool, str]:
        """Pull a run of pulses and check it locally, end to end."""
        pulses = self._request("GET", "/v1/beacon/chain",
                               params={"start": start, "count": count})["pulses"]
        return _v.check_chain(pulses, self.public_key())

    def fair_draw(self, tag: str, count: int = 1, min: int = 0, max: int = 100,
                  round: int | None = None, kind: str = "integers",
                  items: list | None = None) -> FairDraw:
        """Derive a draw from a published pulse.

        Publish `tag` BEFORE the pulse you intend to use exists. That ordering is what
        turns this from "a number the server gave me" into "a number neither of us
        could have chosen". Call `wait_for_next_pulse()` first if you want that
        guarantee automatically.
        """
        if round is None:
            round = self.latest_pulse()["round"]
        body = {"round": round, "tag": tag, "kind": kind, "count": count,
                "min": min, "max": max}
        if items is not None:
            body["items"] = items
        r = self._request("POST", "/v1/beacon/derive", json=body)
        return FairDraw(
            data=r["data"], round=r["round"], tag=r["tag"],
            pulse_output=r["pulse_output"], kind=kind,
            params={"count": count, "min": min, "max": max, "items": items},
        )

    def wait_for_next_pulse(self, poll: float = 2.0, timeout: float = 300.0) -> dict:
        """Block until a pulse newer than the current one is published."""
        start_round = self.latest_pulse()["round"]
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(poll)
            p = self.latest_pulse()
            if p["round"] > start_round:
                return p
        raise TimeoutError(f"no new pulse within {timeout}s")

    # --- account ----------------------------------------------------------
    def usage(self) -> dict:
        return self._request("GET", "/v1/me")

    def health(self) -> dict:
        return self._request("GET", "/v1/health")

    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _msg(r: httpx.Response) -> str:
    try:
        return r.json().get("detail", r.text)
    except Exception:
        return r.text[:200]
