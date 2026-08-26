"""Beamline Python client.

    from beamline_client import Beamline

    bl = Beamline(api_key="bl_live_...", base_url="http://127.0.0.1:8080")
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
from . import __version__ as _version

#: There is no hosted Beamline. The API is something you run -- see DEPLOY.md -- and
#: every example in the README points at a local one.
#:
#: This used to default to "https://api.beamline.dev", which is not the service. The
#: domain is registered to a parking host and refuses connections, so the visible
#: failure was a confusing timeout for anyone who omitted `base_url`. The invisible one
#: is worse: this client sends `Authorization: Bearer <your key>` on the first request,
#: so a default aimed at a host the project does not control is a live key disclosed to
#: whoever picks that domain up.
#:
#: So there is no default. The same fail-closed rule `verify_pulse` applies to a missing
#: trust anchor: if we cannot tell where this is supposed to point, say so rather than
#: guess somewhere plausible.
DEFAULT_BASE = None


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

    `verify()` does the whole check locally -- pulse signature, commitment, and the
    numbers -- without calling the server, so a passing result means the server could
    not have made any of it up.
    """

    data: Any
    round: int
    tag: str
    pulse_output: str
    kind: str
    params: dict
    pulse: dict | None = None
    commitment: dict | None = None
    #: Every commitment registered against this round, so `check()` can answer
    #: whether this was the committer's only draw rather than trusting the receipt.
    siblings: list | None = None
    public_key: str | None = None

    @property
    def committed(self) -> bool:
        """Whether this draw was announced before its deciding pulse existed."""
        return self.commitment is not None

    def verify(self, public_key: str | None = None) -> bool:
        """True only if this draw is fair, not merely reproducible.

        Reproducing the numbers proves the server did not invent them. It says nothing
        about whether the pulse is Beamline's, or whether the tag and round were picked
        after the pulse was published -- and picking either afterwards is enough to
        choose the winner outright. So this checks all of it, and returns False rather
        than raising if any part is missing.
        """
        ok, _ = self.check(public_key)
        return ok

    def check(self, public_key: str | None = None) -> tuple[bool, str]:
        """`verify()` with the reason attached, for when you need to explain a False."""
        key = public_key or self.public_key
        if self.pulse is None or self.commitment is None or not key:
            # Fall back to reproducing the numbers, and say plainly that this is the
            # weaker claim -- the caller should not read it as "the draw was fair".
            recomputed = self._recompute()
            if list(self.data) != list(recomputed):
                return False, "result does not reproduce from the pulse output"
            missing = ("commitment" if self.commitment is None else
                       "pulse" if self.pulse is None else "signing key")
            return False, (f"numbers reproduce, but with no {missing} this shows only "
                           f"that the server did not invent them -- not that the draw "
                           f"was named before the pulse existed")
        return _v.check_draw(
            self.pulse, self.commitment, self.data, key, kind=self.kind,
            items=self.params.get("items"), count=self.params.get("count", 1),
            minimum=self.params.get("min", 0), maximum=self.params.get("max", 100),
            siblings=self.siblings,
        )

    def _recompute(self):
        if self.kind == "integers":
            return _v.reproduce_integers(
                self.pulse_output, self.tag, self.params["count"],
                self.params["min"], self.params["max"],
            )
        if self.kind == "shuffle":
            return _v.reproduce_shuffle(
                self.pulse_output, self.tag, self.params["items"]
            )
        raise NotImplementedError(f"no local verifier for kind={self.kind!r}")


class Beamline:
    def __init__(self, api_key: str, base_url: str | None = DEFAULT_BASE,
                 timeout: float = 30.0, max_retries: int = 3):
        if not api_key:
            raise ValueError("an API key is required")
        if not base_url:
            raise ValueError(
                "base_url is required: there is no hosted Beamline to fall back to.\n"
                "Point it at the service you run, e.g.\n"
                "    Beamline(api_key=..., base_url='http://127.0.0.1:8080')\n"
                "See DEPLOY.md. Verification needs no server at all -- "
                "`beamline_client.verify` works offline against a published chain."
            )
        self._max_retries = max_retries
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers={"Authorization": f"Bearer {api_key}",
                     "User-Agent": f"beamline-python/{_version}"},
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

    def rotations(self) -> list[dict]:
        return self._request("GET", "/v1/beacon/rotations")["rotations"]

    def verify_chain(self, start: int = 1, count: int = 100,
                     public_key: str | None = None,
                     trusted_keys=None) -> tuple[bool, str]:
        """Pull a run of pulses and check it locally, end to end.

        `public_key` defaults to the server's own, which establishes only that the
        server agrees with itself. Pass a key you recorded out of band for an answer
        worth having.
        """
        pulses = self._request("GET", "/v1/beacon/chain",
                               params={"start": start, "count": count})["pulses"]
        return _v.check_chain(pulses, public_key or self.public_key(),
                              trusted_keys=trusted_keys, rotations=self.rotations())

    def commit(self, tag: str, target_round: int | None = None,
               rounds_ahead: int = 1, *, kind: str = "integers", count: int = 1,
               min: int = 0, max: int = 100, items: list | None = None) -> dict:
        """Announce a draw against a pulse that does not exist yet.

        The shape of the draw is part of the announcement. A tag on its own does not
        pick a winner -- the same tag against the same pulse names one person at
        max=100 and a different one at max=5000 -- so kind, count, bounds and the
        entry list are signed into the receipt alongside it.

        Publish the returned `commit_id` and `tag` immediately. That receipt is what
        an entrant checks later to see the draw was named before the outcome existed.
        """
        body = {"tag": tag, "rounds_ahead": rounds_ahead, "kind": kind,
                "count": count, "min": min, "max": max}
        if target_round is not None:
            body["target_round"] = target_round
        if items is not None:
            body["items"] = items
        return self._request("POST", "/v1/beacon/commit", json=body)

    def commitment(self, commit_id: str) -> dict:
        return self._request("GET", f"/v1/beacon/commitment/{commit_id}")

    def fair_draw(self, tag: str, count: int = 1, min: int = 0, max: int = 100,
                  round: int | None = None, kind: str = "integers",
                  items: list | None = None, commit: bool = True,
                  timeout: float = 300.0) -> FairDraw:
        """Announce a draw, wait for its pulse, and derive the result.

        By default this commits first and then blocks until the committed round is
        published, because the alternative -- deriving from a pulse that already
        exists -- is not a fair draw at all. Given a published pulse, a runner can
        search tag spellings until one names the winner they want (a hundred entrants
        costs about a hundred tries, which is instant), or keep the tag and choose
        which pulse to call the draw. Both produce results that verify perfectly.

        `commit=False` skips the commitment and derives from an existing pulse. The
        returned draw reports `committed == False` and `verify()` returns False for
        it: the numbers will reproduce, but nothing shows they were not chosen.
        """
        receipt = None
        if commit:
            receipt = self.commit(tag, target_round=round, kind=kind, count=count,
                                  min=min, max=max, items=items)
            round = receipt["target_round"]
            self.wait_for_round(round, timeout=timeout)
        elif round is None:
            round = self.latest_pulse()["round"]

        body = {"round": round, "tag": tag, "kind": kind, "count": count,
                "min": min, "max": max}
        if items is not None:
            body["items"] = items
        if receipt is not None:
            body["commit_id"] = receipt["commit_id"]
        r = self._request("POST", "/v1/beacon/derive", json=body)
        return FairDraw(
            data=r["data"], round=r["round"], tag=r["tag"],
            pulse_output=r["pulse_output"], kind=kind,
            params={"count": count, "min": min, "max": max, "items": items},
            pulse=self._request("GET", f"/v1/beacon/pulse/{r['round']}"),
            commitment=r.get("commitment"),
            siblings=r.get("sibling_commitments"),
            public_key=self.public_key(),
        )

    def wait_for_round(self, round_no: int, poll: float = 2.0,
                       timeout: float = 300.0) -> dict:
        """Block until `round_no` has been published."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            latest = self.latest_pulse()
            if latest["round"] >= round_no:
                return self._request("GET", f"/v1/beacon/pulse/{round_no}")
            time.sleep(poll)
        raise TimeoutError(f"round {round_no} was not published within {timeout}s")

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
