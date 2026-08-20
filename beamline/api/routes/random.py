"""The randomness endpoints.

Every response carries a `beacon_round` field naming the pulse that was current when
the request was served. That does NOT mean the bytes were derived from the pulse --
live API output comes from the DRBG and is private to the caller. It is an anchor:
it tells the customer where in the public chain their draw sits, which is what an
auditor asks for after the fact.

For draws that must be *provable*, use `/v1/beacon/derive` instead. The distinction
is documented at the endpoint and is the thing to be most careful not to blur in
marketing copy.
"""

from __future__ import annotations

import base64
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from ... import generators as gen
from ...service import SERVICE
from ..deps import Principal, bill, check_size, require_key

router = APIRouter(prefix="/v1/random", tags=["random"])


def _anchor() -> int | None:
    latest = SERVICE.beacon.latest() if SERVICE.beacon else None
    return latest["round"] if latest else None


def _envelope(data: Any, n_bytes: int) -> dict:
    return {"data": data, "beacon_round": _anchor(), "bytes_consumed": n_bytes,
            "source": "beamline-drbg"}


def _guard(fn, *args, **kwargs):
    """Generator argument errors are user errors, not 500s."""
    try:
        return fn(*args, **kwargs)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


# --- raw bytes ------------------------------------------------------------
@router.get("/bytes")
async def get_bytes(
    n: int = 32,
    format: Literal["base64", "hex", "binary"] = "base64",
    p: Principal = Depends(require_key),
):
    check_size(p, n)
    raw = SERVICE.random_bytes(n)
    bill(p, n)
    if format == "binary":
        return Response(raw, media_type="application/octet-stream",
                        headers={"X-Beamline-Beacon-Round": str(_anchor() or 0)})
    encoded = base64.b64encode(raw).decode() if format == "base64" else raw.hex()
    return _envelope(encoded, n)


# --- shaped values --------------------------------------------------------
class IntegersRequest(BaseModel):
    count: int = Field(1, ge=1, le=gen.MAX_COUNT)
    min: int = 0
    max: int = 100
    unique: bool = False


@router.post("/integers")
async def post_integers(req: IntegersRequest, p: Principal = Depends(require_key)):
    est = req.count * 8
    check_size(p, est)
    out = _guard(gen.integers, SERVICE.rand_fn(), req.count, req.min, req.max, req.unique)
    bill(p, est)
    return _envelope(out, est)


class FloatsRequest(BaseModel):
    count: int = Field(1, ge=1, le=gen.MAX_COUNT)
    precision: int = Field(17, ge=1, le=17)


@router.post("/floats")
async def post_floats(req: FloatsRequest, p: Principal = Depends(require_key)):
    est = req.count * 7
    check_size(p, est)
    out = _guard(gen.floats, SERVICE.rand_fn(), req.count, req.precision)
    bill(p, est)
    return _envelope(out, est)


class GaussianRequest(BaseModel):
    count: int = Field(1, ge=1, le=gen.MAX_COUNT)
    mean: float = 0.0
    stddev: float = 1.0


@router.post("/gaussian")
async def post_gaussian(req: GaussianRequest, p: Principal = Depends(require_key)):
    est = req.count * 14
    check_size(p, est)
    out = _guard(gen.gaussian, SERVICE.rand_fn(), req.count, req.mean, req.stddev)
    bill(p, est)
    return _envelope(out, est)


class ShuffleRequest(BaseModel):
    items: list[Any] = Field(..., min_length=1, max_length=gen.MAX_COUNT)


@router.post("/shuffle")
async def post_shuffle(req: ShuffleRequest, p: Principal = Depends(require_key)):
    est = len(req.items) * 4
    check_size(p, est)
    out = _guard(gen.shuffle, SERVICE.rand_fn(), req.items)
    bill(p, est)
    return _envelope(out, est)


class SampleRequest(BaseModel):
    items: list[Any] = Field(..., min_length=1, max_length=gen.MAX_COUNT)
    count: int = Field(1, ge=1)


@router.post("/sample")
async def post_sample(req: SampleRequest, p: Principal = Depends(require_key)):
    est = req.count * 8
    check_size(p, est)
    out = _guard(gen.sample, SERVICE.rand_fn(), req.items, req.count)
    bill(p, est)
    return _envelope(out, est)


class WeightedRequest(BaseModel):
    items: list[Any] = Field(..., min_length=1, max_length=gen.MAX_COUNT)
    weights: list[float] = Field(..., min_length=1)
    count: int = Field(1, ge=1, le=gen.MAX_COUNT)


@router.post("/weighted")
async def post_weighted(req: WeightedRequest, p: Principal = Depends(require_key)):
    est = req.count * 8
    check_size(p, est)
    out = _guard(gen.weighted_choice, SERVICE.rand_fn(), req.items, req.weights, req.count)
    bill(p, est)
    return _envelope(out, est)


@router.get("/uuid")
async def get_uuid(count: int = 1, p: Principal = Depends(require_key)):
    est = count * 16
    check_size(p, est)
    out = _guard(gen.uuid4, SERVICE.rand_fn(), count)
    bill(p, est)
    return _envelope(out, est)


@router.get("/dice")
async def get_dice(count: int = 1, sides: int = 6, p: Principal = Depends(require_key)):
    est = count * 4
    check_size(p, est)
    out = _guard(gen.dice, SERVICE.rand_fn(), count, sides)
    bill(p, est)
    return _envelope(out, est)


@router.get("/password")
async def get_password(
    count: int = 1,
    length: int = 20,
    charset: str = "unambiguous",
    p: Principal = Depends(require_key),
):
    est = count * length
    check_size(p, est)
    out = _guard(gen.password, SERVICE.rand_fn(), count, length, charset)
    bill(p, est)
    # Generated secrets must never sit in a shared cache or a proxy log.
    return Response(
        content=__import__("json").dumps(_envelope(out, est)),
        media_type="application/json",
        headers={"Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff"},
    )
