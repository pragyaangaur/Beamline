"""Public beacon endpoints.

Deliberately unauthenticated. The beacon only has value if a sceptic -- a regulator,
a losing entrant, a journalist -- can pull the chain and check it without holding an
account. Charging for verification would defeat the product.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ... import generators as gen
from ...entropy.beacon import verify_commitment, verify_pulse
from ...service import SERVICE
from ..deps import Principal, bill, require_key

router = APIRouter(prefix="/v1/beacon", tags=["beacon"])


@router.get("/latest")
async def latest():
    pulse = SERVICE.beacon.latest()
    if pulse is None:
        raise HTTPException(404, "no pulses emitted yet; the first lands within one period")
    return pulse


@router.get("/public-key")
async def public_key():
    return {
        "algorithm": "ed25519",
        "public_key": SERVICE.beacon.public_key_hex,
        "signed": bool(SERVICE.beacon.public_key_hex),
        "note": "Unsigned pulses are still hash-chained and tamper-evident to anyone "
                "who recorded an earlier pulse, but cannot be attributed to Beamline "
                "by a third party.",
    }


@router.get("/pulse/{round_no}")
async def pulse(round_no: int):
    p = SERVICE.beacon.get(round_no)
    if p is None:
        raise HTTPException(404, f"pulse {round_no} not found")
    return p


@router.get("/chain")
async def chain(start: int = Query(1, ge=1), count: int = Query(50, ge=1, le=500)):
    return {"pulses": SERVICE.db.pulse_range(start, count)}


@router.get("/verify/{round_no}")
async def verify(round_no: int):
    """Server-side convenience check. The real verification is the client doing this itself."""
    p = SERVICE.beacon.get(round_no)
    if p is None:
        raise HTTPException(404, f"pulse {round_no} not found")
    prev = SERVICE.beacon.get(round_no - 1)
    ok, reason = verify_pulse(
        p,
        prev_output=prev["output"] if prev else None,
        public_key_hex=SERVICE.beacon.public_key_hex,
    )
    return {"round": round_no, "valid": ok, "reason": reason,
            "chain_verified_against": round_no - 1 if prev else "genesis"}


class CommitRequest(BaseModel):
    """Announce a draw against a pulse that has not been emitted yet."""

    tag: str = Field(..., min_length=1, max_length=256,
                     description="The exact string that names this draw. It is signed "
                                 "into the receipt, so it cannot be adjusted later.")
    target_round: int | None = Field(
        None, ge=1, description="Which future round decides the draw. Defaults to "
                                "`rounds_ahead` past the latest emitted round.")
    rounds_ahead: int = Field(1, ge=1, le=10_000,
                              description="Used when target_round is not given.")


@router.post("/commit", status_code=201)
async def commit(req: CommitRequest, p: Principal = Depends(require_key)):
    """Register a draw before the pulse that decides it exists.

    Without this, "we announced the draw first" is the runner's word. The receipt
    returned here is signed by Beamline and records the round the chain had reached
    at the time, so an entrant can check the announcement predates the outcome
    instead of taking it on trust.
    """
    try:
        receipt = SERVICE.beacon.commit(
            req.tag, req.target_round, rounds_ahead=req.rounds_ahead, key_id=p.key_id)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e

    bill(p, 32)
    return {
        **receipt,
        "publish_this": (
            "Post the commit_id and tag now, before round "
            f"{receipt['target_round']} lands. Anyone can then fetch "
            f"/v1/beacon/commitment/{receipt['commit_id']} and confirm the draw was "
            "named while the chain still stood at round "
            f"{receipt['created_after_round']}."
        ),
    }


@router.get("/commitment/{commit_id}")
async def commitment(commit_id: str):
    """Public: anyone can check what was announced, and when."""
    receipt = SERVICE.beacon.commitment(commit_id)
    if receipt is None:
        raise HTTPException(404, f"no commitment {commit_id!r}")
    ok, reason = verify_commitment(
        receipt, SERVICE.beacon.public_key_hex,
        allow_unsigned=not SERVICE.beacon.public_key_hex)
    pulse = SERVICE.beacon.get(receipt["target_round"])
    return {
        **receipt,
        "valid": ok,
        "reason": reason,
        "target_round_emitted": pulse is not None,
        "pulse_output": pulse["output"] if pulse else None,
    }


@router.get("/commitments/{round_no}")
async def commitments_for_round(round_no: int):
    """Every draw announced against one round.

    Deliberately public and deliberately complete. A runner who announces twenty
    draws against the same pulse and publishes only the flattering one is doing
    something this endpoint makes visible.
    """
    receipts = SERVICE.db.commitments_for_round(round_no)
    return {"round": round_no, "count": len(receipts), "commitments": receipts}


class DeriveRequest(BaseModel):
    """A reproducible draw pinned to a published pulse.

    `tag` is the caller's commitment string -- a draw id, an order number, anything
    that names *this specific* draw. Publish the tag before the pulse round happens
    and the result becomes something you can prove you did not choose.
    """

    round: int = Field(..., ge=1)
    tag: str = Field(..., min_length=1, max_length=256)
    kind: str = Field("integers", pattern="^(bytes|integers|shuffle|sample)$")
    count: int = Field(1, ge=1, le=gen.MAX_COUNT)
    min: int = 0
    max: int = 100
    items: list | None = None


@router.post("/derive")
async def derive(req: DeriveRequest, p: Principal = Depends(require_key)):
    pulse_rec = SERVICE.beacon.get(req.round)
    if pulse_rec is None:
        raise HTTPException(
            404, f"pulse {req.round} does not exist yet. Derivation only works against "
                 "already-published pulses -- that is what makes the result verifiable."
        )

    # A deterministic byte stream from the pulse, so the client can recompute this
    # offline from the published pulse alone. Buffered because `bounded_int` pulls
    # variable amounts under rejection sampling.
    stream = bytearray()
    pos = 0
    chunk = 0

    def rand(n: int) -> bytes:
        nonlocal pos, chunk
        while pos + n > len(stream):
            chunk += 1
            stream.extend(SERVICE.beacon.derive(req.round, f"{req.tag}#{chunk}", 4096))
        out = bytes(stream[pos:pos + n])
        pos += n
        return out

    try:
        if req.kind == "bytes":
            result = rand(req.count).hex()
        elif req.kind == "integers":
            result = gen.integers(rand, req.count, req.min, req.max)
        elif req.kind == "shuffle":
            if not req.items:
                raise ValueError("shuffle requires 'items'")
            result = gen.shuffle(rand, req.items)
        else:
            if not req.items:
                raise ValueError("sample requires 'items'")
            result = gen.sample(rand, req.items, req.count)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e

    bill(p, max(32, pos))
    return {
        "data": result,
        "round": req.round,
        "tag": req.tag,
        "pulse_output": pulse_rec["output"],
        "reproducible": True,
        "how_to_verify": (
            "stream = concat over i>=1 of SHA512('beamline/derive/v1' | pulse_output_bytes "
            "| f'{tag}#{i}' | uint32be(j)) for j=0..63; then apply the same generator "
            "algorithm. See sdk/python/beamline_client/verify.py for a reference implementation."
        ),
    }
