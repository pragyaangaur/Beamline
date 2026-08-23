"""Public beacon endpoints.

Deliberately unauthenticated. The beacon only has value if a sceptic -- a regulator,
a losing entrant, a journalist -- can pull the chain and check it without holding an
account. Charging for verification would defeat the product.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from ... import generators as gen
from ...entropy.beacon import (draw_spec, verify_chain, verify_commitment,
                               verify_pulse, verify_rotation)
from ...service import SERVICE


def resolve_kind(kind: str, unique: bool) -> str:
    """Collapse the two ways of asking for distinct values into the one that is signed.

    `unique=True` on integers and `kind="sample"` over a range are the same draw. Two
    spellings are fine in a request and unacceptable in a commitment: the specification
    is signed, and a verifier that has to guess which spelling was meant is a verifier
    that can be argued with. So the alias is resolved here, once, and only the
    canonical form ever reaches a receipt.
    """
    return "sample" if (unique and kind == "integers") else kind
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
                "by a third party, and verification treats them as unattributed.",
        "pin_this_key": "Record this key out of band. A verifier that fetches the key "
                        "from the same server as the pulses checks only that the "
                        "server agrees with itself.",
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
    """Server-side convenience check. The real verification is the client doing this itself.

    Note what this endpoint cannot do for you. It is the operator answering a question
    about the operator's own chain: if the service were dishonest, so would this be.
    It is here to catch transport corruption and to show what the checks look like --
    not to substitute for running `beamline_client.verify` against a key you obtained
    somewhere other than from us.
    """
    p = SERVICE.beacon.get(round_no)
    if p is None:
        raise HTTPException(404, f"pulse {round_no} not found")
    prev = SERVICE.beacon.get(round_no - 1)
    signed = bool(SERVICE.beacon.public_key_hex)
    ok, reason = verify_pulse(
        p,
        prev_output=prev["output"] if prev else None,
        public_key_hex=SERVICE.beacon.public_key_hex,
        # An unsigned deployment cannot attribute anything. Earlier this fell through
        # to "valid: true" because there was no key to check against, which reported a
        # missing signature as a passing verification.
        allow_unsigned=not signed,
    )
    return {
        "round": round_no,
        "valid": ok,
        "reason": reason,
        "attributable": ok and signed,
        "chain_verified_against": round_no - 1 if prev else "genesis",
        "checked_against_key": SERVICE.beacon.public_key_hex,
        "note": ("This is the operator checking their own chain. Verify independently "
                 "with the SDK against a key you did not fetch from this server."),
    }


@router.get("/rotations")
async def rotations():
    """Every signing-key handover, each endorsed by the key it retired.

    Public and unauthenticated, because a verifier cannot check a key change without
    it. Trusting two keys says only that you would accept either; it does not show the
    first one ever handed over to the second.
    """
    records = SERVICE.db.rotations()
    return {
        "count": len(records),
        "rotations": [
            {**r, **dict(zip(("valid", "reason"), verify_rotation(r)))} for r in records
        ],
        "current_public_key": SERVICE.beacon.public_key_hex,
    }


@router.get("/verify-chain")
async def verify_chain_route(start: int = Query(1, ge=1), count: int = Query(50, ge=1, le=500)):
    """Verify a run of pulses end to end: links, ordering, and signatures together.

    Per-pulse checks miss the things that only exist across pulses -- a hole where a
    round was withheld, timestamps that do not increase -- and those are precisely
    what an archive assembled after the fact gets wrong.
    """
    pulses = SERVICE.db.pulse_range(start, count)
    if not pulses:
        raise HTTPException(404, f"no pulses from round {start}")
    signed = bool(SERVICE.beacon.public_key_hex)
    ok, reason = verify_chain(pulses, SERVICE.beacon.public_key_hex,
                              allow_unsigned=not signed,
                              rotations=SERVICE.db.rotations())
    return {"start": pulses[0]["round"], "end": pulses[-1]["round"],
            "count": len(pulses), "valid": ok, "reason": reason,
            "attributable": ok and signed}


class CommitRequest(BaseModel):
    """Announce a draw against a pulse that has not been emitted yet.

    The draw's shape is part of the announcement, not a detail settled later. A tag
    on its own does not determine a winner: one commitment to "giveaway-7" covers a
    draw of one winner from 100 and one from 5000, and those name different people.
    """

    tag: str = Field(..., min_length=1, max_length=256,
                     description="The exact string that names this draw. It is signed "
                                 "into the receipt, so it cannot be adjusted later.")
    target_round: int | None = Field(
        None, ge=1, description="Which future round decides the draw. Defaults to "
                                "`rounds_ahead` past the latest emitted round.")
    rounds_ahead: int = Field(1, ge=1, le=10_000,
                              description="Used when target_round is not given.")
    model_config = ConfigDict(extra="forbid")

    kind: str = Field("integers", pattern="^(bytes|integers|shuffle|sample)$")
    unique: bool = Field(
        False, description="Draw distinct values. Equivalent to kind='sample' over the "
                           "range, and stored as that, so a receipt has one spelling.")
    count: int = Field(1, ge=1, le=gen.MAX_COUNT)
    min: int = 0
    max: int = 100
    items: list | None = Field(
        None, description="The population, when the draw runs over one. Only its "
                          "digest is stored, but that digest is signed -- so adding "
                          "or removing an entrant afterwards invalidates the receipt.")


@router.post("/commit", status_code=201)
async def commit(req: CommitRequest, p: Principal = Depends(require_key)):
    """Register a draw before the pulse that decides it exists.

    Without this, "we announced the draw first" is the runner's word. The receipt
    returned here is signed by Beamline and records the round the chain had reached
    at the time, so an entrant can check the announcement predates the outcome
    instead of taking it on trust.
    """
    if req.min > req.max:
        raise HTTPException(400, "min must be <= max")
    kind = resolve_kind(req.kind, req.unique)
    if kind == "sample":
        population = len(req.items) if req.items is not None else req.max - req.min + 1
        if req.count > population:
            raise HTTPException(
                400, f"cannot draw {req.count} distinct values from a population of "
                     f"{population}. Committing to a draw that cannot be run would "
                     f"leave you holding a signed receipt for an outcome nobody can "
                     f"produce.")
    try:
        receipt = SERVICE.beacon.commit(
            req.tag, req.target_round, rounds_ahead=req.rounds_ahead, key_id=p.key_id,
            kind=kind, count=req.count, minimum=req.min, maximum=req.max,
            items=req.items)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e

    bill(p, 32)
    siblings = SERVICE.db.commitments_for_round(receipt["target_round"])
    mine = [c for c in siblings if c.get("committer") == p.key_id]
    return {
        **receipt,
        "your_commitments_for_this_round": len(mine),
        "exclusivity_note": (
            "This is your only draw against this round."
            if len(mine) == 1 else
            f"You now have {len(mine)} draws registered against round "
            f"{receipt['target_round']}. Each is individually valid, and a verifier "
            f"that fetches the public list will see all of them -- publishing only the "
            f"one you like is grinding, and the sequence number in this receipt says "
            f"which attempt it was."
        ),
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
    siblings = SERVICE.db.commitments_for_round(receipt["target_round"])
    mine = [c for c in siblings if c.get("committer") == receipt.get("committer")]
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
        "committer_draws_for_this_round": len(mine),
        "sibling_tags": sorted(c["tag"] for c in mine if c["commit_id"] != commit_id),
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

    `tag` names *this specific* draw -- a draw id, an order number, an entry-list
    hash. Deriving from an already-published pulse is reproducible by anyone, but
    reproducible is not the same as fair: a runner free to pick the tag after seeing
    the pulse, or to pick which pulse to call the draw, controls the outcome while
    every byte of cryptography stays honest.

    Pass `commit_id` to close that gap. Without one the result is still correct and
    still reproducible; it simply is not evidence of anything about timing, and the
    response says so rather than leaving the reader to assume otherwise.
    """

    model_config = ConfigDict(extra="forbid")

    round: int = Field(..., ge=1)
    tag: str = Field(..., min_length=1, max_length=256)
    commit_id: str | None = Field(
        None, max_length=64,
        description="The receipt from /v1/beacon/commit. Supply it and the response "
                    "carries proof the draw was named before this round existed; "
                    "omit it and the response says plainly that it does not.")
    kind: str = Field("integers", pattern="^(bytes|integers|shuffle|sample)$")
    unique: bool = Field(
        False, description="Draw distinct values. Equivalent to kind='sample'.")
    count: int = Field(1, ge=1, le=gen.MAX_COUNT)
    min: int = 0
    max: int = 100
    items: list | None = None


@router.post("/derive")
async def derive(req: DeriveRequest, p: Principal = Depends(require_key)):
    kind = resolve_kind(req.kind, req.unique)

    pulse_rec = SERVICE.beacon.get(req.round)
    if pulse_rec is None:
        raise HTTPException(
            404, f"pulse {req.round} does not exist yet. Derivation only works against "
                 "already-published pulses -- that is what makes the result verifiable."
        )

    commitment_rec = None
    if req.commit_id:
        commitment_rec = SERVICE.beacon.commitment(req.commit_id)
        if commitment_rec is None:
            raise HTTPException(404, f"no commitment {req.commit_id!r}")
        # The tag and round are inside the signed receipt, so mismatches here are the
        # server catching a runner trying to reuse one announcement for a different
        # draw. A verifier would catch it too; failing early is friendlier.
        if commitment_rec["tag"] != req.tag:
            raise HTTPException(
                409, f"commitment {req.commit_id} names tag {commitment_rec['tag']!r}, "
                     f"not {req.tag!r}")
        if commitment_rec["target_round"] != req.round:
            raise HTTPException(
                409, f"commitment {req.commit_id} names round "
                     f"{commitment_rec['target_round']}, not {req.round}")
        # The shape is signed too. A tag on its own does not pick a winner: the same
        # committed tag against the same pulse names one person at max=100 and a
        # different one at max=5000.
        asked = draw_spec(kind, req.count, req.min, req.max, req.items)
        if commitment_rec["draw"] != asked:
            differences = [f"{k}: committed {commitment_rec['draw'][k]!r}, "
                           f"requested {asked[k]!r}"
                           for k in asked if commitment_rec["draw"][k] != asked[k]]
            raise HTTPException(
                409, f"this draw is not the one committed under {req.commit_id}. "
                     + "; ".join(differences))
        ok, why = verify_commitment(
            commitment_rec, SERVICE.beacon.public_key_hex,
            allow_unsigned=not SERVICE.beacon.public_key_hex)
        if not ok:
            raise HTTPException(409, f"commitment {req.commit_id} does not verify: {why}")

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
        if kind == "bytes":
            result = rand(req.count).hex()
        elif kind == "integers":
            result = gen.integers(rand, req.count, req.min, req.max)
        elif kind == "shuffle":
            if not req.items:
                raise ValueError("shuffle requires 'items'")
            result = gen.shuffle(rand, req.items)
        elif req.items is not None:
            result = gen.sample(rand, req.items, req.count)
        else:
            # A raffle of N entrants by number: distinct values over the range, with no
            # list to send. This used to be rejected outright, which meant the service
            # would sign a commitment for a draw and then refuse to run it -- and the
            # flagship case, picking winners out of a numbered entry list, could not
            # go through the verifiable endpoint at all.
            result = gen.integers(rand, req.count, req.min, req.max, unique=True)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e

    bill(p, max(32, pos))
    return {
        "data": result,
        "round": req.round,
        "tag": req.tag,
        "pulse_output": pulse_rec["output"],
        "reproducible": True,
        "committed": commitment_rec is not None,
        "commitment": commitment_rec,
        # The authoritative answer to "was this their only draw against this round?".
        # A verifier holding it does not have to take the receipt's sequence number
        # on faith, and a runner cannot omit it without the omission being visible.
        "sibling_commitments": (
            SERVICE.db.commitments_for_round(req.round) if commitment_rec else None),
        "provenance_note": (
            f"Announced at round {commitment_rec['created_after_round']}, decided by "
            f"round {req.round}. The deciding pulse did not exist when the draw was "
            f"named, and the tag is inside the signed receipt, so neither could be "
            f"chosen after the fact."
            if commitment_rec else
            "NOT COMMITTED. This result is reproducible by anyone, but nothing here "
            "shows the draw was named before round "
            f"{req.round} was published -- the tag and the round were both chosen "
            "with the pulse already in hand. Use /v1/beacon/commit first if the "
            "result needs to convince someone who assumes you cheated."
        ),
        "how_to_verify": (
            "stream = concat over i>=1 of SHA512('beamline/derive/v1' | pulse_output_bytes "
            "| f'{tag}#{i}' | uint32be(j)) for j=0..63; then apply the same generator "
            "algorithm. See sdk/python/beamline_client/verify.py for a reference implementation."
        ),
    }
