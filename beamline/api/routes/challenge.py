"""The public challenge: lodge a prediction, get it scored, argue with the record.

Unauthenticated on purpose, and more deliberately so than the beacon routes. Beamline
invites strangers to break it; putting an API key between a stranger and the attempt
would mean the only people who can try are people who registered with the operator
they are trying to catch out. The rate limits below are sized to stop a bored script
from filling the disk, not to make attempting the challenge inconvenient.

See `beamline.challenge` for why the receipt is the load-bearing part.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from ... import config as config_module
from ...challenge import OUTPUT_BITS, normalise_output
from ...service import SERVICE


# Resolved through the module rather than bound at import, so a deployment (or a
# test) can retune the limits without the routes having captured the old object.
def _cfg():
    return config_module.CONFIG

router = APIRouter(prefix="/v1/challenge", tags=["challenge"])


def submitter_id(request: Request) -> str:
    """A coarse, non-reversible handle for one origin, used only for rate limiting.

    Hashed rather than stored raw. The registry needs to know that fifty predictions
    came from one place; it has no need to know where, and a public challenge that
    quietly accumulates a table of IP addresses is collecting something it did not
    ask permission for. The digest never enters the signed receipt -- a verifier must
    not be handed a field the operator could have fabricated.
    """
    forwarded = request.headers.get("fly-client-ip") or request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")
    return hashlib.sha256(b"beamline/submitter/v1" + ip.encode()).hexdigest()[:16]


def _require_enabled() -> None:
    if not _cfg().challenge_enabled:
        raise HTTPException(503, "the prediction challenge is not running on this deployment")


def _next_round() -> dict:
    """Which round is open, and when it lands.

    Pulses are aligned to wall-clock period boundaries by the service, so this is
    arithmetic rather than a guess -- a challenger needs the deadline to be exact,
    because a prediction that arrives a second late is refused.
    """
    import time as _time

    latest = SERVICE.beacon.latest() if SERVICE.beacon else None
    period = _cfg().beacon_period_seconds
    now = _time.time()
    return {
        "latest_round": latest["round"] if latest else 0,
        "latest_output": latest["output"] if latest else None,
        "open_round": (latest["round"] if latest else 0) + 1,
        "period_seconds": period,
        "closes_in_seconds": round(period - (now % period), 1),
        "closes_at_ms": int((now - (now % period) + period) * 1000),
    }


@router.get("/rules")
async def rules():
    """The exact terms, in a form a challenger can read before spending effort.

    Written out rather than left to a blog post because the operator is also the
    adjudicator. Anything ambiguous here resolves in favour of whoever is holding
    the prize, which is the wrong default.
    """
    return {
        "claim": ("A Beamline pulse cannot be predicted before it is published."),
        "prize": _cfg().challenge_prize,
        "to_win": (
            f"Lodge the exact {OUTPUT_BITS}-bit `output` of a round that has not been "
            f"published, via POST /v1/challenge/predict, and have it match the pulse "
            f"when that round lands. Exact string equality on all 128 hex characters."
        ),
        "why_the_full_output": (
            "Not a smaller number, and not a derived draw. A one-in-a-hundred guess is "
            "won by luck roughly once every hundred tries, which would prove nothing "
            "about the beacon and would still cost the operator the prize. The claim "
            "under test is unpredictability, so the target is the whole published value."
        ),
        "how_it_is_adjudicated": (
            "Mechanically. Your receipt is signed by the same Ed25519 key that signs "
            "every pulse, and records the round the chain stood at when you lodged it. "
            "Resolution is string equality, run automatically the moment your round is "
            "published. The operator does not get a vote, and cannot deny a winning "
            "receipt without repudiating the key their whole chain depends on."
        ),
        "what_stops_the_operator_cheating": (
            "Less than you might want, and it is better to say so. The pulse is emitted "
            "and persisted before predictions are read, and the code ordering is public. "
            "But an operator who saw a winning prediction could in principle withhold "
            "that pulse and publish the next one instead -- the known re-roll gap in the "
            "threat model. It is not invisible: a withheld round leaves a hole that "
            "GET /v1/beacon/verify-chain reports, and the round cadence is fixed, so "
            "the gap is checkable by anyone watching. Watch the chain, not the promise."
        ),
        "limits": {
            "max_predictions_per_round_per_origin": _cfg().challenge_max_per_round,
            "max_rounds_ahead": _cfg().challenge_max_rounds_ahead,
            "note": ("Grinding does not help. Doubling your attempts halves an "
                     "already-negligible number and the scoreboard shows the count "
                     "next to the result."),
        },
        "also_worth_attacking": (
            "Four of the five breaks Beamline invites need no live server at all -- "
            "forging a chain, passing an uncommitted draw, making the Python and "
            "JavaScript verifiers disagree, or showing statistical bias. See the "
            "'Try to break it' section of the README. This endpoint only covers the "
            "first one, because it is the only one that needs a running beacon."
        ),
        "bias_channel": (
            "Losing predictions are not discarded. Each records how many leading bits "
            "it shared with the real output, which is a geometric(1/2) sample under the "
            "null hypothesis. GET /v1/challenge/scoreboard reports the running mean "
            "against its expectation of 1.0, so failed attempts accumulate into a "
            "public bias test rather than into nothing."
        ),
        "open_now": _next_round(),
    }


@router.get("/next")
async def next_round():
    """What to predict, and how long is left. Cheap enough to poll for a countdown."""
    return _next_round()


class PredictRequest(BaseModel):
    """A predicted pulse output, pinned to a round that has not happened."""

    model_config = ConfigDict(extra="forbid")

    predicted_output: str = Field(
        ..., description=f"The full {OUTPUT_BITS}-bit pulse output you claim round "
                         f"`target_round` will carry: 128 hex characters, the same "
                         f"shape as the `output` field of any published pulse.")
    target_round: int | None = Field(
        None, ge=1, description="Which round you are predicting. Defaults to the next "
                                "one, which is usually what you want.")
    handle: str = Field("", max_length=64,
                        description="Optional name for the public scoreboard. Anything "
                                    "you put here is published; leave it empty to stay "
                                    "anonymous.")


@router.post("/predict", status_code=201)
async def predict(req: PredictRequest, request: Request):
    """Lodge a prediction and receive a signed receipt proving when you lodged it.

    Keep the receipt. It is the whole of your claim: it names the value, the round,
    and the round the chain had reached when it arrived, and it is signed. Reproduce
    the check offline with `beamline.challenge.verify_prediction` against a public key
    you did not fetch from this server.
    """
    _require_enabled()
    if SERVICE.beacon is None:
        raise HTTPException(503, "the beacon has not started yet")

    origin = submitter_id(request)
    allowed, retry_after = SERVICE.limiter.check(
        f"challenge:{origin}", _cfg().challenge_burst, _cfg().challenge_refill)
    if not allowed:
        raise HTTPException(429, f"too many predictions; retry in {retry_after:.1f}s",
                            headers={"Retry-After": str(int(retry_after) + 1)})

    try:
        output = normalise_output(req.predicted_output)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e

    latest = SERVICE.beacon.latest()
    current = latest["round"] if latest else 0
    target = req.target_round if req.target_round is not None else current + 1
    if target > current + _cfg().challenge_max_rounds_ahead:
        raise HTTPException(
            400, f"round {target} is more than {_cfg().challenge_max_rounds_ahead} "
                 f"rounds away (the chain is at {current}). Booking far-future rounds "
                 f"does not improve your odds and does fill the registry.")

    already = SERVICE.db.count_predictions_by(origin, target)
    if already >= _cfg().challenge_max_per_round:
        raise HTTPException(
            429, f"you already have {already} predictions against round {target}, "
                 f"which is the per-round limit of {_cfg().challenge_max_per_round}. "
                 f"Guessing more values does not meaningfully change the odds against "
                 f"{OUTPUT_BITS} bits.")

    try:
        receipt = SERVICE.challenge.predict(
            output, target, handle=req.handle, submitter=origin)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e

    return {
        **receipt,
        "attempts_this_round_from_your_origin": already + 1,
        "keep_this": (
            "This receipt is your claim. It is signed by the beacon's key and records "
            f"that the chain stood at round {receipt['received_after_round']} when you "
            f"lodged a prediction for round {receipt['target_round']}. Verify it "
            "offline rather than trusting this response."
        ),
        "resolves_at": f"/v1/challenge/prediction/{receipt['prediction_id']}",
        "verify_offline": (
            "from beamline.challenge import verify_prediction; "
            "verify_prediction(receipt, public_key_hex)"
        ),
    }


@router.get("/prediction/{prediction_id}")
async def prediction(prediction_id: str):
    """Public: what was predicted, when, and how it went."""
    record = SERVICE.challenge.get(prediction_id)
    if record is None:
        raise HTTPException(404, f"no prediction {prediction_id!r}")
    return record


@router.get("/round/{round_no}")
async def round_predictions(round_no: int):
    """Every prediction lodged against one round, resolved or not.

    Complete by construction. A challenge where the operator picks which attempts to
    show is one where a winning attempt can quietly not have happened.
    """
    records = SERVICE.challenge.for_round(round_no)
    pulse = SERVICE.beacon.get(round_no) if SERVICE.beacon else None
    return {
        "round": round_no,
        "published": pulse is not None,
        "actual_output": pulse["output"] if pulse else None,
        "count": len(records),
        "winners": [r["prediction_id"] for r in records if r.get("correct")],
        "predictions": records,
    }


@router.get("/scoreboard")
async def scoreboard(recent: int = Query(20, ge=1, le=200)):
    """Aggregate state of the challenge, including the bias statistic."""
    return {**SERVICE.challenge.scoreboard(recent), "open_now": _next_round()}
