"""The public prediction registry: the part of Beamline a stranger is invited to break.

Beamline's central claim is narrow and falsifiable: *you cannot predict a pulse before
it is published*. Every other guarantee in the product is downstream of it. A claim
like that is worth nothing unless somebody can actually attempt it, and "email me if
you manage it" is not an attempt -- it is an assertion made afterwards, adjudicated by
the person it would embarrass.

So the attempt is a protocol rather than an honour system:

  1. A challenger POSTs a predicted `output` for a round that has not happened yet.
  2. The server refuses if that round already exists. This is the entire mechanism.
  3. The server returns a receipt signed with the *beacon's own key*, recording the
     round the chain had reached when the prediction arrived.
  4. When the round lands, resolution is mechanical: string equality against the
     published pulse.

Step 3 is what makes a disputed outcome arguable in the challenger's favour instead of
the operator's. The receipt is signed by the same key that signs every pulse, so an
operator who wanted to wave away a winning prediction would have to repudiate the key
their whole chain hangs from. Paying up is cheaper than that, and a challenger can see
in advance that it is cheaper. Nobody has to be trusted.

Nobody is going to win. That is not a hedge, it is the design: a challenge you might
lose to a lucky guess is a raffle, and 512 bits is not a raffle. What the registry
actually produces is a public record of how many people tried and how close they got --
and that record is a live bias test. See `prefix_bits`.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time

from .entropy.beacon import HAVE_ED25519
from .entropy.canonical import encode

if HAVE_ED25519:  # pragma: no branch - mirrors the beacon's optional import
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREDICTION_VERSION = "beamline/prediction/v1"

#: Exactly the fields covered by the signature, in this order. A field outside this
#: tuple is server-side bookkeeping and a verifier must not be asked to trust it.
PREDICTION_BODY_FIELDS = ("version", "prediction_id", "target_round",
                          "predicted_output", "handle", "received_at_ms",
                          "received_after_round", "public_key")

HEX_128 = re.compile(r"\A[0-9a-f]{128}\Z")

#: A pulse output is 64 bytes of SHA-512. Predictions are the same shape, because the
#: claim under test is about the published value and nothing else.
OUTPUT_BITS = 512


def normalise_output(value: str) -> str:
    """Lowercase and validate a predicted output, or raise ValueError.

    Case-folding here rather than at the edge means `ABCD...` and `abcd...` are the
    same prediction and cannot be submitted twice to buy two entries.
    """
    if not isinstance(value, str):
        raise ValueError("predicted output must be a string")
    folded = value.strip().lower()
    if folded.startswith("0x"):
        folded = folded[2:]
    if not HEX_128.match(folded):
        raise ValueError(
            f"a predicted output must be exactly 128 lowercase hex characters "
            f"(64 bytes of SHA-512), got {len(folded)} characters. This is the same "
            f"shape as the `output` field of any pulse from /v1/beacon/latest."
        )
    return folded


def prefix_bits(a: str, b: str) -> int:
    """How many leading bits two hex outputs share.

    This is the scoreboard's unit, and it is not decoration. For an independent guess
    against an unbiased pulse, P(prefix_bits >= k) = 2^-k exactly, so the mean over
    many resolved predictions is 1.0 and the distribution is geometric. Every losing
    attempt therefore contributes a sample to a cumulative, public test for bias in
    the published output -- which is one of the five breaks Beamline invites, and the
    one nobody could previously attempt without generating their own data.

    A challenger does not have to trust the aggregate: every prediction and every
    pulse is public, so the statistic recomputes from primary sources.
    """
    x = int.from_bytes(bytes.fromhex(a), "big") ^ int.from_bytes(bytes.fromhex(b), "big")
    return OUTPUT_BITS if x == 0 else OUTPUT_BITS - x.bit_length()


def prediction_body(receipt: dict) -> dict:
    return {k: receipt.get(k) for k in PREDICTION_BODY_FIELDS}


def verify_prediction(receipt: dict, public_key_hex: str | None = None, *,
                      allow_unsigned: bool = False) -> tuple[bool, str]:
    """Check a prediction receipt: signed by whom, and lodged before what.

    The receipt asserts "at this moment, with the chain standing at round N, this
    challenger named this exact 512-bit value for round M". It is evidence only if
    M > N. If the prediction arrived once its target round already existed, the
    challenger was copying, not predicting, and the receipt says so on its face.
    """
    if not isinstance(receipt, dict):
        return False, "prediction receipt must be an object"
    if receipt.get("version") != PREDICTION_VERSION:
        return False, (f"unknown prediction version {receipt.get('version')!r}; "
                       f"this verifier understands {PREDICTION_VERSION}")
    for field in ("prediction_id", "predicted_output"):
        if not isinstance(receipt.get(field), str) or not receipt[field]:
            return False, f"{field} must be a non-empty string"
    try:
        normalise_output(receipt["predicted_output"])
    except ValueError as e:
        return False, str(e)
    for field in ("target_round", "received_after_round", "received_at_ms"):
        value = receipt.get(field)
        if not isinstance(value, int) or isinstance(value, bool):
            return False, f"{field} must be an integer"

    # The load-bearing check. Everything else is bookkeeping.
    if receipt["target_round"] <= receipt["received_after_round"]:
        return False, (
            f"this receipt is not a prediction: round {receipt['target_round']} had "
            f"already been published when it was lodged (the chain stood at "
            f"{receipt['received_after_round']})."
        )

    signature = receipt.get("signature")
    if signature is None:
        if allow_unsigned:
            return True, "ok (unsigned; not attributable to Beamline)"
        return False, "prediction receipt is unsigned, so nothing attributes it to Beamline"

    key = public_key_hex or receipt.get("public_key")
    if not key:
        return False, "no public key to check the signature against"
    if receipt.get("public_key") and public_key_hex and receipt["public_key"] != public_key_hex:
        return False, ("the receipt names a different signing key than the one supplied; "
                       "check /v1/beacon/rotations before concluding it is a forgery")
    if not HAVE_ED25519:  # pragma: no cover - depends on install extras
        return False, "ed25519 support is not installed, so the signature cannot be checked"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(signature), encode(prediction_body(receipt)))
    except Exception:
        return False, "signature does not verify against the named key"
    return True, "ok"


class ChallengeRegistry:
    """Accepts predictions, and resolves them the moment their round lands.

    Holds no randomness of its own and never touches the pool. The beacon does not
    read this registry when emitting -- deliberately, and the ordering in
    `BeamlineService._pulse_loop` enforces it: a pulse is emitted and persisted
    before resolution is even called. An operator wanting to dodge a payout would
    have to withhold the pulse entirely, which leaves a hole in the chain that
    `/v1/beacon/verify-chain` reports to everybody.
    """

    def __init__(self, store, beacon) -> None:
        self._store = store
        self._beacon = beacon
        self._lock = threading.Lock()

    # --- submission -------------------------------------------------------
    def predict(self, predicted_output: str, target_round: int | None = None, *,
                rounds_ahead: int = 1, handle: str = "", submitter: str = "") -> dict:
        """Lodge a prediction against a round that has not been emitted.

        Refuses an already-published round for the same reason `Beacon.commit` does:
        a receipt that could be issued after the fact would be worthless to the person
        holding it, which is the challenger.
        """
        output = normalise_output(predicted_output)
        handle = (handle or "").strip()[:64]

        with self._lock:
            latest = self._beacon.latest()
            current = latest["round"] if latest else 0
            if target_round is None:
                target_round = current + max(1, rounds_ahead)
            if target_round <= current:
                raise ValueError(
                    f"round {target_round} has already been published (the chain is at "
                    f"{current}). Predict a future round -- copying a published output "
                    f"is not the thing being claimed impossible."
                )

            receipt = {
                "version": PREDICTION_VERSION,
                "prediction_id": hashlib.sha256(
                    b"beamline/prediction/v1" + os.urandom(32) + output.encode()
                ).hexdigest()[:32],
                "target_round": target_round,
                "predicted_output": output,
                "handle": handle,
                "received_at_ms": int(time.time() * 1000),
                "received_after_round": current,
                "public_key": self._beacon.public_key_hex,
            }
            if self._beacon._signer is not None:
                receipt["signature"] = self._beacon._signer.sign(
                    encode(prediction_body(receipt))).hex()
            self._store.insert_prediction(receipt, submitter=submitter)
            return receipt

    def get(self, prediction_id: str) -> dict | None:
        record = self._store.get_prediction(prediction_id)
        return self._decorate(record) if record else None

    def for_round(self, round_no: int) -> list[dict]:
        return [self._decorate(r) for r in self._store.predictions_for_round(round_no)]

    # --- resolution -------------------------------------------------------
    def resolve_round(self, round_no: int) -> dict:
        """Score every prediction lodged against a round that has just been published.

        Called from the pulse loop *after* the pulse is persisted, so the outcome is
        already public and immutable by the time anything here reads it.
        """
        pulse = self._beacon.get(round_no)
        if pulse is None:
            return {"round": round_no, "resolved": 0, "winners": []}

        actual = pulse["output"]
        winners: list[dict] = []
        resolved = 0
        for record in self._store.unresolved_predictions(round_no):
            bits = prefix_bits(record["predicted_output"], actual)
            exact = record["predicted_output"] == actual
            self._store.resolve_prediction(record["prediction_id"], actual, bits, exact)
            resolved += 1
            if exact:
                winners.append(record)
        return {"round": round_no, "resolved": resolved, "actual_output": actual,
                "winners": [w["prediction_id"] for w in winners]}

    def resolve_due(self, up_to_round: int) -> list[dict]:
        """Score every published round that still has unscored predictions.

        Called each pulse. Almost always this resolves exactly the round just emitted
        and nothing else; the loop exists so that a restart or a transient failure
        cannot leave somebody's attempt hanging forever.
        """
        return [self.resolve_round(r)
                for r in self._store.rounds_awaiting_resolution(up_to_round)]

    # --- reporting --------------------------------------------------------
    def _decorate(self, record: dict) -> dict:
        """Attach the verdict a reader would otherwise have to reconstruct."""
        receipt = record["receipt"]
        ok, reason = verify_prediction(
            receipt, self._beacon.public_key_hex,
            allow_unsigned=not self._beacon.public_key_hex)
        pulse = self._beacon.get(record["target_round"])
        return {
            **receipt,
            "receipt_valid": ok,
            "receipt_reason": reason,
            "resolved": record["resolved_at_ms"] is not None,
            "actual_output": pulse["output"] if pulse else None,
            "prefix_bits": record["prefix_bits"],
            "correct": bool(record["exact"]) if record["resolved_at_ms"] else None,
        }

    def scoreboard(self, recent: int = 20) -> dict:
        """The state of the challenge, as numbers anyone can recompute.

        `mean_prefix_bits` is the interesting one. Independent guesses against an
        unbiased 512-bit output give a geometric distribution with mean 1.0; a mean
        that drifts upward as the sample grows is evidence of exactly the bias this
        challenge invites people to find. It is reported even when it is boring,
        because a statistic only published when it flatters the operator is not
        evidence of anything.
        """
        stats = self._store.prediction_stats()
        n = stats["resolved"]
        return {
            "claim": ("You cannot predict a pulse before it is published. Lodge a "
                      "prediction for a future round; it is scored the moment that "
                      "round lands."),
            "predictions_total": stats["total"],
            "predictions_resolved": n,
            "predictions_pending": stats["total"] - n,
            "distinct_challengers": stats["handles"],
            "exact_hits": stats["exact"],
            "best_prefix_bits": stats["best_bits"],
            "mean_prefix_bits": round(stats["mean_bits"], 4) if n else None,
            "expected_mean_prefix_bits": 1.0,
            "bias_note": (
                f"Over {n} resolved predictions the mean shared prefix is "
                f"{stats['mean_bits']:.4f} bits against an expectation of 1.0 under "
                f"the null hypothesis that pulses are unpredictable. Sustained drift "
                f"upward would be a finding; short-run wobble is not."
                if n else
                "No predictions have been resolved yet, so there is nothing to say "
                "about bias. This field will not flatter the beacon until it can."
            ),
            "recent": [self._decorate(r) for r in self._store.recent_predictions(recent)],
        }
