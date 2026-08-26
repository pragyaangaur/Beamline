"""The Beamline beacon: a signed, hash-chained public randomness feed.

This is the part of the product that a customer cannot build for themselves out of
`/dev/urandom`, and it is the reason the service is worth paying for.

Every `beacon_period_seconds` the service emits a *pulse*:

    output = SHA-512( VERSION + b"|" + canonical.encode(pulse.body()) )

where `VERSION` is the string below and `body()` is the eight signed fields: version,
round, timestamp_ms, period_seconds, prev_output, local_value, public_key, provenance.
The signature covers `canonical.encode(body)` alone, without the version prefix.

Both halves of that matter to anyone reimplementing the check, so neither is
paraphrased here. The bytes are `canonical.encode`'s, not `json.dumps`'s -- see
`entropy/canonical.py` for why a verifier that reaches for the latter will disagree
with this one about which pulses are honest. And the version really is part of the
preimage, so a pulse cannot be replayed under a later format that reads the same
fields differently. `output` and `signature` are excluded, being derived from the body
rather than inputs to it, which is why editing `output` alone leaves a pulse whose
signature still verifies and whose contents no longer hash to it.

Pulses form a hash chain, so changing any historical pulse invalidates every pulse
after it. Each pulse is signed with the service's Ed25519 key when one is configured,
so a third party can verify a pulse came from Beamline without trusting the transport.

What that buys a customer:

  * A raffle, lottery draw, shuffle, or audit sample can be derived from a *future*
    pulse. Because the pulse does not exist yet, neither the operator nor the customer
    can bias it -- and afterwards anyone can recompute the derivation and check it.
  * The provenance block records the digests of the physical inputs that fed the pulse,
    including the public astrophysical samples. Those are re-fetchable from NOAA by
    anyone, so a sceptic can confirm the pulse was produced no earlier than the
    timestamp on the space-weather data it consumed.

Each pulse also carries the public key that signed it, inside the signed body. That
makes key rotation an auditable event rather than a silent break: without it, rotating
the signing key would make every historical pulse fail against the current key, and a
verifier would have no way to distinguish an honest rotation from a forged archive.

Note the honest limits: the chain proves *tamper-evidence and ordering*, not that the
operator had no choice at all. An operator who withheld a pulse they disliked and
re-rolled would be caught only by observers who were watching live, or by the fact
that the astrophysical provenance would no longer line up. That is the same trust
model as the NIST Randomness Beacon, and it should be described to customers that way.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import asdict, dataclass, field

from .canonical import NotCanonical, encode, is_canonical, sanitize

try:  # optional -- the beacon still chains correctly unsigned
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    HAVE_ED25519 = True
except Exception:  # pragma: no cover - depends on install extras
    HAVE_ED25519 = False

GENESIS = "00" * 64
VERSION = "beamline/pulse/v3"
#: Versions this build will not verify, and why. Kept explicit so a verifier says
#: "produced by a version with a known weakness" rather than "unknown version".
RETIRED_VERSIONS = {
    "beamline/pulse/v1": "superseded before public release",
    "beamline/pulse/v2": (
        "signed a non-canonical JSON body, so a Python and a JavaScript verifier "
        "could disagree about whether a pulse was authentic"
    ),
}


@dataclass
class Pulse:
    version: str
    round: int
    #: Milliseconds since the epoch, as an INTEGER.
    #:
    #: Not a float, and this is not cosmetic. A float that rounds to a whole number
    #: serialises as "1787150090.0" in Python and "1787150090" in JavaScript, so the
    #: canonical bytes diverge and the signature fails to verify -- for roughly one
    #: pulse in a thousand, silently, and only for cross-language verifiers. Integers
    #: serialise identically everywhere, which is the property this field needs.
    timestamp_ms: int
    period_seconds: int
    prev_output: str
    local_value: str
    #: The Ed25519 key that signed this pulse, carried INSIDE the signed body.
    #: Without this a key rotation is indistinguishable from a forgery: every
    #: historical pulse simply stops verifying against the current key, and a
    #: verifier cannot tell "the operator rotated" from "these were faked".
    public_key: str | None = None
    provenance: dict = field(default_factory=dict)
    output: str = ""
    signature: str | None = None

    def body(self) -> dict:
        """The fields covered by the output hash and the signature."""
        return {
            "version": self.version,
            "round": self.round,
            "timestamp_ms": self.timestamp_ms,
            "period_seconds": self.period_seconds,
            "prev_output": self.prev_output,
            "local_value": self.local_value,
            "public_key": self.public_key,
            "provenance": self.provenance,
        }

    def signing_bytes(self) -> bytes:
        """Canonical bytes. Raises `NotCanonical` rather than signing something a
        verifier in another language might serialise differently."""
        return encode(self.body())

    def compute_output(self) -> str:
        return hashlib.sha512(self.version.encode() + b"|" + self.signing_bytes()).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)


HEX_LENGTHS = {"prev_output": 128, "local_value": 128, "output": 128,
               "public_key": 64, "signature": 128}

def _hex_field(pulse: dict, name: str, required: bool = True) -> str | None:
    """Structural check for one hex field. Length is fixed, so check it."""
    value = pulse.get(name)
    if value is None:
        if required:
            raise ValueError(f"missing field {name!r}")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    want = HEX_LENGTHS[name]
    if len(value) != want:
        raise ValueError(f"{name} must be {want} hex characters, got {len(value)}")
    try:
        bytes.fromhex(value)
    except ValueError as e:
        raise ValueError(f"{name} is not valid hex") from e
    return value


def check_structure(pulse: dict) -> None:
    """Reject anything malformed *before* any cryptography runs.

    A verifier that lets a malformed pulse reach the signature check has to decide
    what a thrown exception means, and the honest answers ("bad key", "old browser",
    "unsupported curve") are indistinguishable from the dishonest one. Rejecting here
    means the crypto only ever sees well-formed input, so a failure downstream can be
    treated as what it is: a failed verification.
    """
    version = pulse.get("version")
    if version in RETIRED_VERSIONS:
        raise ValueError(f"pulse version {version!r} is retired: {RETIRED_VERSIONS[version]}")
    if version != VERSION:
        raise ValueError(f"unexpected pulse version {version!r}; this verifier speaks {VERSION!r}")
    for name in ("round", "timestamp_ms", "period_seconds"):
        value = pulse.get(name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be an integer, got {type(value).__name__}")
    if pulse["round"] < 1:
        raise ValueError("round must be >= 1")
    if pulse["period_seconds"] < 1:
        raise ValueError("period_seconds must be >= 1")
    if pulse["timestamp_ms"] < 0:
        raise ValueError("timestamp_ms must not be negative")
    for name in ("prev_output", "local_value", "output"):
        _hex_field(pulse, name)
    _hex_field(pulse, "public_key", required=False)
    _hex_field(pulse, "signature", required=False)
    if not isinstance(pulse.get("provenance", {}), dict):
        raise ValueError("provenance must be an object")
    ok, why = is_canonical(_body_of(pulse))
    if not ok:
        raise ValueError(f"pulse body is not canonically encodable: {why}")
    if pulse["round"] == 1 and pulse["prev_output"] != GENESIS:
        raise ValueError("round 1 must start from the genesis value")


def _body_of(pulse: dict) -> dict:
    return Pulse(
        version=pulse["version"],
        round=pulse["round"],
        timestamp_ms=pulse["timestamp_ms"],
        period_seconds=pulse["period_seconds"],
        prev_output=pulse["prev_output"],
        local_value=pulse["local_value"],
        public_key=pulse.get("public_key"),
        provenance=pulse.get("provenance", {}),
    ).body()


def _trust_anchor(public_key_hex: str | None, trusted_keys) -> set[str] | None:
    if trusted_keys is None:
        return {public_key_hex} if public_key_hex else None
    if isinstance(trusted_keys, str):
        return {trusted_keys}
    keys = set(trusted_keys)
    return keys or None


def verify_pulse(pulse: dict, prev_output: str | None = None,
                 public_key_hex: str | None = None, *,
                 trusted_keys=None, allow_unsigned: bool = False) -> tuple[bool, str]:
    """Recompute a pulse's output, chain link, and signature. Returns (ok, reason).

    Verification is **fail-closed**, and both halves of that are deliberate.

    A trust anchor is required. Earlier revisions defaulted `public_key_hex` to None
    and, with no key to check against, accepted any internally consistent pulse -- so
    an attacker could publish a wholly fabricated unsigned chain and this function
    would call it valid. Authenticity cannot be established without knowing whose
    signature to expect, so a caller who supplies no key now gets a refusal instead of
    a green light. `allow_unsigned=True` is available for the one honest case, an
    operator inspecting their own not-yet-signed deployment, and it says so in the
    reason string.

    An unrecognised signing key is a failure, not a note. Treating it as an announced
    rotation and returning True meant a chain signed by an attacker's own key passed
    while the caller pinned the real one -- the reason string mentioned it, but every
    caller that checks the boolean saw success. Rotation is expressed by naming both
    keys in `trusted_keys`, which makes accepting a new key a decision the verifier
    makes rather than one the pulse announces about itself.
    """
    anchor = _trust_anchor(public_key_hex, trusted_keys)
    if anchor is None and not allow_unsigned:
        return False, ("no trust anchor: pass the signing key you expect, or "
                       "allow_unsigned=True to check structure and chaining only")

    try:
        check_structure(pulse)
    except ValueError as e:
        return False, str(e)

    p = Pulse(**{k: pulse.get(k) for k in
                 ("version", "round", "timestamp_ms", "period_seconds",
                  "prev_output", "local_value", "public_key")},
              provenance=pulse.get("provenance", {}))
    if p.compute_output() != pulse["output"]:
        return False, "output hash does not match pulse contents"
    if prev_output is not None and pulse["prev_output"] != prev_output:
        return False, "prev_output does not match the preceding pulse"

    sig = pulse.get("signature")
    declared = pulse.get("public_key")

    if not sig:
        if anchor is not None:
            return False, "pulse is unsigned and cannot be attributed to anyone"
        return True, "structure and chaining are valid; pulse is UNSIGNED and unattributed"

    if not declared:
        return False, "pulse is signed but declares no public key"
    if anchor is not None and declared not in anchor:
        return False, (f"signed by an untrusted key ({declared[:16]}...). If this is an "
                       f"announced rotation, pass it in trusted_keys.")
    if not HAVE_ED25519:
        return False, "signature present but ed25519 support is not installed"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(declared)).verify(
            bytes.fromhex(sig), p.signing_bytes())
    except Exception:
        return False, "ed25519 signature verification failed"

    if anchor is None:
        return True, "self-consistent and self-signed, but no trust anchor was supplied"
    return True, "ok"


COMMITMENT_VERSION = "beamline/commitment/v2"
COMMITMENT_BODY_FIELDS = ("version", "commit_id", "tag", "target_round",
                          "created_at_ms", "created_after_round", "committer",
                          "sequence", "draw", "public_key")
DRAW_SPEC_FIELDS = ("kind", "count", "min", "max", "items_digest")


def items_digest(items) -> str | None:
    """A stable digest of the population a draw runs over.

    Committing to the entry list matters as much as committing to the name. A runner
    who names the draw honestly and then adds or removes entrants before deriving has
    changed who can win without touching the tag, the round, or any signature.
    """
    if items is None:
        return None
    return hashlib.sha256(b"beamline/items/v1" + encode(list(items))).hexdigest()


def draw_spec(kind: str, count: int, minimum: int, maximum: int, items=None) -> dict:
    """The shape of a draw, as committed.

    The tag alone is not the draw. One commitment to "giveaway-7" covers a draw of
    one winner from 100 and a draw of one from 5000, and those name different people:

        count=1 min=1 max=100   -> [26]
        count=1 min=1 max=5000  -> [950]
        count=3 min=1 max=100   -> [26, 4, 54]

    Every one of those reproduces from the same pulse and the same committed tag, so a
    verifier that checks only the tag accepts whichever the runner liked best. The
    parameters are part of what has to be fixed in advance.
    """
    return {
        "kind": kind,
        "count": int(count),
        "min": int(minimum),
        "max": int(maximum),
        "items_digest": items_digest(items),
    }


def commitment_body(receipt: dict) -> dict:
    return {k: receipt.get(k) for k in COMMITMENT_BODY_FIELDS}


def _check_draw_spec(spec) -> str | None:
    if not isinstance(spec, dict):
        return "draw specification must be an object"
    if set(spec) != set(DRAW_SPEC_FIELDS):
        return f"draw specification must have exactly the fields {sorted(DRAW_SPEC_FIELDS)}"
    if not isinstance(spec["kind"], str) or not spec["kind"]:
        return "draw kind must be a non-empty string"
    for name in ("count", "min", "max"):
        if not isinstance(spec[name], int) or isinstance(spec[name], bool):
            return f"draw {name} must be an integer"
    if spec["min"] > spec["max"]:
        return "draw min must not exceed max"
    if spec["count"] < 1:
        return "draw count must be at least 1"
    digest = spec["items_digest"]
    if digest is not None and (not isinstance(digest, str) or len(digest) != 64):
        return "draw items_digest must be null or a 64-character hex digest"
    return None


def verify_commitment(receipt: dict, public_key_hex: str | None = None, *,
                      trusted_keys=None, allow_unsigned: bool = False) -> tuple[bool, str]:
    """Check a commitment receipt: signed by whom, and made before what.

    The receipt is the operator attesting "at this moment, with the chain standing at
    round N, this committer named this exact draw against round M". It is only worth
    anything if M > N -- otherwise the pulse that decides the draw already existed when
    the draw was named, and the runner could have chosen either.

    Note what this function does *not* answer: whether this was the only draw the
    committer registered against that round. `sequence` carries the count, and
    `beamline_client.verify.check_draw` is where it is acted on.
    """
    anchor = _trust_anchor(public_key_hex, trusted_keys)
    if anchor is None and not allow_unsigned:
        return False, "no trust anchor: pass the signing key you expect"
    if receipt.get("version") != COMMITMENT_VERSION:
        return False, f"unexpected commitment version {receipt.get('version')!r}"
    for name in ("target_round", "created_at_ms", "created_after_round", "sequence"):
        if not isinstance(receipt.get(name), int) or isinstance(receipt.get(name), bool):
            return False, f"{name} must be an integer"
    if receipt["sequence"] < 1:
        return False, "sequence must be at least 1"
    if not isinstance(receipt.get("tag"), str) or not receipt["tag"]:
        return False, "tag must be a non-empty string"
    if not isinstance(receipt.get("commit_id"), str) or not receipt["commit_id"]:
        return False, "commit_id must be a non-empty string"
    if not isinstance(receipt.get("committer"), str):
        return False, "committer must be a string"
    problem = _check_draw_spec(receipt.get("draw"))
    if problem:
        return False, problem
    if receipt["target_round"] <= receipt["created_after_round"]:
        return False, (f"commitment names round {receipt['target_round']} but the chain "
                       f"had already reached round {receipt['created_after_round']}; "
                       f"the deciding pulse existed before the draw was announced")

    ok, why = is_canonical(commitment_body(receipt))
    if not ok:
        return False, f"commitment body is not canonically encodable: {why}"

    sig, declared = receipt.get("signature"), receipt.get("public_key")
    if not sig:
        if anchor is not None:
            return False, "commitment is unsigned; anyone could have written it afterwards"
        return True, "well-formed but UNSIGNED: proves nothing about when it was made"
    if not declared:
        return False, "commitment is signed but declares no public key"
    if anchor is not None and declared not in anchor:
        return False, f"commitment signed by an untrusted key ({declared[:16]}...)"
    if not HAVE_ED25519:
        return False, "signature present but ed25519 support is not installed"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(declared)).verify(
            bytes.fromhex(sig), encode(commitment_body(receipt)))
    except Exception:
        return False, "ed25519 signature verification failed"
    return True, "ok"


# --- key rotation ----------------------------------------------------------
ROTATION_VERSION = "beamline/rotation/v1"
ROTATION_BODY_FIELDS = ("version", "from_public_key", "to_public_key",
                        "effective_round", "created_at_ms")


def rotation_body(record: dict) -> dict:
    return {k: record.get(k) for k in ROTATION_BODY_FIELDS}


def verify_rotation(record: dict, *, expect_from: str | None = None,
                    expect_to: str | None = None,
                    expect_round: int | None = None) -> tuple[bool, str]:
    """Check that the retiring key endorsed its successor, and the successor exists.

    Both signatures are required and they answer different questions. `signature_from`
    is the endorsement: the key being retired says this successor is legitimate, which
    is the only thing that distinguishes a rotation from someone else's archive.
    `signature_to` is proof of possession: without it an operator -- or anyone who
    compromised the old key once -- could rotate towards a public key nobody holds,
    stranding the chain on a key that can never sign again.
    """
    if record.get("version") != ROTATION_VERSION:
        return False, f"unexpected rotation version {record.get('version')!r}"
    for name in ("from_public_key", "to_public_key"):
        value = record.get(name)
        if not isinstance(value, str) or len(value) != 64:
            return False, f"{name} must be 64 hex characters"
        try:
            bytes.fromhex(value)
        except ValueError:
            return False, f"{name} is not valid hex"
    if record["from_public_key"] == record["to_public_key"]:
        return False, "a rotation must change the key"
    for name in ("effective_round", "created_at_ms"):
        if not isinstance(record.get(name), int) or isinstance(record.get(name), bool):
            return False, f"{name} must be an integer"
    if record["effective_round"] < 1:
        return False, "effective_round must be at least 1"

    ok, why = is_canonical(rotation_body(record))
    if not ok:
        return False, f"rotation body is not canonically encodable: {why}"
    if not HAVE_ED25519:
        return False, "ed25519 support is not installed"

    body = encode(rotation_body(record))
    for field, key in (("signature_from", record["from_public_key"]),
                       ("signature_to", record["to_public_key"])):
        sig = record.get(field)
        if not isinstance(sig, str) or len(sig) != 128:
            return False, f"{field} must be 128 hex characters"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                bytes.fromhex(sig), body)
        except Exception:
            return False, f"{field} is not a valid signature by {key[:16]}..."

    if expect_from is not None and record["from_public_key"] != expect_from:
        return False, (f"rotation retires {record['from_public_key'][:16]}... but the "
                       f"chain was using {expect_from[:16]}...")
    if expect_to is not None and record["to_public_key"] != expect_to:
        return False, (f"rotation appoints {record['to_public_key'][:16]}... but the "
                       f"chain switched to {expect_to[:16]}...")
    if expect_round is not None and record["effective_round"] != expect_round:
        return False, (f"rotation takes effect at round {record['effective_round']}, "
                       f"not round {expect_round}")
    return True, "ok"


#: How far a pulse's timestamp may sit from its scheduled slot before a strict
#: verifier calls the chain back-dated. Wide enough for clock skew and a slow emit.
MAX_TIMESTAMP_SKEW_MS = 5 * 60 * 1000


def verify_chain(pulses: list[dict], public_key_hex: str | None = None, *,
                 trusted_keys=None, allow_unsigned: bool = False,
                 enforce_period: bool = False, rotations=None,
                 allow_unendorsed_rotation: bool = False) -> tuple[bool, str]:
    """Verify a consecutive run of pulses. Any break invalidates everything after it.

    Beyond per-pulse verification this checks the properties that only exist across
    pulses: rounds are consecutive with no hole, each links to the one before it, and
    timestamps strictly increase. Non-increasing timestamps are the signature of an
    archive assembled after the fact, where rounds were written in whatever order the
    forger produced them.

    `enforce_period=True` additionally requires each gap to match the declared period
    within `MAX_TIMESTAMP_SKEW_MS`. It is off by default because a genuine chain can
    contain honest gaps -- a restart, a deploy -- and a verifier should not call those
    forgeries. Turn it on when auditing a run that is supposed to have been continuous.

    A change of signing key must be endorsed by the key being retired. Naming both
    keys in `trusted_keys` is not enough on its own: that only says you would accept
    either, and an attacker who talks you into trusting their key gets a substituted
    archive accepted with nothing in the chain contradicting it. Pass the operator's
    published `rotations` so the switch can be checked against an endorsement signed
    by the outgoing key. `allow_unendorsed_rotation=True` exists for archives that
    predate the mechanism and says what it is doing in the result.
    """
    if not pulses:
        return False, "empty chain"

    ordered = sorted(pulses, key=lambda p: p["round"])
    seen_keys: list[str] = []
    changes: list[int] = []

    for i, p in enumerate(ordered):
        prev = ordered[i - 1] if i else None
        ok, reason = verify_pulse(
            p,
            prev_output=prev["output"] if prev else None,
            public_key_hex=public_key_hex,
            trusted_keys=trusted_keys,
            allow_unsigned=allow_unsigned,
        )
        if not ok:
            return False, f"round {p['round']}: {reason}"
        if prev is not None:
            if p["round"] != prev["round"] + 1:
                return False, (f"chain jumps from round {prev['round']} to {p['round']}; "
                               f"a missing round hides whatever happened in it")
            if p["timestamp_ms"] < prev["timestamp_ms"]:
                # Non-decreasing, not strictly increasing: two pulses can honestly
                # share a millisecond. Time running backwards cannot happen in a
                # chain that was built as it went, and is what an archive assembled
                # afterwards -- rounds written in whatever order the forger produced
                # them -- gets wrong.
                return False, (f"round {p['round']} is dated before round "
                               f"{prev['round']}; the chain was not built in order")
            if enforce_period:
                gap = p["timestamp_ms"] - prev["timestamp_ms"]
                want = prev["period_seconds"] * 1000
                if abs(gap - want) > MAX_TIMESTAMP_SKEW_MS:
                    return False, (f"round {p['round']} lands {gap}ms after round "
                                   f"{prev['round']}, not the declared {want}ms")
        key = p.get("public_key")
        if seen_keys and key != seen_keys[-1]:
            ok, why = _endorsed(rotations, seen_keys[-1], key, p["round"],
                                allow_unendorsed_rotation)
            if not ok:
                return False, f"round {p['round']}: {why}"
            changes.append(p["round"])
        seen_keys.append(key)

    msg = (f"verified {len(ordered)} pulses from round {ordered[0]['round']} "
           f"to {ordered[-1]['round']}")
    if changes:
        # Never silent, even when endorsed: a reader deciding whether to trust this
        # archive needs to know the key changed under it.
        msg += (f"; signing key changed at round(s) {changes}"
                + (" WITHOUT ENDORSEMENT" if allow_unendorsed_rotation else
                   ", each endorsed by the key it retired"))
    return True, msg


def _endorsed(rotations, from_key, to_key, round_no: int,
              allow_unendorsed: bool) -> tuple[bool, str]:
    """Is this key change backed by a record the outgoing key signed?"""
    if allow_unendorsed:
        return True, "ok"
    if not rotations:
        return False, (f"the signing key changes here and no rotation records were "
                       f"supplied. Trusting both keys says only that you would accept "
                       f"either; it does not show {str(from_key)[:16]}... ever handed "
                       f"over to {str(to_key)[:16]}...")
    for record in rotations:
        if record.get("effective_round") != round_no:
            continue
        ok, why = verify_rotation(record, expect_from=from_key, expect_to=to_key,
                                  expect_round=round_no)
        return (True, "ok") if ok else (False, f"rotation record is not usable: {why}")
    return False, (f"the signing key changes here but no rotation record takes effect "
                   f"at round {round_no}")


class Beacon:
    """Owns the pulse chain. `store` is a `beamline.db.Database`."""

    def __init__(self, store, pool, period_seconds: int = 60, signing_key_hex: str | None = None):
        self._store = store
        self._pool = pool
        self.period = period_seconds
        self._lock = threading.Lock()
        self._signer = None
        self.public_key_hex: str | None = None
        if signing_key_hex and HAVE_ED25519:
            self._signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex))
            self.public_key_hex = self._signer.public_key().public_bytes_raw().hex()

    def latest(self) -> dict | None:
        return self._store.latest_pulse()

    def get(self, round_no: int) -> dict | None:
        return self._store.get_pulse(round_no)

    def emit(self) -> dict:
        """Produce and persist the next pulse."""
        with self._lock:
            prev = self._store.latest_pulse()
            round_no = (prev["round"] + 1) if prev else 1
            prev_output = prev["output"] if prev else GENESIS

            # 64 bytes straight out of the pool. Unlike the API's DRBG output this is
            # published, so it must never be reused for anything a customer holds.
            local_value = self._pool.extract(64, require_ready=False)

            # Source metadata is third-party data. Coerce it into the canonical
            # subset here, so a feed that starts returning floats degrades its own
            # provenance entry instead of producing a pulse that some verifiers
            # accept and others reject.
            provenance = sanitize({
                name: {k: v for k, v in sample.items() if k != "raw"}
                for name, sample in self._pool.last_sample.items()
            })

            p = Pulse(
                version=VERSION,
                round=round_no,
                timestamp_ms=int(time.time() * 1000),
                period_seconds=self.period,
                prev_output=prev_output,
                local_value=local_value.hex(),
                public_key=self.public_key_hex,
                provenance=provenance,
            )
            try:
                p.output = p.compute_output()
            except NotCanonical as e:  # pragma: no cover - sanitize() should prevent this
                raise RuntimeError(
                    f"refusing to emit a pulse whose body is not canonically "
                    f"encodable: {e}"
                ) from e
            if self._signer is not None:
                p.signature = self._signer.sign(p.signing_bytes()).hex()

            record = p.to_dict()
            self._store.insert_pulse(record)
            return record

    # --- commitments ------------------------------------------------------
    def commit(self, tag: str, target_round: int | None = None, *,
               rounds_ahead: int = 1, key_id: str = "",
               kind: str = "integers", count: int = 1, minimum: int = 0,
               maximum: int = 100, items=None) -> dict:
        """Record a draw against a round that has not happened yet.

        Refuses to commit to an already-emitted round. That refusal is the entire
        mechanism: it is what makes a commitment evidence rather than a note, because
        a receipt can only ever exist for a draw named before its deciding pulse.

        The receipt fixes the draw's *shape* as well as its name -- kind, count,
        bounds, and a digest of the entry list -- because a tag on its own does not
        determine a winner. It also carries `sequence`, this committer's running count
        of draws registered against this round, so registering twenty and publishing
        the flattering one leaves a signed trace.
        """
        with self._lock:
            latest = self._store.latest_pulse()
            current = latest["round"] if latest else 0
            if target_round is None:
                target_round = current + max(1, rounds_ahead)
            if target_round <= current:
                raise ValueError(
                    f"round {target_round} has already been emitted (the chain is at "
                    f"{current}). A draw can only be committed to a future pulse -- "
                    f"that is what proves nobody chose the outcome."
                )
            receipt = {
                "version": COMMITMENT_VERSION,
                "commit_id": hashlib.sha256(
                    b"beamline/commit/v1" + os.urandom(32) + tag.encode()
                ).hexdigest()[:32],
                "tag": tag,
                "target_round": target_round,
                "created_at_ms": int(time.time() * 1000),
                "created_after_round": current,
                "committer": key_id,
                "sequence": self._store.count_commitments_by(key_id, target_round) + 1,
                "draw": draw_spec(kind, count, minimum, maximum, items),
                "public_key": self.public_key_hex,
            }
            if self._signer is not None:
                receipt["signature"] = self._signer.sign(
                    encode(commitment_body(receipt))).hex()
            self._store.insert_commitment(receipt, key_id)
            return receipt

    def commitment(self, commit_id: str) -> dict | None:
        return self._store.get_commitment(commit_id)

    # --- key rotation -----------------------------------------------------
    def endorse_rotation(self, new_signing_key_hex: str, effective_round: int) -> dict:
        """Sign over authority from the current key to its successor.

        Called while the *old* key is still loaded, which is the only moment the
        endorsement can be produced. An operator who rotates first and thinks about
        provenance afterwards has already lost the ability to prove the change was
        theirs.
        """
        if self._signer is None:
            raise RuntimeError("cannot endorse a rotation: this beacon has no signing key")
        new_signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(new_signing_key_hex))
        record = {
            "version": ROTATION_VERSION,
            "from_public_key": self.public_key_hex,
            "to_public_key": new_signer.public_key().public_bytes_raw().hex(),
            "effective_round": effective_round,
            "created_at_ms": int(time.time() * 1000),
        }
        body = encode(rotation_body(record))
        record["signature_from"] = self._signer.sign(body).hex()
        record["signature_to"] = new_signer.sign(body).hex()
        self._store.insert_rotation(record)
        return record

    def rotations(self) -> list[dict]:
        return self._store.rotations()

    def derive(self, round_no: int, tag: str, n: int) -> bytes:
        """Deterministically derive `n` bytes from a published pulse and a caller tag.

        Two different customers using two different tags against the same pulse get
        unrelated streams, and each can prove their own draw was fixed by the pulse.
        """
        pulse = self._store.get_pulse(round_no)
        if pulse is None:
            raise KeyError(f"pulse {round_no} not found")
        out = bytearray()
        counter = 0
        base = b"beamline/derive/v1" + bytes.fromhex(pulse["output"]) + tag.encode()
        while len(out) < n:
            out += hashlib.sha512(base + counter.to_bytes(4, "big")).digest()
            counter += 1
        return bytes(out[:n])
