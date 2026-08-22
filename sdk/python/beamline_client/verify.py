"""Independent verifier for Beamline beacon pulses and derived draws.

This file deliberately shares NO code with the server. It reimplements the canonical
encoding, the pulse hash, the chain link, the signature check, and the derivation from
the published spec, using nothing but the standard library plus `cryptography` for
Ed25519.

That independence is the point. A verifier that imports the server's own functions
proves only that the server agrees with itself. If you are evaluating Beamline for
something that matters, read this file -- it is short on purpose -- and satisfy
yourself that it computes what the spec says, then run it against live pulses.

Everything here fails closed. Verification answers "should I believe this?", and the
only safe default for that question is no. In particular:

  * You must say which signing key you expect. A verifier with no trust anchor cannot
    distinguish Beamline's chain from one an attacker generated this morning, and an
    earlier revision of this file, called with its default arguments, returned
    "verified 10 pulses" for exactly such a chain.
  * A signature under a key you did not name is a failure, not a footnote. An earlier
    revision reported an unrecognised key as an announced rotation and returned True
    with a note, so a chain signed by an attacker's own key passed while the caller
    pinned the real one. If you do expect a rotation, name both keys.
  * Malformed input is rejected before any cryptography runs, so a thrown exception
    can never be mistaken for a passing check.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAVE_ED25519 = True
except ImportError:  # pragma: no cover
    HAVE_ED25519 = False

VERSION = "beamline/pulse/v3"
GENESIS = "00" * 64
MAX_SAFE_INT = (1 << 53) - 1
MAX_TIMESTAMP_SKEW_MS = 5 * 60 * 1000

RETIRED_VERSIONS = {
    "beamline/pulse/v1": "superseded before public release",
    "beamline/pulse/v2": (
        "signed a non-canonical JSON body, so a Python and a JavaScript verifier "
        "could disagree about whether a pulse was authentic"
    ),
}

HEX_LENGTHS = {"prev_output": 128, "local_value": 128, "output": 128,
               "public_key": 64, "signature": 128}

BODY_FIELDS = ("version", "round", "timestamp_ms", "period_seconds",
               "prev_output", "local_value", "public_key", "provenance")


class NotCanonical(ValueError):
    """The value cannot be encoded unambiguously in every language."""


# --- canonical encoding ----------------------------------------------------
# Reimplemented from the spec, not imported. Objects, arrays, strings, integers below
# 2**53, booleans and null; no floats; ASCII keys sorted bytewise; every character
# outside printable ASCII escaped per UTF-16 code unit. The output is pure ASCII.
_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t",
                  "\b": "\\b", "\f": "\\f"}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif " " <= ch <= "~":
            out.append(ch)
        elif ord(ch) > 0xFFFF:
            c = ord(ch) - 0x10000
            out.append(f"\\u{0xD800 + (c >> 10):04x}\\u{0xDC00 + (c & 0x3FF):04x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    out.append('"')
    return "".join(out)


def _enc(v, path: str) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise NotCanonical(f"{path}: integer {v} is not exactly representable in JavaScript")
        return str(v)
    if isinstance(v, float):
        raise NotCanonical(f"{path}: float {v!r} has no cross-language spelling")
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_enc(x, f"{path}[{i}]") for i, x in enumerate(v)) + "]"
    if isinstance(v, dict):
        parts = []
        for k in sorted(v):
            if not isinstance(k, str) or not k.isascii():
                raise NotCanonical(f"{path}: object key {k!r} must be an ASCII string")
            parts.append(_string(k) + ":" + _enc(v[k], f"{path}.{k}"))
        return "{" + ",".join(parts) + "}"
    raise NotCanonical(f"{path}: {type(v).__name__} is not encodable")


def canonical_body(pulse: dict) -> bytes:
    """The exact bytes the server hashed and signed."""
    body = {k: pulse.get(k) for k in BODY_FIELDS}
    body["provenance"] = pulse.get("provenance", {})
    return _enc(body, "$").encode("ascii")


def pulse_output(pulse: dict) -> str:
    return hashlib.sha512(pulse["version"].encode() + b"|" + canonical_body(pulse)).hexdigest()


# --- structure -------------------------------------------------------------
def _hex_field(pulse: dict, name: str, required: bool = True) -> None:
    value = pulse.get(name)
    if value is None:
        if required:
            raise ValueError(f"missing field {name!r}")
        return
    if not isinstance(value, str) or len(value) != HEX_LENGTHS[name]:
        raise ValueError(f"{name} must be {HEX_LENGTHS[name]} hex characters")
    try:
        bytes.fromhex(value)
    except ValueError as e:
        raise ValueError(f"{name} is not valid hex") from e


def check_structure(pulse: dict) -> None:
    """Reject malformed input before any cryptography touches it.

    This is what stops "the key would not parse" from being reported as "verified":
    by the time a signature check runs, every field it reads is known to be present,
    of the right type, and of the right length.
    """
    if not isinstance(pulse, dict):
        raise ValueError("pulse must be an object")
    version = pulse.get("version")
    if version in RETIRED_VERSIONS:
        raise ValueError(f"pulse version {version!r} is retired: {RETIRED_VERSIONS[version]}")
    if version != VERSION:
        raise ValueError(f"unexpected pulse version {version!r}; this verifier speaks {VERSION!r}")
    for name in ("round", "timestamp_ms", "period_seconds"):
        v = pulse.get(name)
        if not isinstance(v, int) or isinstance(v, bool):
            raise ValueError(f"{name} must be an integer")
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
    canonical_body(pulse)  # raises NotCanonical if the body cannot be spelled one way
    if pulse["round"] == 1 and pulse["prev_output"] != GENESIS:
        raise ValueError("round 1 does not start from the genesis value")


def _anchor(public_key_hex: str | None, trusted_keys) -> set[str] | None:
    if trusted_keys is None:
        return {public_key_hex} if public_key_hex else None
    if isinstance(trusted_keys, str):
        return {trusted_keys}
    keys = set(trusted_keys)
    return keys or None


# --- verification ----------------------------------------------------------
def check_pulse(pulse: dict, public_key_hex: str | None = None, prev: dict | None = None,
                *, trusted_keys: Iterable[str] | str | None = None,
                allow_unsigned: bool = False) -> tuple[bool, str]:
    """Verify one pulse. Returns (ok, reason); `ok` is the whole answer.

    Pass the signing key you expect as `public_key_hex`, or several as `trusted_keys`
    if you are accepting an announced rotation. Without one of those this returns
    False: an internally consistent pulse proves only that whoever wrote it can run
    SHA-512.
    """
    anchor = _anchor(public_key_hex, trusted_keys)
    if anchor is None and not allow_unsigned:
        return False, ("no trust anchor: pass the signing key you expect, or "
                       "allow_unsigned=True to check structure and chaining only")
    try:
        check_structure(pulse)
    except (ValueError, NotCanonical) as e:
        return False, str(e)

    if pulse_output(pulse) != pulse["output"]:
        return False, "output hash does not match the pulse contents"
    if prev is not None:
        if pulse["prev_output"] != prev["output"]:
            return False, f"round {pulse['round']} does not link to round {prev['round']}"
        if pulse["round"] != prev["round"] + 1:
            return False, "round numbers are not consecutive"
        if pulse["timestamp_ms"] < prev["timestamp_ms"]:
            # Non-decreasing: two pulses can honestly share a millisecond, but time
            # never runs backwards in a chain built as it went.
            return False, f"round {pulse['round']} is dated before round {prev['round']}"

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
                       f"announced rotation, name it in trusted_keys.")
    if not HAVE_ED25519:
        return False, "install 'cryptography' to check signatures"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(declared)).verify(
            bytes.fromhex(sig), canonical_body(pulse))
    except Exception:
        return False, "ed25519 signature is invalid"

    if anchor is None:
        return True, "self-consistent and self-signed, but no trust anchor was supplied"
    return True, "ok"


def check_chain(pulses: list[dict], public_key_hex: str | None = None, *,
                trusted_keys: Iterable[str] | str | None = None,
                allow_unsigned: bool = False,
                enforce_period: bool = False,
                rotations: list[dict] | None = None,
                allow_unendorsed_rotation: bool = False) -> tuple[bool, str]:
    """Verify a consecutive run of pulses. Any break invalidates everything after it.

    A change of signing key must be endorsed by the key being retired. Naming both
    keys in `trusted_keys` only says you would accept either; it does not show the
    first ever handed over, so an attacker who talks you into trusting their key gets
    a substituted archive accepted with nothing in the chain contradicting it. Pass
    the operator's published `rotations`.
    """
    if not pulses:
        return False, "empty chain"
    ordered = sorted(pulses, key=lambda p: p["round"])
    changes = []
    for i, p in enumerate(ordered):
        prev = ordered[i - 1] if i else None
        ok, reason = check_pulse(p, public_key_hex, prev,
                                 trusted_keys=trusted_keys, allow_unsigned=allow_unsigned)
        if not ok:
            return False, f"round {p['round']}: {reason}"
        if prev is not None and enforce_period:
            gap = p["timestamp_ms"] - prev["timestamp_ms"]
            want = prev["period_seconds"] * 1000
            if abs(gap - want) > MAX_TIMESTAMP_SKEW_MS:
                return False, (f"round {p['round']} lands {gap}ms after round "
                               f"{prev['round']}, not the declared {want}ms")
        if i and p.get("public_key") != ordered[i - 1].get("public_key"):
            ok, why = _endorsed(rotations, ordered[i - 1].get("public_key"),
                                p.get("public_key"), p["round"],
                                allow_unendorsed_rotation)
            if not ok:
                return False, f"round {p['round']}: {why}"
            changes.append(p["round"])

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
        ok, why = check_rotation(record, expect_from=from_key, expect_to=to_key,
                                 expect_round=round_no)
        return (True, "ok") if ok else (False, f"rotation record is not usable: {why}")
    return False, (f"the signing key changes here but no rotation record takes effect "
                   f"at round {round_no}")


# --- reproducing a derived draw -------------------------------------------
class DerivedStream:
    """The deterministic byte stream a pulse + tag expands to."""

    def __init__(self, pulse_output_hex: str, tag: str):
        self._base_out = bytes.fromhex(pulse_output_hex)
        self._tag = tag
        self._buf = bytearray()
        self._pos = 0
        self._chunk = 0

    def _grow(self) -> None:
        self._chunk += 1
        base = b"beamline/derive/v1" + self._base_out + f"{self._tag}#{self._chunk}".encode()
        block = bytearray()
        counter = 0
        while len(block) < 4096:
            block += hashlib.sha512(base + counter.to_bytes(4, "big")).digest()
            counter += 1
        self._buf.extend(block[:4096])

    def __call__(self, n: int) -> bytes:
        while self._pos + n > len(self._buf):
            self._grow()
        out = bytes(self._buf[self._pos:self._pos + n])
        self._pos += n
        return out


def bounded_int(rand, span: int) -> int:
    """Rejection sampling, identical to the server's. Modulo would introduce bias."""
    if span <= 1:
        return 0
    bits = max(1, (span - 1).bit_length())
    nbytes = (bits + 7) // 8
    mask = (1 << bits) - 1
    while True:
        v = int.from_bytes(rand(nbytes), "big") & mask
        if v < span:
            return v


def reproduce_integers(pulse_output_hex: str, tag: str, count: int,
                       minimum: int, maximum: int) -> list[int]:
    rand = DerivedStream(pulse_output_hex, tag)
    span = maximum - minimum + 1
    return [minimum + bounded_int(rand, span) for _ in range(count)]


def reproduce_shuffle(pulse_output_hex: str, tag: str, items: list) -> list:
    rand = DerivedStream(pulse_output_hex, tag)
    out = list(items)
    for i in range(len(out) - 1, 0, -1):
        j = bounded_int(rand, i + 1)
        out[i], out[j] = out[j], out[i]
    return out


# --- commitments -----------------------------------------------------------
COMMITMENT_VERSION = "beamline/commitment/v2"
COMMITMENT_BODY_FIELDS = ("version", "commit_id", "tag", "target_round",
                          "created_at_ms", "created_after_round", "committer",
                          "sequence", "draw", "public_key")
DRAW_SPEC_FIELDS = ("kind", "count", "min", "max", "items_digest")

ROTATION_VERSION = "beamline/rotation/v1"
ROTATION_BODY_FIELDS = ("version", "from_public_key", "to_public_key",
                        "effective_round", "created_at_ms")


def canonical_commitment_body(receipt: dict) -> bytes:
    return _enc({k: receipt.get(k) for k in COMMITMENT_BODY_FIELDS}, "$").encode("ascii")


def canonical_rotation_body(record: dict) -> bytes:
    return _enc({k: record.get(k) for k in ROTATION_BODY_FIELDS}, "$").encode("ascii")


def items_digest(items) -> str | None:
    """The digest a commitment pins an entry list to."""
    if items is None:
        return None
    return hashlib.sha256(b"beamline/items/v1" + _enc(list(items), "$").encode("ascii")).hexdigest()


def _spec_problem(spec) -> str | None:
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


def check_commitment(receipt: dict, public_key_hex: str | None = None, *,
                     trusted_keys: Iterable[str] | str | None = None,
                     allow_unsigned: bool = False) -> tuple[bool, str]:
    """Check that a draw was named, in full, before the pulse that decided it existed.

    This is the check the beacon cannot make for you. A pulse proves it was not
    edited; it says nothing about whether the draw was settled before or after it was
    published, and a runner with any freedom left after the pulse appears picks the
    winner outright while every signature stays valid.

    Three things have to be nailed down, and the first version of this only did one.

      * **When.** `created_after_round` is where the chain stood when the receipt was
        issued. If that is not strictly below `target_round`, the deciding pulse
        already existed and no signature can rescue the receipt -- so it is checked
        before the signature is.
      * **What.** The tag alone does not determine a winner. One commitment to
        "giveaway-7" covers a draw of one from 100 and one from 5000, which name
        different people. The receipt fixes kind, count, bounds, and a digest of the
        entry list.
      * **How many.** `sequence` is the committer's running count of draws registered
        against this round. Twenty commitments made honestly in advance are twenty
        valid receipts, and publishing the flattering one is grinding by another
        route; see `check_draw`, which acts on this.
    """
    anchor = _anchor(public_key_hex, trusted_keys)
    if anchor is None and not allow_unsigned:
        return False, "no trust anchor: pass the signing key you expect"
    if not isinstance(receipt, dict):
        return False, "commitment must be an object"
    if receipt.get("version") != COMMITMENT_VERSION:
        return False, f"unexpected commitment version {receipt.get('version')!r}"
    for name in ("target_round", "created_at_ms", "created_after_round", "sequence"):
        v = receipt.get(name)
        if not isinstance(v, int) or isinstance(v, bool):
            return False, f"{name} must be an integer"
    if receipt["sequence"] < 1:
        return False, "sequence must be at least 1"
    if not isinstance(receipt.get("tag"), str) or not receipt["tag"]:
        return False, "tag must be a non-empty string"
    if not isinstance(receipt.get("commit_id"), str) or not receipt["commit_id"]:
        return False, "commit_id must be a non-empty string"
    if not isinstance(receipt.get("committer"), str):
        return False, "committer must be a string"
    problem = _spec_problem(receipt.get("draw"))
    if problem:
        return False, problem
    if receipt["target_round"] <= receipt["created_after_round"]:
        return False, (f"commitment names round {receipt['target_round']} but the chain "
                       f"had already reached round {receipt['created_after_round']}; "
                       f"the deciding pulse existed before the draw was announced")
    try:
        body = canonical_commitment_body(receipt)
    except NotCanonical as e:
        return False, str(e)

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
        return False, "install 'cryptography' to check signatures"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(declared)).verify(
            bytes.fromhex(sig), body)
    except Exception:
        return False, "ed25519 signature is invalid"
    return True, "ok"


def check_rotation(record: dict, *, expect_from: str | None = None,
                   expect_to: str | None = None,
                   expect_round: int | None = None) -> tuple[bool, str]:
    """Check that the retiring key endorsed its successor, and the successor exists.

    Two signatures, answering two questions. The outgoing key's signature is the
    endorsement -- the only thing separating a rotation from somebody else's archive.
    The incoming key's is proof of possession, so authority cannot be handed to a key
    nobody holds.
    """
    if not isinstance(record, dict):
        return False, "rotation must be an object"
    if record.get("version") != ROTATION_VERSION:
        return False, f"unexpected rotation version {record.get('version')!r}"
    for name in ("from_public_key", "to_public_key"):
        v = record.get(name)
        if not isinstance(v, str) or len(v) != 64:
            return False, f"{name} must be 64 hex characters"
        try:
            bytes.fromhex(v)
        except ValueError:
            return False, f"{name} is not valid hex"
    if record["from_public_key"] == record["to_public_key"]:
        return False, "a rotation must change the key"
    for name in ("effective_round", "created_at_ms"):
        v = record.get(name)
        if not isinstance(v, int) or isinstance(v, bool):
            return False, f"{name} must be an integer"
    if record["effective_round"] < 1:
        return False, "effective_round must be at least 1"
    if not HAVE_ED25519:
        return False, "install 'cryptography' to check signatures"
    try:
        body = canonical_rotation_body(record)
    except NotCanonical as e:
        return False, str(e)

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


def check_draw(pulse: dict, commitment: dict, result, public_key_hex: str | None = None, *,
               kind: str = "integers", items: list | None = None,
               count: int = 1, minimum: int = 0, maximum: int = 100,
               prev: dict | None = None,
               siblings: list[dict] | None = None,
               allow_multiple_commitments: bool = False,
               trusted_keys: Iterable[str] | str | None = None) -> tuple[bool, str]:
    """The whole question, answered in one call: was this draw fair?

    Five things have to hold, and checking four of them is how people convince
    themselves of something untrue:

      1. The pulse is authentic -- signed by a key you named, hashing to its contents.
      2. The commitment is authentic, and was made before that pulse existed.
      3. The commitment names *this* draw: this tag, this round, and this shape --
         kind, count, bounds, entry list.
      4. This was the committer's only draw against this round, or you have said you
         accept otherwise. Pass `siblings` -- the public commitment list for the round,
         from /v1/beacon/commitments/{round} -- for the authoritative answer; without
         it the receipt's own sequence number is the only evidence, and it catches a
         grinder only when the winning receipt is not their first.
      5. The published result is what that pulse and that commitment actually produce.

    Returns (ok, reason). A False here means do not believe the result, whatever the
    runner has published alongside it.
    """
    ok, why = check_pulse(pulse, public_key_hex, prev, trusted_keys=trusted_keys)
    if not ok:
        return False, f"pulse: {why}"

    ok, why = check_commitment(commitment, public_key_hex, trusted_keys=trusted_keys)
    if not ok:
        return False, f"commitment: {why}"

    if commitment["target_round"] != pulse["round"]:
        return False, (f"commitment names round {commitment['target_round']} but the "
                       f"result was drawn from round {pulse['round']}")

    spec = commitment["draw"]
    asked = {"kind": kind, "count": int(count), "min": int(minimum),
             "max": int(maximum), "items_digest": items_digest(items)}
    differences = [f"{k}={spec[k]!r} was committed, {asked[k]!r} was used"
                   for k in DRAW_SPEC_FIELDS if spec[k] != asked[k]]
    if differences:
        return False, ("the draw does not match what was committed: "
                       + "; ".join(differences))

    ok, why = _check_exclusivity(commitment, siblings, allow_multiple_commitments)
    if not ok:
        return False, why
    exclusivity = why

    tag = commitment["tag"]
    if spec["kind"] == "integers":
        expected = reproduce_integers(pulse["output"], tag, spec["count"],
                                      spec["min"], spec["max"])
    elif spec["kind"] == "shuffle":
        if items is None:
            return False, "shuffle requires the item list"
        expected = reproduce_shuffle(pulse["output"], tag, items)
    else:
        return False, f"check_draw does not know how to reproduce kind {spec['kind']!r}"

    if list(result) != list(expected):
        return False, (f"result does not match the pulse: published {list(result)!r}, "
                       f"recomputed {expected!r}")

    return True, (f"round {pulse['round']} is authentic, tag {tag!r} was committed at "
                  f"round {commitment['created_after_round']} before that pulse "
                  f"existed, the draw ran to the committed specification, "
                  f"{exclusivity}, and the result reproduces exactly")


def _check_exclusivity(commitment: dict, siblings, allow_multiple: bool) -> tuple[bool, str]:
    """Was this the committer's only draw against this round?

    Committing twenty draws in advance and publishing the one that wins is grinding
    that survives every other check: each receipt is honest, early, and signed. The
    public commitment list is the authoritative answer, and the receipt's own sequence
    number is the fallback -- weaker, because a grinder whose first attempt happens to
    win holds a receipt reading sequence 1.
    """
    if siblings is not None:
        mine = [c for c in siblings if c.get("committer") == commitment["committer"]
                and c.get("target_round") == commitment["target_round"]]
        ids = {c.get("commit_id") for c in mine}
        if commitment["commit_id"] not in ids:
            return False, ("this commitment is missing from the published list for the "
                           "round, so the list cannot be the whole story")
        if len(mine) > 1 and not allow_multiple:
            others = sorted(c.get("tag") for c in mine
                            if c.get("commit_id") != commitment["commit_id"])
            return False, (f"the committer registered {len(mine)} draws against round "
                           f"{commitment['target_round']} and published this one. The "
                           f"others were {others!r}. Each is individually valid, which "
                           f"is the point: picking among them after the pulse is "
                           f"grinding. Pass allow_multiple_commitments=True if you have "
                           f"a reason to accept it.")
        return True, (f"it was the committer's only draw against that round"
                      if len(mine) == 1 else
                      f"the committer registered {len(mine)} draws against that round "
                      f"and you chose to accept that")

    if commitment["sequence"] > 1 and not allow_multiple:
        return False, (f"this receipt is the committer's draw number "
                       f"{commitment['sequence']} against round "
                       f"{commitment['target_round']}; the earlier ones were not "
                       f"published, and picking among them after the pulse is grinding")
    return True, ("its receipt is the committer's first for that round, though without "
                  "the published commitment list that is the receipt's own word")
