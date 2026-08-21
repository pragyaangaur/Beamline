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
                enforce_period: bool = False) -> tuple[bool, str]:
    """Verify a consecutive run of pulses. Any break invalidates everything after it."""
    if not pulses:
        return False, "empty chain"
    ordered = sorted(pulses, key=lambda p: p["round"])
    rotations = []
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
            rotations.append(p["round"])

    msg = (f"verified {len(ordered)} pulses from round {ordered[0]['round']} "
           f"to {ordered[-1]['round']}")
    if rotations:
        # Every one of these keys was checked against the trust anchor above, so this
        # is a rotation you accepted -- but it is never silent, because an unannounced
        # rotation is what an archive substitution looks like.
        msg += f"; signing key changed at round(s) {rotations}"
    return True, msg


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
COMMITMENT_VERSION = "beamline/commitment/v1"
COMMITMENT_BODY_FIELDS = ("version", "commit_id", "tag", "target_round",
                          "created_at_ms", "created_after_round", "public_key")


def canonical_commitment_body(receipt: dict) -> bytes:
    return _enc({k: receipt.get(k) for k in COMMITMENT_BODY_FIELDS}, "$").encode("ascii")


def check_commitment(receipt: dict, public_key_hex: str | None = None, *,
                     trusted_keys: Iterable[str] | str | None = None,
                     allow_unsigned: bool = False) -> tuple[bool, str]:
    """Check that a draw was named before the pulse that decided it existed.

    This is the check the beacon cannot make for you. A pulse proves it was not
    edited; it says nothing about whether the tag and the round were chosen before or
    after it was published, and a runner who chooses either afterwards picks the
    winner outright while every signature stays valid.

    The receipt carries `created_after_round`: where the chain stood when the
    announcement was made. If that is not strictly below `target_round`, the deciding
    pulse already existed and the commitment is worthless -- so that is checked before
    anything else, and no signature can rescue it.
    """
    anchor = _anchor(public_key_hex, trusted_keys)
    if anchor is None and not allow_unsigned:
        return False, "no trust anchor: pass the signing key you expect"
    if not isinstance(receipt, dict):
        return False, "commitment must be an object"
    if receipt.get("version") != COMMITMENT_VERSION:
        return False, f"unexpected commitment version {receipt.get('version')!r}"
    for name in ("target_round", "created_at_ms", "created_after_round"):
        v = receipt.get(name)
        if not isinstance(v, int) or isinstance(v, bool):
            return False, f"{name} must be an integer"
    if not isinstance(receipt.get("tag"), str) or not receipt["tag"]:
        return False, "tag must be a non-empty string"
    if not isinstance(receipt.get("commit_id"), str) or not receipt["commit_id"]:
        return False, "commit_id must be a non-empty string"
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


def check_draw(pulse: dict, commitment: dict, result, public_key_hex: str | None = None, *,
               kind: str = "integers", items: list | None = None,
               count: int = 1, minimum: int = 0, maximum: int = 100,
               prev: dict | None = None,
               trusted_keys: Iterable[str] | str | None = None) -> tuple[bool, str]:
    """The whole question, answered in one call: was this draw fair?

    Four things have to hold, and checking three of them is how people convince
    themselves of something untrue:

      1. The pulse is authentic -- signed by a key you named, hashing to its contents.
      2. The commitment is authentic, and was made before that pulse existed.
      3. The commitment names *this* draw: this exact tag, this exact round.
      4. The published result is what that pulse and that tag actually produce.

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

    tag = commitment["tag"]
    if kind == "integers":
        expected = reproduce_integers(pulse["output"], tag, count, minimum, maximum)
    elif kind == "shuffle":
        if items is None:
            return False, "shuffle requires the item list"
        expected = reproduce_shuffle(pulse["output"], tag, items)
    else:
        return False, f"check_draw does not know how to reproduce kind {kind!r}"

    if list(result) != list(expected):
        return False, (f"result does not match the pulse: published {list(result)!r}, "
                       f"recomputed {expected!r}")

    return True, (f"round {pulse['round']} is authentic, tag {tag!r} was committed at "
                  f"round {commitment['created_after_round']} before that pulse "
                  f"existed, and the result reproduces exactly")
