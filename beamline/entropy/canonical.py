"""The canonical byte encoding for anything Beamline signs.

Every signature and every hash in this system is taken over the output of `encode()`.
A verifier written in another language must reproduce these bytes exactly, or it will
reject honest pulses and -- far worse -- disagree with other verifiers about which
pulses are honest. That disagreement is not hypothetical: the previous encoding used
`json.dumps(..., sort_keys=True)` directly on a free-form provenance blob, and

    {"at": 1787300619.0}   ->   Python: {"at":1787300619.0}
                                    JS: {"at":1787300619}

    {"flux": 1e-8}         ->   Python: {"flux":1e-08}
                                    JS: {"flux":1e-8}

    {"station": "Ny-Ålesund"} -> Python: {"station":"Ny-Ålesund"}
                                    JS: {"station":"Ny-Ålesund"}

Each of those is a pulse that one verifier calls valid and another calls forged. The
`timestamp_ms` field was already an integer for exactly this reason, but the fix was
never applied to the provenance dict beside it, which carries wall-clock floats and
strings copied out of a third party's JSON feed.

So the encoding is no longer "whatever json.dumps does". It is a small, explicitly
specified subset, and anything outside the subset is rejected before it is signed
rather than papered over:

  * Objects, arrays, strings, integers, booleans and null. **No floats.** Floats have
    no cross-language decimal spelling, and no field in a signed body needs one --
    a timestamp becomes integer milliseconds, a measurement becomes a string.
  * Integers must satisfy |n| < 2**53, so a JavaScript verifier can hold them exactly.
  * Object keys must be ASCII, and are sorted bytewise. Python sorts strings by code
    point and JavaScript sorts by UTF-16 code unit; those orders differ above the BMP,
    so non-ASCII keys are simply not allowed rather than trusted to agree.
  * Strings are escaped as `\\uXXXX` for every character outside printable ASCII,
    using UTF-16 code units and surrogate pairs -- what Python's `ensure_ascii=True`
    emits, and what the JavaScript encoder in `docs/index.html` reimplements.

The result is pure ASCII, which means the byte string is also stable across whatever
encoding assumptions sit between here and a verifier.
"""

from __future__ import annotations

MAX_SAFE_INT = (1 << 53) - 1

# Escapes required by RFC 8259, spelled the same way Python's json module spells them.
_SHORT_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t",
    "\b": "\\b", "\f": "\\f",
}


class NotCanonical(ValueError):
    """Raised when a value cannot be encoded unambiguously in every language."""


def encode_string(s: str) -> str:
    """A JSON string literal restricted to printable ASCII.

    Non-ASCII is escaped per UTF-16 code unit, so an astral character becomes a
    surrogate pair of `\\uXXXX` escapes exactly as `ensure_ascii=True` produces.
    """
    out = ['"']
    for ch in s:
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            code = ord(ch)
            if code > 0xFFFF:
                code -= 0x10000
                out.append(f"\\u{0xD800 + (code >> 10):04x}")
                out.append(f"\\u{0xDC00 + (code & 0x3FF):04x}")
            else:
                out.append(f"\\u{code:04x}")
    out.append('"')
    return "".join(out)


def _encode(value, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise NotCanonical(
                f"{path}: integer {value} exceeds 2**53-1 and cannot be represented "
                f"exactly by a JavaScript verifier"
            )
        return str(value)
    if isinstance(value, float):
        raise NotCanonical(
            f"{path}: float {value!r} has no cross-language decimal spelling. "
            f"Use integer milliseconds, or a string."
        )
    if isinstance(value, str):
        return encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(v, f"{path}[{i}]") for i, v in enumerate(value)) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise NotCanonical(f"{path}: object key {key!r} is not a string")
            if not key.isascii():
                raise NotCanonical(
                    f"{path}: object key {key!r} is not ASCII; key ordering would "
                    f"differ between a Python and a JavaScript verifier"
                )
            parts.append(encode_string(key) + ":" + _encode(value[key], f"{path}.{key}"))
        return "{" + ",".join(parts) + "}"
    raise NotCanonical(f"{path}: {type(value).__name__} is not encodable")


def encode(value) -> bytes:
    """Canonical bytes for `value`. Raises `NotCanonical` rather than guessing."""
    return _encode(value, "$").encode("ascii")


def is_canonical(value) -> tuple[bool, str]:
    """Non-raising form, for verifiers that want a reason string."""
    try:
        encode(value)
    except NotCanonical as e:
        return False, str(e)
    return True, "ok"


def sanitize(value, path: str = "$"):
    """Coerce a value into the encodable subset, for data Beamline does not author.

    Provenance metadata comes from entropy sources, and a source is free to hand back
    a float or a nested structure we did not anticipate. Refusing to emit a pulse over
    it would let a third-party feed halt the beacon, so untrusted metadata is coerced
    on the way in: floats become their shortest round-trip string spelling, oversized
    integers become strings, non-ASCII keys become their escaped spelling, and anything
    else becomes its `repr`. The pulse stays canonical and the provenance stays honest
    about what arrived.
    """
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value if abs(value) <= MAX_SAFE_INT else str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return [sanitize(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        return {_sanitize_key(k): sanitize(v, f"{path}.{k}") for k, v in value.items()}
    return repr(value)


def _sanitize_key(key) -> str:
    """Keys must be ASCII to sort identically everywhere; escape rather than drop."""
    key = key if isinstance(key, str) else str(key)
    return key if key.isascii() else encode_string(key)[1:-1]
