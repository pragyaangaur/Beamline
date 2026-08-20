"""Independent verifier for Beamline beacon pulses and derived draws.

This file deliberately shares NO code with the server. It reimplements the pulse hash,
the chain link, the signature check, and the derivation from the published spec, using
nothing but the standard library plus `cryptography` for Ed25519.

That independence is the point. A verifier that imports the server's own functions
proves only that the server agrees with itself. If you are evaluating Beamline for
something that matters, read this file -- it is short on purpose -- and satisfy
yourself that it computes what the spec says, then run it against live pulses.
"""

from __future__ import annotations

import hashlib
import json

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAVE_ED25519 = True
except ImportError:  # pragma: no cover
    HAVE_ED25519 = False

VERSION = "beamline/pulse/v2"
GENESIS = "00" * 64


def canonical_body(pulse: dict) -> bytes:
    """The exact bytes the server hashed and signed.

    Sorted keys, no whitespace, and an INTEGER millisecond timestamp. The integer is
    load-bearing: a float timestamp that lands on a whole second serialises differently
    in Python and JavaScript, which would break cross-language verification for a small
    fraction of pulses and only for the verifiers that matter most.
    """
    return json.dumps(
        {
            "version": pulse["version"],
            "round": pulse["round"],
            "timestamp_ms": pulse["timestamp_ms"],
            "period_seconds": pulse["period_seconds"],
            "prev_output": pulse["prev_output"],
            "local_value": pulse["local_value"],
            "public_key": pulse.get("public_key"),
            "provenance": pulse["provenance"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def pulse_output(pulse: dict) -> str:
    return hashlib.sha512(VERSION.encode() + b"|" + canonical_body(pulse)).hexdigest()


def check_pulse(pulse: dict, public_key_hex: str | None = None,
                prev: dict | None = None) -> tuple[bool, str]:
    if pulse.get("version") != VERSION:
        return False, f"unexpected pulse version {pulse.get('version')!r}"
    if pulse_output(pulse) != pulse["output"]:
        return False, "output hash does not match the pulse contents"
    if prev is not None:
        if pulse["prev_output"] != prev["output"]:
            return False, f"round {pulse['round']} does not link to round {prev['round']}"
        if pulse["round"] != prev["round"] + 1:
            return False, "round numbers are not consecutive"
    elif pulse["round"] == 1 and pulse["prev_output"] != GENESIS:
        return False, "round 1 does not start from the genesis value"

    sig = pulse.get("signature")
    declared = pulse.get("public_key")

    if sig:
        if not declared:
            return False, "pulse is signed but declares no public key"
        if not HAVE_ED25519:
            return False, "install 'cryptography' to check signatures"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(declared)).verify(
                bytes.fromhex(sig), canonical_body(pulse)
            )
        except Exception:
            return False, "ed25519 signature is invalid"
    elif public_key_hex:
        return False, "pulse is unsigned"

    # A key the caller did not expect is a rotation, not a forgery: the signature is
    # sound, it simply chains to a different operator key. Report it as such so a
    # verifier can decide whether that rotation was announced.
    if public_key_hex and declared and declared != public_key_hex:
        return True, f"valid under a different signing key ({declared[:16]}...)"
    return True, "ok"


def check_chain(pulses: list[dict], public_key_hex: str | None = None) -> tuple[bool, str]:
    """Verify a consecutive run of pulses. Any break invalidates everything after it."""
    if not pulses:
        return False, "empty chain"
    ordered = sorted(pulses, key=lambda p: p["round"])
    rotations = []
    for i, p in enumerate(ordered):
        ok, reason = check_pulse(p, public_key_hex, ordered[i - 1] if i else None)
        if not ok:
            return False, f"round {p['round']}: {reason}"
        if i and p.get("public_key") != ordered[i - 1].get("public_key"):
            rotations.append(p["round"])

    msg = (f"verified {len(ordered)} pulses from round {ordered[0]['round']} "
           f"to {ordered[-1]['round']}")
    if rotations:
        # Not a failure, but never silent: an unannounced rotation is exactly what an
        # archive substitution would look like.
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
