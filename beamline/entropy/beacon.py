"""The Beamline beacon: a signed, hash-chained public randomness feed.

This is the part of the product that a customer cannot build for themselves out of
`/dev/urandom`, and it is the reason the service is worth paying for.

Every `beacon_period_seconds` the service emits a *pulse*:

    output = SHA-512( "beamline/pulse/v2" | round | timestamp | prev_output
                      | local_value | public_key | provenance_digest )

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
import threading
import time
from dataclasses import asdict, dataclass, field

from .canonical import NotCanonical, encode, sanitize

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


def verify_pulse(pulse: dict, prev_output: str | None = None,
                 public_key_hex: str | None = None) -> tuple[bool, str]:
    """Recompute a pulse's output, chain link, and signature. Returns (ok, reason).

    The signature is checked against the key the pulse itself declares, which is inside
    the signed body and therefore cannot be swapped without breaking the hash. When
    `public_key_hex` is supplied it is treated as the caller's trust anchor: a mismatch
    is reported as a key change rather than a bad signature, so a rotation is visible as
    what it is instead of looking like tampering.
    """
    p = Pulse(
        version=pulse["version"],
        round=pulse["round"],
        timestamp_ms=pulse["timestamp_ms"],
        period_seconds=pulse["period_seconds"],
        prev_output=pulse["prev_output"],
        local_value=pulse["local_value"],
        public_key=pulse.get("public_key"),
        provenance=pulse.get("provenance", {}),
    )
    if p.compute_output() != pulse.get("output"):
        return False, "output hash does not match pulse contents"
    if prev_output is not None and pulse["prev_output"] != prev_output:
        return False, "prev_output does not match the preceding pulse"
    sig = pulse.get("signature")
    declared = pulse.get("public_key")

    if sig:
        if not declared:
            return False, "pulse is signed but declares no public key"
        if not HAVE_ED25519:
            return False, "signature present but ed25519 support is not installed"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(declared)).verify(
                bytes.fromhex(sig), p.signing_bytes())
        except Exception:
            return False, "ed25519 signature verification failed"
    elif public_key_hex:
        return False, "pulse is unsigned but a public key was supplied"

    if public_key_hex and declared and declared != public_key_hex:
        return True, (f"valid, but signed by a DIFFERENT key "
                      f"({declared[:16]}... not {public_key_hex[:16]}...) -- "
                      f"the operator rotated keys at or before this round")
    return True, "ok"


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
