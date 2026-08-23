"""Health, transparency, and the honesty page."""

from __future__ import annotations

from fastapi import APIRouter

from ... import __version__
from ...service import SERVICE

router = APIRouter(tags=["meta"])


@router.get("/healthz")
async def healthz():
    return {"status": "ok" if SERVICE.drbg else "starting"}


@router.get("/v1/health")
async def health():
    """Full entropy-chain health. Public on purpose -- an entropy vendor that hides
    its source health is asking to be taken on faith, which is the opposite of the pitch."""
    return SERVICE.health()


@router.get("/v1/about")
async def about():
    """What Beamline actually guarantees, in machine-readable form.

    This endpoint exists so the claims live next to the code and cannot quietly drift
    from it. If the marketing site says something this endpoint does not, the
    marketing site is wrong.
    """
    return {
        "service": "beamline",
        "version": __version__,
        "how_it_works": [
            "Physical sources (ANU quantum vacuum-fluctuation QRNG, NOAA space weather, "
            "the host kernel CSPRNG) are polled continuously.",
            "Their output is mixed into a SHA-512 entropy accumulator with per-source "
            "NIST SP 800-90B health tests.",
            "The accumulator seeds and continuously reseeds an HMAC_DRBG(SHA-512) "
            "per NIST SP 800-90A.",
            "API responses are DRBG output. Beacon pulses are separate, published, and chained.",
        ],
        "entropy_credit_policy": {
            "anu_qrng": "6 bits/byte -- quantum origin, but delivered over a third party's TLS.",
            "local_os": "8 bits/byte -- kernel CSPRNG, not observable by an external attacker.",
            "astro": "0 bits/byte -- NOAA data is PUBLIC. Provenance only, never secrecy.",
        },
        "what_we_do_not_claim": [
            "We do not claim API output is raw unprocessed quantum measurement. It is "
            "DRBG output seeded by physical entropy, which is what every hardware RNG "
            "driver in production does.",
            "We do not claim the astrophysical inputs add secrecy. They are public data "
            "and are credited zero bits.",
            "We do not claim to be a better source of key material than your local "
            "/dev/urandom for ordinary cryptography. Randomness fetched over a network "
            "is randomness someone else could have seen. Use the OS for keys; use "
            "Beamline when you need randomness that is PUBLICLY VERIFIABLE.",
            "We are not FIPS 140-3 validated and are not a certified RNG for regulated "
            "gaming without an independent audit.",
            "We do not claim that a draw derived from a pulse is fair merely because it "
            "reproduces. Given an already-published pulse, a draw runner can try tag "
            "spellings until one names the winner they want, or keep the tag and choose "
            "which pulse to call the draw; both produce results that reproduce exactly "
            "and carry a valid signature. Only a commitment made before the deciding "
            "round rules that out -- see /v1/beacon/commit.",
            "We do not claim a commitment to a draw's NAME is sufficient. The same tag "
            "against the same pulse names a different winner at max=100 than at "
            "max=5000, so the receipt fixes kind, count, bounds and a digest of the "
            "entry list as well.",
            "We do not claim a single valid receipt proves a draw was not ground out. "
            "Twenty draws registered honestly in advance produce twenty valid receipts, "
            "and publishing only the winning one is grinding no single-receipt check "
            "can see. The public list at /v1/beacon/commitments/{round} is the "
            "authoritative answer; the sequence number inside each receipt is a weaker "
            "offline fallback that misses a grinder whose first attempt happened to win.",
        ],
        "verify_without_writing_code": (
            "`beamline verify --draw record.json --public-key <key>` checks a published "
            "record offline and exits non-zero if it does not hold up. Verification "
            "should not require being a programmer; the person who most needs it is the "
            "entrant who lost."
        ),
        "best_uses": [
            "Provably-fair draws, raffles, lotteries, and giveaways "
            "(commit at /v1/beacon/commit, then derive at /v1/beacon/derive).",
            "Audit and compliance sampling that must be shown to be unbiased after the fact.",
            "Public randomness for research, games, and simulation where reproducibility "
            "and third-party verification matter.",
        ],
        "beacon_trust_model": (
            "Pulses are hash-chained and Ed25519-signed, which proves ordering and "
            "tamper-evidence. Commitment receipts prove a draw was named before the "
            "pulse that decided it existed, which is the part the chain cannot show. "
            "Neither proves the operator never withheld a pulse it disliked and "
            "re-rolled: that is visible to observers watching live and to nobody else, "
            "and it is the same residual trust the NIST Randomness Beacon carries. "
            "Anchoring pulses into an external append-only log would close it and is "
            "not built."
        ),
        "key_rotation": (
            "A change of signing key must be endorsed by the key being retired, and the "
            "records are public at /v1/beacon/rotations. Trusting two keys says only "
            "that you would accept either; it does not show the first handed over. "
            "Verifiers that skip this accept a substituted archive from anyone who also "
            "persuaded them to trust a second key."
        ),
        "verification_requires_a_trust_anchor": (
            "Verify against a signing key recorded out of band. A verifier that fetches "
            "the key from this server checks only that this server agrees with itself, "
            "and one that supplies no key at all cannot distinguish our chain from a "
            "fabricated one. Both SDKs refuse to answer without one."
        ),
    }
