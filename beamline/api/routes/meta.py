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
        ],
        "best_uses": [
            "Provably-fair draws, raffles, lotteries, and giveaways (see /v1/beacon/derive).",
            "Audit and compliance sampling that must be shown to be unbiased after the fact.",
            "Public randomness for research, games, and simulation where reproducibility "
            "and third-party verification matter.",
        ],
        "beacon_trust_model": (
            "Pulses are hash-chained and Ed25519-signed. This proves ordering and "
            "tamper-evidence. It does not by itself prove the operator never withheld "
            "a pulse. Same model as the NIST Randomness Beacon."
        ),
    }
