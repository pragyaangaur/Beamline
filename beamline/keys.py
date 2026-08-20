"""API key minting and verification.

Format:  bl_<env>_<key_id><secret>
         e.g. bl_live_7QK4M2XA_9F3TZP0RB6HC8VNJ4WDYKQ2SM5EGL7A

  * `key_id` is 8 chars, stored in the clear, indexed. It makes verification a single
    indexed lookup instead of a table scan against every hash.
  * `secret` is 32 chars of Crockford-style base32 drawn from the service's own DRBG
    -- 160 bits. Only its SHA-256 is stored. A database leak does not yield working keys.
  * The `live`/`test` env segment is in the string itself so a key pasted into the
    wrong environment fails loudly, and so secret-scanners can pattern-match it.

Verification is constant-time against the stored digest. There is no "list keys and
compare" path anywhere.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

# Crockford base32: no I, L, O, U -- avoids transcription errors and accidental words.
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
KEY_ID_LEN = 8
SECRET_LEN = 32
PREFIX = "bl"


def _rand_string(n: int, rng=None) -> str:
    if rng is None:
        return "".join(secrets.choice(ALPHABET) for _ in range(n))
    # Rejection sampling off the service DRBG: 256 % 32 == 0, so plain modulo is
    # already unbiased here, but the assert keeps that true if ALPHABET ever changes.
    assert 256 % len(ALPHABET) == 0, "alphabet length must divide 256 to stay unbiased"
    return "".join(ALPHABET[b % len(ALPHABET)] for b in rng.generate(n))


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


@dataclass
class MintedKey:
    key_id: str
    token: str  # full plaintext key -- shown exactly once, never stored
    secret_hash: str
    env: str
    tier: str
    label: str
    created_at: float


def mint(tier: str = "free", label: str = "", env: str = "live", rng=None) -> MintedKey:
    key_id = _rand_string(KEY_ID_LEN, rng)
    secret = _rand_string(SECRET_LEN, rng)
    return MintedKey(
        key_id=key_id,
        token=f"{PREFIX}_{env}_{key_id}_{secret}",
        secret_hash=hash_secret(secret),
        env=env,
        tier=tier,
        label=label,
        created_at=time.time(),
    )


def parse(token: str) -> tuple[str, str, str] | None:
    """Split a presented token into (env, key_id, secret). None if malformed."""
    if not token:
        return None
    parts = token.strip().split("_")
    if len(parts) != 4:
        return None
    prefix, env, key_id, secret = parts
    if prefix != PREFIX or env not in ("live", "test"):
        return None
    if len(key_id) != KEY_ID_LEN or len(secret) != SECRET_LEN:
        return None
    if not all(c in ALPHABET for c in key_id + secret):
        return None
    return env, key_id, secret


def verify(secret: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), stored_hash)


def fingerprint(token: str) -> str:
    """Safe-to-log identifier for a key: env + id only, never the secret."""
    parsed = parse(token)
    if not parsed:
        return "invalid"
    env, key_id, _ = parsed
    return f"{PREFIX}_{env}_{key_id}_****"
