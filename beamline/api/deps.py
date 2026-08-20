"""Auth and quota dependencies."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException, Request

from .. import keys as keylib
from ..config import TIERS, Tier
from ..service import SERVICE


@dataclass
class Principal:
    key_id: str
    tier: Tier
    env: str
    label: str


def _extract_token(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


async def require_key(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Principal:
    token = _extract_token(authorization, x_api_key)
    if not token:
        raise HTTPException(401, "missing API key: send 'Authorization: Bearer bl_live_...' or X-API-Key")

    parsed = keylib.parse(token)
    if not parsed:
        raise HTTPException(401, "malformed API key")
    env, key_id, secret = parsed

    row = SERVICE.db.get_key(key_id)
    # Verify against a dummy hash when the key_id is unknown so that a valid-but-unknown
    # id and a valid-but-wrong-secret take the same time. Otherwise the endpoint leaks
    # which key_ids exist.
    stored = row["secret_hash"] if row else "0" * 64
    ok = keylib.verify(secret, stored)
    if not row or not ok:
        raise HTTPException(401, "invalid API key")
    if row["revoked_at"]:
        raise HTTPException(401, "API key has been revoked")
    if row["env"] != env:
        raise HTTPException(401, "API key environment mismatch")

    tier = TIERS.get(row["tier"], TIERS["free"])

    allowed, retry = SERVICE.limiter.check(key_id, tier.burst, tier.refill)
    if not allowed:
        raise HTTPException(
            429, f"rate limit exceeded for tier '{tier.name}'",
            headers={"Retry-After": str(max(1, int(retry + 0.999)))},
        )

    if tier.monthly_bytes:
        used = SERVICE.db.get_usage(key_id)["bytes"]
        if used >= tier.monthly_bytes:
            raise HTTPException(
                402, f"monthly quota exhausted ({used}/{tier.monthly_bytes} bytes on tier "
                     f"'{tier.name}'). Upgrade or wait for the next billing period.",
            )

    SERVICE.db.touch_key(key_id)
    request.state.principal = Principal(key_id, tier, env, row["label"])
    return request.state.principal


def check_size(p: Principal, n: int) -> None:
    if n < 1:
        raise HTTPException(400, "requested size must be at least 1")
    if n > p.tier.max_bytes_per_request:
        raise HTTPException(
            413, f"request exceeds the {p.tier.max_bytes_per_request} byte per-request "
                 f"limit for tier '{p.tier.name}'",
        )


def bill(p: Principal, n_bytes: int) -> None:
    SERVICE.db.record_usage(p.key_id, n_bytes)


async def require_admin(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> None:
    from ..config import CONFIG
    import hmac

    if not CONFIG.admin_token:
        raise HTTPException(503, "admin API disabled: BEAMLINE_ADMIN_TOKEN is not set")
    if not x_admin_token or not hmac.compare_digest(x_admin_token, CONFIG.admin_token):
        raise HTTPException(401, "invalid admin token")
