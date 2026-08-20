"""Key administration and account self-service."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ... import keys as keylib
from ...config import TIERS
from ...service import SERVICE
from ..deps import Principal, require_admin, require_key

router = APIRouter(tags=["keys"])


class CreateKeyRequest(BaseModel):
    tier: str = Field("free")
    label: str = Field("", max_length=120)
    owner: str = Field("", max_length=200)
    env: str = Field("live", pattern="^(live|test)$")


@router.post("/v1/admin/keys", dependencies=[Depends(require_admin)])
async def create_key(req: CreateKeyRequest):
    if req.tier not in TIERS:
        raise HTTPException(400, f"unknown tier; choose from {sorted(TIERS)}")
    # Mint from the service DRBG so customer keys inherit the same physical entropy
    # the product sells. os.urandom would be perfectly safe; this is coherence, and
    # it means a key is one more thing the beacon chain timestamps.
    mk = keylib.mint(tier=req.tier, label=req.label, env=req.env, rng=SERVICE.drbg)
    SERVICE.db.insert_key(mk.key_id, mk.secret_hash, mk.env, mk.tier,
                          mk.label, req.owner, mk.created_at)
    return {
        "key": mk.token,
        "key_id": mk.key_id,
        "tier": mk.tier,
        "env": mk.env,
        "label": mk.label,
        "warning": "This is the only time the full key is returned. Only its SHA-256 is stored.",
    }


@router.get("/v1/admin/keys", dependencies=[Depends(require_admin)])
async def list_keys():
    return {"keys": SERVICE.db.list_keys()}


@router.delete("/v1/admin/keys/{key_id}", dependencies=[Depends(require_admin)])
async def revoke_key(key_id: str):
    if not SERVICE.db.revoke_key(key_id):
        raise HTTPException(404, "no active key with that id")
    return {"key_id": key_id, "revoked": True}


@router.get("/v1/me")
async def me(p: Principal = Depends(require_key)):
    """Self-service usage. The endpoint customers hit to see what they are burning."""
    usage = SERVICE.db.get_usage(p.key_id)
    quota = p.tier.monthly_bytes
    return {
        "key_id": p.key_id,
        "env": p.env,
        "label": p.label,
        "tier": p.tier.name,
        "usage_this_period": usage,
        "quota_bytes": quota or None,
        "quota_used_fraction": round(usage["bytes"] / quota, 4) if quota else None,
        "limits": {
            "max_bytes_per_request": p.tier.max_bytes_per_request,
            "burst": p.tier.burst,
            "sustained_per_second": p.tier.refill,
        },
    }
