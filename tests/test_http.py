"""HTTP-level tests: authentication, quotas, and endpoint contracts.

These drive the real ASGI app, but wire the service to a temp database and skip the
background poll loops -- the network sources are covered separately and must not make
the suite depend on ANU or NOAA being reachable.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from beamline import config as config_module
from beamline import keys as keylib
from beamline.api.app import app
from beamline.config import CONFIG
from beamline.db import Database
from beamline.entropy.beacon import Beacon
from beamline.entropy.drbg import HmacDrbg
from beamline.entropy.pool import EntropyPool
from beamline.ratelimit import RateLimiter
from beamline.service import SERVICE

ADMIN = "test-admin-token"


@pytest.fixture
def client(monkeypatch):
    tmp = tempfile.TemporaryDirectory()
    # Config is frozen, so swap in a replaced copy. deps.py imports CONFIG inside the
    # request handler, so it resolves against the module attribute at call time.
    monkeypatch.setattr(config_module, "CONFIG", replace(CONFIG, admin_token=ADMIN))

    SERVICE.db = Database(Path(tmp.name) / "test.db")
    SERVICE.pool = EntropyPool()
    SERVICE.pool.add("local_os", os.urandom(256))
    SERVICE.drbg = HmacDrbg(SERVICE.pool.extract(64))
    SERVICE.beacon = Beacon(SERVICE.db, SERVICE.pool, period_seconds=60)
    SERVICE.limiter = RateLimiter()
    SERVICE.beacon.emit()

    # Constructed without the context manager on purpose: entering it would run the
    # app lifespan, which calls SERVICE.start() and would both clobber this fixture
    # and start network polling against ANU and NOAA from the test suite.
    yield TestClient(app)
    tmp.cleanup()


@pytest.fixture
def key(client):
    r = client.post("/v1/admin/keys", headers={"X-Admin-Token": ADMIN},
                    json={"tier": "pro", "label": "test"})
    assert r.status_code == 200
    return r.json()["key"]


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


class TestAuth:
    def test_requires_a_key(self, client):
        assert client.get("/v1/random/bytes").status_code == 401

    def test_rejects_malformed_key(self, client):
        assert client.get("/v1/random/bytes", headers=auth("nonsense")).status_code == 401

    def test_rejects_unknown_but_well_formed_key(self, client):
        fake = keylib.mint().token
        assert client.get("/v1/random/bytes", headers=auth(fake)).status_code == 401

    def test_rejects_valid_id_with_wrong_secret(self, client, key):
        env, kid, _ = keylib.parse(key)
        assert client.get("/v1/random/bytes",
                          headers=auth(f"bl_{env}_{kid}_{'A' * 32}")).status_code == 401

    def test_accepts_x_api_key_header(self, client, key):
        assert client.get("/v1/random/bytes", headers={"X-API-Key": key}).status_code == 200

    def test_revoked_key_is_refused(self, client, key):
        kid = keylib.parse(key)[1]
        assert client.delete(f"/v1/admin/keys/{kid}",
                             headers={"X-Admin-Token": ADMIN}).status_code == 200
        r = client.get("/v1/random/bytes", headers=auth(key))
        assert r.status_code == 401 and "revoked" in r.json()["detail"]

    def test_admin_requires_token(self, client):
        assert client.post("/v1/admin/keys", json={"tier": "free"}).status_code == 401
        assert client.post("/v1/admin/keys", headers={"X-Admin-Token": "wrong"},
                           json={"tier": "free"}).status_code == 401

    def test_admin_rejects_unknown_tier(self, client):
        r = client.post("/v1/admin/keys", headers={"X-Admin-Token": ADMIN},
                        json={"tier": "platinum"})
        assert r.status_code == 400

    def test_key_returned_once_and_hashed_at_rest(self, client, key):
        kid = keylib.parse(key)[1]
        secret = key.split("_")[-1]
        stored = SERVICE.db.get_key(kid)
        assert secret not in stored["secret_hash"]

        # The listing endpoint must never expose the secret or even its hash.
        listed = client.get("/v1/admin/keys", headers={"X-Admin-Token": ADMIN}).json()["keys"][0]
        assert "secret_hash" not in listed
        assert secret not in str(listed)


class TestRandomEndpoints:
    def test_bytes_formats(self, client, key):
        h = client.get("/v1/random/bytes?n=16&format=hex", headers=auth(key)).json()
        assert len(h["data"]) == 32
        b = client.get("/v1/random/bytes?n=16&format=binary", headers=auth(key))
        assert len(b.content) == 16
        assert b.headers["content-type"] == "application/octet-stream"

    def test_bytes_rejects_oversize(self, client, key):
        assert client.get("/v1/random/bytes?n=99999999", headers=auth(key)).status_code == 413

    def test_bytes_rejects_zero(self, client, key):
        assert client.get("/v1/random/bytes?n=0", headers=auth(key)).status_code == 400

    def test_integers_respect_bounds(self, client, key):
        d = client.post("/v1/random/integers", headers=auth(key),
                        json={"count": 50, "min": 5, "max": 9}).json()["data"]
        assert len(d) == 50 and all(5 <= v <= 9 for v in d)

    def test_integers_bad_range_is_400_not_500(self, client, key):
        r = client.post("/v1/random/integers", headers=auth(key),
                        json={"count": 5, "min": 100, "max": 1})
        assert r.status_code == 400

    def test_unique_overdraw_is_400(self, client, key):
        r = client.post("/v1/random/integers", headers=auth(key),
                        json={"count": 20, "min": 1, "max": 5, "unique": True})
        assert r.status_code == 400

    def test_shuffle_preserves_multiset(self, client, key):
        items = list(range(30))
        d = client.post("/v1/random/shuffle", headers=auth(key), json={"items": items}).json()["data"]
        assert sorted(d) == items

    def test_sample_overdraw_is_400(self, client, key):
        r = client.post("/v1/random/sample", headers=auth(key),
                        json={"items": [1, 2, 3], "count": 10})
        assert r.status_code == 400

    def test_password_is_not_cacheable(self, client, key):
        r = client.get("/v1/random/password?length=24", headers=auth(key))
        assert "no-store" in r.headers["cache-control"]
        assert len(r.json()["data"][0]["value"]) == 24

    def test_uuid_shape(self, client, key):
        d = client.get("/v1/random/uuid?count=3", headers=auth(key)).json()["data"]
        assert len(d) == 3 and all(u[14] == "4" for u in d)

    def test_responses_are_anchored_to_the_beacon(self, client, key):
        assert client.get("/v1/random/bytes?n=8", headers=auth(key)).json()["beacon_round"] == 1

    def test_successive_requests_differ(self, client, key):
        seen = {client.get("/v1/random/bytes?n=32&format=hex",
                           headers=auth(key)).json()["data"] for _ in range(25)}
        assert len(seen) == 25


class TestQuotaAndUsage:
    def test_usage_is_recorded(self, client, key):
        client.get("/v1/random/bytes?n=100", headers=auth(key))
        assert client.get("/v1/me", headers=auth(key)).json()["usage_this_period"]["bytes"] >= 100

    def test_free_tier_per_request_cap(self, client):
        k = client.post("/v1/admin/keys", headers={"X-Admin-Token": ADMIN},
                        json={"tier": "free"}).json()["key"]
        assert client.get("/v1/random/bytes?n=4096", headers=auth(k)).status_code == 413
        assert client.get("/v1/random/bytes?n=512", headers=auth(k)).status_code == 200

    def test_exhausted_quota_returns_402(self, client, key):
        kid = keylib.parse(key)[1]
        SERVICE.db.record_usage(kid, 5 * 1024 * 1024 * 1024)  # blow past the pro cap
        r = client.get("/v1/random/bytes?n=8", headers=auth(key))
        assert r.status_code == 402 and "quota" in r.json()["detail"]

    def test_rate_limit_returns_429_with_retry_after(self, client):
        k = client.post("/v1/admin/keys", headers={"X-Admin-Token": ADMIN},
                        json={"tier": "free"}).json()["key"]
        codes = [client.get("/v1/random/bytes?n=8", headers=auth(k)).status_code
                 for _ in range(60)]
        assert 429 in codes
        r = client.get("/v1/random/bytes?n=8", headers=auth(k))
        if r.status_code == 429:
            assert "retry-after" in r.headers


class TestBeaconEndpoints:
    def test_beacon_is_public(self, client):
        assert client.get("/v1/beacon/latest").status_code == 200
        assert client.get("/v1/beacon/verify/1").json()["valid"] is True

    def test_unknown_pulse_is_404(self, client):
        assert client.get("/v1/beacon/pulse/9999").status_code == 404

    def test_derive_is_reproducible(self, client, key):
        body = {"round": 1, "tag": "t1", "kind": "integers", "count": 5, "min": 1, "max": 100}
        a = client.post("/v1/beacon/derive", headers=auth(key), json=body).json()["data"]
        b = client.post("/v1/beacon/derive", headers=auth(key), json=body).json()["data"]
        assert a == b

    def test_derive_differs_by_tag(self, client, key):
        base = {"round": 1, "kind": "integers", "count": 8, "min": 1, "max": 10_000}
        a = client.post("/v1/beacon/derive", headers=auth(key), json={**base, "tag": "a"}).json()["data"]
        b = client.post("/v1/beacon/derive", headers=auth(key), json={**base, "tag": "b"}).json()["data"]
        assert a != b

    def test_cannot_derive_from_a_future_pulse(self, client, key):
        """The guarantee depends on the pulse already being published."""
        r = client.post("/v1/beacon/derive", headers=auth(key),
                        json={"round": 5000, "tag": "future", "kind": "integers", "count": 1})
        assert r.status_code == 404

    def test_derive_requires_a_key(self, client):
        assert client.post("/v1/beacon/derive",
                           json={"round": 1, "tag": "t", "kind": "integers"}).status_code == 401


class TestMeta:
    def test_health_reports_pool_and_drbg(self, client):
        h = client.get("/v1/health").json()
        assert h["seeded"] and h["drbg"]["bytes_generated"] >= 0
        assert "credit_policy_bits_per_byte" in h["pool"]

    def test_about_states_astro_credit_is_zero(self, client):
        """Guards against the marketing claim drifting away from the implementation."""
        from beamline.entropy.pool import CREDIT_BITS_PER_BYTE

        about = client.get("/v1/about").json()
        assert CREDIT_BITS_PER_BYTE["astro"] == 0.0
        assert about["entropy_credit_policy"]["astro"].startswith("0 bits/byte")
        assert any("public data" in c.lower() for c in about["what_we_do_not_claim"])

    def test_openapi_renders(self, client):
        assert client.get("/openapi.json").status_code == 200


@pytest.fixture
def signed_client(client):
    """A client whose beacon has a signing key, as any real deployment must have.

    The chain is restarted from empty so every round in it is signed. Leaving the
    unsigned pulse the base fixture emitted would make round 1 unattributable and the
    attribution assertions below would be testing the wrong thing.
    """
    ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    sk = ed.Ed25519PrivateKey.generate()
    with SERVICE.db._conn() as c:
        c.execute("DELETE FROM pulses")
    SERVICE.beacon = Beacon(SERVICE.db, SERVICE.pool, 60, sk.private_bytes_raw().hex())
    SERVICE.beacon.emit()
    return client


class TestCommitmentEndpoints:
    """The endpoints that turn 'we announced it first' from a claim into evidence."""

    def test_commit_names_a_future_round(self, signed_client, key):
        latest = signed_client.get("/v1/beacon/latest").json()["round"]
        r = signed_client.post("/v1/beacon/commit", headers={"Authorization": f"Bearer {key}"},
                               json={"tag": "giveaway-7"})
        assert r.status_code == 201, r.text
        receipt = r.json()
        assert receipt["target_round"] > receipt["created_after_round"] == latest
        assert receipt["signature"] and receipt["tag"] == "giveaway-7"

    def test_commit_refuses_an_emitted_round(self, signed_client, key):
        """Committing to the past is the whole attack, so it is refused at the source."""
        latest = signed_client.get("/v1/beacon/latest").json()["round"]
        r = signed_client.post("/v1/beacon/commit", headers={"Authorization": f"Bearer {key}"},
                               json={"tag": "after-the-fact", "target_round": latest})
        assert r.status_code == 409
        assert "already been emitted" in r.json()["detail"]

    def test_commitment_lookup_is_public(self, signed_client, key):
        commit = signed_client.post(
            "/v1/beacon/commit", headers={"Authorization": f"Bearer {key}"},
            json={"tag": "public-check"}).json()
        r = signed_client.get(f"/v1/beacon/commitment/{commit['commit_id']}")
        assert r.status_code == 200, "an entrant with no account must be able to check this"
        assert r.json()["valid"] is True
        assert r.json()["target_round_emitted"] is False

    def test_commitments_for_a_round_are_listed(self, signed_client, key):
        """A runner announcing twenty draws against one pulse should be visible."""
        headers = {"Authorization": f"Bearer {key}"}
        target = signed_client.get("/v1/beacon/latest").json()["round"] + 1
        for i in range(3):
            signed_client.post("/v1/beacon/commit", headers=headers,
                               json={"tag": f"variant-{i}", "target_round": target})
        r = signed_client.get(f"/v1/beacon/commitments/{target}")
        assert r.json()["count"] == 3
        assert {c["tag"] for c in r.json()["commitments"]} == {"variant-0", "variant-1", "variant-2"}

    def test_derive_with_a_commitment_reports_it(self, signed_client, key):
        headers = {"Authorization": f"Bearer {key}"}
        commit = signed_client.post("/v1/beacon/commit", headers=headers,
                                    json={"tag": "bound-draw"}).json()
        SERVICE.beacon.emit()
        r = signed_client.post("/v1/beacon/derive", headers=headers, json={
            "round": commit["target_round"], "tag": "bound-draw",
            "commit_id": commit["commit_id"], "count": 1, "min": 1, "max": 100})
        assert r.status_code == 200, r.text
        assert r.json()["committed"] is True
        assert "did not exist when the draw was named" in r.json()["provenance_note"]

    def test_derive_refuses_a_commitment_for_another_tag(self, signed_client, key):
        """Grinding, at the API boundary: the tag is inside the signed receipt."""
        headers = {"Authorization": f"Bearer {key}"}
        commit = signed_client.post("/v1/beacon/commit", headers=headers,
                                    json={"tag": "giveaway-7"}).json()
        SERVICE.beacon.emit()
        r = signed_client.post("/v1/beacon/derive", headers=headers, json={
            "round": commit["target_round"], "tag": "giveaway-7 (attempt 138)",
            "commit_id": commit["commit_id"], "count": 1, "min": 1, "max": 100})
        assert r.status_code == 409 and "not" in r.json()["detail"]

    def test_derive_refuses_a_commitment_for_another_round(self, signed_client, key):
        headers = {"Authorization": f"Bearer {key}"}
        commit = signed_client.post("/v1/beacon/commit", headers=headers,
                                    json={"tag": "giveaway-7"}).json()
        SERVICE.beacon.emit()
        later = SERVICE.beacon.emit()
        r = signed_client.post("/v1/beacon/derive", headers=headers, json={
            "round": later["round"], "tag": "giveaway-7",
            "commit_id": commit["commit_id"], "count": 1, "min": 1, "max": 100})
        assert r.status_code == 409

    def test_uncommitted_derive_says_so(self, signed_client, key):
        """It still works. It just stops implying something it cannot support."""
        r = signed_client.post("/v1/beacon/derive", headers={"Authorization": f"Bearer {key}"},
                               json={"round": 1, "tag": "whatever", "count": 1,
                                     "min": 1, "max": 100})
        assert r.status_code == 200
        assert r.json()["committed"] is False
        assert "NOT COMMITTED" in r.json()["provenance_note"]


class TestVerifyEndpointHonesty:
    def test_an_unsigned_deployment_is_not_reported_as_attributable(self, client):
        """The `client` fixture's beacon has no key, as an unsigned deployment would not."""
        r = client.get("/v1/beacon/verify/1").json()
        assert r["attributable"] is False, "an unsigned pulse cannot be attributed to anyone"
        assert r["checked_against_key"] is None

    def test_a_signed_deployment_is_attributable(self, signed_client):
        r = signed_client.get("/v1/beacon/verify/1").json()
        assert r["valid"] is True and r["attributable"] is True

    def test_chain_verification_is_public(self, signed_client):
        SERVICE.beacon.emit()
        r = signed_client.get("/v1/beacon/verify-chain?start=1&count=10")
        assert r.status_code == 200
        assert r.json()["valid"] is True and r.json()["attributable"] is True
