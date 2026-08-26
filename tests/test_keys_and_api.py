"""Key handling, beacon integrity, and API surface tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from beamline import keys as keylib
from beamline.db import Database
from beamline.entropy.beacon import Beacon, Pulse, verify_pulse
from beamline.entropy.pool import EntropyPool
from beamline.ratelimit import RateLimiter


class TestKeys:
    def test_roundtrip(self):
        mk = keylib.mint(tier="pro", label="test")
        env, key_id, secret = keylib.parse(mk.token)
        assert env == "live" and key_id == mk.key_id
        assert keylib.verify(secret, mk.secret_hash)

    def test_wrong_secret_rejected(self):
        mk = keylib.mint()
        assert not keylib.verify("Z" * 32, mk.secret_hash)

    def test_plaintext_secret_is_not_in_the_stored_hash(self):
        mk = keylib.mint()
        _, _, secret = keylib.parse(mk.token)
        assert secret not in mk.secret_hash

    def test_keys_are_unique(self):
        assert len({keylib.mint().token for _ in range(500)}) == 500

    def test_secret_entropy(self):
        """32 chars of a 32-symbol alphabet is 160 bits. Below ~128 is not sellable."""
        import math
        assert keylib.SECRET_LEN * math.log2(len(keylib.ALPHABET)) >= 128

    @pytest.mark.parametrize("bad", [
        "", "garbage", "bl_live_short_x", "xx_live_ABCDEFGH_" + "A" * 32,
        "bl_prod_ABCDEFGH_" + "A" * 32,          # unknown environment
        "bl_live_ABCDEFGH_" + "A" * 31,          # short secret
        "bl_live_ABCDEFGH_" + "U" * 32,          # 'U' is not in the alphabet
        "bl_live_ABCDEFGH",                      # missing segment
    ])
    def test_malformed_tokens_rejected(self, bad):
        assert keylib.parse(bad) is None

    def test_test_env_parses(self):
        mk = keylib.mint(env="test")
        assert keylib.parse(mk.token)[0] == "test"

    def test_fingerprint_hides_secret(self):
        mk = keylib.mint()
        fp = keylib.fingerprint(mk.token)
        _, _, secret = keylib.parse(mk.token)
        assert secret not in fp and mk.key_id in fp

    def test_alphabet_excludes_confusable_characters(self):
        assert not (set("ILOU") & set(keylib.ALPHABET))


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as d:
        yield Database(Path(d) / "t.db")


class TestDatabase:
    def test_key_lifecycle(self, db):
        mk = keylib.mint(tier="starter", label="l")
        db.insert_key(mk.key_id, mk.secret_hash, mk.env, mk.tier, mk.label, "o", mk.created_at)
        row = db.get_key(mk.key_id)
        assert row["tier"] == "starter" and row["revoked_at"] is None
        assert db.revoke_key(mk.key_id)
        assert db.get_key(mk.key_id)["revoked_at"] is not None
        assert not db.revoke_key(mk.key_id), "revoking twice must be a no-op"

    def test_usage_accumulates(self, db):
        for _ in range(5):
            db.record_usage("k1", 100)
        assert db.get_usage("k1") == {"requests": 5, "bytes": 500}

    def test_usage_is_per_key(self, db):
        db.record_usage("a", 10)
        assert db.get_usage("b")["bytes"] == 0

    def test_unknown_key(self, db):
        assert db.get_key("NOPE") is None


class TestBeacon:
    @pytest.fixture
    def beacon(self, db):
        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        return Beacon(db, pool, period_seconds=1)

    def test_first_pulse_starts_from_genesis(self, beacon):
        p = beacon.emit()
        assert p["round"] == 1 and p["prev_output"] == "00" * 64

    def test_chain_links(self, beacon):
        pulses = [beacon.emit() for _ in range(5)]
        for i in range(1, 5):
            assert pulses[i]["prev_output"] == pulses[i - 1]["output"]
            assert pulses[i]["round"] == pulses[i - 1]["round"] + 1

    def test_pulses_verify(self, beacon):
        """An unsigned beacon: structure and chaining hold, attribution does not.

        allow_unsigned is explicit here because that is now the only way to get an
        answer about an unsigned pulse. Verification with no trust anchor used to
        return True, which meant a fabricated chain verified.
        """
        prev = None
        for _ in range(4):
            p = beacon.emit()
            ok, reason = verify_pulse(p, prev_output=prev, allow_unsigned=True)
            assert ok, reason
            assert "UNSIGNED" in reason
            prev = p["output"]

    def test_an_unsigned_pulse_is_not_verified_by_default(self):
        """The attack this closes: publish a fabricated chain, sign nothing.

        Every pulse in it hashes to its own contents and links to the one before,
        because the forger controls all of it. Without a key to check against there
        is nothing to distinguish it from Beamline's, so a caller who names no key
        gets a refusal rather than a pass.
        """
        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        with tempfile.TemporaryDirectory() as d:
            b = Beacon(Database(Path(d) / "f.db"), pool, 1)
            forged = b.emit()
        ok, reason = verify_pulse(forged)
        assert not ok and "trust anchor" in reason

    def test_tampering_is_detected(self, beacon):
        beacon.emit()
        p = beacon.emit()
        for field in ("local_value", "prev_output"):
            bad = dict(p)
            bad[field] = "ff" * 64
            ok, reason = verify_pulse(bad, allow_unsigned=True)
            assert not ok, f"tampering with {field} went undetected"
            assert "output hash" in reason, reason

    def test_broken_chain_link_detected(self, beacon):
        beacon.emit()
        p2 = beacon.emit()
        assert not verify_pulse(p2, prev_output="ab" * 64, allow_unsigned=True)[0]

    def test_outputs_are_unique(self, beacon):
        assert len({beacon.emit()["output"] for _ in range(20)}) == 20

    def test_derive_is_deterministic(self, beacon):
        beacon.emit()
        a = beacon.derive(1, "tag", 64)
        b = beacon.derive(1, "tag", 64)
        assert a == b

    def test_derive_separates_tags(self, beacon):
        beacon.emit()
        assert beacon.derive(1, "alice", 64) != beacon.derive(1, "bob", 64)

    def test_derive_separates_rounds(self, beacon):
        beacon.emit(); beacon.emit()
        assert beacon.derive(1, "t", 64) != beacon.derive(2, "t", 64)

    def test_derive_unknown_round(self, beacon):
        with pytest.raises(KeyError):
            beacon.derive(99, "t", 8)

    def test_signed_pulses_verify_and_reject_wrong_key(self, db):
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        sk = Ed25519PrivateKey.generate()
        b = Beacon(db, pool, 1, sk.private_bytes_raw().hex())
        p = b.emit()
        assert p["signature"]
        assert verify_pulse(p, public_key_hex=b.public_key_hex)[0]

        # A key the caller did not name is a FAILURE. This used to return True with a
        # note calling it a rotation, which meant a chain signed by an attacker's own
        # key passed while the caller pinned the real one -- the note was in a string
        # nobody reads and the boolean said yes.
        other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        ok, reason = verify_pulse(p, public_key_hex=other)
        assert not ok
        assert "untrusted key" in reason

    def test_a_real_rotation_is_accepted_only_when_named(self, db):
        """Rotation is a decision the verifier makes, not one the pulse announces."""
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        old = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        sk = Ed25519PrivateKey.generate()
        b = Beacon(db, pool, 1, sk.private_bytes_raw().hex())
        p = b.emit()

        assert not verify_pulse(p, public_key_hex=old)[0]
        ok, reason = verify_pulse(p, trusted_keys=[old, b.public_key_hex])
        assert ok, reason

    def test_timestamp_is_an_integer_in_the_signed_body(self, db):
        """Guards a cross-language canonicalisation bug.

        A float timestamp that lands on a whole second serialises as "1787150090.0" in
        Python and "1787150090" in JavaScript. The canonical bytes then differ, and
        signature verification fails for about one pulse in a thousand -- silently, and
        only for the independent verifiers the product depends on. An integer
        millisecond field serialises identically in both.
        """
        import json as _json

        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        b = Beacon(db, pool, 1)
        p = b.emit()

        assert isinstance(p["timestamp_ms"], int)
        assert "timestamp" not in p, "a float timestamp must not shadow the integer field"

        body = _json.loads(Pulse(
            version=p["version"], round=p["round"], timestamp_ms=p["timestamp_ms"],
            period_seconds=p["period_seconds"], prev_output=p["prev_output"],
            local_value=p["local_value"], public_key=p.get("public_key"),
            provenance=p["provenance"],
        ).signing_bytes())
        assert isinstance(body["timestamp_ms"], int)
        assert "." not in str(body["timestamp_ms"])

    def test_whole_second_timestamp_still_verifies(self, db):
        """The exact case that broke: a timestamp with no fractional milliseconds."""
        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        b = Beacon(db, pool, 1)
        p = b.emit()
        p = dict(p)
        p["timestamp_ms"] = (p["timestamp_ms"] // 1000) * 1000   # land on a whole second

        rebuilt = Pulse(
            version=p["version"], round=p["round"], timestamp_ms=p["timestamp_ms"],
            period_seconds=p["period_seconds"], prev_output=p["prev_output"],
            local_value=p["local_value"], public_key=p.get("public_key"),
            provenance=p["provenance"],
        )
        p["output"] = rebuilt.compute_output()
        assert verify_pulse(p, allow_unsigned=True)[0]

    def test_declared_key_cannot_be_swapped(self, db):
        """Substituting the declared key must break the output hash."""
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        sk = Ed25519PrivateKey.generate()
        b = Beacon(db, pool, 1, sk.private_bytes_raw().hex())
        p = b.emit()

        forged = dict(p)
        forged["public_key"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        ok, reason = verify_pulse(forged, public_key_hex=b.public_key_hex)
        # The declared key is inside the signed body, so swapping it breaks the output
        # hash before the signature check is even reached.
        assert not ok and "output hash" in reason

    def test_rotation_is_reported_by_the_chain_verifier(self, db):
        """A key change is legal but must never pass unremarked."""
        pytest.importorskip("cryptography")
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))
        from beamline_client import verify as v
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        k1 = Ed25519PrivateKey.generate().private_bytes_raw().hex()
        k2 = Ed25519PrivateKey.generate().private_bytes_raw().hex()

        b1 = Beacon(db, pool, 1, k1)
        pulses = [b1.emit(), b1.emit()]
        endorsement = b1.endorse_rotation(k2, effective_round=3)
        b2 = Beacon(db, pool, 1, k2)          # operator rotates
        pulses.append(b2.emit())

        # Naming only the old key rejects the chain: an unannounced rotation is
        # indistinguishable from someone substituting their own archive.
        assert not v.check_chain(pulses, b1.public_key_hex)[0]

        # Trusting both is still not enough on its own -- the outgoing key has to
        # have said so.
        both = [b1.public_key_hex, b2.public_key_hex]
        assert not v.check_chain(pulses, trusted_keys=both)[0]

        ok, msg = v.check_chain(pulses, trusted_keys=both, rotations=[endorsement])
        assert ok, msg
        assert "signing key changed at round(s) [3]" in msg


class TestRateLimit:
    def test_burst_then_throttle(self):
        rl = RateLimiter()
        allowed = sum(rl.check("k", capacity=10, refill=0.0)[0] for _ in range(20))
        assert allowed == 10

    def test_retry_after_is_reported(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.check("k", 5, 1.0)
        ok, retry = rl.check("k", 5, 1.0)
        assert not ok and retry > 0

    def test_keys_are_independent(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.check("a", 5, 0.0)
        assert rl.check("b", 5, 0.0)[0]

    def test_tier_change_resets_bucket(self):
        rl = RateLimiter()
        for _ in range(3):
            rl.check("k", 3, 0.0)
        assert not rl.check("k", 3, 0.0)[0]
        assert rl.check("k", 50, 1.0)[0], "an upgraded tier should take effect immediately"


class TestVerifierAgreesWithServer:
    """The independent SDK verifier must reproduce server output exactly.

    If this test fails, the product's central claim is broken -- so it is worth
    having even though it couples the two implementations in one process.
    """

    def test_reproduces_derived_integers(self, db):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))
        from beamline_client import verify as v

        from beamline import generators as gen

        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        beacon = Beacon(db, pool, 1)
        pulse = beacon.emit()

        # Server-side derivation, mirroring routes/beacon.py.
        stream, pos, chunk = bytearray(), 0, 0

        def rand(n: int) -> bytes:
            nonlocal pos, chunk
            while pos + n > len(stream):
                chunk += 1
                stream.extend(beacon.derive(pulse["round"], f"draw-1#{chunk}", 4096))
            out = bytes(stream[pos:pos + n])
            pos += n
            return out

        server = gen.integers(rand, 10, 1, 49)
        client = v.reproduce_integers(pulse["output"], "draw-1", 10, 1, 49)
        assert server == client

    def test_verifier_checks_chain(self, db):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))
        from beamline_client import verify as v

        pool = EntropyPool()
        pool.add("local_os", os.urandom(256))
        beacon = Beacon(db, pool, 1)
        pulses = [beacon.emit() for _ in range(6)]
        assert v.check_chain(pulses, allow_unsigned=True)[0]

        pulses[3]["local_value"] = "00" * 64
        ok, reason = v.check_chain(pulses, allow_unsigned=True)
        assert not ok and "round 4" in reason


def test_the_sdk_will_not_send_a_key_to_a_host_nobody_runs():
    """Both clients defaulted to https://api.beamline.dev, which is not the service.

    There is no hosted Beamline; every example in the README points at a local one. The
    domain sits on a parking host and currently refuses connections, so omitting
    `base_url` produced a confusing timeout. The real cost is that the first request
    carries `Authorization: Bearer <key>`, so a default aimed at a host the project does
    not control is a live key disclosed to whoever takes that domain over.

    Fail closed, the same rule `verify_pulse` applies to a missing trust anchor.
    """
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "sdk" / "python"))
    from beamline_client.client import DEFAULT_BASE, Beamline

    assert DEFAULT_BASE is None

    with pytest.raises(ValueError, match="base_url is required"):
        Beamline(api_key="bl_live_test")

    # And the refusal says what to do instead, rather than only what went wrong.
    try:
        Beamline(api_key="bl_live_test")
    except ValueError as e:
        assert "127.0.0.1:8080" in str(e) and "DEPLOY.md" in str(e)

    # A real base_url still constructs.
    assert Beamline(api_key="bl_live_test", base_url="http://127.0.0.1:8080")

    # Neither SDK may reintroduce the phantom host.
    for path in (root / "sdk" / "python" / "beamline_client" / "client.py",
                 root / "sdk" / "js" / "index.js"):
        body = path.read_text()
        assert "= 'https://api.beamline.dev'" not in body
        assert '= "https://api.beamline.dev"' not in body
