"""Every attack that worked against this codebase, kept working against it.

Each test below reproduces something that succeeded before the verification rewrite,
against the shipped verifiers, using the same code an attacker would. They are written
as attacks rather than as unit tests because the failure mode they guard is not "this
function returns the wrong value" -- it is "a stranger publishes a fabricated draw and
our own tooling calls it verified".

The five that worked:

  1. A wholly fabricated unsigned chain verified, because the verifier's trust anchor
     defaulted to None and an internally consistent chain was accepted on that basis.
  2. A chain signed with the attacker's own key verified while the caller pinned the
     real one, because an unrecognised key was reported as a rotation and returned True.
  3. The browser verifier reported success from inside its own catch block, so a pulse
     with an unparseable public key showed all green ticks.
  4. A draw could be rigged with no forgery at all, by grinding the tag or the round
     against genuine published pulses.
  5. Python and JavaScript disagreed about the canonical bytes, so an honest pulse
     could verify in one and fail in the other.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from beamline_client import verify as V  # noqa: E402

from beamline.db import Database  # noqa: E402
from beamline.entropy.beacon import (  # noqa: E402
    GENESIS, VERSION, Beacon, Pulse, verify_chain, verify_pulse)
from beamline.entropy.pool import EntropyPool  # noqa: E402

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="attack tests need Ed25519",
)
Ed25519PrivateKey = ed25519.Ed25519PrivateKey


@pytest.fixture
def operator(tmp_path):
    """A running beacon with a signing key, as a real deployment would have."""
    pool = EntropyPool()
    pool.add("local_os", b"\x01" * 256)
    sk = Ed25519PrivateKey.generate()
    return Beacon(Database(tmp_path / "real.db"), pool, 60, sk.private_bytes_raw().hex())


def forge(rounds: int, *, signer=None, public_key=None, start_ms: int = 1787300000000,
          value=lambda r: hashlib.sha512(f"ATTACKER-CHOSE-{r}".encode()).hexdigest()):
    """Build a chain from nothing. The attacker controls every byte in it."""
    out, prev = [], GENESIS
    for r in range(1, rounds + 1):
        p = Pulse(
            version=VERSION, round=r, timestamp_ms=start_ms + r * 60_000,
            period_seconds=60, prev_output=prev, local_value=value(r),
            public_key=public_key,
            provenance={"local_os": {"at_ms": start_ms, "bytes": 64}},
        )
        p.output = p.compute_output()
        if signer is not None:
            p.signature = signer.sign(p.signing_bytes()).hex()
        prev = p.output
        out.append(p.to_dict())
    return out


class TestFabricatedChain:
    """Attack 1: publish your own chain and sign nothing."""

    def test_sdk_refuses_a_forged_chain(self):
        ok, reason = V.check_chain(forge(10))
        assert not ok, "a chain built from nothing was accepted"
        assert "trust anchor" in reason

    def test_server_refuses_a_forged_chain(self):
        ok, reason = verify_chain(forge(10))
        assert not ok and "trust anchor" in reason

    def test_naming_a_key_also_refuses_it(self, operator):
        """Even a caller who does pin a key must not be fooled by an unsigned chain."""
        ok, reason = V.check_chain(forge(10), operator.public_key_hex)
        assert not ok and "unsigned" in reason.lower()

    def test_the_forged_chain_is_internally_perfect(self):
        """Establishing that the refusal is not luck: the forgery is well-formed.

        Every pulse hashes to its own contents and links to the one before. Nothing
        about its structure is wrong -- which is exactly why structure alone was never
        enough to accept it.
        """
        chain = forge(10)
        for i, p in enumerate(chain):
            assert V.pulse_output(p) == p["output"]
            if i:
                assert p["prev_output"] == chain[i - 1]["output"]
        ok, _ = V.check_chain(chain, allow_unsigned=True)
        assert ok, "the forgery should be structurally sound; that was the point"


class TestKeySubstitution:
    """Attack 2: sign your forgery with your own key and let the verifier rationalise it."""

    def test_attacker_signed_chain_is_refused(self, operator):
        atk = Ed25519PrivateKey.generate()
        chain = forge(10, signer=atk, public_key=atk.public_key().public_bytes_raw().hex())
        ok, reason = V.check_chain(chain, operator.public_key_hex)
        assert not ok, "a chain signed by an attacker's key was accepted"
        assert "untrusted key" in reason

    def test_splicing_onto_a_genuine_chain_is_refused(self, operator):
        """The realistic form: keep the real history, rewrite the rounds that matter."""
        real = [operator.emit() for _ in range(4)]
        atk = Ed25519PrivateKey.generate()
        atk_pub = atk.public_key().public_bytes_raw().hex()

        spliced, prev = list(real), real[-1]["output"]
        for r in range(5, 11):
            p = Pulse(version=VERSION, round=r, timestamp_ms=real[-1]["timestamp_ms"] + r,
                      period_seconds=60, prev_output=prev,
                      local_value=hashlib.sha512(f"RIGGED-{r}".encode()).hexdigest(),
                      public_key=atk_pub, provenance={})
            p.output = p.compute_output()
            p.signature = atk.sign(p.signing_bytes()).hex()
            prev = p.output
            spliced.append(p.to_dict())

        ok, reason = V.check_chain(spliced, operator.public_key_hex)
        assert not ok, "a spliced chain was accepted"
        assert "round 5" in reason and "untrusted key" in reason

    def test_a_named_rotation_still_works(self, operator, tmp_path):
        """The legitimate case the old behaviour was trying to serve."""
        first = [operator.emit(), operator.emit()]
        sk2 = Ed25519PrivateKey.generate()
        second = Beacon(operator._store, operator._pool, 60, sk2.private_bytes_raw().hex())
        rotated = first + [second.emit()]

        assert not V.check_chain(rotated, operator.public_key_hex)[0]
        ok, msg = V.check_chain(
            rotated, trusted_keys=[operator.public_key_hex, second.public_key_hex])
        assert ok, msg
        assert "signing key changed" in msg


class TestBrowserVerifier:
    """Attack 3: crash the signature check instead of defeating it."""

    def test_the_page_rejects_every_forgery(self):
        """Runs the page's own functions, sliced out of docs/index.html.

        The harness is a separate script because the code under test is JavaScript;
        it is invoked here so a Python-only test run still covers it.
        """
        node = subprocess.run(["node", str(ROOT / "scripts" / "check_js_verifiers.mjs")],
                              capture_output=True, text=True, cwd=ROOT)
        assert node.returncode == 0, node.stdout + node.stderr

    def test_the_published_page_and_chain_are_in_step(self):
        chain = json.loads((ROOT / "docs" / "chain.json").read_text())
        ok, reason = V.check_chain(chain["pulses"], chain["public_key"])
        assert ok, reason
        assert chain["pulses"][0]["version"] == VERSION


class TestGrinding:
    """Attack 4: rig the draw without forging anything at all."""

    def test_tag_grinding_finds_a_winner_fast(self, operator):
        """Not a fix -- a measurement. This is what an uncommitted draw is worth.

        The point of asserting it is that the number is small: if a future change
        makes derivation expensive, this test should be reconsidered rather than
        deleted, because the defence is the commitment, not the cost.
        """
        pulse = operator.emit()
        entrants = [f"entrant_{i:03d}" for i in range(100)]
        target = "entrant_042"

        for tries in range(1, 2001):
            tag = f"Giveaway 7 (draw attempt {tries})"
            winner = entrants[V.reproduce_integers(pulse["output"], tag, 1, 0, 99)[0]]
            if winner == target:
                break
        else:
            pytest.fail("expected to grind a winning tag within 2000 tries")

        # And the rigged draw verifies, because nothing about it is forged.
        assert V.check_pulse(pulse, operator.public_key_hex)[0]
        assert tries < 1000, f"took {tries} tries; the attack is cheap, and that is the point"

    def test_a_commitment_refuses_the_ground_tag(self, operator):
        """The fix: the announced tag is inside a signed receipt."""
        receipt = operator.commit("Giveaway 7")
        pulse = operator.emit()
        assert pulse["round"] == receipt["target_round"]

        rigged = "Giveaway 7 (draw attempt 138)"
        result = V.reproduce_integers(pulse["output"], rigged, 1, 0, 99)
        ok, reason = V.check_draw({**pulse}, {**receipt, "tag": rigged}, result,
                                  operator.public_key_hex, count=1, minimum=0, maximum=99)
        assert not ok, "a ground-out tag passed as a committed draw"
        assert "signature" in reason

    def test_round_grinding_is_refused(self, operator):
        """The other half: keep the tag, choose the pulse."""
        receipt = operator.commit("Giveaway 7")
        committed = operator.emit()
        later = [operator.emit() for _ in range(5)]

        result = V.reproduce_integers(later[3]["output"], "Giveaway 7", 1, 0, 99)
        ok, reason = V.check_draw(later[3], receipt, result, operator.public_key_hex,
                                  count=1, minimum=0, maximum=99)
        assert not ok, "a draw was accepted against a round it was not committed to"
        assert "commitment names round" in reason

        honest = V.reproduce_integers(committed["output"], "Giveaway 7", 1, 0, 99)
        assert V.check_draw(committed, receipt, honest, operator.public_key_hex,
                            count=1, minimum=0, maximum=99)[0]

    def test_a_commitment_cannot_name_an_existing_round(self, operator):
        """Announcing after the fact is refused at the source, not just in the verifier."""
        operator.emit()
        operator.emit()
        with pytest.raises(ValueError, match="already been emitted"):
            operator.commit("after the fact", target_round=2)

    def test_a_backdated_receipt_is_refused_by_the_verifier(self, operator):
        """Even if the operator colluded and wrote one anyway."""
        operator.emit()
        pulse = operator.emit()
        forged_receipt = {
            "version": "beamline/commitment/v1", "commit_id": "0" * 32,
            "tag": "after the fact", "target_round": 2,
            "created_at_ms": 1787300000000, "created_after_round": 2,
            "public_key": operator.public_key_hex,
        }
        forged_receipt["signature"] = operator._signer.sign(
            V.canonical_commitment_body(forged_receipt)).hex()

        ok, reason = V.check_commitment(forged_receipt, operator.public_key_hex)
        assert not ok, "a receipt naming an already-emitted round was accepted"
        assert "already reached round" in reason


class TestCanonicalDivergence:
    """Attack 5: an honest pulse that two verifiers disagree about."""

    def test_a_float_in_the_body_cannot_be_signed(self, operator):
        """The reachable case: time.time() landing on a whole second."""
        p = Pulse(version=VERSION, round=1, timestamp_ms=1787300000000, period_seconds=60,
                  prev_output=GENESIS, local_value="ab" * 64, public_key=None,
                  provenance={"local_os": {"at": 1787300619.0}})
        with pytest.raises(ValueError, match="float"):
            p.compute_output()

    def test_a_float_in_the_body_cannot_be_verified(self, operator):
        pulse = operator.emit()
        pulse = dict(pulse)
        pulse["provenance"] = {"local_os": {"at": 1787300619.0}}
        ok, reason = V.check_pulse(pulse, operator.public_key_hex)
        assert not ok and "float" in reason

    def test_emitted_provenance_is_integer_only(self, operator):
        """What the live beacon actually publishes."""
        def floats(node):
            if isinstance(node, float):
                yield node
            elif isinstance(node, dict):
                for v in node.values():
                    yield from floats(v)
            elif isinstance(node, list):
                for v in node:
                    yield from floats(v)

        pulse = operator.emit()
        assert not list(floats(pulse)), "a float reached a signed pulse body"
        assert isinstance(pulse["timestamp_ms"], int)

    def test_the_two_implementations_produce_the_same_bytes(self, operator):
        """Server and SDK, independently written, over a real pulse."""
        from beamline.entropy.canonical import encode

        pulse = operator.emit()
        body = {k: pulse.get(k) for k in V.BODY_FIELDS}
        assert encode(body) == V.canonical_body(pulse)

    def test_a_hostile_source_cannot_break_the_beacon(self, tmp_path):
        """A feed returning floats degrades its own provenance, not the chain."""
        pool = EntropyPool()
        pool.add("local_os", b"\x02" * 256)
        sk = Ed25519PrivateKey.generate()
        b = Beacon(Database(tmp_path / "h.db"), pool, 60, sk.private_bytes_raw().hex())
        pool.last_sample["astro"] = {"at_ms": 1, "bytes": 4, "flux": 1e-8,
                                     "station": "Ny-Ålesund"}
        pulse = b.emit()
        assert V.check_pulse(pulse, b.public_key_hex)[0]


class TestUnsignedDeployment:
    """The operational version of attack 1: running with no key at all."""

    def test_the_service_refuses_to_start_unsigned(self, monkeypatch):
        import asyncio
        import importlib

        monkeypatch.delenv("BEAMLINE_BEACON_KEY", raising=False)
        monkeypatch.delenv("BEAMLINE_ALLOW_UNSIGNED_BEACON", raising=False)
        with tempfile.TemporaryDirectory() as d:
            monkeypatch.setenv("BEAMLINE_DB", str(Path(d) / "u.db"))
            import beamline.config
            importlib.reload(beamline.config)
            import beamline.service
            importlib.reload(beamline.service)
            svc = beamline.service.BeamlineService()
            with pytest.raises(RuntimeError, match="BEAMLINE_BEACON_KEY"):
                asyncio.run(svc.start())
