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
import os
import re
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

    def test_an_endorsed_rotation_works(self, operator, tmp_path):
        """The legitimate case, which now needs the old key's signature to say so."""
        first = [operator.emit(), operator.emit()]
        sk2 = Ed25519PrivateKey.generate()
        endorsement = operator.endorse_rotation(sk2.private_bytes_raw().hex(),
                                                effective_round=3)
        second = Beacon(operator._store, operator._pool, 60, sk2.private_bytes_raw().hex())
        rotated = first + [second.emit()]
        both = [operator.public_key_hex, second.public_key_hex]

        assert not V.check_chain(rotated, operator.public_key_hex)[0]
        ok, msg = V.check_chain(rotated, trusted_keys=both, rotations=[endorsement])
        assert ok, msg
        assert "endorsed by the key it retired" in msg

    def test_trusting_both_keys_is_not_an_endorsement(self, operator):
        """The hole: naming two keys says you would accept either, nothing more.

        An attacker who talks a verifier into trusting their key -- a doctored docs
        page, a support reply, a mirror of the repository -- gets a substituted
        archive accepted, with nothing in the chain contradicting it.
        """
        first = [operator.emit(), operator.emit()]
        attacker = Ed25519PrivateKey.generate()
        theirs = Beacon(operator._store, operator._pool, 60,
                        attacker.private_bytes_raw().hex())
        spliced = first + [theirs.emit()]

        ok, why = V.check_chain(
            spliced, trusted_keys=[operator.public_key_hex, theirs.public_key_hex])
        assert not ok, "an unendorsed key change was accepted"
        assert "ever handed over to" in why

    def test_a_rotation_cannot_be_forged_by_the_incoming_key(self, operator):
        """Whoever wants the chain must get the outgoing key to sign for them."""
        operator.emit()
        sk2 = Ed25519PrivateKey.generate()
        endorsement = operator.endorse_rotation(sk2.private_bytes_raw().hex(),
                                                effective_round=2)

        attacker = Ed25519PrivateKey.generate()
        forged = dict(endorsement)
        forged["to_public_key"] = attacker.public_key().public_bytes_raw().hex()
        forged["signature_to"] = attacker.sign(
            V.canonical_rotation_body(forged)).hex()

        ok, why = V.check_rotation(forged)
        assert not ok and "signature_from" in why

    def test_a_rotation_must_prove_the_new_key_exists(self, operator):
        """Proof of possession: authority cannot be handed to a key nobody holds."""
        operator.emit()
        sk2 = Ed25519PrivateKey.generate()
        endorsement = operator.endorse_rotation(sk2.private_bytes_raw().hex(),
                                                effective_round=2)
        stranded = dict(endorsement)
        del stranded["signature_to"]
        ok, why = V.check_rotation(stranded)
        assert not ok and "signature_to" in why


class TestBrowserVerifier:
    """Attack 3: crash the signature check instead of defeating it."""

    def test_the_page_rejects_every_forgery(self):
        """Runs the page's own functions, sliced out of index.html.

        The harness is a separate script because the code under test is JavaScript;
        it is invoked here so a Python-only test run still covers it.
        """
        node = subprocess.run(["node", str(ROOT / "scripts" / "check_js_verifiers.mjs")],
                              capture_output=True, text=True, cwd=ROOT)
        assert node.returncode == 0, node.stdout + node.stderr

    def test_the_published_page_and_chain_are_in_step(self):
        chain = json.loads((ROOT / "chain.json").read_text())
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
        receipt = operator.commit("Giveaway 7", minimum=0, maximum=99)
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
        receipt = operator.commit("Giveaway 7", minimum=0, maximum=99)
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
            "version": V.COMMITMENT_VERSION, "commit_id": "0" * 32,
            "tag": "after the fact", "target_round": 2,
            "created_at_ms": 1787300000000, "created_after_round": 2,
            "committer": "someone", "sequence": 1,
            "draw": {"kind": "integers", "count": 1, "min": 0, "max": 100,
                     "items_digest": None},
            "public_key": operator.public_key_hex,
        }
        forged_receipt["signature"] = operator._signer.sign(
            V.canonical_commitment_body(forged_receipt)).hex()

        ok, reason = V.check_commitment(forged_receipt, operator.public_key_hex)
        assert not ok, "a receipt naming an already-emitted round was accepted"
        assert "already reached round" in reason


class TestShapeGrinding:
    """Attack 6: commit the name honestly, then choose the size of the draw.

    The first version of the commitment fixed the tag and nothing else. A tag does
    not name a winner -- the same committed tag against the same pulse picks a
    different person at max=100 than at max=5000 -- so the runner still had a free
    choice after the pulse appeared, and every result verified.
    """

    def test_the_parameters_really_do_change_the_winner(self, operator):
        """Establishing the attack is real before asserting it is closed."""
        operator.commit("giveaway-7")
        pulse = operator.emit()
        winners = {
            (c, lo, hi): tuple(V.reproduce_integers(pulse["output"], "giveaway-7", c, lo, hi))
            for c, lo, hi in [(1, 1, 100), (1, 1, 5000), (1, 0, 99), (1, 1, 50)]
        }
        assert len(set(winners.values())) > 1, (
            "if the parameters did not change the outcome there would be nothing to fix")

    def test_a_different_range_is_refused(self, operator):
        receipt = operator.commit("giveaway-7", count=1, minimum=1, maximum=100)
        pulse = operator.emit()
        ground = V.reproduce_integers(pulse["output"], "giveaway-7", 1, 1, 5000)
        ok, why = V.check_draw(pulse, receipt, ground, operator.public_key_hex,
                               count=1, minimum=1, maximum=5000)
        assert not ok, "a draw over a different range passed under the same receipt"
        assert "max=100 was committed, 5000 was used" in why

    def test_a_different_number_of_winners_is_refused(self, operator):
        receipt = operator.commit("giveaway-7", count=1, minimum=1, maximum=100)
        pulse = operator.emit()
        ground = V.reproduce_integers(pulse["output"], "giveaway-7", 3, 1, 100)
        ok, why = V.check_draw(pulse, receipt, ground, operator.public_key_hex,
                               count=3, minimum=1, maximum=100)
        assert not ok and "count=1 was committed, 3 was used" in why

    def test_the_entry_list_is_pinned(self, operator):
        """Adding an entrant after naming the draw changes who can win."""
        entrants = [f"entrant_{i}" for i in range(50)]
        receipt = operator.commit("raffle", kind="shuffle", count=1, items=entrants)
        pulse = operator.emit()

        padded = entrants + ["the-organiser's-cousin"]
        ok, why = V.check_draw(pulse, receipt, V.reproduce_shuffle(pulse["output"], "raffle", padded),
                               operator.public_key_hex, kind="shuffle", items=padded, count=1)
        assert not ok, "the population was swapped under a valid receipt"
        assert "items_digest" in why

        honest = V.reproduce_shuffle(pulse["output"], "raffle", entrants)
        assert V.check_draw(pulse, receipt, honest, operator.public_key_hex,
                            kind="shuffle", items=entrants, count=1)[0]

    def test_the_shape_cannot_be_edited_after_signing(self, operator):
        receipt = operator.commit("giveaway-7", count=1, minimum=1, maximum=100)
        tampered = {**receipt, "draw": {**receipt["draw"], "max": 5000}}
        ok, why = V.check_commitment(tampered, operator.public_key_hex)
        assert not ok and "signature" in why


class TestMultiCommitmentGrinding:
    """Attack 7: register twenty draws in advance, publish the one that wins.

    Every receipt is honest. Each was signed before the deciding pulse existed, each
    names a real draw, each verifies on its own. The grinding happens in the choice of
    which one to show, and no amount of checking a single receipt can see it.
    """

    def _twenty(self, operator, committer="grinder"):
        receipts = [operator.commit(f"giveaway-8-plan-{i}", key_id=committer,
                                    count=1, minimum=1, maximum=100)
                    for i in range(20)]
        pulse = operator.emit()
        scored = sorted(
            ((V.reproduce_integers(pulse["output"], r["tag"], 1, 1, 100)[0], r)
             for r in receipts), key=lambda kv: kv[0])
        return pulse, receipts, scored[0]

    def test_every_individual_receipt_is_genuine(self, operator):
        """The premise. These are not forgeries and cannot be made to look like any."""
        _, receipts, _ = self._twenty(operator)
        for r in receipts:
            assert V.check_commitment(r, operator.public_key_hex)[0]
            assert r["created_after_round"] < r["target_round"]

    def test_the_published_list_catches_it(self, operator):
        """The authoritative answer: the operator's record of the whole round."""
        pulse, _, (winner_value, receipt) = self._twenty(operator)
        siblings = operator._store.commitments_for_round(pulse["round"])
        ok, why = V.check_draw(pulse, receipt, [winner_value], operator.public_key_hex,
                               count=1, minimum=1, maximum=100, siblings=siblings)
        assert not ok, "a ground-out draw passed with the sibling list in hand"
        assert "registered 20 draws" in why

    def test_the_sequence_number_catches_it_without_the_list(self, operator):
        """The offline fallback, and it is weaker on purpose."""
        pulse, _, (winner_value, receipt) = self._twenty(operator)
        if receipt["sequence"] == 1:
            pytest.skip("the winning plan happened to be the first; see the test below")
        ok, why = V.check_draw(pulse, receipt, [winner_value], operator.public_key_hex,
                               count=1, minimum=1, maximum=100)
        assert not ok and "draw number" in why

    def test_the_sequence_fallback_misses_a_lucky_grinder(self, operator):
        """Stated as a test so the limitation cannot be quietly forgotten.

        A grinder whose *first* plan happens to win holds a receipt reading sequence 1,
        which is indistinguishable from an honest single commitment. Only the
        published list closes that, which is why check_draw says which of the two it
        relied on.
        """
        receipts = [operator.commit(f"plan-{i}", key_id="lucky", count=1,
                                    minimum=1, maximum=100) for i in range(5)]
        pulse = operator.emit()
        first = receipts[0]
        value = V.reproduce_integers(pulse["output"], first["tag"], 1, 1, 100)[0]

        ok, why = V.check_draw(pulse, first, [value], operator.public_key_hex,
                               count=1, minimum=1, maximum=100)
        assert ok, "the fallback cannot see this, and the reason must admit it"
        assert "the receipt's own word" in why

        siblings = operator._store.commitments_for_round(pulse["round"])
        ok, why = V.check_draw(pulse, first, [value], operator.public_key_hex,
                               count=1, minimum=1, maximum=100, siblings=siblings)
        assert not ok and "registered 5 draws" in why

    def test_an_honest_single_commitment_still_passes(self, operator):
        receipt = operator.commit("just-the-one", key_id="honest",
                                 count=1, minimum=1, maximum=100)
        pulse = operator.emit()
        value = V.reproduce_integers(pulse["output"], "just-the-one", 1, 1, 100)[0]
        siblings = operator._store.commitments_for_round(pulse["round"])
        ok, why = V.check_draw(pulse, receipt, [value], operator.public_key_hex,
                               count=1, minimum=1, maximum=100, siblings=siblings)
        assert ok, why
        assert "only draw against that round" in why

    def test_a_truncated_sibling_list_is_refused(self, operator):
        """A runner cannot publish a list that omits their own receipt."""
        pulse, _, (value, receipt) = self._twenty(operator)
        ok, why = V.check_draw(pulse, receipt, [value], operator.public_key_hex,
                               count=1, minimum=1, maximum=100, siblings=[])
        assert not ok and "missing from the published list" in why


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


class TestCrossImplementationAgreement:
    """Four implementations of the same spec, pinned to one committed answer.

    The Python SDK, the JavaScript SDK, the demo page and the published draw record
    each reimplement the derivation from the spec rather than sharing code. That
    independence is the product's central claim, and it is also four chances to drift:
    a verifier that disagrees calls an honest draw forged, or an unfair one verified.
    """

    VECTORS = json.loads((ROOT / "tests" / "data" / "draw_vectors.json").read_text())

    def test_the_python_sdk_matches_the_vectors(self):
        out = self.VECTORS["pulse_output"]
        for draw in self.VECTORS["draws"]:
            kind, tag = draw["kind"], draw["tag"]
            if kind == "integers":
                got = V.reproduce_integers(out, tag, draw["count"], draw["min"], draw["max"])
            elif kind == "sample":
                got = V.reproduce_unique_integers(out, tag, draw["count"], draw["min"], draw["max"])
            elif kind == "shuffle":
                got = V.reproduce_shuffle(out, tag, draw["items"])
            elif kind == "bytes":
                got = V.reproduce_bytes(out, tag, draw["count"])
            else:
                pytest.fail(f"unknown kind {kind!r} in the vectors")
            assert got == draw["expected"], f"{kind} {tag!r} drifted"

    def test_the_vectors_cover_both_sampling_branches(self):
        """The threshold is the part that drifts silently, so it must stay covered.

        A verifier on the wrong side of span <= 4*count or span <= 4096 produces
        different winners from the same pulse and nothing looks wrong. If a future
        edit trims these vectors, this fails rather than the coverage quietly going.
        """
        samples = [d for d in self.VECTORS["draws"] if d["kind"] == "sample"]
        dense = [d for d in samples
                 if (d["max"] - d["min"] + 1) <= 4 * d["count"]
                 or (d["max"] - d["min"] + 1) <= 4096]
        sparse = [d for d in samples if d not in dense]
        assert dense, "no vector exercises the materialised-list branch"
        assert sparse, "no vector exercises the draw-and-reject branch"

        spans = {d["max"] - d["min"] + 1 for d in samples}
        assert {4096, 4097} <= spans, "the 4096/4097 boundary is no longer pinned"

    def test_the_server_agrees_with_the_vectors(self, operator):
        """The vectors are generated by the SDK; the server must land on them too."""
        from beamline import generators as gen

        out = self.VECTORS["pulse_output"]
        for draw in (d for d in self.VECTORS["draws"] if d["kind"] == "sample"):
            stream = V.DerivedStream(out, draw["tag"])
            server = gen.integers(stream, draw["count"], draw["min"], draw["max"],
                                  unique=True)
            assert server == draw["expected"], f"server disagrees on {draw['tag']!r}"

    def test_the_javascript_side_is_checked_too(self):
        """Delegated to the Node harness, which reads the same file."""
        node = subprocess.run(["node", str(ROOT / "scripts" / "check_js_verifiers.mjs")],
                              capture_output=True, text=True, cwd=ROOT)
        assert node.returncode == 0, node.stdout + node.stderr
        assert "reproduces sample" in node.stdout, (
            "the harness no longer checks draw reproduction:\n" + node.stdout)


class TestVerifyCommand:
    """`beamline verify` -- the verifier for people who do not write Python.

    The independent verifier has always been a library, which quietly assumed the
    sceptic is a programmer. The person who most needs to check a giveaway is the
    entrant who lost it, and telling them to import a module is telling them to trust
    the result.
    """

    @pytest.fixture
    def record(self, tmp_path):
        """The JSON a runner publishes, taken from the real draw page."""
        page = (ROOT / "examples" / "draw_page.html").read_text()
        blob = re.search(
            r'<script id="draw-data" type="application/json">(.*?)</script>',
            page, re.S).group(1)
        path = tmp_path / "record.json"
        path.write_text(blob)
        return path

    def _run(self, path, *extra):
        return subprocess.run(
            [sys.executable, "-m", "beamline.cli", "verify", "--draw", str(path), *extra],
            capture_output=True, text=True, cwd=ROOT,
            env={**os.environ, "PYTHONPATH": f"{ROOT}:{ROOT / 'sdk' / 'python'}"})

    def test_an_honest_record_verifies(self, record):
        out = self._run(record)
        assert out.returncode == 0, out.stdout + out.stderr
        assert "VERIFIED" in out.stdout

    def test_a_rigged_winner_is_refused(self, record, tmp_path):
        data = json.loads(record.read_text())
        data["winners"][0] = 4242
        rigged = tmp_path / "rigged.json"
        rigged.write_text(json.dumps(data))

        out = self._run(rigged)
        assert out.returncode == 1, "a rigged record exited zero"
        assert "NOT VERIFIED" in out.stdout
        assert "recomputed" in out.stdout

    def test_a_record_with_no_commitment_is_refused(self, record, tmp_path):
        """It reproduces. That was never the question."""
        data = json.loads(record.read_text())
        data.pop("commitment")
        path = tmp_path / "uncommitted.json"
        path.write_text(json.dumps(data))

        out = self._run(path)
        assert out.returncode == 1
        assert "nothing shows the draw was named before" in out.stdout

    def test_a_key_the_caller_did_not_expect_is_refused(self, record, tmp_path):
        out = self._run(record, "--public-key", "ab" * 32)
        assert out.returncode == 1
        assert "untrusted key" in out.stdout

    def test_json_output_is_machine_readable(self, record):
        out = self._run(record, "--json")
        parsed = json.loads(out.stdout)
        assert parsed["valid"] is True
        assert {c["name"] for c in parsed["checks"]} == {"pulse", "draw"}

    def test_it_says_when_the_sibling_list_is_missing(self, record):
        """A passing check that rests on the receipt's own word must say so."""
        out = self._run(record)
        assert "receipt's own sequence number" in out.stdout

    def test_a_missing_file_is_an_error_not_a_pass(self, tmp_path):
        out = self._run(tmp_path / "nope.json")
        assert out.returncode == 2, "a record that could not be read must not verify"
