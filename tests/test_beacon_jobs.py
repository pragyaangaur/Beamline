"""The scheduled beacon, and the rule that decides who wins.

The live challenge moved off a server we control and onto GitHub: a prediction is an
issue, a pulse is a commit, and the ordering between them is stamped by a third party.
That removed the operator's clock from the adjudication, which is the point -- but it
also means the fairness of the whole challenge now rests on one comparison, made in
`adjudicate`. These tests attack that comparison, and the chain-continuation logic that
decides which pulses a given key is entitled to extend.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


resolve = _load("resolve_predictions")
tick = _load("beacon_tick")

A = "a" * 128           # a stand-in published output
EMITTED = 1_700_000_000_000


def issue(created: str, body: str = A, number: int = 1) -> dict:
    return {"number": number, "created_at": created, "body": body,
            "user": {"login": "someone"}}


# --- the ordering rule ----------------------------------------------------

def test_a_guess_lodged_before_the_pulse_is_scored():
    call = resolve.adjudicate(issue("2023-11-14T22:13:00Z"), A, EMITTED)
    assert call["verdict"] == "early"
    assert call["correct"] is True
    assert call["prefix_bits"] == 512


def test_a_guess_lodged_after_the_pulse_is_not_scored_against_it():
    """The whole challenge. Copying a published value must not be scoreable.

    This is the case an operator would have no way to refuse if the timestamps were
    ours: the value is public, it matches exactly, and only the clock says otherwise.
    """
    late = issue("2023-11-14T22:14:00Z")           # a minute after EMITTED
    call = resolve.adjudicate(late, A, EMITTED)
    assert call["verdict"] == "late"
    assert "correct" not in call


def test_a_guess_lodged_in_the_same_millisecond_is_not_scored():
    """Ties go against the challenger, because the alternative cannot be checked.

    An issue stamped at exactly the emission moment cannot be shown to have preceded
    the value. Scoring it would mean asserting an ordering the public record does not
    establish.
    """
    exact = issue("2023-11-14T22:13:20Z")
    assert resolve.iso_to_ms(exact["created_at"]) == EMITTED
    assert resolve.adjudicate(exact, A, EMITTED)["verdict"] == "late"


def test_a_near_miss_is_scored_on_shared_bits_not_thrown_away():
    guess = "8" + "0" * 127        # 0b1000... vs 0b1010... -> 2 shared leading bits
    call = resolve.adjudicate(issue("2023-11-14T22:13:00Z", guess), A, EMITTED)
    assert call["verdict"] == "early"
    assert call["correct"] is False
    assert call["prefix_bits"] == 2


# --- reading the guess out of a human-written issue -----------------------

@pytest.mark.parametrize("body", [
    A,
    f"my guess is {A} thanks",
    f"0x{A}",
    f"### Your predicted output\n\n{A}\n\n### How\n\nguessed",
    A.upper(),
])
def test_a_prediction_is_found_however_the_issue_is_formatted(body):
    assert resolve.extract(body) == A


@pytest.mark.parametrize("body", ["", "no hex here", "a" * 127, "zz" * 64,
                                  "I predict it will be a big number"])
def test_an_issue_without_a_full_output_is_unreadable(body):
    assert resolve.extract(body) is None
    assert resolve.adjudicate(issue("2023-11-14T22:13:00Z", body), A,
                              EMITTED)["verdict"] == "unreadable"


def test_a_guess_is_case_folded_so_one_value_is_one_guess():
    """`ABC...` and `abc...` are the same prediction and must score identically."""
    upper = resolve.adjudicate(issue("2023-11-14T22:13:00Z", A.upper()), A, EMITTED)
    assert upper["correct"] is True


def test_an_over_long_hex_run_is_not_silently_truncated_into_a_guess():
    """129 hex characters is not a 128-character prediction with a typo.

    Accepting a prefix of it would let one issue be read as a value the author never
    wrote, which is the kind of ambiguity a disputed payout would turn on.
    """
    assert resolve.extract("f" * 129) is None


# --- which chain a key may continue ---------------------------------------

def test_a_new_key_starts_a_new_chain_rather_than_grafting_onto_the_old(tmp_path, monkeypatch):
    """An unendorsed key change mid-chain is the forgery `verify_chain` exists to catch.

    So the tick must not append pulses signed by a key the existing chain does not
    name. It starts over instead, which verifies cleanly from its own genesis.
    """
    chain = tmp_path / "chain.json"
    chain.write_text(json.dumps({"public_key": "old" * 21 + "a",
                                 "pulses": [{"round": 1, "output": A}]}))
    monkeypatch.setattr(tick, "CHAIN", chain)
    assert tick.load_chain("a different key") == []


def test_the_matching_key_continues_the_chain_it_signed(tmp_path, monkeypatch):
    chain = tmp_path / "chain.json"
    pulses = [{"round": 1, "output": A}]
    chain.write_text(json.dumps({"public_key": "kk", "pulses": pulses}))
    monkeypatch.setattr(tick, "CHAIN", chain)
    assert tick.load_chain("kk") == pulses


def test_a_corrupt_chain_file_does_not_stop_the_beacon(tmp_path, monkeypatch):
    """A truncated commit must not wedge the beacon into never publishing again.

    Silence is the one failure mode with no evidence in it: a stopped chain looks
    identical to a withheld round.
    """
    chain = tmp_path / "chain.json"
    chain.write_text("{not json")
    monkeypatch.setattr(tick, "CHAIN", chain)
    assert tick.load_chain("kk") == []


def test_a_missing_chain_file_is_a_genesis(tmp_path, monkeypatch):
    monkeypatch.setattr(tick, "CHAIN", tmp_path / "absent.json")
    assert tick.load_chain("kk") == []


# --- checking a published chain from the command line ---------------------

def _chain_file(tmp_path, pulses, key):
    f = tmp_path / "chain.json"
    f.write_text(json.dumps({"public_key": key, "pulses": pulses}))
    return f


@pytest.fixture(scope="module")
def signed_chain():
    """Two genuinely signed pulses, built the way the beacon builds them.

    The environment is restored afterwards. `CONFIG` is frozen at import time, so a
    leaked `BEAMLINE_DB` would not affect an already-imported module -- but it would
    quietly reroute anything imported later, and a test suite whose result depends on
    collection order is worse than a failing one.
    """
    import asyncio
    import os
    import tempfile

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    saved = {k: os.environ.get(k) for k in ("BEAMLINE_BEACON_KEY", "BEAMLINE_DB")}
    os.environ["BEAMLINE_BEACON_KEY"] = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    os.environ["BEAMLINE_DB"] = str(Path(tempfile.mkdtemp()) / "t.db")
    from beamline.service import BeamlineService

    async def build():
        svc = BeamlineService()
        await svc.start()
        for t in svc._tasks:
            if t.get_name() == "pulse":
                t.cancel()
        try:
            svc.beacon.emit()
            svc.beacon.emit()
            return svc.beacon.public_key_hex, svc.db.pulse_range(1, 2)
        finally:
            await svc.stop()

    try:
        yield asyncio.run(build())
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _verify(path, key=None):
    from beamline.cli import main
    argv = ["verify", "--chain", str(path)]
    if key:
        argv += ["--public-key", key]
    return main(argv)


def test_a_genuine_chain_verifies_from_the_command_line(tmp_path, signed_chain):
    key, pulses = signed_chain
    assert _verify(_chain_file(tmp_path, pulses, key)) == 0


def test_a_tampered_output_is_caught(tmp_path, signed_chain):
    key, pulses = signed_chain
    bad = [dict(pulses[0]), {**pulses[1], "output": "f" * 128}]
    assert _verify(_chain_file(tmp_path, bad, key)) == 1


def test_a_chain_checked_against_the_wrong_key_fails(tmp_path, signed_chain):
    key, pulses = signed_chain
    assert _verify(_chain_file(tmp_path, pulses, key), key="ab" * 32) == 1


def test_a_hole_in_the_chain_is_caught(tmp_path, signed_chain):
    """A missing round is how a withheld pulse would show up, so it must not pass."""
    key, pulses = signed_chain
    holed = [pulses[0], {**pulses[1], "round": 7}]
    assert _verify(_chain_file(tmp_path, holed, key)) == 1


def test_an_empty_or_unreadable_chain_is_an_error_not_a_pass(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"public_key": "kk", "pulses": []}))
    assert _verify(empty) == 2
    assert _verify(tmp_path / "does-not-exist.json") == 2
