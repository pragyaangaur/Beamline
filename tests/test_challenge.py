"""The prediction challenge: receipts, refusals, resolution, and the bias statistic.

The properties worth defending here are adversarial ones. A challenger has to be able
to show they predicted rather than copied, and the operator has to be unable to score
a round twice or quietly drop an attempt. Most of these tests are written from the
challenger's side, because the operator is the one who would benefit from a bug.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from beamline import config as config_module
from beamline.api.app import app
from beamline.challenge import (ChallengeRegistry, normalise_output, prefix_bits,
                                verify_prediction)
from beamline.config import CONFIG
from beamline.db import Database
from beamline.entropy.beacon import Beacon
from beamline.entropy.drbg import HmacDrbg
from beamline.entropy.pool import EntropyPool
from beamline.ratelimit import RateLimiter
from beamline.service import SERVICE

SIGNING_KEY = os.urandom(32).hex()
MISS = "ab" * 64


@pytest.fixture
def client(monkeypatch):
    tmp = tempfile.TemporaryDirectory()
    monkeypatch.setattr(config_module, "CONFIG", replace(CONFIG, challenge_enabled=True))

    SERVICE.db = Database(Path(tmp.name) / "test.db")
    SERVICE.pool = EntropyPool()
    SERVICE.pool.add("local_os", os.urandom(256))
    SERVICE.drbg = HmacDrbg(SERVICE.pool.extract(64))
    SERVICE.beacon = Beacon(SERVICE.db, SERVICE.pool, period_seconds=60,
                            signing_key_hex=SIGNING_KEY)
    SERVICE.limiter = RateLimiter()
    SERVICE.challenge = ChallengeRegistry(SERVICE.db, SERVICE.beacon)
    SERVICE.beacon.emit()

    yield TestClient(app)
    tmp.cleanup()


def lodge(client, output=MISS, **kw):
    return client.post("/v1/challenge/predict", json={"predicted_output": output, **kw})


# --- input handling ---------------------------------------------------------
def test_output_must_be_a_full_512_bit_value():
    for bad in ["", "abc", "zz" * 64, "ab" * 63]:
        with pytest.raises(ValueError):
            normalise_output(bad)


def test_case_and_0x_prefix_are_folded_so_one_guess_is_one_entry():
    assert normalise_output("0x" + "AB" * 64) == MISS


def test_prefix_bits_counts_shared_leading_bits():
    assert prefix_bits("00" * 64, "00" * 64) == 512
    assert prefix_bits("00" * 64, "80" + "00" * 63) == 0
    assert prefix_bits("00" * 64, "40" + "00" * 63) == 1
    assert prefix_bits("00" * 64, "01" + "00" * 63) == 7


# --- the load-bearing refusal ----------------------------------------------
def test_a_published_round_cannot_be_predicted(client):
    """The whole mechanism. Copying a published output must not produce a receipt."""
    published = client.get("/v1/beacon/latest").json()
    r = lodge(client, published["output"], target_round=published["round"])
    assert r.status_code == 409
    assert "already been published" in r.json()["detail"]


def test_receipt_records_the_round_the_chain_had_reached(client):
    r = lodge(client)
    assert r.status_code == 201
    body = r.json()
    assert body["received_after_round"] == 1
    assert body["target_round"] == 2
    assert body["received_after_round"] < body["target_round"]


def test_receipt_verifies_against_the_beacon_key(client):
    receipt = lodge(client).json()
    ok, reason = verify_prediction(receipt, SERVICE.beacon.public_key_hex)
    assert ok, reason


def test_a_backdated_receipt_is_rejected_by_the_verifier():
    """A receipt whose target had already landed is not evidence, however well signed."""
    forged = {"version": "beamline/prediction/v1", "prediction_id": "x" * 32,
              "target_round": 5, "predicted_output": MISS, "handle": "",
              "received_at_ms": 0, "received_after_round": 9, "public_key": None,
              "signature": None}
    ok, reason = verify_prediction(forged, allow_unsigned=True)
    assert not ok
    assert "already been published" in reason


def test_tampering_with_the_predicted_value_breaks_the_signature(client):
    receipt = lodge(client).json()
    receipt["predicted_output"] = "cd" * 64
    ok, reason = verify_prediction(receipt, SERVICE.beacon.public_key_hex)
    assert not ok
    assert "signature" in reason


# --- resolution -------------------------------------------------------------
def test_a_losing_prediction_resolves_and_keeps_its_prefix_score(client):
    pid = lodge(client).json()["prediction_id"]
    pulse = SERVICE.beacon.emit()
    SERVICE.challenge.resolve_due(pulse["round"])

    record = client.get(f"/v1/challenge/prediction/{pid}").json()
    assert record["resolved"] is True
    assert record["correct"] is False
    assert record["actual_output"] == pulse["output"]
    assert record["prefix_bits"] == prefix_bits(MISS, pulse["output"])


def test_a_winning_prediction_is_recorded_as_a_win(client):
    """Contrived: the only way to test the payout path is to know the answer."""
    receipt = SERVICE.challenge.predict(MISS, 2)
    pulse = SERVICE.beacon.emit()
    # Rewrite the stored pulse so the prediction matches, then score against it.
    SERVICE.db._conn().execute("UPDATE pulses SET output = ? WHERE round = ?",
                               (MISS, pulse["round"])).connection.commit()
    SERVICE.db._conn().execute(
        "UPDATE pulses SET body = json_set(body, '$.output', ?) WHERE round = ?",
        (MISS, pulse["round"])).connection.commit()

    outcome = SERVICE.challenge.resolve_round(2)
    assert outcome["winners"] == [receipt["prediction_id"]]
    assert SERVICE.challenge.get(receipt["prediction_id"])["correct"] is True


def test_resolution_is_write_once(client):
    """A resolved row must never be re-scored: that is how a win would be erased."""
    pid = lodge(client).json()["prediction_id"]
    SERVICE.beacon.emit()
    SERVICE.challenge.resolve_due(2)
    first = SERVICE.challenge.get(pid)

    SERVICE.db.resolve_prediction(pid, "ff" * 64, 0, False)
    assert SERVICE.challenge.get(pid)["actual_output"] == first["actual_output"]


def test_unscored_rounds_are_caught_up_after_a_restart(client):
    """A prediction left unresolved by a crash must not stay unresolved forever."""
    pid = lodge(client, target_round=2).json()["prediction_id"]
    SERVICE.beacon.emit()   # round 2 lands, but nothing resolves it
    SERVICE.beacon.emit()   # round 3
    assert SERVICE.challenge.get(pid)["resolved"] is False

    SERVICE.challenge.resolve_due(3)
    assert SERVICE.challenge.get(pid)["resolved"] is True


# --- public record ----------------------------------------------------------
def test_every_attempt_against_a_round_is_listed(client):
    lodge(client, "11" * 64, handle="alice")
    lodge(client, "22" * 64, handle="bob")
    listing = client.get("/v1/challenge/round/2").json()
    assert listing["count"] == 2
    assert {p["handle"] for p in listing["predictions"]} == {"alice", "bob"}


def test_scoreboard_reports_the_bias_statistic_against_its_expectation(client):
    for i in range(3):
        lodge(client, f"{i:02x}" * 64)
    SERVICE.beacon.emit()
    SERVICE.challenge.resolve_due(2)

    board = client.get("/v1/challenge/scoreboard").json()
    assert board["predictions_resolved"] == 3
    assert board["exact_hits"] == 0
    assert board["expected_mean_prefix_bits"] == 1.0
    assert board["mean_prefix_bits"] is not None


def test_scoreboard_says_nothing_about_bias_before_it_can(client):
    board = client.get("/v1/challenge/scoreboard").json()
    assert board["mean_prefix_bits"] is None
    assert "nothing to say" in board["bias_note"]


# --- limits -----------------------------------------------------------------
def test_per_round_cap_is_enforced_per_origin(client, monkeypatch):
    monkeypatch.setattr(config_module, "CONFIG",
                        replace(CONFIG, challenge_enabled=True, challenge_max_per_round=2))
    assert lodge(client, "11" * 64).status_code == 201
    assert lodge(client, "22" * 64).status_code == 201
    r = lodge(client, "33" * 64)
    assert r.status_code == 429
    assert "per-round limit" in r.json()["detail"]


def test_far_future_rounds_are_refused(client):
    r = lodge(client, target_round=100_000)
    assert r.status_code == 400
    assert "rounds away" in r.json()["detail"]


def test_rules_state_the_prize_and_the_known_reroll_gap(client):
    rules = client.get("/v1/challenge/rules").json()
    assert rules["prize"]
    assert "withhold" in rules["what_stops_the_operator_cheating"]
    assert rules["open_now"]["open_round"] == 2


def test_challenge_can_be_switched_off(client, monkeypatch):
    monkeypatch.setattr(config_module, "CONFIG",
                        replace(CONFIG, challenge_enabled=False))
    assert lodge(client).status_code == 503
