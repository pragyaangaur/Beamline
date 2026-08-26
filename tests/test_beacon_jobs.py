"""The scheduled beacon, and the rule that decides who wins.

The live challenge moved off a server we control and onto GitHub: a prediction is an
issue, a pulse is a commit, and the ordering between them is stamped by a third party.
That removed the operator's clock from the adjudication, which is the point. It also
means the fairness of the whole challenge now rests on one comparison, made in
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
    leaked `BEAMLINE_DB` would not affect an already-imported module. It would quietly
    reroute anything imported later, and a test suite whose result depends on collection
    order is worse than a failing one.
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


# --- a tick must not lose a pulse it has already signed --------------------

def test_a_shutdown_failure_does_not_discard_the_pulse(tmp_path, monkeypatch):
    """Cleanup talks to the network, so it can fail after the pulse is signed.

    A source having a bad day is exactly the one likely to raise on the way out, and
    losing the tick to that would leave a stopped chain. A stopped chain and a
    withheld round look identical from outside, which is the one failure mode with no
    evidence in it.
    """
    import asyncio
    import os

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    saved = {k: os.environ.get(k) for k in ("BEAMLINE_BEACON_KEY", "BEAMLINE_DB")}
    os.environ["BEAMLINE_BEACON_KEY"] = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    monkeypatch.setattr(tick, "CHAIN", tmp_path / "chain.json")

    real_service = None

    async def run():
        nonlocal real_service
        from beamline.service import BeamlineService

        original = BeamlineService.stop

        async def exploding_stop(self):
            real_service = self
            await original(self)
            raise RuntimeError("a source blew up on the way out")

        monkeypatch.setattr(BeamlineService, "stop", exploding_stop)
        return await tick.tick(gather=0.1, period=600)

    try:
        bundle = asyncio.run(run())
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # The round number depends on whichever database this module's other tests left
    # behind, because CONFIG freezes BEAMLINE_DB at import time. What matters is that
    # a bundle came back at all, carrying the signed pulse the run had already emitted.
    assert bundle["pulses"], "the emitted pulse was lost to the shutdown failure"
    assert bundle["pulses"][-1]["round"] == bundle["latest_round"]
    assert bundle["pulses"][-1]["signature"]


# --- the published source summary --------------------------------------------

def _snap(name, ok=None, errors=0, err=None, archive=None, public=False):
    s = {"name": name, "public_data": public, "last_ok": ok,
         "last_error": err, "consecutive_errors": errors}
    if archive is not None:
        s["archive_empty"] = archive
        s["archive_blocks_remaining"] = 0 if archive else 40
    return s


def test_the_live_quantum_source_and_the_local_archive_are_told_apart():
    """Both answer to `anu_qrng`, and the published record has to distinguish them.

    This file is the evidence behind a public claim about where the randomness comes
    from. A reader must be able to tell "the quantum endpoint answered" from "the
    local cache had nothing spare".
    """
    live = tick._source_state(_snap("anu_qrng", ok=1e9))
    arch = tick._source_state(_snap("anu_qrng", archive=True))
    assert live["role"] == "live" and arch["role"] == "archive"
    assert live["state"] == "ok"


def test_an_empty_archive_is_idle_rather_than_failing():
    """A cold runner has nothing cached yet, and that is not a fault.

    Reporting it as a failure was the bug: it made a working quantum endpoint look
    broken in the published chain for three consecutive rounds.
    """
    s = tick._source_state(_snap("anu_qrng", archive=True))
    assert s["state"] == "idle"
    assert s["last_error"] is None
    assert s["blocks_remaining"] == 0


def test_a_source_that_raised_is_reported_as_failing_with_its_reason():
    s = tick._source_state(_snap("anu_qrng", errors=3, err="HTTP 429"))
    assert s["state"] == "failing"
    assert s["last_error"] == "HTTP 429"


def test_a_stocked_archive_that_has_served_is_ok_and_reports_what_is_left():
    s = tick._source_state(_snap("anu_qrng", ok=1e9, archive=False))
    assert s["state"] == "ok"
    assert s["blocks_remaining"] == 40


def test_public_data_sources_stay_marked_as_public():
    """NOAA contributes zero secret entropy, and the record must keep saying so."""
    assert tick._source_state(_snap("astro", ok=1e9, public=True))["public_data"] is True


# --- recognising a guess when the label is missing -------------------------

def _issue(title="prediction: round 9", labels=(), body=A):
    return {"number": 1, "created_at": "2023-11-14T22:13:00Z", "body": body,
            "title": title, "user": {"login": "someone"},
            "labels": [{"name": n} for n in labels]}


def test_a_labelled_issue_is_a_prediction():
    assert resolve.is_prediction(_issue(labels=["prediction"]))


def test_an_unlabelled_issue_from_the_form_is_still_a_prediction():
    """The label did not exist in the repository until it was created.

    GitHub silently drops a label an issue form names but the repository lacks, so
    early guesses carry no label through no fault of the person who lodged them.
    Scoring only labelled issues would have quietly ignored every one of them.
    """
    assert resolve.is_prediction(_issue(labels=[]))


def test_the_title_check_is_not_case_sensitive():
    assert resolve.is_prediction(_issue(title="Prediction: round 9"))


def test_an_ordinary_issue_is_not_a_prediction():
    assert not resolve.is_prediction(_issue(title="Bug: verifier crashes", labels=[]))


def test_a_bug_report_quoting_a_pulse_is_not_swept_up_as_a_guess():
    """Matching on "contains 128 hex characters" would auto-close it as a loss.

    Being closed as a losing guess is a poor reward for reporting a bug, and the
    report would be buried under a verdict nobody asked for.
    """
    quoted = _issue(title="Bug: round 12 fails to verify", labels=[],
                    body=f"the output was {A} and check_chain rejects it")
    assert not resolve.is_prediction(quoted)


def test_every_label_the_challenge_writes_is_declared_for_creation():
    """Anything applied later must be creatable, or it is dropped just as silently."""
    written = {"prediction", "resolved", "unreadable"}
    assert written <= set(resolve.LABELS)
    for name, (colour, description) in resolve.LABELS.items():
        assert len(colour) == 6 and int(colour, 16) >= 0, name
        assert description


def test_the_per_run_cap_is_smaller_than_the_hourly_api_budget():
    """Scoring costs two API calls each, against 5000 an hour.

    Somebody scripting thousands of guesses must not be able to exhaust that, because
    the people it takes scoring away from are the ones who lodged an honest guess.
    """
    assert resolve.MAX_PER_RUN * 2 < 5000


def _scored(handle: str, bits: int, issue_no: int, round_no: int) -> dict:
    return {"handle": handle, "issue": issue_no, "round": round_no,
            "predicted": A, "prefix_bits": bits, "correct": False}


def test_the_leaderboard_counts_every_attempt_not_just_the_ones_after_the_best():
    """A better score must not wipe out the count of the tries that preceded it.

    `attempts` used to live on the best-score entry, so replacing that entry threw the
    counter away. The board credited this challenger with one attempt out of three, and
    the one it kept was the hit. Losing attempts are the thing the challenge asks people
    to accumulate, so undercounting them is not a cosmetic error.
    """
    # Newest first, as `recent` is stored. The best score is the OLDEST entry, which is
    # the ordering that triggered the bug.
    recent = [_scored("alice", 5, 3, 10),
              _scored("alice", 2, 2, 9),
              _scored("alice", 9, 1, 8)]

    (row,) = resolve.build_leaderboard(recent)
    assert row["attempts"] == 3
    assert row["best_prefix_bits"] == 9
    # And it points at the attempt that actually earned the score.
    assert (row["issue"], row["round"]) == (1, 8)


def test_the_leaderboard_ranks_by_best_score_and_keeps_challengers_separate():
    recent = [_scored("alice", 4, 1, 9), _scored("bob", 7, 2, 9),
              _scored("bob", 1, 3, 8)]
    board = resolve.build_leaderboard(recent)
    assert [r["handle"] for r in board] == ["bob", "alice"]
    assert {r["handle"]: r["attempts"] for r in board} == {"bob": 2, "alice": 1}


def test_the_leaderboard_is_bounded():
    recent = [_scored(f"user{i}", i, i, 1) for i in range(resolve.LEADERBOARD + 15)]
    assert len(resolve.build_leaderboard(recent)) == resolve.LEADERBOARD


def test_an_empty_board_is_a_leaderboard_not_a_crash():
    assert resolve.build_leaderboard([]) == []


def _bundle(rounds: list[int], latest: int | None = None) -> dict:
    pulses = [{"round": r, "output": A, "timestamp_ms": EMITTED + r} for r in rounds]
    return {"pulses": pulses,
            "latest_round": rounds[-1] if latest is None else latest}


def test_the_deciding_pulse_is_the_highest_round_not_the_last_line():
    """Scoring must not depend on the file happening to be sorted.

    `pulses[-1]` was correct only because a SQL ORDER BY elsewhere kept it so. This
    value decides who wins a prize, and the identical assumption about the NOAA feed
    shipped and had to be fixed in production, where the last row is a day old.
    """
    out_of_order = _bundle([7, 9, 8], latest=9)
    assert resolve.latest_pulse(out_of_order)["round"] == 9


def test_a_chain_file_that_contradicts_itself_scores_nobody():
    """Two readings of "newest" that disagree means the file is wrong, not that one
    of them should be picked. Resolving against the wrong value would close honest
    predictions against a number the beacon may never have published."""
    with pytest.raises(SystemExit):
        resolve.latest_pulse(_bundle([7, 8, 9], latest=11))


def test_an_empty_chain_is_refused_rather_than_indexed():
    with pytest.raises(SystemExit):
        resolve.latest_pulse({"pulses": [], "latest_round": 0})


def test_the_real_published_chain_reads_cleanly():
    """The live file, exactly as the beacon writes it."""
    bundle = json.loads((ROOT / "beacon" / "chain.json").read_text())
    assert resolve.latest_pulse(bundle)["round"] == bundle["latest_round"]


# --- the guess must still be a secret when it is scored ---------------------
#
# `created_at` is GitHub's and cannot be forged, so the ordering half of the rule is
# safe. The guess is not: `adjudicate` reads it out of the issue BODY at scoring time,
# and an author can edit a body whenever they like. Lodge a placeholder early, wait for
# the answer, paste it in, and adjudicate sees an untouched early timestamp beside a
# perfect guess -- verified against a real published pulse at 512 of 512 bits.
#
# The only thing that ever stopped it was the workflow scoring before it pushes. That
# invariant was asserted nowhere and tested nowhere, and this module's own usage line
# violates it: run standalone against a checkout, the newest pulse in the file is
# already public.

def test_editing_the_body_after_publication_would_win_if_the_answer_were_public():
    """The attack itself, so the guard below is protecting something demonstrable."""
    actual = "5c" * 64
    lodged = "2026-08-26T00:00:00Z"
    emitted = resolve.iso_to_ms("2026-08-26T04:00:00Z")   # an hour later

    placeholder = issue(lodged, body="00" * 64)
    assert resolve.adjudicate(placeholder, actual, emitted)["correct"] is False

    edited = issue(lodged, body=actual)      # same created_at, new body
    call = resolve.adjudicate(edited, actual, emitted)
    assert call["verdict"] == "early" and call["correct"] is True
    assert call["prefix_bits"] == 512


def test_scoring_refuses_a_pulse_the_world_can_already_read(monkeypatch):
    monkeypatch.setattr(resolve, "published_round", lambda: 81)
    with pytest.raises(SystemExit, match="already published"):
        resolve.check_target_is_unpublished(81)
    with pytest.raises(SystemExit, match="already published"):
        resolve.check_target_is_unpublished(80)


def test_scoring_proceeds_for_the_round_that_has_not_been_pushed_yet(monkeypatch):
    """What the workflow actually does: emit N+1, score it, then publish it."""
    monkeypatch.setattr(resolve, "published_round", lambda: 81)
    resolve.check_target_is_unpublished(82)     # must not raise


def test_an_undeterminable_publication_state_fails_closed(monkeypatch):
    """A skipped round costs nothing -- the issues stay open and the next pulse takes
    them, which is what already happens when scoring fails. Guessing costs the prize."""
    monkeypatch.setattr(resolve, "published_round", lambda: None)
    with pytest.raises(SystemExit, match="cannot tell"):
        resolve.check_target_is_unpublished(82)


def test_published_round_reads_the_committed_chain():
    """Against this repository's real origin/main."""
    seen = resolve.published_round()
    assert seen is None or isinstance(seen, int)


def _labelled(*names: str) -> dict:
    got = issue("2026-08-26T00:00:00Z")
    got["labels"] = [{"name": n} for n in names]
    return got


@pytest.mark.parametrize("label", ["resolved", "unreadable"])
def test_a_reopened_issue_is_not_scored_a_second_time(label):
    """Scoring closes and labels an issue. Nothing stops the author reopening it.

    Nothing here used to look, so a reopened issue went back through scoring as if it
    were new -- and kept its original `created_at` forever, so it was permanently
    "early". One issue lodged once became an unlimited supply of attempts, each landing
    in the attempt count, the leaderboard, and the running mean the README offers as a
    public bias test for the beacon.
    """
    assert resolve.already_scored(_labelled("prediction", label))


def test_a_fresh_prediction_is_still_scored():
    assert not resolve.already_scored(_labelled("prediction"))
    assert not resolve.already_scored(issue("2026-08-26T00:00:00Z"))


def test_every_settled_label_is_one_the_scorer_actually_applies():
    """If a label were renamed in LABELS but not here, reopening would work again."""
    assert resolve.SETTLED <= set(resolve.LABELS)


# --- the second-vs-millisecond boundary ------------------------------------
#
# Pulses carry millisecond timestamps; GitHub stamps issues to the second. Comparing
# them directly understated creation by up to 999ms, so an issue created after a pulse
# could be scored as though it had been lodged first.

def test_an_issue_stamped_in_the_same_second_as_the_pulse_waits_for_the_next_round():
    """04:50:04.900 is after a pulse emitted at 04:50:04.212, but GitHub reports
    04:50:04Z. Scored on the start of that second it read as early."""
    emitted = resolve.iso_to_ms("2026-08-26T04:50:04Z") + 212
    same_second = issue("2026-08-26T04:50:04Z")
    assert resolve.adjudicate(same_second, A, emitted)["verdict"] == "late"


def test_an_issue_from_the_previous_second_is_still_scored():
    """The fix must cost exactly one second of caution, not a whole round."""
    emitted = resolve.iso_to_ms("2026-08-26T04:50:04Z") + 212
    earlier = issue("2026-08-26T04:50:03Z")
    assert resolve.adjudicate(earlier, A, emitted)["verdict"] == "early"


def test_the_ambiguous_second_resolves_against_the_challenger_never_for_them():
    """Across every millisecond offset a pulse can land on within one second, an issue
    stamped in that same second is never credited as early."""
    base = resolve.iso_to_ms("2026-08-26T04:50:04Z")
    same_second = issue("2026-08-26T04:50:04Z")
    for offset in range(0, 1000, 7):
        assert resolve.adjudicate(same_second, A, base + offset)["verdict"] == "late"


def test_a_guess_refused_on_the_boundary_is_not_thrown_away():
    """It waits, like every late guess. The next pulse is ten minutes later."""
    base = resolve.iso_to_ms("2026-08-26T04:50:04Z")
    same_second = issue("2026-08-26T04:50:04Z")
    assert resolve.adjudicate(same_second, A, base + 500)["verdict"] == "late"
    next_pulse = base + 600_000
    assert resolve.adjudicate(same_second, A, next_pulse)["verdict"] == "early"


# --- listing must not walk around the per-run cap ---------------------------

class _FakeGitHub:
    """Stands in for `gh`, counting the API calls a listing costs."""

    def __init__(self, n_open: int):
        self.pages = [[{"number": i, "title": "prediction: x",
                        "labels": [{"name": "prediction"}],
                        "created_at": "2026-08-26T00:00:00Z",
                        "user": {"login": "flooder"}, "body": A}
                       for i in range(p, min(p + 100, n_open))]
                      for p in range(0, max(n_open, 1), 100)]
        self.calls = 0

    def __call__(self, path, method="GET", body=None):
        self.calls += 1
        # "&page=" with the ampersand: splitting on "page=" also matches "per_page=".
        page = int(path.split("&page=")[1].split("&")[0])
        return self.pages[page - 1] if page - 1 < len(self.pages) else []


def test_listing_is_bounded_so_a_flood_cannot_exhaust_the_api_budget(monkeypatch):
    """MAX_PER_RUN caps SCORING at two calls each. Listing walked every open issue at
    one call per hundred, so a big enough flood burned the hourly budget on the listing
    alone, `gh` raised on the 403, and scoring stopped for everybody -- including the
    honest guesses the cap was written to protect.
    """
    fake = _FakeGitHub(n_open=50_000)          # 500 pages if walked to the end
    monkeypatch.setattr(resolve, "gh", fake)

    issues, complete = resolve.open_predictions("o/r", limit=resolve.MAX_PER_RUN * 3)

    assert not complete, "a truncated listing must say so"
    assert fake.calls <= resolve.MAX_LIST_PAGES
    assert len(issues) >= resolve.MAX_PER_RUN, "still enough to fill a run's scoring"


def test_a_normal_number_of_predictions_is_listed_completely(monkeypatch):
    fake = _FakeGitHub(n_open=37)
    monkeypatch.setattr(resolve, "gh", fake)
    issues, complete = resolve.open_predictions("o/r", limit=resolve.MAX_PER_RUN * 3)
    assert complete and len(issues) == 37


def test_an_empty_repository_lists_cleanly(monkeypatch):
    monkeypatch.setattr(resolve, "gh", _FakeGitHub(n_open=0))
    assert resolve.open_predictions("o/r", limit=10) == ([], True)


def test_the_listing_ceiling_leaves_room_for_a_full_run_of_scoring():
    assert resolve.MAX_LIST_PAGES * 100 > resolve.MAX_PER_RUN
