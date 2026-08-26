"""Score every prediction that was lodged before the latest pulse existed.

A prediction is a GitHub issue. It answers the only hard problem the challenge has,
which is proving the order of two events to somebody who has no reason to trust us.
Lacking a server did not force this.

The old design had Beamline's own API stamp each guess with "received at time T, chain
standing at round N" and sign it. Every part of that is the operator's word: our clock,
our ordering, our option to lose an inconvenient receipt. A challenger who won would be
appealing to the honesty of the person the win embarrasses.

Here, both sides of the comparison are timestamped by GitHub:

  * the guess is an issue, with a `created_at` we cannot backdate;
  * the pulse is a commit from a public Actions run, with a log we cannot rewrite.

So the rule this script enforces, which is to score an issue against a pulse only if
the issue was created before that pulse's timestamp, is checkable by anyone against records
held by a third party who does not care who wins. An issue that arrives after a pulse
is not scored against it; it stays open and waits for the next one, which is the same
rule the API's `received_after_round` check enforced, moved somewhere it can be audited.

    GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo python scripts/resolve_predictions.py

Nothing here can change the pulse: `beacon_tick.py` has already written and signed it
before this runs. The scoring is string equality, and every input to it is public.

ORDERING IS LOAD-BEARING, and this file used to describe it backwards. Scoring happens
BEFORE the pulse is pushed, not after. That is not a detail of the workflow, it is the
reason the challenge works at all:

    beacon_tick.py   emits round N+1 into beacon/chain.json  (local, not yet public)
    THIS SCRIPT      scores every open issue against round N+1
    publish          pushes round N+1, making it public

An issue's `created_at` is fixed by GitHub, but its BODY is not: the author can edit it
at any time, and this script reads the guess out of the body when it scores. So the only
thing stopping somebody lodging a placeholder, waiting for the answer, and editing it in
is that the answer is not public yet when the scoring runs. `check_target_is_unpublished`
enforces exactly that, out loud, instead of leaving the whole challenge resting on the
order of two lines in a shell script.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from beamline.challenge import prefix_bits  # noqa: E402

CHAIN = ROOT / "beacon" / "chain.json"
BOARD = ROOT / "beacon" / "predictions.json"

LABEL = "prediction"
API = "https://api.github.com"

#: A predicted output anywhere in the issue body. Issue forms are markdown, so the
#: value arrives surrounded by headings and whitespace rather than as clean JSON.
HEX_128 = re.compile(r"\b(?:0x)?([0-9a-fA-F]{128})\b")

#: Kept in the served file. The full history is in this file's git log.
RECENT = 50

#: Most predictions scored in a single run. Each one costs two API calls, a comment and
#: a close, against a budget of 5000 an hour. Somebody scripting thousands of guesses
#: would otherwise exhaust that and take the scoring down for everybody, which punishes
#: the people who lodged an honest guess rather than the person flooding it.
#:
#: Anything over the cap keeps its place: issues are processed oldest first and the
#: remainder stay open for the next run, so a backlog drains in order rather than
#: being dropped.
MAX_PER_RUN = 100


def gh(path: str, method: str = "GET", body: dict | None = None) -> object:
    token = os.environ["GITHUB_TOKEN"]
    req = urllib.request.Request(
        path if path.startswith("http") else f"{API}{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "beamline-beacon",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"null")


#: `created_at` is stamped to the second, so it names a one-second interval rather than
#: an instant. The true creation time is somewhere in [t, t+1000).
CREATED_AT_RESOLUTION_MS = 1000


def iso_to_ms(stamp: str) -> int:
    """GitHub's `created_at`, which is always UTC with a trailing Z.

    This is the START of the second the issue was created in, not the moment.
    """
    from datetime import datetime, timezone
    return int(datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=timezone.utc).timestamp() * 1000)


def created_no_later_than(stamp: str) -> int:
    """The latest instant an issue stamped `stamp` could actually have been created.

    Pulses carry millisecond timestamps; GitHub stamps issues to the second. Comparing
    the two directly understated the creation time by up to 999ms, so an issue created
    at 04:50:04.900 -- after a pulse emitted at 04:50:04.212 -- reported 04:50:04.000
    and was scored as though it had been lodged first.

    Taking the end of the interval resolves that against the challenger, which is the
    right direction: a guess that might have been lodged after the answer existed is
    not scored against that round. It is not refused either. It stays open and the next
    pulse takes it, ten minutes later, exactly like every guess that arrives late.
    """
    return iso_to_ms(stamp) + CREATED_AT_RESOLUTION_MS - 1


#: Created if absent on every run. The issue form declares `labels: [prediction]`, and
#: GitHub silently drops a label that does not exist in the repository. That failure is
#: invisible from the challenger's side: their issue is created, looks lodged, and is
#: never seen again by anything that scores it.
LABELS = {
    LABEL: ("1D76DB", "A guess at a future pulse, awaiting the round it names"),
    "resolved": ("0E8A16", "Scored against the pulse it predicted"),
    "unreadable": ("BFD4F2", "No 512-bit value could be found in the issue"),
}


def ensure_labels(repo: str) -> None:
    """Make sure the labels this challenge depends on exist. Idempotent."""
    try:
        existing = {l["name"] for l in gh(f"/repos/{repo}/labels?per_page=100")}
    except Exception as e:
        print(f"could not list labels ({e}); continuing", file=sys.stderr)
        return
    for name, (colour, description) in LABELS.items():
        if name in existing:
            continue
        try:
            gh(f"/repos/{repo}/labels", "POST",
               {"name": name, "color": colour, "description": description})
            print(f"created missing label {name!r}", file=sys.stderr)
        except Exception as e:
            print(f"could not create label {name!r}: {e}", file=sys.stderr)


def is_prediction(issue: dict) -> bool:
    """Is this issue a guess?

    The label is the intended marker, and the title prefix is the backstop. An issue
    opened while the label was missing from the repository carries no label and would
    otherwise never be scored, through no fault of the person who opened it. The
    template sets both, so either alone is enough to recognise one.

    Deliberately not "any issue containing 128 hex characters": a bug report quoting a
    pulse output would match that, and being auto-closed as a losing guess is a poor
    reward for reporting a bug.
    """
    if LABEL in {l["name"] for l in issue.get("labels", [])}:
        return True
    return (issue.get("title") or "").strip().lower().startswith("prediction:")


#: Applied when an issue has been through scoring. Seeing one on an OPEN issue means
#: it was reopened after the fact.
SETTLED = {"resolved", "unreadable"}


def already_scored(issue: dict) -> bool:
    """Has this issue already had its verdict?

    Scoring closes an issue and labels it. Nothing stops the author reopening it, and
    nothing here used to look, so a reopened issue went back through scoring as though
    it were new -- keeping its original `created_at` forever. One issue lodged once
    became an unlimited supply of attempts that are permanently "early", each one
    landing in the attempt count, the leaderboard, and the running mean the README
    offers as a public test for bias in the beacon.
    """
    return bool({l["name"] for l in issue.get("labels", [])} & SETTLED)


#: Hard ceiling on pages walked while listing. `MAX_PER_RUN` bounds how many issues are
#: SCORED, at two API calls each, and was written against somebody scripting thousands
#: of guesses. Listing walked every open issue regardless, one call per hundred, so the
#: exhaustion the cap exists to prevent was reachable straight around it: enough open
#: issues and the listing alone burns the hourly budget, `gh` raises on the 403, and
#: scoring stops for everybody -- including the honest guesses the cap was protecting.
#:
#: Ten pages is a thousand issues, well past a run's scoring capacity, so under any
#: normal load every prediction is still seen.
MAX_LIST_PAGES = 10


def open_predictions(repo: str, limit: int | None = None) -> tuple[list[dict], bool]:
    """Open predictions, oldest first. Returns (issues, complete).

    `complete` is False when the listing was cut short, which makes any count derived
    from it a lower bound rather than a total. Said out loud because the alternative is
    a scoreboard that quietly under-reports during exactly the flood it was built to
    survive.
    """
    issues: list[dict] = []
    for page in range(1, MAX_LIST_PAGES + 1):
        batch = gh(f"/repos/{repo}/issues?state=open"
                   f"&per_page=100&page={page}&sort=created&direction=asc")
        if not batch:
            return issues, True
        # The issues endpoint returns pull requests too; they are not predictions.
        issues += [i for i in batch
                   if "pull_request" not in i and is_prediction(i)]
        if len(batch) < 100:
            return issues, True
        # Sorted oldest first, and only `limit` of them can be scored this run, so the
        # rest would be re-listed next round anyway.
        if limit is not None and len(issues) >= limit:
            return issues, False
    return issues, False


def extract(body: str) -> str | None:
    m = HEX_128.search(body or "")
    return m.group(1).lower() if m else None


def adjudicate(issue: dict, actual: str, emitted_ms: int) -> dict:
    """Decide what a single issue gets, without touching the network.

    Returns a verdict of `"early"` (lodged before the pulse existed, so it is scored),
    `"late"` (arrived once the answer was public, so it is left open for the next round), or
    `"unreadable"` (no 512-bit value in it).

    This is a pure function on purpose. It is the only place the challenge's fairness
    actually lives, so it has to be testable without a GitHub token, a network, or a
    running beacon.
    """
    created_ms = iso_to_ms(issue["created_at"])

    # The load-bearing check. An issue opened after the pulse was emitted has had the
    # answer available to read.
    #
    # Compared at the END of the second GitHub stamped, because that stamp is an
    # interval and this is the one comparison the whole challenge rests on. Using its
    # start credited an issue created up to 999ms AFTER the pulse as having been lodged
    # first. Ambiguity here resolves against the challenger and costs them one round.
    if created_no_later_than(issue["created_at"]) >= emitted_ms:
        return {"verdict": "late", "created_ms": created_ms}

    guess = extract(issue.get("body") or "")
    if guess is None:
        return {"verdict": "unreadable", "created_ms": created_ms}

    return {"verdict": "early", "created_ms": created_ms, "guess": guess,
            "prefix_bits": prefix_bits(guess, actual), "correct": guess == actual}


#: Places on the published leaderboard.
LEADERBOARD = 20


def build_leaderboard(recent: list[dict]) -> list[dict]:
    """Best-ever score per challenger, plus how many tries it took them.

    Pure, and separate from `main`, for the same reason `adjudicate` is: it decides
    something challengers read about themselves, so it has to be checkable without a
    token or a network.

    The two tallies are kept apart deliberately. They used to share one dictionary,
    with `attempts` stored on whichever entry was current, so replacing that entry with
    a better score threw the counter away and restarted it. A challenger who scored 5,
    2 and then 9 bits was credited with one attempt rather than three: the board
    remembered their hit and forgot their misses, which is backwards. Misses are the
    thing this project asks people to accumulate.

    Rebuilt from `recent`, so it is a rolling view over the last `RECENT` resolutions
    rather than an all-time one. The complete record is the closed issues themselves.
    """
    best: dict[str, dict] = {}
    attempts: dict[str, int] = {}
    for r in recent:
        handle = r["handle"]
        attempts[handle] = attempts.get(handle, 0) + 1
        cur = best.get(handle)
        if cur is None or r["prefix_bits"] > cur["best_prefix_bits"]:
            best[handle] = {"handle": handle, "best_prefix_bits": r["prefix_bits"],
                            "issue": r["issue"], "round": r["round"]}
    for handle, entry in best.items():
        entry["attempts"] = attempts[handle]
    return sorted(best.values(),
                  key=lambda x: -x["best_prefix_bits"])[:LEADERBOARD]


def latest_pulse(bundle: dict) -> dict:
    """The pulse predictions are scored against: the highest round in the file.

    Chosen by round rather than by position. `pulses[-1]` was the last element of a
    list, which is the newest pulse only for as long as whatever wrote the file kept it
    sorted -- an assumption held somewhere else entirely, in a SQL `ORDER BY`. This
    value decides who wins, so it should not rest on a property nothing here checks.
    The same mistake in the NOAA reader shipped and had to be fixed in production: the
    last row of that feed is a day old, not the newest.

    `latest_round` is cross-checked rather than trusted on its own. If the two disagree
    the file is inconsistent, and scoring against either reading would resolve honest
    predictions against a value the beacon may not have published.
    """
    pulses = bundle.get("pulses") or []
    if not pulses:
        raise SystemExit("beacon/chain.json holds no pulses; nothing to score against")

    pulse = max(pulses, key=lambda p: p["round"])
    declared = bundle.get("latest_round")
    if declared is not None and declared != pulse["round"]:
        raise SystemExit(
            f"beacon/chain.json declares latest_round {declared} but its newest pulse "
            f"is round {pulse['round']}. Refusing to score: one of the two is wrong, "
            f"and guessing which would resolve predictions against a value that may "
            f"never have been published."
        )
    return pulse


def _round_from_git() -> int | None:
    """The newest published round per `origin/main`, without touching the network."""
    try:
        out = subprocess.run(
            ["git", "show", "origin/main:beacon/chain.json"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
    except Exception as e:
        print(f"could not read the published chain from git: {e}", file=sys.stderr)
        return None
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout).get("latest_round")
    except json.JSONDecodeError:
        return None


def _round_from_web(repo: str) -> int | None:
    """The same answer from the file GitHub actually serves.

    A fallback, and a closer reading of the question. The check is "can a challenger
    already see this value", and this is literally the bytes they would fetch.
    """
    url = f"https://raw.githubusercontent.com/{repo}/main/beacon/chain.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "beamline-beacon"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read()).get("latest_round")
    except Exception as e:
        print(f"could not read the published chain over HTTP: {e}", file=sys.stderr)
        return None


def published_round(repo: str | None = None) -> int | None:
    """The highest round either reading says is public.

    Two independent sources, and the ANSWER IS THE MAXIMUM, not the first one that
    replies. The question is whether a challenger can already see this value anywhere,
    so one source saying yes settles it. A local `origin/main` ref can lag the file
    GitHub is actually serving -- observed lagging by a round while writing this -- and
    trusting the lower reading would wave through the exact pulse the guard exists to
    catch.

    Two sources also because failing closed stops scoring entirely, and one git
    invocation is a thin thread for that to hang on. Returns None only when neither
    answers, which is the one case the caller refuses on.
    """
    repo = repo or os.environ.get("GITHUB_REPOSITORY", "")
    seen = [r for r in (_round_from_git(), _round_from_web(repo) if repo else None)
            if r is not None]
    return max(seen) if seen else None


def check_target_is_unpublished(round_no: int, repo: str | None = None) -> None:
    """Refuse to score against a pulse the world can already read.

    This is the check that makes the challenge hold, and it was missing.

    `created_at` cannot be forged, so the ordering half of the rule is safe. The guess
    is not: it is read out of the issue body at scoring time, and an author can edit
    that body whenever they like. Lodge a placeholder early, wait for the answer, paste
    it in, and `adjudicate` sees an untouched early timestamp beside a perfect guess.
    Verified against a real published pulse: verdict "early", 512 of 512 bits, exact
    match, on a value copied after publication.

    Nothing in the code stopped that. What stopped it was that the workflow scores
    before it pushes, so the answer was not available to copy -- an invariant asserted
    nowhere, tested nowhere, and one reordered line from silently voiding the prize.
    This module's own usage line, run standalone against a checkout, scores against the
    newest pulse in the file, which in any clone is already public.

    Fail closed. A skipped round costs nothing: the issues stay open and the next pulse
    scores them, which is what already happens whenever scoring fails.
    """
    published = published_round(repo)
    if published is None:
        raise SystemExit(
            "cannot tell whether round {n} is already public, so refusing to score.\n"
            "This needs `git show origin/main:beacon/chain.json` to work, which means "
            "running inside the repository with an origin remote fetched.\n"
            "Scoring against a pulse anybody can already read lets a challenger edit "
            "the answer into an issue lodged earlier.".format(n=round_no)
        )
    if published >= round_no:
        raise SystemExit(
            f"round {round_no} is already published (origin/main is at {published}), so "
            f"its output is public and an open issue could have been edited to match it "
            f"after the fact. Refusing to score.\n"
            f"Scoring must run between `beacon_tick.py` and the push, which is what "
            f".github/workflows/beacon.yml does. Predictions stay open and the next "
            f"pulse resolves them."
        )


def load_board() -> dict:
    if BOARD.exists():
        try:
            return json.loads(BOARD.read_text())
        except json.JSONDecodeError:
            pass
    return {"attempts": 0, "exact_hits": 0, "sum_prefix_bits": 0,
            "best": None, "recent": [], "leaderboard": []}


def main() -> None:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo or not os.environ.get("GITHUB_TOKEN"):
        raise SystemExit("GITHUB_REPOSITORY and GITHUB_TOKEN are both required")
    if not CHAIN.exists():
        raise SystemExit("no beacon/chain.json yet; run scripts/beacon_tick.py first")

    ensure_labels(repo)

    bundle = json.loads(CHAIN.read_text())
    pulse = latest_pulse(bundle)
    actual, round_no = pulse["output"], pulse["round"]
    emitted_ms = pulse["timestamp_ms"]

    # Before anything is scored: is the answer still secret?
    check_target_is_unpublished(round_no, repo)

    board = load_board()
    scored = 0
    pending = 0

    # Three times the cap, so issues that cost a slot without being scored (reopened,
    # or lodged after this pulse) cannot starve the ones that would be.
    queue, complete = open_predictions(repo, limit=MAX_PER_RUN * 3)
    if not complete:
        print(f"listing stopped at {len(queue)} open predictions; pending is a lower "
              f"bound this run", file=sys.stderr)
    for index, issue in enumerate(queue):
        if scored >= MAX_PER_RUN:
            # Oldest first, so the ones left behind are the newest. They keep their
            # target: an unscored issue is still open, and the next pulse is the next
            # round it could name.
            #
            # Stopped rather than skipped one at a time. This branch used to `continue`,
            # printing the same line for every remaining issue, so the flood the cap
            # exists to absorb produced a run log with thousands of identical lines in
            # it. That log is one of the three public artefacts the challenge is audited
            # from; burying it is a cost, not a cosmetic detail.
            remaining = len(queue) - index
            print(f"reached the {MAX_PER_RUN} per run cap; {remaining} prediction(s) "
                  f"wait for the next pulse", file=sys.stderr)
            pending += remaining
            break

        # Reopened after it was already settled. Close it again rather than scoring it
        # twice; the verdict it was given is still on the issue.
        if already_scored(issue):
            print(f"issue #{issue['number']} was reopened after scoring; re-closing",
                  file=sys.stderr)
            gh(f"/repos/{repo}/issues/{issue['number']}", "PATCH", {"state": "closed"})
            continue

        call = adjudicate(issue, actual, emitted_ms)
        created_ms = call["created_ms"]

        # Lodged after the answer was public, so it carries no evidence about this
        # round. It stays open and waits for the next one.
        if call["verdict"] == "late":
            pending += 1
            continue

        if call["verdict"] == "unreadable":
            gh(f"/repos/{repo}/issues/{issue['number']}/comments", "POST", {
                "body": (
                    "I could not find a prediction in this issue.\n\n"
                    "A prediction is **exactly 128 hex characters**, the same shape as "
                    "the `output` field of any pulse in "
                    "[`beacon/chain.json`](https://github.com/" + repo + "/blob/main/beacon/chain.json). "
                    "Open a new one and paste the full value.\n\n"
                    "<sub>Posted automatically by the beacon.</sub>"
                )})
            gh(f"/repos/{repo}/issues/{issue['number']}", "PATCH",
               {"state": "closed", "labels": ["prediction", "unreadable"]})
            continue

        guess, bits, exact = call["guess"], call["prefix_bits"], call["correct"]
        handle = issue["user"]["login"]
        scored += 1

        board["attempts"] += 1
        board["sum_prefix_bits"] += bits
        board["exact_hits"] += int(exact)
        if board["best"] is None or bits > board["best"]["prefix_bits"]:
            board["best"] = {"handle": handle, "prefix_bits": bits,
                             "round": round_no, "issue": issue["number"]}

        board["recent"].insert(0, {
            "handle": handle, "issue": issue["number"], "round": round_no,
            "predicted": guess, "prefix_bits": bits, "correct": exact,
            "lodged_at_ms": created_ms, "resolved_at_ms": emitted_ms,
        })
        del board["recent"][RECENT:]

        verdict = (
            f"### 🎉 Exact match on round {round_no}\n\n"
            f"This is the outcome the challenge exists to be falsified by. "
            f"All 512 bits agree. Please open a discussion, this needs a human.\n"
            if exact else
            f"### Round {round_no} is published, and it is not a match\n\n"
            f"You matched the first **{bits}** bit{'s' if bits != 1 else ''} "
            f"before diverging.\n"
        )
        gh(f"/repos/{repo}/issues/{issue['number']}/comments", "POST", {
            "body": (
                f"{verdict}\n"
                f"| | |\n|---|---|\n"
                f"| You predicted | `{guess[:32]}…` |\n"
                f"| Round {round_no} was | `{actual[:32]}…` |\n"
                f"| Shared leading bits | **{bits}** |\n"
                f"| Lodged | `{issue['created_at']}` |\n"
                f"| Pulse emitted | `{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(emitted_ms / 1000))}` |\n\n"
                f"Your guess was recorded before the pulse existed. Both timestamps are "
                f"GitHub's, not ours, so the ordering does not depend on trusting anyone. "
                f"Check the full pulse in "
                f"[`beacon/chain.json`](https://github.com/{repo}/blob/main/beacon/chain.json) and verify its "
                f"signature with `beamline verify`.\n\n"
                f"<sub>Scored automatically against round {round_no}. "
                f"Expected shared prefix for an unbiased guess: 1 bit.</sub>"
            )})
        gh(f"/repos/{repo}/issues/{issue['number']}", "PATCH",
           {"state": "closed", "labels": ["prediction", "resolved"]})

    if scored:
        # Best-ever score per challenger, which is the ranking people actually care
        # about. Rebuilt from `recent`, so it is a rolling view rather than an
        # all-time one; the complete record is the closed issues themselves.
        board["leaderboard"] = build_leaderboard(board["recent"])

    n = board["attempts"]
    board["updated_at_ms"] = int(time.time() * 1000)
    board["latest_round"] = round_no
    # Guesses lodged for a round that has not landed. The page adds this to the
    # resolved count so a challenger sees their own attempt appear straight away,
    # without waiting up to ten minutes for the next pulse to score it.
    board["pending"] = pending
    board["mean_prefix_bits"] = round(board["sum_prefix_bits"] / n, 4) if n else None
    board["expected_mean_prefix_bits"] = 1.0

    BOARD.parent.mkdir(parents=True, exist_ok=True)
    BOARD.write_text(json.dumps(board, indent=1, sort_keys=True) + "\n")
    print(f"scored {scored} prediction(s) against round {round_no}", file=sys.stderr)


if __name__ == "__main__":
    main()
