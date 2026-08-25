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

Nothing here can change the pulse: this runs after `beacon_tick.py` has already written
and committed it. The scoring is string equality, and every input to it is public.
"""

from __future__ import annotations

import json
import os
import re
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


def iso_to_ms(stamp: str) -> int:
    """GitHub's `created_at`, which is always UTC with a trailing Z."""
    from datetime import datetime, timezone
    return int(datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=timezone.utc).timestamp() * 1000)


def open_predictions(repo: str) -> list[dict]:
    issues, page = [], 1
    while True:
        batch = gh(f"/repos/{repo}/issues?state=open&labels={LABEL}"
                   f"&per_page=100&page={page}&sort=created&direction=asc")
        if not batch:
            break
        # The issues endpoint returns pull requests too; they are not predictions.
        issues += [i for i in batch if "pull_request" not in i]
        if len(batch) < 100:
            break
        page += 1
    return issues


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

    # The load-bearing check, and the only one that matters. An issue opened after the
    # pulse was emitted has had the answer available to read.
    if created_ms >= emitted_ms:
        return {"verdict": "late", "created_ms": created_ms}

    guess = extract(issue.get("body") or "")
    if guess is None:
        return {"verdict": "unreadable", "created_ms": created_ms}

    return {"verdict": "early", "created_ms": created_ms, "guess": guess,
            "prefix_bits": prefix_bits(guess, actual), "correct": guess == actual}


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

    bundle = json.loads(CHAIN.read_text())
    pulse = bundle["pulses"][-1]
    actual, round_no = pulse["output"], pulse["round"]
    emitted_ms = pulse["timestamp_ms"]

    board = load_board()
    scored = 0
    pending = 0

    for issue in open_predictions(repo):
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
                    "[`beacon/chain.json`](../blob/main/beacon/chain.json). "
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
                f"[`beacon/chain.json`](../blob/main/beacon/chain.json) and verify its "
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
        best: dict[str, dict] = {}
        for r in board["recent"]:
            cur = best.get(r["handle"])
            if cur is None or r["prefix_bits"] > cur["best_prefix_bits"]:
                best[r["handle"]] = {"handle": r["handle"],
                                     "best_prefix_bits": r["prefix_bits"],
                                     "issue": r["issue"], "round": r["round"]}
            best[r["handle"]]["attempts"] = best[r["handle"]].get("attempts", 0) + 1
        board["leaderboard"] = sorted(
            best.values(), key=lambda x: -x["best_prefix_bits"])[:20]

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
