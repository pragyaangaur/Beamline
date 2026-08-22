#!/usr/bin/env python3
"""A narrated walkthrough of Beamline from a customer's point of view.

Run it against a local server to see the whole product surface in one pass:

    beamline serve --port 8080          # in one terminal
    python examples/user_journey.py     # in another

It plays six scenes, each a thing a real customer actually does:

    1. A developer gets a key and makes their first call
    2. They generate the everyday things (passwords, UUIDs, dice, samples)
    3. A creator runs a giveaway that their audience can audit
    4. A sceptical viewer verifies that giveaway without an account
    5. Someone tries to cheat, and gets caught
    6. An auditor pulls a defensible compliance sample

Nothing here is mocked. Every number comes from the running service.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))

import httpx

from beamline_client import Beamline, verify

BASE = os.environ.get("BEAMLINE_URL", "http://127.0.0.1:8080")
ADMIN = os.environ.get("BEAMLINE_ADMIN_TOKEN", "")

W = 76


def scene(n: int, title: str) -> None:
    print()
    print("\033[1m" + "=" * W)
    print(f"  SCENE {n}   {title}")
    print("=" * W + "\033[0m")


def say(text: str = "") -> None:
    print(f"  {text}" if text else "")


def show(cmd: str) -> None:
    print(f"  \033[2m$ {cmd}\033[0m")


def main() -> int:
    try:
        httpx.get(f"{BASE}/healthz", timeout=5).raise_for_status()
    except Exception:
        print(f"No Beamline server at {BASE}.\n\n    beamline serve --port 8080\n")
        return 1

    # ---------------------------------------------------------------- scene 1
    scene(1, "A developer signs up and makes their first call")
    say("Beamline issues a key. It is shown exactly once; only its SHA-256 is stored,")
    say("so a database breach yields nothing an attacker can use.")
    say()

    if not ADMIN:
        say("BEAMLINE_ADMIN_TOKEN is not set, so this demo cannot mint a key.")
        say("Start the server with an admin token, or mint one with:")
        show("beamline keys create --tier pro --label 'demo'")
        return 1

    show("curl -X POST $BEAMLINE/v1/admin/keys -d '{\"tier\":\"pro\"}'")
    r = httpx.post(f"{BASE}/v1/admin/keys", headers={"X-Admin-Token": ADMIN},
                   json={"tier": "pro", "label": "user journey demo"}, timeout=15)
    r.raise_for_status()
    key = r.json()["key"]
    say()
    say(f"\033[1m{key}\033[0m")
    say()
    say("The prefix says what it is at a glance: bl_<env>_<id>_<secret>. A test key")
    say("pasted into production fails loudly instead of silently working.")
    say()

    bl = Beamline(api_key=key, base_url=BASE)

    show("bl.integers(count=6, min=1, max=49, unique=True)")
    say(f"-> {bl.integers(count=6, min=1, max=49, unique=True)}")
    say()
    usage = bl.usage()
    say(f"Usage so far: {usage['usage_this_period']['requests']} requests, "
        f"{usage['usage_this_period']['bytes']} bytes on the '{usage['tier']}' tier.")

    # ---------------------------------------------------------------- scene 2
    scene(2, "The everyday calls")
    for label, cmd, val in [
        ("passwords", "bl.password(length=20)", bl.password(count=2, length=20)),
        ("uuids", "bl.uuid(count=2)", bl.uuid(count=2)),
        ("dice", "bl.dice(count=5, sides=20)", bl.dice(count=5, sides=20)),
        ("gaussian", "bl.gaussian(count=4)", [round(x, 3) for x in bl.gaussian(count=4)]),
        ("shuffle", "bl.shuffle(list('ABCDEFG'))", bl.shuffle(list("ABCDEFG"))),
        ("weighted", "bl.weighted(['gold','silver','bronze'], [1,10,89], 6)",
         bl.weighted(["gold", "silver", "bronze"], [1, 10, 89], 6)),
    ]:
        show(cmd)
        say(f"-> {json.dumps(val) if not isinstance(val, list) or not isinstance(val[0], dict) else val}")
    say()
    say("Every bounded draw uses rejection sampling. `rand() % 6` would make faces 0")
    say("and 1 very slightly more likely, and a customer running a real lottery is")
    say("exactly the customer who would eventually notice.")

    # ---------------------------------------------------------------- scene 3
    scene(3, "A creator runs a giveaway their audience can audit")
    say("The problem is not randomness. It is that the creator is an interested party,")
    say("so 'we picked fairly' is worth nothing coming from them.")
    say()
    tag = f"summer-giveaway-{int(time.time())}"
    say("Step 1. Register the draw name against a pulse that does not exist yet.")
    say("        Announcing it in a caption would be the creator's word. Registering it")
    say("        produces a receipt signed by Beamline, recording where the chain stood")
    say("        at the time -- which is the part an entrant can check.")
    show(f"bl.commit('{tag}')")
    receipt = bl.commit(tag)
    say(f"-> commit {receipt['commit_id']}")
    say(f"   names round {receipt['target_round']}, registered while the chain stood at "
        f"round {receipt['created_after_round']}")
    say()
    say("Step 2. Wait for that pulse. It does not exist yet, so neither the creator nor")
    say("        Beamline can steer it.")
    show(f"bl.wait_for_round({receipt['target_round']})")
    pulse = bl.wait_for_round(receipt["target_round"], poll=1.0, timeout=180)
    say(f"-> pulse {pulse['round']} published at {time.strftime('%H:%M:%S', time.localtime(pulse['timestamp_ms'] / 1000))}")
    say()
    say("        That pulse mixed in live space-weather readings. Its provenance names")
    say("        the NOAA feeds and their timestamps, so the pulse demonstrably could")
    say("        not have been computed before that data existed:")
    for name, meta in list(pulse["provenance"].items()):
        if name == "astro":
            for feed, info in meta.get("feeds", {}).items():
                say(f"          {feed:<20} {info.get('latest_time_tag', 'n/a')}")
    say()
    say("Step 3. Draw 3 winners from 5,000 entrants, against the committed round.")
    show(f"bl.fair_draw('{tag}', count=3, min=1, max=5000)")
    draw = bl.fair_draw(tag, count=3, min=1, max=5000, round=pulse["round"], commit=False)
    draw.commitment = bl.commitment(receipt["commit_id"])
    say(f"-> winners: \033[1m{draw.data}\033[0m  (from pulse {draw.round})")
    say()
    say("        `bl.fair_draw(tag, ...)` on its own does all three steps: it commits,")
    say("        waits for the round, and derives. They are spelled out here because")
    say("        the ordering is the product.")

    # ---------------------------------------------------------------- scene 4
    scene(4, "A sceptical viewer checks the result -- with no account")
    say("This is the part that makes the product worth paying for. The viewer does not")
    say("trust the creator and does not have a Beamline key. They do not need one:")
    say("the beacon endpoints are public, and the verifier runs entirely locally.")
    say()
    show(f"curl $BEAMLINE/v1/beacon/pulse/{draw.round}")
    public_pulse = httpx.get(f"{BASE}/v1/beacon/pulse/{draw.round}", timeout=10).json()
    pk = httpx.get(f"{BASE}/v1/beacon/public-key", timeout=10).json()["public_key"]

    ok, why = verify.check_pulse(public_pulse, public_key_hex=pk)
    say(f"-> pulse hash + Ed25519 signature valid: \033[1m{ok}\033[0m ({why})")
    say()
    show(f"curl $BEAMLINE/v1/beacon/commitment/{receipt['commit_id']}")
    public_commit = httpx.get(
        f"{BASE}/v1/beacon/commitment/{receipt['commit_id']}", timeout=10).json()
    ok_c, why_c = verify.check_commitment(public_commit, public_key_hex=pk)
    say(f"-> the draw name was registered at round {public_commit['created_after_round']}, "
        f"before round {public_commit['target_round']} existed: \033[1m{ok_c}\033[0m ({why_c})")
    say()
    show(f"verify.reproduce_integers(pulse_output, '{tag}', 3, 1, 5000)")
    local = verify.reproduce_integers(public_pulse["output"], tag, 3, 1, 5000)
    say(f"-> recomputed independently: \033[1m{local}\033[0m")
    say(f"-> matches the announced winners: \033[1m{local == draw.data}\033[0m")
    say()
    siblings = httpx.get(
        f"{BASE}/v1/beacon/commitments/{draw.round}", timeout=10).json()["commitments"]
    ok_d, why_d = verify.check_draw(public_pulse, public_commit, draw.data, pk,
                                    count=3, minimum=1, maximum=5000, siblings=siblings)
    say(f"All five questions at once -- authentic pulse, authentic receipt, receipt names")
    say(f"this draw and its shape, it was the only draw registered for this round, and")
    say(f"the numbers reproduce:")
    say(f"-> \033[1m{ok_d}\033[0m ({why_d})")
    say()
    chain = httpx.get(f"{BASE}/v1/beacon/chain?start=1&count=200", timeout=15).json()["pulses"]
    ok, msg = verify.check_chain(chain, pk)
    say(f"Whole-chain check: {msg} -> \033[1m{ok}\033[0m")
    say()
    say("The verifier shares no code with the server. It reimplements the published")
    say("spec from scratch, so agreeing with the server means something.")

    # ---------------------------------------------------------------- scene 5
    scene(5, "Someone tries to cheat")
    say("Suppose the creator disliked the winners and published different ones, or")
    say("edited the pulse to justify the result. Both are caught:")
    say()
    faked = list(draw.data)
    faked[0] = 4242
    say(f"a) Publishing fake winners {faked} instead of {draw.data}:")
    say(f"   recomputation from the pulse still gives {local}"
        f" -> \033[1mmismatch detected\033[0m")
    say()
    tampered = json.loads(json.dumps(public_pulse))
    tampered["local_value"] = "00" * 64
    ok2, why2 = verify.check_pulse(tampered, public_key_hex=pk)
    say("b) Editing the pulse so it produces the numbers they wanted:")
    say(f"   -> valid={ok2}: {why2}")
    say()
    say("And because pulses are chained, rewriting an old one invalidates every pulse")
    say("after it, which anyone holding a later pulse can see.")
    say()
    say("c) The cheat that forges nothing at all. With the pulse already published, the")
    say("   creator tries draw names until one crowns the entrant they wanted. Every")
    say("   result is genuine, reproducible, and signed:")
    entrants, target = 5000, 1234
    for tries in range(1, 20001):
        rigged_tag = f"{tag}-v{tries}"
        if verify.reproduce_integers(public_pulse["output"], rigged_tag, 1, 1, entrants)[0] == target:
            break
    say(f"   found '{rigged_tag}' after {tries} tries -- it really does draw #{target}")
    ok3, why3 = verify.check_draw(public_pulse, public_commit, [target], pk,
                                  count=1, minimum=1, maximum=entrants)
    say(f"   -> but the receipt names '{public_commit['tag']}', not that one: "
        f"\033[1mvalid={ok3}\033[0m")
    say(f"      ({why3})")
    say()
    say("   This is the attack the commitment exists for, and the only one of the three")
    say("   that a hash chain and a signature cannot see. Nothing about the rigged draw")
    say("   is forged; it was simply chosen after the outcome was known.")
    say()
    say("d) Same idea, without touching the name. Keep the announced tag and quietly")
    say("   change the size of the draw:")
    for entrants in (100, 5000, 40000):
        w = verify.reproduce_integers(public_pulse["output"], tag, 1, 1, entrants)
        say(f"   1 winner from {entrants:>6,} -> #{w[0]}")
    ok4, why4 = verify.check_draw(public_pulse, public_commit,
                                  verify.reproduce_integers(public_pulse["output"], tag, 1, 1, 100),
                                  pk, count=1, minimum=1, maximum=100)
    say(f"   -> the receipt fixed 3 from 5,000, so: \033[1mvalid={ok4}\033[0m")
    say(f"      ({why4})")
    say()
    say("e) And the one that needs no cheating at all: register twenty draws in advance,")
    say("   all of them honest, then publish whichever wins. Every receipt predates the")
    say("   pulse and verifies on its own -- so the public list for the round, and the")
    say("   sequence number inside each receipt, are what make the choice visible.")
    say()
    say("The honest limit, stated plainly: this proves ordering and tamper-evidence, and")
    say("the receipt proves the creator named the draw first. It does not by itself prove")
    say("Beamline never withheld a pulse it disliked and re-rolled. Anchoring pulses to an")
    say("external log is what would close that last gap, and it is not built yet.")

    # ---------------------------------------------------------------- scene 6
    scene(6, "An auditor pulls a defensible sample")
    say("Same mechanism, entirely different buyer. An internal auditor needs 8 invoices")
    say("out of 40,000, and needs to show the sample was not chosen to look clean.")
    say()
    audit_tag = f"Q3-AP-invoice-sample-{int(time.time())}"
    show(f"bl.fair_draw('{audit_tag}', count=8, min=1, max=40000)")
    sample = bl.fair_draw(audit_tag, count=8, min=1, max=40000, timeout=180)
    say(f"-> invoices: {sample.data}")
    say(f"-> committed before the deciding pulse: \033[1m{sample.committed}\033[0m")
    say(f"-> verifies end to end: \033[1m{sample.verify()}\033[0m")
    say()
    say("The workpaper cites the tag, the commit id, the pulse round, and the pulse")
    say("hash. A reviewer")
    say("years later can recompute the same eight invoice numbers and confirm the")
    say("sample was fixed before anyone looked at the population -- not merely that it")
    say("reproduces, which a sample chosen afterwards would also do.")

    print()
    print("=" * W)
    say("What a customer is actually buying: not unpredictability -- their laptop")
    say("already has that for free -- but unpredictability a third party will believe.")
    print("=" * W)
    print()
    bl.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
