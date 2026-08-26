"""The published demo page must never carry a chain that does not verify.

index.html embeds ten real pulses and invites strangers to check them. If the
pulse format ever changes and the embedded data is not regenerated, the page becomes
a live demonstration that Beamline's own verification fails -- which is worse than
having no demo at all. So the embedded bundle is verified here, by the independent
Python verifier in the SDK, on every test run.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "index.html"
CHAIN = ROOT / "chain.json"

sys.path.insert(0, str(ROOT / "sdk" / "python"))
from beamline_client import verify as V  # noqa: E402

EMBEDDED = re.compile(
    r'<script id="chain-data" type="application/json">(.*?)</script>', re.S)


def load_embedded() -> dict:
    m = EMBEDDED.search(SITE.read_text())
    assert m, 'index.html has no <script id="chain-data"> block'
    return json.loads(m.group(1))


class TestPublishedSite:
    def test_page_and_chain_json_agree(self):
        """The file on disk and the copy baked into the page must not drift apart."""
        assert load_embedded() == json.loads(CHAIN.read_text())

    def test_embedded_chain_verifies(self):
        bundle = load_embedded()
        pulses = bundle["pulses"]
        assert len(pulses) >= 2, "a one-pulse chain demonstrates nothing"
        ok, reason = V.check_chain(pulses, bundle["public_key"])
        assert ok, reason

    def test_rounds_are_consecutive(self):
        """A hole in the chain would show up on the page as a broken link."""
        rounds = [p["round"] for p in load_embedded()["pulses"]]
        assert rounds == list(range(rounds[0], rounds[0] + len(rounds)))

    def test_every_pulse_is_signed(self):
        """An unsigned pulse cannot be attributed to anyone, so it proves nothing."""
        for p in load_embedded()["pulses"]:
            assert p.get("signature"), f"round {p['round']} is unsigned"

    def test_tampering_is_detected(self):
        """The page's core promise: an altered pulse fails verification."""
        bundle = load_embedded()
        pulses = json.loads(json.dumps(bundle["pulses"]))
        target = pulses[len(pulses) // 2]
        v = target["local_value"]
        target["local_value"] = v[:9] + f"{(int(v[9], 16) + 1) % 16:x}" + v[10:]
        ok, _ = V.check_chain(pulses, bundle["public_key"])
        assert not ok

    def test_page_is_self_contained(self):
        """No fetch() at runtime: the page has to work from a file:// URL too."""
        html = SITE.read_text()
        assert "fetch(" not in html
        allowed = (
            "https://fonts.googleapis.com",   # webfont stylesheet
            "https://fonts.gstatic.com",      # the font files it pulls
            "https://github.com/",            # the source link in the footer
            "http://www.w3.org/2000/svg",     # the inline favicon's XML namespace
        )
        for url in re.findall(r'https?://[^\s"\')]+', html):
            assert url.startswith(allowed), f"unexpected remote reference: {url}"

    @pytest.mark.parametrize("tag,count,minimum,maximum", [
        ("midsummer-giveaway-2026", 3, 1, 4820),        # dense: partial Fisher-Yates
        ("audit-sample-q3", 5, 1, 4_000_000),           # sparse: draw-and-reject
    ])
    def test_draw_reproduces_from_the_published_pulse(self, tag, count, minimum, maximum):
        """Both sampling strategies the page reimplements in JavaScript are exercised
        here against the server's own generators, from the same embedded pulse."""
        from beamline import generators as gen

        pulse = load_embedded()["pulses"][-1]

        def draw() -> list[int]:
            stream, state = bytearray(), {"pos": 0, "chunk": 0}

            def rand(n: int) -> bytes:
                while state["pos"] + n > len(stream):
                    state["chunk"] += 1
                    stream.extend(_derive(pulse["output"], f"{tag}#{state['chunk']}", 4096))
                out = bytes(stream[state["pos"]:state["pos"] + n])
                state["pos"] += n
                return out

            return gen.integers(rand, count, minimum, maximum, unique=True)

        drawn = draw()
        assert len(set(drawn)) == count
        assert all(minimum <= v <= maximum for v in drawn)
        # The promise the page makes out loud: same pulse, same tag, same numbers.
        assert draw() == drawn


def _derive(output_hex: str, tag: str, n: int) -> bytes:
    """The published derivation, spelled out rather than imported from the server."""
    import hashlib

    out = bytearray()
    counter = 0
    base = b"beamline/derive/v1" + bytes.fromhex(output_hex) + tag.encode()
    while len(out) < n:
        out += hashlib.sha512(base + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:n])


def test_every_package_agrees_with_the_licence_the_repository_ships():
    """A shipped package must not offer terms the repository does not.

    `sdk/js/package.json` said `"license": "MIT"` through two relicensings. npm shows
    that field on the package page, so anyone taking it at face value would have
    believed they held a permissive grant over code published under PolyForm
    Noncommercial -- and the copy of the terms that would have contradicted them was
    not in `files`, so it never shipped either.

    Both halves are checked here, because a correct declaration pointing at a file the
    tarball omits is not much better than the wrong declaration.
    """
    text = (ROOT / "LICENSE").read_text()
    assert "PolyForm Noncommercial License 1.0.0" in text

    pkg = json.loads((ROOT / "sdk" / "js" / "package.json").read_text())
    assert "MIT" not in pkg["license"]
    assert pkg["license"] == "SEE LICENSE IN LICENSE"

    shipped = pkg.get("files") or []
    assert "LICENSE" in shipped, "the licence must be in the published tarball"
    for name in shipped:
        assert (ROOT / "sdk" / "js" / name).exists(), f"files lists a missing {name}"

    # And the copy beside the package is the same terms, not a stale fork of them.
    assert (ROOT / "sdk" / "js" / "LICENSE").read_text() == text


def test_the_python_project_declares_the_same_licence():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert 'license = "LicenseRef-PolyForm-Noncommercial-1.0.0"' in pyproject


@pytest.mark.parametrize("name", ["index.html", "challenge.html",
                                  "examples/draw_page.html"])
def test_every_published_page_renders_in_standards_mode(name):
    """A page with no doctype is rendered in quirks mode, on the 1990s box model.

    `examples/draw_page.html` had none. It is the artifact a customer hands to
    entrants -- the "here is the draw, check it yourself" page -- so it is the one
    example of the product a stranger sees finished, and it was being laid out under
    rules no stylesheet here was written for.
    """
    text = (ROOT / name).read_text().lstrip()
    assert text[:15].lower() == "<!doctype html>", f"{name} has no doctype"


@pytest.mark.parametrize("name", ["index.html", "challenge.html",
                                  "examples/draw_page.html"])
def test_every_published_page_declares_its_language(name):
    """Screen readers pick a voice from this. Without it they guess."""
    assert re.search(r'<html[^>]*\blang="[a-z]{2}', (ROOT / name).read_text()), name


# --- the chain window rolls mid-challenge -----------------------------------
#
# beacon/chain.json holds a bounded window, so once the beacon passes that many rounds
# the file stops starting at round 1. At a ten-minute cadence that happens inside two
# days of launching, which is inside the challenge period, and nothing covered it: a
# partial window that failed to verify would turn the published chain into a live
# demonstration of Beamline's own verification failing.

def _live_chain():
    return json.loads((ROOT / "beacon" / "chain.json").read_text())


def test_a_window_that_no_longer_starts_at_round_one_still_verifies():
    """What the published file becomes after the window rolls."""
    bundle = _live_chain()
    pulses = sorted(bundle["pulses"], key=lambda p: p["round"])
    key = bundle["public_key"]

    for keep in (2, 10, 50):
        if len(pulses) < keep:
            continue
        window = pulses[-keep:]
        assert window[0]["round"] > 1 or len(pulses) == keep
        ok, why = V.check_chain(window, public_key_hex=key)
        assert ok, f"a {keep}-pulse window failed to verify: {why}"


def test_a_single_pulse_verifies_on_its_own():
    """What somebody auditing one old draw actually holds."""
    bundle = _live_chain()
    newest = max(bundle["pulses"], key=lambda p: p["round"])
    ok, why = V.check_pulse(newest, public_key_hex=bundle["public_key"])
    assert ok, why


def test_the_published_file_never_exceeds_its_declared_window():
    bundle = _live_chain()
    assert len(bundle["pulses"]) <= bundle["window"]


def test_the_window_keeps_the_newest_pulses_not_the_oldest():
    """The rollover must drop history, never the round people are predicting against."""
    bundle = _live_chain()
    rounds = sorted(p["round"] for p in bundle["pulses"])
    assert rounds[-1] == bundle["latest_round"]
    assert rounds == list(range(rounds[0], rounds[-1] + 1)), "no holes in the window"
