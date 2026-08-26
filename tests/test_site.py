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
import shutil
import subprocess
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


# --- the challenge page's own inputs ----------------------------------------
#
# `?data=` is a development convenience that shipped to production, and it used to
# accept anything. A link like
#     challenge.html?data=https://attacker.example
# made the page fetch somebody else's chain.json, and values from it reach innerHTML:
# a hostile `round` executed script on the real origin. Confirmed firing before the
# fix, on the page whose whole argument is that you should not have to trust anyone.
#
# The tests below RUN the shipped code rather than grepping it, because grepping it is
# what let the hole survive its own fix. The previous versions asserted that
# `escapeHtml(p.handle)` and `escapeHtml(p.predicted` appeared in the row template, and
# both did -- while `round`, `issue` and `prefix_bits` beside them were interpolated
# raw. An assertion that two escapes are present says nothing about the fields next to
# them. Likewise the guard on `?data=` was checked by asserting its regex was still in
# the file; the regex was there, and `?data=/\evil.example` went off-origin anyway,
# because a browser reads a backslash as a slash and a string test does not.

CHALLENGE = (ROOT / "challenge.html").read_text()

#: Values that must never leave this origin. The backslash forms are the ones that
#: defeated the string-matching guard: neither carries a scheme, neither starts with
#: "//", and a browser's URL parser resolves both to https://evil.example.
OFF_ORIGIN = [
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "/\\/evil.example",
    "javascript:alert(1)",
    "data:text/plain,x",
]


def _run_node(script: str) -> str:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    out = subprocess.run([node, "--input-type=module", "-e", script],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout


def _data_root_source() -> str:
    """The shipped `dataRoot`, lifted out of the page verbatim."""
    start = CHALLENGE.index("function dataRoot()")
    end = CHALLENGE.index("const DATA = dataRoot();")
    return CHALLENGE[start:end]


@pytest.mark.parametrize("hostile", OFF_ORIGIN)
def test_the_data_parameter_cannot_point_off_origin(hostile):
    """Run the real guard, in a real URL parser, against a real bypass."""
    script = f"""
    const PAGE = "https://pragyaangaur.github.io/Beamline/challenge.html";
    const location = {{ href: PAGE, origin: new URL(PAGE).origin,
                       search: "?data=" + encodeURIComponent({json.dumps(hostile)}) }};
    const console = {{ warn() {{}} }};
    {_data_root_source()}
    const DATA = dataRoot();
    process.stdout.write(new URL(DATA + "/chain.json", PAGE).origin);
    """
    assert _run_node(script) == "https://pragyaangaur.github.io", (
        f"?data={hostile} reached a third party's server")


@pytest.mark.parametrize("benign,expect_suffix", [
    ("./beacon", "/Beamline/beacon"),
    ("beacon", "/Beamline/beacon"),
    ("../other/beacon", "/other/beacon"),
])
def test_a_same_origin_data_path_still_works(benign, expect_suffix):
    """The guard must not cost the development convenience it is guarding."""
    script = f"""
    const PAGE = "https://pragyaangaur.github.io/Beamline/challenge.html";
    const location = {{ href: PAGE, origin: new URL(PAGE).origin,
                       search: "?data=" + encodeURIComponent({json.dumps(benign)}) }};
    const console = {{ warn() {{}} }};
    {_data_root_source()}
    process.stdout.write(new URL(dataRoot() + "/chain.json", PAGE).pathname);
    """
    assert _run_node(script) == expect_suffix + "/chain.json"


def test_the_round_is_validated_before_it_reaches_the_page():
    """Every later use is arithmetic or concatenation into innerHTML, so a value that
    is not an integer must not get that far."""
    assert "Number.isInteger(last.round)" in CHALLENGE
    assert "Number.isInteger(d.latest_round)" in CHALLENGE
    assert "HEX128.test(last.output)" in CHALLENGE


def _row_template() -> str:
    return CHALLENGE[CHALLENGE.index("const rows ="):CHALLENGE.index('$("b-rows")')]


def test_nothing_from_the_scoreboard_file_reaches_innerHTML_unescaped():
    """Every `${...}` in the row template must be escaped, checked, or locally derived.

    Stated as "no raw interpolation survives" rather than "these two fields are
    escaped", because the second form is what shipped while `round`, `issue` and
    `prefix_bits` went in raw beside the fields it named. A new column added later is
    caught by this; it would not have been caught by the old test.
    """
    rows = _row_template()
    # Locals the template computes for itself, each of which is escaped or type-checked
    # where it is built a few lines above.
    SAFE = {"escapeHtml(p.handle)", "escapeHtml(p.round)", "escapeHtml(p.prefix_bits)",
            "escapeHtml(predicted)", "REPO", "state", "handle", "issue"}
    raw = [expr for expr in re.findall(r"\$\{([^{}]*)\}", rows)
           if expr.strip() not in SAFE]
    assert not raw, f"unescaped interpolation into innerHTML: {raw}"
    assert "Number.isInteger(p.issue)" in rows, (
        "an issue number must be checked, not merely escaped: it is a URL, and an "
        "inert non-integer is still not a link to an issue")


def test_a_hostile_scoreboard_row_renders_as_text():
    """The end-to-end shape of the bug: a string where an integer was assumed.

    Each of these fired in a browser before the fix -- `round` and `prefix_bits`
    straight into a cell, `issue` by breaking out of the href attribute.
    """
    hostile = {"handle": "alice", "issue": '1"><img src=x onerror=alert(1)>',
               "round": "<img src=x onerror=alert(1)>", "predicted": "ab" * 64,
               "prefix_bits": "<svg onload=alert(1)>", "correct": False}
    script = f"""
    const REPO = "pragyaangaur/Beamline";
    function escapeHtml(s){{
      return String(s).replace(/[&<>"']/g,
        c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]));
    }}
    const d = {{ recent: [{json.dumps(hostile)}] }};
    {_row_template()}
    process.stdout.write(rows.join(""));
    """
    html = _run_node(script)
    # The payloads survive as TEXT -- "onerror=alert(1)" is still in there, spelled
    # out and inert. What must not survive is the markup: no new element opens, and
    # no attribute is broken out of.
    assert "<img" not in html and "<svg" not in html, html
    assert "&lt;img" in html and "&lt;svg" in html, html
    assert '"><' not in html, html
    # Only the tags the template itself writes.
    assert set(re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9]*)", html)) <= {"tr", "td", "span"}, html
    # The handle still renders; a bad issue number costs the link, not the row.
    assert "alice" in html
    assert "issues/1" not in html, html


def test_a_row_with_a_real_issue_number_still_links():
    """The check must not quietly break the ordinary case it guards."""
    good = {"handle": "bob", "issue": 42, "round": 7, "predicted": "cd" * 64,
            "prefix_bits": 3, "correct": True}
    script = f"""
    const REPO = "pragyaangaur/Beamline";
    function escapeHtml(s){{
      return String(s).replace(/[&<>"']/g,
        c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]));
    }}
    const d = {{ recent: [{json.dumps(good)}] }};
    {_row_template()}
    process.stdout.write(rows.join(""));
    """
    html = _run_node(script)
    assert 'href="https://github.com/pragyaangaur/Beamline/issues/42"' in html
    assert ">bob</a>" in html
    assert "MATCH" in html
