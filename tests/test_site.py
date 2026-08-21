"""The published demo page must never carry a chain that does not verify.

docs/index.html embeds ten real pulses and invites strangers to check them. If the
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
SITE = ROOT / "docs" / "index.html"
CHAIN = ROOT / "docs" / "chain.json"

sys.path.insert(0, str(ROOT / "sdk" / "python"))
from beamline_client import verify as V  # noqa: E402

EMBEDDED = re.compile(
    r'<script id="chain-data" type="application/json">(.*?)</script>', re.S)


def load_embedded() -> dict:
    m = EMBEDDED.search(SITE.read_text())
    assert m, 'docs/index.html has no <script id="chain-data"> block'
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
