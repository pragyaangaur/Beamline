"""The canonical encoder is the root of trust for every signature, so it gets tested
against the failure it exists to prevent: two verifiers disagreeing about the bytes."""

from __future__ import annotations

import json
import random
import string

import pytest

from beamline.entropy.canonical import (
    MAX_SAFE_INT, NotCanonical, encode, is_canonical, sanitize)


class TestRejectsAmbiguity:
    @pytest.mark.parametrize("value", [1.0, 1e-8, -0.0, 3.14, float("inf"), float("nan")])
    def test_floats_are_refused(self, value):
        """Every one of these spells differently in Python and JavaScript."""
        with pytest.raises(NotCanonical, match="float"):
            encode({"v": value})

    def test_oversized_integers_are_refused(self):
        """A JS verifier holds these as doubles and silently rounds them."""
        with pytest.raises(NotCanonical, match="2\\*\\*53"):
            encode({"n": MAX_SAFE_INT + 1})
        assert encode({"n": MAX_SAFE_INT})  # the boundary itself is fine

    def test_non_ascii_keys_are_refused(self):
        """Python sorts by code point, JS by UTF-16 code unit; above the BMP they differ."""
        with pytest.raises(NotCanonical, match="ASCII"):
            encode({"Ålesund": 1})

    def test_unencodable_types_are_refused(self):
        with pytest.raises(NotCanonical):
            encode({"v": {1, 2}})

    def test_is_canonical_reports_instead_of_raising(self):
        ok, why = is_canonical({"at": 1.0})
        assert not ok and "float" in why
        assert is_canonical({"at": 1787300619000}) == (True, "ok")


class TestEncoding:
    def test_output_is_pure_ascii(self):
        assert encode({"s": "Ny-Ålesund", "e": "\U0001f6f0"}).decode("ascii")

    def test_astral_characters_become_surrogate_pairs(self):
        """Matching what Python's ensure_ascii=True emits, which JS must reproduce."""
        assert encode("\U0001f6f0") == b'"\\ud83d\\udef0"'

    def test_keys_are_sorted(self):
        assert encode({"b": 1, "a": 2, "C": 3}) == b'{"C":3,"a":2,"b":1}'

    def test_matches_json_dumps_on_the_safe_subset(self):
        """Where json.dumps is unambiguous, we must agree with it byte for byte --
        otherwise every already-published pulse would need re-signing."""
        rng = random.Random(20260821)
        alphabet = string.printable[:95]
        for _ in range(500):
            body = {
                "".join(rng.choices(alphabet, k=6)): rng.choice(
                    [1, -7, 0, 'a"b\\c', None, True, False, [1, "x"], {"k": 2}])
                for _ in range(5)
            }
            assert encode(body) == json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    def test_escapes_match_the_json_module(self):
        s = '\n\r\t\b\f"\\/\x00\x1f'
        assert encode(s) == json.dumps(s, ensure_ascii=True).encode()


class TestSanitize:
    def test_floats_survive_as_strings(self):
        assert encode(sanitize({"at": 1787300619.0})) == b'{"at":"1787300619.0"}'

    def test_a_hostile_source_cannot_halt_the_beacon(self):
        """Whatever a third-party feed returns, the result must be encodable."""
        nasty = {"f": 1e-8, "big": 2 ** 70, "keyé": "Ålesund",
                 "nested": [1.5, {"x": float("nan")}], "obj": object()}
        assert encode(sanitize(nasty))

    def test_canonical_values_are_left_alone(self):
        clean = {"rows": 6, "tag": "2026-08-21T08:19:00Z", "ok": True, "none": None}
        assert sanitize(clean) == clean
