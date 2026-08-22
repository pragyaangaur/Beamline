"""Generate the cross-language test vectors.

Two files, both checked by the Python suite and by the JavaScript harness.

The Python encoder is the reference. These vectors are what the JavaScript verifier
in `index.html` is checked against, so that "both verifiers agree" is a fact
established on every test run rather than an assumption.

Only values that encode successfully are recorded. Values the encoder rejects are
covered separately: rejection messages are prose and there is no reason for two
implementations to phrase them identically.

    python scripts/build_canonical_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from beamline.entropy.canonical import encode  # noqa: E402

sys.path.insert(0, str(ROOT / "sdk" / "python"))
from beamline_client import verify as V  # noqa: E402

VALUES = [
    {},
    {"a": 1, "b": 2, "C": 3},
    {"b": 1, "a": 2},
    {"nested": {"z": [1, 2, {"y": None}], "a": True}},
    {"empty_list": [], "empty_obj": {}, "false": False},
    {"neg": -1, "zero": 0, "big": (1 << 53) - 1, "negbig": -((1 << 53) - 1)},
    {"quote": 'he said "hi"', "backslash": "a\\b", "slash": "a/b"},
    {"control": "\n\r\t\b\f", "nul": "\x00", "unit_sep": "\x1f"},
    {"latin1": "Ny-Ålesund", "greek": "λ", "cjk": "東京"},
    {"astral": "\U0001f6f0", "mixed": "sat \U0001f6f0 elite"},
    {"del": "\x7f", "high_ascii_edge": "~"},
    # Shaped like a real pulse body, including a provenance block.
    {
        "version": "beamline/pulse/v3", "round": 10, "timestamp_ms": 1787300655457,
        "period_seconds": 60, "prev_output": "ab" * 64, "local_value": "cd" * 64,
        "public_key": None,
        "provenance": {
            "local_os": {"at_ms": 1787300654442, "bytes": 64, "provider": "kernel getrandom(2)"},
            "astro": {"at_ms": 1787300621847, "feeds": {"goes_xray": {"rows": 6}},
                      "advanced": True},
        },
    },
    "bare string",
    ["a", 1, None, True, False],
    0,
    -0,
    None,
    True,
]


#: Draws whose expected output every implementation must reproduce.
#:
#: The sampling threshold is what these exist for. The server switches between a
#: partial Fisher-Yates over a materialised list and draw-and-reject against a set at
#: span <= 4*count or span <= 4096, and an implementation on the wrong side of that
#: line produces different winners from the same pulse with nothing looking wrong.
#: So both boundaries are covered, in both directions.
PULSE_OUT = "3f" * 64
DRAWS = [
    {"kind": "integers", "tag": "d-int", "count": 6, "min": 1, "max": 49},
    {"kind": "integers", "tag": "d-int-wide", "count": 3, "min": 0, "max": 1_000_000},
    {"kind": "sample", "tag": "d-dense", "count": 6, "min": 1, "max": 49},
    {"kind": "sample", "tag": "d-4096", "count": 2, "min": 1, "max": 4096},
    {"kind": "sample", "tag": "d-4097", "count": 2, "min": 1, "max": 4097},
    {"kind": "sample", "tag": "d-sparse", "count": 3, "min": 1, "max": 4820},
    {"kind": "sample", "tag": "d-ratio", "count": 1200, "min": 1, "max": 4800},
    {"kind": "shuffle", "tag": "d-shuffle", "items": [f"e{i}" for i in range(12)]},
    {"kind": "bytes", "tag": "d-bytes", "count": 48},
]


def expected(draw: dict):
    kind = draw["kind"]
    if kind == "integers":
        return V.reproduce_integers(PULSE_OUT, draw["tag"], draw["count"],
                                    draw["min"], draw["max"])
    if kind == "sample":
        return V.reproduce_unique_integers(PULSE_OUT, draw["tag"], draw["count"],
                                           draw["min"], draw["max"])
    if kind == "shuffle":
        return V.reproduce_shuffle(PULSE_OUT, draw["tag"], draw["items"])
    if kind == "bytes":
        return V.reproduce_bytes(PULSE_OUT, draw["tag"], draw["count"])
    raise SystemExit(f"unknown kind {kind!r}")


def main() -> None:
    data = ROOT / "tests" / "data"
    out = data / "canonical_vectors.json"
    vectors = [{"value": v, "encoded": encode(v).decode("ascii")} for v in VALUES]
    out.write_text(json.dumps(vectors, indent=1) + "\n")
    print(f"wrote {len(vectors)} vectors to {out}", file=sys.stderr)

    draws = data / "draw_vectors.json"
    bundle = {"pulse_output": PULSE_OUT,
              "draws": [{**d, "expected": expected(d)} for d in DRAWS]}
    draws.write_text(json.dumps(bundle, indent=1) + "\n")
    print(f"wrote {len(DRAWS)} draw vectors to {draws}", file=sys.stderr)


if __name__ == "__main__":
    main()
