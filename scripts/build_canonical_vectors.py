"""Generate the cross-language test vectors for the canonical encoding.

The Python encoder is the reference. These vectors are what the JavaScript verifier
in `docs/index.html` is checked against, so that "both verifiers agree" is a fact
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


def main() -> None:
    out = ROOT / "tests" / "data" / "canonical_vectors.json"
    vectors = [{"value": v, "encoded": encode(v).decode("ascii")} for v in VALUES]
    out.write_text(json.dumps(vectors, indent=1) + "\n")
    print(f"wrote {len(vectors)} vectors to {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
