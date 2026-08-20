"""`beamline` command line.

    beamline serve                       run the API
    beamline keys create --tier pro      mint a key (works offline, no running server)
    beamline keys list
    beamline keys revoke <key_id>
    beamline beacon-key                  generate an Ed25519 signing key
    beamline selftest                    statistical smoke test of the generator stack
"""

from __future__ import annotations

import argparse
import json
import sys

from . import keys as keylib
from .config import CONFIG, TIERS
from .db import Database


def _cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("beamline.api.app:app", host=args.host, port=args.port,
                reload=args.reload, log_level="info")
    return 0


def _cmd_keys_create(args) -> int:
    if args.tier not in TIERS:
        print(f"unknown tier '{args.tier}'; choose from {sorted(TIERS)}", file=sys.stderr)
        return 2
    db = Database(CONFIG.db_path)
    mk = keylib.mint(tier=args.tier, label=args.label, env=args.env)
    db.insert_key(mk.key_id, mk.secret_hash, mk.env, mk.tier, mk.label, args.owner, mk.created_at)
    if args.json:
        print(json.dumps({"key": mk.token, "key_id": mk.key_id, "tier": mk.tier, "env": mk.env}))
    else:
        print(f"\n  {mk.token}\n")
        print(f"  key_id : {mk.key_id}")
        print(f"  tier   : {mk.tier}  ({TIERS[mk.tier].monthly_bytes // (1024*1024) or 'unlimited'} MB/month)")
        print(f"  label  : {mk.label or '-'}")
        print("\n  Shown once. Only the SHA-256 is stored.\n")
    return 0


def _cmd_keys_list(args) -> int:
    db = Database(CONFIG.db_path)
    rows = db.list_keys()
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("no keys yet -- run: beamline keys create --tier free")
        return 0
    print(f"{'KEY ID':<10} {'ENV':<6} {'TIER':<10} {'STATE':<9} LABEL")
    for r in rows:
        state = "revoked" if r["revoked_at"] else "active"
        print(f"{r['key_id']:<10} {r['env']:<6} {r['tier']:<10} {state:<9} {r['label']}")
    return 0


def _cmd_keys_revoke(args) -> int:
    db = Database(CONFIG.db_path)
    if db.revoke_key(args.key_id):
        print(f"revoked {args.key_id}")
        return 0
    print(f"no active key with id {args.key_id}", file=sys.stderr)
    return 1


def _cmd_beacon_key(args) -> int:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("install the 'cryptography' package to use signed beacon pulses", file=sys.stderr)
        return 2
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes_raw().hex()
    pub = sk.public_key().public_bytes_raw().hex()
    print(f"\n  BEAMLINE_BEACON_KEY={priv}\n")
    print(f"  public key (publish this): {pub}\n")
    print("  Store the private key in a secret manager, not an environment variable.")
    print("  If it leaks, every pulse ever signed with it becomes deniable.\n")
    print("  Rotation is safe: each pulse carries the key that signed it, so a chain")
    print("  verifier reports the round where the key changed instead of silently")
    print("  failing. Announce the rotation round so the change is expected.\n")
    return 0


def _cmd_selftest(args) -> int:
    """Sanity-check the shaping layer for bias. Not a substitute for dieharder/TestU01
    on the raw stream, but it catches the mistake that actually happens: an off-by-one
    or a modulo shortcut in `generators.py`."""
    import collections
    import math
    import os as _os

    from . import generators as gen

    def rand(n: int) -> bytes:
        return _os.urandom(n)

    n = args.n
    print(f"drawing {n:,} samples per test\n")
    failures = 0

    for sides in (6, 7, 10, 100):
        counts: collections.Counter = collections.Counter()
        drawn = 0
        while drawn < n:
            batch = min(gen.MAX_COUNT, n - drawn)
            counts.update(gen.dice(rand, batch, sides))
            drawn += batch
        expected = n / sides
        chi2 = sum((c - expected) ** 2 / expected for c in counts.values())
        # Rough 99.9% critical value via the Wilson-Hilferty normal approximation.
        df = sides - 1
        crit = df * (1 - 2 / (9 * df) + 3.09 * math.sqrt(2 / (9 * df))) ** 3
        ok = chi2 < crit and len(counts) == sides
        failures += not ok
        print(f"  d{sides:<4} chi2={chi2:8.2f} crit={crit:8.2f}  {'PASS' if ok else 'FAIL'}")

    vals = []
    while len(vals) < n:
        vals += gen.floats(rand, min(gen.MAX_COUNT, n - len(vals)))
    mean = sum(vals) / len(vals)
    tol = 4 / math.sqrt(12 * len(vals))
    ok = abs(mean - 0.5) < tol and all(0.0 <= v < 1.0 for v in vals)
    failures += not ok
    print(f"  float mean={mean:.6f} (expect 0.5 +/- {tol:.6f})  {'PASS' if ok else 'FAIL'}")

    pos = collections.Counter()
    for _ in range(min(n, 20000)):
        pos[gen.shuffle(rand, [0, 1, 2, 3]).index(0)] += 1
    trials = sum(pos.values())
    exp = trials / 4
    chi2 = sum((c - exp) ** 2 / exp for c in pos.values())
    ok = chi2 < 16.27
    failures += not ok
    print(f"  shuffle position chi2={chi2:.2f} (crit 16.27)  {'PASS' if ok else 'FAIL'}")

    print(f"\n{'all checks passed' if not failures else f'{failures} check(s) FAILED'}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="beamline", description="Beamline randomness service")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the API server")
    s.add_argument("--host", default=CONFIG.host)
    s.add_argument("--port", type=int, default=CONFIG.port)
    s.add_argument("--reload", action="store_true")
    s.set_defaults(func=_cmd_serve)

    k = sub.add_parser("keys", help="manage API keys").add_subparsers(dest="sub", required=True)

    kc = k.add_parser("create")
    kc.add_argument("--tier", default="free")
    kc.add_argument("--label", default="")
    kc.add_argument("--owner", default="")
    kc.add_argument("--env", default="live", choices=["live", "test"])
    kc.add_argument("--json", action="store_true")
    kc.set_defaults(func=_cmd_keys_create)

    kl = k.add_parser("list")
    kl.add_argument("--json", action="store_true")
    kl.set_defaults(func=_cmd_keys_list)

    kr = k.add_parser("revoke")
    kr.add_argument("key_id")
    kr.set_defaults(func=_cmd_keys_revoke)

    bk = sub.add_parser("beacon-key", help="generate an Ed25519 beacon signing key")
    bk.set_defaults(func=_cmd_beacon_key)

    st = sub.add_parser("selftest", help="statistical smoke test of the generator stack")
    st.add_argument("-n", type=int, default=200_000)
    st.set_defaults(func=_cmd_selftest)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
