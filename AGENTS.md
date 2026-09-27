# Beamline

Context for anyone, human or AI, picking this up cold. Written 4 September 2026.

## What it is

Provably fair draws. You pick winners, sample records or shuffle anything, and hand everyone a result they can check for themselves without an account and without your cooperation.

- Repo: https://github.com/pragyaangaur/Beamline
- Live: https://pragyaangaur.github.io/Beamline/ and the challenge page at `challenge.html`
- Language: Python package plus a static site, JS and Python SDKs, Docker and fly.io deploy
- Licence: PolyForm Noncommercial 1.0.0. It was MIT, then AGPL-3.0-or-later, then this. Do not let a package manifest or SDK offer the old terms.

## Status

**Update, 23 September 2026.** The last pulse is round 596 at 08:54:34 UTC on 31 August 2026. `beacon/predictions.json` records 0 scored attempts, so nobody claimed the prize. Commit `d2e01cc` updated the README, `DEPLOY.md`, `index.html` and `challenge.html`, which had still described a live beacon and an open prize. They now say the beacon is stopped and the chain is frozen at round 596. Issue #13 is an open test issue from 26 August. Known test quirk: `tests/test_beacon_jobs.py::test_a_genuine_chain_verifies_from_the_command_line` fails when run together with `test_site.py` and `test_challenge.py` and passes alone. It did this before the 23 September commit as well, so it is an order dependence and not a regression.

The public challenge is over. The last commit, `5e64c53 beacon: disable automatic triggers now that the challenge is over` on 31 August 2026, turned off the scheduled beacon job. The chain in `chain.json` and `beacon/` is frozen where it stopped, at round 596. The working tree is clean.

Restarting the beacon means re-enabling the schedule in `.github/workflows/beacon.yml`. Be deliberate about that: a chained beacon that stops and restarts leaves a visible gap, and the whole value of the thing is that the chain is continuous.

## The core idea

"We picked fairly" is worth nothing from a party to the draw, because they would say that either way. So Beamline publishes a signed beacon pulse every ten minutes, chained to the pulse before it. You name your draw in public, wait for the next pulse, and derive the result from it. The pulse did not exist when you named the draw, and afterwards anyone can recompute the result from the published pulse alone.

Randomness comes from three sources mixed in a health-monitored accumulator that seeds a NIST SP 800-90A DRBG.

| Source | Credit | Why |
| --- | --- | --- |
| ANU quantum vacuum fluctuations | 6 bits per byte | The device is ANU's, not ours, and bytes arrive over their TLS connection |
| NOAA space weather | zero bits, deliberately | Public data can hold no secret. It is in the mix for provenance and timing |
| Host kernel CSPRNG | the real security | The one input an external attacker cannot observe. Every extraction folds in a fresh `os.urandom(64)` |

Beamline is explicitly the wrong tool for generating private keys. Use the operating system for that. This is documented in the README and should stay documented.

## Layout

```
beamline/          the package: api, entropy, sources, generators, harvester,
                   keys, store, db, service, challenge, ratelimit, qa, cli
beacon/            chain.json and predictions.json, the live chain state
scripts/           beacon_tick, harvest_anu, run_nist_tests, site and page builders,
                   resolve_predictions, check_js_verifiers.mjs
sdk/python, sdk/js the client libraries
tests/             entropy, generators, harvest, http, nist, canonical, attacks,
                   challenge, beacon_jobs, keys_and_api, astro_freshness, site
reports/           nist-report.json and the run log
index.html, challenge.html, DEPLOY.md, Dockerfile, fly.toml
```

## How it was built, in three phases

1. **The library, to 23 August.** Entropy accumulation, the DRBG, draw generators, the verification story, NIST SP 800-22 testing, the SDKs and the demo page. 726 commits total, most of them automated beacon rounds.
2. **Going live and inviting attack, 23 to 26 August.** The beacon was hosted, then moved off a personal server onto GitHub's clocks so the operator does not own the timing. A prize was offered for predicting the next value before it publishes.
3. **Hardening under real adversaries, 26 August.** This is the most instructive stretch in the history and worth reading before touching the challenge code. Fixes included closing a `?data=` script-injection bypass on the challenge page, escaping demo page innerHTML, refusing to score a pulse the challenger can already read, closing a one-second-wide gap in the single comparison that decides the challenge, stopping a reopened issue being scored twice, bounding the issue listing that walked around the per-run cap, picking the deciding pulse by round rather than array position, and pinning the SP 800-22 tests to the standard's own worked examples.

## Conventions

- Prose style: no em dashes, no antitheses, no rhythm-stacking. There is a commit that stripped these out on purpose.
- Claims in the README are load-bearing. "Ten minutes" must match the workflow schedule, and the entropy credits must match what was measured.
- The challenge scoring path is adversarial code. Any change there needs a test that fails without it. `tests/test_challenge.py` and `tests/test_attacks.py` are the right homes.

## Running it

```bash
pip install -e ".[dev,qa]"
beamline serve --port 8080
pytest
```
