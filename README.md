# Beamline

**Provably fair draws.** Pick winners, sample records, or shuffle anything, and hand
everyone a result they can check for themselves.

[**Try it in your browser →**](https://pragyaangaur.github.io/Beamline/) Run a draw, then
try to rig it. Nothing to install.

```bash
pip install -e ".[dev,qa]"
```

```bash
beamline serve --port 8080
```

## Contents

- [What it does](#what-it-does)
- [Try it](#try-it)
- [Quick start](#quick-start)
- [Running a fair draw](#running-a-fair-draw)
- [API reference](#api-reference)
- [How it works](#how-it-works)
- [Randomness testing](#randomness-testing)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security notes](#security-notes)

## What it does

Whenever you run a draw you are also a party to, "we picked fairly" is worth nothing,
because you would say that either way. A creator picking a giveaway winner, a marketplace
allocating limited stock, an auditor sampling 200 transactions out of four million: the
problem is never finding random numbers. It is producing evidence that convinces somebody
who assumes you cheated.

Beamline publishes a signed **beacon pulse** every minute, chained to the pulse before it.
You name your draw in public, wait for the next pulse, and derive the result from it. The
pulse did not exist when you named the draw, so nobody could have picked the outcome — and
afterwards anyone can recompute the result from the published pulse alone, with no account
and no cooperation from you.

The randomness underneath comes from a quantum source (the ANU vacuum-fluctuation QRNG),
live NOAA space-weather readings, and the host kernel CSPRNG, mixed in a health-monitored
accumulator that seeds a NIST SP 800-90A DRBG.

### Where Beamline is not the right tool

Generating private keys. Randomness fetched over a network is randomness someone else
could have observed, so use your operating system: `/dev/urandom` and friends are free,
instant, and better audited than this. A well-seeded CSPRNG is computationally
indistinguishable from ideal, and no attack exists that a quantum source prevents and
ChaCha20 does not.

Beamline is for the case where the randomness has to be **publicly verifiable**, not the
case where it has to be secret.

## Try it

**[The interactive demo](https://pragyaangaur.github.io/Beamline/)** is the fastest way in.
Run a draw against a real signed pulse, then edit that pulse and watch the checks fail, or
rewrite the chain and see what breaks. Ten genuine pulses are baked into the page, and
everything runs in the browser. It is [`index.html`](index.html) at the repository root,
which is where GitHub Pages serves this branch from; regenerate its pulses from a live
service run with `python scripts/build_site_data.py`.

**[The user journey](examples/user_journey.py)** is the same story from a customer's side,
against a live local server with nothing mocked: a developer gets a key and makes a first
call, a creator runs an auditable giveaway, a sceptical viewer verifies it without an
account, two cheating attempts get caught, and an auditor pulls a defensible sample.

```bash
BEAMLINE_ADMIN_TOKEN=... python examples/user_journey.py
```

**[`examples/draw_page.html`](examples/draw_page.html)** is the artifact a customer would
publish: a finished draw record with a "verify in this browser" button.

## Quick start

Generate a beacon signing key:

```bash
beamline beacon-key
```

Set the configuration (see [`.env.example`](.env.example)):

```bash
export BEAMLINE_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

```bash
export BEAMLINE_BEACON_KEY="<the private key printed by beacon-key>"
```

Run the server:

```bash
beamline serve --port 8080
```

Mint a key:

```bash
beamline keys create --tier pro --label "my app"
```

Use it:

```bash
curl -s http://127.0.0.1:8080/v1/random/integers -H "Authorization: Bearer bl_live_..." -H "Content-Type: application/json" -d '{"count":6,"min":1,"max":49,"unique":true}'
```

Interactive API docs are served at `/docs`.

## Running a fair draw

1. **Publish the draw name first** — a draw id, an entry-list hash, an order number.
2. **Wait for the next pulse.** It does not exist yet, so neither side can choose it.
3. **Derive the result** from that pulse.
4. **Anyone can now recompute it** from the published pulse alone.

```python
from beamline_client import Beamline

bl = Beamline(api_key="bl_live_...", base_url="http://127.0.0.1:8080")

bl.wait_for_next_pulse()                                  # step 2
draw = bl.fair_draw("raffle-2026-08-19", count=3, min=1, max=5000)

print(draw.data, draw.round)
assert draw.verify()                                      # recomputed locally
print(bl.verify_chain())                                  # (True, 'verified N pulses')
```

`draw.verify()` makes zero server calls. It recomputes the numbers using
[`sdk/python/beamline_client/verify.py`](sdk/python/beamline_client/verify.py), which shares
no code with the server and reimplements the spec from scratch — a verifier that imports the
server's own functions only proves the server agrees with itself. A JavaScript verifier
([`sdk/js/index.js`](sdk/js/index.js)) does the same in the browser via WebCrypto.

**What this proves, and what it doesn't.** The chain proves ordering and tamper-evidence.
It does not by itself prove an operator never withheld a pulse they disliked and waited for
the next one — that is caught by observers watching live, and by the space-weather
provenance no longer lining up. It is the same trust model as the NIST Randomness Beacon.
Publishing the draw name in advance closes the gap from your side.

## API reference

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/random/bytes?n=&format=` | key | raw bytes (`base64`, `hex`, or `binary`) |
| `POST /v1/random/integers` | key | bounded integers, optional `unique` |
| `POST /v1/random/floats` | key | uniform floats in [0,1) |
| `POST /v1/random/gaussian` | key | normal deviates |
| `POST /v1/random/shuffle` | key | Fisher-Yates permutation |
| `POST /v1/random/sample` | key | draw without replacement |
| `POST /v1/random/weighted` | key | weighted draw with replacement |
| `GET /v1/random/uuid` | key | RFC 4122 version 4 |
| `GET /v1/random/dice` | key | dice rolls |
| `GET /v1/random/password` | key | passwords with entropy, served `no-store` |
| `POST /v1/beacon/derive` | key | reproducible draw from a pulse |
| `GET /v1/beacon/latest`, `/pulse/{n}`, `/chain`, `/verify/{n}` | none | the beacon |
| `GET /v1/beacon/public-key` | none | Ed25519 verification key |
| `GET /v1/me` | key | usage and limits |
| `GET /v1/health`, `/v1/about` | none | source health, claims |
| `POST`, `GET`, `DELETE` `/v1/admin/keys` | admin | key management |

Beacon endpoints are unauthenticated on purpose: verification has to work for a sceptic
with no account.

### Rate limits

| Tier | Monthly | Burst | Sustained | Max per request |
|---|---|---|---|---|
| free | 1 MB | 30 | 0.5/s | 1 KB |
| starter | 256 MB | 120 | 5/s | 64 KB |
| pro | 4 GB | 600 | 40/s | 1 MB |
| unlimited | none | 5000 | 1000/s | 8 MB |

Configured in [`beamline/config.py`](beamline/config.py).

### API keys

Keys look like `bl_live_7QK4M2XA_9F3TZP0RB6HC8VNJ4WDYKQ2SM5EGL7A`. The secret is 160 bits
in Crockford base32, which drops `I`, `L`, `O`, and `U` to avoid transcription errors. Only
the SHA-256 is stored, so a database leak yields no working keys, and the 8-character key id
is indexed so verification is one lookup plus a constant-time compare. Unknown ids are
compared against a dummy hash, so the endpoint does not leak which ids exist. The `live` /
`test` segment means a test key pasted into production fails loudly.

```bash
beamline keys list
```

```bash
beamline keys revoke 7QK4M2XA
```

## How it works

```
sources ──▶ entropy pool ──▶ DRBG ──▶ API
                  │
                  └────────▶ beacon pulse ──▶ signed, chained, public
```

| Source | Credit | Notes |
|---|---|---|
| `anu_qrng` | 6.0 bits/byte | quantum vacuum fluctuations, delivered over a third party's TLS |
| `local_os` | 8.0 bits/byte | kernel CSPRNG, the one source a remote attacker cannot observe |
| `astro` | 0.0 | NOAA X-ray flux, solar wind, magnetometer. Public data. |

Two claims are stated up front because they are the ones most easily oversold. **API
responses are DRBG output seeded by physical entropy**, not raw quantum measurements piped
to a socket — that is how every hardware RNG in production works, and mixing in the local
kernel CSPRNG means an attacker must compromise *every* source, not just the one being
resold. **The space-weather data is public**, so it contributes zero secret entropy and is
credited 0.0 bits. It is mixed in for provenance: it timestamps a pulse against a record
anyone can independently observe. `GET /v1/about` returns both claims in machine-readable
form, and a test fails the build if the code and the claims drift apart.

Credit is always the conservative figure, never the measured one. The ANU alphabet is
measured at 63 symbols rather than the 64 a base64url assumption would give, so a block
carries 6,120 bits instead of 6,144, and crediting the conditioned output at 6 bits/byte
holds back a further 25 percent against the fact that the bytes arrived over someone else's
connection. Every credited source runs permanent SP 800-90B health tests (Repetition Count
and Adaptive Proportion) and is quarantined if it dies stuck or its distribution collapses;
live state is at `GET /v1/health`.

### The pulse

```
output = SHA-512("beamline/pulse/v2" | canonical_json(
             round, timestamp_ms, period, prev_output,
             local_value, public_key, provenance))
```

Signed with Ed25519, chained through `prev_output`. Two details in that body exist because
of failures found while testing the Python and JavaScript verifiers against each other.
**`public_key` sits inside the signed body**, so rotating the signing key is an auditable
event rather than a silent break — otherwise every historical pulse stops verifying and a
verifier cannot tell an honest rotation from a substituted archive. **`timestamp_ms` is an
integer**, because a float landing on a whole second serialises as `1787150090.0` in Python
and `1787150090` in JavaScript, so the canonical bytes diverge and verification fails for
about one pulse in a thousand, silently.

### The harvester

Beamline runs on the free public ANU endpoint, so what matters is sustained long-run yield,
not peak burst rate. Measured on the live endpoint, throughput is still climbing at 12
concurrent requests but latency has doubled and per-connection yield has fallen 59 percent:
past the knee, extra load buys queue time rather than blocks. That knee moves with time of
day, so [`beamline/harvester.py`](beamline/harvester.py) finds it at runtime with a
latency-gradient controller in the style of TCP Vegas, over a continuous worker pipeline.
Removing the head-of-line barrier of a batched design was worth 2.9x on its own. Measured
result: ~33 blocks/s, roughly 200 kbit/s of source entropy, at 1.01x baseline latency with
zero errors and zero duplicates.

```bash
python scripts/harvest_anu.py --duration 600
```

Blocks are deduplicated by SHA-256 (a block served twice carries the entropy of one),
validated before archival (an HTML error page is not entropy), and consumed once (replaying
stored bytes adds no unpredictability). A metered API key from
<https://quantumnumbers.anu.edu.au/> removes the dependency on the free endpoint; set
`BEAMLINE_ANU_API_KEY` and the same code path uses it.

## Randomness testing

Full implementations of both NIST suites live in [`beamline/qa/`](beamline/qa/): SP 800-22
Rev 1a with all 15 tests, and SP 800-90B with nine of the ten non-IID min-entropy
estimators.

```bash
python scripts/run_nist_tests.py --target all --streams 12 --json reports/nist-report.json
```

Twelve streams of 1,000,000 bits per target. `urandom` is an experimental control: the same
pipeline run against the host kernel CSPRNG, so a quirk in the harness shows up there too.

| Target | What it is | SP 800-22 | p-value uniformity |
|---|---|---|---|
| `raw-packed` | harvested blocks, 6-bit packed, no conditioning | 4 / 13 | 0.000000 |
| `conditioned` | what actually enters the entropy pool | 15 / 15 | 0.555 |
| `drbg` | what the API serves | 15 / 15 | 0.005 |
| `urandom` | host kernel CSPRNG (control) | 15 / 15 | 0.255 |

**The raw source fails on purpose, and that is the useful result.** `raw-packed` fails nine
of thirteen tests because packing a 63-symbol alphabet into 6 bits leaves a code point
unused and biases the stream toward zero. So the suite has real detection power on real
data, and hash conditioning is load-bearing rather than decorative — the `conditioned` row
is it working.

Three honest caveats. The suite is validated against known-bad generators (all-zeros,
alternating bits, a 32-bit counter, RANDU's low bytes, a coin biased by 0.5 percent) in
[`tests/test_nist.py`](tests/test_nist.py), because a suite that passes everything is
worthless. Min-entropy estimates at these sample sizes have a spread of roughly 0.68 to 0.90
bits per bit — the kernel control moved 0.13 between identical runs — so they are not a
ranking, and differences inside that band carry no information. And passing means no
implemented test found the structure it was designed to find, which is evidence about
specific defects, not proof of unpredictability: a counter encrypted under AES passes
everything and is perfectly predictable to whoever holds the key.

Beamline is **not** FIPS 140-3 validated and holds no GLI-19 or iTech Labs certification.
Regulated gambling needs one, and running these suites is not a substitute. Full per-run
detail, including the estimators that are skipped and why, is in
[`reports/nist-report.json`](reports/).

## Configuration

All variables take a `BEAMLINE_` prefix. See [`.env.example`](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `BEAMLINE_ADMIN_TOKEN` | none | required for `/v1/admin/*` |
| `BEAMLINE_BEACON_KEY` | none | Ed25519 private key; unset means unsigned pulses |
| `BEAMLINE_ANU_API_KEY` | none | official metered ANU API |
| `BEAMLINE_ANU_POLL_SECONDS` | 20 | live source poll interval |
| `BEAMLINE_ASTRO_POLL_SECONDS` | 60 | space-weather poll interval |
| `BEAMLINE_BEACON_PERIOD_SECONDS` | 60 | pulse cadence |
| `BEAMLINE_RESEED_SECONDS` | 60 | DRBG reseed interval |
| `BEAMLINE_RESEED_BYTES` | 16777216 | reseed after this many generated bytes |
| `BEAMLINE_POOL_DIR` | `data/pool` | harvested block archive |
| `BEAMLINE_DB` | `data/beamline.db` | SQLite path |
| `BEAMLINE_HOST` | `127.0.0.1` | bind address |
| `BEAMLINE_PORT` | 8080 | bind port |

## Architecture

```
beamline/
  config.py          tiers, env configuration
  keys.py            minting, parsing, constant-time verification
  db.py              SQLite: keys, usage, pulse chain
  store.py           harvested-block archive with dedup and consume-once reads
  harvester.py       adaptive-concurrency ANU harvester
  generators.py      bias-free shaping (rejection sampling throughout)
  ratelimit.py       per-key token bucket
  service.py         orchestrator: poll loops, reseed, pulse emission
  entropy/
    blocks.py        measured alphabet, 6-bit packing, conditioning
    pool.py          SHA-512 accumulator and entropy credit policy
    health.py        SP 800-90B continuous health tests
    drbg.py          HMAC_DRBG(SHA-512), SP 800-90A
    beacon.py        signed hash-chained pulses and derivation
  sources/           anu.py, astro.py, local.py (pluggable)
  api/               FastAPI app, auth dependencies, routes
  qa/                SP 800-22 and SP 800-90B implementations
sdk/python/          client and independent verifier
sdk/js/              client and verifier (WebCrypto)
index.html           the interactive demo, served by GitHub Pages
chain.json           the pulses embedded in it
examples/            user journey demo, public draw page
scripts/             harvest_anu.py, run_nist_tests.py, build_site_data.py
data/                runtime state, never committed
```

Adding a physical source, such as a cosmic-ray detector or a second QRNG vendor, means
writing one `Source` subclass and registering it.

Nothing under `data/` is committed: the archive is the raw entropy behind pulses that have
already been published and signed, and `beamline.db` holds key hashes and usage history.
Populate it with `python scripts/harvest_anu.py --duration 600`.

### Tests

```bash
pytest -q
```

247 tests cover DRBG correctness and backtracking resistance, pool credit policy, health-test
failure detection, statistical bias in every generator (including a chi-square across all 24
permutations of a 4-element shuffle), the alphabet and packing layer, store deduplication,
harvester control-law behaviour, key handling, beacon chain integrity and tamper detection,
signing-key rotation, HTTP auth, quotas and rate limits, the published demo page, and the
NIST suites against known-bad generators.

```bash
beamline selftest -n 200000
```

## Security notes

**The beacon signing key is the critical secret.** If it leaks, every pulse ever signed
becomes deniable. It belongs in a KMS or HSM, not an environment variable.

**Harvested entropy is never committed.** Publishing the seed archive would publish the
material behind past pulses.

**Generated passwords are served `no-store`** so they cannot land in a proxy cache.

**Rate limiting is per-process.** Behind a load balancer the effective ceiling is N times the
configured rate; the monthly byte quota in SQLite is the hard limit, and Redis-backed
limiting is the fix for multi-instance deployments.
