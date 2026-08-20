# Beamline

**Randomness you can prove.**

Beamline harvests entropy from a quantum source (the ANU vacuum-fluctuation QRNG),
real-time astrophysical measurements (NOAA space weather), and the host kernel CSPRNG;
mixes them in a health-monitored accumulator; and seeds a NIST SP 800-90A DRBG that
serves the API. Every minute it publishes a signed, hash-chained **beacon pulse** that
anyone can verify without an account — which is what lets a draw be shown to be fair
after the fact.

```bash
pip install -e ".[dev,qa]"
```

```bash
beamline serve --port 8080
```

---

## Contents

- [What this is, plainly](#what-this-is-plainly)
- [Quick start](#quick-start)
- [The beacon](#the-beacon)
- [Try it: the user journey demo](#try-it-the-user-journey-demo)
- [API reference](#api-reference)
- [Entropy sources and the harvester](#entropy-sources-and-the-harvester)
- [Randomness testing](#randomness-testing)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Security notes](#security-notes)

---

## What this is, plainly

Two facts govern how everything here is built, and both are stated up front because
they are the ones most easily oversold.

**API responses are DRBG output seeded by physical entropy — not raw quantum
measurements piped to a socket.** That is how every hardware RNG in production works,
including `/dev/urandom` and every QRNG vendor's driver stack. It is the correct design:
a network entropy source is finite and slow, and mixing it with the local kernel CSPRNG
means an attacker must compromise *every* source rather than just the one being resold.

**The astrophysical data is public.** NOAA serves the same bytes to everyone, so it
contributes zero secret entropy and is credited **0.0 bits** in
[`beamline/entropy/pool.py`](beamline/entropy/pool.py). It is mixed in for *provenance* —
it timestamps a pulse against an independently observable physical record — not for
secrecy.

`GET /v1/about` returns these claims in machine-readable form, and a test fails the
build if the code and the claims drift apart.

### Where Beamline is not the right tool

Nowhere, for generating private keys. Randomness fetched over a network is randomness
someone else could have observed; for key material, use the operating system. A
well-seeded CSPRNG is computationally indistinguishable from ideal, and no attack exists
that a quantum source prevents and ChaCha20 does not.

Beamline is for the case where randomness must be **publicly verifiable** — where
"trust us, it was random" is not an acceptable answer:

- Raffles, giveaways, lotteries, tournament seeding, loot drops
- Audit and compliance sampling that must be defended afterwards
- Research and simulation where a third party must reproduce a draw
- Any drawing where the operator is an interested party

See [PRODUCT.md](PRODUCT.md) for the reasoning behind that positioning.

---

## Quick start

Generate a beacon signing key:

```bash
beamline beacon-key
```

Export the configuration (see [`.env.example`](.env.example)):

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
curl -s http://127.0.0.1:8080/v1/random/integers \
  -H "Authorization: Bearer bl_live_..." \
  -H "Content-Type: application/json" \
  -d '{"count":6,"min":1,"max":49,"unique":true}'
```

Interactive docs are at `/docs`.

---

## The beacon

Every `BEAMLINE_BEACON_PERIOD_SECONDS` (default 60), the service publishes a pulse:

```
output = SHA-512("beamline/pulse/v2" | canonical_json(
             round, timestamp_ms, period, prev_output,
             local_value, public_key, provenance))
```

signed with Ed25519 and chained through `prev_output`. Beacon endpoints are
**unauthenticated on purpose** — verification has to work for a sceptic who has no
account, and charging for it would defeat the product.

Two details in that body exist because of failures found while testing verifiers
against each other, and both matter more than they look:

- **`public_key` is inside the signed body.** Each pulse declares the key that signed
  it, so rotating the signing key is an auditable event rather than a silent break.
  Without it, every historical pulse simply stops verifying against the current key and
  a verifier cannot distinguish an honest rotation from a substituted archive. The chain
  verifier reports the round at which a key changed.
- **`timestamp_ms` is an integer, not a float.** A float that lands on a whole second
  serialises as `1787150090.0` in Python and `1787150090` in JavaScript. The canonical
  bytes then differ and verification fails — for roughly one pulse in a thousand,
  silently, and only for the cross-language verifiers the product depends on. Integers
  serialise identically everywhere.

### Running a provably fair draw

1. **Publish the `tag` first** — a draw id, an entry-list hash, an order number.
2. Wait for the next pulse. It does not exist yet, so neither party can choose it.
3. Derive the result from that pulse.
4. Anyone can now recompute it from the published pulse alone.

```python
from beamline_client import Beamline

bl = Beamline(api_key="bl_live_...", base_url="http://127.0.0.1:8080")

bl.wait_for_next_pulse()                                  # step 2
draw = bl.fair_draw("raffle-2026-08-19", count=3, min=1, max=5000)

print(draw.data, draw.round)
assert draw.verify()                                      # recomputed locally
print(bl.verify_chain())                                  # (True, 'verified N pulses')
```

`draw.verify()` makes **zero** server calls. It recomputes the numbers from the pulse
using [`sdk/python/beamline_client/verify.py`](sdk/python/beamline_client/verify.py),
which shares no code with the server and reimplements the spec from scratch. That
independence is the point — a verifier that imports the server's own functions proves
only that the server agrees with itself.

A JavaScript verifier ([`sdk/js/index.js`](sdk/js/index.js)) does the same in the
browser via WebCrypto, and its canonical serialisation is byte-identical to the
Python implementation.

### Trust model, stated honestly

The chain proves **ordering and tamper-evidence**. It does not, by itself, prove the
operator never withheld a pulse they disliked and waited for the next one. That would be
caught by observers watching live, and by the astrophysical provenance no longer lining
up — the same trust model as the NIST Randomness Beacon. Publishing the tag in advance
closes the gap on the customer's side; anchoring pulse hashes to an external
append-only log closes it on the operator's side and is on the roadmap.

---

## Try it: the user journey demo

The fastest way to understand what Beamline feels like in use:

```bash
python examples/user_journey.py
```

Six scenes against a live local server, with nothing mocked:

1. A developer gets a key and makes their first call
2. The everyday calls — passwords, UUIDs, dice, weighted picks
3. A creator runs a giveaway their audience can audit
4. A sceptical viewer verifies it **without an account**
5. Someone tries to cheat, and gets caught
6. An auditor pulls a defensible compliance sample

---

## API reference

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/random/bytes?n=&format=` | key | raw bytes (`base64`/`hex`/`binary`) |
| `POST /v1/random/integers` | key | bounded ints, optional `unique` |
| `POST /v1/random/floats` | key | uniform floats in [0,1) |
| `POST /v1/random/gaussian` | key | normal deviates |
| `POST /v1/random/shuffle` | key | Fisher-Yates permutation |
| `POST /v1/random/sample` | key | draw without replacement |
| `POST /v1/random/weighted` | key | weighted draw with replacement |
| `GET /v1/random/uuid` | key | RFC 4122 v4 |
| `GET /v1/random/dice` | key | dice rolls |
| `GET /v1/random/password` | key | passwords + entropy, `no-store` |
| `POST /v1/beacon/derive` | key | **reproducible** draw from a pulse |
| `GET /v1/beacon/latest` · `/pulse/{n}` · `/chain` · `/verify/{n}` | none | the beacon |
| `GET /v1/beacon/public-key` | none | Ed25519 verification key |
| `GET /v1/me` | key | usage and limits |
| `GET /v1/health` · `/v1/about` | none | source health, claims |
| `POST`/`GET`/`DELETE` `/v1/admin/keys` | admin | key management |

### Tiers

| Tier | Monthly | Burst | Sustained | Max/request |
|---|---|---|---|---|
| free | 1 MB | 30 | 0.5/s | 1 KB |
| starter | 256 MB | 120 | 5/s | 64 KB |
| pro | 4 GB | 600 | 40/s | 1 MB |
| unlimited | — | 5000 | 1000/s | 8 MB |

Configured in [`beamline/config.py`](beamline/config.py).

### API keys

Format `bl_<env>_<key_id>_<secret>`, e.g. `bl_live_7QK4M2XA_9F3TZP0RB6HC8VNJ4WDYKQ2SM5EGL7A`.

- 160-bit secret in Crockford base32 (no `I`/`L`/`O`/`U`)
- Only the SHA-256 is stored; a database leak yields no working keys
- The 8-character `key_id` is indexed, so verification is one indexed lookup and a
  constant-time compare. Unknown key ids are compared against a dummy hash so the
  endpoint does not leak which ids exist
- The env segment means a test key pasted into production fails loudly, and secret
  scanners can pattern-match the format

```bash
beamline keys list
```

```bash
beamline keys revoke 7QK4M2XA
```

---

## Entropy sources and the harvester

| Source | Credit | Notes |
|---|---|---|
| `anu_qrng` | 6.0 bits/byte | quantum vacuum fluctuations; strongest input, third-party transport |
| `local_os` | 8.0 bits/byte | kernel CSPRNG; the one source a remote attacker cannot observe |
| `astro` | **0.0** | NOAA GOES X-ray flux + L1 solar wind + magnetometer. **Public data.** |

Every credited source runs permanent NIST SP 800-90B health tests (Repetition Count and
Adaptive Proportion). A source that dies stuck-at-a-value or collapses in distribution is
quarantined and stops earning credit. Zero-credit sources are deliberately *not*
health-tested — NOAA's packed doubles are full of zero padding and would trip the
repetition test forever, training operators to ignore the one flag that matters.
Live state is at `GET /v1/health`.

### The harvester

Beamline runs on the free public ANU endpoint, so sustained long-run yield is the thing
being optimised — not peak burst rate. Measured on the live endpoint:

| concurrency | throughput | p50 latency | per-connection yield |
|---|---|---|---|
| 1 | 2.55 blocks/s | 326 ms | 2.55 |
| 4 | 8.53 blocks/s | 357 ms | 2.13 |
| 12 | 12.61 blocks/s | 693 ms | 1.05 |

Throughput is still climbing at 12, but latency has doubled and per-connection yield has
fallen 59%: past the knee, extra load buys queue time rather than blocks. That knee moves
with time of day and network conditions, so it is found at runtime rather than
hard-coded.

[`beamline/harvester.py`](beamline/harvester.py) implements a latency-gradient
controller in the style of TCP Vegas — additive increase while latency is flat,
multiplicative decrease when it inflates or errors appear — over a continuous worker
pipeline. (A batched design has to wait for the slowest request in each round before
starting the next; removing that head-of-line barrier was worth **2.9x** throughput on
its own.)

Measured result: **~33 blocks/s sustained, ~200 kbit/s of source entropy**, at 1.01x
baseline latency with zero errors and zero duplicates.

```bash
python scripts/harvest_anu.py --duration 600
```

```bash
python scripts/harvest_anu.py --stats
```

Three properties matter more than raw speed:

- **Deduplication is correctness, not optimisation.** A block served twice carries the
  entropy of one block. Every block is keyed by SHA-256 in an indexed table, and a rising
  duplicate rate is treated as a signal that the endpoint has begun serving from cache —
  at which point the harvester slows down, because asking harder cannot produce new
  entropy.
- **Validation before archival.** An HTML error page is not entropy. Blocks are checked
  against the measured alphabet before being written; live runs have caught and rejected
  malformed responses.
- **Consume-once storage.** Archived blocks are marked when fed to the pool. Replaying
  stored bytes adds no unpredictability, and crediting them twice would corrupt the
  pool's accounting.

Storage packs each character into 6 bits — lossless, and 25% smaller than ASCII.

For production, an official metered API key from
<https://quantumnumbers.anu.edu.au/> removes the dependency on a free public endpoint;
set `BEAMLINE_ANU_API_KEY` and the same code path uses it.

---

## Randomness testing

Full implementations of both NIST suites live in [`beamline/qa/`](beamline/qa/):

- **SP 800-22 Rev 1a** — all 15 statistical tests, with p-value uniformity checking and
  pass-proportion confidence intervals
- **SP 800-90B** — nine of the ten non-IID min-entropy estimators

```bash
python scripts/run_nist_tests.py --target all
```

The suite is validated against known-bad generators — it detects all-zeros, alternating
bits, periodic patterns, a 32-bit counter, RANDU's low bytes, and a coin biased by just
0.5% — while passing `os.urandom` and a SHA-256 counter stream. A test suite that passes
everything is worthless, so that validation runs in CI
([`tests/test_nist.py`](tests/test_nist.py)).

Results on 12 streams of 1,000,000 bits each:

| target | SP 800-22 | min-entropy |
|---|---|---|
| raw ANU blocks, 6-bit packed, unconditioned | **4 / 13** | 0.682 bits/bit |
| conditioned (what enters the pool) | **15 / 15** | 0.846 bits/bit |
| DRBG output (what the API serves) | **15 / 15** | 0.799 bits/bit |
| `os.urandom` (experimental control) | **15 / 15** | 0.717 bits/bit |

The min-entropy column is not a ranking. That estimator has a spread of roughly
0.68–0.90 at these sample sizes — the kernel CSPRNG control itself moved 0.846 to 0.717
between two runs of identical code. Differences inside that band say nothing about the
generator; see [docs/ENTROPY.md](docs/ENTROPY.md).

The unconditioned row failing is the informative one: it is the 63-symbol alphabet
showing through (0.491 ones against an expected 0.500), which is why the pipeline
hash-conditions instead of bit-packing.

On the native 63-symbol alphabet the raw quantum source scores **5.365 bits/symbol** of
min-entropy. A synthetic uniform source measured through the same pipeline at the same
sample size scores 5.317–5.369 — so the ANU stream shows no detectable deviation from
uniform.

Full methodology, the 63-symbol alphabet finding, and an explicit list of what is *not*
implemented: **[docs/ENTROPY.md](docs/ENTROPY.md)**.

What passing means, stated carefully: no implemented test found the structure it was
designed to find. That is evidence of the *absence of specific defects*, not evidence of
unpredictability. A counter encrypted under AES passes every test in SP 800-22.

---

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
    pool.py          SHA-512 accumulator + entropy credit policy
    health.py        SP 800-90B continuous health tests
    drbg.py          HMAC_DRBG(SHA-512), SP 800-90A
    beacon.py        signed hash-chained pulses + derivation
  sources/           anu.py, astro.py, local.py (pluggable)
  api/               FastAPI app, auth dependencies, routes
  qa/                SP 800-22 and SP 800-90B implementations
sdk/python/          client + independent verifier
sdk/js/              client + verifier (WebCrypto)
examples/            user journey demo
scripts/             harvest_anu.py, run_nist_tests.py
```

Adding a physical source — a cosmic-ray detector, a second QRNG vendor — means writing
one `Source` subclass and registering it.

### Testing

```bash
pytest -q
```

Covers DRBG correctness and backtracking resistance, pool credit policy, health-test
failure detection, statistical bias tests on every generator (chi-square across all 24
permutations of a 4-shuffle, modulo-bias checks on non-power-of-two ranges), the
alphabet and packing layer, store deduplication, harvester control-law behaviour, key
handling, beacon chain integrity and tamper detection, HTTP auth/quota/rate limits, and
the NIST suites against known-bad generators.

---

## Configuration

All variables take a `BEAMLINE_` prefix. See [`.env.example`](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `BEAMLINE_ADMIN_TOKEN` | — | required for `/v1/admin/*` |
| `BEAMLINE_BEACON_KEY` | — | Ed25519 private key; unset means unsigned pulses |
| `BEAMLINE_ANU_API_KEY` | — | official metered ANU API |
| `BEAMLINE_BEACON_PERIOD_SECONDS` | 60 | pulse cadence |
| `BEAMLINE_RESEED_SECONDS` | 60 | DRBG reseed interval |
| `BEAMLINE_POOL_DIR` | `data/pool` | harvested block archive |
| `BEAMLINE_DB` | `data/beamline.db` | SQLite path |

---

## Security notes

- **The beacon signing key is the critical secret.** If it leaks, every pulse ever
  signed becomes deniable. It belongs in a KMS or HSM, not an environment variable,
  before the service takes money.
- **Harvested entropy is never committed.** `data/` is gitignored; publishing the seed
  archive would publish the material behind past pulses.
- **Generated passwords are served `no-store`** so they cannot land in a proxy cache.
- **Rate limiting is per-process.** Behind a load balancer the effective ceiling is N×
  the configured rate; the monthly byte quota in SQLite is the hard commercial limit.
  Redis-backed limiting is the fix when running more than one instance.
- Beamline is **not FIPS 140-3 validated** and holds no GLI-19 or iTech Labs RNG
  certification. Regulated gambling requires one; running the NIST suites is not a
  substitute.

## Status

V1, and honest about what that means: the cryptographic core, the beacon, the SDKs, and
the test suites are complete and covered. The hosted draw pages described in
[PRODUCT.md](PRODUCT.md) are not built yet.

## License

MIT — see [LICENSE](LICENSE).
