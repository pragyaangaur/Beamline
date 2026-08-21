# Beamline

Randomness you can prove.

Beamline harvests entropy from a quantum source (the ANU vacuum-fluctuation QRNG), real-time astrophysical measurements (NOAA space weather), and the host kernel CSPRNG. It mixes them in a health-monitored accumulator, and uses the result to seed a NIST SP 800-90A DRBG that serves the API. Every minute it publishes a signed, hash-chained beacon pulse that anyone can verify without an account, which is what lets a draw be shown to be fair after the fact.

[Try it in your browser](https://pragyaangaur.github.io/Beamline/): run a draw against a real signed pulse, then tamper with it and watch the verification fail. Nothing to install, and the page makes no network calls.

```bash
pip install -e ".[dev,qa]"
```

```bash
beamline serve --port 8080
```

## Contents

- [What Beamline is, plainly](#what-beamline-is-plainly)
- [Quick start](#quick-start)
- [The beacon](#the-beacon)
- [Demos](#demos)
- [API reference](#api-reference)
- [Entropy sources and the harvester](#entropy-sources-and-the-harvester)
- [Entropy accounting](#entropy-accounting)
- [Randomness testing](#randomness-testing)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Security notes](#security-notes)
- [Product direction](#product-direction)
- [Status](#status)
- [License](#license)

## What Beamline is, plainly

Two facts govern how everything here is built. Both are stated up front because they are the two most easily oversold.

**API responses are DRBG output seeded by physical entropy, not raw quantum measurements piped to a socket.** That is how every hardware RNG in production works, including `/dev/urandom` and every QRNG vendor's driver stack. It is the correct design. A network entropy source is finite and slow, and mixing it with the local kernel CSPRNG means an attacker has to compromise every source rather than just the one being resold.

**The astrophysical data is public.** NOAA serves the same bytes to everyone, so it contributes zero secret entropy and is credited 0.0 bits in [`beamline/entropy/pool.py`](beamline/entropy/pool.py). It is mixed in for provenance, because it timestamps a pulse against an independently observable physical record, and not for secrecy.

`GET /v1/about` returns these claims in machine-readable form, and a test fails the build if the code and the claims drift apart.

### Where Beamline is not the right tool

Nowhere, for generating private keys. Randomness fetched over a network is randomness someone else could have observed, so for key material the operating system is the correct source. A well-seeded CSPRNG is computationally indistinguishable from ideal, and there is no attack that a quantum source prevents and ChaCha20 does not.

Beamline is for the case where randomness has to be publicly verifiable, where "trust us, it was random" is not an acceptable answer:

- Raffles, giveaways, lotteries, tournament seeding, loot drops
- Audit and compliance sampling that has to be defended afterwards
- Research and simulation where a third party must reproduce a draw
- Any drawing where the operator is also an interested party

The reasoning behind that positioning is in [Product direction](#product-direction).

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
curl -s http://127.0.0.1:8080/v1/random/integers -H "Authorization: Bearer bl_live_..." -H "Content-Type: application/json" -d '{"count":6,"min":1,"max":49,"unique":true}'
```

Interactive API docs are served at `/docs`.

## The beacon

Every `BEAMLINE_BEACON_PERIOD_SECONDS` (default 60), the service publishes a pulse:

```
output = SHA-512("beamline/pulse/v2" | canonical_json(
             round, timestamp_ms, period, prev_output,
             local_value, public_key, provenance))
```

The pulse is signed with Ed25519 and chained through `prev_output`. Beacon endpoints are unauthenticated on purpose: verification has to work for a sceptic who has no account, and charging for it would defeat the product.

Two details in that body exist because of failures found while testing the Python and JavaScript verifiers against each other, and both matter more than they look.

**`public_key` sits inside the signed body.** Each pulse declares the key that signed it, so rotating the signing key becomes an auditable event rather than a silent break. Without it, every historical pulse simply stops verifying against the current key, and a verifier has no way to distinguish an honest rotation from a substituted archive. The chain verifier reports the round at which a key changed.

**`timestamp_ms` is an integer, not a float.** A float that lands on a whole second serialises as `1787150090.0` in Python and `1787150090` in JavaScript. The canonical bytes then differ and verification fails, for roughly one pulse in a thousand, silently, and only for the cross-language verifiers the product depends on. Integers serialise identically everywhere.

### Running a provably fair draw

1. Publish the `tag` first: a draw id, an entry-list hash, an order number.
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

`draw.verify()` makes zero server calls. It recomputes the numbers from the pulse using [`sdk/python/beamline_client/verify.py`](sdk/python/beamline_client/verify.py), which shares no code with the server and reimplements the spec from scratch. That independence is the point: a verifier that imports the server's own functions proves only that the server agrees with itself.

A JavaScript verifier ([`sdk/js/index.js`](sdk/js/index.js)) does the same in the browser via WebCrypto, and its canonical serialisation is byte-identical to the Python implementation.

### Trust model, stated honestly

The chain proves ordering and tamper-evidence. It does not, by itself, prove the operator never withheld a pulse they disliked and waited for the next one. That would be caught by observers watching live, and by the astrophysical provenance no longer lining up, which is the same trust model as the NIST Randomness Beacon. Publishing the tag in advance closes the gap on the customer's side. Anchoring pulse hashes to an external append-only log closes it on the operator's side, and is on the roadmap rather than in the code.

## Demos

### The interactive demo

[pragyaangaur.github.io/Beamline](https://pragyaangaur.github.io/Beamline/) is the public demonstration, served from [`docs/`](docs/). It is a single self-contained file with ten real signed pulses baked into it, and it does three things a description cannot.

First, it runs a draw. Name it, choose the pulse that will fix it, and the winners are derived in the browser by the same rejection sampling the server uses. Run it twice for identical numbers. Change one character of the name and the numbers are entirely different, with no way to steer them anywhere in particular.

Second, it invites tampering. Every field of the pulse is editable, with one-click shortcuts for rewriting the entropy, backdating the timestamp, forging the signature, and swapping the output hash the winners are derived from. Four checks then report precisely what broke. Rewriting the output really does change the winners, which is the part worth seeing: the numbers can be moved, and the move is visible to anyone who runs the checks.

Third, it lets a visitor rewrite history. Altering round 5 leaves the pulse after it no longer fitting, and repairing that one moves the break forward. Repair the whole chain and it becomes internally consistent again, with six pulses that no longer carry a valid signature. Rewriting a chain is arithmetic anyone can do. Re-signing it needs the private key.

The verifier on that page shares no code with the server: it reimplements the pulse and derivation spec from scratch, and its output was cross-checked against `beamline.generators` for both the dense and the sparse sampling strategy. [`tests/test_site.py`](tests/test_site.py) re-verifies the embedded chain with the Python SDK on every test run, because a published page that demonstrates Beamline's own verification failing would be worse than having no page at all.

The embedded pulses come from a real service run rather than a fixture. Regenerate them with:

```bash
python scripts/build_site_data.py --rounds 10 --spacing 6
```

That starts the service against a throwaway database, lets the entropy sources poll, emits a signed chain, and injects it back into the page. To publish the result, point Settings then Pages at the `main` branch and the `/docs` folder.

### The user journey

The fastest way to understand what Beamline feels like in use:

```bash
beamline serve --port 8080
```

```bash
BEAMLINE_ADMIN_TOKEN=... python examples/user_journey.py
```

Six scenes run against a live local server, with nothing mocked: a developer gets a key and makes a first call, the everyday generator calls (passwords, UUIDs, dice, weighted picks), a creator runs a giveaway their audience can audit, a sceptical viewer verifies that giveaway without an account, two cheating attempts get caught, and an auditor pulls a defensible compliance sample.

### The public draw page

[`examples/draw_page.html`](examples/draw_page.html) is the customer-facing artifact: a public draw record for a giveaway. Open it in a browser and press "Verify in this browser".

The page carries a real beacon pulse, including its round, timestamp, output hash, Ed25519 signature, and the NOAA space-weather readings mixed into it. The verify button then does the whole check client-side with WebCrypto: it recomputes the pulse output hash from the pulse contents, re-derives the winning numbers from that hash using the same rejection sampling the server used, and checks the Ed25519 signature against the key the pulse declares. There is no server call, no API key, and no need to trust whoever ran the draw. Altering any field in the embedded pulse makes the check fail, which is the point.

The embedded data was captured from a live Beamline instance. The draw itself is an illustration. `examples/_draw_data.json` holds the same payload separately for anyone who wants to rebuild the page.

That page is the record of one finished draw. The interactive demo above is the version where the visitor chooses the draw, edits the pulse, and breaks the chain themselves.

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

### Tiers

| Tier | Monthly | Burst | Sustained | Max per request |
|---|---|---|---|---|
| free | 1 MB | 30 | 0.5/s | 1 KB |
| starter | 256 MB | 120 | 5/s | 64 KB |
| pro | 4 GB | 600 | 40/s | 1 MB |
| unlimited | none | 5000 | 1000/s | 8 MB |

Tiers are configured in [`beamline/config.py`](beamline/config.py).

### API keys

Keys have the format `bl_<env>_<key_id>_<secret>`, for example `bl_live_7QK4M2XA_9F3TZP0RB6HC8VNJ4WDYKQ2SM5EGL7A`.

The secret is 160 bits in Crockford base32, which excludes `I`, `L`, `O`, and `U` to avoid transcription errors. Only the SHA-256 is stored, so a database leak yields no working keys. The 8-character `key_id` is stored in the clear and indexed, which makes verification a single indexed lookup followed by a constant-time compare. An unknown key id is compared against a dummy hash so the endpoint does not leak which ids exist. The environment segment means a test key pasted into production fails loudly instead of silently working, and lets secret scanners pattern-match the format.

```bash
beamline keys list
```

```bash
beamline keys revoke 7QK4M2XA
```

## Entropy sources and the harvester

| Source | Credit | Notes |
|---|---|---|
| `anu_qrng` | 6.0 bits/byte | quantum vacuum fluctuations, the strongest input, delivered over a third party's TLS |
| `local_os` | 8.0 bits/byte | kernel CSPRNG, the one source a remote attacker cannot observe |
| `astro` | 0.0 | NOAA GOES X-ray flux, L1 solar wind, and magnetometer. Public data. |

Every credited source runs permanent NIST SP 800-90B health tests (Repetition Count and Adaptive Proportion). A source that dies stuck at a value, or whose distribution collapses, is quarantined and stops earning credit. Zero-credit sources are deliberately not health-tested: NOAA's struct-packed doubles are full of zero padding and would trip the repetition test forever, which would train whoever is on call to ignore the one flag that actually matters. Live state is exposed at `GET /v1/health`.

### The harvester

Beamline runs on the free public ANU endpoint, so sustained long-run yield is the thing being optimised, not peak burst rate. Measured on the live endpoint at 24 requests per level over HTTP/1.1 with keep-alive:

| Concurrency | Throughput | p50 latency | Per-connection yield |
|---|---|---|---|
| 1 | 2.55 blocks/s | 326 ms | 2.55 |
| 4 | 8.53 blocks/s | 357 ms | 2.13 |
| 12 | 12.61 blocks/s | 693 ms | 1.05 |

Throughput is still climbing at 12, but latency has doubled and per-connection yield has fallen 59 percent. Past the knee, extra load buys queue time rather than blocks. That knee moves with time of day and network conditions, so it is found at runtime rather than hard-coded.

[`beamline/harvester.py`](beamline/harvester.py) implements a latency-gradient controller in the style of TCP Vegas, with additive increase while latency is flat and multiplicative decrease when it inflates or errors appear, running over a continuous worker pipeline. A batched design has to wait for the slowest request in each round before starting the next, and removing that head-of-line barrier was worth 2.9x throughput on its own.

Measured result: about 33 blocks per second, roughly 200 kbit/s of source entropy, at 1.01x baseline latency with zero errors and zero duplicates.

```bash
python scripts/harvest_anu.py --duration 600
```

```bash
python scripts/harvest_anu.py --stats
```

Three properties matter more than raw speed.

**Deduplication is correctness, not optimisation.** A block served twice carries the entropy of one block. Every block is keyed by SHA-256 in an indexed table, and a rising duplicate rate is treated as a signal that the endpoint has begun serving from cache, at which point the harvester slows down, because asking harder cannot produce new entropy.

**Validation happens before archival.** An HTML error page is not entropy. Blocks are checked against the measured alphabet before being written, and live runs have caught and rejected malformed responses.

**Storage is consume-once.** Archived blocks are marked when they are fed to the pool. Replaying stored bytes adds no unpredictability, and crediting them twice would corrupt the pool's accounting. Storage packs each character into 6 bits, which is lossless and 25 percent smaller than ASCII.

For production, an official metered API key from <https://quantumnumbers.anu.edu.au/> removes the dependency on a free public endpoint. Setting `BEAMLINE_ANU_API_KEY` makes the same code path use it.

## Entropy accounting

How much unpredictability Beamline believes it has, where that belief comes from, and where it deliberately refuses to give credit. The governing rule is that an entropy source gets credited the conservative rate, never the measured one, because measured estimates on a source nobody controls are how operators talk themselves into trusting a source that has quietly died.

### The source alphabet is 63 symbols, not 64

The ANU public endpoint returns 1024-character blocks. They look like base64url, and assuming base64url gives 6.0 bits per character. That assumption is wrong. Measured over 113,664 harvested characters:

| Property | Value |
|---|---|
| distinct symbols | 63, that is `[0-9A-Za-z_]`, base64url without `-` |
| Shannon entropy | 5.9768 bits/char |
| theoretical max for 63 symbols | 5.9773 bits/char |
| blocks harvested and unique | 111 and 111 |

The `-` character is genuinely absent rather than rare. Under a uniform 64-symbol model, the probability of never seeing it in 113,664 draws is about e^-1800.

So each character carries log2(63) = 5.9773 bits, and a 1024-character block carries 6,120 bits rather than the 6,144 a base64url assumption would claim. The gap is 0.4 percent, which is small, but it runs the wrong way, and entropy accounting is the one place where optimism compounds into a false claim. [`beamline/entropy/blocks.py`](beamline/entropy/blocks.py) uses the measured figure everywhere: conditioning output length, the harvester's reported bit rate, and the store's entropy totals.

There is a visible consequence. Packing 63 symbols into 6 bits leaves code point 63 unused, so a naively packed raw stream is biased toward zero bits: the average popcount per group is 2.952 instead of 3.0, a 1.6 percent deficit. That is far too large to hide, and the `raw-packed` target in the test runner exists specifically to show it failing. It is the concrete reason the pipeline hash-conditions instead of bit-packing.

### Credit policy

The ANU figure is deliberately conservative in a way that is easy to miss. A 1024-character block holds about 6,120 bits and conditions down to 765 bytes. Crediting those at 6 bits per byte counts 4,590 bits against a source that supplied 6,120. That 25 percent haircut is the margin held back for the fact that the bytes arrived over someone else's TLS connection.

The `astro` source earning zero is the load-bearing honesty in this system. NOAA serves identical bytes to everyone, so the data cannot be secret, and a design that credited it would be claiming security it does not have. It is mixed in anyway, because mixing a public value into a hash accumulator can never reduce entropy, and because it timestamps beacon pulses against an independently observable physical record.

## Randomness testing

Full implementations of both NIST suites live in [`beamline/qa/`](beamline/qa/): SP 800-22 Rev 1a with all 15 statistical tests, p-value uniformity checking, and pass-proportion confidence intervals; and SP 800-90B with nine of the ten non-IID min-entropy estimators.

```bash
pip install -e ".[qa]"
```

```bash
python scripts/run_nist_tests.py --target all --streams 12 --json reports/nist-report.json
```

The suite is validated against known-bad generators. It detects all-zeros, all-ones, alternating bits, periodic patterns, a 32-bit counter, RANDU's low bytes, and a coin biased by just 0.5 percent, while passing `os.urandom` and a SHA-256 counter stream. A test suite that passes everything is worthless, so that validation runs in CI as part of [`tests/test_nist.py`](tests/test_nist.py).

### Results

Four targets answer different questions. The `urandom` target is an experimental control: the identical pipeline run against the host kernel CSPRNG, so a quirk in the harness shows up there too and can be told apart from a finding about Beamline.

| Target | What it is | SP 800-22 | p-value uniformity | Min-entropy |
|---|---|---|---|---|
| `raw-packed` | harvested blocks, 6-bit packed, no conditioning | 4 / 13 | 0.000000 | 0.682 bits/bit |
| `conditioned` | what actually enters the entropy pool | 15 / 15 | 0.555 | 0.846 bits/bit |
| `drbg` | what the API serves | 15 / 15 | 0.005 | 0.799 bits/bit |
| `urandom` | host kernel CSPRNG (control) | 15 / 15 | 0.255 | 0.717 bits/bit |

Twelve streams of 1,000,000 bits per target. The SP 800-22 column counts tests whose pass proportion sits inside the SP 800-22 section 4.2.1 confidence interval.

### The raw source fails on purpose, and that is the useful result

`raw-packed` fails nine of thirteen tests with monobit p = 0.000000 across every stream. That is not a defect in the quantum source, it is the 63-symbol alphabet showing through. Measured on the real archive, the packed stream runs at 0.491 ones against an expected 0.500.

Two things follow, and both matter more than a passing grade would. The suite has real detection power on real data, not just on synthetic defects. And bit-packing the ANU stream and shipping it would be a broken product, so hash conditioning is load-bearing, with the `conditioned` row showing it working.

Note also that `raw-packed` still holds 0.682 bits per bit of min-entropy while failing almost every statistical test. The two suites answer different questions: SP 800-22 detects structure, SP 800-90B measures worst-case unpredictability. A small bias is statistically obvious over a million bits while costing very little entropy.

### The raw quantum source, on its native alphabet

Assessed over 400,000 harvested symbols on the native 63-symbol alphabet, non-IID track:

| Estimator | Bits per symbol |
|---|---|
| Most Common Value | 5.893 |
| Markov | 5.365 |
| t-Tuple | 5.724 |
| Longest Repeated Substring | 5.826 |
| Lag Prediction | 5.458 |
| MultiMMC Prediction | 5.458 |
| LZ78Y Prediction | 5.458 |
| Collision | skipped, binary-only implementation |
| MultiMCW | skipped, binary-only implementation |
| **Min-entropy, worst estimator** | **5.365** |

That number should be compared against the right baseline, not the theoretical maximum. SP 800-90B's non-IID estimators are deliberately conservative at finite sample sizes and do not return the maximum even for a perfect source. A synthetic uniform 63-symbol generator scored through this same pipeline, at the same 400,000-symbol size, produced 5.317, 5.369, 5.332, and 5.333 across four trials, with a median of 5.333.

The harvested ANU stream scores 5.365, which sits inside the range an ideal uniform source produces under identical measurement. The correct reading is that the quantum source shows no detectable deviation from uniform, not that it is "better than random", which is not a meaningful claim.

### Min-entropy is not a ranking

The SP 800-90B prediction estimators bound entropy partly by the longest run of correct predictions, and one extra correct prediction moves the figure noticeably. Re-running this identical suite against identical code produced:

| Target | Run A | Run B |
|---|---|---|
| `conditioned` | 0.846 | 0.846 |
| `drbg` | 0.682 | 0.799 |
| `urandom` | 0.846 | 0.717 |

The kernel CSPRNG, which is the control and by construction the reference for correct behaviour, moved from 0.846 to 0.717 between runs on its own. The estimator's spread at these sample sizes is roughly 0.68 to 0.90 bits per bit, so differences inside that band carry no information about the generator. All three streams behave identically against the control, which is the only conclusion the data supports. Reporting a single run's number as a quality score for one stream over another would be reading noise.

One value is worth naming rather than glossing over: `drbg` p-value uniformity came in at 0.0048 on run B. SP 800-22 section 4.2.2 sets the uniformity threshold at 0.0001, so this passes by a wide margin, and a uniformity p-value is itself uniform under the null, so one low draw across several targets is expected. It is recorded here rather than rounded away, because a suite that only ever reports comfortable numbers is not being run honestly.

### What passing means

No implemented test found the structure it was designed to find. That is evidence of the absence of specific defects, not evidence of unpredictability. A counter encrypted under AES passes every test in SP 800-22 and is perfectly predictable to whoever holds the key. No statistical suite can distinguish a good PRNG from a true RNG, and any vendor claiming otherwise is overselling.

### What is not implemented

**SP 800-90B section 6.3.4, the Compression estimate.** Its G(z) inversion needs a series from the publication that is not reproduced here, and a wrong estimator that reports a confident number is worse than an absent one. Because the final figure is a minimum over estimators, omitting one can only push the reported entropy higher than a complete run would, so the headline number should be read as an upper bound on what the full suite would return.

**The Collision and MultiMCW estimators for non-binary alphabets.** Both use binary-only shortcuts and sit out rather than approximate.

**The SP 800-90B IID track**, meaning permutation testing. The non-IID track is the correct and conservative choice for a source with any memory or drift, which is the safe assumption for a network-delivered source.

**Independent certification.** Beamline is not FIPS 140-3 validated and holds no GLI-19 or iTech Labs RNG certification. Anything sold into regulated gambling needs one, and running this suite is not a substitute for it.

A full run takes several minutes. The SP 800-90B prediction estimators are O(n) with per-sample dictionary work and dominate the runtime, so `--entropy-bits` trades assessment depth for time. Available targets are `raw-symbols`, `raw-packed`, `conditioned`, `drbg`, `urandom`, or `all`.

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
examples/            user journey demo, public draw page
scripts/             harvest_anu.py, run_nist_tests.py
data/                runtime state, never committed
```

Adding a physical source, such as a cosmic-ray detector or a second QRNG vendor, means writing one `Source` subclass and registering it.

### The data directory

Nothing under `data/` is committed. `pool/anu-NNNNNN.bin` holds harvested ANU blocks packed at 6 bits per character, `pool/index.db` holds block hashes for deduplication plus consume-once bookkeeping, and `beamline.db` holds API key hashes, usage counters, and the beacon pulse chain.

There are two reasons this stays out of version control. The archive is the raw entropy that seeded beacon pulses which have already been published and signed, so releasing it would expose the material behind them. And `beamline.db` holds key hashes and usage history. Populate the archive with `python scripts/harvest_anu.py --duration 600`.

### Testing

```bash
pytest -q
```

239 tests cover DRBG correctness and backtracking resistance, pool credit policy, health-test failure detection, statistical bias tests on every generator (including a chi-square across all 24 permutations of a 4-element shuffle and modulo-bias checks on non-power-of-two ranges), the alphabet and packing layer, store deduplication, harvester control-law behaviour, key handling, beacon chain integrity and tamper detection, signing-key rotation, HTTP auth, quotas and rate limits, and the NIST suites against known-bad generators.

There is also a statistical smoke test of the shaping layer:

```bash
beamline selftest -n 200000
```

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

## Security notes

**The beacon signing key is the critical secret.** If it leaks, every pulse ever signed becomes deniable. It belongs in a KMS or HSM, not an environment variable, before the service takes money.

**Harvested entropy is never committed.** `data/` is gitignored, and publishing the seed archive would publish the material behind past pulses.

**Generated passwords are served `no-store`** so they cannot land in a proxy cache.

**Rate limiting is per-process.** Behind a load balancer the effective ceiling is N times the configured rate. The monthly byte quota in SQLite is the hard commercial limit, and Redis-backed limiting is the fix when running more than one instance.

**Beamline is not FIPS 140-3 validated** and holds no GLI-19 or iTech Labs RNG certification. Regulated gambling requires one, and running the NIST suites is not a substitute.

## Product direction

The engineering in this repository is the easy half. This section is the harder half: what the product actually is, who pays for it, and why the most obvious framing is the wrong one.

### Why "true random numbers for security and cryptography" does not sell

It is the pitch that feels most natural for a service like this, and it will not work. Three reasons, in increasing order of how much they matter.

**Every machine already has a better answer, for free.** `/dev/urandom`, `getrandom(2)`, `BCryptGenRandom`, and `crypto.randomBytes` are all kernel CSPRNGs seeded from hardware entropy, all audited far more heavily than this codebase will ever be, all instantaneous, and all free. A developer who needs 32 bytes for an AES key has no unmet need.

**Network delivery makes randomness worse for secrets, not better.** Key material fetched over HTTP existed on someone else's server, traversed someone else's TLS termination, and sat in someone else's memory. That asks a security-conscious buyer to add a third party to the most sensitive operation in their stack. The correct advice, which Beamline's own `/v1/about` endpoint gives, is not to do that. A product whose honest documentation tells you not to use it for its advertised purpose is not a product.

**"Truer" randomness has no security value above the threshold.** A CSPRNG seeded with 256 bits of genuine entropy is computationally indistinguishable from ideal. No attack exists that a quantum source prevents and a well-seeded ChaCha20 does not. The marginal buyer gets nothing measurable.

The failure mode is not "few customers". It is that the customers who do arrive are buying on a misconception, and the technically strong ones, the ones with budget, spot it in the first five minutes and leave. Some competitors sell this framing successfully as marketing. It does not hold up as a durable business. So: keep the physics, change the claim.

### What people will pay for is randomness that can be proved

The thing a customer genuinely cannot produce alone is not unpredictability. It is unpredictability a third party will believe.

Whenever someone runs a draw in which they are also an interested party, "we picked fairly" is worth nothing, because they would say that either way:

- A creator running a $5,000 giveaway, accused by their own audience of picking a friend
- A marketplace assigning limited inventory, product drops, or launch slots
- An auditor pulling 200 transactions from 4 million, who must show the sample was not chosen to look clean
- A tournament seeding a bracket where the organiser has a favourite
- A game studio whose loot-box odds are under regulatory scrutiny
- A DAO, a research trial, a jury pool, a housing lottery, a school placement

Every one has the same shape: a decision that must be defensible afterwards to someone who assumes you cheated. That is not a randomness problem, it is an evidence problem, and evidence is something you can charge for, because the alternative is a lawyer, an auditor, or a public relations crisis.

That is what the beacon in [`beamline/entropy/beacon.py`](beamline/entropy/beacon.py) provides, and it is the only part of Beamline that `/dev/urandom` cannot replace. Everything else in the codebase exists to make the beacon credible.

Prior art validates the shape, and also the risk: the NIST Randomness Beacon, drand and the League of Entropy, and random.org's paid signed-draw service. random.org is the closest commercial comparison, a real business built almost entirely on verifiable public draws rather than on selling bytes.

The reframe is this. Beamline is the fairness layer for anything drawn, picked, or sampled in public. The quantum and astrophysical sourcing is what makes the claim credible and the story worth telling. The verifiable beacon is what makes it a business. The physics is not decoration, since the astrophysical provenance genuinely timestamps a pulse against an independently observable physical record and the quantum source is real, but it is the supporting claim, not the headline.

### Product forms, ranked

**Tier 1, build next.**

*Hosted public draw pages.* A customer creates a draw, gets a public URL, and publishes it before the pulse exists. Afterwards the page shows entrants, the pulse, the result, and a "verify this yourself" button running the JavaScript verifier client-side. The page is the product and the API is plumbing. This is the whole business in one artifact, and it is shareable: every draw page markets Beamline to an audience already primed to be suspicious, which is precisely the audience that converts. It prices at $19 to $99 per month to businesses, not $5 to developers. A working prototype of the verification half is in [`examples/draw_page.html`](examples/draw_page.html).

*Verification as a free public good.* Verifier libraries, a `/verify` web page, the chain, and the public key: free, unauthenticated, forever. The asymmetry is the moat. Anyone can check a Beamline draw, but only customers can make one, and free verification is what makes the paid side worth anything. The interactive demo in [`docs/`](docs/) is the first piece of this: a stranger can run a draw, tamper with the pulse, and rewrite the chain without an account or an API key.

**Tier 2, natural follow-ons.**

*Compliance sampling.* Upload a population, get a defensible sample plus a PDF methodology statement citing the pulse. This sells to internal audit and quality teams who already pay real money for far less, and carries the highest revenue per customer by a wide margin.

*Provably-fair SDK for games.* Commit-reveal built on the beacon: the server commits to a seed hash, the pulse supplies public entropy, and the player verifies the drop. The crypto-casino world already demands this, and the mechanism generalises to any game with published odds.

*Webhooks and scheduled draws.* "Every Friday at 16:00 UTC, draw 3 winners from this list and POST the result." This turns a one-off into recurring revenue.

**Tier 3, later or never.**

*Bulk entropy for simulation.* Monte Carlo shops want reproducibility and speed, which a seeded PRNG already gives them. The angle is a certified, timestamped seed: one API call, then run a local Mersenne Twister. Sell seeds, not streams.

*Hardware.* A muon detector or an owned optical source removes the ANU dependency and creates something defensible. Interesting at scale, a distraction at V1.

### Pricing

The $5 to $10 per month instinct prices this as a developer utility, which is the wrong category. Utilities compete with free. Evidence products compete with the cost of not having evidence.

| Plan | Price | Who | What they get |
|---|---|---|---|
| Free | $0 | everyone | 1 MB/month, public draws with Beamline branding, full verification |
| Creator | $19/mo | streamers, small brands | unbranded draw pages, 50 draws/month, webhooks |
| Business | $99/mo | marketplaces, studios | API and draws, custom domain, PDF certificates |
| Audit | $499/mo | internal audit, compliance | methodology docs, retention guarantees, SSO |
| Enterprise | custom | gaming, regulated | SLA, dedicated beacon, audit support |

A metered developer tier is worth keeping, since it is how people discover the service and costs almost nothing to serve, but it should not define the company.

The arithmetic that settles it: at $5 to $10 per month, roughly 1,000 paying developers are needed to reach $100k ARR, in a category whose incumbent is a free system call. At $99 per month, 85 businesses that run public draws get to the same place. The second number is much smaller, and those customers have a real problem.

### Risks

**The ANU dependency is the largest technical risk.** It is a free endpoint at a university, with no contract, no SLA, and no obligation to anyone. If it disappears, the headline claim disappears with it. The mitigation, when budget allows, is the metered API key. Until then, the harvester is built to stay inside the endpoint's measured capacity precisely because getting blocked would take yield to zero permanently. A second QRNG vendor would remove the single point of failure entirely, and the pool already supports it, so adding one means writing a single `Source` subclass.

**Key rotation is handled, key compromise is not.** Each pulse carries the key that signed it, so a rotation is visible and auditable rather than silently invalidating history. That does not help if the key leaks. Beacon signing key compromise is the extinction event: every pulse ever signed becomes deniable, so the key belongs in a KMS or HSM before the service takes money.

**Withholding is the honest gap in the trust model.** The chain proves ordering and tamper-evidence, not that an operator never re-rolled a pulse they disliked. Mitigations, in rough order of effort: publish pulse hashes to a third party such as a transparency log, a public repository, or another beacon, so withholding becomes externally visible; run threshold or multi-party pulse generation in the style of drand; anchor periodically to a public chain. This limitation belongs in the documentation, since the NIST beacon states it plainly and the credibility gained from naming a weakness exceeds what hiding it would buy.

**Regulated gaming needs certification that does not exist yet.** No sales into licensed gambling before an independent RNG audit under GLI-19 or iTech Labs. Adjacent non-regulated use is fine and is a large market by itself.

**Statistical claims need evidence, and have it up to a point.** The NIST SP 800-22 and SP 800-90B suites are implemented and validated against known-bad generators, with results above. Running dieharder, PractRand, or TestU01 BigCrush against `/v1/random/bytes` and publishing those results too would close the remaining gap. None of it substitutes for certification.

### Order of work

1. Move the beacon key to a KMS, before the first paying customer.
2. Build the hosted draw page, since it is the product and everything it needs already exists.
3. Publish the verifier as `@beamline/verify` on npm and PyPI, with the pulse spec as a standalone document, because verification credibility compounds.
4. Mirror pulse hashes to a public append-only log, which closes the withholding gap enough to matter in enterprise conversations.
5. Find five design partners running real public draws: a creator, a marketplace, an internal auditor. Their objections determine which of Tier 2 gets built.
6. Buy the ANU metered API key when revenue justifies it, and add a second QRNG vendor for source independence.

## Status

V1, and honest about what that means. The cryptographic core, the beacon, both SDKs, and the test suites are complete and covered. The hosted draw pages described above are not built yet, beyond two verification prototypes: the static draw record in `examples/` and the interactive demo in `docs/`.

## License

MIT. See [LICENSE](LICENSE).
