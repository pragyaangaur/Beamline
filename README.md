# Beamline

**Provably fair draws.** Pick winners, sample records, or shuffle anything, and hand
everyone a result they can check for themselves.

[**Try it in your browser →**](https://pragyaangaur.github.io/Beamline/) Run a draw, then
try to rig it. Nothing to install.

[**Or try to break it →**](https://pragyaangaur.github.io/Beamline/challenge.html) Predict
the next value the live beacon publishes, before it publishes it. There is a prize.

```bash
pip install -e ".[dev,qa]"
```

```bash
beamline serve --port 8080
```

## Contents

- [What it does](#what-it-does)
- [Try it](#try-it)
- [Try to break it](#try-to-break-it)
- [The standing challenge](#the-standing-challenge)
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

The randomness underneath comes from three sources, mixed in a health-monitored
accumulator that seeds a NIST SP 800-90A DRBG:

- **A quantum source.** The Australian National University measures vacuum fluctuations
  of the electromagnetic field and publishes the result; Beamline reads their public
  endpoint. The device is ANU's, not ours, and the bytes arrive over their TLS
  connection — which is why they are credited 6 bits per byte rather than 8.
- **Live NOAA space weather.** X-ray flux, solar wind, magnetometer. **Credited zero
  bits**, and deliberately: it is public data, so anyone can fetch the same readings and
  it can hold no secret. It is in the mix for provenance and timing — a pulse's
  provenance names the NOAA readings it consumed, which anyone can re-fetch to confirm
  the pulse was not produced before that data existed.
- **The host kernel CSPRNG.** The one input an external attacker cannot observe, and
  the reason predicting a pulse is hard. Every extraction folds in a fresh
  `os.urandom(64)` before hashing.

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

**No browser and no Python?** `beamline verify --draw record.json` checks a published
record offline and exits non-zero if it does not hold up. Verification should not require
being a programmer — the person who most needs it is the entrant who lost.

## Try to break it

The claim is narrow on purpose: **you cannot predict a pulse before it is published,
and you cannot make a verifier accept a draw that was not fixed in advance.** If you can
do either, the code is wrong and I want to know — and there is
[a month of Claude Pro](#the-standing-challenge) in it for whoever shows me first.

What a break looks like, in order of how much it would matter:

| Claim | How to show it |
|---|---|
| Predict a pulse | Publish `output` for a round before that round's timestamp. Any method. |
| Forge a chain a verifier accepts | Any chain that passes `check_chain` against the published key without the key. |
| Pass a draw that was not committed | Any result `check_draw` accepts where the tag, round or shape was chosen after the pulse. |
| Two verifiers disagree | One pulse where Python and JavaScript reach different verdicts. |
| Bias the output | A statistical argument against `drbg` output with enough samples to be convincing. |

Three things that are **not** breaks, because they are already documented limits:

- **The operator withholding a pulse and re-rolling.** Beamline can emit a pulse,
  dislike it, and publish the next one instead. This is real, it is in the
  [threat model](#threat-model), and closing it needs external anchoring that is not
  built. Demonstrating it is confirming a known gap, not finding one.
- **Reading raw source bytes over the network.** The ANU stream arrives over a third
  party's TLS and is credited 6 bits per byte for that reason. Intercepting it does not
  predict a pulse, because every extraction folds in a fresh `os.urandom(64)`.
- **`raw-packed` failing SP 800-22.** It is meant to. See
  [Randomness testing](#randomness-testing) — that failure is the evidence the suite has
  detection power, and the conditioned stream is what enters the pool.

The fastest way in is [`tests/test_attacks.py`](tests/test_attacks.py): every attack that
once worked against this codebase, kept as a test. If you find one it does not cover,
that is the interesting case.

```bash
beamline verify --draw record.json --public-key <key you recorded yourself>
```

Four of those five need nothing but this repository — no luck, no beacon, no waiting.
The first one needs a beacon that is actually running, which is what the next section is
for. It is also the one you are least likely to win, and it is worth being clear about
why: the target is 512 bits, so guessing is not a strategy. The other four are.

## The standing challenge

**A month of Claude Pro to the first person who breaks any row of the table above.**
One prize, first demonstration takes it, and the terms are in this file — in public
version control, where an edit after somebody wins is itself a public record.

[**The challenge page**](https://pragyaangaur.github.io/Beamline/challenge.html) is the
easy way in.

### How a prediction is timestamped, and why not by me

A prediction is a [GitHub issue](../../issues/new?template=prediction.yml). That is not
a shortcut around running a server — it is the answer to the only hard problem the
challenge has.

The claim under test is an *ordering*: that your guess existed before the value did.
Whoever timestamps both sides of that comparison decides who wins. It should not be me,
and until recently it was: predictions went to an API I ran, which stamped them with my
clock, my ordering, and my option to lose an inconvenient one. A challenger who won
would have been appealing to the honesty of the person the win embarrasses.

So both sides moved to records held by somebody with no stake:

| | Stamped by | Public artefact |
|---|---|---|
| Your prediction | GitHub, on issue creation | the issue's `created_at` |
| The pulse | GitHub Actions, on commit | the commit, and the run log |

The rule is then mechanical, and you can audit it: an issue is scored against a pulse
only if it was created before that pulse's timestamp. An issue that arrives afterwards
is not refused — it simply waits for the next round, because the ordering is a fact
about two clocks rather than a decision anyone makes. Resolution is string equality,
and every input to it is public.

The beacon runs from [`.github/workflows/beacon.yml`](.github/workflows/beacon.yml),
emitting one signed pulse roughly every ten minutes into
[`beacon/chain.json`](beacon/chain.json). That file holds a rolling window; the full
history is its git log, which is append-only and public. Scoring is
[`scripts/resolve_predictions.py`](scripts/resolve_predictions.py), and the rule above
lives in one pure function, `adjudicate`, tested in
[`tests/test_beacon_jobs.py`](tests/test_beacon_jobs.py).

Verify any pulse yourself rather than trusting the page:

```bash
beamline verify --pulse beacon/chain.json
```

### What you are actually up against

**The target is the full 512-bit output, not a small number.** A one-in-a-hundred guess
gets won by luck roughly once every hundred tries, which would cost a prize and prove
nothing about the beacon. The claim under test is unpredictability, so the target is the
entire published value — about 1.34 × 10^154 possibilities, against roughly 10^80 atoms
in the observable universe.

Nobody is going to win by guessing, and saying so is not a hedge. It is why the other
four rows of that table are worth far more of your time: they need no luck at all, and
the same prize is on offer for any of them.

**Losing attempts are still the point.** Each is scored on how many leading bits it
shared with the real output — a geometric(1/2) sample under the null hypothesis, mean
1.0 bit. The scoreboard reports the running mean against that expectation, so failed
predictions accumulate into a public bias test instead of into nothing. That is the
fifth row of the table, made attackable by the people attempting the first.

**And the conflict of interest, stated plainly:** I hold the prize. What stops me
quietly declining a winner is not my good intentions — it is that I hold neither clock,
and the evidence would already be in GitHub's hands and yours. I can still withhold a
pulse I dislike, as the [threat model](#threat-model) says; that leaves a scheduled run
with no commit behind it, and both the schedule and the run log are public. It is also
why the prize is a subscription and not a house: the incentive to cheat should stay
smaller than the cost of being caught. Watch the chain, not the promise.

### Running the beacon yourself

The scheduled job needs one secret, and publishes nothing without it:

```bash
beamline beacon-key    # then add the hex as the BEAMLINE_BEACON_KEY Actions secret
```

Losing that key breaks nothing already published — every pulse stays verifiable against
the public key baked into it — but a new key starts a new chain from round 1, because an
unendorsed key change mid-chain is exactly the forgery `verify_chain` exists to catch.

For the full always-on service with the HTTP API instead, see [DEPLOY.md](DEPLOY.md). It
is one machine, and it must stay one — the chain is single-writer.

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

1. **Register the draw name** against a round that has not happened yet. Beamline returns
   a signed receipt recording where the chain stood when you registered.
2. **Wait for that pulse.** It does not exist yet, so neither side can choose it.
3. **Derive the result** from that pulse.
4. **Anyone can now recompute it** and check the receipt predates the pulse.

```python
from beamline_client import Beamline

bl = Beamline(api_key="bl_live_...", base_url="http://127.0.0.1:8080")

draw = bl.fair_draw("raffle-2026-08-19", count=3, min=1, max=5000)   # steps 1-3

print(draw.data, draw.round, draw.committed)
assert draw.verify()                                      # checked locally, end to end
print(bl.verify_chain())                                  # (True, 'verified N pulses')
```

`draw.verify()` makes zero server calls and answers the whole question, not part of it:
the pulse is signed by the key you named, the receipt is signed and was issued before that
pulse existed, the receipt names *this* tag and *this* round, and the numbers reproduce. It
uses [`sdk/python/beamline_client/verify.py`](sdk/python/beamline_client/verify.py), which
shares no code with the server and reimplements the spec from scratch — a verifier that
imports the server's own functions only proves the server agrees with itself. A JavaScript
verifier ([`sdk/js/index.js`](sdk/js/index.js)) does the same in the browser via WebCrypto.

### Why step 1 is not optional

Reproducible is not the same as fair, and this is the difference. Given a pulse that has
already been published, a draw runner can:

- **Grind the tag.** Try spellings — `Giveaway 7`, `giveaway-7`, `Giveaway 7 (v2)` — until
  one names the winner they want. Against 100 entrants that takes about 100 tries, which is
  a hundredth of a second.
- **Grind the round.** Keep the tag honest and choose *which* pulse to call the draw.
  Waiting an hour gives a 45% chance some pulse in it crowns their friend; four hours, 91%.

Neither forges anything. Every such result reproduces exactly, carries a valid signature,
and passes any check that only asks "do these numbers follow from this pulse?" The receipt
is what rules them out: the tag and the round are inside it, signed, alongside the round the
chain had reached when it was issued.

`bl.fair_draw(...)` commits by default. `commit=False` gives you a reproducible number
without the fairness claim, `draw.committed` is `False`, and `draw.verify()` returns `False`
— because in that mode there is nothing to verify beyond arithmetic.

**What this proves, and what it doesn't.** The chain proves ordering and tamper-evidence.
The receipt proves you named the draw before the outcome existed. Together they cover
everything a draw runner could do. They do not prove *Beamline* never withheld a pulse it
disliked and re-rolled — that is caught by observers watching live, and by the space-weather
provenance no longer lining up, and it is the same residual trust the NIST Randomness Beacon
carries. Anchoring pulses to an external log is what would close it, and it is not built.

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
| `POST /v1/beacon/commit` | key | announce a draw against a future round |
| `POST /v1/beacon/derive` | key | reproducible draw from a pulse, bound to a commitment |
| `GET /v1/beacon/latest`, `/pulse/{n}`, `/chain`, `/verify/{n}`, `/verify-chain` | none | the beacon |
| `GET /v1/beacon/commitment/{id}`, `/commitments/{round}` | none | what was announced, and when |
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
output = SHA-512("beamline/pulse/v3" | canonical_bytes(
             round, timestamp_ms, period, prev_output,
             local_value, public_key, provenance))
```

Signed with Ed25519, chained through `prev_output`. Details in that body exist because of
failures found while testing the Python and JavaScript verifiers against each other.

**`public_key` sits inside the signed body**, so swapping it breaks the output hash, and
rotating the signing key is an auditable event rather than a silent break.

**`canonical_bytes` is a specified subset, not `json.dumps`** — see
[`beamline/entropy/canonical.py`](beamline/entropy/canonical.py). No floats, integers below
2⁵³, ASCII object keys sorted bytewise, everything else escaped per UTF-16 code unit.
`timestamp_ms` was already an integer for this reason, but the provenance dict beside it was
not, and it carries wall-clock times and strings copied from third-party feeds. A float
landing on a whole second is `1787150090.0` in Python and `1787150090` in JavaScript;
`1e-8` is `1e-08` in one and `1e-8` in the other; Python escapes non-ASCII and
`JSON.stringify` does not. Each is an honest pulse that one verifier calls valid and another
calls forged. The encoder now refuses to sign anything it cannot spell one way, and
[`tests/data/canonical_vectors.json`](tests/data/canonical_vectors.json) pins the two
implementations together on every test run.

### The commitment

```
receipt = Ed25519_sign(canonical_bytes(
              version, commit_id, tag, target_round,
              created_at_ms, created_after_round,
              committer, sequence, draw, public_key))

draw = {kind, count, min, max, items_digest}
```

Three fields carry the weight, and each closes a grinding route that the others do not.

**`created_after_round`** is where the chain stood when the receipt was issued, and the
server refuses to issue one for a round already emitted. A verifier rejects any receipt
whose `target_round` is not strictly above it — before checking the signature, because a
perfectly signed receipt written after the deciding pulse proves nothing.

**`draw`** fixes the shape. A tag does not name a winner: the same committed tag against
the same pulse picks a different person at `max=100` than at `max=5000`, and a different
set again at `count=3`. `items_digest` pins the population, so adding an entrant after
naming the draw invalidates the receipt instead of quietly changing who can win.

**`sequence`** is the committer's running count of draws registered against that round.
Twenty receipts made honestly in advance are twenty valid receipts, and publishing only
the one that wins is grinding by a route no single-receipt check can see. The
authoritative answer is the public list at `/v1/beacon/commitments/{round}`; the sequence
number is the offline fallback, and it is weaker — a grinder whose *first* plan happens to
win holds a receipt reading `sequence: 1`. `check_draw` says which of the two it relied on.

### Key rotation

```
rotation = {version, from_public_key, to_public_key, effective_round, created_at_ms}
           signed by BOTH keys
```

A change of signing key is only meaningful if the key being retired endorses it. Naming
two keys as trusted says you would accept either; it does not show the first ever handed
over, so an attacker who talks a verifier into trusting their key gets a substituted
archive accepted with nothing in the chain contradicting it. `check_chain` requires a
matching endorsement, served from `/v1/beacon/rotations`.

The second signature is proof of possession. Without it, authority could be rotated
towards a public key nobody holds — stranding the chain on a key that can never sign
again.

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

298 tests cover DRBG correctness and backtracking resistance, pool credit policy, health-test
failure detection, statistical bias in every generator (including a chi-square across all 24
permutations of a 4-element shuffle), the alphabet and packing layer, store deduplication,
harvester control-law behaviour, key handling, beacon chain integrity and tamper detection,
signing-key rotation, HTTP auth, quotas and rate limits, the published demo page, and the
NIST suites against known-bad generators.

[`tests/test_attacks.py`](tests/test_attacks.py) is worth reading on its own. Every test in
it reproduces an attack that once succeeded against the shipped verifiers — a fabricated
chain, a chain signed with the attacker's own key, a browser verifier that reported success
from inside its own catch block, a draw rigged by grinding the tag, an honest pulse the two
verifiers disagreed about.

```bash
node scripts/check_js_verifiers.mjs
```

Attacks all three JavaScript verifiers — the demo page, the published draw record, and the
JS SDK — by slicing them out of their real files rather than copying them, and checks every
canonical encoder against
[shared test vectors](tests/data/canonical_vectors.json). Two implementations of an encoding
agree until they don't, and the way that surfaces is an honest pulse one verifier calls
forged.

```bash
beamline selftest -n 200000
```

```bash
beamline verify --draw record.json --public-key <key>
```

Checks a published draw record offline: the pulse is authentic under the key you name,
the commitment predates it, the commitment covers this draw's tag *and shape*, and the
result reproduces. Exits non-zero when it does not, so it can run in a script. If the
record omits the round's commitment list, the output says the exclusivity check rested
on the receipt's own sequence number rather than reporting an unqualified pass.

## Security notes

### Threat model

What an attacker can try, and what stops it. Each row has a test in
[`tests/test_attacks.py`](tests/test_attacks.py) that performs the attack.

| Attack | Stopped by |
|---|---|
| Predict a pulse before publication | Every extraction folds a fresh `os.urandom(64)` before hashing, so this needs the kernel CSPRNG *and* SHA-512 preimage resistance. Public inputs (NOAA, ANU) are credited zero secret entropy. |
| Edit a published pulse | The output hash covers the whole body; the chain link propagates the break to every later pulse. |
| Bias the numbers | Rejection sampling on every bounded draw. `rand() % 6` is not a fair die. |
| Publish a wholly fabricated chain | Verification requires a trust anchor. An unsigned chain is refused, and so is an internally consistent one, because internal consistency is free to whoever wrote it. |
| Sign a fabricated chain with your own key | An unrecognised signing key is a failure. A rotation is accepted only when the verifier names both keys. |
| Splice attacker-signed rounds onto a real chain | Same check, applied per pulse, so the splice point fails and everything after it is unverified. |
| Crash the verifier instead of defeating it | Structural validation runs before any cryptography, and every "could not check" path — unparseable key, missing Ed25519 — is a failure with a reason, never a pass. |
| Make two verifiers disagree about one pulse | The canonical encoding is a specified subset that refuses anything it cannot spell one way, pinned across languages by shared test vectors. |
| Rig the draw by grinding the tag or the round | The signed commitment: it names the exact tag and round, and records where the chain stood when it was issued. |
| Announce a draw after seeing its pulse | The server refuses to commit to an emitted round; the verifier refuses a receipt whose `target_round` is not above its `created_after_round`. |
| Commit the name honestly, then pick the size of the draw | The receipt fixes kind, count, bounds and a digest of the entry list. One tag covered `max=100` and `max=5000`, which name different people. |
| Register twenty draws in advance, publish the one that wins | Every receipt is genuine, so no single-receipt check can see it. The public commitment list for the round is authoritative; the receipt's `sequence` is the offline fallback. |
| Switch signing keys and call it a rotation | The retiring key must sign an endorsement, and the incoming key must sign to prove it exists. |
| Reproduce a draw with the wrong sampling branch | Both SDKs reimplement the server's threshold and are checked against it at the boundary; a verifier on the wrong branch silently produces different winners. |

**Not defended: the operator withholding a pulse and re-rolling.** Beamline could emit a
pulse, dislike it, and publish the next one instead. The provenance gives a lower bound on
when a pulse was produced — the NOAA readings it consumed did not exist earlier — but no
upper bound, so this is visible to observers watching live and to nobody else. Anchoring
each pulse into an external append-only log is the fix, and it is not built. Every claim
here is about what a *draw runner* can do; the residual trust in the operator is the same
one the NIST Randomness Beacon carries, and it should be described to customers that way.

**The beacon signing key is the critical secret.** If it leaks, every pulse ever signed
becomes deniable. It belongs in a KMS or HSM, not an environment variable.

**Harvested entropy is never committed.** Publishing the seed archive would publish the
material behind past pulses.

**Generated passwords are served `no-store`** so they cannot land in a proxy cache.

**Rate limiting is per-process.** Behind a load balancer the effective ceiling is N times the
configured rate; the monthly byte quota in SQLite is the hard limit, and Redis-backed
limiting is the fix for multi-instance deployments.

**The service refuses to start without a signing key.** Unsigned pulses are chained but
cannot be attributed to anyone, so a chain an attacker generated this morning is
indistinguishable from Beamline's — while the API looks identical. This used to be a
startup warning, which reaches neither the API client nor the entrant the beacon exists for.
`BEAMLINE_ALLOW_UNSIGNED_BEACON=1` opts in for local development.

**Pin the public key out of band.** A verifier that fetches the signing key from the same
server as the pulses is checking only that the server agrees with itself.
