# Running the live beacon

The beacon is the only part of Beamline that has to be hosted. Verification,
the demo, the SDKs, and four of the five [breaks the README
invites](README.md#try-to-break-it) all work against static files. What needs a
server is the one claim that cannot be attempted without it: **you cannot predict
a pulse before it is published.** Nobody can try that against ten pulses baked
into a page, because every one of them already happened.

## Before you deploy

Generate the signing key. Do this locally, once, and keep it:

```bash
beamline beacon-key
```

The public half is published in every pulse and the private half never leaves your
secrets store. **Rotate rather than replace**: `beamline` records key handovers as
signed rotation records, and a chain whose key changes without one is
indistinguishable from a forged archive. Losing this key means the chain cannot be
continued, only restarted, and a restarted chain is a new chain.

## Deploy

```bash
fly launch --no-deploy --copy-config --name beamline
```

```bash
fly volumes create beamline_data --size 3 --region iad
```

```bash
fly secrets set BEAMLINE_BEACON_KEY="<private key from beacon-key>" BEAMLINE_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

```bash
fly deploy
```

The first pulse lands within one period. Confirm the chain is moving before you
tell anybody it exists:

```bash
curl -s https://beamline.fly.dev/v1/beacon/latest | python3 -m json.tool
```

```bash
curl -s "https://beamline.fly.dev/v1/beacon/verify-chain?start=1&count=100" | python3 -m json.tool
```

## The constraint that matters

**One machine. Never scale this out.** The pulse chain is single-writer — round
`N+1` links to `N`, and two emitters racing the same SQLite file fork it into two
mutually invalidating histories. The rate limiters in `beamline/ratelimit.py` are
in-process for the same reason. `fly.toml` pins `min_machines_running = 1` and
disables auto-stop; going wider needs a single-writer chain and Redis buckets
first, and is not a config change.

Check it before and after any deploy:

```bash
fly scale show
```

## Uptime is the product

A gap in the chain is not cosmetic. `verify-chain` reports a hole as a withheld
round, which is exactly what a dishonest operator's chain looks like — Beamline
[documents the re-roll gap](README.md#threat-model) as a known limit, and an
outage during a public challenge is the moment that limit gets pointed at.

Start the beacon well before you announce anything. Days, not hours. That gives
you chain depth to point at and surfaces crashes while nobody is watching.

```bash
fly logs
```

Redeploys restart the machine and will drop one pulse. Deploy during quiet
periods, and never mid-challenge if you can avoid it.

## Costs

One `shared-cpu-1x` machine at 512 MB, always on, plus a 3 GB volume. The chain
grows at 1440 rows/day — roughly 200 MB/year including the prediction registry, so
3 GB is years of headroom.

## Turning the challenge off

The prediction registry is on by default. To run a beacon without it:

```bash
fly secrets set BEAMLINE_CHALLENGE_ENABLED=0
```

Everything else is tunable without a redeploy — see `beamline/config.py` for the
full list of `BEAMLINE_CHALLENGE_*` settings.
