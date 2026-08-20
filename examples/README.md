# Examples

## `user_journey.py`

A narrated walkthrough of Beamline from a customer's point of view. Six scenes against a
live local server, with nothing mocked.

```bash
beamline serve --port 8080
```

```bash
BEAMLINE_ADMIN_TOKEN=... python examples/user_journey.py
```

It covers a developer getting a key and making a first call, the everyday generator
calls, a creator running an auditable giveaway, a sceptical viewer verifying it without
an account, two cheating attempts being caught, and an auditor pulling a defensible
compliance sample.

## `draw_page.html`

The customer-facing artifact: a public draw record for a giveaway. Open it in a browser
and press **Verify in this browser**.

The page carries a real beacon pulse — round, timestamp, output hash, Ed25519 signature,
and the NOAA space-weather readings that were mixed into it. The verify button then does
the whole check client-side with WebCrypto:

1. recomputes the pulse output hash from the pulse contents
2. re-derives the winning numbers from that hash, using the same rejection sampling the
   server used
3. checks the Ed25519 signature against the published key

No server call, no API key, no trust in whoever ran the draw. Altering any field in the
embedded pulse makes the check fail, which is the point.

The embedded data was captured from a live Beamline instance; the draw itself is an
illustration. `_draw_data.json` holds the same payload separately for reference.
