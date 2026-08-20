# What Beamline is for

The engineering in this repository is the easy half. This document is the harder half:
what the product actually is, who pays for it, and why the most obvious framing is the
wrong one.

---

## 1. "True random numbers for security and cryptography" does not sell

It is the pitch that feels most natural for a service like this, and it will not work.
Three reasons, in increasing order of how much they matter.

**Every machine already has a better answer, for free.** `/dev/urandom`,
`getrandom(2)`, `BCryptGenRandom`, `crypto.randomBytes` — all kernel CSPRNGs seeded from
hardware entropy, all audited far more heavily than this codebase will ever be, all
instantaneous, all free. A developer who needs 32 bytes for an AES key has no unmet need.

**Network delivery makes randomness worse for secrets, not better.** Key material
fetched over HTTP existed on someone else's server, traversed someone else's TLS
termination, and sat in someone else's memory. That asks a security-conscious buyer to
add a third party to the most sensitive operation in their stack. The correct advice —
which Beamline's own `/v1/about` endpoint gives — is *don't do that*. A product whose
honest documentation tells you not to use it for its advertised purpose is not a product.

**"Truer" randomness has no security value above the threshold.** A CSPRNG seeded with
256 bits of genuine entropy is computationally indistinguishable from ideal. No attack
exists that a quantum source prevents and a well-seeded ChaCha20 does not. The marginal
buyer gets nothing measurable.

The failure mode is not "few customers". It is that the customers who *do* arrive are
buying on a misconception, and the technically strong ones — the ones with budget — spot
it in the first five minutes and leave. Some competitors sell this framing successfully
as marketing. It does not hold up as a durable business.

**So: keep the physics, change the claim.**

---

## 2. What people will pay for: randomness that can be *proved*

The thing a customer genuinely cannot produce alone is not unpredictability. It is
**unpredictability a third party will believe**.

Whenever someone runs a draw in which they are also an interested party, "we picked
fairly" is worth nothing, because they would say that either way:

- A creator running a $5,000 giveaway, accused by their own audience of picking a friend
- A marketplace assigning limited inventory, product drops, or launch slots
- An auditor pulling 200 transactions from 4 million, who must show the sample was not
  chosen to look clean
- A tournament seeding a bracket where the organiser has a favourite
- A game studio whose loot-box odds are under regulatory scrutiny
- A DAO, a research trial, a jury pool, a housing lottery, a school placement

Every one has the same shape: **a decision that must be defensible afterwards to someone
who assumes you cheated.** That is not a randomness problem. It is an evidence problem —
and evidence is something you can charge for, because the alternative is a lawyer, an
auditor, or a public relations crisis.

That is what the beacon in [`beamline/entropy/beacon.py`](beamline/entropy/beacon.py)
provides, and it is the only part of Beamline that `/dev/urandom` cannot replace.
Everything else in the codebase exists to make the beacon credible.

Prior art that validates the shape — and the risk: the NIST Randomness Beacon,
drand / League of Entropy, and random.org's paid signed-draw service. random.org is the
closest commercial comparison: a real business, built almost entirely on verifiable
public draws rather than on selling bytes.

### The reframe

> **Beamline is the fairness layer for anything drawn, picked, or sampled in public.**
> The quantum and astrophysical sourcing is what makes the claim credible and the story
> worth telling. The verifiable beacon is what makes it a business.

The physics is not decoration. The astrophysical provenance genuinely timestamps a pulse
against an independently observable physical record, and the quantum source is real. But
it is the *supporting* claim, not the headline.

---

## 3. Product forms, ranked

### Tier 1 — build next

**A. Hosted public draw pages.** A customer creates a draw, gets a public URL, and
publishes it *before* the pulse exists. Afterwards the page shows entrants, the pulse,
the result, and a "verify this yourself" button running the JavaScript verifier
client-side. The page is the product; the API is plumbing.

This is the whole business in one artifact, and it is shareable: every draw page markets
Beamline to an audience already primed to be suspicious — precisely the audience that
converts. It prices at $19–99/month to businesses, not $5 to developers.

**B. Verification as a free public good.** Verifier libraries, a `/verify` web page, the
chain, and the public key: free, unauthenticated, forever. The asymmetry is the moat.
Anyone can *check* a Beamline draw; only customers can *make* one. Free verification is
what makes the paid side worth anything.

### Tier 2 — natural follow-ons

**C. Compliance sampling.** Upload a population, get a defensible sample plus a PDF
methodology statement citing the pulse. Sells to internal audit and quality teams who
already pay real money for far less. Highest revenue per customer by a wide margin.

**D. Provably-fair SDK for games.** Commit-reveal built on the beacon: the server commits
to a seed hash, the pulse supplies public entropy, the player verifies the drop. The
crypto-casino world already demands this, and the mechanism generalises to any game with
published odds.

**E. Webhooks and scheduled draws.** "Every Friday at 16:00 UTC, draw 3 winners from this
list and POST the result." Turns a one-off into recurring revenue.

### Tier 3 — later, or never

**F. Bulk entropy for simulation.** Monte Carlo shops want reproducibility and speed,
which a seeded PRNG already gives them. The angle is a *certified, timestamped seed*: one
API call, then run a local Mersenne Twister. Sell seeds, not streams.

**G. Hardware.** A muon detector or an owned optical source removes the ANU dependency
and creates something defensible. Interesting at scale; a distraction at V1.

---

## 4. Pricing

The $5–10/month instinct prices this as a developer utility, which is the wrong category.
Utilities compete with free. Evidence products compete with the cost of *not* having
evidence.

| Plan | Price | Who | What they get |
|---|---|---|---|
| Free | $0 | everyone | 1 MB/month, public draws with Beamline branding, full verification |
| Creator | $19/mo | streamers, small brands | unbranded draw pages, 50 draws/month, webhooks |
| Business | $99/mo | marketplaces, studios | API + draws, custom domain, PDF certificates |
| Audit | $499/mo | internal audit, compliance | methodology docs, retention guarantees, SSO |
| Enterprise | custom | gaming, regulated | SLA, dedicated beacon, audit support |

A metered developer tier is worth keeping — it is how people discover the service and
costs almost nothing to serve — but it should not define the company.

The arithmetic that settles it: at $5–10/month, roughly 1,000 paying developers are
needed to reach $100k ARR, in a category whose incumbent is a free system call. At
$99/month, 85 businesses that run public draws get to the same place. The second number
is much smaller, and those customers have a real problem.

---

## 5. Risks

**The ANU dependency is the largest technical risk.** It is a free endpoint at a
university, with no contract, no SLA, and no obligation to anyone. If it disappears, the
headline claim disappears with it. The mitigation, when budget allows, is the metered API
key; until then, the harvester is built to stay inside the endpoint's measured capacity
precisely because getting blocked would take yield to zero permanently. A second QRNG
vendor would remove the single point of failure entirely — the pool already supports it,
and adding one means writing a single `Source` subclass.

**Key rotation is handled; key compromise is not.** Each pulse carries the key that
signed it, so a rotation is visible and auditable rather than silently invalidating
history. That does not help if the key leaks.

**Beacon signing key compromise is the extinction event.** Every pulse ever signed
becomes deniable. The key belongs in a KMS or HSM, not an environment variable, before
the service takes money.

**Withholding is the honest gap in the trust model.** The chain proves ordering and
tamper-evidence, not that an operator never re-rolled a pulse they disliked.
Mitigations, in rough order of effort: publish pulse hashes to a third party (a
transparency log, a public repository, another beacon) so withholding becomes externally
visible; run threshold or multi-party pulse generation in the style of drand; anchor
periodically to a public chain. This limitation belongs in the documentation — the NIST
beacon states it plainly, and the credibility gained from naming a weakness exceeds what
hiding it would buy.

**Regulated gaming needs certification that does not exist yet.** No sales into licensed
gambling before an independent RNG audit (GLI-19 or iTech Labs). Adjacent non-regulated
use is fine and is a large market by itself.

**Statistical claims need evidence, and have it — up to a point.** The NIST SP 800-22 and
SP 800-90B suites in [`beamline/qa/`](beamline/qa/) are implemented and validated against
known-bad generators; results are in [docs/ENTROPY.md](docs/ENTROPY.md). Running
dieharder, PractRand, or TestU01 BigCrush against `/v1/random/bytes` and publishing those
results too would close the remaining gap. None of it substitutes for certification.

---

## 6. Order of work

1. **Move the beacon key to a KMS.** Before the first paying customer.
2. **Build the hosted draw page** (Tier 1A). This is the product. Everything it needs
   already exists.
3. **Publish the verifier** as `@beamline/verify` on npm and PyPI, with the pulse spec as
   a standalone document. Verification credibility compounds.
4. **Mirror pulse hashes to a public append-only log.** Closes the withholding gap enough
   to matter in enterprise conversations.
5. **Find five design partners** running real public draws — a creator, a marketplace, an
   internal auditor. Their objections determine which of Tier 2 gets built.
6. **Buy the ANU metered API key** when revenue justifies it, and add a second QRNG
   vendor for source independence.

---

## 7. What already exists

- Multi-source entropy pool with SP 800-90B health tests and an explicit, conservative
  credit policy that refuses to credit public data
- HMAC_DRBG(SHA-512) with continuous reseeding
- Signed, hash-chained beacon with reproducible derivation
- Bias-free generators (rejection sampling throughout), statistically tested
- Adaptive-concurrency harvester tuned to the endpoint's measured capacity
- API keys, tiers, quotas, rate limiting, usage tracking
- Python and JavaScript SDKs, each with an **independent** verifier sharing no code with
  the server
- Full NIST SP 800-22 and SP 800-90B implementations, validated against known-bad
  generators

The engineering is not the bottleneck. The positioning is.
