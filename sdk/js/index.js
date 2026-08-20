/**
 * Beamline JavaScript client. Works in Node 18+ and modern browsers.
 *
 *   import { Beamline } from '@beamline/client';
 *   const bl = new Beamline({ apiKey: 'bl_live_...' });
 *   await bl.integers({ count: 6, min: 1, max: 49, unique: true });
 *
 *   const draw = await bl.fairDraw({ tag: 'raffle-88', count: 3, min: 1, max: 500 });
 *   await draw.verify();   // recomputed locally from the published pulse
 *
 * Verification uses WebCrypto's SHA-512, which is async, so every verify path
 * returns a promise. That is why this file cannot simply mirror the Python one.
 */

const DEFAULT_BASE = 'https://api.beamline.dev';
const VERSION_TAG = 'beamline/pulse/v2';

const enc = new TextEncoder();

function subtle() {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error('WebCrypto unavailable: need Node 18+ or a secure browser context');
  return c.subtle;
}

async function sha512(bytes) {
  return new Uint8Array(await subtle().digest('SHA-512', bytes));
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function u32be(n) {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

export class BeamlineError extends Error {
  constructor(status, message) {
    super(`[${status}] ${message}`);
    this.status = status;
  }
}

/**
 * The deterministic byte stream a pulse + tag expands to.
 * Pre-buffers so callers can pull variable-width reads during rejection sampling.
 */
class DerivedStream {
  constructor(pulseOutputHex, tag) {
    this.base = hexToBytes(pulseOutputHex);
    this.tag = tag;
    this.buf = new Uint8Array(0);
    this.pos = 0;
    this.chunk = 0;
  }

  async grow() {
    this.chunk += 1;
    const prefix = concat(enc.encode('beamline/derive/v1'), this.base,
                          enc.encode(`${this.tag}#${this.chunk}`));
    const blocks = [];
    let produced = 0;
    for (let j = 0; produced < 4096; j++) {
      const d = await sha512(concat(prefix, u32be(j)));
      blocks.push(d);
      produced += d.length;
    }
    this.buf = concat(this.buf, concat(...blocks).slice(0, 4096));
  }

  async take(n) {
    while (this.pos + n > this.buf.length) await this.grow();
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
}

/** Uniform integer in [0, span) by rejection sampling -- modulo would bias the draw. */
async function boundedInt(stream, span) {
  if (span <= 1) return 0;
  const bits = BigInt(span - 1).toString(2).length;
  const nbytes = Math.ceil(bits / 8);
  const mask = (1n << BigInt(bits)) - 1n;
  for (;;) {
    const b = await stream.take(nbytes);
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    v &= mask;
    if (v < BigInt(span)) return Number(v);
  }
}

export async function reproduceIntegers(pulseOutputHex, tag, count, min, max) {
  const s = new DerivedStream(pulseOutputHex, tag);
  const span = max - min + 1;
  const out = [];
  for (let i = 0; i < count; i++) out.push(min + (await boundedInt(s, span)));
  return out;
}

export async function reproduceShuffle(pulseOutputHex, tag, items) {
  const s = new DerivedStream(pulseOutputHex, tag);
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = await boundedInt(s, i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/** Canonical pulse serialisation. Must byte-match the server: sorted keys, no spaces. */
function canonicalBody(pulse) {
  const body = {
    local_value: pulse.local_value,
    period_seconds: pulse.period_seconds,
    prev_output: pulse.prev_output,
    public_key: pulse.public_key ?? null,
    provenance: pulse.provenance,
    round: pulse.round,
    timestamp_ms: pulse.timestamp_ms,
    version: pulse.version,
  };
  return enc.encode(stableStringify(body));
}

function stableStringify(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(',')}}`;
}

export async function checkPulse(pulse, prev = null) {
  if (pulse.version !== VERSION_TAG) return [false, `unexpected version ${pulse.version}`];
  const computed = bytesToHex(await sha512(concat(enc.encode(VERSION_TAG), enc.encode('|'),
                                                  canonicalBody(pulse))));
  if (computed !== pulse.output) return [false, 'output hash does not match pulse contents'];
  if (prev) {
    if (pulse.prev_output !== prev.output) return [false, `round ${pulse.round} does not link to ${prev.round}`];
    if (pulse.round !== prev.round + 1) return [false, 'round numbers are not consecutive'];
    // A signing-key change is legitimate but must never pass unremarked: an
    // unannounced rotation looks identical to a substituted archive.
    if (pulse.public_key !== prev.public_key) {
      return [true, `ok (signing key changed at round ${pulse.round})`];
    }
  }
  return [true, 'ok'];
}

export async function checkChain(pulses) {
  if (!pulses.length) return [false, 'empty chain'];
  const ordered = [...pulses].sort((a, b) => a.round - b.round);
  for (let i = 0; i < ordered.length; i++) {
    const [ok, why] = await checkPulse(ordered[i], i ? ordered[i - 1] : null);
    if (!ok) return [false, `round ${ordered[i].round}: ${why}`];
  }
  return [true, `verified ${ordered.length} pulses`];
}

export class Beamline {
  constructor({ apiKey, baseUrl = DEFAULT_BASE, maxRetries = 3, fetchImpl } = {}) {
    if (!apiKey) throw new Error('an API key is required');
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.maxRetries = maxRetries;
    this.fetch = fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  async #request(method, path, { params, body } = {}) {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(params ?? {})) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const res = await this.fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });

      if (res.status === 429 && attempt < this.maxRetries - 1) {
        // Honour the server's own backoff instead of retrying blind.
        const wait = Number(res.headers.get('Retry-After') ?? 2 ** attempt);
        await new Promise((r) => setTimeout(r, wait * 1000));
        continue;
      }
      if (res.status >= 500 && attempt < this.maxRetries - 1) {
        await new Promise((r) => setTimeout(r, 2 ** attempt * 1000));
        continue;
      }
      if (!res.ok) {
        let detail = res.statusText;
        try { detail = (await res.json()).detail ?? detail; } catch { /* non-JSON error body */ }
        throw new BeamlineError(res.status, detail);
      }
      return res.json();
    }
    throw new BeamlineError(0, `request failed after ${this.maxRetries} attempts`);
  }

  async bytes({ n = 32, format = 'hex' } = {}) {
    return (await this.#request('GET', '/v1/random/bytes', { params: { n, format } })).data;
  }

  async integers({ count = 1, min = 0, max = 100, unique = false } = {}) {
    return (await this.#request('POST', '/v1/random/integers',
      { body: { count, min, max, unique } })).data;
  }

  async floats({ count = 1, precision = 17 } = {}) {
    return (await this.#request('POST', '/v1/random/floats', { body: { count, precision } })).data;
  }

  async gaussian({ count = 1, mean = 0, stddev = 1 } = {}) {
    return (await this.#request('POST', '/v1/random/gaussian', { body: { count, mean, stddev } })).data;
  }

  async shuffle(items) {
    return (await this.#request('POST', '/v1/random/shuffle', { body: { items } })).data;
  }

  async sample(items, count) {
    return (await this.#request('POST', '/v1/random/sample', { body: { items, count } })).data;
  }

  async weighted(items, weights, count = 1) {
    return (await this.#request('POST', '/v1/random/weighted', { body: { items, weights, count } })).data;
  }

  async uuid(count = 1) {
    return (await this.#request('GET', '/v1/random/uuid', { params: { count } })).data;
  }

  async dice({ count = 1, sides = 6 } = {}) {
    return (await this.#request('GET', '/v1/random/dice', { params: { count, sides } })).data;
  }

  async password({ count = 1, length = 20, charset = 'unambiguous' } = {}) {
    return (await this.#request('GET', '/v1/random/password', { params: { count, length, charset } })).data;
  }

  latestPulse() { return this.#request('GET', '/v1/beacon/latest'); }

  async verifyChain({ start = 1, count = 100 } = {}) {
    const { pulses } = await this.#request('GET', '/v1/beacon/chain', { params: { start, count } });
    return checkChain(pulses);
  }

  async fairDraw({ tag, count = 1, min = 0, max = 100, round = null, kind = 'integers', items = null }) {
    if (round === null) round = (await this.latestPulse()).round;
    const body = { round, tag, kind, count, min, max };
    if (items) body.items = items;
    const r = await this.#request('POST', '/v1/beacon/derive', { body });
    return {
      ...r,
      kind,
      verify: async () => {
        if (kind === 'integers') {
          const local = await reproduceIntegers(r.pulse_output, tag, count, min, max);
          return JSON.stringify(local) === JSON.stringify(r.data);
        }
        if (kind === 'shuffle') {
          const local = await reproduceShuffle(r.pulse_output, tag, items);
          return JSON.stringify(local) === JSON.stringify(r.data);
        }
        throw new Error(`no local verifier for kind=${kind}`);
      },
    };
  }

  usage() { return this.#request('GET', '/v1/me'); }
  health() { return this.#request('GET', '/v1/health'); }
}

export default Beamline;
