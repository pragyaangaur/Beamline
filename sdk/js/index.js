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
const VERSION_TAG = 'beamline/pulse/v3';
const COMMITMENT_VERSION = 'beamline/commitment/v1';

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

/* ---------------------------------------------------------------------------
 * Canonical bytes.
 *
 * This was stableStringify, which is not the function Python's json.dumps is: a
 * whole-second float serialises as 1787300619.0 there and 1787300619 here, 1e-8
 * becomes 1e-08 there, and Python escapes non-ASCII where JSON.stringify emits it
 * raw. Each is an honest pulse that one verifier calls valid and the other calls
 * forged. So this is an explicit subset -- objects, arrays, strings, safe integers,
 * booleans, null; ASCII keys sorted bytewise; everything else escaped per UTF-16
 * code unit -- and anything outside it throws rather than being guessed at.
 * ------------------------------------------------------------------------- */
const SHORT_ESCAPES = {
  '"': '\\"', '\\': '\\\\', '\n': '\\n', '\r': '\\r',
  '\t': '\\t', '\b': '\\b', '\f': '\\f',
};

function canonicalString(str) {
  let out = '"';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    const code = str.charCodeAt(i);
    if (SHORT_ESCAPES[ch] !== undefined) out += SHORT_ESCAPES[ch];
    else if (code >= 0x20 && code <= 0x7e) out += ch;
    else out += `\\u${code.toString(16).padStart(4, '0')}`;
  }
  return `${out}"`;
}

function canonicalEncode(v, path = '$') {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error(`${path}: ${v} is not an integer`);
    if (!Number.isSafeInteger(v)) throw new Error(`${path}: ${v} exceeds 2^53`);
    return String(v);
  }
  if (typeof v === 'string') return canonicalString(v);
  if (Array.isArray(v)) return `[${v.map((x, i) => canonicalEncode(x, `${path}[${i}]`)).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => {
      if (!/^[\x00-\x7f]*$/.test(k)) throw new Error(`${path}: key ${k} is not ASCII`);
      return `${canonicalString(k)}:${canonicalEncode(v[k], `${path}.${k}`)}`;
    }).join(',')}}`;
  }
  throw new Error(`${path}: ${typeof v} is not encodable`);
}

function canonicalBody(pulse) {
  return enc.encode(canonicalEncode({
    local_value: pulse.local_value,
    period_seconds: pulse.period_seconds,
    prev_output: pulse.prev_output,
    public_key: pulse.public_key ?? null,
    provenance: pulse.provenance ?? {},
    round: pulse.round,
    timestamp_ms: pulse.timestamp_ms,
    version: pulse.version,
  }));
}

function canonicalCommitmentBody(c) {
  return enc.encode(canonicalEncode({
    version: c.version,
    commit_id: c.commit_id,
    tag: c.tag,
    target_round: c.target_round,
    created_at_ms: c.created_at_ms,
    created_after_round: c.created_after_round,
    public_key: c.public_key ?? null,
  }));
}

const HEX_LENGTHS = {
  prev_output: 128, local_value: 128, output: 128, public_key: 64, signature: 128,
};
const RETIRED_VERSIONS = {
  'beamline/pulse/v1': 'superseded before public release',
  'beamline/pulse/v2': 'signed a non-canonical body, so two verifiers could disagree',
};
const GENESIS = '0'.repeat(128);

/** Everything the signature check would otherwise have to survive, checked first. */
function structureError(pulse) {
  if (!pulse || typeof pulse !== 'object') return 'pulse is not an object';
  if (RETIRED_VERSIONS[pulse.version]) {
    return `pulse version ${pulse.version} is retired: ${RETIRED_VERSIONS[pulse.version]}`;
  }
  if (pulse.version !== VERSION_TAG) return `unexpected version ${pulse.version}`;
  for (const f of ['round', 'timestamp_ms', 'period_seconds']) {
    if (!Number.isSafeInteger(pulse[f])) return `${f} must be an integer`;
  }
  if (pulse.round < 1) return 'round must be at least 1';
  if (pulse.period_seconds < 1) return 'period_seconds must be at least 1';
  for (const f of ['prev_output', 'local_value', 'output']) {
    if (typeof pulse[f] !== 'string' || !new RegExp(`^[0-9a-f]{${HEX_LENGTHS[f]}}$`).test(pulse[f])) {
      return `${f} must be ${HEX_LENGTHS[f]} lowercase hex characters`;
    }
  }
  for (const f of ['public_key', 'signature']) {
    const v = pulse[f];
    if (v !== null && v !== undefined
        && (typeof v !== 'string' || !new RegExp(`^[0-9a-f]{${HEX_LENGTHS[f]}}$`).test(v))) {
      return `${f} must be ${HEX_LENGTHS[f]} lowercase hex characters`;
    }
  }
  try { canonicalBody(pulse); } catch (e) { return `body is not canonically encodable: ${e.message}`; }
  if (pulse.round === 1 && pulse.prev_output !== GENESIS) {
    return 'round 1 does not start from the genesis value';
  }
  return null;
}

function trustAnchor(publicKeyHex, trustedKeys) {
  if (trustedKeys) return new Set(typeof trustedKeys === 'string' ? [trustedKeys] : trustedKeys);
  return publicKeyHex ? new Set([publicKeyHex]) : null;
}

/** True only if the signature is genuinely valid. Any failure to check is a false. */
async function ed25519Verify(publicKeyHex, signatureHex, message) {
  const key = await crypto.subtle.importKey(
    'raw', hexToBytes(publicKeyHex), { name: 'Ed25519' }, false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, hexToBytes(signatureHex), message);
}

/**
 * Verify one pulse. Returns [ok, reason].
 *
 * This function did not check signatures at all. It hashed the body and followed the
 * chain link, which a forger satisfies for free because they control every byte, so a
 * fabricated chain verified. It also reported a signing-key change as `[true, 'ok
 * (signing key changed...)']`, which passes an attacker's own key.
 *
 * You must now name the key you expect, as `publicKeyHex` or several in `trustedKeys`.
 * Without one there is nothing to distinguish Beamline's chain from anyone else's, and
 * that is reported rather than papered over.
 */
export async function checkPulse(pulse, publicKeyHex = null, prev = null,
                                 { trustedKeys = null, allowUnsigned = false } = {}) {
  const anchor = trustAnchor(publicKeyHex, trustedKeys);
  if (!anchor && !allowUnsigned) {
    return [false, 'no trust anchor: pass the signing key you expect, or allowUnsigned'];
  }
  const structural = structureError(pulse);
  if (structural) return [false, structural];

  const computed = bytesToHex(await sha512(concat(
    enc.encode(pulse.version), enc.encode('|'), canonicalBody(pulse))));
  if (computed !== pulse.output) return [false, 'output hash does not match pulse contents'];

  if (prev) {
    if (pulse.prev_output !== prev.output) return [false, `round ${pulse.round} does not link to ${prev.round}`];
    if (pulse.round !== prev.round + 1) return [false, 'round numbers are not consecutive'];
    if (pulse.timestamp_ms < prev.timestamp_ms) {
      return [false, `round ${pulse.round} is dated before round ${prev.round}`];
    }
  }

  if (!pulse.signature) {
    if (anchor) return [false, 'pulse is unsigned and cannot be attributed to anyone'];
    return [true, 'structure and chaining are valid; pulse is UNSIGNED and unattributed'];
  }
  if (!pulse.public_key) return [false, 'pulse is signed but declares no public key'];
  if (anchor && !anchor.has(pulse.public_key)) {
    return [false, `signed by an untrusted key (${pulse.public_key.slice(0, 16)}...). `
      + 'If this is an announced rotation, name it in trustedKeys.'];
  }
  let good = false;
  try {
    good = await ed25519Verify(pulse.public_key, pulse.signature, canonicalBody(pulse));
  } catch (e) {
    return [false, `signature could not be checked here (${e.message}); this is not a pass`];
  }
  if (!good) return [false, 'ed25519 signature is invalid'];
  if (!anchor) return [true, 'self-consistent and self-signed, but no trust anchor was supplied'];
  return [true, 'ok'];
}

export async function checkChain(pulses, publicKeyHex = null,
                                 { trustedKeys = null, allowUnsigned = false } = {}) {
  if (!pulses.length) return [false, 'empty chain'];
  const ordered = [...pulses].sort((a, b) => a.round - b.round);
  const rotations = [];
  for (let i = 0; i < ordered.length; i++) {
    const [ok, why] = await checkPulse(ordered[i], publicKeyHex, i ? ordered[i - 1] : null,
                                       { trustedKeys, allowUnsigned });
    if (!ok) return [false, `round ${ordered[i].round}: ${why}`];
    if (i && ordered[i].public_key !== ordered[i - 1].public_key) rotations.push(ordered[i].round);
  }
  let msg = `verified ${ordered.length} pulses`;
  // Every key here already matched the trust anchor, so this is a rotation you
  // accepted -- but never a silent one: an unannounced rotation is what an archive
  // substitution looks like.
  if (rotations.length) msg += `; signing key changed at round(s) ${rotations.join(', ')}`;
  return [true, msg];
}

/**
 * Verify a commitment receipt: signed by whom, and made before what.
 *
 * A pulse cannot testify about when a draw was named, and that is the claim that
 * matters. Given a published pulse anyone can try draw names until one crowns the
 * entrant they wanted, and every such result reproduces perfectly.
 */
export async function checkCommitment(receipt, publicKeyHex = null,
                                      { trustedKeys = null, allowUnsigned = false } = {}) {
  const anchor = trustAnchor(publicKeyHex, trustedKeys);
  if (!anchor && !allowUnsigned) return [false, 'no trust anchor: pass the signing key you expect'];
  if (!receipt || typeof receipt !== 'object') return [false, 'commitment is not an object'];
  if (receipt.version !== COMMITMENT_VERSION) return [false, `unexpected commitment version ${receipt.version}`];
  for (const f of ['target_round', 'created_at_ms', 'created_after_round']) {
    if (!Number.isSafeInteger(receipt[f])) return [false, `${f} must be an integer`];
  }
  if (typeof receipt.tag !== 'string' || !receipt.tag) return [false, 'tag must be a non-empty string'];
  if (receipt.target_round <= receipt.created_after_round) {
    return [false, `commitment names round ${receipt.target_round} but the chain had already `
      + `reached round ${receipt.created_after_round}; the deciding pulse existed before the `
      + 'draw was announced'];
  }
  if (!receipt.signature) {
    if (anchor) return [false, 'commitment is unsigned; anyone could have written it afterwards'];
    return [true, 'well-formed but UNSIGNED: proves nothing about when it was made'];
  }
  if (anchor && !anchor.has(receipt.public_key)) {
    return [false, `commitment signed by an untrusted key (${String(receipt.public_key).slice(0, 16)}...)`];
  }
  try {
    if (!await ed25519Verify(receipt.public_key, receipt.signature, canonicalCommitmentBody(receipt))) {
      return [false, 'ed25519 signature is invalid'];
    }
  } catch (e) {
    return [false, `signature could not be checked here (${e.message}); this is not a pass`];
  }
  return [true, 'ok'];
}

/**
 * The whole question in one call: was this draw fair?
 *
 * Four things have to hold, and checking three of them is how people convince
 * themselves of something untrue -- the pulse is authentic, the receipt is authentic
 * and predates it, the receipt names this exact draw, and the result reproduces.
 */
export async function checkDraw(pulse, commitment, result, publicKeyHex,
                                { kind = 'integers', items = null, count = 1,
                                  min = 0, max = 100, prev = null, trustedKeys = null } = {}) {
  const [pulseOk, pulseWhy] = await checkPulse(pulse, publicKeyHex, prev, { trustedKeys });
  if (!pulseOk) return [false, `pulse: ${pulseWhy}`];

  const [commitOk, commitWhy] = await checkCommitment(commitment, publicKeyHex, { trustedKeys });
  if (!commitOk) return [false, `commitment: ${commitWhy}`];

  if (commitment.target_round !== pulse.round) {
    return [false, `commitment names round ${commitment.target_round} but the result was `
      + `drawn from round ${pulse.round}`];
  }

  let expected;
  if (kind === 'integers') expected = await reproduceIntegers(pulse.output, commitment.tag, count, min, max);
  else if (kind === 'shuffle') expected = await reproduceShuffle(pulse.output, commitment.tag, items);
  else return [false, `checkDraw cannot reproduce kind ${kind}`];

  if (JSON.stringify(expected) !== JSON.stringify(result)) {
    return [false, `result does not match the pulse: published ${JSON.stringify(result)}, `
      + `recomputed ${JSON.stringify(expected)}`];
  }
  return [true, `round ${pulse.round} is authentic, tag "${commitment.tag}" was committed at `
    + `round ${commitment.created_after_round} before that pulse existed, and the result `
    + 'reproduces exactly'];
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

  pulse(round) { return this.#request('GET', `/v1/beacon/pulse/${round}`); }

  async publicKey() {
    return (await this.#request('GET', '/v1/beacon/public-key')).public_key;
  }

  /** Announce a draw against a round that has not been emitted yet. */
  commit(tag, { targetRound = null, roundsAhead = 1 } = {}) {
    const body = { tag, rounds_ahead: roundsAhead };
    if (targetRound !== null) body.target_round = targetRound;
    return this.#request('POST', '/v1/beacon/commit', { body });
  }

  commitment(commitId) { return this.#request('GET', `/v1/beacon/commitment/${commitId}`); }

  async waitForRound(roundNo, { poll = 2000, timeout = 300000 } = {}) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if ((await this.latestPulse()).round >= roundNo) return this.pulse(roundNo);
      await new Promise((r) => setTimeout(r, poll));
    }
    throw new Error(`round ${roundNo} was not published within ${timeout}ms`);
  }

  /**
   * Pull a run of pulses and check it locally.
   *
   * `publicKey` defaults to the server's own, which checks only that the server
   * agrees with itself. Pass a key you recorded out of band for a real answer.
   */
  async verifyChain({ start = 1, count = 100, publicKey = null, trustedKeys = null } = {}) {
    const { pulses } = await this.#request('GET', '/v1/beacon/chain', { params: { start, count } });
    return checkChain(pulses, publicKey ?? await this.publicKey(), { trustedKeys });
  }

  /**
   * Announce a draw, wait for its pulse, and derive the result.
   *
   * Commits first by default. Deriving from a pulse that already exists is not a
   * fair draw: with the pulse in hand a runner can try tag spellings until one names
   * the winner they want -- a hundred entrants costs about a hundred tries -- or keep
   * the tag and choose which pulse to call the draw. Both verify perfectly.
   *
   * `commit: false` derives from an existing pulse. `verify()` then returns false,
   * because the numbers reproducing was never the question.
   */
  async fairDraw({ tag, count = 1, min = 0, max = 100, round = null, kind = 'integers',
                   items = null, commit = true, timeout = 300000 }) {
    let receipt = null;
    if (commit) {
      receipt = await this.commit(tag, round === null ? {} : { targetRound: round });
      round = receipt.target_round;
      await this.waitForRound(round, { timeout });
    } else if (round === null) {
      round = (await this.latestPulse()).round;
    }

    const body = { round, tag, kind, count, min, max };
    if (items) body.items = items;
    if (receipt) body.commit_id = receipt.commit_id;
    const r = await this.#request('POST', '/v1/beacon/derive', { body });

    const pulse = await this.pulse(r.round);
    const publicKey = await this.publicKey();
    return {
      ...r,
      kind,
      pulse,
      committed: !!r.commitment,
      /** [ok, reason] for the whole question, not just the arithmetic. */
      check: async () => {
        if (!r.commitment) {
          return [false, 'this draw was not committed: the numbers reproduce, but nothing '
            + 'shows the tag and round were not chosen with the pulse already published'];
        }
        return checkDraw(pulse, r.commitment, r.data, publicKey, { kind, items, count, min, max });
      },
      verify: async () => (await (async () => {
        if (!r.commitment) return [false, 'not committed'];
        return checkDraw(pulse, r.commitment, r.data, publicKey, { kind, items, count, min, max });
      })())[0],
    };
  }

  usage() { return this.#request('GET', '/v1/me'); }
  health() { return this.#request('GET', '/v1/health'); }
}

export default Beamline;
