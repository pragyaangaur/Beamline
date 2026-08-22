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
const COMMITMENT_VERSION = 'beamline/commitment/v2';
const ROTATION_VERSION = 'beamline/rotation/v1';
const DRAW_SPEC_FIELDS = ['kind', 'count', 'min', 'max', 'items_digest'];

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

/**
 * `count` distinct values from [0, span), reimplemented from the server's spec.
 *
 * Two branches, and taking the wrong one silently produces different winners from the
 * same pulse. A lottery drawing 6 of 49 shuffles a real list; an audit sampling 10k of
 * 10M draws and rejects against a set, because materialising the range would be
 * absurd. The threshold is part of the algorithm, not an optimisation detail.
 */
async function sampleIndices(stream, span, count) {
  if (span <= 4 * count || span <= 4096) {
    const pool = Array.from({ length: span }, (_, i) => i);
    for (let i = 0; i < count; i++) {
      const j = i + await boundedInt(stream, span - i);
      [pool[i], pool[j]] = [pool[j], pool[i]];
    }
    return pool.slice(0, count);
  }
  const seen = new Set();
  const out = [];
  while (out.length < count) {
    const v = await boundedInt(stream, span);
    if (!seen.has(v)) { seen.add(v); out.push(v); }
  }
  return out;
}

/** `count` items drawn without replacement, as /v1/beacon/derive kind='sample'. */
export async function reproduceSample(pulseOutputHex, tag, items, count) {
  const s = new DerivedStream(pulseOutputHex, tag);
  return (await sampleIndices(s, items.length, count)).map((i) => items[i]);
}

/**
 * `count` DISTINCT integers in [min, max].
 *
 * What a raffle actually wants -- one prize each -- and a different algorithm from
 * reproduceIntegers, not a filtered version of it.
 */
export async function reproduceUniqueIntegers(pulseOutputHex, tag, count, min, max) {
  const span = max - min + 1;
  if (count > span) throw new Error(`cannot draw ${count} unique values from a range of ${span}`);
  const s = new DerivedStream(pulseOutputHex, tag);
  return (await sampleIndices(s, span, count)).map((v) => v + min);
}

/** Raw derived bytes, hex-encoded, as /v1/beacon/derive kind='bytes'. */
export async function reproduceBytes(pulseOutputHex, tag, n) {
  return bytesToHex(await new DerivedStream(pulseOutputHex, tag).take(n));
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
    committer: c.committer ?? null,
    sequence: c.sequence,
    draw: c.draw ?? null,
    public_key: c.public_key ?? null,
  }));
}

function canonicalRotationBody(r) {
  return enc.encode(canonicalEncode({
    version: r.version,
    from_public_key: r.from_public_key,
    to_public_key: r.to_public_key,
    effective_round: r.effective_round,
    created_at_ms: r.created_at_ms,
  }));
}

/** The digest a commitment pins an entry list to. */
export async function itemsDigest(items) {
  if (items === null || items === undefined) return null;
  const bytes = enc.encode(canonicalEncode([...items]));
  const salted = concat(enc.encode('beamline/items/v1'), bytes);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', salted)));
}

function drawSpecProblem(spec) {
  if (!spec || typeof spec !== 'object') return 'draw specification must be an object';
  const keys = Object.keys(spec).sort();
  if (keys.join(',') !== [...DRAW_SPEC_FIELDS].sort().join(',')) {
    return `draw specification must have exactly the fields ${[...DRAW_SPEC_FIELDS].sort()}`;
  }
  if (typeof spec.kind !== 'string' || !spec.kind) return 'draw kind must be a non-empty string';
  for (const f of ['count', 'min', 'max']) {
    if (!Number.isSafeInteger(spec[f])) return `draw ${f} must be an integer`;
  }
  if (spec.min > spec.max) return 'draw min must not exceed max';
  if (spec.count < 1) return 'draw count must be at least 1';
  if (spec.items_digest !== null
      && (typeof spec.items_digest !== 'string' || spec.items_digest.length !== 64)) {
    return 'draw items_digest must be null or a 64-character hex digest';
  }
  return null;
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
                                 { trustedKeys = null, allowUnsigned = false,
                                   rotations = null, allowUnendorsedRotation = false } = {}) {
  if (!pulses.length) return [false, 'empty chain'];
  const ordered = [...pulses].sort((a, b) => a.round - b.round);
  const changes = [];
  for (let i = 0; i < ordered.length; i++) {
    const [ok, why] = await checkPulse(ordered[i], publicKeyHex, i ? ordered[i - 1] : null,
                                       { trustedKeys, allowUnsigned });
    if (!ok) return [false, `round ${ordered[i].round}: ${why}`];
    if (i && ordered[i].public_key !== ordered[i - 1].public_key) {
      const [endorsedOk, endorsedWhy] = await endorsed(
        rotations, ordered[i - 1].public_key, ordered[i].public_key,
        ordered[i].round, allowUnendorsedRotation);
      if (!endorsedOk) return [false, `round ${ordered[i].round}: ${endorsedWhy}`];
      changes.push(ordered[i].round);
    }
  }
  let msg = `verified ${ordered.length} pulses`;
  // Never silent, even when endorsed: a reader deciding whether to trust this archive
  // needs to know the key changed under it.
  if (changes.length) {
    msg += `; signing key changed at round(s) ${changes.join(', ')}`
      + (allowUnendorsedRotation ? ' WITHOUT ENDORSEMENT' : ', each endorsed by the key it retired');
  }
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
  for (const f of ['target_round', 'created_at_ms', 'created_after_round', 'sequence']) {
    if (!Number.isSafeInteger(receipt[f])) return [false, `${f} must be an integer`];
  }
  if (receipt.sequence < 1) return [false, 'sequence must be at least 1'];
  if (typeof receipt.tag !== 'string' || !receipt.tag) return [false, 'tag must be a non-empty string'];
  if (typeof receipt.committer !== 'string') return [false, 'committer must be a string'];
  const specProblem = drawSpecProblem(receipt.draw);
  if (specProblem) return [false, specProblem];
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
 * Check that the retiring key endorsed its successor, and that the successor exists.
 *
 * Two signatures answering two questions. The outgoing key's is the endorsement --
 * the only thing separating a rotation from somebody else's archive. The incoming
 * key's is proof of possession, so authority cannot be handed to a key nobody holds.
 */
export async function checkRotation(record, { expectFrom = null, expectTo = null,
                                              expectRound = null } = {}) {
  if (!record || typeof record !== 'object') return [false, 'rotation is not an object'];
  if (record.version !== ROTATION_VERSION) return [false, `unexpected rotation version ${record.version}`];
  for (const f of ['from_public_key', 'to_public_key']) {
    if (typeof record[f] !== 'string' || !/^[0-9a-f]{64}$/.test(record[f])) {
      return [false, `${f} must be 64 hex characters`];
    }
  }
  if (record.from_public_key === record.to_public_key) return [false, 'a rotation must change the key'];
  for (const f of ['effective_round', 'created_at_ms']) {
    if (!Number.isSafeInteger(record[f])) return [false, `${f} must be an integer`];
  }
  if (record.effective_round < 1) return [false, 'effective_round must be at least 1'];

  const body = canonicalRotationBody(record);
  for (const [field, key] of [['signature_from', record.from_public_key],
                              ['signature_to', record.to_public_key]]) {
    if (typeof record[field] !== 'string' || record[field].length !== 128) {
      return [false, `${field} must be 128 hex characters`];
    }
    try {
      if (!await ed25519Verify(key, record[field], body)) {
        return [false, `${field} is not a valid signature by ${key.slice(0, 16)}...`];
      }
    } catch (e) {
      return [false, `${field} could not be checked here (${e.message}); this is not a pass`];
    }
  }
  if (expectFrom !== null && record.from_public_key !== expectFrom) {
    return [false, `rotation retires ${record.from_public_key.slice(0, 16)}... but the chain `
      + `was using ${expectFrom.slice(0, 16)}...`];
  }
  if (expectTo !== null && record.to_public_key !== expectTo) {
    return [false, `rotation appoints ${record.to_public_key.slice(0, 16)}... but the chain `
      + `switched to ${expectTo.slice(0, 16)}...`];
  }
  if (expectRound !== null && record.effective_round !== expectRound) {
    return [false, `rotation takes effect at round ${record.effective_round}, not ${expectRound}`];
  }
  return [true, 'ok'];
}

async function endorsed(rotations, fromKey, toKey, roundNo, allowUnendorsed) {
  if (allowUnendorsed) return [true, 'ok'];
  if (!rotations || !rotations.length) {
    return [false, 'the signing key changes here and no rotation records were supplied. '
      + 'Trusting both keys says only that you would accept either; it does not show '
      + `${String(fromKey).slice(0, 16)}... ever handed over to ${String(toKey).slice(0, 16)}...`];
  }
  for (const record of rotations) {
    if (record.effective_round !== roundNo) continue;
    const [ok, why] = await checkRotation(record, { expectFrom: fromKey, expectTo: toKey,
                                                    expectRound: roundNo });
    return ok ? [true, 'ok'] : [false, `rotation record is not usable: ${why}`];
  }
  return [false, `the signing key changes here but no rotation record takes effect at round ${roundNo}`];
}

/**
 * Was this the committer's only draw against this round?
 *
 * Committing twenty draws in advance and publishing the one that wins is grinding
 * that survives every other check: each receipt is honest, early and signed. The
 * public commitment list is the authoritative answer; the receipt's own sequence
 * number is the weaker fallback, since a grinder whose first attempt wins holds a
 * receipt reading sequence 1.
 */
function checkExclusivity(commitment, siblings, allowMultiple) {
  if (siblings) {
    const mine = siblings.filter((c) => c.committer === commitment.committer
      && c.target_round === commitment.target_round);
    if (!mine.some((c) => c.commit_id === commitment.commit_id)) {
      return [false, 'this commitment is missing from the published list for the round, '
        + 'so the list cannot be the whole story'];
    }
    if (mine.length > 1 && !allowMultiple) {
      const others = mine.filter((c) => c.commit_id !== commitment.commit_id)
        .map((c) => c.tag).sort();
      return [false, `the committer registered ${mine.length} draws against round `
        + `${commitment.target_round} and published this one. The others were `
        + `${JSON.stringify(others)}. Each is individually valid, which is the point: `
        + 'picking among them after the pulse is grinding.'];
    }
    return [true, mine.length === 1
      ? "it was the committer's only draw against that round"
      : `the committer registered ${mine.length} draws against that round and you chose to accept that`];
  }
  if (commitment.sequence > 1 && !allowMultiple) {
    return [false, `this receipt is the committer's draw number ${commitment.sequence} `
      + `against round ${commitment.target_round}; the earlier ones were not published, `
      + 'and picking among them after the pulse is grinding'];
  }
  return [true, "its receipt is the committer's first for that round, though without the "
    + "published commitment list that is the receipt's own word"];
}

/**
 * The whole question in one call: was this draw fair?
 *
 * Five things have to hold, and checking four of them is how people convince
 * themselves of something untrue -- the pulse is authentic, the receipt is authentic
 * and predates it, the receipt names this draw's tag *and shape*, this was the
 * committer's only draw against the round, and the result reproduces.
 */
export async function checkDraw(pulse, commitment, result, publicKeyHex,
                                { kind = 'integers', items = null, count = 1,
                                  min = 0, max = 100, prev = null, trustedKeys = null,
                                  siblings = null, allowMultipleCommitments = false } = {}) {
  const [pulseOk, pulseWhy] = await checkPulse(pulse, publicKeyHex, prev, { trustedKeys });
  if (!pulseOk) return [false, `pulse: ${pulseWhy}`];

  const [commitOk, commitWhy] = await checkCommitment(commitment, publicKeyHex, { trustedKeys });
  if (!commitOk) return [false, `commitment: ${commitWhy}`];

  if (commitment.target_round !== pulse.round) {
    return [false, `commitment names round ${commitment.target_round} but the result was `
      + `drawn from round ${pulse.round}`];
  }

  const spec = commitment.draw;
  const asked = { kind, count, min, max, items_digest: await itemsDigest(items) };
  const differences = DRAW_SPEC_FIELDS
    .filter((k) => JSON.stringify(spec[k]) !== JSON.stringify(asked[k]))
    .map((k) => `${k}=${JSON.stringify(spec[k])} was committed, ${JSON.stringify(asked[k])} was used`);
  if (differences.length) {
    return [false, `the draw does not match what was committed: ${differences.join('; ')}`];
  }

  const [exclusive, exclusivity] = checkExclusivity(commitment, siblings, allowMultipleCommitments);
  if (!exclusive) return [false, exclusivity];

  let expected;
  if (spec.kind === 'integers') {
    expected = await reproduceIntegers(pulse.output, commitment.tag, spec.count, spec.min, spec.max);
  } else if (spec.kind === 'shuffle') {
    if (!items) return [false, 'shuffle requires the item list'];
    expected = await reproduceShuffle(pulse.output, commitment.tag, items);
  } else if (spec.kind === 'sample') {
    // Over an explicit population when one was committed; otherwise over the committed
    // integer range, which is how a raffle of N entrants is expressed.
    expected = items
      ? await reproduceSample(pulse.output, commitment.tag, items, spec.count)
      : await reproduceUniqueIntegers(pulse.output, commitment.tag, spec.count, spec.min, spec.max);
  } else if (spec.kind === 'bytes') {
    expected = await reproduceBytes(pulse.output, commitment.tag, spec.count);
  } else {
    return [false, `checkDraw cannot reproduce kind ${spec.kind}`];
  }

  if (JSON.stringify(expected) !== JSON.stringify(result)) {
    return [false, `result does not match the pulse: published ${JSON.stringify(result)}, `
      + `recomputed ${JSON.stringify(expected)}`];
  }
  return [true, `round ${pulse.round} is authentic, tag "${commitment.tag}" was committed at `
    + `round ${commitment.created_after_round} before that pulse existed, the draw ran to the `
    + `committed specification, ${exclusivity}, and the result reproduces exactly`];
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
  /**
   * Announce a draw against a round that has not been emitted yet.
   *
   * The shape is part of the announcement: the same tag against the same pulse names
   * one person at max=100 and a different one at max=5000, so kind, count, bounds and
   * the entry list are signed into the receipt alongside the name.
   */
  commit(tag, { targetRound = null, roundsAhead = 1, kind = 'integers', count = 1,
                min = 0, max = 100, items = null } = {}) {
    const body = { tag, rounds_ahead: roundsAhead, kind, count, min, max };
    if (targetRound !== null) body.target_round = targetRound;
    if (items) body.items = items;
    return this.#request('POST', '/v1/beacon/commit', { body });
  }

  rotations() { return this.#request('GET', '/v1/beacon/rotations'); }

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
    const { rotations } = await this.rotations();
    return checkChain(pulses, publicKey ?? await this.publicKey(), { trustedKeys, rotations });
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
      receipt = await this.commit(tag, { targetRound: round, kind, count, min, max, items });
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
        return checkDraw(pulse, r.commitment, r.data, publicKey,
                         { kind, items, count, min, max, siblings: r.sibling_commitments });
      },
      verify: async () => (await (async () => {
        if (!r.commitment) return [false, 'not committed'];
        return checkDraw(pulse, r.commitment, r.data, publicKey,
                         { kind, items, count, min, max, siblings: r.sibling_commitments });
      })())[0],
    };
  }

  usage() { return this.#request('GET', '/v1/me'); }
  health() { return this.#request('GET', '/v1/health'); }
}

export default Beamline;
