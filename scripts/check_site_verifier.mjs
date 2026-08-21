/* Run the demo page's OWN verifier against forged input, outside a browser.
 *
 * docs/index.html invites strangers to try to fool it, which makes its verifier a
 * piece of security-critical code that ships with no test around it. It shipped a
 * fail-open catch block for months: crash the signature check and the page reported
 * success. So the functions are lifted out of the page verbatim and attacked here.
 *
 *     node scripts/check_site_verifier.mjs
 *
 * Exits non-zero on the first failure, so CI can run it.
 */
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HTML = readFileSync(join(ROOT, "docs", "index.html"), "utf8");
const BUNDLE = JSON.parse(readFileSync(join(ROOT, "docs", "chain.json"), "utf8"));

/* Lift the verifier out of the page. Slicing the real file rather than copying it is
   the point: a copy drifts, and the copy would be the thing under test. */
function slice(from, to) {
  const a = HTML.indexOf(from), b = HTML.indexOf(to);
  if (a < 0 || b < 0 || b <= a) throw new Error(`cannot locate ${from} .. ${to} in docs/index.html`);
  return HTML.slice(a, b);
}
const SOURCE = [
  slice("/* ---------- bytes ---------- */", "/* ---------- derivation ---------- */"),
  slice("async function checkOne(p, prev) {", "async function checkChain() {"),
].join("\n");

const sandbox = new Function("crypto", "PUBKEY", "TextEncoder", `
  const enc = new TextEncoder();
  ${SOURCE}
  return { canonical, recompute, structureError, signatureState, checkOne, cenc };
`);
const V = sandbox(webcrypto, BUNDLE.public_key, TextEncoder);

let failures = 0;
const check = (name, cond, detail = "") => {
  if (cond) console.log(`  ok    ${name}`);
  else { console.log(`  FAIL  ${name}${detail ? "  -- " + detail : ""}`); failures++; }
};

const sha512 = async (b) => new Uint8Array(await webcrypto.subtle.digest("SHA-512", b));
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const enc = new TextEncoder();

async function forgeChain(n, publicKeyField) {
  const out = [];
  let prev = "0".repeat(128);
  for (let r = 1; r <= n; r++) {
    const p = {
      version: "beamline/pulse/v3", round: r, timestamp_ms: 1787300623434 + r * 60000,
      period_seconds: 60, prev_output: prev,
      local_value: hex(await sha512(enc.encode("ATTACKER-CHOSE-" + r))),
      public_key: publicKeyField,
      provenance: { local_os: { at_ms: 1787300619400, bytes: 64, digest: "00".repeat(32) } },
    };
    p.output = await V.recompute(p);
    prev = p.output;
    out.push(p);
  }
  return out;
}

console.log("\nthe genuine published chain still verifies");
{
  const ps = [...BUNDLE.pulses].sort((a, b) => a.round - b.round);
  for (let i = 0; i < ps.length; i++) {
    const r = await V.checkOne(ps[i], i ? ps[i - 1] : null);
    check(`round ${ps[i].round} verified`, r.state === "ok", r.label);
  }
}

console.log("\nfabricated chains are refused however the signature check is attacked");
for (const [label, pk] of [
  ["public_key: null", null],
  ["public_key: 'not-a-key'", "not-a-key"],
  ["public_key: wrong length", "ab".repeat(31)],
  ["public_key: valid-looking but not Beamline's", "cd".repeat(32)],
]) {
  const c = await forgeChain(6, pk);
  const results = [];
  for (let i = 0; i < c.length; i++) results.push(await V.checkOne(c[i], i ? c[i - 1] : null));
  check(`forged chain rejected (${label})`, results.every((r) => r.state === "bad"),
        results.map((r) => r.state + ":" + r.label).join(", "));
}

console.log("\ntampering with a genuine pulse is caught");
{
  const real = structuredClone(BUNDLE.pulses[4]);
  real.local_value = "ff" + real.local_value.slice(2);
  check("edited body rejected", (await V.checkOne(real, null)).state === "bad");

  const resigned = structuredClone(BUNDLE.pulses[4]);
  resigned.local_value = "ff" + resigned.local_value.slice(2);
  resigned.output = await V.recompute(resigned);   // a rewriter keeps their own hash right
  const r = await V.checkOne(resigned, null);
  check("rewritten-but-consistent pulse rejected", r.state === "bad", r.label);

  const reordered = [structuredClone(BUNDLE.pulses[1]), structuredClone(BUNDLE.pulses[2])];
  reordered[1].timestamp_ms = reordered[0].timestamp_ms - 1000;
  reordered[1].output = await V.recompute(reordered[1]);
  const r2 = await V.checkOne(reordered[1], reordered[0]);
  check("back-dated pulse rejected", r2.state === "bad", r2.label);
}

console.log("\nmalformed and retired pulses are refused before the crypto runs");
{
  const cases = {
    "retired v2": { ...BUNDLE.pulses[0], version: "beamline/pulse/v2" },
    "float in the body": {
      ...BUNDLE.pulses[0],
      provenance: { local_os: { at: 1787300619.5 } },
    },
    "short hex": { ...BUNDLE.pulses[0], local_value: "abcd" },
    "non-integer round": { ...BUNDLE.pulses[0], round: 1.5 },
  };
  for (const [label, p] of Object.entries(cases)) {
    check(`rejected: ${label}`, V.structureError(p) !== null, "structureError returned null");
  }
}

console.log("\ncanonical bytes match the Python encoder");
{
  const vectors = JSON.parse(readFileSync(join(ROOT, "tests", "data", "canonical_vectors.json"), "utf8"));
  for (const v of vectors) {
    let got;
    try { got = V.cenc(v.value, "$"); } catch (e) { got = "ERROR: " + e.message; }
    check(`canonical ${JSON.stringify(v.value).slice(0, 48)}`, got === v.encoded,
          `python ${v.encoded} != js ${got}`);
  }
}

console.log(failures ? `\n${failures} FAILED\n` : "\nall checks passed\n");
process.exit(failures ? 1 : 0);
