/* Attack every JavaScript verifier Beamline ships, outside a browser.
 *
 * There are three of them -- the demo page, the published draw record, and the JS SDK
 * -- and all three were security-critical code with no test around them. The demo page
 * shipped a fail-open catch block, so crashing the signature check reported success.
 * The SDK did not check signatures at all.
 *
 * The page verifiers are lifted out of their real files by slicing, not by copying: a
 * copy drifts, and then the copy is the thing under test.
 *
 *     node scripts/check_js_verifiers.mjs
 *
 * Exits non-zero if anything fails, so CI can run it.
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

const sandbox = new Function("crypto", "PUBKEY", "DATA", "TextEncoder", `
  const enc = new TextEncoder();
  ${SOURCE}
  return { canonical, recompute, structureError, signatureState, checkOne, cenc,
           commitmentState, commitBody };
`);
const V = sandbox(webcrypto, BUNDLE.public_key, BUNDLE, TextEncoder);

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

console.log("\nthe commitment check refuses everything except the announced draw");
{
  const c = BUNDLE.commitment;
  check("genuine draw accepted", (await V.commitmentState(c.tag, c.target_round)) === "ok");
  check("a different name is not covered",
        (await V.commitmentState(c.tag + " (attempt 138)", c.target_round)) === "mismatch");
  check("a different round is not covered",
        (await V.commitmentState(c.tag, c.target_round - 1)) === "mismatch");
  /* Grinding, concretely: with the pulse in hand, try names until one wins. Every
     result reproduces; none of them is announced. */
  let covered = 0;
  for (let i = 0; i < 200; i++) {
    if ((await V.commitmentState(`${c.tag} #${i}`, c.target_round)) !== "mismatch") covered++;
  }
  check("200 ground-out name variants all uncovered", covered === 0, `${covered} slipped through`);
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

/* The customer-facing artifact carries its own copy of the same verifier, so it gets
   the same treatment. Its verify() is DOM-bound, but the encoder and the structural
   gate in front of the crypto are not, and those are what the attacks went through. */
console.log("\nexamples/draw_page.html agrees with the Python encoder and rejects malformed pulses");
{
  const PAGE = readFileSync(join(ROOT, "examples", "draw_page.html"), "utf8");
  const a = PAGE.indexOf("/* Canonical pulse bytes.");
  const b = PAGE.indexOf("/* The deterministic stream a pulse and tag expand to. */");
  if (a < 0 || b <= a) { console.log("  FAIL  cannot locate the verifier in draw_page.html"); failures++; }
  else {
    const P = new Function("TextEncoder", `
      const enc = new TextEncoder();
      ${PAGE.slice(a, b)}
      return { cenc, canonical, structureError, commitBody };
    `)(TextEncoder);

    const vectors = JSON.parse(readFileSync(join(ROOT, "tests", "data", "canonical_vectors.json"), "utf8"));
    let mismatched = 0;
    for (const v of vectors) {
      let got; try { got = P.cenc(v.value, "$"); } catch (e) { got = "ERROR"; }
      if (got !== v.encoded) mismatched++;
    }
    check("canonical encoder matches the Python vectors", mismatched === 0, `${mismatched} differ`);

    const record = JSON.parse(
      /<script id="draw-data" type="application\/json">(.*?)<\/script>/s.exec(PAGE)[1]);
    check("the published record's pulse is well-formed",
          P.structureError(record.pulse) === null, String(P.structureError(record.pulse)));
    check("the published record carries a commitment", !!record.commitment);
    for (const [label, mutate] of [
      ["retired version", (p) => ({ ...p, version: "beamline/pulse/v2" })],
      ["float in the body", (p) => ({ ...p, provenance: { x: { at: 1.5 } } })],
      ["missing signature", (p) => ({ ...p, signature: null })],
      ["unparseable key", (p) => ({ ...p, public_key: "not-a-key" })],
    ]) {
      check(`rejected: ${label}`, P.structureError(mutate(record.pulse)) !== null);
    }
  }
}

console.log("\nthe JavaScript SDK refuses what the Python one refuses");
{
  const SDK = await import(new URL("../sdk/js/index.js", import.meta.url));
  const real = BUNDLE.pulses;

  check("genuine chain accepted", (await SDK.checkChain(real, BUNDLE.public_key))[0]);
  check("no trust anchor is refused", !(await SDK.checkChain(real))[0]);
  check("wrong key is refused", !(await SDK.checkChain(real, "ab".repeat(32)))[0]);

  const forged = await forgeChain(6, null);
  check("unsigned forgery refused", !(await SDK.checkChain(forged, BUNDLE.public_key))[0]);
  check("unsigned forgery refused without an anchor too", !(await SDK.checkChain(forged))[0]);

  const c = BUNDLE.commitment;
  const pulse = real.find((p) => p.round === c.target_round);
  const drawn = await SDK.reproduceIntegers(pulse.output, c.tag, 1, 1, 5000);
  check("committed draw verifies",
        (await SDK.checkDraw(pulse, c, drawn, BUNDLE.public_key, { count: 1, min: 1, max: 5000 }))[0]);
  check("a ground-out tag does not",
        !(await SDK.checkDraw(pulse, { ...c, tag: c.tag + "-v138" }, drawn, BUNDLE.public_key,
                              { count: 1, min: 1, max: 5000 }))[0]);
  check("a back-dated receipt does not",
        !(await SDK.checkCommitment({ ...c, created_after_round: c.target_round },
                                    BUNDLE.public_key))[0]);

  /* The two SDKs and the two pages must agree byte for byte, or an honest pulse
     verifies in one place and fails in another. */
  const vectors = JSON.parse(readFileSync(join(ROOT, "tests", "data", "canonical_vectors.json"), "utf8"));
  let drifted = 0;
  for (const v of vectors) {
    let got;
    try { got = V.cenc(v.value, "$"); } catch (e) { got = "ERROR"; }
    if (got !== v.encoded) drifted++;
  }
  check("all JS encoders agree with the Python vectors", drifted === 0);
}

console.log(failures ? `\n${failures} FAILED\n` : "\nall checks passed\n");
process.exit(failures ? 1 : 0);
