import { test, suite, finish, assert } from "./harness";
import {
  findEncodedCandidates,
  decodeCandidate,
  EncodedCandidate,
  EncodedTransform,
  MIN_DECODED_BYTES,
  MAX_ENCODED_CHARS,
  MAX_DECODED_BYTES,
  TRANSFORM_ORDER,
} from "../src/encoded";
import { scanText } from "../src/scanner";
import { positiveSamples } from "./fixtures";

/**
 * The pure decoder layer, against the contract frozen in
 * encoded-v1-preimplementation-freeze-v0.4.0.md. Every encoded value here is
 * computed at run time from a synthetic fixture, so no encoded credential is
 * written into this file.
 */

const gh = positiveSamples["github-token"];
const aws = positiveSamples["aws-access-key"];

const b64 = (s: string | Buffer) => Buffer.from(s).toString("base64");
const hex = (s: string | Buffer) => Buffer.from(s).toString("hex");
const pctFull = (s: string) =>
  [...Buffer.from(s)].map((b) => "%" + b.toString(16).toUpperCase().padStart(2, "0")).join("");

const only = (text: string, transform: EncodedTransform): EncodedCandidate[] =>
  findEncodedCandidates(text).filter((c) => c.transform === transform);

/** The one candidate of a transform, with the span invariant checked. */
function single(text: string, transform: EncodedTransform): EncodedCandidate {
  const found = only(text, transform);
  assert.strictEqual(found.length, 1, `expected one ${transform} candidate, got ${found.length}`);
  const c = found[0];
  assert.strictEqual(c.source, text.slice(c.start, c.end), "source must be the exact span");
  return c;
}

suite("encoded.ts — constants");

test("limits and order are the frozen values", () => {
  assert.strictEqual(MIN_DECODED_BYTES, 12);
  assert.strictEqual(MAX_ENCODED_CHARS, 4096);
  assert.strictEqual(MAX_DECODED_BYTES, 4096);
  assert.deepStrictEqual([...TRANSFORM_ORDER], ["base64", "hex", "url-percent"]);
});

// ---------------------------------------------------------------------------
suite("encoded.ts — base64");

test("valid standalone", () => {
  const c = single(b64(gh), "base64");
  assert.strictEqual(c.decoded, gh);
  assert.strictEqual(c.start, 0);
});

test("assignment boundary", () => {
  const text = `TOKEN_B64=${b64(gh)}`;
  const c = single(text, "base64");
  assert.strictEqual(c.decoded, gh);
  assert.strictEqual(c.start, "TOKEN_B64=".length);
});

test("quoted", () => {
  const c = single(`secret = "${b64(gh)}"`, "base64");
  assert.strictEqual(c.decoded, gh);
  assert.strictEqual(c.source, b64(gh));
});

test("punctuation boundary", () => {
  const c = single(`[${b64(gh)}],`, "base64");
  assert.strictEqual(c.decoded, gh);
  assert.strictEqual(c.start, 1);
});

test("malformed alphabet is not a candidate", () => {
  assert.deepStrictEqual(only("Zm9vYmFy!!!not-base64$$$", "base64"), []);
});

test("bad padding is not a candidate", () => {
  assert.deepStrictEqual(only("Zm9vYmFyYmF6=====", "base64"), []);
  assert.deepStrictEqual(only(`${b64(gh)}===`, "base64"), []);
  // Non-canonical: the same string with its padding removed does not round-trip.
  assert.deepStrictEqual(only(b64(gh).replace(/=+$/, ""), "base64").map((c) => c.decoded), [
    ...(b64(gh).endsWith("=") ? [] : [gh]),
  ]);
});

test("truncated input is not a candidate", () => {
  assert.deepStrictEqual(only(b64(gh).slice(0, -6), "base64"), []);
});

test("minimum decoded boundary: 12 bytes in, 11 out", () => {
  assert.strictEqual(single(b64("abcdefghijkl"), "base64").decoded, "abcdefghijkl");
  assert.deepStrictEqual(only(b64("abcdefghijk"), "base64"), []);
});

test("maximum source boundary: exactly 4096 chars decodes, 4100 does not", () => {
  const atMax = b64("lorem ipsum dolor sit amet ".repeat(200).slice(0, 3072));
  assert.strictEqual(atMax.length, 4096);
  const c = single(atMax, "base64");
  assert.strictEqual(Buffer.byteLength(c.decoded), 3072);

  const over = b64("lorem ipsum dolor sit amet ".repeat(200).slice(0, 3075));
  assert.strictEqual(over.length, 4100);
  assert.deepStrictEqual(only(over, "base64"), []);
  assert.strictEqual(decodeCandidate("base64", over), null);
});

test("invalid UTF-8 is not text", () => {
  assert.deepStrictEqual(only(b64(Buffer.from(Array(16).fill(0xff))), "base64"), []);
});

test("NUL-bearing output is not text", () => {
  assert.deepStrictEqual(only(b64("abcdefgh\0ijklmnop"), "base64"), []);
});

// ---------------------------------------------------------------------------
suite("encoded.ts — hex");

test("lowercase", () => {
  assert.strictEqual(single(hex(gh), "hex").decoded, gh);
});

test("uppercase decodes to the same bytes", () => {
  assert.strictEqual(single(hex(gh).toUpperCase(), "hex").decoded, gh);
});

test("odd length is not a candidate", () => {
  assert.deepStrictEqual(findEncodedCandidates(hex(gh).slice(0, -1)), []);
});

test("invalid characters are not a candidate", () => {
  assert.deepStrictEqual(only("zzxxyy6768705f31364337653432", "hex"), []);
});

test("git-SHA and digest shapes decode without throwing and yield no text or harmless text", () => {
  for (const sha of [
    "afdbef61e2979a11b048880d6f2f48cf343c47eb",
    "e07155c856c4c52701231cbc57b0af69557381848a9063d9768936f391a815b2",
  ]) {
    const decoded = decodeCandidate("hex", sha);
    assert.ok(decoded === null || typeof decoded === "string");
    // Whatever it is, it is not a credential: the scanner reports nothing.
    assert.deepStrictEqual(scanText(sha), []);
  }
});

test("minimum decoded boundary: 12 bytes in, 11 out", () => {
  assert.strictEqual(single(hex("abcdefghijkl"), "hex").decoded, "abcdefghijkl");
  assert.deepStrictEqual(only(hex("abcdefghijk"), "hex"), []);
});

test("invalid UTF-8 is not text", () => {
  assert.deepStrictEqual(only("ff".repeat(16), "hex"), []);
});

test("NUL-bearing output is not text", () => {
  assert.deepStrictEqual(only(hex("abcdefgh\0ijklmnop"), "hex"), []);
});

// ---------------------------------------------------------------------------
suite("encoded.ts — URL percent");

test("fully escaped", () => {
  assert.strictEqual(single(pctFull(gh), "url-percent").decoded, gh);
});

test("mixed escaped/unescaped (encodeURIComponent output)", () => {
  const dsn = "mongodb+srv://app:s3cret@cluster0.mongodb.net/s3cret_db";
  const text = `dsn=${encodeURIComponent(dsn)}`;
  const c = single(text, "url-percent");
  assert.strictEqual(c.decoded, dsn);
  assert.strictEqual(c.start, 4);
});

test("query value", () => {
  const c = single(`GET /v1/auth?token=${pctFull(aws)} HTTP/1.1`, "url-percent");
  assert.strictEqual(c.decoded, aws);
  assert.strictEqual(c.source, pctFull(aws));
});

test("quoted", () => {
  assert.strictEqual(single(`url = "${pctFull(gh)}"`, "url-percent").decoded, gh);
});

test("punctuation boundary", () => {
  const c = single(`<${pctFull(gh)}>;`, "url-percent");
  assert.strictEqual(c.decoded, gh);
  assert.strictEqual(c.start, 1);
});

test("malformed escape rejects the whole candidate", () => {
  assert.deepStrictEqual(only("value=%ZZ%GG%not-an-escape", "url-percent"), []);
});

test("incomplete escape rejects the whole candidate", () => {
  assert.deepStrictEqual(only("value=abc%4", "url-percent"), []);
  assert.deepStrictEqual(only("value=abcdefghijklmnop%", "url-percent"), []);
});

test("no % means not a percent candidate, even when the run is long", () => {
  assert.deepStrictEqual(only("loremipsumdolorsitamet".repeat(3), "url-percent"), []);
  assert.strictEqual(decodeCandidate("url-percent", gh), null);
});

test("+ is a literal byte, not a space", () => {
  const c = single("a+b+c+d+e+f+g%20h+i+j+k+l+m", "url-percent");
  assert.strictEqual(c.decoded, "a+b+c+d+e+f+g h+i+j+k+l+m");
});

test("4096-char mixed candidate decodes to 4094 bytes; 4097 chars is rejected", () => {
  const literal = "loremipsumdolorsitamet".repeat(200);
  const atMax = literal.slice(0, 4093) + "%20";
  assert.strictEqual(atMax.length, MAX_ENCODED_CHARS);
  const c = single(atMax, "url-percent");
  assert.strictEqual(Buffer.byteLength(c.decoded), 4094);
  assert.ok(Buffer.byteLength(c.decoded) <= MAX_DECODED_BYTES);
  assert.ok(Buffer.byteLength(c.decoded) > 3072, "the case a 3072-byte cap would have rejected");

  const over = literal.slice(0, 4094) + "%20";
  assert.strictEqual(over.length, MAX_ENCODED_CHARS + 1);
  assert.deepStrictEqual(only(over, "url-percent"), []);
});

test("invalid UTF-8 is not text", () => {
  assert.deepStrictEqual(only("%FF%FE" + "%FF".repeat(12), "url-percent"), []);
});

test("NUL-bearing output is not text", () => {
  assert.deepStrictEqual(only("abcdefgh%00ijklmnop", "url-percent"), []);
});

// ---------------------------------------------------------------------------
suite("encoded.ts — duplicates and order");

test("a span valid under more than one transform is offered under each, in frozen order", () => {
  // Hex digits are base64 alphabet, so a 40-char SHA is a candidate span for
  // both. Neither decodes to text here, but both are attempted without error
  // and the attempt order is what the scanner's precedence rests on.
  const sha = "afdbef61e2979a11b048880d6f2f48cf343c47eb";
  assert.doesNotThrow(() => decodeCandidate("base64", sha));
  assert.doesNotThrow(() => decodeCandidate("hex", sha));
  const text = `${pctFull(gh)} ${hex(gh)} ${b64(gh)}`;
  const seen = findEncodedCandidates(text).map((c) => c.transform);
  assert.deepStrictEqual(seen, ["base64", "hex", "url-percent"]);
});

test("candidates are transform-major, then text order", () => {
  const text = `${hex(gh)}\n${b64(gh)}\n${b64(aws)}\n${hex(aws)}`;
  const order = findEncodedCandidates(text).map((c) => `${c.transform}@${c.start}`);
  const b = text.indexOf(b64(gh));
  const b2 = text.indexOf(b64(aws));
  const h2 = text.indexOf(hex(aws));
  assert.deepStrictEqual(order, [`base64@${b}`, `base64@${b2}`, `hex@0`, `hex@${h2}`]);
});

test("identical input yields identical output", () => {
  const text = `x=${b64(gh)} y=${hex(aws)} z=${pctFull(gh)}`;
  assert.deepStrictEqual(findEncodedCandidates(text), findEncodedCandidates(text));
});

// ---------------------------------------------------------------------------
suite("encoded.ts — one layer only");

test("one layer of encoding is detected by the scanner", () => {
  for (const enc of [b64(gh), hex(gh), pctFull(gh)]) {
    const hits = scanText(enc).filter((f) => f.ruleId === "github-token");
    assert.strictEqual(hits.length, 1, `expected github-token through ${enc.slice(0, 8)}…`);
  }
});

test("two layers are never decoded", () => {
  for (const enc of [b64(b64(gh)), hex(b64(gh)), pctFull(b64(gh)), b64(hex(gh)), hex(hex(gh))]) {
    assert.deepStrictEqual(scanText(enc), [], `double encoding must not surface: ${enc.slice(0, 12)}…`);
  }
});

test("decoder output is never fed back to the decoder", () => {
  // If it were, the inner base64 would surface as github-token here. The
  // wrapper deliberately does not start with "tok": base64("tok…") begins
  // with dG9r, which is intercom-token's literal prefix and would match the
  // RAW text through the ordinary rule pass, encoded or not.
  const inner = b64(gh);
  const outer = b64(`inner ${inner} end`);
  const c = single(outer, "base64");
  assert.ok(c.decoded.includes(inner), "sanity: the decoded text contains an encoded token");
  const findings = scanText(outer);
  assert.deepStrictEqual(findings.filter((f) => f.ruleId === "github-token"), []);
  assert.deepStrictEqual(findings.filter((f) => f.encoding), [], "no encoded-derived finding at all");
});

finish();
