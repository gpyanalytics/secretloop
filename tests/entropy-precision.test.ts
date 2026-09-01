import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { scanText, Finding, ENTROPY_RULE_ID } from "../src/scanner";
import { defaultConfig, SecretLoopConfig } from "../src/config";

/**
 * 0.1.4 — the two precision vetoes on `generic-high-entropy`.
 *
 * The first external run on a real frontend monorepo produced two findings and
 * both were false positives, both from this one tier. The two values are
 * committed verbatim under tests/fixtures/false-positives/ and are the anchor
 * for everything below; the synthetic cases exist so each veto is pinned on its
 * own rather than only through the two shapes that happened to be reported.
 *
 *   N7a  ordered-run veto  — Shannon entropy is blind to ordering, so a
 *                            printed alphabet scores higher than a key.
 *   N7b  path-shape veto   — an identifier path is not a credential.
 *
 * A third gate, N8, would have required a secret-like WORD in the identifier
 * before this tier fired at all. It is DEFERRED TO 0.1.5 and its cases were
 * removed from this file rather than skipped: measured against the suite's own
 * documented true positives it suppressed 198 of 276 against a 5% budget, and
 * the measurement exposed a resolution defect -- an FCM token reads
 * "AAAA<id>:APA91b<rest>", so the assignment pattern split it at the token's
 * own colon and gated a real credential on half of itself. The work survives on
 * the n8-key-context branch; nothing in this file depends on it, and the two
 * vetoes below are pinned without it.
 *
 * Every veto here is evaluated inside the entropy tier alone. Named provider
 * rules are unconditional and the anti-regression suite at the bottom is what
 * holds that: a precision fix that also removes a credential is not a fix.
 */

// ---------------------------------------------------------------- generators

let seed = 20260901;
function rand(): number {
  // xorshift32, matching tests/fixtures.ts and tests/fixed-prefix.test.ts.
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return Math.abs(seed) / 2 ** 31;
}
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const B64 = ALNUM + "+/";
const HEX = "0123456789abcdef";

/** A uniform draw. Credential-shaped values are generated, never written. */
function gen(n: number, alphabet = ALNUM): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

// Drawn once, in this order, so every constant below is stable across runs.
/** The ONE literal used for all three N8 placements. Entropy 4.753. */
const SECRET = gen(40);
/** A 40-character AWS-shaped secret with no AWS_SECRET_ACCESS_KEY anchor. */
const AWS_SECRET = gen(40, B64);
/** A base64 payload that contains "/" — the shape N7b must not eat. */
const B64_PAYLOAD = gen(64, B64);
const HEX_32 = gen(32, HEX);
const HEX_64 = gen(64, HEX);

/**
 * One monotonic run of 7 inside an otherwise uniform token: longest_run is 6+
 * while the pair fraction stays at 0.154, so this case can only be rejected by
 * the run length and not by the fraction.
 */
const ORDERED_RUN = SECRET.slice(0, 17) + "hijklmn" + SECRET.slice(24);

/**
 * The mirror image: consecutive pairs written in alternating directions, so no
 * run ever reaches 3 while 26 of 51 adjacent pairs are one apart (0.510). Only
 * seq_fraction can reject this one. 52 distinct characters, entropy 5.700.
 */
const SEQUENTIAL_PAIRS = "abdcefhgijlkmnpoqrtsuvxwyzABDCEFHGIJLKMNPOQRTSUVXWYZ";

/** A component path, entropy 4.601 — the storybook shape, different value. */
const PATH_SHAPED = "Widgets/QuickBrowseDialog/ExportSummaryPanel";

/** A provider credential with a named rule of its own. Never entropy-tier. */
const PROVIDER_TOKEN = "ghp_" + gen(36);

// ------------------------------------------------------------------- helpers

/**
 * The entropy tier, measured on its own.
 *
 * generic-api-key-assignment matches the same span as the entropy pass and
 * wins the overlap merge, so `apiKey = "..."` would report as the assignment
 * rule and the entropy finding would never be offered. Excluding it here is
 * what makes every count below attributable to generic-high-entropy — and the
 * anti-regression suite scans WITHOUT the exclusion, so nothing that rule
 * covers is going untested.
 */
const ENTROPY_ONLY: SecretLoopConfig = {
  ...defaultConfig,
  excludeRules: ["generic-api-key-assignment"],
};

function entropyHits(snippet: string, config: SecretLoopConfig = ENTROPY_ONLY): Finding[] {
  return scanText(snippet, { config }).filter((f) => f.ruleId === ENTROPY_RULE_ID);
}

function allHits(snippet: string): Finding[] {
  return scanText(snippet, { config: defaultConfig });
}

/** `const <name> = "<value>";` — the identifier is resolvable on the line. */
const assigned = (name: string, value: string) => `const ${name} = "${value}";\n`;

/** A bare element of an array literal: no identifier resolves for this line. */
const bare = (value: string) => `const list = [\n  "${value}",\n];\n`;

const FIXTURES = path.join(__dirname, "fixtures", "false-positives");
const CLI = path.join(__dirname, "..", "out", "cli.js");

/**
 * Runs the built CLI over a copy of a committed fixture.
 *
 * The fixture is copied into a temp tree rather than scanned where it lives:
 * tests/fixtures/ is a fixture path, and the product suppresses the entropy
 * tier there by design, so scanning it in place would report zero for a reason
 * that has nothing to do with these gates.
 */
function scanFixtureFile(name: string, extraArgs: string[] = []): Finding[] {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-precision-0.1.4-"));
  try {
    const body = readFileSync(path.join(FIXTURES, name), "utf8");
    mkdirSync(path.join(dir, "src"), { recursive: true });
    writeFileSync(path.join(dir, "src", name), body, "utf8");
    const res = spawnSync(
      "node",
      [CLI, "scan", "--format", "json", "--fail-on", "never", ...extraArgs, "--path", dir],
      { encoding: "utf8" }
    );
    assert.strictEqual(res.status, 0, `CLI exited ${res.status}: ${res.stderr}`);
    return JSON.parse(res.stdout).findings as Finding[];
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const entropyOf = (findings: Finding[]) => findings.filter((f) => f.ruleId === ENTROPY_RULE_ID);

// ------------------------------------------------- N7a: the ordered-run veto

suite("0.1.4 N7a — ordered character runs are not randomness");

test("the reported character-class alphabet no longer fires", () => {
  // tests/fixtures/false-positives/charset-alphabet.ts, verbatim. Entropy 6.02
  // — higher than any real credential, because it is every character exactly
  // once. Its identifier sits on the previous line, so no key context resolves
  // and N8 falls through: this is N7a's case alone.
  const found = entropyOf(scanFixtureFile("charset-alphabet.ts"));
  assert.strictEqual(found.length, 0, `still fired: ${found.map((f) => f.line).join(", ")}`);
});

test("a monotonic run of 6 or more is rejected on run length alone", () => {
  assert.strictEqual(entropyHits(assigned("sessionToken", ORDERED_RUN)).length, 0);
});

test("sequential adjacent pairs are rejected on pair fraction alone", () => {
  assert.strictEqual(entropyHits(assigned("sessionToken", SEQUENTIAL_PAIRS)).length, 0);
});

// -------------------------------------------------- N7b: the path-shape veto

suite("0.1.4 N7b — identifier paths are not credentials");

test("a path-shaped value with no resolvable identifier no longer fires", () => {
  // Deliberately in an array literal. With no identifier to resolve, N8 falls
  // through and a zero here is attributable to the path-shape veto and to
  // nothing else.
  assert.strictEqual(entropyHits(bare(PATH_SHAPED)).length, 0);
});

test("the reported storybook title no longer fires, end to end", () => {
  const found = entropyOf(scanFixtureFile("storybook-title.stories.js"));
  assert.strictEqual(found.length, 0, `still fired: ${found.map((f) => f.line).join(", ")}`);
});

// ------------------------------------------------ N8: the key-context gate

suite("0.1.4 — one literal, two placements, both still reported");

/**
 * The surviving half of what was going to be N8's three-placement comparison.
 * The suppression case went with N8; these two did not, because they are what
 * says the two vetoes leave an ordinary credential alone wherever it sits.
 * Neither depends on identifier context existing.
 */
test("under a secret-like identifier the literal fires", () => {
  assert.strictEqual(entropyHits(assigned("sessionToken", SECRET)).length, 1);
});

test("with no resolvable identifier the same literal fires", () => {
  assert.strictEqual(entropyHits(bare(SECRET)).length, 1);
});

// --------------------------------------------- N8: whole words, not substrings

suite("0.1.4 — the same literal under credential-shaped identifiers");

/**
 * Seven names a leaked credential actually gets given. 0.1.4 does not read the
 * identifier at all, so these assert only that neither veto rejects the value
 * -- which is the point: an over-broad ordered-run or path-shape predicate
 * would show up here first, under exactly the names that matter most.
 *
 * The mirror set -- author, design, assignee, bypass, apiVersion, apiUrl,
 * contentHash, gitSha, which must NOT be read as credential context -- went
 * with N8 to the n8-key-context branch. It asserts a gate that does not exist
 * in this slice.
 */
const CREDENTIAL_NAMES = [
  "apiKey",
  "API_TOKEN",
  "db_pass",
  "authToken",
  "clientSecret",
  "private_key",
  "signingSecret",
];
for (const name of CREDENTIAL_NAMES) {
  test(`a high-entropy literal under ${name} still reports`, () => {
    assert.strictEqual(entropyHits(assigned(name, SECRET)).length, 1);
  });
}

// --------------------------------------------------------- anti-regression

suite("0.1.4 — anti-regression: what these vetoes must never remove");

test("a provider credential still reports, whatever the identifier says", () => {
  const found = allHits(assigned("columnWidth", PROVIDER_TOKEN));
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].ruleId, "github-token");
});

test("an unanchored 40-character AWS secret still reports with no identifier", () => {
  assert.strictEqual(entropyHits(bare(AWS_SECRET)).length, 1);
});

test("an unanchored 40-character AWS secret still reports under a key name", () => {
  // `bearerToken`, not `awsSecretKey`: the latter lowercases to a string
  // containing "awssecret", which is one of the aws-secret-key rule's own
  // keywords. That would anchor the value to a named rule and the entropy tier
  // would correctly yield to it -- testing the opposite of "unanchored".
  assert.strictEqual(entropyHits(assigned("bearerToken", AWS_SECRET)).length, 1);
});

test("a base64 payload containing / still reports with no identifier", () => {
  assert.strictEqual(entropyHits(bare(B64_PAYLOAD)).length, 1);
});

test("a base64 payload containing / still reports under a key name", () => {
  assert.strictEqual(entropyHits(assigned("signingSecret", B64_PAYLOAD)).length, 1);
});

test("a 32-character hex key under a secret-like identifier still reports", () => {
  const found = allHits(assigned("apiKey", HEX_32));
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].ruleId, "generic-api-key-assignment");
});

test("a 64-character hex key under a secret-like identifier still reports", () => {
  const found = allHits(assigned("apiKey", HEX_64));
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].ruleId, "generic-api-key-assignment");
});

test("a generic high-entropy secret under a secret-like key name still reports", () => {
  assert.strictEqual(entropyHits(assigned("db_password", SECRET)).length, 1);
});

finish();
