import { test, suite, finish, assert } from "./harness";
import { scanText, Finding } from "../src/scanner";
import { rules } from "../src/rules";
import { positiveSamples } from "./fixtures";

/**
 * The 0.1.1 detection fixes, each attributed to a benchmark result.
 *
 * These are unit-level guards. They are not the evidence that a fix worked —
 * that is `npm run bench`, whose corpus scores are recorded per fix in
 * bench/BASELINE.md and the changelog. A rule change that passes here and moves
 * the corpus the wrong way has not worked.
 */

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
function gen(n: number, alphabet = alnum, salt = 3): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[(i * 17 + salt * 7 + 5) % alphabet.length];
  return out;
}
const ids = (text: string) => scanText(text, { filePath: "f.txt" }).map((f) => f.ruleId);

// ---------------------------------------------------------------------------
suite("detection — Fix 1: passwords containing punctuation");

/**
 * Benchmark: 7 of 7 planted `generic-password` values missed, in both tiers.
 * The capture class was [A-Za-z0-9_\-/+=.], and a controlled run measured
 * 10/10 detected on an alphanumeric alphabet against 2/10 once !@#$% was added.
 */
test("a password containing punctuation is reported", () => {
  // `password := "..."` is deliberately absent: that form is broken by the
  // separator bug, which is Fix 2's subject, not this one. Keeping it here
  // would make Fix 1 look incomplete and Fix 2 look unnecessary.
  const cases = [
    'password: "Ijea#33QErs!!4Xa9vQULjL"',
    'password = "w9ugjq$XisET@lx!5PTR4W"',
    'api_key = "k7!Lm@2Qw#9Rt$4Yu%6Io^8Pa"',
    'client_secret = "a1(b2)c3[d4]e5{f6}g7<h8>"',
    'auth_token = "x1?y2,z3;w4:v5~u6t7s8r9q0p"',
  ];
  for (const c of cases) {
    assert.ok(
      ids(c).includes("generic-api-key-assignment"),
      `not reported: ${c}`
    );
  }
});

test("the widened class does not defeat the placeholder guard", () => {
  // $ { } are now inside the capture class, so the regex can match a shell or
  // template expansion that it previously could not even see. isPlaceholder is
  // what has to stop it, and this is the test that says so.
  for (const c of [
    'password = "${DATABASE_PASSWORD_VALUE}"',
    'password = "${env.PRODUCTION_SECRET}"',
    'api_key = "$PRODUCTION_API_KEY_VALUE"',
    'client_secret = "${{ secrets.DEPLOY_TOKEN }}"',
  ]) {
    assert.deepStrictEqual(ids(c), [], `an expansion was reported as a secret: ${c}`);
  }
});

test("a password that merely contains a dollar sign still reports", () => {
  // The guard is anchored to the start on purpose; widening the class must not
  // turn that into "any value containing $ is a placeholder".
  assert.ok(ids('password = "Km4$Rt7Yu2Iop9As3Df6"').includes("generic-api-key-assignment"));
});

test("the keyword gate is unchanged — punctuation alone is not a credential", () => {
  // The class got wider; the gate did not. A long punctuated string with no
  // credential keyword in front of it is still nothing.
  assert.deepStrictEqual(ids('const banner = "!!!===***<<<###>>>***===!!!"'), []);
  assert.deepStrictEqual(ids('const sep = "----------------------------------"'), []);
});

// ---------------------------------------------------------------------------
suite("detection — Fix 2: the := separator");

/**
 * Benchmark: `aws_secret_access_key := "..."` scored 0/10 with named rules only,
 * against 10/10 for the `=` form. `\s*[:=]\s*` consumes ONE character, so Go's
 * short variable declaration leaves the `=` unconsumed and the match dies.
 *
 * The entropy pass covers it in the default tier, which is why this never
 * surfaced: it is invisible to exactly the users who follow
 * .secretloop.example.json's advice and turn the entropy pass off.
 *
 * Table-driven over every separator-bearing rule rather than the two the
 * benchmark happened to plant. A bug in a shared idiom is present wherever the
 * idiom is, and 22 rules carry it.
 */
const SEPARATOR_RULES = rules.filter((r) => /\[:=\]/.test(r.regex.source)).map((r) => r.id);

/** Rewrites a fixture's separator, leaving keyword and value untouched. */
function withSeparator(sample: string, sep: string): string {
  return sample.replace(/\s*[:=]\s*/, ` ${sep} `);
}

test("every separator-bearing rule is found — the table cannot silently empty", () => {
  assert.ok(
    SEPARATOR_RULES.length >= 20,
    `expected the separator idiom across many rules, found ${SEPARATOR_RULES.length}`
  );
  for (const id of SEPARATOR_RULES) {
    assert.ok(positiveSamples[id], `${id} has no fixture to vary`);
  }
});

for (const sep of ["=", ":", ":="]) {
  test(`every separator-bearing rule matches \`key ${sep} value\``, () => {
    const broken: string[] = [];
    for (const id of SEPARATOR_RULES) {
      const text = withSeparator(positiveSamples[id], sep);
      // Named rules only: the entropy pass masks this bug in the default tier,
      // which is the entire reason it survived to be found by a benchmark.
      const found = scanText(text, {
        filePath: "f.txt",
        config: { ...require("../src/config").defaultConfig, entropyPassEnabled: false },
      }).map((f: Finding) => f.ruleId);
      if (!found.includes(id)) broken.push(id);
    }
    assert.deepStrictEqual(broken, [], `these rules do not match with \`${sep}\`: ${broken.join(", ")}`);
  });
}

test("the two separator rules with fixed syntax are deliberately not varied", () => {
  // gcp-service-account-key is `"private_key_id" : "..."` -- JSON, where `:=` is
  // not a thing. azure-storage-account-key is `AccountKey=...` inside a
  // connection string, where neither `:` nor `:=` is valid. Both are recorded
  // here so the audit's two exclusions are visible rather than merely absent.
  for (const id of ["gcp-service-account-key", "azure-storage-account-key"]) {
    const r = rules.find((x) => x.id === id);
    assert.ok(r, `${id} is missing`);
    assert.ok(!/\[:=\]/.test(r!.regex.source), `${id} now uses the shared separator idiom; vary it`);
  }
});

finish();
