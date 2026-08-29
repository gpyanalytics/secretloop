import { test, suite, finish, assert } from "./harness";
import { scanText } from "../src/scanner";

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

finish();
