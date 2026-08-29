import { test, suite, finish, assert } from "./harness";
import { scanText, Finding } from "../src/scanner";
import { rules } from "../src/rules";
import { findHighEntropyStrings } from "../src/entropy";
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

// ---------------------------------------------------------------------------
suite("detection — Fix 3: the jwt.io documentation sample");

/**
 * Benchmark: 10 of secretloop's 13 corpus-A false positives were one string --
 * the jwt.io demo token, planted 10 times as a decoy. gitleaks reports it too.
 *
 * Anchored on the PAYLOAD, not the signature and not the whole string. The
 * signature is derived from header + payload + secret, so swapping HS256 for
 * HS512 changes it and a signature match stops working; the payload is the
 * `{"sub":"1234567890","name":"John Doe","iat":1516239022}` that every copy of
 * the sample carries and that makes it recognisable in the first place. A
 * re-encoded payload with the claims reordered would defeat this, and that is
 * accepted: the target is the published sample, not every possible imitation.
 */
const JWT_DEMO_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const JWT_DEMO_PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
const JWT_DEMO_SIG = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const JWT_DEMO = `${JWT_DEMO_HEADER}.${JWT_DEMO_PAYLOAD}.${JWT_DEMO_SIG}`;

test("the doc sample is dropped on the named path", () => {
  assert.deepStrictEqual(ids(`const token = "${JWT_DEMO}";`), []);
});

test("the doc sample is dropped on the entropy path too", () => {
  // A sample the named rule declines still has the randomness of a real token,
  // so without the entropy pass consulting the same list it is simply reported
  // one tier down instead of not at all.
  const found = scanText(`const token = "${JWT_DEMO}";`, {
    filePath: "f.txt",
    config: { ...require("../src/config").defaultConfig, excludeRules: ["jwt"] },
  }).map((f: Finding) => f.ruleId);
  assert.deepStrictEqual(found, [], `entropy reported the doc sample: ${found.join(",")}`);
});

test("a different header still identifies it as the sample", () => {
  // The point of anchoring on the payload: this variant has a different header
  // and therefore a different signature, and is still the documentation sample.
  const alg512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9";
  const other = `${alg512}.${JWT_DEMO_PAYLOAD}.${gen(43, alnum, 17)}`;
  assert.deepStrictEqual(ids(`const token = "${other}";`), []);
});

test("a same-shape JWT that is NOT the sample still reports", () => {
  const realish = `${JWT_DEMO_HEADER}.eyJ${gen(69, alnum, 11)}.${gen(43, alnum, 13)}`;
  assert.ok(
    ids(`const token = "${realish}";`).includes("jwt"),
    "the filter swallowed a JWT that is not the documentation sample"
  );
});

test("the jwt rule itself is unchanged", () => {
  const r = rules.find((x) => x.id === "jwt");
  assert.ok(r, "jwt rule missing");
  assert.strictEqual(
    r!.regex.source,
    "\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    "fix 3 was supposed to change the sample list, not the rule"
  );
});

// ---------------------------------------------------------------------------
suite("detection — Fix 4: hashed asset filenames with more than one dot");

/**
 * Benchmark: 3 corpus-A false positives, all `main.<20 hex>.chunk.js`.
 *
 * The structural filter's stem class was [A-Za-z0-9+/=_-]*, which cannot contain
 * a dot, so it matched `<stem>.js` and nothing with an inner dot -- and inner
 * dots are exactly what a content-hashed bundle name has. The filter caught the
 * shape it was named for only in its simplest form.
 */
const fires = (v: string) => findHighEntropyStrings(`const asset = "${v}";`, 4.3).length > 0;

test("multi-dot hashed asset names no longer fire", () => {
  for (const v of [
    "main.6f1a2b3c4d5e6f7a8b9c.chunk.js",
    "vendor.a1b2c3d4e5f6a7b8c9d0.bundle.min.js",
    "styles.0f9e8d7c6b5a4938271a.chunk.css",
    "app.9a8b7c6d5e4f3a2b1c0d.esm.js",
  ]) {
    assert.ok(!fires(v), `still reported: ${v}`);
  }
});

test("the single-dot form it already handled still does not fire", () => {
  for (const v of ["6f1a2b3c4d5e6f7a8b9c1d2e3f4a5b6c.js", "a1b2c3d4e5f6a7b8c9d0e1f2.css"]) {
    assert.ok(!fires(v), `regressed: ${v}`);
  }
});

test("the extension alternation still anchors — dotted strings do not slip through", () => {
  // Adding the dot widens the stem; it must not turn the filter into "anything
  // containing a dot". Each of these is high-entropy, dotted, and NOT an asset
  // name, so each must still be reported.
  for (const v of [
    `${gen(30, alnum, 21)}.${gen(30, alnum, 23)}`,
    `${gen(24, alnum, 25)}.${gen(24, alnum, 27)}.${gen(24, alnum, 29)}`,
    `${gen(40, alnum, 31)}.exe`,
    `${gen(40, alnum, 33)}.sql`,
  ]) {
    assert.ok(fires(v), `the widened filter swallowed a non-asset value: ${v}`);
  }
});

// ---------------------------------------------------------------------------
suite("detection — C2: the relative-path filter no longer eats base64 keys");

/**
 * 0.1.1's relative-path filter was `^(?:[\w.-]+/)+[\w.-]+$`, which a 40-char
 * base64 credential satisfies whenever it contains a slash and no + or =.
 * Measured over 200k random keys: 23.12% were eaten, invisible to the entropy
 * tier -- the tier that exists for credentials no named rule can catch.
 *
 * The replacement requires a path to look like one: an extension-bearing final
 * segment, or an explicit ./ ../ / or drive-letter prefix. Measured at 0.823%.
 */
test("a base64 key with one slash is reported again", () => {
  for (const v of [
    "R6nK5HlG/ehNexnGZEP0Ccpjw5WdZMcjuKTWW8qj",
    "AbCd3fGh/JkLmNoPqRsTuVwXyZ0123456789abcd",
  ]) {
    assert.ok(
      findHighEntropyStrings(`secret = "${v}"`, 4.3).length > 0,
      `still filtered as a path: ${v}`
    );
  }
});

test("genuine paths are still filtered", () => {
  for (const p of [
    "../node_modules/react-native/Libraries/ActionSheetIOS",
    "../node_modules/react-native/third-party-podspecs/DoubleConversion.podspec",
    "./src/components/Button/index.tsx",
    "/usr/local/share/some-package/lib/thing.js",
    "packages/core/src/client/transport.js",
  ]) {
    assert.strictEqual(
      findHighEntropyStrings(`p = "${p}"`, 4.3).length,
      0,
      `a real path started firing: ${p}`
    );
  }
});

test("the known cost of the narrowing, pinned rather than hidden", () => {
  // A relative path with no ./ prefix AND no file extension is now
  // indistinguishable from a slash-bearing token, so it reports. Measured
  // alternatives that catch it cost 1.802% of random keys against 0.823% --
  // more than double the false-negative surface to remove one false positive
  // shape. The trade is recorded here so it is a decision, not a surprise.
  const bare = "react-native/Libraries/TurboModule/RCTExport";
  assert.ok(
    findHighEntropyStrings(`m = "${bare}"`, 4.3).length > 0,
    "if this stops firing the predicate widened; re-measure the key-eating rate"
  );
});

finish();
