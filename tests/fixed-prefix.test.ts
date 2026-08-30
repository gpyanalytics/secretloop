import { test, suite, finish, assert } from "./harness";
import { scanText } from "../src/scanner";
import { shannonEntropy } from "../src/entropy";
import { rules } from "../src/rules";
import { defaultConfig } from "../src/config";

/**
 * 0.1.3 — the post-prefix entropy floor on fixed-prefix rules.
 *
 * A fixed-prefix rule carries all of its specificity in a literal head and
 * constrains the rest to a length and a character class. When every character
 * of that head is ALSO in the class -- `AAAA...A` in front of `[A-Za-z0-9%]`,
 * `EAA` in front of `[A-Za-z0-9]` -- the pattern describes one unbroken run
 * from one alphabet, and any long enough run of that alphabet satisfies it.
 * Padding data does. Base64 blobs do.
 *
 * The fix is a floor on the entropy of the portion AFTER the prefix, and the
 * numbers below are measured, not chosen:
 *
 *   false positives, from the five public files the 0.1.3 benchmark named,
 *   re-fetched read-only and re-scanned:      post-prefix H 0.040 .. 3.337
 *   uniform random tokens at the tightest
 *   enabled configuration (50 chars, 62- and
 *   63-symbol alphabets), 100,000,000 samples: post-prefix H 4.1649 minimum
 *
 * The floor sits at 3.75 -- the midpoint of that band, 0.413 bits above the
 * worst false positive and 0.415 bits below the least random of a hundred
 * million legitimate tokens.
 *
 * DISTINCT-CHARACTER COUNT WAS MEASURED AND REJECTED as the discriminator. Over
 * the same 100,000,000 samples the least diverse legitimate token carried 21
 * distinct characters, while the worst false positive carried 29. The two
 * populations overlap on that axis and do not overlap on entropy, so entropy is
 * the only one of the two that can separate them.
 *
 * Every RED case here is paired with an anti-regression case on the same rule.
 * A filter that removes noise and a credential with it is worse than the noise.
 */

// ---------------------------------------------------------------- generators

let seed = 20260831;
function rand(): number {
  // xorshift32, matching tests/fixtures.ts -- deterministic, no dependency, so
  // a failure here is reproducible rather than a once-in-a-run fluke.
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return Math.abs(seed) / 2 ** 31;
}
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const B64URL = ALNUM + "_-";
const B64 = ALNUM + "+/=";
const PCT = ALNUM + "%";

/** A uniformly drawn run. Credential-shaped values are generated, never written. */
function gen(n: number, alphabet = ALNUM): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

/**
 * A run of `total` characters in which one character takes `dominant` of the
 * slots and the remainder cycle through `spread` others.
 *
 * This is the shape of both benchmark false-positive families: IL-assembly
 * padding is the degenerate case (`dominant` is nearly everything), and base64
 * of a mostly-zero binary blob is the milder one, where the zero byte's `A`
 * dominates and real bytes supply the rest.
 */
function lowDiversityRun(total: number, dominant: number, spread: number): string {
  const others = ALNUM.slice(1, 1 + spread);
  let out = "A".repeat(dominant);
  for (let i = 0; i < total - dominant; i++) out += others[i % others.length];
  return out;
}

/** The post-prefix portion the floor actually inspects. */
const after = (value: string, prefix: string) => value.slice(prefix.length);

/**
 * Which NAMED rules report this value.
 *
 * The entropy pass is off. Leaving it on would let a generic-tier finding stand
 * in for a named one in the anti-regression cases below, so a rule that stopped
 * matching its own token would still look green.
 */
function ruleIdsFor(text: string): string[] {
  const config = { ...defaultConfig, entropyPassEnabled: false };
  return scanText(text, { config }).map((f) => f.ruleId);
}

const TWITTER_PREFIX = "A".repeat(21);

// ------------------------------------------------- N1: homogeneous runs (RED)

suite("0.1.3 N1 — twitter-bearer-token must decline homogeneous runs");

/**
 * The IL-assembly padding shape. Measured on the four `.cool` loader-test files
 * the benchmark named: 255-character values, 2 to 3 distinct characters,
 * post-prefix entropy 0.040 to 0.074, 6,997 findings across the four files.
 *
 * `isPlaceholder` does not catch it. Its repeated-character guard is
 * /^(.)\1+$/, which needs the value to be ONE character repeated; a padding run
 * with two stray bytes in it is not, and reports at severity high.
 */
const IL_PADDING = "A".repeat(200) + "g" + "A".repeat(53) + "Q";

test("declines an IL-padding run (2-3 distinct characters over 255)", () => {
  const post = after(IL_PADDING, TWITTER_PREFIX);
  // Pin the fixture to the measured false-positive band, so it cannot drift
  // into a shape the benchmark never saw.
  assert.ok(
    shannonEntropy(post) < 0.1,
    `fixture drifted out of the measured band: H=${shannonEntropy(post).toFixed(4)}`
  );
  assert.ok(new Set(post).size <= 3, "fixture should carry 2-3 distinct characters");
  assert.ok(
    !ruleIdsFor(`.field public static literal string Pad = "${IL_PADDING}"`).includes(
      "twitter-bearer-token"
    ),
    "twitter-bearer-token fired on an IL-assembly padding run"
  );
});

/**
 * The harder half of the same family, and the one that sets the threshold:
 * base64 of a mostly-zero binary blob, as committed test assembly data. The
 * zero byte encodes to `A`, so the run is dominated by `A` but carries real
 * bytes too.
 *
 * Measured worst case across the benchmark's `TestData.cs`: post-prefix entropy
 * 3.337 over 90 characters with 29 distinct. This fixture targets that worst
 * case deliberately. A fix that rejects the easiest false positive proves
 * nothing; this one has to reject the hardest.
 */
const BASE64_ZERO_BLOB = TWITTER_PREFIX + lowDiversityRun(90, 45, 29);

test("declines base64 of a mostly-zero blob at the measured worst case", () => {
  const post = after(BASE64_ZERO_BLOB, TWITTER_PREFIX);
  const h = shannonEntropy(post);
  assert.ok(
    h > 3.0 && h < 3.5,
    `fixture must sit at the top of the measured false-positive band, got H=${h.toFixed(4)}`
  );
  assert.ok(
    !ruleIdsFor(`byte[] blob = Convert.FromBase64String("${BASE64_ZERO_BLOB}");`).includes(
      "twitter-bearer-token"
    ),
    "twitter-bearer-token fired on a low-diversity base64 blob"
  );
});

// ------------------------------------------------------ anti-regression (RED)

/**
 * A realistically shaped synthetic token for every rule the floor is enabled
 * on, at that rule's documented format AND at the shortest variable run its
 * pattern accepts. The short form is the one that matters: it is where a
 * legitimate token has the least entropy to spare, so it is where an
 * over-tight floor would take one.
 *
 * These are the tests that must NOT be weakened to make a measurement pass.
 */
const REALISTIC: Array<[label: string, value: string]> = [
  // X/Twitter bearer tokens are a 21-character `A` prefix and roughly 90
  // percent-encoded base64 characters.
  ["twitter-bearer-token, real shape", TWITTER_PREFIX + gen(89, PCT)],
  ["twitter-bearer-token, at the pattern floor", TWITTER_PREFIX + gen(50, PCT)],
  ["facebook-access-token, real shape", "EAA" + gen(180)],
  ["facebook-access-token, at the pattern floor", "EAA" + gen(90)],
  ["square-access-token EAAA, real shape", "EAAA" + gen(96, B64URL)],
  ["square-access-token EAAA, at the pattern floor", "EAAA" + gen(59, B64URL)],
  // The other Square branch. Its variable run is 22 characters, far below the
  // length at which the floor can be shown to be safe, so the floor must not
  // apply to it at all.
  ["square-access-token sq0atp-, untouched branch", "sq0atp-" + gen(22, B64URL)],
  ["atlassian-api-token, real shape", "ATATT3x" + gen(185, B64URL)],
  ["atlassian-api-token, at the pattern floor", "ATATT3x" + gen(100, B64URL)],
  ["github-fine-grained-pat, real shape", "github_pat_" + gen(22) + "_" + gen(59)],
  ["github-fine-grained-pat, at the pattern floor", "github_pat_" + gen(60)],
  ["jfrog-token AKCp, real shape", "AKCp" + gen(64)],
  ["jfrog-token reftkn, real shape", "cmVmdGtuOjAx" + gen(64, B64URL)],
  ["pypi-token, real shape", "pypi-AgEIcHlwaS5vcmc" + gen(150, B64URL)],
  ["pypi-token, at the pattern floor", "pypi-AgEIcHlwaS5vcmc" + gen(50, B64URL)],
  ["intercom-token, real shape", "dG9r" + gen(60, B64)],
  ["intercom-token, at the pattern floor", "dG9r" + gen(50, B64)],
];

suite("\n0.1.3 — realistically shaped tokens still report");

for (const [label, value] of REALISTIC) {
  test(`still reports ${label}`, () => {
    const ids = ruleIdsFor(`token = "${value}"`);
    assert.ok(
      ids.length > 0,
      `no rule reported a realistically shaped token: ${label}`
    );
  });
}

// ------------------------------------------------------------------ hygiene

suite("\n0.1.3 — mechanism hygiene");

/**
 * The enablement criterion, asserted rather than described.
 *
 * The floor is enabled exactly where the measurement can show it is safe: a
 * fixed prefix whose characters all come from the variable portion's own class
 * (so dense single-alphabet data can satisfy the whole pattern), a variable run
 * of at least 50 characters, and a class of at least 62 symbols. Below 50
 * characters the legitimate-token entropy distribution reaches down into the
 * false-positive band and no threshold separates them -- which is why
 * `sentry-auth-token`, whose 40-character run is declared over 65 symbols but
 * issued as hex, is deliberately NOT on the list.
 */
test("every rule declaring the floor declares it at the measured threshold", () => {
  const declared = rules.filter((r) => r.postPrefixEntropy !== undefined);
  assert.ok(declared.length > 0, "no rule declares postPrefixEntropy");
  for (const r of declared) {
    assert.strictEqual(
      r.postPrefixEntropy!.min,
      3.75,
      `${r.id} declares a threshold other than the measured 3.75`
    );
  }
});

test("the floor is enabled on exactly the measured-safe rule set", () => {
  const enabled = rules
    .filter((r) => r.postPrefixEntropy !== undefined)
    .map((r) => r.id)
    .sort();
  assert.deepStrictEqual(enabled, [
    "atlassian-api-token",
    "facebook-access-token",
    "github-fine-grained-pat",
    "intercom-token",
    "jfrog-token",
    "pypi-token",
    "square-access-token",
    "twitter-bearer-token",
  ]);
});

/**
 * A prefix pattern that stops matching its own rule silently disables the
 * floor. The check fails open by design -- a filter that cannot see the
 * structure it filters must not drop a finding -- so nothing would report the
 * drift except this.
 */
test("every declared prefix still matches its own rule's shape", () => {
  for (const r of rules) {
    const pp = r.postPrefixEntropy;
    if (!pp) continue;
    const probe = REALISTIC.find(([label]) => label.startsWith(r.id));
    assert.ok(probe, `${r.id} declares the floor but has no realistic fixture here`);
    const m = pp.prefix.exec(probe![1]);
    assert.ok(m, `${r.id}'s prefix pattern no longer matches its own token shape`);
    assert.ok(
      m![0].length > 0 && m![0].length < probe![1].length,
      `${r.id}'s prefix pattern consumed nothing or everything`
    );
  }
});

/**
 * The documented scope boundary, encoded so it cannot be crossed by accident.
 *
 * The benchmark proposed this same floor for its N4 family -- fixed-prefix
 * rules firing inside base64 asset data. Measurement rejected that: the N4
 * false positive carries 4.810 bits over 95 characters, while the least random
 * of 10,000,000 uniformly random tokens of that length carries 4.885. The gap
 * is 0.075 bits, INSIDE the legitimate distribution's own tail, so no threshold
 * separates them.
 *
 * This test asserts the floor does not reach that far. It is here so that
 * lowering the threshold to catch N4 fails loudly and reopens the collateral
 * argument, rather than quietly trading real credentials for five findings.
 */
test("the floor does not reach N4-shaped base64 asset data", () => {
  const n4 = "EAAA" + gen(95, B64URL);
  const h = shannonEntropy(after(n4, "EAAA"));
  assert.ok(h > 4.7, `N4-shaped fixture should be high entropy, got ${h.toFixed(3)}`);
  assert.ok(
    ruleIdsFor(`d="${n4}"`).includes("square-access-token"),
    "the floor was lowered far enough to reach N4 -- see the collateral argument above"
  );
});

// ----------------------------------------------------------------- boundary

suite("\n0.1.3 — behaviour at the threshold");

test("a value just below the floor is declined and just above is reported", () => {
  // Tuned by construction rather than by search: dominance is the only knob,
  // and entropy falls monotonically as the dominant character takes more slots.
  let below: string | undefined;
  let above: string | undefined;
  for (let dominant = 20; dominant < 80; dominant++) {
    const run = lowDiversityRun(120, dominant, 40);
    const h = shannonEntropy(run);
    if (h < 3.75 && below === undefined) below = TWITTER_PREFIX + run;
    if (h >= 3.75) above = TWITTER_PREFIX + run;
  }
  // `above` is the last one at or over the floor; walk down for the closest.
  assert.ok(below && above, "could not construct values on both sides of the floor");
  assert.ok(
    !ruleIdsFor(`x = "${below}"`).includes("twitter-bearer-token"),
    "a below-floor value reported"
  );
  assert.ok(
    ruleIdsFor(`x = "${above}"`).includes("twitter-bearer-token"),
    "an above-floor value was declined"
  );
});

finish();
