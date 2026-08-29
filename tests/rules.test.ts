import { scanText } from "../src/scanner";
import { rules, isDocumentationSample } from "../src/rules";
import { positiveSamples, negativeSamples } from "./fixtures";
import { test, suite, finish, assert } from "./harness";

suite("rules.ts — detection corpus");

/**
 * The single most important property of a scanner: every shipped rule actually
 * fires on the credential shape it claims to cover. A rule that never matches
 * is worse than no rule, because it creates false confidence.
 */
test("every rule has a fixture in the corpus", () => {
  const missing = rules.map((r) => r.id).filter((id) => !(id in positiveSamples));
  assert.deepStrictEqual(missing, [], `rules with no test fixture: ${missing.join(", ")}`);
});

for (const rule of rules) {
  const sample = positiveSamples[rule.id];
  if (sample === undefined) continue;
  test(`detects ${rule.id}`, () => {
    const findings = scanText(sample);
    const hit = findings.find((f) => f.ruleId === rule.id);
    assert.ok(hit, `${rule.id} did not match its own fixture`);
    assert.strictEqual(hit!.severity, rule.severity);
  });
}

suite("\nrules.ts — false positive corpus");

for (const { label, text } of negativeSamples) {
  test(`stays quiet on ${label}`, () => {
    const findings = scanText(text);
    assert.deepStrictEqual(
      findings.map((f) => `${f.ruleId}:${f.value}`),
      [],
      `expected no findings for ${label}`
    );
  });
}

suite("\nrules.ts — hygiene");

test("the AWS fixture is a fake the rule still fires on, not an allowlisted sample", () => {
  // Two ways this fixture can rot, and the generic "detects <rule>" loop above
  // catches only the first.
  //
  // It went in as a randomly-generated real-format key ID, which detects fine
  // and reads to any outside reader like a planted AWS credential. The obvious
  // repair -- reach for a recognisable placeholder -- walks straight into the
  // second failure: AKIAIOSFODNN7EXAMPLE and anything else carrying /EXAMPLE/i
  // is on DOC_SAMPLE, so the rule correctly DECLINES it and the fixture would
  // then prove the opposite of what it is filed under.
  //
  // So the sentinel has to satisfy both at once, and this pins both. Adding the
  // value to DOC_SAMPLE, to aws-access-key's allowlist or to
  // placeholderDenylist fails here rather than silently turning a positive
  // fixture into a negative one.
  const sample = positiveSamples["aws-access-key"];
  assert.match(sample, /^AKIA[0-9A-Z]{16}$/, "the fixture no longer has the shape the rule matches");
  assert.strictEqual(
    isDocumentationSample(sample),
    false,
    `${sample} is on the documentation-sample allowlist, so it can never be a positive fixture`
  );
  const hit = scanText(sample).find((f) => f.ruleId === "aws-access-key");
  assert.ok(hit, `aws-access-key did not fire on ${sample}`);
  assert.strictEqual(hit!.value, sample, "the rule matched something other than the whole key ID");
});

test("no duplicate rule ids", () => {
  const seen = new Set<string>();
  const dupes: string[] = [];
  for (const r of rules) {
    if (seen.has(r.id)) dupes.push(r.id);
    seen.add(r.id);
  }
  assert.deepStrictEqual(dupes, []);
});

test("every rule regex is global (required for exec loops)", () => {
  const nonGlobal = rules.filter((r) => !r.regex.global).map((r) => r.id);
  assert.deepStrictEqual(nonGlobal, [], `non-global regexes would loop forever: ${nonGlobal}`);
});

test("capture-group rules actually declare a capture group", () => {
  const broken = rules
    .filter((r) => !r.fullMatch)
    .filter((r) => !/\((?!\?[:=!])/.test(r.regex.source))
    .map((r) => r.id);
  assert.deepStrictEqual(broken, []);
});

test("no rule is pathologically slow on adversarial input", () => {
  const adversarial = "a".repeat(400) + "!" + "A".repeat(400) + "=".repeat(400) + ' key="' + "x".repeat(800);
  for (const rule of rules) {
    const started = Date.now();
    rule.regex.lastIndex = 0;
    while (rule.regex.exec(adversarial) !== null) {
      if (Date.now() - started > 300) break;
    }
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 300, `${rule.id} took ${elapsed}ms — possible catastrophic backtracking`);
  }
});

test("no two named rules match the same span anywhere in the corpus", () => {
  // Named-vs-named overlaps are deliberately left unmerged: a tiebreak would
  // bury a rule-design bug that a red build surfaces. Today they are kept
  // disjoint by rule-scoped allowlists and keyword prescreens.
  const collisions: string[] = [];
  for (const [ruleId, sample] of Object.entries(positiveSamples)) {
    const found = scanText(sample, { filePath: `corpus/${ruleId}` });
    for (let i = 0; i < found.length; i++) {
      for (let j = i + 1; j < found.length; j++) {
        const a = found[i];
        const b = found[j];
        if (a.startIndex >= b.endIndex || b.startIndex >= a.endIndex) continue;
        collisions.push(`${ruleId}: ${a.ruleId} + ${b.ruleId}`);
      }
    }
  }
  assert.deepStrictEqual(collisions, [], "fix the overlap with an allowlist, do not add a tiebreak");
});

finish();
