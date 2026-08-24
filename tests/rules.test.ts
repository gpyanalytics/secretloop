import { scanText } from "../src/scanner";
import { rules } from "../src/rules";
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
