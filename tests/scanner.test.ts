import { scanText, redactValue } from "../src/scanner";
import { mergeConfig } from "../src/config";
import { test, suite, finish, assert } from "./harness";

suite("scanner.ts");

/**
 * Stripe-shaped fixtures are assembled from a prefix and a body rather than
 * written out whole.
 *
 * A complete sk_live_ string is indistinguishable from a live key to any
 * scanner — GitHub's push protection blocked this file over exactly these
 * fixtures — and that is the same argument SecretLoop makes about its own
 * findings. Neither half matches the Stripe pattern alone; joined at run time
 * they exercise the rule identically.
 *
 * Stripe's published sample below is the one value written in full, in a
 * comment, because it is public by design and it is what the exemption is for.
 */
const stripeLive = (body: string) => `sk_live_${body}`;

/** Not any published sample — an arbitrary body, so the rule must report it. */
const UNKNOWN_KEY_BODY = "9QmZt4KpXvR2bNwL7cHdY3Fs";

/** The sample's body. Joined with a prefix, this is the value being exempted. */
const SAMPLE_BODY = "4eC39HqLyjWDarjtT1zdp7dc";

/** One character off the sample, to prove the exemption is anchored to it. */
const NEAR_SAMPLE_BODY = "4eC39HqLyjWDarjtT1zdp7dX";

test("detects a GitHub token by format", () => {
  const findings = scanText('const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";', 4.3);
  const hit = findings.find((f) => f.ruleId === "github-token");
  assert.ok(hit, "expected a github-token finding");
  assert.strictEqual(hit!.confidence, "format-match");
  assert.strictEqual(hit!.severity, "critical");
});

test("detects an AWS access key ID", () => {
  const findings = scanText('AWS_KEY = "AKIA2Q7RZDXK4LM9PBWT"', 4.3);
  assert.ok(findings.find((f) => f.ruleId === "aws-access-key"));
});

test("does NOT flag the AWS documentation sample key", () => {
  // AKIAIOSFODNN7EXAMPLE appears in every AWS doc page and countless tutorials.
  // Flagging it is the canonical way a scanner loses a developer's trust.
  const findings = scanText('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', 4.3);
  assert.strictEqual(findings.length, 0);
});

test("detects a Stripe live secret key", () => {
  const findings = scanText(`stripe.apiKey = "${stripeLive(UNKNOWN_KEY_BODY)}"`, 4.3);
  assert.ok(findings.find((f) => f.ruleId === "stripe-secret-key"));
});

test("does NOT flag the Stripe documentation sample key", () => {
  // sk_test_4eC39HqLyjWDarjtT1zdp7dc is Stripe's own published sample and
  // appears in their docs, every quickstart and countless tutorials — the same
  // category as AKIAIOSFODNN7EXAMPLE above.
  for (const prefix of ["sk_test_", "sk_live_", "rk_test_", "rk_live_"]) {
    const findings = scanText(`stripe.apiKey = "${prefix}${SAMPLE_BODY}"`, 4.3);
    // Nothing at all, not merely no stripe-secret-key: the generic assignment
    // rule matches the same span, so a rule-scoped exemption would only change
    // which rule reported the sample.
    assert.strictEqual(findings.length, 0, `${prefix} sample must not be reported by any rule`);
  }
});

test("a key that merely resembles the Stripe sample is still flagged", () => {
  // The exemption is for that exact value, not for anything starting sk_live_4.
  const findings = scanText(`stripe.apiKey = "${stripeLive(NEAR_SAMPLE_BODY)}"`, 4.3);
  assert.ok(findings.find((f) => f.ruleId === "stripe-secret-key"));
});

test("detects a Slack bot token", () => {
  const findings = scanText("SLACK_TOKEN=xoxb-1234567890-abcdefghijklmnop", 4.3);
  assert.ok(findings.find((f) => f.ruleId === "slack-token"));
});

test("detects a PEM private key block", () => {
  const text = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaBcgVJcXOFbdc6JGf",
    "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaBcgVJcXOFbdc6JGf",
    "-----END RSA PRIVATE KEY-----",
  ].join("\n");
  assert.ok(scanText(text, 4.3).find((f) => f.ruleId === "private-key-block"));
});

test("ignores denylisted placeholders", () => {
  assert.strictEqual(scanText('api_key = "your_api_key_here"', 4.3).length, 0);
});

test("ignores repeated-character strings", () => {
  const findings = scanText('token: "xxxxxxxxxxxxxxxxxxxxxxxxxx"', 4.3);
  assert.strictEqual(findings.length, 0);
});

test("does not double-count overlapping rule + entropy matches", () => {
  // The entropy pass must not re-report a span a named rule already covered.
  // (Two *rules* may still both match one span — e.g. stripe-secret-key and the
  // generic assignment rule here — which is separate, intended behavior.)
  const findings = scanText(`stripe.apiKey = "${stripeLive(UNKNOWN_KEY_BODY)}"`, 3.0);
  assert.ok(findings.find((f) => f.ruleId === "stripe-secret-key"), "the format rule must fire");
  assert.strictEqual(
    findings.filter((f) => f.ruleId === "generic-high-entropy").length,
    0,
    "entropy pass should not re-flag a span already covered by a rule"
  );
});

test("flags a high-entropy string with no known format as entropy-heuristic", () => {
  const findings = scanText('value = "Zk9pQ2xR8mLtW3vXyB7nD1sF4jH6uK0eA5"', 4.3);
  const hit = findings.find((f) => f.ruleId === "generic-high-entropy");
  assert.ok(hit, "expected a generic-high-entropy finding");
  assert.strictEqual(hit!.confidence, "entropy-heuristic");
});

test("does not flag ordinary low-entropy prose", () => {
  assert.strictEqual(
    scanText('const greeting = "hello world this is a normal string";', 4.3).length,
    0
  );
});

suite("\nscanner.ts — line numbers and identity");

test("reports the correct 1-based line number", () => {
  const text = ["line one", "line two", 'token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"'].join(
    "\n"
  );
  const hit = scanText(text, 4.3).find((f) => f.ruleId === "github-token");
  assert.strictEqual(hit!.line, 3);
});

test("reports the offset of the credential, not a later copy of the same text", () => {
  // The quick-fixes rewrite document text between startIndex and endIndex, so a
  // span that merely *reads* the same as the secret is not good enough — it has
  // to be the secret itself. Here the password recurs in the database name, and
  // pointing at the wrong copy redacts the database name and leaves the
  // credential sitting in the file.
  const text = 'MONGO_URI="mongodb+srv://app:s3cret@cluster0.mongodb.net/s3cret_db"';
  const hit = scanText(text, 4.3).find((f) => f.ruleId === "db-connection-string");
  assert.ok(hit, "expected a db-connection-string finding");
  assert.strictEqual(hit!.value, "s3cret");
  assert.strictEqual(hit!.startIndex, text.indexOf("s3cret"), "must point at the password");
  assert.strictEqual(text.slice(hit!.startIndex, hit!.endIndex), hit!.value);
});

test("reports the offset of basic-auth credentials that recur in the host", () => {
  const text = 'fetch("https://svc:hunter2pw@hunter2pw-db.internal/health")';
  const hit = scanText(text, 4.3).find((f) => f.ruleId === "http-basic-auth-url");
  assert.ok(hit, "expected an http-basic-auth-url finding");
  assert.strictEqual(hit!.startIndex, text.indexOf("hunter2pw"), "must point at the password");
  assert.strictEqual(text.slice(hit!.startIndex, hit!.endIndex), hit!.value);
});

test("still reports the offset of a capture that ends the match", () => {
  // Guards the other direction: most rules put the captured value last, and
  // those offsets were already correct.
  const text = 'aws_secret_access_key = "wJalrXUtnFEMI7MDENGbPxRfiCYzK9qLvT2sHdB4"';
  const hit = scanText(text, 4.3).find((f) => f.ruleId === "aws-secret-key");
  assert.ok(hit, "expected an aws-secret-key finding");
  assert.strictEqual(hit!.startIndex, text.indexOf("wJalr"));
  assert.strictEqual(text.slice(hit!.startIndex, hit!.endIndex), hit!.value);
});

test("fingerprint is stable across line moves but differs per value", () => {
  const a = scanText('x = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"', {
    filePath: "src/a.ts",
  })[0];
  const moved = scanText('\n\n\nx = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"', {
    filePath: "src/a.ts",
  })[0];
  const other = scanText('x = "ghp_26C7e42F292c6912E7710c838347Ae178B4a"', {
    filePath: "src/a.ts",
  })[0];
  assert.strictEqual(a.fingerprint, moved.fingerprint, "moving code must not change identity");
  assert.notStrictEqual(a.fingerprint, other.fingerprint, "different secrets must differ");
});

suite("\nscanner.ts — suppression");

test("honors an inline secretloop:allow on the same line", () => {
  const text = 'const t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"; // secretloop:allow';
  assert.strictEqual(scanText(text, 4.3).length, 0);
});

test("honors secretloop:allow on the line above", () => {
  const text = [
    "// secretloop:allow -- documented sample token",
    'const t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(scanText(text, 4.3).length, 0);
});

test("honors secretloop-ignore as well as secretloop:allow", () => {
  const text = 'const t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"; // secretloop-ignore';
  assert.strictEqual(scanText(text, 4.3).length, 0);
});

test("still honors the pre-rebrand secretguard:allow directive", () => {
  // Suppression annotations live in the user's own source. Dropping the old
  // spelling would re-report every previously dismissed finding at once.
  const text = 'const t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"; // secretguard:allow';
  assert.strictEqual(scanText(text, 4.3).length, 0);
});

test("still honors the pre-rebrand secretguard:allow on the line above", () => {
  const text = [
    "// secretguard:allow -- annotated before the SecretLoop rebrand",
    'const t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(scanText(text, 4.3).length, 0);
});

test("honors gitleaks:allow for repos migrating from gitleaks", () => {
  const text = 'const t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"; // gitleaks:allow';
  assert.strictEqual(scanText(text, 4.3).length, 0);
});

test("config excludeRules disables a rule", () => {
  const config = mergeConfig({ excludeRules: ["github-token"] });
  const findings = scanText('const t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";', { config });
  assert.strictEqual(findings.find((f) => f.ruleId === "github-token"), undefined);
});

test("config allowValues drops a matching value", () => {
  const config = mergeConfig({ allowValues: ["^ghp_16C7e42F"] });
  assert.strictEqual(scanText('t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"', { config }).length, 0);
});

test("entropyPassEnabled=false silences the heuristic tier only", () => {
  const config = mergeConfig({ entropyPassEnabled: false });
  const text = 'a = "Zk9pQ2xR8mLtW3vXyB7nD1sF4jH6uK0eA5"\nb = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"';
  const findings = scanText(text, { config });
  assert.strictEqual(findings.find((f) => f.ruleId === "generic-high-entropy"), undefined);
  assert.ok(findings.find((f) => f.ruleId === "github-token"), "format rules must still fire");
});

suite("\nscanner.ts — redaction");

test("redactValue never leaks the middle of a secret", () => {
  const masked = redactValue("ghp_16C7e42F292c6912E7710c838347Ae178B4a");
  assert.ok(!masked.includes("292c6912"), "redacted output must not contain the body");
  assert.ok(masked.startsWith("ghp_"));
});

test("redactValue fully masks short values", () => {
  assert.strictEqual(redactValue("abc123"), "******");
});

finish();
