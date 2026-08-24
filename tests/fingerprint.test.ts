import { scanText, secretFreeContext, Finding } from "../src/scanner";
import { createFingerprint, BASELINE_VERSION, loadBaseline } from "../src/config";
import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";

const GH_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

function fingerprintsOf(text: string, filePath = "src/app.ts"): Finding[] {
  return scanText(text, { filePath });
}

function only(text: string, ruleId: string, filePath = "src/app.ts"): Finding {
  const hit = fingerprintsOf(text, filePath).find((f) => f.ruleId === ruleId);
  if (!hit) throw new Error(`no ${ruleId} finding in: ${text}`);
  return hit;
}

suite("config.ts — fingerprint strategies");

test("a password-bearing finding keeps its fingerprint when only the password changes", () => {
  // The invariant the whole change exists for: a committed baseline must not
  // encode anything an attacker can run a wordlist against.
  const a = only('DATABASE_URL=postgres://svc:Alpha-97xQ-one@host:5432/app', "db-connection-string");
  const b = only('DATABASE_URL=postgres://svc:Bravo-42kT-two@host:5432/app', "db-connection-string");
  assert.strictEqual(a.fingerprint, b.fingerprint);
});

test("the same password in different files gets different fingerprints", () => {
  const a = only('DATABASE_URL=postgres://svc:Alpha-97xQ-one@host/app', "db-connection-string", "config/a.env");
  const b = only('DATABASE_URL=postgres://svc:Alpha-97xQ-one@host/app', "db-connection-string", "config/b.env");
  assert.notStrictEqual(a.fingerprint, b.fingerprint);
});

test("different rules over the same context differ", () => {
  const value = createFingerprint({
    filePath: "src/app.ts",
    ruleId: "db-connection-string",
    strategy: "context",
    value: "irrelevant",
    context: "same context",
  });
  const other = createFingerprint({
    filePath: "src/app.ts",
    ruleId: "http-basic-auth-url",
    strategy: "context",
    value: "irrelevant",
    context: "same context",
  });
  assert.notStrictEqual(value, other);
});

test("unrelated formatting does not change a context fingerprint", () => {
  const plain = only('DATABASE_URL=postgres://svc:Alpha-97xQ-one@host:5432/app', "db-connection-string");
  const spaced = only(
    '\n\n// an unrelated line\nDATABASE_URL=postgres://svc:Alpha-97xQ-one@host:5432/app   \n',
    "db-connection-string"
  );
  assert.strictEqual(plain.fingerprint, spaced.fingerprint);
});

test("non-password rules keep value-based fingerprints", () => {
  // Proves the change is scoped: two different tokens must stay distinguishable.
  const a = only(`const t = "${GH_TOKEN}";`, "github-token");
  const b = only('const t = "ghp_26C7e42F292c6912E7710c838347Ae178B4a";', "github-token");
  assert.notStrictEqual(a.fingerprint, b.fingerprint);
  assert.strictEqual(a.fingerprintStrategy, "value");
});

suite("\nscanner.ts — the fingerprint input carries no secret");

test("the captured password is absent from the context", () => {
  const text = 'DATABASE_URL=postgres://svc:Hunter2-Delta-9x@host:5432/app';
  const findings = scanText(text, { filePath: "src/app.ts" });
  const hit = findings.find((f) => f.ruleId === "db-connection-string")!;
  const context = secretFreeContext(text, hit.matchStart!, hit.matchEnd!, findings);
  assert.ok(!context.includes("hunter2"), `password leaked into: ${context}`);
  assert.match(context, /postgres:\/\//, "but the structural context survives");
  assert.match(context, /host:5432/);
});

test("another finding's secret on the same line never enters the context", () => {
  // Redacting only this finding's span would write a live GitHub token into a
  // committed baseline — a fingerprinting fix with a worse leak than the bug.
  const text = `DB=postgres://svc:Pw1-Charlie-88z@h/db  # legacy: ${GH_TOKEN}`;
  const findings = scanText(text, { filePath: "src/app.ts" });
  const hit = findings.find((f) => f.ruleId === "db-connection-string")!;
  const context = secretFreeContext(text, 0, text.length, findings);
  assert.ok(!context.includes(GH_TOKEN), `another secret leaked into: ${context}`);
  assert.ok(!context.includes("Pw1-Charlie-88z"));
  assert.ok(hit.fingerprint && !hit.fingerprint.includes(GH_TOKEN));
});

suite("\nscanner.ts — strategy selection");

test("password and passwd route to context, within the same rule", () => {
  const pw = only('password = "Passw0rd-Delta-97xQ"', "generic-api-key-assignment");
  const pwd = only('db_passwd: "Xk7-Foxtrot-92mQz"', "generic-api-key-assignment");
  assert.strictEqual(pw.fingerprintStrategy, "context");
  assert.strictEqual(pwd.fingerprintStrategy, "context");
});

test("api_key and client_secret stay on value, within the same rule", () => {
  const key = only('api_key = "aB3xY7zQ1mN8pL4vK6wR"', "generic-api-key-assignment");
  const secret = only('client_secret = "aB3xY7zQ1mN8pL4vK6wR"', "generic-api-key-assignment");
  assert.strictEqual(key.fingerprintStrategy, "value");
  assert.strictEqual(secret.fingerprintStrategy, "value");
});

test("all three arbitrary-text rules use context", () => {
  assert.strictEqual(
    only('DB=postgres://svc:Alpha-97xQ-one@h/db', "db-connection-string").fingerprintStrategy,
    "context"
  );
  assert.strictEqual(
    only('fetch("https://svc:aB3xY7zQ@h/x")', "http-basic-auth-url").fingerprintStrategy,
    "context"
  );
  assert.strictEqual(
    only('snowflake_password = "Golf-Hotel-91xQ"', "snowflake-credentials").fingerprintStrategy,
    "context"
  );
});

suite("\nscanner.ts — collision fallback");

test("two password findings in one file get different fingerprints", () => {
  // Both reduce to `password = "[REDACTED]"`, so the match alone cannot tell
  // them apart and baselining one would silence the other.
  const text = ['db_password = "Jd9-Alpha-58kRyBn"', 'api_password = "Zq4-Second-81vTnR"'].join("\n");
  const findings = scanText(text, { filePath: "src/app.ts" }).filter(
    (f) => f.ruleId === "generic-api-key-assignment"
  );
  assert.strictEqual(findings.length, 2, "expected both password findings");
  assert.notStrictEqual(findings[0].fingerprint, findings[1].fingerprint);
});

test("the fallback is deterministic across scans", () => {
  const text = ['password = "Alpha-One-97xQ-mN"', 'password = "Bravo-Two-42kT-pL"'].join("\n");
  const first = scanText(text, { filePath: "src/app.ts" }).map((f) => f.fingerprint);
  const second = scanText(text, { filePath: "src/app.ts" }).map((f) => f.fingerprint);
  assert.deepStrictEqual(first, second);
});

suite("\nconfig.ts — baseline v2");

test("newly written baselines declare version 2", () => {
  assert.strictEqual(BASELINE_VERSION, 2);
});

test("a v1 baseline is reported, not silently matched against", () => {
  // v1 fingerprints hashed the password; interpreting them as v2 would match
  // nothing and resurface every triaged finding with no explanation.
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-baseline-"));
  try {
    const file = path.join(dir, "baseline.json");
    writeFileSync(file, JSON.stringify({ version: 1, fingerprints: ["a:b:c"] }), "utf8");
    const loaded = loadBaseline(file);
    assert.strictEqual(loaded.version, 1);
    assert.ok(loaded.outdated, "a v1 baseline must announce itself as outdated");
    assert.match(loaded.notice ?? "", /regenerat/i, "and say what to do about it");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a v2 baseline loads without a notice", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-baseline-"));
  try {
    const file = path.join(dir, "baseline.json");
    writeFileSync(file, JSON.stringify({ version: 2, fingerprints: ["a:b:c"] }), "utf8");
    const loaded = loadBaseline(file);
    assert.strictEqual(loaded.outdated, false);
    assert.strictEqual(loaded.notice, undefined);
    assert.ok(loaded.fingerprints.has("a:b:c"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

suite("\nbaseline matching end to end");

test("a baselined password finding stays baselined when the password changes", () => {
  const before = only('DATABASE_URL=postgres://svc:Old-Passw0rd-42x@host/app', "db-connection-string");
  const after = only('DATABASE_URL=postgres://svc:New-Passw0rd-73y@host/app', "db-connection-string");
  assert.strictEqual(after.fingerprint, before.fingerprint, "still the same accepted finding");
});

test("changing the logical context does stop it matching", () => {
  const before = only('DATABASE_URL=postgres://svc:Echo-55mN-four@host/app', "db-connection-string");
  const moved = only('DATABASE_URL=postgres://svc:Echo-55mN-four@other-host/app', "db-connection-string");
  assert.notStrictEqual(moved.fingerprint, before.fingerprint, "a different host is a new finding");
});

finish();
