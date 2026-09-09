import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import { createHash } from "crypto";
import * as path from "path";
import { scanText, maskFindings, isGenericTier, isEntropyTier, Finding } from "../src/scanner";
import { rules, genericRuleIds } from "../src/rules";
import { mergeConfig } from "../src/config";
import { shannonEntropy } from "../src/entropy";
import { scanFiles } from "../src/workspace";
import { buildZip } from "./archive-builders";

/**
 * encryption-key-assignment: a keyword-anchored shape rule for a quoted
 * 32-byte symmetric key in canonical base64 (exactly 43 symbols and one `=`)
 * assigned to an `aes…key`, `secretbox…key` or `encryption…key` identifier.
 *
 * Frozen contract: secretloop-benchmark/c2-encryption-key-recall-a1
 * (policies/candidate-clarified.md, selected variant "clar + A1 + A3"):
 * GAK's separator and quote grammar, any identifier prefix, no suffix, an
 * optional AES key-size token, entropy floor 3.5, `generic: true`, severity
 * high, value-strategy fingerprint, no verifier, no canonical trailing-bit
 * check. Every value below is synthetic and built at runtime or by
 * concatenation, so a scan of this repository does not carry a literal key.
 */

const RULE = "encryption-key-assignment";
const CLI = path.join(__dirname, "..", "out", "cli.js");
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** A random-looking 44-character base64 value (43 symbols + "="), deterministic per salt. */
function key(salt: number): string {
  let s = 0x9e3779b9 ^ (salt * 2654435761);
  let out = "";
  for (let i = 0; i < 43; i++) {
    s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
    out += B64[Math.abs(s) % 64];
  }
  return out + "=";
}
const digest16 = (v: string) => createHash("sha256").update(v).digest("hex").slice(0, 16);
const ours = (fs: Finding[]) => fs.filter((f) => f.ruleId === RULE);
const cfg = (raw: Parameters<typeof mergeConfig>[0] = {}) => mergeConfig(raw);
const scan = (text: string, filePath?: string, raw: Parameters<typeof mergeConfig>[0] = {}) =>
  scanText(text, { config: cfg(raw), filePath });

function withRepo(files: Record<string, string | Buffer>, fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-eka-"));
  try {
    for (const [rel, body] of Object.entries(files)) {
      const full = path.join(dir, rel);
      mkdirSync(path.dirname(full), { recursive: true });
      writeFileSync(full, body);
    }
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const cli = (args: string[], dir: string) =>
  spawnSync("node", [CLI, ...args, "--path", dir], { encoding: "utf8" });

// ---------------------------------------------------------------------------
suite("encryption-key-assignment — the target shape, entropy OFF, in a test path");

test("the F3 shape reports at default settings inside a fixture path, with the frozen identity", () => {
  const v = key(1);
  const text = `package x\n\nconst (\n\toldAESCBCKey = "${v}"\n\toldSecretVal = "x"\n)\n`;
  const file = "test/integration/transformation/transformation_test.go";
  const found = scan(text, file);
  assert.strictEqual(found.length, 1, "exactly one finding, the named rule");
  const f = found[0];
  assert.strictEqual(f.ruleId, RULE);
  assert.strictEqual(f.severity, "high");
  assert.strictEqual(f.confidence, "format-match");
  assert.strictEqual(f.value, v, "the capture is the 44-character value alone");
  assert.strictEqual(text.slice(f.startIndex, f.endIndex), v, "span == capture");
  // The prefix is accepted but not matched: like generic-api-key-assignment,
  // the regex has no left boundary, so the match begins at the keyword tail.
  assert.strictEqual(text.slice(f.matchStart!, f.matchEnd!), `AESCBCKey = "${v}"`, "match == keyword tail through closing quote");
  assert.strictEqual(f.line, 4);
  assert.strictEqual(f.fingerprintStrategy, "value");
  assert.strictEqual(f.fingerprint, `${file}:${RULE}:${digest16(v)}`, "value-strategy fingerprint: path:rule:sha256(value)[0:16]");
});

test("no verifier: the rule is not a generic-tier suppression candidate and is a generic-tier overlap member", () => {
  assert.ok(rules.some((r) => r.id === RULE), "rule is registered");
  assert.ok(genericRuleIds.has(RULE), "generic: true");
  assert.strictEqual(isGenericTier(RULE), true);
  assert.strictEqual(isEntropyTier(RULE), false, "never fixture-suppressed");
  const rule = rules.find((r) => r.id === RULE)!;
  assert.strictEqual(rule.entropy, 3.5);
  assert.strictEqual(rule.fullMatch, false);
  assert.deepStrictEqual(rule.keywords, ["aes", "secretbox", "encryption"]);
  assert.strictEqual(rule.fingerprintStrategy, undefined, "value strategy by default");
});

// ---------------------------------------------------------------------------
suite("\nidentifier families, AES key-size token, prefix acceptance, suffix rejection");

const POSITIVE_IDENTS = [
  "aesKey", "aes_key", "AES_KEY", "aesCBCKey", "aes_cbc_key", "aesGCMKey", "aes-gcm-key",
  "aes128Key", "aes_192_cbc_key", "AES256_KEY", "aes-256-gcm-key", "aes256gcmkey",
  "secretboxKey", "secretbox_key", "SECRETBOX_KEY",
  "encryptionKey", "encryption_key", "encryption-key", "Encryption.Key",
  "oldAESCBCKey", "keyEncryptionKey", "myaeskey", "dataEncryptionKey",
];
for (const ident of POSITIVE_IDENTS) {
  test(`identifier ${ident} = "<44>" is detected`, () => {
    const v = key(2);
    const found = ours(scan(`${ident} = "${v}"\n`));
    assert.strictEqual(found.length, 1, `${ident} must match`);
    assert.strictEqual(found[0].value, v);
  });
}

const NEGATIVE_IDENTS = [
  "encryptionKeyId", "aesKeyName", "encryption_keys", "encryptionKeyBase64", "encryption_key_name",
  "aesKeyRef", "aes_key_size", "encryptionKeyDigest", "aesMode", "aes512_key", "aes key",
];
// Not a control: the declared regex's three optional separators accept a
// doubled one (`aes__key`), exactly as the evaluated C2 regex did. Pinned so a
// narrowing of the grammar is a visible contract change, not a silent one.
test("a doubled separator inside the aes family is inside the declared grammar", () => {
  assert.strictEqual(ours(scan(`aes__key = "${key(3)}"\n`)).length, 1);
});
for (const ident of NEGATIVE_IDENTS) {
  test(`identifier ${ident} = "<44>" is NOT detected (suffix or non-identifier)`, () => {
    assert.deepStrictEqual(ours(scan(`${ident} = "${key(3)}"\n`)), []);
  });
}

test("a bracketed list after the keyword does not match (separator must follow the tail)", () => {
  assert.deepStrictEqual(ours(scan(`aesKeys = ["${key(4)}"]\n`)), []);
  assert.deepStrictEqual(ours(scan(`aes_key: ["${key(4)}"]\n`)), []);
});

// ---------------------------------------------------------------------------
suite("\nseparator and quote grammar (GAK's)");

test("`:=`, `=`, `:` and a quoted identifier all match; single and double quotes both", () => {
  const v = key(5);
  for (const line of [
    `aesCBCKey := "${v}"`, `aesCBCKey = "${v}"`, `aesCBCKey="${v}"`, `aes_cbc_key: "${v}"`,
    `"aescbcKey": "${v}"`, `AES_KEY = '${v}'`, `encryptionKey: '${v}'`, `'encryption_key': "${v}"`,
  ]) {
    assert.strictEqual(ours(scan(line + "\n")).length, 1, `must match: ${line.slice(0, 24)}…`);
  }
});

test("whitespace around the separator may cross a newline; the value never does", () => {
  const v = key(6);
  assert.strictEqual(ours(scan(`var encryptionKey =\n\t"${v}"\n`)).length, 1);
  assert.deepStrictEqual(ours(scan(`var encryptionKey = "${v.slice(0, 20)}\n${v.slice(20)}"\n`)), []);
});

test("backticks, bare values, `=>`, a type annotation and concatenation are outside the grammar", () => {
  const v = key(7);
  for (const line of [
    "aesKey := `" + v + "`",
    `ENCRYPTION_KEY=${v}`,
    `encryption.key=${v}`,
    `- secret: ${v}`,
    `'encryption_key' => '${v}'`,
    `pub const SECRETBOX_KEY: &str = "${v}";`,
    `aesKey := "${v.slice(0, 22)}" + "${v.slice(22)}"`,
  ]) {
    assert.deepStrictEqual(ours(scan(line + "\n")), [], `must not match: ${line.slice(0, 30)}…`);
  }
});

// ---------------------------------------------------------------------------
suite("\nthe captured value: exactly 43 base64 symbols and one `=`");

test("length and alphabet near-misses do not match", () => {
  const v = key(8);
  for (const value of [
    v.slice(0, 43) + "==",          // double pad
    v.slice(0, 43) + "A",           // 44, no pad
    "A" + v,                        // 45
    v.slice(0, 42) + "=",           // 43
    v.slice(0, 10) + "-" + v.slice(11), // URL-safe alphabet
    v.slice(0, 10) + "_" + v.slice(11),
    "0123456789abcdef".repeat(4),   // 64 hex
    v.slice(0, 32),                 // 24-byte key shape
    v.slice(0, 22) + "==",          // 16-byte key shape
  ]) {
    assert.deepStrictEqual(ours(scan(`aesKey = "${value}"\n`)), [], `must not match value of length ${value.length}`);
  }
});

test("a non-canonical trailing symbol is ACCEPTED (A2 not adopted): decoders take it as a working key", () => {
  const v = key(9);
  // Force the 43rd symbol to carry non-zero padding bits: `B` (index 1).
  const nonCanonical = v.slice(0, 42) + "B=";
  assert.ok(!/[AEIMQUYcgkosw048]=$/.test(nonCanonical), "precondition: not encoder output");
  assert.strictEqual(ours(scan(`aesKey = "${nonCanonical}"\n`)).length, 1);
});

// ---------------------------------------------------------------------------
suite("\nentropy floor 3.5 and placeholder handling");

test("degenerate values pass isPlaceholder (the `=` defeats the repeated-character rule) and are rejected by the floor", () => {
  for (const value of ["A".repeat(43) + "=", "x".repeat(43) + "=", "ab".repeat(21) + "a="]) {
    assert.ok(shannonEntropy(value) < 3.5, "precondition: below the floor");
    assert.deepStrictEqual(ours(scan(`encryptionKey = "${value}"\n`)), [], `rejected: ${value.slice(0, 6)}…`);
  }
});

test("the floor is `entropy < 3.5 rejects`: just below is dropped, at-or-above reports", () => {
  // The pad is itself a symbol of the captured value. 10 symbols cycled over
  // the 43 positions plus "=" -> ~3.39 bits; 11 symbols plus "=" -> ~3.53 bits.
  const build = (n: number) => {
    let out = "";
    for (let i = 0; i < 43; i++) out += B64[i % n];
    return out + "=";
  };
  const below = build(10);
  const above = build(11);
  assert.ok(shannonEntropy(below) < 3.5 && shannonEntropy(below) > 3.3, `below: ${shannonEntropy(below)}`);
  assert.ok(shannonEntropy(above) >= 3.5 && shannonEntropy(above) < 3.7, `above: ${shannonEntropy(above)}`);
  assert.deepStrictEqual(ours(scan(`aesKey = "${below}"\n`)), [], "just below the floor is dropped");
  assert.strictEqual(ours(scan(`aesKey = "${above}"\n`)).length, 1, "at or above the floor reports");
});

test("template expansions, brace placeholders and DOC_SAMPLE values never report", () => {
  for (const value of ["${ENCRYPTION_KEY}", "{{ .Values.encryptionKey }}", "{ENCRYPTION_KEY}"]) {
    assert.deepStrictEqual(ours(scan(`encryptionKey: "${value}"\n`)), []);
  }
  // /EXAMPLE/i is the one DOC_SAMPLE pattern the base64 alphabet can carry.
  const v = key(10);
  const sample = v.slice(0, 10) + "EXAMPLE" + v.slice(17);
  assert.ok(shannonEntropy(sample) >= 3.5);
  assert.deepStrictEqual(ours(scan(`encryptionKey = "${sample}"\n`)), [], "documentation sample is allowlisted");
});

// ---------------------------------------------------------------------------
suite("\nexclusions, inline directives, allowValues, mask");

test("excludeRules disables the rule; allowValues drops the value; inline directives suppress and are counted", () => {
  const v = key(11);
  const line = `encryptionKey = "${v}"\n`;
  assert.deepStrictEqual(ours(scan(line, "a.go", { excludeRules: [RULE] })), []);
  assert.deepStrictEqual(ours(scan(line, "a.go", { allowValues: ["^" + v.slice(0, 8)] })), []);
  let suppressed = 0;
  const same = scanText(`encryptionKey = "${v}" // secretloop:allow\n`, { config: cfg(), filePath: "a.go", onSuppressed: (n) => (suppressed += n) });
  assert.deepStrictEqual(ours(same), []);
  const above = scanText(`# secretloop-ignore\nencryptionKey = "${v}"\n`, { config: cfg(), filePath: "a.go", onSuppressed: (n) => (suppressed += n) });
  assert.deepStrictEqual(ours(above), []);
  assert.strictEqual(suppressed, 2, "each suppressed span is disclosed once");
  const ignored = scanText(`encryptionKey = "${v}" // gitleaks:allow\n`, { config: cfg(), honorInlineDirectives: false });
  assert.strictEqual(ours(ignored).length, 1, "mask-style callers do not honour directives");
});

test("mask replaces the captured span with the rule id", () => {
  const v = key(12);
  const text = `aes_key: "${v}"\n`;
  const found = scanText(text, { config: cfg(), honorInlineDirectives: false });
  assert.strictEqual(maskFindings(text, found), `aes_key: "[REDACTED:${RULE}]"\n`);
});

// ---------------------------------------------------------------------------
suite("\noverlap with the entropy tier and with generic-api-key-assignment");

const F3_LIKE = (v1: string, v2: string) =>
  `package x\n\nconst (\n\toldAESCBCKey = "${v1}"\n\toldSecret    = "${v2}"\n)\n`;

test("entropy ON + fixtures included: the named finding claims line 4; the entropy finding at line 5 is unchanged", () => {
  const v1 = key(13), v2 = key(14);
  const file = "test/integration/x_test.go";
  const found = scan(F3_LIKE(v1, v2), file, { entropyPassEnabled: true, includeFixtures: true });
  assert.deepStrictEqual(found.map((f) => [f.ruleId, f.line]), [[RULE, 4], ["generic-high-entropy", 5]]);
  assert.strictEqual(found[1].fingerprint, `${file}:generic-high-entropy:${digest16(v2)}`, "line-5 identity untouched");
  assert.strictEqual(found[0].fingerprint, `${file}:${RULE}:${digest16(v1)}`, "line-4 identity is the named rule's");
});

test("entropy ON, fixtures suppressed: the named finding survives and only the line-5 entropy finding is counted as suppressed", () => {
  const v1 = key(15), v2 = key(16);
  let fixtureSuppressed = 0;
  const found = scanText(F3_LIKE(v1, v2), {
    config: cfg({ entropyPassEnabled: true }),
    filePath: "test/integration/x_test.go",
    onFixtureSuppressed: (n) => (fixtureSuppressed += n),
  });
  assert.deepStrictEqual(found.map((f) => f.ruleId), [RULE]);
  assert.strictEqual(fixtureSuppressed, 1, "the claimed span is never offered to the entropy pass, so it is not counted");
});

test("generic-api-key-assignment never co-reports the same span", () => {
  const v = key(17);
  for (const line of [`encryption_key = "${v}"`, `aes_secret_key = "${v}"`, `secret_encryption_key = "${v}"`, `private_aes_key = "${v}"`]) {
    const found = scan(line + "\n", "a.go");
    const spans = found.map((f) => `${f.startIndex}:${f.endIndex}`);
    assert.strictEqual(new Set(spans).size, spans.length, `one finding per span: ${line.slice(0, 22)}`);
    for (const f of found) assert.ok(!f.alsoMatched?.includes(RULE), "the rule yields to nothing here");
  }
  assert.deepStrictEqual(scan(`encryption_key = "${v}"\n`).map((f) => f.ruleId), [RULE]);
});

test("API description documents: the named rule is unconditional while the entropy tier is scoped", () => {
  const v = key(18);
  const doc = JSON.stringify({ openapi: "3.0.0", info: { title: "x", version: "1" }, paths: {}, components: { examples: { encryptionKey: v } } });
  let scoped = 0;
  const found = scanText(doc, { config: cfg({ entropyPassEnabled: true }), filePath: "api/openapi.json", onApiDocumentScoped: () => scoped++ });
  assert.strictEqual(scoped, 1, "the document is recognised and the entropy pass skipped");
  assert.deepStrictEqual(found.map((f) => f.ruleId), [RULE]);
});

// ---------------------------------------------------------------------------
suite("\nencoded and archive composition");

test("a base64-encoded `aes_key: \"…\"` reports through the encoded pass with the transform recorded", () => {
  const v = key(19);
  const blob = Buffer.from(`aes_key: "${v}"\n`, "utf8").toString("base64");
  const found = ours(scan(`data: ${blob}\n`, "deploy/enc.b64"));
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].encoding, "base64");
  assert.strictEqual(found[0].value, blob, "the encoded source span is the value; the decoded key is not retained");
});

test("an archive member reports with the container path and source metadata", () => withRepo({}, (dir) => {
  const v = key(20);
  writeFileSync(path.join(dir, "bundle.zip"), buildZip([{ name: "config/enc.yaml", data: Buffer.from(`encryptionKey: "${v}"\n`) }]));
  const found = ours(scanFiles(dir, ["bundle.zip"], cfg()).flatMap((s) => s.findings));
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].file, "bundle.zip!/config/enc.yaml");
  assert.strictEqual(found[0].source?.member, "config/enc.yaml");
  assert.strictEqual(found[0].value, v);
}));

// ---------------------------------------------------------------------------
suite("\nCLI (built bundle)");

test("scan reports it in JSON with the frozen fingerprint, at default settings, in a test path", () => {
  const v = key(21);
  withRepo({ "test/integration/x_test.go": `package x\n\nvar oldAESCBCKey = "${v}"\n` }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json", "--fail-on", "never"], dir).stdout);
    assert.deepStrictEqual(d.findings.map((f: any) => [f.ruleId, f.line, f.severity, f.confidence]), [[RULE, 3, "high", "format-match"]]);
    assert.strictEqual(d.findings[0].fingerprint, `test/integration/x_test.go:${RULE}:${digest16(v)}`);
    assert.strictEqual(d.summary.scope, "1 file(s)");
  });
});

test("scan --include-entropy: the suppressed-count disclosure counts only the entropy line", () => {
  const v1 = key(22), v2 = key(23);
  withRepo({ "test/integration/x_test.go": F3_LIKE(v1, v2) }, (dir) => {
    const d = JSON.parse(cli(["scan", "--format", "json", "--fail-on", "never", "--include-entropy"], dir).stdout);
    assert.deepStrictEqual(d.findings.map((f: any) => f.ruleId), [RULE]);
    assert.match(d.summary.scope, /1 generic finding\(s\) suppressed in test\/fixture paths/);
    const inc = JSON.parse(cli(["scan", "--format", "json", "--fail-on", "never", "--include-entropy", "--include-fixtures"], dir).stdout);
    assert.deepStrictEqual(inc.findings.map((f: any) => [f.ruleId, f.line]), [[RULE, 4], ["generic-high-entropy", 5]]);
  });
});

finish();
