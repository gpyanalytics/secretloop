import { test, suite, finish, assert } from "./harness";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { scanText, maskFindings, redactValue, Finding } from "../src/scanner";
import { mergeConfig, fingerprint as legacyFingerprint } from "../src/config";
import { render } from "../src/report";
import { verifyFinding, verifyFindings, VerificationCache } from "../src/verify";
import {
  projectFinding,
  wrapUntrusted,
  toolScan,
  toolVerify,
  setAllowedRoots,
  getAllowedRoots,
  resetSessions,
  setVerifyFetchForTests,
  resetOutboundCountForTests,
  outboundRequestCount,
} from "../src/mcp-core";
import { setConsentRootForTests, listRecords } from "../src/consent";
import { positiveSamples } from "./fixtures";
import { TRANSFORM_ORDER } from "../src/encoded";

/**
 * Encoded-secret detection as the scanner, reports, MCP and verification see
 * it. The plaintext of every fixture is proven detectable FIRST, then encoded
 * at run time -- the same discipline as the frozen Phase A corpus, and the
 * reason no encoded credential is written into this file.
 */

const b64 = (s: string) => Buffer.from(s).toString("base64");
const hex = (s: string) => Buffer.from(s).toString("hex");
const pctFull = (s: string) =>
  [...Buffer.from(s)].map((b) => "%" + b.toString(16).toUpperCase().padStart(2, "0")).join("");

const dsn = "mongodb+srv://app:s3cret@cluster0.mongodb.net/s3cret_db";

/** ruleId -> plaintext whose detection is proven before it is encoded. */
const ORACLES: Array<{ ruleId: string; plain: string }> = [
  { ruleId: "github-token", plain: positiveSamples["github-token"] },
  { ruleId: "aws-access-key", plain: positiveSamples["aws-access-key"] },
  { ruleId: "slack-token", plain: "xoxb-1234567890-abcdefghijklmnop" },
  { ruleId: "huggingface-token", plain: "hf_abcdefghijklmnopqrstuvwxyz0123456789ABCD" },
  { ruleId: "db-connection-string", plain: dsn },
];

type Encoder = { transform: (typeof TRANSFORM_ORDER)[number]; encode: (s: string) => string };
const ENCODERS: Encoder[] = [
  { transform: "base64", encode: b64 },
  { transform: "hex", encode: hex },
  { transform: "url-percent", encode: pctFull },
];

const FILE = "src/settings.txt";

function scan(text: string, extra: Record<string, unknown> = {}): Finding[] {
  return scanText(text, { config: mergeConfig({}), filePath: FILE, ...extra });
}

function encodedFinding(text: string, ruleId: string): Finding {
  const hits = scan(text).filter((f) => f.ruleId === ruleId);
  assert.strictEqual(hits.length, 1, `expected exactly one ${ruleId} finding in ${JSON.stringify(text)}`);
  return hits[0];
}

/** A fetch that answers 200 and counts. Nothing real is contacted. */
function countingFetch() {
  const calls: string[] = [];
  const impl = (async (input: any) => {
    calls.push(typeof input === "string" ? input : String(input));
    return new Response("{}", { status: 200, headers: { "x-oauth-scopes": "repo" } });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

// ---------------------------------------------------------------------------
suite("encoded scan — plaintext oracles first");

for (const { ruleId, plain } of ORACLES) {
  test(`${ruleId}: plaintext is detected before it is encoded`, () => {
    const hits = scan(`credential = "${plain}"`).filter((f) => f.ruleId === ruleId);
    assert.strictEqual(hits.length, 1);
  });
}

// ---------------------------------------------------------------------------
suite("encoded scan — every rule through every transform");

for (const { ruleId, plain } of ORACLES) {
  for (const { transform, encode } of ENCODERS) {
    test(`${ruleId} via ${transform}: rule id, span, line, value invariant, identity`, () => {
      const encoded = encode(plain);
      const text = `# config\nunrelated = 1\nvalue = "${encoded}"\ntrailing\n`;
      const f = encodedFinding(text, ruleId);

      assert.strictEqual(f.ruleId, ruleId, "public rule id is the underlying rule");
      assert.strictEqual(f.line, 3, "line of the encoded source");
      assert.strictEqual(f.value, text.slice(f.startIndex, f.endIndex), "value === slice(start, end)");
      assert.strictEqual(f.value, encoded, "value is the encoded source span");
      assert.strictEqual(f.encoding, transform);
      assert.strictEqual(f.confidence, "format-match");
      assert.strictEqual(f.file, FILE);
      assert.ok(f.fingerprint, "fingerprint assigned");
      assert.ok(!(plain.length > 8 && f.value.includes(plain)), "encoded value does not carry the plaintext");

      // No decoded-plaintext field of any name.
      for (const key of Object.keys(f)) {
        assert.ok(!/decod|plain|transformedSecret/i.test(key), `unexpected field ${key}`);
        const v = (f as any)[key];
        if (typeof v === "string") assert.notStrictEqual(v, plain, `${key} holds the plaintext`);
      }
      assert.ok(!JSON.stringify(f).includes(plain), "serialised finding never contains the plaintext");

      // Deterministic.
      assert.deepStrictEqual(encodedFinding(text, ruleId), f);
    });
  }
}

// ---------------------------------------------------------------------------
suite("encoded scan — identity");

test("transform participates: the same secret under three encodings has three fingerprints", () => {
  const plain = positiveSamples["github-token"];
  const fps = ENCODERS.map(({ encode }) => encodedFinding(`t = "${encode(plain)}"`, "github-token").fingerprint);
  assert.strictEqual(new Set(fps).size, 3);
  const plainFp = encodedFinding(`t = "${plain}"`, "github-token").fingerprint;
  assert.ok(!fps.includes(plainFp), "an encoded finding never collides with the plaintext one");
});

test("a plaintext finding's complete object and fingerprint are unchanged by the feature", () => {
  const plain = positiveSamples["github-token"];
  const text = `const token = "${plain}";`;
  const [f] = scan(text);
  assert.deepStrictEqual(f, {
    ruleId: "github-token",
    description: "GitHub Personal Access Token",
    value: plain,
    startIndex: 15,
    endIndex: 15 + plain.length,
    confidence: "format-match",
    severity: "critical",
    line: 1,
    // Added by the SARIF-column work, not by the encoded feature this test
    // guards. The snapshot is a COMPLETE object, so a new field has to appear
    // here or the assertion stops meaning what it says: startIndex is 15 on a
    // single-line input, and the column is one past it.
    column: 16,
    file: FILE,
    commit: undefined,
    matchStart: 15,
    matchEnd: 15 + plain.length,
    fingerprintStrategy: "value",
    fingerprint: legacyFingerprint(FILE, "github-token", plain),
  });
  assert.ok(!("encoding" in f), "no encoding key on a plaintext finding");
});

test("context-strategy rules keep the password out of the fingerprint when encoded", () => {
  const f = encodedFinding(`dsn=${encodeURIComponent(dsn)}`, "db-connection-string");
  assert.strictEqual(f.fingerprintStrategy, "context");
  assert.strictEqual(f.encoding, "url-percent");
  assert.ok(f.fingerprint);
});

test("two encoded occurrences on two lines are two findings with two identities", () => {
  const plain = positiveSamples["github-token"];
  const text = `a = "${b64(plain)}"\nb = "${hex(plain)}"\n`;
  const hits = scan(text).filter((f) => f.ruleId === "github-token");
  assert.strictEqual(hits.length, 2);
  assert.deepStrictEqual(hits.map((f) => f.line), [1, 2]);
  assert.notStrictEqual(hits[0].fingerprint, hits[1].fingerprint);
});

// ---------------------------------------------------------------------------
suite("encoded scan — controls, directives, entropy");

test("harmless valid encodings yield nothing", () => {
  const harmless = [
    b64("the quick brown fox jumps over the lazy dog"),
    b64('{"page":2,"per_page":50,"sort":"created_at"}'),
    hex("user_profile_avatar_thumbnail_v3"),
    "afdbef61e2979a11b048880d6f2f48cf343c47eb",
    "/api/v2/users%2Fprofile/settings",
    "q=hello%20world%20from%20the%20docs",
    pctFull("the quick brown fox jumps over the lazy dog"),
  ];
  for (const line of harmless) assert.deepStrictEqual(scan(line), [], `unexpected finding in ${line}`);
});

test("an inline allow directive suppresses an encoded finding and is counted", () => {
  let suppressed = 0;
  const text = `t = "${b64(positiveSamples["github-token"])}" # secretloop:allow\n`;
  const hits = scanText(text, { filePath: FILE, onSuppressed: (n) => (suppressed += n) });
  assert.deepStrictEqual(hits, []);
  assert.strictEqual(suppressed, 1);
});

test("with --include-entropy the named rule is reported on the span, not a high-entropy string", () => {
  const text = `secret = "${b64("xoxb-1234567890-abcdefghijklmnop")}"`;
  const hits = scanText(text, { config: mergeConfig({ entropyPassEnabled: true }), filePath: FILE });
  const slack = hits.filter((f) => f.ruleId === "slack-token");
  assert.strictEqual(slack.length, 1);
  const entropy = hits.filter(
    (f) => f.ruleId === "generic-high-entropy" && f.startIndex < slack[0].endIndex && f.endIndex > slack[0].startIndex
  );
  assert.deepStrictEqual(entropy, [], "no entropy finding overlaps the explained span");
});

test("a pre-existing entropy-only finding on a harmless blob is left alone", () => {
  const text = `path = "${b64("docs/architecture/decision-records/0007-scanning.md")}"`;
  const withEntropy = scanText(text, { config: mergeConfig({ entropyPassEnabled: true }) });
  const without = scanText(text, { config: mergeConfig({}) });
  assert.deepStrictEqual(without, []);
  assert.ok(withEntropy.every((f) => f.ruleId === "generic-high-entropy"));
});

// ---------------------------------------------------------------------------
suite("encoded scan — output safety");

const PLAIN = positiveSamples["github-token"];
const ENC = b64(PLAIN);
const TEXT = `token = "${ENC}"\n`;

test("maskFindings replaces the encoded span and leaks neither form", () => {
  const findings = scan(TEXT);
  const masked = maskFindings(TEXT, findings);
  assert.strictEqual(masked, `token = "[REDACTED:github-token]"\n`);
  assert.ok(!masked.includes(PLAIN) && !masked.includes(ENC));
});

for (const format of ["text", "json", "sarif"] as const) {
  test(`redacted ${format} report carries no plaintext and no full encoded value`, () => {
    const out = render(scan(TEXT), format, { redact: true, root: "/repo" });
    assert.ok(!out.includes(PLAIN), `${format} leaked the plaintext`);
    assert.ok(!out.includes(ENC), `${format} printed the full encoded value while redacting`);
    assert.ok(out.includes(redactValue(ENC)) || format === "sarif", `${format} shows the redacted encoded value`);
    assert.ok(!/decodedValue|plaintext|transformedSecret/.test(out));
  });

  test(`unredacted ${format} report prints the encoded source, never the plaintext`, () => {
    // The actual contract of --no-redact: it prints what is in the file. What
    // is in the file is the encoded text, and the decoded form was never kept.
    const out = render(scan(TEXT), format, { redact: false, root: "/repo" });
    assert.ok(!out.includes(PLAIN), `${format} --no-redact leaked the plaintext`);
    assert.ok(out.includes(ENC) || format === "sarif", `${format} --no-redact prints the source value`);
  });
}

test("JSON report exposes no encoding-specific or decoded field", () => {
  const parsed = JSON.parse(render(scan(TEXT), "json", { redact: true, root: "/repo" }));
  const keys = Object.keys(parsed.findings[0]);
  assert.ok(!keys.some((k) => /encod|decod|plain|transform/i.test(k)), `unexpected key in ${keys}`);
});

test("MCP projection is masked and carries transform identity nowhere", () => {
  const p = projectFinding(scan(TEXT)[0]);
  const json = JSON.stringify(p);
  assert.ok(!json.includes(PLAIN) && !json.includes(ENC));
  assert.strictEqual(p.redactedValue, redactValue(ENC));
  assert.ok(!Object.keys(p).some((k) => /encod|decod|plain|transform/i.test(k)));
});

test("MCP context window masks the encoded value", () => {
  const values = scan(TEXT).map((f) => f.value);
  const out = JSON.stringify(wrapUntrusted("src/settings.txt", TEXT, 1, 1, values));
  assert.ok(!out.includes(ENC) && !out.includes(PLAIN));
  assert.ok(out.includes(redactValue(ENC)), "the window shows the masked encoded value");
});

test("the only transform metadata on a finding is a transform name", () => {
  const f = scan(TEXT)[0];
  assert.ok((TRANSFORM_ORDER as readonly string[]).includes(f.encoding as string));
});

// ---------------------------------------------------------------------------
suite("encoded scan — verification is refused before any transmission");

test("verifyFinding: encoded finding -> unknown, no fetch", async () => {
  const f = scan(TEXT)[0];
  const { impl, calls } = countingFetch();
  const result = await verifyFinding(f, { fullText: TEXT, fetchImpl: impl });
  assert.ok(result);
  assert.strictEqual(result.status, "unknown");
  assert.strictEqual(result.reason, "unsupported-transform");
  assert.match(result.detail, /base64/);
  assert.match(result.detail, /nothing was sent/i);
  assert.ok(!/\b(dead|revoked|safe|inactive)\b/i.test(result.detail), "never reads as a verdict");
  assert.strictEqual(calls.length, 0, "network calls must be zero");
});

test("the refusal reason is distinct from every other unknown, and the rule keeps its verifier", async () => {
  const f = scan(TEXT)[0];
  const { impl, calls } = countingFetch();
  const result = await verifyFinding(f, { fullText: TEXT, fetchImpl: impl });
  assert.ok(result);
  assert.notStrictEqual(result.reason, "no-verifier", "github-token HAS a verifier");
  assert.ok(!["network", "provider-refused", "provider-unavailable", "missing-pair", "ambiguous-issuer"].includes(result.reason!));
  assert.strictEqual(calls.length, 0);
  // Every unknown reason renders in a report, this one included.
  const marked: Finding = { ...f, verifyStatus: result.status, verifyReason: result.reason, verifyDetail: result.detail };
  const out = render([marked], "text", { redact: true, root: "/repo" });
  assert.match(out, /found in encoded form/);
  assert.ok(!out.includes(PLAIN));
});

test("a rule with no verifier at all is untouched: null result, no reason written, zero fetches", async () => {
  const text = `AccountKey=${"A".repeat(86)}==`;
  const [azure] = scan(text).filter((f) => f.ruleId === "azure-storage-account-key");
  assert.ok(azure, "fixture produced the finding");
  assert.strictEqual(azure.encoding, undefined);
  const { impl, calls } = countingFetch();
  assert.strictEqual(await verifyFinding(azure, { fullText: text, fetchImpl: impl }), null);
  await verifyFindings([azure], { fullText: text, fetchImpl: impl });
  assert.strictEqual(azure.verifyStatus, undefined, "never marked: verifyFindings skips unverifiable rules");
  assert.strictEqual(azure.verifyReason, undefined, "no-verifier is the report's default bucket, never written");
  assert.strictEqual(calls.length, 0);
  const out = render([{ ...azure, verifyStatus: "unknown" }], "text", { redact: true, root: "/repo" });
  assert.match(out, /no verifier exists for this credential type/);
});

test("verifyFindings: encoded findings are marked unknown, never counted outbound, no fetch", async () => {
  const text = ENCODERS.map(({ encode }) => `t = "${encode(PLAIN)}"`).join("\n");
  const findings = scan(text);
  assert.strictEqual(findings.length, 3);
  const { impl, calls } = countingFetch();
  const outbound: Finding[] = [];
  await verifyFindings(findings, { fullText: text, fetchImpl: impl }, { onOutbound: (f) => outbound.push(f) });
  assert.strictEqual(calls.length, 0);
  assert.deepStrictEqual(outbound, []);
  for (const f of findings) {
    assert.strictEqual(f.verifyStatus, "unknown");
    assert.strictEqual(f.verifyReason, "unsupported-transform");
    assert.match(f.verifyDetail ?? "", new RegExp(`${f.encoding}-encoded`));
    assert.strictEqual(f.confidence, "format-match");
  }
});

test("verifyFindings through the cache: still zero fetches, key holds no plaintext", async () => {
  const findings = scan(TEXT);
  const { impl, calls } = countingFetch();
  const cache = new VerificationCache();
  let outbound = 0;
  await verifyFindings(findings, { fullText: TEXT, fetchImpl: impl }, { cache, onOutbound: () => outbound++ });
  await verifyFindings(findings, { fullText: TEXT, fetchImpl: impl }, { cache, onOutbound: () => outbound++ });
  assert.strictEqual(calls.length, 0);
  assert.strictEqual(outbound, 0);
  assert.ok(cache.keys().every((k) => !k.includes(PLAIN) && !k.includes(ENC)));
});

test("an ordinary plaintext finding is still verified exactly as before", async () => {
  const text = `token = "${PLAIN}"\n`;
  const findings = scan(text);
  const { impl, calls } = countingFetch();
  let outbound = 0;
  await verifyFindings(findings, { fullText: text, fetchImpl: impl }, { onOutbound: () => outbound++ });
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(outbound, 1);
  assert.strictEqual(findings[0].verifyStatus, "live");
});

test("MCP secretloop_verify refuses an encoded finding without minting consent", async () => {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-encoded-"));
  const savedRoots = getAllowedRoots();
  try {
    mkdirSync(path.join(base, "repo"), { recursive: true });
    const root = realpathSync(path.join(base, "repo"));
    writeFileSync(path.join(root, "app.js"), TEXT, "utf8");
    setConsentRootForTests(path.join(base, "consent"));
    setAllowedRoots([root]);
    resetSessions();
    resetOutboundCountForTests();
    const { impl, calls } = countingFetch();
    setVerifyFetchForTests(impl);

    const scanResult = toolScan({ path: root }) as { ok: true; payload: any };
    const finding = scanResult.payload.findings.find((f: any) => f.ruleId === "github-token");
    assert.ok(finding, "encoded token surfaced through the MCP scan");
    assert.ok(!JSON.stringify(scanResult).includes(PLAIN));

    const verify = (await toolVerify({ fingerprint: finding.fingerprint, path: root })) as any;
    assert.strictEqual(verify.ok, false);
    assert.match(String(verify.error ?? JSON.stringify(verify)), /base64/);
    assert.match(String(verify.error ?? JSON.stringify(verify)), /nothing will be transmitted/);
    assert.deepStrictEqual(listRecords(), [], "no pending consent record");
    assert.strictEqual(calls.length, 0);
    assert.strictEqual(outboundRequestCount(), 0);
  } finally {
    setAllowedRoots(savedRoots);
    setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

finish();
