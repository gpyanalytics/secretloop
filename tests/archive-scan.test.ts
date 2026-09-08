// The vscode stub first, for the extension's action-gating functions below.
import "./stubs/install-vscode";
import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { scanFiles, scanWorkspaceFiles } from "../src/workspace";
import { scanText, Finding, redactValue } from "../src/scanner";
import { mergeConfig, fingerprint as legacyFingerprint, createFingerprint, defaultConfig } from "../src/config";
import { render } from "../src/report";
import { verifyFinding, verifyFindings, VerificationCache } from "../src/verify";
import { detectPkcs12Bytes } from "../src/pkcs12";
import {
  projectFinding, toolScan, toolVerify, setAllowedRoots, getAllowedRoots, resetSessions,
  setVerifyFetchForTests, resetOutboundCountForTests, outboundRequestCount,
} from "../src/mcp-core";
import { setConsentRootForTests, listRecords } from "../src/consent";
import { offersRotation, offersEnvExtraction } from "../src/extension";
import { positiveSamples } from "./fixtures";
import { buildZip, buildTar, buildGzip } from "./archive-builders";

/**
 * Archive members through the real scan path (workspace.scanFiles), the
 * reports, MCP, verification and the CLI. Every archive is built in memory at
 * run time from committed fake fixtures; nothing encoded or packed is written
 * into this file.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const GH = positiveSamples["github-token"];
const SLACK = "xoxb-1234567890-abcdefghijklmnop";
const HF = "hf_abcdefghijklmnopqrstuvwxyz0123456789ABCD";
const DSN = "mongodb+srv://app:s3cret@cluster0.mongodb.net/s3cret_db";
const text = (s: string) => Buffer.from(s, "utf8");
const ENV = text(`# service config\nLOG_LEVEL=info\nGITHUB_TOKEN=${GH}\n`); // secret on line 3
const README = text("# readme\nordinary text, nothing here\n");
const cfg = mergeConfig({});

function withDir(fn: (dir: string) => void): void {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secretloop-archive-")));
  try { fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function put(dir: string, rel: string, bytes: Buffer): void {
  mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  writeFileSync(path.join(dir, rel), bytes);
}
function scanOne(dir: string, rel: string, config = cfg, onSkipped?: (r: string) => void): Finding[] {
  return scanFiles(dir, [rel], config, { onSkipped }).flatMap((s) => s.findings);
}
function countingFetch() {
  const calls: string[] = [];
  const impl = (async (input: any) => { calls.push(String(input)); return new Response("{}", { status: 200, headers: { "x-oauth-scopes": "repo" } }); }) as unknown as typeof fetch;
  return { impl, calls };
}

// Minimal qualifying PKCS#12 (tests/pkcs12.test.ts shape: pkcs7-data outer, one direct keyBag).
function der(tag: number, c: Buffer): Buffer {
  const len = c.length < 0x80 ? Buffer.from([c.length]) : c.length < 0x100 ? Buffer.from([0x81, c.length]) : Buffer.from([0x82, c.length >> 8, c.length & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, c]);
}
const seq = (...p: Buffer[]) => der(0x30, Buffer.concat(p));
const OID_DATA = Buffer.from("06092A864886F70D010701", "hex");
const OID_KEYBAG = Buffer.from("060B2A864886F70D010C0A0101", "hex");
const PKCS12 = seq(der(0x02, Buffer.from([3])), seq(OID_DATA, der(0xa0, der(0x04, seq(seq(OID_DATA, der(0xa0, der(0x04, seq(seq(OID_KEYBAG, der(0xa0, der(0x04, Buffer.alloc(48, 0x4b)))))))))))));

// ---------------------------------------------------------------------------
suite("archive scan — plaintext oracles first");

for (const [rule, plain] of [["github-token", GH], ["slack-token", SLACK], ["huggingface-token", HF], ["db-connection-string", DSN], ["aws-access-key", positiveSamples["aws-access-key"]]] as const) {
  test(`${rule} is detected in plaintext before any archive test relies on it`, () => {
    assert.strictEqual(scanText(`credential = "${plain}"\n`, { filePath: "x.txt" }).filter((f) => f.ruleId === rule).length, 1);
  });
}

// ---------------------------------------------------------------------------
suite("archive scan — members through scanFiles");

test("zip member: rule, display path, member-relative line/offsets, source, fingerprint", () => withDir((dir) => {
  put(dir, "artifacts/bundle.zip", buildZip([{ name: "README.md", data: README }, { name: "src/config.env", data: ENV }]));
  const [f] = scanOne(dir, "artifacts/bundle.zip");
  assert.strictEqual(f.ruleId, "github-token");
  assert.strictEqual(f.file, "artifacts/bundle.zip!/src/config.env");
  assert.strictEqual(f.line, 3);
  assert.strictEqual(ENV.toString("utf8").slice(f.startIndex, f.endIndex), f.value, "offsets are into the member text");
  assert.deepStrictEqual(f.source, { kind: "archive-member", container: "artifacts/bundle.zip", containerKind: "zip", member: "src/config.env" });
  assert.ok(f.fingerprint && f.fingerprint.startsWith("artifacts/bundle.zip!/src/config.env:github-token:"));
  assert.ok(!JSON.stringify(f.source).includes(GH));
}));

test("tar, gzip and tgz members surface the same way; gzip name comes from the outer path", () => withDir((dir) => {
  put(dir, "a.tar", buildTar([{ name: "creds/slack.yaml", data: text(`slack:\n  bot_token: "${SLACK}"\n`) }]));
  put(dir, "logs/app.log.gz", buildGzip(text(`hf_token = '${HF}'\n`), "../../etc/creds"));
  put(dir, "site.tar.gz", buildGzip(buildTar([{ name: "pkg/db.ini", data: text(`[database]\nurl = ${DSN}\n`) }]), "ignored.tar"));
  const tar = scanOne(dir, "a.tar"); const gz = scanOne(dir, "logs/app.log.gz"); const tgz = scanOne(dir, "site.tar.gz");
  assert.deepStrictEqual([tar[0].ruleId, tar[0].file, tar[0].line], ["slack-token", "a.tar!/creds/slack.yaml", 2]);
  assert.deepStrictEqual([gz[0].ruleId, gz[0].file, gz[0].line, gz[0].source!.containerKind], ["huggingface-token", "logs/app.log.gz!/app.log", 1, "gzip"]);
  assert.deepStrictEqual([tgz[0].ruleId, tgz[0].file, tgz[0].line, tgz[0].source!.containerKind], ["db-connection-string", "site.tar.gz!/pkg/db.ini", 2, "tgz"]);
  assert.ok(!JSON.stringify([gz, tgz]).includes("creds") && !JSON.stringify([gz, tgz]).includes("ignored.tar"), "FNAME never appears");
}));

test("a normal file finding has no source key at all, and its complete object is unchanged", () => withDir((dir) => {
  put(dir, "app.ts", text(`const token = "${GH}";\n`));
  const [f] = scanOne(dir, "app.ts");
  assert.ok(!("source" in f));
  assert.strictEqual(f.fingerprint, legacyFingerprint("app.ts", "github-token", GH));
}));

test("the archive counts as ONE scanned file; skipped members are disclosed through the existing reasons", () => withDir((dir) => {
  const big = Buffer.alloc(1_000_001, 0x61);
  put(dir, "x.zip", buildZip([{ name: "ok.txt", data: ENV }, { name: "big.txt", data: big }, { name: "enc.txt", data: ENV, flags: 1, method: 0 }, { name: "bin.dat", data: Buffer.concat([Buffer.from([0, 1, 2, 3]), ENV]) }]));
  const skips: string[] = [];
  const scanned = scanFiles(dir, ["x.zip"], cfg, { onSkipped: (r) => skips.push(r) });
  assert.strictEqual(scanned.length, 1);
  assert.strictEqual(scanned[0].path, "x.zip");
  assert.strictEqual(scanned[0].findings.length, 1);
  assert.deepStrictEqual(skips.sort(), ["oversized", "unreadable", "unreadable"]); // big, encrypted, binary
}));

// ---------------------------------------------------------------------------
suite("archive scan — identity (§18.1)");

test("display collision: a real file named like a member keeps its legacy fingerprint; the member differs", () => withDir((dir) => {
  put(dir, "real.zip!/member.txt", ENV);
  put(dir, "real.zip", buildZip([{ name: "member.txt", data: ENV }]));
  const [real] = scanOne(dir, "real.zip!/member.txt");
  const [member] = scanOne(dir, "real.zip");
  assert.strictEqual(real.file, member.file, "same display string");
  assert.strictEqual(real.fingerprint, legacyFingerprint("real.zip!/member.txt", "github-token", GH));
  assert.ok(!("source" in real));
  assert.notStrictEqual(real.fingerprint, member.fingerprint);
  assert.deepStrictEqual(scanOne(dir, "real.zip")[0].fingerprint, member.fingerprint, "deterministic");
  // baseline suppression does not cross: accepting one leaves the other reported
  const accepted = new Set([real.fingerprint!]);
  assert.ok(!accepted.has(member.fingerprint!));
}));

test("different containers, different members, identical secret bytes -> distinct fingerprints", () => withDir((dir) => {
  put(dir, "a.zip", buildZip([{ name: "one/t.txt", data: ENV }, { name: "two/t.txt", data: ENV }]));
  put(dir, "b.zip", buildZip([{ name: "one/t.txt", data: ENV }]));
  put(dir, "c.tar", buildTar([{ name: "one/t.txt", data: ENV }]));
  const fps = [...scanOne(dir, "a.zip"), ...scanOne(dir, "b.zip"), ...scanOne(dir, "c.tar")].map((f) => f.fingerprint);
  assert.strictEqual(fps.length, 4);
  assert.strictEqual(new Set(fps).size, 4);
}));

test("fingerprint material is the frozen structure, not the display string", () => {
  const source = { kind: "archive-member" as const, container: "a.zip", containerKind: "zip" as const, member: "m.txt" };
  const fp = createFingerprint({ filePath: "a.zip!/m.txt", ruleId: "github-token", strategy: "value", value: GH, source });
  assert.ok(fp.startsWith("a.zip!/m.txt:github-token:"));
  assert.notStrictEqual(fp, legacyFingerprint("a.zip!/m.txt", "github-token", GH));
  // container boundary first, then transform
  const enc = createFingerprint({ filePath: "a.zip!/m.txt", ruleId: "github-token", strategy: "value", value: GH, source, transform: "base64" });
  assert.notStrictEqual(enc, fp);
  assert.strictEqual(createFingerprint({ filePath: "a.zip!/m.txt", ruleId: "github-token", strategy: "value", value: GH }), legacyFingerprint("a.zip!/m.txt", "github-token", GH), "no source -> unchanged formula");
});

// ---------------------------------------------------------------------------
suite("archive scan — detector composition (§18.5)");

test("encoded-v1 composes inside a member: expected named rule, encoding set, distinct identity", () => withDir((dir) => {
  put(dir, "x.zip", buildZip([{ name: "notes.txt", data: text(`payload: ${Buffer.from(GH).toString("base64")}\n`) }, { name: "plain.txt", data: ENV }]));
  const fs = scanOne(dir, "x.zip");
  const enc = fs.find((f) => f.encoding)!;
  assert.strictEqual(enc.ruleId, "github-token");
  assert.strictEqual(enc.encoding, "base64");
  assert.strictEqual(enc.source!.member, "notes.txt");
  assert.notStrictEqual(enc.fingerprint, fs.find((f) => !f.encoding)!.fingerprint);
}));

test("archive inside a member is opaque: depth 1, no findings from the inner archive", () => withDir((dir) => {
  const inner = buildZip([{ name: "inner.env", data: ENV }]);
  put(dir, "outer.zip", buildZip([{ name: "inner.zip", data: inner, method: 0 }, { name: "README.md", data: README }]));
  put(dir, "outer.tar", buildTar([{ name: "inner.tgz", data: buildGzip(buildTar([{ name: "e", data: ENV }])) }]));
  put(dir, "outer.gz.gz", buildGzip(buildGzip(ENV)));
  const skips: string[] = [];
  assert.deepStrictEqual([...scanOne(dir, "outer.zip", cfg, (r) => skips.push(r)), ...scanOne(dir, "outer.tar", cfg, (r) => skips.push(r)), ...scanOne(dir, "outer.gz.gz", cfg, (r) => skips.push(r))], []);
  assert.deepStrictEqual(skips, ["unreadable", "unreadable", "unreadable"]);
}));

test("generic entropy follows the configured mode inside members", () => withDir((dir) => {
  const blob = "aGlnaGVudHJvcHl2YWx1ZXRoYXRpc2xvbmdlbm91Z2g0MzBhYmNkZWZnaGlqa2xtbm9wcXJz";
  put(dir, "x.zip", buildZip([{ name: "cfg.txt", data: text(`api_secret = "${blob}"\n`) }]));
  const off = scanOne(dir, "x.zip", mergeConfig({ entropyPassEnabled: false }));
  const on = scanOne(dir, "x.zip", mergeConfig({ entropyPassEnabled: true, includeFixtures: true }));
  assert.ok(off.every((f) => f.ruleId !== "generic-high-entropy"));
  assert.ok(on.some((f) => f.ruleId === "generic-high-entropy" && f.source), "entropy finding carries the member source");
}));

test("PKCS#12 member: structural detector runs on member bytes with an archive-aware identity", () => withDir((dir) => {
  put(dir, "certs.zip", buildZip([{ name: "keystore.pfx", data: PKCS12, method: 0 }, { name: "README.md", data: README }]));
  put(dir, "certs.tar", buildTar([{ name: "k.p12", data: PKCS12 }]));
  const z = scanOne(dir, "certs.zip"); const t = scanOne(dir, "certs.tar");
  assert.deepStrictEqual([z[0].ruleId, z[0].file, z[0].line], ["pkcs12-private-key", "certs.zip!/keystore.pfx", 1]);
  assert.strictEqual(t[0].ruleId, "pkcs12-private-key");
  assert.deepStrictEqual(z[0].source, { kind: "archive-member", container: "certs.zip", containerKind: "zip", member: "keystore.pfx" });
  const standalone = detectPkcs12Bytes(PKCS12, "certs.zip!/keystore.pfx")!;
  assert.notStrictEqual(z[0].fingerprint, standalone.fingerprint, "member identity differs from a real file at the same display path");
  assert.ok(!("source" in standalone));
}));

test("a random binary member is not mistaken for PKCS#12", () => withDir((dir) => {
  put(dir, "x.zip", buildZip([{ name: "blob.bin", data: Buffer.from(Array.from({ length: 2048 }, (_, i) => i & 0xff)) }]));
  assert.deepStrictEqual(scanOne(dir, "x.zip"), []);
}));

test("inline directives and fixture-path suppression apply to members through the display path", () => withDir((dir) => {
  put(dir, "x.zip", buildZip([{ name: "cfg.env", data: text(`GITHUB_TOKEN=${GH} # secretloop:allow\n`) }]));
  assert.deepStrictEqual(scanOne(dir, "x.zip"), []);
  const blob = "aGlnaGVudHJvcHl2YWx1ZXRoYXRpc2xvbmdlbm91Z2g0MzBhYmNkZWZnaGlqa2xtbm9wcXJz";
  put(dir, "y.zip", buildZip([{ name: "tests/data.txt", data: text(`api_secret = "${blob}"\n`) }]));
  const on = scanOne(dir, "y.zip", mergeConfig({ entropyPassEnabled: true }));
  assert.ok(on.every((f) => f.ruleId !== "generic-high-entropy"), "entropy tier suppressed under a tests/ member path");
}));

// ---------------------------------------------------------------------------
suite("archive scan — exclusion semantics (§8)");

function withRepo(fn: (dir: string) => void): void {
  withDir((dir) => {
    const git = (...a: string[]) => { const r = spawnSync("git", a, { cwd: dir, encoding: "utf8" }); if (r.status !== 0) throw new Error(r.stderr); };
    git("init", "-q"); git("config", "user.email", "t@example.com"); git("config", "user.name", "t");
    fn(dir);
  });
}

test("an excluded outer archive is never opened; a member glob excludes members", () => withRepo((dir) => {
  put(dir, "vendor.zip", buildZip([{ name: "cfg.env", data: ENV }]));
  put(dir, "app.zip", buildZip([{ name: "secret/cfg.env", data: ENV }, { name: "public/cfg.env", data: ENV }]));
  const outerExcluded = scanWorkspaceFiles(dir, mergeConfig({ excludePaths: ["vendor.zip"] })).flatMap((s) => s.findings);
  assert.ok(outerExcluded.every((f) => !f.file!.startsWith("vendor.zip")));
  const memberExcluded = scanWorkspaceFiles(dir, mergeConfig({ excludePaths: ["**/*.zip!/secret/**"] })).flatMap((s) => s.findings);
  assert.deepStrictEqual(memberExcluded.filter((f) => f.file!.startsWith("app.zip")).map((f) => f.file), ["app.zip!/public/cfg.env"]);
}));

// ---------------------------------------------------------------------------
suite("archive scan — outputs (§18.3, §21)");

function memberFinding(dir: string): Finding {
  put(dir, "artifacts/bundle.zip", buildZip([{ name: "src/config.env", data: ENV }]));
  return scanOne(dir, "artifacts/bundle.zip")[0];
}

test("JSON and MCP projections carry the display path and no source/decompressed key", () => withDir((dir) => {
  const f = memberFinding(dir);
  const json = JSON.parse(render([f], "json", { redact: true, root: dir }));
  const keys = Object.keys(json.findings[0]);
  assert.ok(!keys.some((k) => /source|archive|member|decompress|decod|plain/i.test(k)), `unexpected key in ${keys}`);
  assert.strictEqual(json.findings[0].file, "artifacts/bundle.zip!/src/config.env");
  assert.ok(!JSON.stringify(json).includes(GH));
  const p = projectFinding(f);
  assert.ok(!Object.keys(p).some((k) => /source|archive|member/i.test(k)));
  assert.strictEqual(p.file, "artifacts/bundle.zip!/src/config.env");
  assert.strictEqual(p.redactedValue, redactValue(GH));
}));

test("text report shows the display path and redacts the value", () => withDir((dir) => {
  const out = render([memberFinding(dir)], "text", { redact: true, root: dir });
  assert.ok(out.includes("artifacts/bundle.zip!/src/config.env:3"));
  assert.ok(!out.includes(GH));
}));

test("SARIF: outer archive is the artifact, the member is a logical location, the line is member-relative", () => withDir((dir) => {
  const parsed = JSON.parse(render([memberFinding(dir)], "sarif", { redact: true, root: dir }));
  const loc = parsed.runs[0].results[0].locations[0];
  assert.strictEqual(loc.physicalLocation.artifactLocation.uri, "artifacts/bundle.zip");
  assert.strictEqual(loc.physicalLocation.region.startLine, 3);
  assert.deepStrictEqual(loc.logicalLocations, [{ fullyQualifiedName: "artifacts/bundle.zip!/src/config.env", name: "src/config.env", kind: "member" }]);
  assert.match(parsed.runs[0].results[0].message.text, /archive member src\/config\.env \(line 3 of the member\)/);
  assert.ok(!JSON.stringify(parsed).includes(GH));
}));

test("SARIF for a normal file is unchanged: physical uri, no logicalLocations", () => withDir((dir) => {
  put(dir, "app.ts", text(`const token = "${GH}";\n`));
  const parsed = JSON.parse(render(scanOne(dir, "app.ts"), "sarif", { redact: true, root: dir }));
  const loc = parsed.runs[0].results[0].locations[0];
  assert.strictEqual(loc.physicalLocation.artifactLocation.uri, "app.ts");
  assert.ok(!("logicalLocations" in loc));
  assert.ok(!parsed.runs[0].results[0].message.text.includes("archive member"));
}));

test("gzip FNAME never leaks into text, JSON or SARIF; concatenated stream reports the combined line", () => withDir((dir) => {
  put(dir, "cases/x.gz", Buffer.concat([buildGzip(README, "a.txt"), buildGzip(ENV, "b.txt")]));
  const fs = scanOne(dir, "cases/x.gz");
  assert.deepStrictEqual([fs[0].file, fs[0].line], ["cases/x.gz!/x", 2 + 3]);
  for (const format of ["text", "json", "sarif"] as const) {
    const out = render(fs, format, { redact: true, root: dir });
    assert.ok(!/\ba\.txt\b|\bb\.txt\b/.test(out), `${format} leaked an FNAME`);
  }
}));

// ---------------------------------------------------------------------------
suite("archive scan — verification refusal (§18.5)");

test("verifyFinding refuses with unsupported-container, zero fetches; container wins over transform", async () => {
  await new Promise<void>((resolve) => withDir((dir) => {
    put(dir, "x.zip", buildZip([{ name: "p.env", data: ENV }, { name: "e.txt", data: text(`payload: ${Buffer.from(GH).toString("base64")}\n`) }]));
    const fs = scanOne(dir, "x.zip");
    (async () => {
      const { impl, calls } = countingFetch();
      for (const f of fs) {
        const r = await verifyFinding(f, { fullText: "", fetchImpl: impl });
        assert.strictEqual(r!.status, "unknown");
        assert.strictEqual(r!.reason, "unsupported-container");
        assert.ok(!/\b(safe|dead|revoked|invalid)\b/i.test(r!.detail));
        assert.ok(!r!.detail.includes(GH));
      }
      assert.strictEqual(calls.length, 0);
      let outbound = 0;
      const cache = new VerificationCache();
      await verifyFindings(fs, { fullText: "", fetchImpl: impl }, { cache, onOutbound: () => outbound++ });
      await verifyFindings(fs, { fullText: "", fetchImpl: impl }, { onOutbound: () => outbound++ });
      assert.strictEqual(calls.length, 0);
      assert.strictEqual(outbound, 0);
      assert.ok(fs.every((f) => f.verifyReason === "unsupported-container" && f.verifyStatus === "unknown"));
      resolve();
    })();
  }));
});

test("MCP secretloop_verify refuses an archive member before minting consent; scan projection is clean", async () => {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-archive-mcp-"));
  const saved = getAllowedRoots();
  try {
    mkdirSync(path.join(base, "repo"), { recursive: true });
    const root = realpathSync(path.join(base, "repo"));
    put(root, "artifacts/bundle.zip", buildZip([{ name: "src/config.env", data: ENV }]));
    setConsentRootForTests(path.join(base, "consent")); setAllowedRoots([root]); resetSessions(); resetOutboundCountForTests();
    const { impl, calls } = countingFetch(); setVerifyFetchForTests(impl);
    const scan = toolScan({ path: root }) as any;
    const f = scan.payload.findings.find((x: any) => x.ruleId === "github-token");
    assert.strictEqual(f.file, "artifacts/bundle.zip!/src/config.env");
    assert.ok(!JSON.stringify(scan).includes(GH));
    const v = (await toolVerify({ fingerprint: f.fingerprint, path: root })) as any;
    assert.strictEqual(v.ok, false);
    assert.match(String(v.error), /archive member/);
    assert.match(String(v.error), /nothing will be transmitted/);
    assert.deepStrictEqual(listRecords(), []);
    assert.strictEqual(calls.length, 0);
    assert.strictEqual(outboundRequestCount(), 0);
  } finally {
    setAllowedRoots(saved); setConsentRootForTests(undefined); rmSync(base, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
suite("archive scan — remediation refusal (§18.4)");

test("no rotation or env-extraction action is offered for a member finding", () => withDir((dir) => {
  const f = memberFinding(dir);
  assert.strictEqual(offersEnvExtraction(f), false);
  assert.strictEqual(offersRotation({ ...f, confidence: "verified-live" }), false);
  assert.strictEqual(offersRotation({ ...f, verifyStatus: "unknown", verifyReason: "provider-refused" }), false);
  put(dir, "app.ts", text(`const token = "${GH}";\n`));
  assert.strictEqual(offersEnvExtraction(scanOne(dir, "app.ts")[0]), true, "normal file unchanged");
}));

// ---------------------------------------------------------------------------
suite("archive scan — surfaces through the CLI");

function cli(cwd: string, ...args: string[]) {
  const r = spawnSync("node", [CLI, ...args], { cwd, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("scan: JSON report carries the member with display path; baseline round-trips and does not cross the collision", () => withRepo((dir) => {
  put(dir, "real.zip!/member.txt", ENV);
  put(dir, "real.zip", buildZip([{ name: "member.txt", data: ENV }]));
  const r = cli(dir, "scan", "--format", "json", "--fail-on", "never");
  const rep = JSON.parse(r.stdout);
  const fps = rep.findings.map((f: any) => f.fingerprint).sort();
  assert.strictEqual(fps.length, 2);
  assert.ok(fps.every((fp: string) => fp.startsWith("real.zip!/member.txt:github-token:")));
  assert.notStrictEqual(fps[0], fps[1]);
  // baseline both, then nothing; baseline only the real file, the member still reports
  cli(dir, "scan", "--write-baseline", "b.json", "--fail-on", "never");
  assert.strictEqual(JSON.parse(cli(dir, "scan", "--baseline", "b.json", "--format", "json", "--fail-on", "never").stdout).findings.length, 0);
  const realFp = legacyFingerprint("real.zip!/member.txt", "github-token", GH);
  writeFileSync(path.join(dir, "r.json"), JSON.stringify({ version: 2, fingerprints: [realFp] }));
  const left = JSON.parse(cli(dir, "scan", "--baseline", "r.json", "--format", "json", "--fail-on", "never").stdout).findings;
  assert.strictEqual(left.length, 1);
  assert.notStrictEqual(left[0].fingerprint, realFp);
}));

test("staged: a staged archive is scanned; content comes from the working tree, exactly like a staged text file", () => withRepo((dir) => {
  put(dir, "b.zip", buildZip([{ name: "cfg.env", data: ENV }]));
  put(dir, "t.txt", text(`const token = "${GH}";\n`));
  spawnSync("git", ["add", "b.zip", "t.txt"], { cwd: dir });
  const staged = JSON.parse(cli(dir, "staged", "--format", "json", "--fail-on", "never").stdout).findings;
  assert.deepStrictEqual(staged.map((f: any) => f.file).sort(), ["b.zip!/cfg.env", "t.txt"]);
  // Existing staged semantics (git diff --cached --name-only, then read from disk):
  // the index blob is NOT what is scanned, for archives and text files alike.
  put(dir, "b.zip", buildZip([{ name: "cfg.env", data: README }]));
  put(dir, "t.txt", README);
  const after = JSON.parse(cli(dir, "staged", "--format", "json", "--fail-on", "never").stdout).findings;
  assert.deepStrictEqual(after, [], "worktree content is what staged scanning reads today, for every file type");
}));

test("history is unchanged: a committed archive yields no archive findings; mask is unchanged", () => withRepo((dir) => {
  put(dir, "b.zip", buildZip([{ name: "cfg.env", data: ENV }]));
  spawnSync("git", ["add", "b.zip"], { cwd: dir }); spawnSync("git", ["commit", "-qm", "add archive"], { cwd: dir });
  const hist = JSON.parse(cli(dir, "history", "--format", "json", "--fail-on", "never").stdout).findings;
  assert.deepStrictEqual(hist, []);
  // mask's existing contract for binary stdin: refuse with exit 2 and write
  // nothing. An archive is binary, so nothing here changed for it.
  const m = spawnSync("node", [CLI, "mask"], { input: buildZip([{ name: "cfg.env", data: ENV }]) });
  assert.strictEqual(m.status, 2);
  assert.match(m.stderr.toString(), /input looks binary/);
  assert.strictEqual(m.stdout.length, 0);
  assert.ok(!m.stderr.toString().includes("!/"));
}));

test("open-document semantics unchanged: scanText on archive bytes as text finds nothing and sets no source", () => {
  const fs = scanText(buildZip([{ name: "cfg.env", data: ENV }]).toString("utf8"), { filePath: "b.zip" });
  assert.deepStrictEqual(fs.filter((f) => f.source), []);
});

// ---------------------------------------------------------------------------
suite("archive scan — bounds and determinism through the scanner");

test("10,051-entry archive and a ratio bomb terminate with the secret beyond the cap unreported", () => withDir((dir) => {
  const many = []; for (let i = 0; i < 10_050; i++) many.push({ name: `m/${i}`, data: Buffer.alloc(0), method: 0 });
  many.push({ name: "last.env", data: ENV, method: 0 });
  put(dir, "many.zip", buildZip(many));
  const zeros = Buffer.alloc(900_000, 0);
  const bomb = []; for (let i = 0; i < 40; i++) bomb.push({ name: `z/${i}`, data: zeros });
  bomb.push({ name: "last.env", data: ENV });
  put(dir, "bomb.zip", buildZip(bomb));
  const t0 = Date.now();
  assert.deepStrictEqual(scanOne(dir, "many.zip"), []);
  assert.deepStrictEqual(scanOne(dir, "bomb.zip"), []);
  assert.ok(Date.now() - t0 < 20_000, "bounded");
}));

test("malformed inputs never throw through scanFiles", () => withDir((dir) => {
  const z = buildZip([{ name: "cfg.env", data: ENV }]);
  put(dir, "t.zip", z.subarray(0, z.length >> 1));
  put(dir, "t.gz", buildGzip(ENV).subarray(0, 12));
  put(dir, "t.tar", Buffer.alloc(2048, 0x41));
  put(dir, "e.tar", Buffer.alloc(1024, 0));
  assert.doesNotThrow(() => scanFiles(dir, ["t.zip", "t.gz", "t.tar", "e.tar"], cfg));
  assert.deepStrictEqual(scanFiles(dir, ["t.zip", "t.gz", "t.tar", "e.tar"], cfg).flatMap((s) => s.findings), []);
}));

test("two scans of the same tree are deep-equal", () => withDir((dir) => {
  put(dir, "a.zip", buildZip([{ name: "x/one.env", data: ENV }, { name: "x/two.env", data: ENV }]));
  put(dir, "b.tgz", buildGzip(buildTar([{ name: "s.yaml", data: text(`slack:\n  bot_token: "${SLACK}"\n`) }])));
  const once = scanFiles(dir, ["a.zip", "b.tgz"], cfg);
  const twice = scanFiles(dir, ["a.zip", "b.tgz"], cfg);
  assert.deepStrictEqual(once, twice);
  assert.deepStrictEqual(once.flatMap((s) => s.findings).map((f) => f.file), ["a.zip!/x/one.env", "a.zip!/x/two.env", "b.tgz!/s.yaml"]);
}));

finish();
