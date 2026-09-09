import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { gzipSync } from "zlib";
import { openArchive, ArchiveListing } from "../src/archive";
import { scanFiles, ScannedFile } from "../src/workspace";
import { mergeConfig, loadConfig } from "../src/config";
import { describeScope } from "../src/report";
import { describeScope as mcpDescribeScope, toolScan, setAllowedRoots, ToolResult } from "../src/mcp-core";
import { buildZip, buildTar, buildGzip } from "./archive-builders";

/**
 * Archive coverage disclosure (contract: archive-coverage-disclosure-v1 Phase A.1 addendum).
 * What a scan says about the archives it met: opened containers and their members, members it
 * refused (by a bounded reason code), metadata records that are not members, empty members,
 * members excluded by configuration, enumeration that stopped (known declared remainder for ZIP,
 * unknown remainder for TAR), and containers it recognized but could not open -- none of which may
 * masquerade as ordinary-file skips. Parsing decisions, findings and fingerprints are unchanged.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const cfg = mergeConfig({});
const MAX = cfg.maxFileSizeBytes;
const text = (s: string) => Buffer.from(s, "utf8");
const TXT = (label: string) => text(`line 1 of ${label}: plain text, nothing secret\nline 2 of ${label}\n`);
function tmp(): string { return mkdtempSync(path.join(tmpdir(), "sl-acd-")); }
function write(root: string, rel: string, data: Buffer | string): void {
  mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); writeFileSync(path.join(root, rel), data);
}
function listing(o: ReturnType<typeof openArchive>): ArchiveListing {
  assert.ok(o !== null && !("notOpened" in o), `expected an opened listing, got ${JSON.stringify(o)}`);
  return o as ArchiveListing;
}
function ghp(salt = 5): string {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; let out = "";
  for (let i = 0; i < 36; i++) out += a[(i * 19 + salt * 7 + 3) % a.length]; return "ghp_" + out;
}
function zip64Markers(z: Buffer): Buffer { const b = Buffer.from(z); const e = b.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06])); b.writeUInt16LE(0xffff, e + 10); return b; }
function corruptCentralDirectory(z: Buffer): Buffer { const b = Buffer.from(z); const c = b.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])); b.write("XXXX", c, "latin1"); return b; }
/** gzip magic, FHCRC header with nonzero fields, a stored deflate block of ASCII: gunzip rejects it and no NUL occurs early. */
function rawTextGzip(payload: Buffer): Buffer {
  const hdr = Buffer.from([0x1f, 0x8b, 0x08, 0x02, 0x44, 0x33, 0x22, 0x11, 0x02, 0x03, 0x11, 0x22]);
  const len = Buffer.alloc(4); len.writeUInt16LE(payload.length, 0); len.writeUInt16LE(~payload.length & 0xffff, 2);
  const out = Buffer.concat([hdr, Buffer.from([0x01]), len, payload, Buffer.alloc(8, 0x55)]);
  assert.strictEqual(out.subarray(0, Math.min(8000, out.length - 8)).indexOf(0), -1, "fixture must carry no early NUL");
  return out;
}
function payload(result: ToolResult): Record<string, any> { assert.ok(result.ok, JSON.stringify(result)); return (result as { ok: true; payload: Record<string, any> }).payload; }

// ---------------------------------------------------------------------------
suite("archive disclosure — parser outcomes");

test("recognized but unopened containers carry a reason; non-archives stay null", () => {
  const z = buildZip([{ name: "a.txt", data: TXT("a") }]);
  assert.deepStrictEqual(openArchive(zip64Markers(z), "z.zip", MAX), { notOpened: "unsupported-feature" });
  assert.deepStrictEqual(openArchive(corruptCentralDirectory(z), "c.zip", MAX), { notOpened: "malformed" });
  assert.deepStrictEqual(openArchive(z.subarray(0, z.length >> 1), "t.zip", MAX), { notOpened: "malformed" });
  const g = buildGzip(TXT("g"));
  assert.deepStrictEqual(openArchive(g.subarray(0, g.length - 12), "t.gz", MAX), { notOpened: "malformed" });
  assert.strictEqual(openArchive(text("not an archive at all, just text"), "n.gz", MAX), null);
  assert.strictEqual(openArchive(Buffer.alloc(2048, 0x41), "noise.tar", MAX), null);
});

test("member refusals are counted by reason; metadata records are not members; empty members are counted", () => {
  const z = listing(openArchive(buildZip([
    { name: "enc.txt", data: TXT("e"), flags: 1 },
    { name: "bz.txt", data: TXT("b"), method: 12 },
    { name: "../up.txt", data: TXT("u") },
    { name: "dup.txt", data: TXT("d1") }, { name: "dup.txt", data: TXT("d2") },
    { name: "empty.txt", data: Buffer.alloc(0) },
    { name: "ok.txt", data: TXT("ok") },
  ]), "m.zip", MAX));
  assert.deepStrictEqual(z.refused, { encrypted: 1, "unsupported-compression": 1, "unsafe-name": 1, "duplicate-name": 1 });
  assert.strictEqual(z.empty, 1);
  assert.strictEqual(z.metadataEntries, 0);
  assert.deepStrictEqual(z.members.map((m) => m.member), ["dup.txt", "ok.txt"]);
  assert.deepStrictEqual(z.enumeration, { complete: true, declaredNotInspected: 0 });
  assert.strictEqual((z as any).skipped, undefined, "the old two-bucket counter is gone");

  const t = listing(openArchive(buildTar([
    { name: "real.txt", data: TXT("r") },
    { name: "link.txt", type: "2", linkname: "real.txt" },
    { name: "dev", type: "3" },
    { name: "././@LongLink", type: "L", data: text("a/very/long/name.txt") },
    { name: "PaxHeader/x", type: "x", data: text("30 path=some/extended/path.txt\n") },
    { name: "zero.txt", data: Buffer.alloc(0) },
  ]), "m.tar", MAX));
  assert.deepStrictEqual(t.refused, { "non-regular-entry": 2 }, "symlink and device are known non-file entries");
  assert.strictEqual(t.metadataEntries, 2, "GNU long-name and pax records are metadata, not members");
  assert.strictEqual(t.empty, 1);
  assert.strictEqual(t.members.length, 1);
});

test("ZIP: a stop at the member cap or the budget leaves a KNOWN declared remainder", () => {
  const cap = listing(openArchive(buildZip(Array.from({ length: 10_050 }, (_, i) => ({ name: `m${i}.t`, data: Buffer.alloc(0), method: 0 }))), "cap.zip", MAX));
  assert.strictEqual(cap.empty, 10_000);
  assert.deepStrictEqual(cap.refused, {});
  assert.deepStrictEqual(cap.enumeration, { complete: false, reason: "member-cap", declaredNotInspected: 50 });
  const zeros = Buffer.alloc(200_000, 0);
  const budget = listing(openArchive(buildZip([...Array.from({ length: 8 }, (_, i) => ({ name: `z${i}.bin`, data: zeros })), { name: "tail.txt", data: TXT("t") }]), "b.zip", MAX));
  assert.strictEqual(budget.members.length, 1, "the first member is offered before the budget is crossed");
  assert.strictEqual(budget.enumeration.complete, false);
  assert.strictEqual(budget.enumeration.reason, "decompression-budget");
  assert.strictEqual(budget.enumeration.declaredNotInspected, 8, "the crossing entry and the seven after it");
});

test("TAR: a stop leaves an UNKNOWN remainder; truncation also refuses the truncated member", () => {
  const tar = buildTar([{ name: "first.txt", data: TXT("1") }, { name: "second.txt", data: TXT("2") }, { name: "third.txt", data: TXT("3") }]);
  const bad = Buffer.from(tar); bad.write("0000000\0", 1024 + 148, "latin1"); // second header's checksum
  const l = listing(openArchive(bad, "mid.tar", MAX));
  assert.strictEqual(l.members.length, 1);
  assert.deepStrictEqual(l.enumeration, { complete: false, reason: "malformed-header", declaredNotInspected: 0 });
  assert.deepStrictEqual(l.refused, {}, "a stopped walk is not a refused member");
  const trunc = listing(openArchive(tar.subarray(0, 512 + 100), "t.tar", MAX));
  assert.deepStrictEqual(trunc.refused, { malformed: 1 });
  assert.deepStrictEqual(trunc.enumeration, { complete: false, reason: "truncated", declaredNotInspected: 0 });
});

// ---------------------------------------------------------------------------
suite("archive disclosure — scanFiles accounting");

test("an unopened container is not an ordinary binary skip, and an ordinary binary is not a container", () => {
  const dir = tmp();
  try {
    write(dir, "z64.zip", zip64Markers(buildZip([{ name: "a.txt", data: TXT("a") }])));
    write(dir, "image.bin", Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), Buffer.alloc(64, 0)]));
    const skips: string[] = []; const notOpened: string[] = [];
    const scanned = scanFiles(dir, ["z64.zip", "image.bin"], cfg, { onSkipped: (r) => skips.push(r), onContainerNotOpened: (r) => notOpened.push(r) });
    assert.deepStrictEqual(scanned, [], "neither yields a scanned file");
    assert.deepStrictEqual(skips, ["unreadable"], "only the plain binary is an ordinary skip");
    assert.deepStrictEqual(notOpened, ["unsupported-feature"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("raw-text fallback after a recognized-but-unopened gzip is preserved and still detects", () => {
  const dir = tmp();
  try {
    const body = Buffer.from(`config line one\ntoken = "${ghp()}"\n` + "filler line of plain text with nothing in it\n".repeat(120));
    write(dir, "weird.gz", rawTextGzip(body));
    const notOpened: string[] = []; const skips: string[] = [];
    const scanned = scanFiles(dir, ["weird.gz"], cfg, { onSkipped: (r) => skips.push(r), onContainerNotOpened: (r) => notOpened.push(r) });
    assert.deepStrictEqual(notOpened, ["malformed"]);
    assert.deepStrictEqual(skips, []);
    assert.strictEqual(scanned.length, 1, "the raw bytes were scanned as a file");
    assert.strictEqual(scanned[0].archive, undefined, "file coverage, not archive-member coverage");
    assert.deepStrictEqual(scanned[0].findings.map((f) => [f.ruleId, f.file, f.source]), [["github-token", "weird.gz", undefined]]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("per-container accounting: scanned, binary, excluded, empty, metadata; no onSkipped for members", () => {
  const dir = tmp();
  try {
    write(dir, "b.zip", buildZip([
      { name: "src/a.txt", data: TXT("a") },
      { name: "node_modules/dep/index.js", data: TXT("dep") },
      { name: "blob.bin", data: Buffer.concat([Buffer.alloc(16, 0), TXT("x")]) },
      { name: "empty.txt", data: Buffer.alloc(0) },
      { name: "enc.txt", data: TXT("e"), flags: 1 },
    ]));
    const skips: string[] = [];
    const [s] = scanFiles(dir, ["b.zip"], cfg, { onSkipped: (r) => skips.push(r) });
    assert.deepStrictEqual(skips, [], "member outcomes never reach the ordinary skip counter");
    assert.ok(s.archive);
    assert.strictEqual(s.archive!.kind, "zip");
    assert.deepStrictEqual(s.archive!.members, { scanned: 1, empty: 1, excluded: 1, refused: { binary: 1, encrypted: 1 } });
    assert.strictEqual(s.archive!.metadataEntries, 0);
    assert.deepStrictEqual(s.archive!.enumeration, { incompleteContainers: 0, declaredNotInspected: 0, unknownRemainderContainers: 0, byReason: {} });
    assert.strictEqual(s.archive!.containersOpened, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("TAR/TGZ stops mark an unknown remainder; ZIP stops carry the declared count", () => {
  const dir = tmp();
  try {
    const tar = buildTar([{ name: "first.txt", data: TXT("1") }, { name: "second.txt", data: TXT("2") }]);
    const bad = Buffer.from(tar); bad.write("0000000\0", 1024 + 148, "latin1");
    write(dir, "mid.tgz", gzipSync(bad));
    write(dir, "cap.zip", buildZip(Array.from({ length: 10_050 }, (_, i) => ({ name: `m${i}.t`, data: Buffer.alloc(0), method: 0 }))));
    const [tgz, zip] = scanFiles(dir, ["mid.tgz", "cap.zip"], cfg);
    assert.deepStrictEqual(tgz.archive!.enumeration, { incompleteContainers: 1, declaredNotInspected: 0, unknownRemainderContainers: 1, byReason: { "malformed-header": 1 } });
    assert.deepStrictEqual(zip.archive!.enumeration, { incompleteContainers: 1, declaredNotInspected: 50, unknownRemainderContainers: 0, byReason: { "member-cap": 1 } });
    assert.strictEqual(zip.archive!.members.empty, 10_000);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------------------
suite("archive disclosure — scope sentence and surfaces");

const ACC = {
  containersOpened: 2, containersNotOpened: { malformed: 1 },
  members: { scanned: 3, empty: 2, excluded: 4, refused: { binary: 1, encrypted: 2 } },
  metadataEntries: 6,
  enumeration: { incompleteContainers: 1, declaredNotInspected: 50, unknownRemainderContainers: 0, byReason: { "member-cap": 1 } },
};
const EXPECTED = "9 file(s); 3 file(s) not scanned — binary or unreadable; 2 archive(s) opened — 5 member(s) scanned; 3 archive member(s) not scanned; 4 archive member(s) excluded by configuration; 6 archive metadata entry(s) skipped; 1 archive(s) not fully enumerated — 50 declared entry(s) not inspected, 0 with unknown remainder; 1 recognized archive container(s) not opened";

test("describeScope renders the six clauses in order, after the file clauses, omitting zeros; the MCP copy agrees", () => {
  assert.strictEqual(describeScope(9, "file", { unreadableExcluded: 3, archives: ACC }), EXPECTED);
  assert.strictEqual(mcpDescribeScope(9, "file", { unreadableExcluded: 3, archives: ACC }), EXPECTED);
  const none = { containersOpened: 0, containersNotOpened: {}, members: { scanned: 0, empty: 0, excluded: 0, refused: {} }, metadataEntries: 0, enumeration: { incompleteContainers: 0, declaredNotInspected: 0, unknownRemainderContainers: 0, byReason: {} } };
  assert.strictEqual(describeScope(9, "file", { archives: none }), "9 file(s)");
  assert.strictEqual(describeScope(9, "file", { archives: { ...none, containersNotOpened: { malformed: 2 } } }), "9 file(s); 2 recognized archive container(s) not opened");
});

function project(): string {
  const dir = tmp();
  write(dir, "bundle.zip", buildZip([{ name: "a.txt", data: TXT("a") }, { name: "empty.txt", data: Buffer.alloc(0) }, { name: "enc.txt", data: TXT("e"), flags: 1 }, { name: "node_modules/x.js", data: TXT("x") }]));
  write(dir, "bad.zip", corruptCentralDirectory(buildZip([{ name: "b.txt", data: TXT("b") }])));
  write(dir, "readme.txt", TXT("readme"));
  return dir;
}
const PROJECT_SENTENCE = "2 file(s); 1 archive(s) opened — 2 member(s) scanned; 1 archive member(s) not scanned; 1 archive member(s) excluded by configuration; 1 recognized archive container(s) not opened";
const PROJECT_ACC = { containersOpened: 1, containersNotOpened: { malformed: 1 }, members: { scanned: 1, empty: 1, excluded: 1, refused: { encrypted: 1 } }, metadataEntries: 0, enumeration: { incompleteContainers: 0, declaredNotInspected: 0, unknownRemainderContainers: 0, byReason: {} } };

test("CLI text, JSON and SARIF carry the sentence; JSON and SARIF carry the structured object only when archives were met", () => {
  const dir = project();
  try {
    const json = JSON.parse(spawnSync("node", [CLI, "scan", "--format", "json", "--fail-on", "never"], { cwd: dir, encoding: "utf8" }).stdout);
    assert.strictEqual(json.summary.scope, PROJECT_SENTENCE);
    assert.deepStrictEqual(json.summary.archives, PROJECT_ACC);
    assert.strictEqual(json.findings.length, 0);
    const sarif = JSON.parse(spawnSync("node", [CLI, "scan", "--format", "sarif", "--fail-on", "never"], { cwd: dir, encoding: "utf8" }).stdout);
    assert.strictEqual(sarif.runs[0].invocations[0].properties.scope, PROJECT_SENTENCE);
    assert.deepStrictEqual(sarif.runs[0].invocations[0].properties.archives, PROJECT_ACC);
    const txt = spawnSync("node", [CLI, "scan", "--fail-on", "never"], { cwd: dir, encoding: "utf8" });
    assert.strictEqual(txt.status, 0);
    assert.ok(txt.stdout.includes(`Scanned ${PROJECT_SENTENCE}.`), txt.stdout);
    // no archives -> no object, sentence unchanged
    const plain = tmp();
    try {
      write(plain, "readme.txt", TXT("r"));
      const j = JSON.parse(spawnSync("node", [CLI, "scan", "--format", "json", "--fail-on", "never"], { cwd: plain, encoding: "utf8" }).stdout);
      assert.strictEqual(j.summary.scope, "1 file(s)");
      assert.ok(!("archives" in j.summary));
      const s = JSON.parse(spawnSync("node", [CLI, "scan", "--format", "sarif", "--fail-on", "never"], { cwd: plain, encoding: "utf8" }).stdout);
      assert.ok(!("archives" in s.runs[0].invocations[0].properties));
    } finally { rmSync(plain, { recursive: true, force: true }); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("MCP: statement word-for-word plus the structured object, present only when archives were met", () => {
  const dir = project();
  try {
    setAllowedRoots([dir]);
    const p = payload(toolScan({ path: dir }));
    assert.strictEqual(p.scope.statement, `Scanned ${PROJECT_SENTENCE}.`);
    assert.deepStrictEqual(p.scope.archives, PROJECT_ACC);
    assert.strictEqual(p.scope.filesScanned, 2);
    assert.ok(!JSON.stringify(p.scope).includes("enc.txt"), "no member name in the disclosure");
    const plain = tmp();
    try {
      write(plain, "readme.txt", TXT("r")); setAllowedRoots([plain]);
      const q = payload(toolScan({ path: plain }));
      assert.ok(!("archives" in q.scope));
    } finally { rmSync(plain, { recursive: true, force: true }); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("history never opens archives: no archive clause, no object", () => {
  const dir = project();
  try {
    const g = (...a: string[]) => spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a], { cwd: dir, encoding: "utf8" });
    g("init", "-q"); g("add", "-A"); g("commit", "-q", "-m", "seed");
    const h = JSON.parse(spawnSync("node", [CLI, "history", "--format", "json", "--fail-on", "never"], { cwd: dir, encoding: "utf8" }).stdout);
    assert.doesNotMatch(h.summary.scope, /archive/);
    assert.ok(!("archives" in h.summary));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

finish();
