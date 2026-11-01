"use strict";
// Run with: npm run test:comparator (routine), or npm run test:comparator:n10 (release checklist).
// Both go through run-comparator-tests.js, which accounts for every reported result.
// Synthetic controls write only under a session-local scratch directory: R4_TEST_TMP if set, else a
// fresh directory under the system temp directory. The frozen N10 evidence is read and hashed before
// and after, never written.
//
// The N10 record lives outside the repository, and its location comes only from R4_N10_ROOT. Without
// it the three historical N10 cases skip and name the reason. With R4_REQUIRE_N10=1 a missing or
// unusable record fails those cases instead, so a checklist run cannot pass on a skip.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { compare, exitCodeFor } = require("../compare-fail-closed.js");

const HERE = path.resolve(__dirname, "..");
const CLI = path.join(HERE, "compare-fail-closed.js");
const N10 = process.env.R4_N10_ROOT ? path.resolve(process.env.R4_N10_ROOT) : null;
const N10_REQUIRE = process.env.R4_REQUIRE_N10;
const N10_PROBLEM = n10Problem();
const SCRATCH = process.env.R4_TEST_TMP || fs.mkdtempSync(path.join(os.tmpdir(), "r4-comparator-tests-"));
const POSIX = process.platform !== "win32";
const REPRO = path.join(__dirname, "fixtures", "n10-v060-to-main.reproduction.json");
const FP = "src/a.js:aws-key:0123456789abcdef";
const FP2 = "src/a.js:aws-key:fedcba9876543210";

function scratch(name) {
  fs.mkdirSync(SCRATCH, { recursive: true });
  return fs.mkdtempSync(path.join(SCRATCH, `${name}-`));
}

function sha(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function writeDir(dir, files, { sums = true } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  if (sums) resumSums(dir);
  return dir;
}

// Rewrites SHA256SUMS over every regular file in dir, except SHA256SUMS itself.
function resumSums(dir) {
  const names = fs.readdirSync(dir).filter((n) => n !== "SHA256SUMS").sort();
  const lines = names.map((n) => `${sha(fs.readFileSync(path.join(dir, n)))}  ${n}`);
  fs.writeFileSync(path.join(dir, "SHA256SUMS"), lines.join("\n") + "\n");
}

function inventory(root, entries) {
  const file = path.join(root, "inventory.json");
  fs.writeFileSync(file, JSON.stringify({ schema: "r4-inventory-1", reports: entries }, null, 2));
  return file;
}

// A base and a candidate directory holding one report of the given kind, with its inventory.
function pairOf(name, kind, baseText, candText) {
  const root = scratch("pair");
  const base = writeDir(path.join(root, "base"), { [name]: baseText });
  const cand = writeDir(path.join(root, "cand"), { [name]: candText });
  return {
    root,
    base,
    cand,
    name,
    inv: inventory(root, [{ file: name, kind }]),
    bsha: sha(fs.readFileSync(path.join(base, name))),
    csha: sha(fs.readFileSync(path.join(cand, name))),
  };
}

const jsonPair = (b, c) => pairOf("scan.json", "json", b, c);

// An approval pinned to the exact bytes of pair p. Callers add the category, match and values.
function approve(p, props) {
  return { id: "A1", status: "approved", reason: "test", report: p.name, baseSha256: p.bsha, candidateSha256: p.csha, ...props };
}

function approvalsFile(p, approvals, schema = "r4-deltas-1") {
  const file = path.join(p.root, `deltas-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(file, JSON.stringify({ schema, approvals }, null, 2));
  return file;
}

const run = (p, extra = {}) => compare({ inventory: p.inv, base: p.base, candidate: p.cand, ...extra });

// The categories of the unapproved differences, in record order.
const unapprovedCategories = (r) => (r.record.differences || []).filter((d) => d.approvedBy === null).map((d) => d.category);

function EXPECT_BLOCK(r, pattern) {
  assert.equal(r.verdict, "BLOCK", `expected BLOCK, got ${r.verdict}: ${JSON.stringify(r.record.blocks || r.record.unapprovedCount)}`);
  if (pattern) assert.match(r.record.blocks[0], pattern);
}

function EXPECT_FAIL(r, expectedUnapproved) {
  assert.equal(r.verdict, "FAIL", `expected FAIL, got ${r.verdict}: ${JSON.stringify(r.record.blocks || "")}`);
  if (expectedUnapproved) assert.deepEqual(unapprovedCategories(r), expectedUnapproved);
}

function report({ findings = [], extra = {}, summary = {}, schemaVersion = 5 } = {}) {
  return JSON.stringify(
    {
      tool: "secretloop",
      schemaVersion,
      toolVersion: "0.0.0-test",
      root: ".",
      configDigest: "c",
      ruleSetDigest: "r",
      suppressionDigest: "s",
      scopeDigest: "d",
      binaryDigest: "b",
      incomplete: false,
      summary: { total: findings.length, scope: "1 file", scannedCount: 1, scopeNoun: "file", ...summary },
      findings,
      ...extra,
    },
    null,
    2
  );
}

function finding(overrides = {}) {
  return {
    ruleId: "aws-key",
    description: "AWS key",
    severity: "high",
    confidence: "high",
    verifyStatus: "unchecked",
    verifyReason: null,
    verifyDetail: null,
    file: "src/a.js",
    line: 3,
    commit: null,
    fingerprint: FP,
    alsoMatched: null,
    value: "AKIA****",
    ...overrides,
  };
}

function sarifRaw(runs, version = "2.1.0") {
  return JSON.stringify({ version, runs }, null, 2);
}

function sarifRun(results, extra = {}) {
  return { tool: { driver: { name: "secretloop" } }, results, ...extra };
}

function sarifResult(overrides = {}) {
  return {
    ruleId: "aws-key",
    level: "error",
    message: { text: "AWS key" },
    properties: { alsoMatched: null },
    partialFingerprints: { "secretloopFingerprint/v2": FP },
    locations: [{ physicalLocation: { artifactLocation: { uri: "src/a.js" }, region: { startLine: 3 } } }],
    ...overrides,
  };
}

function sarifAt(uri, identity = FP) {
  return sarifResult({
    partialFingerprints: { "secretloopFingerprint/v2": identity },
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 3 } } }],
  });
}

// ---------------------------------------------------------------- basic outcomes

test("identical reports PASS with no differences", () => {
  const text = report({ findings: [finding()] });
  const r = run(jsonPair(text, text));
  assert.equal(r.verdict, "PASS");
  assert.equal(r.record.differences.length, 0);
});

test("an unapproved additive field is FAIL: credentialGroups is known but not approved", () => {
  const p = jsonPair(report({ findings: [finding()] }), report({ findings: [finding()], extra: { credentialGroups: [] } }));
  const r = run(p);
  EXPECT_FAIL(r, ["json-added"]);
});

test("the same additive field PASSes once approved, pinned to its exact value", () => {
  const p = jsonPair(report({ findings: [finding()] }), report({ findings: [finding()], extra: { credentialGroups: [] } }));
  const r = run(p, { deltas: approvalsFile(p, [approve(p, { id: "ADD-1", category: "json-added", match: { path: "credentialGroups" }, to: [] })]) });
  assert.equal(r.verdict, "PASS");
  assert.equal(r.record.approvedCount, 1);
});

test("an injected severity change is FAIL, classified as reclassified", () => {
  const r = run(jsonPair(report({ findings: [finding()] }), report({ findings: [finding({ severity: "critical" })] })));
  EXPECT_FAIL(r, ["finding-reclassified"]);
});

test("a lost finding is FAIL, and a new finding is FAIL", () => {
  const one = report({ findings: [finding()], summary: { total: 1 } });
  const none = report({ findings: [], summary: { total: 1 } });
  EXPECT_FAIL(run(jsonPair(one, none)), ["finding-lost"]);
  EXPECT_FAIL(run(jsonPair(none, one)), ["finding-new"]);
});

test("an identity change at the same site is FAIL, classified as identity-changed", () => {
  const r = run(jsonPair(report({ findings: [finding()] }), report({ findings: [finding({ fingerprint: FP2 })] })));
  EXPECT_FAIL(r, ["finding-identity-changed"]);
});

test("two identical base findings and one candidate finding: exactly one is lost", () => {
  const r = run(jsonPair(report({ findings: [finding(), finding()], summary: { total: 2 } }), report({ findings: [finding()], summary: { total: 2 } })));
  EXPECT_FAIL(r, ["finding-lost"]);
});

test("a finding field change is FAIL unless approved by fingerprint, field and both values", () => {
  const p = jsonPair(report({ findings: [finding()] }), report({ findings: [finding({ description: "AWS key, revised" })] }));
  EXPECT_FAIL(run(p), ["finding-field-changed"]);
  const r = run(p, {
    deltas: approvalsFile(p, [approve(p, { id: "F-1", category: "finding-field-changed", match: { fingerprint: FP, field: "description" }, from: "AWS key", to: "AWS key, revised" })]),
  });
  assert.equal(r.verdict, "PASS");
});

// ---------------------------------------------------------------- REQ-1: paired findings carry their other fields

test("D1: a severity-only approval cannot hide a verifyStatus change on the same finding", () => {
  const p = jsonPair(
    report({ findings: [finding()] }),
    report({ findings: [finding({ severity: "critical", verifyStatus: "verified" })] })
  );
  const reclass = approve(p, { id: "RECLASS", category: "finding-reclassified", match: { fingerprint: FP, detail: "severity" } });
  // The reclassification alone: the verifyStatus change is still an unapproved difference.
  EXPECT_FAIL(run(p, { deltas: approvalsFile(p, [reclass]) }), ["finding-field-changed"]);
  // Both approved: PASS.
  const field = approve(p, { id: "VERIFY", category: "finding-field-changed", match: { fingerprint: FP, field: "verifyStatus" }, from: "unchecked", to: "verified" });
  assert.equal(run(p, { deltas: approvalsFile(p, [reclass, field]) }).verdict, "PASS");
});

test("D2: an identity-only approval cannot hide a description change on the same finding", () => {
  const p = jsonPair(report({ findings: [finding()] }), report({ findings: [finding({ fingerprint: FP2, description: "changed" })] }));
  const identity = approve(p, { id: "ID", category: "finding-identity-changed", match: { fingerprint: FP, newFingerprint: FP2 } });
  EXPECT_FAIL(run(p, { deltas: approvalsFile(p, [identity]) }), ["finding-field-changed"]);
  const description = approve(p, { id: "DESC", category: "finding-field-changed", match: { fingerprint: FP, field: "description" }, from: "AWS key", to: "changed" });
  assert.equal(run(p, { deltas: approvalsFile(p, [identity, description]) }).verdict, "PASS");
});

test("REQ-1: each changed non-key field of a paired finding is its own difference, counted once", () => {
  const p = jsonPair(
    report({ findings: [finding()] }),
    report({ findings: [finding({ severity: "low", description: "x", verifyStatus: "verified" })] })
  );
  const r = run(p);
  const cats = r.record.differences.map((d) => d.category).sort();
  assert.deepEqual(cats, ["finding-field-changed", "finding-field-changed", "finding-reclassified"]);
});

// ---------------------------------------------------------------- REQ-2: reproduction outcome

test("D4: a run given a historical reproduction never reports PASS or exit 0", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  const repro = approvalsFile(p, [approve(p, { status: "historical-reproduction", category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5 })], "r4-reproduction-1");
  const r = run(p, { reproduction: repro });
  assert.equal(r.verdict, "PASS-REPRODUCTION");
  assert.notEqual(r.verdict, "PASS");
  assert.equal(exitCodeFor(r.verdict), 3);
  const cli = spawnSync(process.execPath, [CLI, "--inventory", p.inv, "--base", p.base, "--candidate", p.cand, "--reproduction", repro], { encoding: "utf8" });
  assert.equal(cli.status, 3, cli.stdout);
});

test("exit semantics: PASS 0, FAIL 1, BLOCK 2, PASS-REPRODUCTION 3, usage 64", () => {
  assert.equal(exitCodeFor("PASS"), 0);
  assert.equal(exitCodeFor("FAIL"), 1);
  assert.equal(exitCodeFor("BLOCK"), 2);
  assert.equal(exitCodeFor("PASS-REPRODUCTION"), 3);
  const text = report();
  const same = jsonPair(text, text);
  const args = (p) => ["--inventory", p.inv, "--base", p.base, "--candidate", p.cand];
  assert.equal(spawnSync(process.execPath, [CLI, ...args(same)], { encoding: "utf8" }).status, 0);
  assert.equal(spawnSync(process.execPath, [CLI, ...args(jsonPair(report({ findings: [finding()] }), report()))], { encoding: "utf8" }).status, 1);
  const missing = pairOf("scan.json", "json", text, text);
  fs.unlinkSync(path.join(missing.cand, "scan.json"));
  assert.equal(spawnSync(process.execPath, [CLI, ...args(missing)], { encoding: "utf8" }).status, 2);
  assert.equal(spawnSync(process.execPath, [CLI], { encoding: "utf8" }).status, 64);
  assert.equal(spawnSync(process.execPath, [CLI, "--bogus"], { encoding: "utf8" }).status, 64);
});

test("an empty reproduction file BLOCKs; it is never a silent normal run", () => {
  const p = jsonPair(report(), report());
  const file = path.join(p.root, "empty-repro.json");
  fs.writeFileSync(file, JSON.stringify({ schema: "r4-reproduction-1", approvals: [] }));
  EXPECT_BLOCK(run(p, { reproduction: file }), /no entries/);
});

// ---------------------------------------------------------------- BLOCK controls

test("a draft approval BLOCKs the run; drafts are never applied", () => {
  const text = report({ findings: [finding()] });
  const p = jsonPair(text, text);
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { status: "draft", category: "json-added", match: { path: "x" }, to: 1 })]) }), /status must be "approved"/);
});

test("a stale approval that matches no difference BLOCKs the run", () => {
  const text = report({ findings: [finding()] });
  const p = jsonPair(text, text);
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-added", match: { path: "nothing" }, to: 1 })]) }), /stale/);
});

test("a missing required report BLOCKs the run", () => {
  const root = scratch("missing");
  const base = writeDir(path.join(root, "base"), { "scan.json": report() });
  const cand = writeDir(path.join(root, "cand"), {});
  EXPECT_BLOCK(compare({ inventory: inventory(root, [{ file: "scan.json", kind: "json" }]), base, candidate: cand }), /missing report/);
});

test("a duplicate inventory entry BLOCKs the run", () => {
  const p = jsonPair(report(), report());
  fs.writeFileSync(p.inv, JSON.stringify({ schema: "r4-inventory-1", reports: [{ file: "scan.json", kind: "json" }, { file: "scan.json", kind: "json" }] }));
  EXPECT_BLOCK(run(p), /twice/);
});

test("an unexpected extra file in a directory BLOCKs the run", () => {
  const text = report();
  const p = jsonPair(text, text);
  fs.writeFileSync(path.join(p.cand, "scan.json.bak"), text);
  resumSums(p.cand);
  EXPECT_BLOCK(run(p), /unexpected file/);
});

test("a tampered report with a stale checksum record BLOCKs the run", () => {
  const p = jsonPair(report({ findings: [finding()] }), report({ findings: [finding()] }));
  fs.writeFileSync(path.join(p.cand, "scan.json"), report({ findings: [finding({ severity: "low" })] }));
  EXPECT_BLOCK(run(p), /checksum mismatch/);
});

test("an unknown schema field BLOCKs the run, not a FAIL", () => {
  const p = jsonPair(report({ findings: [finding()] }), report({ findings: [finding()], extra: { newUnknownField: 1 } }));
  EXPECT_BLOCK(run(p), /unknown field: newUnknownField/);
});

test("a report with no checksum record at all BLOCKs the run", () => {
  const text = report();
  const root = scratch("nosum");
  const base = writeDir(path.join(root, "base"), { "scan.json": text }, { sums: false });
  const cand = writeDir(path.join(root, "cand"), { "scan.json": text }, { sums: false });
  EXPECT_BLOCK(compare({ inventory: inventory(root, [{ file: "scan.json", kind: "json" }]), base, candidate: cand }), /no checksum record/);
});

test("a manifest covers a report without SHA256SUMS; a tampered manifest BLOCKs", () => {
  const text = report({ findings: [finding()] });
  const root = scratch("manifest");
  const base = writeDir(path.join(root, "base"), { "scan.json": text }, { sums: false });
  const cand = writeDir(path.join(root, "cand"), { "scan.json": text }, { sums: false });
  const line = (dir) => {
    const buf = fs.readFileSync(path.join(dir, "scan.json"));
    return `${sha(buf)}  ${buf.length}  ${path.relative(root, path.join(dir, "scan.json"))}`;
  };
  const manifest = path.join(root, "MANIFEST.txt");
  fs.writeFileSync(manifest, `# test manifest\n${line(base)}\n${line(cand)}\n`);
  const inv = inventory(root, [{ file: "scan.json", kind: "json" }]);
  assert.equal(compare({ inventory: inv, base, candidate: cand, manifests: [manifest] }).verdict, "PASS");
  fs.writeFileSync(manifest, `${line(base)}\n${line(cand).replace(/  \d+  /, "  1  ")}\n`);
  EXPECT_BLOCK(compare({ inventory: inv, base, candidate: cand, manifests: [manifest] }), /manifest/);
});

test("a malformed inventory BLOCKs the run", () => {
  const root = scratch("badinv");
  const file = path.join(root, "inventory.json");
  fs.writeFileSync(file, JSON.stringify({ schema: "wrong", reports: [] }));
  EXPECT_BLOCK(compare({ inventory: file, base: root, candidate: root }));
});

// ---------------------------------------------------------------- R1: approval shape

test("R1: a misspelt match key ('matchh') BLOCKs, even with a real difference it would have covered", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  const file = approvalsFile(p, [{ ...approve(p, { category: "json-changed", from: 4, to: 5 }), matchh: { path: "nothing-real" } }]);
  EXPECT_BLOCK(run(p, { deltas: file }), /unknown field: matchh/);
});

test("R1: an approval with no match criteria BLOCKs; it is never category-wide", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", from: 4, to: 5 })]) }), /no match criteria/);
});

test("R1: an empty match object BLOCKs", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: {}, from: 4, to: 5 })]) }), /match lacks path/);
});

test("R1: a match with an extra key BLOCKs", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: { path: "schemaVersion", field: "x" }, from: 4, to: 5 })]) }), /unknown key: field/);
});

test("R1: an unknown approval field such as notes BLOCKs", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5, notes: "x" })]) }), /unknown field: notes/);
});

test("R1: a wildcard report name BLOCKs; an approval names exactly one report", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { report: "*", category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5 })]) }), /exactly one report/);
});

// ---------------------------------------------------------------- R2: pinned values

test("R2: schemaVersion 4->6 is refused when the approval pins only 4->5", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 6 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5 })]) }), /stale/);
});

test("R2: a wrong old value is refused as stale", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: { path: "schemaVersion" }, from: 3, to: 5 })]) }), /stale/);
});

test("R2: type is significant: a pinned 5 does not approve the string \"5\"", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: "5" }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5 })]) }), /stale/);
});

test("R2: a broader summary.scope difference is not covered by an approval pinned to the old wording", () => {
  const p = jsonPair(report({ summary: { scope: "190 files" } }), report({ summary: { scope: "150 files" } }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: { path: "summary.scope" }, from: "190 files", to: "190 files; 40 not scanned" })]) }), /stale/);
});

test("R2: an openedFileChecks object approval refuses a different structured value", () => {
  const p = jsonPair(report(), report({ summary: { coverage: { openedFileChecks: { opened: 999, identity: { verified: 999 } } } } }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-added", match: { path: "summary.coverage.openedFileChecks" }, to: { opened: 570, identity: { verified: 570 } } })]) }), /stale/);
});

test("R2: an unpinned json-changed approval BLOCKs (from and to are required)", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: { path: "schemaVersion" } })]) }), /must pin from/);
});

test("R2: a from pin on a category that does not take one BLOCKs", () => {
  const p = jsonPair(report(), report({ extra: { credentialGroups: [] } }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-added", match: { path: "credentialGroups" }, from: [], to: [] })]) }), /may not carry from/);
});

// ---------------------------------------------------------------- R3: no broad hiding

test("R3: a json approval cannot cover a finding loss", () => {
  const p = jsonPair(report({ findings: [finding()] }), report({ findings: [] }));
  const r = run(p, { deltas: approvalsFile(p, [approve(p, { category: "json-changed", match: { path: "summary.total" }, from: 1, to: 0 })]) });
  EXPECT_FAIL(r, ["finding-lost"]);
});

// A loss also changes summary.total, so a loss needs its own approval for the total as well.
test("R3: a lost-finding approval for fingerprint X does not cover lost finding Y", () => {
  const x = finding();
  const y = finding({ file: "src/b.js", fingerprint: "src/b.js:aws-key:1111111111111111", value: "BBBB****" });
  const p = jsonPair(report({ findings: [x, y] }), report({ findings: [] }));
  const r = run(p, {
    deltas: approvalsFile(p, [
      approve(p, { id: "TOTAL", category: "json-changed", match: { path: "summary.total" }, from: 2, to: 0 }),
      approve(p, { id: "LOST-X", category: "finding-lost", match: { fingerprint: x.fingerprint } }),
    ]),
  });
  EXPECT_FAIL(r, ["finding-lost"]);
  assert.equal(r.record.differences.find((d) => d.approvedBy === null).fingerprint, y.fingerprint);
});

test("R3: one approval covers one difference, even when two lost findings share a fingerprint", () => {
  const p = jsonPair(report({ findings: [finding(), finding()] }), report({ findings: [] }));
  const r = run(p, {
    deltas: approvalsFile(p, [
      approve(p, { id: "TOTAL", category: "json-changed", match: { path: "summary.total" }, from: 2, to: 0 }),
      approve(p, { id: "LOST", category: "finding-lost", match: { fingerprint: FP } }),
    ]),
  });
  EXPECT_FAIL(r, ["finding-lost"]);
});

test("R3: an identity-change approval pinned to one pair does not cover a different site", () => {
  const base = report({ findings: [finding(), finding({ file: "src/b.js", fingerprint: "src/b.js:aws-key:1111111111111111", value: "BBBB****" })] });
  const cand = report({ findings: [finding({ fingerprint: FP2 })], summary: { total: 2 } });
  const p = jsonPair(base, cand);
  const r = run(p, { deltas: approvalsFile(p, [approve(p, { category: "finding-identity-changed", match: { fingerprint: FP, newFingerprint: FP2 } })]) });
  EXPECT_FAIL(r, ["finding-lost"]);
});

test("R3: the historical reproduction is not applied unless --reproduction is given", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  const repro = approvalsFile(p, [approve(p, { status: "historical-reproduction", category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5 })], "r4-reproduction-1");
  EXPECT_FAIL(run(p, {}), ["json-changed"]);
  assert.equal(run(p, { reproduction: repro }).verdict, "PASS-REPRODUCTION");
});

test("R3: a reproduction record used against unrelated bytes is refused as stale", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  const repro = approvalsFile(p, [approve(p, { status: "historical-reproduction", category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5 })], "r4-reproduction-1");
  const other = jsonPair(report({ schemaVersion: 4, summary: { scope: "2 files" } }), report({ schemaVersion: 5, summary: { scope: "2 files" } }));
  EXPECT_BLOCK(run(other, { reproduction: repro }), /stale/);
});

test("R3: approvals and reproductions are never interchangeable", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  const body = { category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5 };
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, body)], "r4-reproduction-1") }), /must declare schema r4-deltas-1/);
  EXPECT_BLOCK(run(p, { reproduction: approvalsFile(p, [approve(p, body)], "r4-deltas-1") }), /must declare schema r4-reproduction-1/);
  EXPECT_BLOCK(run(p, { reproduction: approvalsFile(p, [approve(p, body)], "r4-reproduction-1") }), /status must be "historical-reproduction"/);
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [{ ...approve(p, body), status: "historical-reproduction" }]) }), /status must be "approved"/);
});

// ---------------------------------------------------------------- every approvable category

// One scenario per category. Each builds a pair whose only difference is that category, and the
// approval that exactly covers it. The summary total is held equal on both sides, so no other
// difference appears.
const SCENARIOS = [
  {
    category: "json-removed",
    pair: () => jsonPair(report({ extra: { credentialGroups: [] } }), report()),
    approval: { match: { path: "credentialGroups" }, from: [] },
  },
  {
    category: "json-added",
    pair: () => jsonPair(report(), report({ extra: { credentialGroups: [1] } })),
    approval: { match: { path: "credentialGroups" }, to: [1] },
  },
  {
    category: "json-changed",
    pair: () => jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 })),
    approval: { match: { path: "schemaVersion" }, from: 4, to: 5 },
  },
  {
    category: "finding-lost",
    pair: () => jsonPair(report({ findings: [finding()], summary: { total: 1 } }), report({ summary: { total: 1 } })),
    approval: { match: { fingerprint: FP } },
  },
  {
    category: "finding-new",
    pair: () => jsonPair(report({ summary: { total: 1 } }), report({ findings: [finding()], summary: { total: 1 } })),
    approval: { match: { fingerprint: FP } },
  },
  {
    category: "finding-reclassified",
    pair: () => jsonPair(report({ findings: [finding()] }), report({ findings: [finding({ severity: "critical" })] })),
    approval: { match: { fingerprint: FP, detail: "severity" } },
  },
  {
    category: "finding-identity-changed",
    pair: () => jsonPair(report({ findings: [finding()] }), report({ findings: [finding({ fingerprint: FP2 })] })),
    approval: { match: { fingerprint: FP, newFingerprint: FP2 } },
  },
  {
    category: "finding-field-changed",
    pair: () => jsonPair(report({ findings: [finding()] }), report({ findings: [finding({ description: "changed" })] })),
    approval: { match: { fingerprint: FP, field: "description" }, from: "AWS key", to: "changed" },
  },
  {
    category: "finding-field-added",
    pair: () => {
      const b = finding();
      delete b.verifyDetail;
      return jsonPair(report({ findings: [b] }), report({ findings: [finding({ verifyDetail: "x" })] }));
    },
    approval: { match: { fingerprint: FP, field: "verifyDetail" }, to: "x" },
  },
  {
    category: "finding-field-removed",
    pair: () => {
      const c = finding();
      delete c.verifyDetail;
      return jsonPair(report({ findings: [finding({ verifyDetail: "x" })] }), report({ findings: [c] }));
    },
    approval: { match: { fingerprint: FP, field: "verifyDetail" }, from: "x" },
  },
  {
    category: "sarif-changed",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifResult()])], "2.1.0"), sarifRaw([sarifRun([sarifResult()])], "2.1.1")),
    approval: { match: { path: "version" }, from: "2.1.0", to: "2.1.1" },
  },
  {
    category: "sarif-added",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifResult()])]), sarifRaw([sarifRun([sarifResult()], { properties: { x: 1 } })])),
    approval: { match: { path: "runs[0].properties" }, to: { x: 1 } },
  },
  {
    category: "sarif-removed",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifResult()], { invocations: [{}] })]), sarifRaw([sarifRun([sarifResult()])])),
    approval: { match: { path: "runs[0].invocations" }, from: [{}] },
  },
  {
    category: "sarif-run-count",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifResult()])]), sarifRaw([sarifRun([sarifResult()]), sarifRun([])])),
    approval: { match: { detail: "1 -> 2" } },
  },
  {
    category: "sarif-result-lost",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifAt("src/a.js")])]), sarifRaw([sarifRun([])])),
    approval: { match: { identity: FP, uri: "src/a.js" } },
  },
  {
    category: "sarif-result-new",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([])]), sarifRaw([sarifRun([sarifAt("src/a.js")])])),
    approval: { match: { identity: FP, uri: "src/a.js" } },
  },
  {
    category: "sarif-identity-changed",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifAt("src/a.js", FP)])]), sarifRaw([sarifRun([sarifAt("src/a.js", FP2)])])),
    approval: { match: { identity: FP, newIdentity: FP2 } },
  },
  {
    category: "sarif-uri-encoding",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifAt("a#1.js")])]), sarifRaw([sarifRun([sarifAt("a%231.js")])])),
    approval: { match: { identity: FP, uri: "a#1.js", candidateUri: "a%231.js" } },
  },
  {
    category: "sarif-uri-changed",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifAt("src/a.js")])]), sarifRaw([sarifRun([sarifAt("src/b.js")])])),
    approval: { match: { identity: FP, uri: "src/a.js", candidateUri: "src/b.js" } },
  },
  {
    category: "sarif-result-changed",
    pair: () => pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifResult({ message: { text: "one" } })])]), sarifRaw([sarifRun([sarifResult({ message: { text: "two" } })])])),
    approval: { match: { identity: FP, detail: "result fields" } },
  },
  {
    category: "stderr-output",
    pair: () => pairOf("run.err", "stderr", "one\n", "two\n"),
    approval: { match: { detail: "first difference at line 1" } },
  },
  {
    category: "text-output",
    pair: () => pairOf("out.txt", "text", "one\n", "two\n"),
    approval: { match: { detail: "first difference at line 1" } },
  },
];

test("every approvable category is covered: FAIL without approval, exact PASS with it, BLOCK with a wrong pin", () => {
  const seen = new Set();
  for (const s of SCENARIOS) {
    seen.add(s.category);
    const p = s.pair();
    EXPECT_FAIL(run(p), [s.category]);
    const exact = approve(p, { category: s.category, ...s.approval });
    assert.equal(run(p, { deltas: approvalsFile(p, [exact]) }).verdict, "PASS", `${s.category} with its exact approval`);
    // A wrong pin: change the first pinned value, or the first match key, so the approval cannot match.
    const wrong = { ...exact };
    if (hasOwn(exact, "from")) wrong.from = "WRONG";
    else if (hasOwn(exact, "to")) wrong.to = "WRONG";
    else wrong.match = { ...exact.match, [Object.keys(exact.match)[0]]: "WRONG" };
    EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [wrong]) }), /stale/);
  }
  assert.equal(seen.size, 22, "every approvable category has a scenario");
});

function hasOwn(o, k) {
  return Object.prototype.hasOwnProperty.call(o, k);
}

// ---------------------------------------------------------------- F1–F6 and input safety

test("F1: an --out write failure ends as BLOCK with exit 2, not as the FAIL code", () => {
  const text = report({ findings: [finding()] });
  const p = jsonPair(text, text);
  const blocker = path.join(p.root, "blocker");
  fs.writeFileSync(blocker, "a regular file, so a directory cannot be made under it");
  const r = spawnSync(process.execPath, [CLI, "--inventory", p.inv, "--base", p.base, "--candidate", p.cand, "--out", path.join(blocker, "sub")], { encoding: "utf8" });
  assert.equal(r.status, 2);
  assert.match(r.stdout, /BLOCK/);
  assert.match(r.stdout, /cannot write output/);
});

test("F2: relative directory and manifest paths PASS when the manifest is correct, and BLOCK when it is not", () => {
  const text = report({ findings: [finding()] });
  const root = scratch("relative");
  writeDir(path.join(root, "base"), { "scan.json": text }, { sums: false });
  writeDir(path.join(root, "cand"), { "scan.json": text }, { sums: false });
  const line = (d) => {
    const buf = fs.readFileSync(path.join(root, d, "scan.json"));
    return `${sha(buf)}  ${buf.length}  ${d}/scan.json`;
  };
  fs.writeFileSync(path.join(root, "MANIFEST.txt"), `${line("base")}\n${line("cand")}\n`);
  fs.writeFileSync(path.join(root, "inventory.json"), JSON.stringify({ schema: "r4-inventory-1", reports: [{ file: "scan.json", kind: "json" }] }));
  const args = ["--inventory", "inventory.json", "--base", "base", "--candidate", "cand", "--manifest", "MANIFEST.txt"];
  assert.equal(spawnSync(process.execPath, [CLI, ...args], { cwd: root, encoding: "utf8" }).status, 0);
  const manifest = path.join(root, "MANIFEST.txt");
  fs.writeFileSync(manifest, fs.readFileSync(manifest, "utf8").replace(/  \d+  /, "  1  "));
  assert.equal(spawnSync(process.execPath, [CLI, ...args], { cwd: root, encoding: "utf8" }).status, 2);
});

test("F3: a duplicate key at the top level, in summary, or in a finding BLOCKs", () => {
  const good = report({ findings: [finding()] });
  const variants = {
    top: good.replace('"tool": "secretloop"', '"tool": "secretloop",\n  "tool": "other"'),
    summary: good.replace('"total": 1', '"total": 1,\n    "total": 2'),
    finding: good.replace('"ruleId": "aws-key"', '"ruleId": "aws-key",\n      "ruleId": "other"'),
  };
  for (const [where, text] of Object.entries(variants)) {
    assert.notEqual(text, good, `variant ${where} did not change the text`);
    EXPECT_BLOCK(run(jsonPair(good, text)), /duplicate JSON key/);
  }
});

test("F3: a duplicate key in an approvals file BLOCKs", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  const file = path.join(p.root, "deltas.json");
  fs.writeFileSync(file, `{"schema":"r4-deltas-1","approvals":[],"approvals":[]}`);
  EXPECT_BLOCK(run(p, { deltas: file }), /duplicate JSON key/);
});

test("F4: a symlinked SHA256SUMS BLOCKs", { skip: !POSIX && "symlinks need privilege on Windows" }, () => {
  const text = report();
  const p = jsonPair(text, text);
  const outside = path.join(p.root, "outside-sums.txt");
  fs.writeFileSync(outside, fs.readFileSync(path.join(p.cand, "SHA256SUMS")));
  fs.unlinkSync(path.join(p.cand, "SHA256SUMS"));
  fs.symlinkSync(outside, path.join(p.cand, "SHA256SUMS"));
  EXPECT_BLOCK(run(p), /symbolic link/);
});

test("F4: a symlinked manifest BLOCKs", { skip: !POSIX && "symlinks need privilege on Windows" }, () => {
  const text = report();
  const p = jsonPair(text, text);
  const real = path.join(p.root, "real-manifest.txt");
  fs.writeFileSync(real, `${sha(fs.readFileSync(path.join(p.base, "scan.json")))}  ${fs.statSync(path.join(p.base, "scan.json")).size}  base/scan.json\n`);
  const link = path.join(p.root, "MANIFEST.txt");
  fs.symlinkSync(real, link);
  EXPECT_BLOCK(compare({ inventory: p.inv, base: p.base, candidate: p.cand, manifests: [link] }), /symbolic link/);
});

test("F4: a symlinked report file BLOCKs", { skip: !POSIX && "symlinks need privilege on Windows" }, () => {
  const text = report();
  const p = jsonPair(text, text);
  const copy = path.join(p.root, "copy.json");
  fs.writeFileSync(copy, text);
  fs.unlinkSync(path.join(p.cand, "scan.json"));
  fs.symlinkSync(copy, path.join(p.cand, "scan.json"));
  EXPECT_BLOCK(run(p), /non-regular entry/);
});

test("F4: a symlinked report root BLOCKs", { skip: !POSIX && "symlinks need privilege on Windows" }, () => {
  const text = report();
  const p = jsonPair(text, text);
  const linked = path.join(p.root, "linked-base");
  fs.symlinkSync(p.base, linked);
  EXPECT_BLOCK(compare({ inventory: p.inv, base: linked, candidate: p.cand }), /same directory|real directory, not a link/);
});

test("F5: the inventory is opened exactly once, so its hash and its parse come from one read", () => {
  const p = jsonPair(report(), report());
  const real = fs.openSync;
  const target = path.resolve(p.inv);
  let opens = 0;
  fs.openSync = function (file, ...rest) {
    if (typeof file === "string" && path.resolve(file) === target) opens++;
    return real.call(fs, file, ...rest);
  };
  let r;
  try {
    r = run(p);
  } finally {
    fs.openSync = real;
  }
  assert.equal(r.verdict, "PASS");
  assert.equal(opens, 1, "the inventory was opened more than once");
  assert.equal(r.record.inventory.sha256, sha(fs.readFileSync(p.inv)));
});

test("F6: a field change approval without a fingerprint BLOCKs, and a field-only approval never covers", () => {
  const p = jsonPair(report({ findings: [finding()] }), report({ findings: [finding({ description: "x" })] }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "finding-field-changed", match: { field: "description" }, from: "AWS key", to: "x" })]) }), /match lacks fingerprint/);
});

test("masked-value collision: a lost-identity approval for one same-mask finding cannot cover the other", () => {
  const a = finding({ fingerprint: "src/a.js:aws-key:0000000000000001" });
  const b = finding({ fingerprint: "src/a.js:aws-key:0000000000000002" });
  const p = jsonPair(report({ findings: [a, b], summary: { total: 2 } }), report({ findings: [a], summary: { total: 1 } }));
  const total = approve(p, { id: "TOTAL", category: "json-changed", match: { path: "summary.total" }, from: 2, to: 1 });
  assert.equal(run(p, { deltas: approvalsFile(p, [total, approve(p, { id: "LOST-B", category: "finding-lost", match: { fingerprint: b.fingerprint } })]) }).verdict, "PASS");
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [total, approve(p, { id: "LOST-A", category: "finding-lost", match: { fingerprint: a.fingerprint } })]) }), /stale/);
});

test("same directory: base and candidate that are the same directory BLOCK", () => {
  const text = report({ findings: [finding()] });
  const root = scratch("same");
  const dir = writeDir(path.join(root, "one"), { "scan.json": text });
  const inv = inventory(root, [{ file: "scan.json", kind: "json" }]);
  EXPECT_BLOCK(compare({ inventory: inv, base: dir, candidate: dir }), /same directory/);
  EXPECT_BLOCK(compare({ inventory: inv, base: dir, candidate: path.join(dir, "..", "one") }), /same directory/);
});

test("same directory: a symlink to the other side BLOCKs", { skip: !POSIX && "symlinks need privilege on Windows" }, () => {
  const text = report();
  const p = jsonPair(text, text);
  const link = path.join(p.root, "cand-link");
  fs.symlinkSync(p.base, link);
  EXPECT_BLOCK(compare({ inventory: p.inv, base: p.base, candidate: link }), /same directory/);
});

// Reviewer-facing name safety: each of these must BLOCK, not reach the filesystem.
const UNSAFE_NAMES = [
  ["a colon", "a:b.json"],
  ["an NTFS alternate data stream", "scan.json:stream"],
  ["a drive-relative name", "C:scan.json"],
  ["a Windows device name", "CON.json"],
  ["a Windows device name with no extension", "nul"],
  ["a trailing dot", "scan.json."],
  ["a trailing space", "scan.json "],
  ["a leading space", " scan.json"],
  ["a control character", "scan\u0001.json"],
  ["a forbidden character", "scan<1>.json"],
  ["an over-long name", "x".repeat(260) + ".json"],
];

for (const [label, name] of UNSAFE_NAMES) {
  test(`name safety: an inventory entry with ${label} BLOCKs`, () => {
    const p = jsonPair(report(), report());
    fs.writeFileSync(p.inv, JSON.stringify({ schema: "r4-inventory-1", reports: [{ file: name, kind: "json" }] }));
    EXPECT_BLOCK(run(p), /inventory entry is malformed/);
  });
}

test("name safety: an approval naming an unsafe report BLOCKs", () => {
  const p = jsonPair(report({ schemaVersion: 4 }), report({ schemaVersion: 5 }));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { report: "C:scan.json", category: "json-changed", match: { path: "schemaVersion" }, from: 4, to: 5 })]) }), /exactly one report/);
});

// ---------------------------------------------------------------- SARIF

test("identical SARIF PASSes", () => {
  const doc = sarifRaw([sarifRun([sarifResult()])]);
  assert.equal(run(pairOf("scan.sarif", "sarif", doc, doc)).verdict, "PASS");
});

test("a SARIF result without a location BLOCKs the run", () => {
  const doc = sarifRaw([sarifRun([sarifResult({ locations: [] })])]);
  EXPECT_BLOCK(run(pairOf("scan.sarif", "sarif", doc, doc)));
});

test("a SARIF approval pinned to a different identity does not cover this result", () => {
  const p = pairOf("scan.sarif", "sarif", sarifRaw([sarifRun([sarifAt("a#1.js")])]), sarifRaw([sarifRun([sarifAt("a%231.js")])]));
  EXPECT_BLOCK(run(p, { deltas: approvalsFile(p, [approve(p, { category: "sarif-uri-encoding", match: { identity: "src/other.js:aws-key:1111111111111111", uri: "a#1.js", candidateUri: "a%231.js" } })]) }), /stale/);
});

// ---------------------------------------------------------------- stderr and text

test("stderr that differs is FAIL; identical stderr PASSes", () => {
  EXPECT_FAIL(run(pairOf("run.err", "stderr", "warning one\n", "warning two\n")), ["stderr-output"]);
  assert.equal(run(pairOf("run.err", "stderr", "warning one\n", "warning one\n")).verdict, "PASS");
});

// ---------------------------------------------------------------- determinism and inputs untouched

test("the comparator writes nothing into the directories it compares", () => {
  const text = report({ findings: [finding()] });
  const p = jsonPair(text, text);
  const snap = (dir) => fs.readdirSync(dir).sort().map((n) => `${n}:${sha(fs.readFileSync(path.join(dir, n)))}`);
  const before = [snap(p.base), snap(p.cand)];
  run(p);
  assert.deepEqual([snap(p.base), snap(p.cand)], before);
});

test("the record is deterministic: two runs produce byte-identical output", () => {
  const base = report({ findings: [finding()] });
  const cand = report({ findings: [finding({ severity: "low" }), finding({ file: "src/b.js", fingerprint: "src/b.js:aws-key:1111111111111111", value: "BBBB****" })] });
  const p = jsonPair(base, cand);
  assert.equal(JSON.stringify(run(p).record), JSON.stringify(run(p).record));
});

// ---------------------------------------------------------------- frozen N10 evidence

// Why the frozen N10 record cannot be used, or null when it can. Only its shape is checked here: its
// bytes are checked by the comparison itself, which BLOCKs on any payload that differs from MANIFEST.txt.
function n10Problem() {
  if (!N10) return "R4_N10_ROOT is not set";
  const is = (rel, kind) => {
    try {
      return fs.lstatSync(path.join(N10, rel))[kind]();
    } catch {
      return false;
    }
  };
  if (!is(".", "isDirectory")) return `R4_N10_ROOT is not a real directory: ${N10}`;
  if (!is("MANIFEST.txt", "isFile")) return `no regular MANIFEST.txt under R4_N10_ROOT: ${N10}`;
  for (const dir of ["evidence/main", "evidence/v0.6.0"]) {
    if (!is(dir, "isDirectory")) return `no ${dir} directory under R4_N10_ROOT: ${N10}`;
  }
  return null;
}

// The three historical N10 cases, by the id each records when it runs to completion.
const N10_CASES = ["n10-reproduction", "n10-without-reproduction", "n10-tamper-refused"];
const N10_RAN = new Set();

// A historical N10 case. It runs when the record is usable. Otherwise it fails under R4_REQUIRE_N10=1
// and skips, naming the reason, when R4_REQUIRE_N10 is unset. Any other value, the empty string
// included, fails, so a misspelt requirement cannot quietly become a skip. A case that runs to
// completion records its id, and appends it to R4_N10_RECEIPT when the runner provides one.
function n10Test(id, name, fn) {
  if (N10_REQUIRE !== undefined && N10_REQUIRE !== "1") {
    return test(name, () => assert.fail(`R4_REQUIRE_N10 must be 1 or unset, not ${JSON.stringify(N10_REQUIRE)}`));
  }
  if (N10_PROBLEM === null) {
    return test(name, () => {
      fn();
      N10_RAN.add(id);
      if (process.env.R4_N10_RECEIPT) fs.appendFileSync(process.env.R4_N10_RECEIPT, `${id}\n`);
    });
  }
  if (N10_REQUIRE === "1") {
    return test(name, () => assert.fail(`R4_REQUIRE_N10=1, but the frozen N10 record cannot be used: ${N10_PROBLEM}`));
  }
  return test(name, { skip: `historical N10 case not run: ${N10_PROBLEM} (R4_REQUIRE_N10=1 makes this a failure)` }, fn);
}

// With R4_REQUIRE_N10 set to any value, this process fails unless all three cases ran to completion.
// A test-runner filter (--test-name-pattern, --test-skip-pattern, --test-only) removes cases without
// failing them, and this is what notices. It cannot notice a run in which this file never loads, such
// as a --test-shard that leaves it out: run-comparator-tests.js refuses NODE_OPTIONS and checks the
// receipt for that.
if (N10_REQUIRE !== undefined) {
  process.on("exit", () => {
    const missing = N10_CASES.filter((id) => !N10_RAN.has(id));
    if (missing.length > 0) {
      process.stderr.write(`R4_REQUIRE_N10 is set, but these historical N10 cases did not run to completion: ${missing.join(", ")}\n`);
      process.exitCode = 1;
    }
  });
}

const frozenFiles = () => {
  const out = [];
  for (const dir of ["evidence/main", "evidence/v0.6.0"]) {
    for (const name of fs.readdirSync(path.join(N10, dir)).sort()) {
      out.push(`${dir}/${name}:${sha(fs.readFileSync(path.join(N10, dir, name)))}`);
    }
  }
  out.push(`MANIFEST.txt:${sha(fs.readFileSync(path.join(N10, "MANIFEST.txt")))}`);
  return out;
};

const n10Args = (candidate) => ({
  inventory: path.join(HERE, "fixtures", "n10-inventory.json"),
  base: path.join(N10, "evidence/v0.6.0"),
  candidate,
  manifests: [path.join(N10, "MANIFEST.txt")],
});

n10Test("n10-reproduction", "N10 reproduction: PASS-REPRODUCTION, 27 recorded differences, zero finding-level differences, frozen evidence unchanged", () => {
  const before = frozenFiles();
  const args = { ...n10Args(path.join(N10, "evidence/main")), reproduction: REPRO };
  const r = compare(args);
  assert.equal(r.verdict, "PASS-REPRODUCTION", JSON.stringify(r.record.blocks || r.record.unapprovedCount));
  assert.equal(r.record.reports.filter((x) => x.kind === "json").length, 13);
  assert.equal(r.record.differences.length, 27);
  assert.equal(r.record.reproductionCount, 27);
  assert.equal(r.record.approvedCount, 0, "a reproduction is never release approval");
  assert.equal(r.record.differences.filter((d) => d.category.startsWith("finding-")).length, 0);
  const cli = spawnSync(process.execPath, [CLI, "--inventory", args.inventory, "--base", args.base, "--candidate", args.candidate, "--manifest", args.manifests[0], "--reproduction", REPRO], { encoding: "utf8" });
  assert.equal(cli.status, 3, cli.stdout);
  assert.deepEqual(frozenFiles(), before, "frozen N10 evidence changed during the comparison");
});

n10Test("n10-without-reproduction", "N10 without the reproduction is FAIL, with 27 unapproved metadata differences", () => {
  const r = compare(n10Args(path.join(N10, "evidence/main")));
  EXPECT_FAIL(r);
  assert.equal(r.record.unapprovedCount, 27);
});

n10Test("n10-tamper-refused", "N10 reproduction refuses a changed finding in a scratch copy: the pinned bytes no longer match", () => {
  const root = scratch("n10-inject");
  const cand = path.join(root, "candidate");
  fs.mkdirSync(cand, { recursive: true });
  for (const name of fs.readdirSync(path.join(N10, "evidence/main"))) {
    fs.copyFileSync(path.join(N10, "evidence/main", name), path.join(cand, name));
  }
  const doc = JSON.parse(fs.readFileSync(path.join(cand, "A.tree.json"), "utf8"));
  doc.findings[0].severity = doc.findings[0].severity === "critical" ? "low" : "critical";
  fs.writeFileSync(path.join(cand, "A.tree.json"), JSON.stringify(doc, null, 2));
  resumSums(cand);
  EXPECT_BLOCK(compare({ ...n10Args(cand), reproduction: REPRO }), /stale/);
});
