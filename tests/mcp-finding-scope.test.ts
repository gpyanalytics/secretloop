import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { spawnSync } from "child_process";
import {
  toolScan,
  toolListFindings,
  toolHistoryScan,
  cachedScan,
  setAllowedRoots,
  resetSessions,
} from "../src/mcp-core";
import { positiveSamples } from "./fixtures";
import { buildZip } from "./archive-builders";

/**
 * WHERE THE FINDINGS A CLIENT IS LOOKING AT CAME FROM.
 *
 * `secretloop_scan` computed a scope and then dropped it: the session cache kept
 * the findings and not the account of what had been inspected, so
 * `secretloop_list_findings` returned rows with no statement of their origin at
 * all -- the key was absent, not null.
 *
 * The contract these tests pin:
 *
 *   PROVENANCE is response-level, because the cache has exactly ONE writer and
 *   each entry therefore describes exactly one working-tree scan of one root.
 *   No per-finding field is added; none would carry information the entry does
 *   not already carry.
 *
 *   SCOPE DESCRIBES THE SCAN, not the response. Filters change which rows are
 *   returned and say so through matched/totalInScan/filteredOut; they do not
 *   change what was looked at.
 *
 *   FRESHNESS stays where it already was: `source` and `scannedAt`.
 *
 * These drive the real handlers in-process over disposable synthetic
 * repositories. THEY ARE NOT MCP-CLIENT VALIDATION: no client, transport or
 * protocol framing is exercised anywhere in this file.
 */

const TOKEN = positiveSamples["github-token"];
const dirs: string[] = [];

function repo(files: Record<string, string>, asGit = true): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sl-scope-"));
  dirs.push(dir);
  for (const [name, text] of Object.entries(files)) {
    const full = path.join(dir, name);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, text, "utf8");
  }
  if (asGit) {
    const git = (...a: string[]) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
    git("init", "-q", ".");
    git("config", "user.email", "t@e.com");
    git("config", "user.name", "t");
    git("add", "-A");
    git("commit", "-qm", "fixture");
  }
  return dir;
}

const payload = (r: any) => {
  assert.ok(r.ok, `handler refused: ${r.ok ? "" : r.error}`);
  return r.payload;
};

// ---------------------------------------------------------------------------
suite("MCP finding scope — working-tree provenance");

test("a scan's scope reaches list_findings unchanged", () => {
  const dir = repo({ "app.js": `const gh = "${TOKEN}";\n` });
  resetSessions();
  setAllowedRoots([dir]);
  const scan = payload(toolScan({ path: dir }));
  const list = payload(toolListFindings({ path: dir }));

  assert.ok(
    Object.prototype.hasOwnProperty.call(list, "scope"),
    "list_findings must carry the scope of the scan behind its rows"
  );
  assert.deepStrictEqual(list.scope, scan.scope, "the same scope object the scan reported");
  assert.match(String(list.scope.statement), /^Scanned \d+ file\(s\)/);
  assert.strictEqual(list.scope.filesScanned, scan.scope.filesScanned);
});

test("scope survives filtering, because a filter narrows rows and not the scan", () => {
  const dir = repo({ "app.js": `const gh = "${TOKEN}";\n` });
  resetSessions();
  setAllowedRoots([dir]);
  const scan = payload(toolScan({ path: dir }));
  const all = payload(toolListFindings({ path: dir }));
  const narrowed = payload(toolListFindings({ path: dir, ruleId: ["github-token"] }));
  const empty = payload(toolListFindings({ path: dir, severity: ["low"] }));

  assert.deepStrictEqual(narrowed.scope, scan.scope, "a matching filter does not move scope");
  assert.deepStrictEqual(empty.scope, scan.scope, "a filter matching nothing does not move scope");
  assert.deepStrictEqual(all.scope, empty.scope);
  // The row counts are what change, and they are reported separately.
  assert.ok(empty.matched === 0 && empty.totalInScan > 0, "the total survives an empty match");
});

test("a rescan replaces findings and scope together", () => {
  const dir = repo({ "app.js": `const gh = "${TOKEN}";\n` });
  resetSessions();
  setAllowedRoots([dir]);
  const first = payload(toolScan({ path: dir }));
  writeFileSync(path.join(dir, "second.js"), `const b = "${TOKEN}";\n`, "utf8");
  const second = payload(toolScan({ path: dir }));
  const list = payload(toolListFindings({ path: dir }));

  assert.ok(second.scope.filesScanned > first.scope.filesScanned, "the second scan saw more files");
  assert.deepStrictEqual(list.scope, second.scope, "the newer scan's scope, not the older one's");
  assert.strictEqual(list.totalInScan, second.findings.length, "findings moved with it");
});

test("two roots keep their own scope; neither is relabelled by the other", () => {
  const a = repo({ "a.js": `const gh = "${TOKEN}";\n` });
  const b = repo({ "b.js": `const gh = "${TOKEN}";\n`, "extra.js": "const ok = 1;\n" });
  resetSessions();
  setAllowedRoots([a, b]);
  const scanA = payload(toolScan({ path: a }));
  const scanB = payload(toolScan({ path: b }));
  const listA = payload(toolListFindings({ path: a }));
  const listB = payload(toolListFindings({ path: b }));

  assert.deepStrictEqual(listA.scope, scanA.scope);
  assert.deepStrictEqual(listB.scope, scanB.scope);
  assert.notDeepStrictEqual(listA.scope, listB.scope, "the later scan must not relabel the earlier");
});

// ---------------------------------------------------------------------------
suite("MCP finding scope — no prior scan, empty scans, failures");

test("no scan yet is a REFUSAL, and a zero-finding scan is a real answer with scope", () => {
  const clean = repo({ "ok.js": "const x = 1;\n" });
  resetSessions();
  setAllowedRoots([clean]);

  const before = toolListFindings({ path: clean });
  assert.strictEqual(before.ok, false, "no prior scan must not read as a clean repository");
  assert.match((before as { ok: false; error: string }).error, /not a clean result/);

  const scan = payload(toolScan({ path: clean }));
  const after = payload(toolListFindings({ path: clean }));
  assert.strictEqual(scan.findings.length, 0);
  assert.strictEqual(after.matched, 0);
  assert.deepStrictEqual(after.scope, scan.scope, "a completed zero-finding scan still says what it looked at");
  assert.ok(after.scope.filesScanned > 0, "it inspected files and found nothing, which is not the same as not looking");
});

test("a failed scan does not relabel or erase the previous scan's findings", () => {
  const dir = repo({ "app.js": `const gh = "${TOKEN}";\n` });
  resetSessions();
  setAllowedRoots([dir]);
  const good = payload(toolScan({ path: dir }));
  const listed = payload(toolListFindings({ path: dir }));

  // A malformed project config makes the next scan refuse before it can store.
  writeFileSync(path.join(dir, ".secretloop.json"), "{ not json", "utf8");
  const failed = toolScan({ path: dir });
  assert.strictEqual(failed.ok, false, "a malformed config is a refusal, not a clean scan");

  const after = payload(toolListFindings({ path: dir }));
  assert.deepStrictEqual(after.scope, good.scope, "the failed scan must not overwrite the stored scope");
  assert.strictEqual(after.scannedAt, listed.scannedAt, "nor the freshness of the scan that did run");
  assert.strictEqual(after.totalInScan, listed.totalInScan, "nor the findings");
});

// ---------------------------------------------------------------------------
suite("MCP finding scope — history stays out of the working-tree cache");

test("a history scan carries its own scope and never enters the session cache", async () => {
  const dir = repo({ "app.js": `const gh = "${TOKEN}";\n` });
  resetSessions();
  setAllowedRoots([dir]);
  const scan = payload(toolScan({ path: dir }));
  const before = payload(toolListFindings({ path: dir }));

  const history = payload(await toolHistoryScan({ path: dir }));
  assert.match(String(history.scope.statement), /commit\(s\)/, "history scope counts commits");
  assert.ok(!/file\(s\)/.test(String(history.scope.statement)), "and does not claim files");

  const after = payload(toolListFindings({ path: dir }));
  assert.deepStrictEqual(after.scope, scan.scope, "still the working-tree scan's scope");
  assert.strictEqual(after.scannedAt, before.scannedAt, "the history scan did not restamp the cache");
  assert.strictEqual(after.totalInScan, before.totalInScan, "nor add its findings to it");
  // The architectural guarantee this rests on: only toolScan writes the cache.
  assert.strictEqual(cachedScan(dir)!.scope.filesScanned, scan.scope.filesScanned);
});

test("a stopped history scan stays partial and still writes nothing to the cache", async () => {
  const dir = repo({ "a.js": `const a = "${TOKEN}";\n` });
  const git = (...a: string[]) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
  writeFileSync(path.join(dir, "b.js"), `const b = "${TOKEN}";\n`, "utf8");
  git("add", "-A");
  git("commit", "-qm", "second");
  resetSessions();
  setAllowedRoots([dir]);
  const scan = payload(toolScan({ path: dir }));

  const stopped = payload(await toolHistoryScan({ path: dir, maxCommits: 1 } as never));
  assert.strictEqual(stopped.complete, false, "a stopped scan is not complete");
  assert.strictEqual(stopped.stopReason, "commit-limit");
  assert.match(String(stopped.scope.statement), /^Stopped after/, "and says so in its own scope");

  const after = payload(toolListFindings({ path: dir }));
  assert.deepStrictEqual(after.scope, scan.scope, "the partial history scan labelled nothing");
});

// ---------------------------------------------------------------------------
suite("MCP finding scope — overlapping operations and per-scan accounting");

test("a history scan in flight cannot pair its work with the workspace cache", async () => {
  // DETERMINISTIC, not timing-dependent: toolScan is a SYNCHRONOUS function, so
  // once it starts it runs to completion before any pending promise resumes.
  // Starting the async history scan and then calling toolScan without awaiting
  // puts a real history scan in flight across a real workspace scan.
  const dir = repo({ "app.js": `const gh = "${TOKEN}";\n` });
  resetSessions();
  setAllowedRoots([dir]);
  payload(toolScan({ path: dir }));

  const inFlight = toolHistoryScan({ path: dir });     // async, deliberately not awaited
  const during = payload(toolScan({ path: dir }));     // synchronous: completes now

  const whileFlying = cachedScan(dir)!;
  assert.strictEqual(whileFlying.scope, during.scope, "the cache holds the scan that just ran");

  await inFlight;                                       // the history scan now resolves

  const afterwards = cachedScan(dir)!;
  assert.strictEqual(afterwards.scope, during.scope, "a resolving history scan relabels nothing");
  assert.strictEqual(
    afterwards.findings.length,
    during.findings.length,
    "and contributes no findings to the workspace cache"
  );
  const list = payload(toolListFindings({ path: dir }));
  assert.deepStrictEqual(list.scope, during.scope, "list_findings still reports the workspace scan");
});

test("archive accounting in scope is per scan, never accumulated across scans", () => {
  // scope.archives is the only non-primitive it carries. If that accumulator
  // were ever shared between calls, a second scan would report the first scan's
  // containers on top of its own -- visible in the serialized payload, not just
  // in memory.
  const dir = repo({ "app.js": "const ok = 1;\n" }, false);
  writeFileSync(path.join(dir, "one.zip"), buildZip([{ name: "a.txt", data: Buffer.from("x\n") }]));
  resetSessions();
  setAllowedRoots([dir]);
  const first = payload(toolScan({ path: dir }));
  assert.strictEqual(first.scope.archives.containersOpened, 1);

  writeFileSync(path.join(dir, "two.zip"), buildZip([{ name: "b.txt", data: Buffer.from("y\n") }]));
  const second = payload(toolScan({ path: dir }));
  assert.strictEqual(
    second.scope.archives.containersOpened,
    2,
    "two containers are present, so two are reported -- not three"
  );
  assert.strictEqual(second.scope.archives.members.scanned, 2);

  const list = payload(toolListFindings({ path: dir }));
  assert.deepStrictEqual(list.scope.archives, second.scope.archives, "the listing carries the later scan's accounting");
});

// ---------------------------------------------------------------------------
suite("MCP finding scope — what it must not become");

test("scope is counts and one sentence: no path, no credential, no digest", () => {
  const dir = repo({ "secrets/app.js": `const gh = "${TOKEN}";\n` });
  resetSessions();
  setAllowedRoots([dir]);
  toolScan({ path: dir });
  const list = payload(toolListFindings({ path: dir }));
  const scope = JSON.stringify(list.scope);

  assert.ok(!scope.includes(TOKEN), "no credential reaches scope");
  assert.ok(!scope.includes(dir), "no absolute path reaches scope");
  assert.ok(!scope.includes("secrets/app.js"), "no scanned path reaches scope");
  assert.ok(!/digest|Digest/.test(scope), "no digest is invented here");
  assert.ok(!/scopeDigest/.test(JSON.stringify(list)), "and it is not the comparator's scopeDigest");
  for (const key of Object.keys(list.scope)) {
    assert.ok(
      ["filesScanned", "outsideExcluded", "apiDocumentsScoped", "archives", "openedFileChecks", "statement"].includes(key),
      `unexpected scope key ${key}`
    );
  }
  // The readers' check accounting is numbers all the way down: no path, no
  // name, no platform string.
  const leaves = (v: unknown): unknown[] =>
    v && typeof v === "object" ? Object.values(v as object).flatMap(leaves) : [v];
  for (const leaf of leaves(list.scope.openedFileChecks)) {
    assert.strictEqual(typeof leaf, "number", `openedFileChecks carries a non-count: ${String(leaf)}`);
  }
});

test("no per-finding provenance field was added", () => {
  // The cache has one writer and one origin per entry, so a per-row field would
  // repeat the response-level one on every row and could drift from it.
  const dir = repo({ "app.js": `const gh = "${TOKEN}";\n` });
  resetSessions();
  setAllowedRoots([dir]);
  toolScan({ path: dir });
  const list = payload(toolListFindings({ path: dir }));
  assert.ok(list.findings.length > 0);
  for (const f of list.findings) {
    assert.ok(!("scope" in f), "a finding row must not carry its own scope");
    assert.ok(!("origin" in f), "nor an origin field");
    assert.ok(!("provenance" in f), "nor a provenance field");
  }
});

finish();
process.on("exit", () => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
