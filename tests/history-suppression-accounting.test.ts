import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { spawnSync } from "child_process";
import { scanHistory, LogPatchParser } from "../src/history";
import { mergeConfig } from "../src/config";
import { SuppressionAccounting } from "../src/scanner";
import { test, suite, finish, assert } from "./harness";

suite("history suppression accounting");

/**
 * The directive token, assembled, for annotations meant to be refused.
 *
 * Same reason as in tests/suppression-accountability.test.ts: a scanner reads
 * its own test suite, and a refusal written out whole would raise its
 * diagnostic on every scan of this repository.
 */
const SL = "secretloop" + ":allow";
// Annotated with the form under test, scoped to the one rule each fixture
// trips, so the repository's own scan stays honest about them and neither line
// can suppress anything else that later lands on it.
const AWS = "AKIAIOSFODNN7ABCDEFG"; // secretloop:allow(aws-access-key) -- synthetic test fixture
const GITHUB = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"; // secretloop:allow(github-token) -- synthetic test fixture
const CLI_PATH = path.join(__dirname, "..", "out", "cli.js");

/** A fresh marker per call, so nothing asserted here can match stale output. */
const marker = (tag: string) => `zz${tag}${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}zz`;

function withRepo<T>(fn: (dir: string, git: (...a: string[]) => void) => T): T {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-histacct-"));
  const git = (...args: string[]) => {
    const res = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    if (res.status !== 0) throw new Error(`git ${args.join(" ")}: ${res.stderr}`);
  };
  git("init", "-q");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  try {
    return fn(dir, git);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The awaiting variant: the synchronous one removes the directory too early. */
async function withRepoAsync<T>(
  fn: (dir: string, git: (...a: string[]) => void) => Promise<T>
): Promise<T> {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-histacct-"));
  const git = (...args: string[]) => {
    const res = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    if (res.status !== 0) throw new Error(`git ${args.join(" ")}: ${res.stderr}`);
  };
  git("init", "-q");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  try {
    return await fn(dir, git);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function cli(dir: string, args: string[]): { stdout: string; stderr: string; status: number } {
  const res = spawnSync("node", [CLI_PATH, ...args], { cwd: dir, encoding: "utf8" });
  return { stdout: res.stdout ?? "", stderr: res.stderr ?? "", status: res.status ?? -1 };
}

function summaryOf(stdout: string): any {
  return JSON.parse(stdout).summary;
}

/** One reasoned suppression and one without, in a single commit. */
function twoSuppressions(reason: string): string {
  return (
    `const a = "${AWS}"; // secretloop:allow(aws-access-key) -- ${reason}\n` +
    `const g = "${GITHUB}"; // secretloop:allow(github-token)\n`
  );
}

// --- the false zero ---------------------------------------------------------

test("history reports the reasoned count it measured, as the working tree does", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, "app.js"), twoSuppressions("vendor sample"), "utf8");
    git("add", "-A");
    git("commit", "-qm", "one reasoned and one unreasoned suppression");

    const history = summaryOf(cli(dir, ["history", "--format", "json"]).stdout);
    const worktree = summaryOf(cli(dir, ["scan", "--format", "json"]).stdout);

    // This commit introduces each line exactly once, so the two modes see the
    // same occurrences. That is a property of THIS fixture, not a rule: history
    // counts every version of a line it meets.
    assert.strictEqual(history.coverage.suppression.inlineSuppressed, 2);
    assert.strictEqual(
      history.coverage.suppression.inlineSuppressedWithReason,
      1,
      "history published 0 here before the correction"
    );
    assert.strictEqual(worktree.coverage.suppression.inlineSuppressed, 2);
    assert.strictEqual(worktree.coverage.suppression.inlineSuppressedWithReason, 1);
    assert.match(history.scope, /2 finding\(s\) suppressed by inline directives, 1 with a recorded reason/);
    assert.match(worktree.scope, /2 finding\(s\) suppressed by inline directives, 1 with a recorded reason/);
    assert.strictEqual(history.total, 0, "both findings stay suppressed");
  });
});

test("the SARIF scope sentence carries the same clause", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, "app.js"), twoSuppressions("vendor sample"), "utf8");
    git("add", "-A");
    git("commit", "-qm", "c");
    const sarif = JSON.parse(cli(dir, ["history", "--format", "sarif"]).stdout);
    const scope = sarif.runs[0].invocations[0].properties.scope;
    assert.match(scope, /2 finding\(s\) suppressed by inline directives, 1 with a recorded reason/);
  });
});

test("no reasons: a measured zero, and the legacy sentence byte for byte", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, "app.js"), `const g = "${GITHUB}"; // secretloop:allow\n`, "utf8");
    git("add", "-A");
    git("commit", "-qm", "c");
    const s = summaryOf(cli(dir, ["history", "--format", "json"]).stdout);
    assert.strictEqual(s.coverage.suppression.inlineSuppressed, 1);
    assert.strictEqual(
      s.coverage.suppression.inlineSuppressedWithReason,
      0,
      "present and zero: the producer counted, and counted none"
    );
    assert.ok(
      s.scope.endsWith("1 finding(s) suppressed by inline directives"),
      `${s.scope} — the clause must not appear when nothing was explained`
    );
  });
});

test("several commits count every occurrence history meets", () => {
  withRepo((dir, git) => {
    for (const name of ["a.js", "b.js", "c.js"]) {
      writeFileSync(
        path.join(dir, name),
        `const g = "${GITHUB}"; // secretloop:allow(github-token) -- fixture\n`,
        "utf8"
      );
      git("add", "-A");
      git("commit", "-qm", `add ${name}`);
    }
    const s = summaryOf(cli(dir, ["history", "--format", "json"]).stdout);
    assert.strictEqual(s.coverage.suppression.inlineSuppressed, 3, "three introductions");
    assert.strictEqual(s.coverage.suppression.inlineSuppressedWithReason, 3);
  });
});

// --- the producer itself, not a mock ---------------------------------------

test("scanHistory hands the accounting to its caller", async () => {
  await withRepoAsync(async (dir, git) => {
    writeFileSync(path.join(dir, "app.js"), twoSuppressions("vendor sample"), "utf8");
    git("add", "-A");
    git("commit", "-qm", "c");
    let count: number | undefined;
    let accounting: SuppressionAccounting | undefined;
    let diagnostics: string[] = [];
    await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      onSuppressed: (n, a) => {
        count = n;
        accounting = a;
      },
      onSuppressionDiagnostic: (m) => (diagnostics = m),
    });
    assert.strictEqual(count, 2);
    assert.deepStrictEqual(
      accounting,
      { withReason: 1 },
      "the accounting is reported, not reconstructed from findings"
    );
    assert.deepStrictEqual(diagnostics, [], "nothing to complain about in this fixture");
  });
});

test("scanHistory forwards directive diagnostics, deduplicated", async () => {
  await withRepoAsync(async (dir, git) => {
    // The same malformed annotation in three files: one complaint, not three.
    for (const name of ["a.js", "b.js", "c.js"]) {
      writeFileSync(path.join(dir, name), `const a = "${AWS}"; // ${SL}(aws-access-key!)\n`, "utf8");
      git("add", "-A");
      git("commit", "-qm", `add ${name}`);
    }
    const diagnostics: string[] = [];
    const findings = await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      onSuppressionDiagnostic: (m) => diagnostics.push(...m),
    });
    // Three files, so three identities -- a fingerprint carries the path.
    assert.strictEqual(findings.length, 3);
    assert.strictEqual(diagnostics.length, 1, "deduplicated across the whole parse");
    assert.match(diagnostics[0], /\[directive-scope-malformed\]$/);
  });
});

/**
 * Feed a patch through the seam exactly as the streaming path does.
 *
 * `push` takes ONE LINE: the production handler splits arriving chunks on
 * newlines and carries the partial last line itself, then pushes the carry
 * before `finish`. Driving it any other way tests the harness, not the parser --
 * pushing a whole multi-line patch as a single "line" parses nothing at all.
 */
function feed(parser: LogPatchParser, patch: string, chunkSize: number): void {
  let carry = "";
  for (let i = 0; i < patch.length; i += chunkSize) {
    const lines = (carry + patch.slice(i, i + chunkSize)).split("\n");
    carry = lines.pop() ?? "";
    for (const line of lines) parser.push(line);
  }
  if (carry.length > 0) parser.push(carry);
  parser.finish();
}

test("a patch split across chunk boundaries is counted once", () => {
  const patch = [
    "@@SGCOMMIT@@abc1234@@SGF@@Dev <dev@example.com>@@SGF@@2026-01-01T00:00:00Z@@SGF@@add app",
    "diff --git a/app.js b/app.js",
    "--- /dev/null",
    "+++ b/app.js",
    "@@ -0,0 +1,2 @@",
    `+const a = "${AWS}"; // secretloop:allow(aws-access-key) -- vendor sample`,
    `+const g = "${GITHUB}"; // secretloop:allow(github-token)`,
    "",
  ].join("\n");

  for (const size of [1, 7, 64, patch.length]) {
    const parser = new LogPatchParser(mergeConfig({}));
    feed(parser, patch, size);
    assert.strictEqual(parser.suppressedCount(), 2, `chunk size ${size}`);
    assert.deepStrictEqual(
      parser.suppressionAccounting(),
      { withReason: 1 },
      `chunk size ${size}: the final flush must not double count`
    );
  }
});

test("a parse that read only part of a patch reports what it read", () => {
  // The cancelled close path reports these same totals and then marks the
  // coverage incomplete; this is the parser half of that, deterministically.
  const head = [
    "@@SGCOMMIT@@abc1234@@SGF@@Dev <dev@example.com>@@SGF@@2026-01-01T00:00:00Z@@SGF@@add app",
    "diff --git a/app.js b/app.js",
    "--- /dev/null",
    "+++ b/app.js",
    "@@ -0,0 +1,2 @@",
    `+const a = "${AWS}"; // secretloop:allow(aws-access-key) -- vendor sample`,
    "",
  ].join("\n");
  const parser = new LogPatchParser(mergeConfig({}));
  feed(parser, head, 8);
  assert.strictEqual(parser.suppressedCount(), 1, "a floor, not a total");
  assert.deepStrictEqual(parser.suppressionAccounting(), { withReason: 1 });
});

// --- what must not change ---------------------------------------------------

test("an invalid scope still fails closed in history, and only advises", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, "bad.js"), `const a = "${AWS}"; // ${SL}(aws-access-key!)\n`, "utf8");
    git("add", "-A");
    git("commit", "-qm", "c");
    const run = cli(dir, ["history", "--format", "json"]);
    const s = summaryOf(run.stdout);
    assert.strictEqual(s.total, 1, "the finding is reported, not hidden");
    assert.strictEqual(s.coverage.suppression.inlineSuppressed, 0);
    assert.strictEqual(s.coverage.suppression.inlineSuppressedWithReason, 0);
    assert.match(run.stderr, /\[directive-scope-malformed\]/);
    assert.ok(!run.stderr.includes("aws-access-key!"), "the rejected text is never quoted back");
  });
});

test("an advisory diagnostic alone does not change the exit code", () => {
  withRepo((dir, git) => {
    // A refused directive on a line with nothing to find: advice, and exit 0.
    writeFileSync(path.join(dir, "note.js"), `const ok = 1; // ${SL}()\n`, "utf8");
    git("add", "-A");
    git("commit", "-qm", "c");
    const run = cli(dir, ["history", "--fail-on", "critical"]);
    assert.strictEqual(run.status, 0, run.stderr);
    assert.match(run.stderr, /\[directive-scope-empty\]/);
  });
});

test("the reason text reaches no history surface", () => {
  withRepo((dir, git) => {
    const token = marker("histreason");
    writeFileSync(path.join(dir, "app.js"), twoSuppressions(token), "utf8");
    git("add", "-A");
    git("commit", "-qm", "c");
    for (const format of ["text", "json", "sarif"]) {
      const run = cli(dir, ["history", "--format", format]);
      assert.ok(!run.stdout.includes(token), `the ${format} history report published the reason`);
      assert.ok(!run.stderr.includes(token), `the ${format} run logged the reason`);
    }
  });
});

test("suppression identity stays withheld when history suppressed anything", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, "app.js"), twoSuppressions("vendor sample"), "utf8");
    git("add", "-A");
    git("commit", "-qm", "c");
    const report = JSON.parse(cli(dir, ["history", "--format", "json"]).stdout);
    assert.strictEqual(
      report.suppressionDigest,
      undefined,
      "a scan that hid something may not publish a suppression identity"
    );
    assert.deepStrictEqual(report.summary.coverage.suppression.unidentified, [
      "findings were suppressed by inline directives in the scanned source",
    ]);
  });
});

finish();
