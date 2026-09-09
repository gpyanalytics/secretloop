import {
  parseLogPatch,
  scanHistory,
  describeGitFailure,
  validateRevRange,
  InvalidRevRangeError,
} from "../src/history";
import { defaultConfig, mergeConfig } from "../src/config";
import { test, suite, finish, assert } from "./harness";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";

suite("history.ts");

const MARKER = "@@SGCOMMIT@@";
const SEP = "@@SGF@@";

function commitHeader(sha: string, subject = "add config"): string {
  return `${MARKER}${sha}${SEP}Dev <dev@example.com>${SEP}2026-01-01T00:00:00Z${SEP}${subject}`;
}

test("finds a secret in an added line", () => {
  const patch = [
    commitHeader("abc123def456"),
    "diff --git a/config.js b/config.js",
    "--- /dev/null",
    "+++ b/config.js",
    "@@ -0,0 +1,1 @@",
    '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");

  const findings = parseLogPatch(patch, defaultConfig);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, "github-token");
  assert.strictEqual(findings[0].file, "config.js");
  assert.strictEqual(findings[0].commit, "abc123def456");
});

test("computes the line number from the hunk header", () => {
  const patch = [
    commitHeader("aaa111"),
    "+++ b/app.js",
    "@@ -40,0 +41,1 @@",
    '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, defaultConfig)[0].line, 41);
});

test("ignores removed and context lines", () => {
  // A secret being DELETED in this commit was already reported when it was
  // added; re-reporting it on every removal would triple-count history.
  const patch = [
    commitHeader("bbb222"),
    "+++ b/app.js",
    "@@ -1,1 +1,1 @@",
    '-const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
    ' const other = "ghp_26C7e42F292c6912E7710c838347Ae178B4a";',
    "+const token = process.env.TOKEN;",
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, defaultConfig).length, 0);
});

test("reports a secret once even when many commits touch it", () => {
  const line = '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";';
  const patch = [
    commitHeader("c1"),
    "+++ b/app.js",
    "@@ -0,0 +1,1 @@",
    line,
    commitHeader("c2"),
    "+++ b/app.js",
    "@@ -1,1 +1,1 @@",
    line,
  ].join("\n");
  const findings = parseLogPatch(patch, defaultConfig);
  assert.strictEqual(findings.length, 1, "duplicate across commits must collapse");
  assert.strictEqual(findings[0].commit, "c1", "attributed to the first commit seen");
});

test("assembles a multi-line PEM block from consecutive added lines", () => {
  const patch = [
    commitHeader("ddd444"),
    "+++ b/id_rsa",
    "@@ -0,0 +1,4 @@",
    "+-----BEGIN RSA PRIVATE KEY-----",
    "+MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaBcgVJcXOFbdc6JGf",
    "+MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaBcgVJcXOFbdc6JGf",
    "+-----END RSA PRIVATE KEY-----",
  ].join("\n");
  const findings = parseLogPatch(patch, defaultConfig);
  assert.ok(
    findings.find((f) => f.ruleId === "private-key-block"),
    "a PEM block split across added lines must still be detected"
  );
});

test("skips files excluded by config", () => {
  const patch = [
    commitHeader("eee555"),
    "+++ b/node_modules/pkg/index.js",
    "@@ -0,0 +1,1 @@",
    '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, defaultConfig).length, 0);
});

test("respects a user-configured exclude path", () => {
  const config = mergeConfig({ excludePaths: ["testdata/**"] });
  const patch = [
    commitHeader("fff666"),
    "+++ b/testdata/keys.js",
    "@@ -0,0 +1,1 @@",
    '+const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, config).length, 0);
});

test("handles a deleted file (+++ /dev/null) without crashing", () => {
  const patch = [
    commitHeader("ggg777"),
    "+++ /dev/null",
    "@@ -1,1 +0,0 @@",
    '-const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";',
  ].join("\n");
  assert.strictEqual(parseLogPatch(patch, defaultConfig).length, 0);
});

// A `+++` line INSIDE a hunk is added content, not a file header. `git log -p`
// renders an added line as "+" followed by its content, so a committed patch
// file whose body is combined-diff output (`git diff --cc` — any merge patch)
// puts lines beginning "++ " into the hunk, and they arrive here as "+++ ".
// The diff grammar has no `+++` header inside a hunk: git emits `diff --git`
// before every real one, so position is what tells them apart.
test("a +++ line inside a hunk is scanned as added content, not read as a header", () => {
  const patch = [
    commitHeader("hhh888", "commit a merge patch"),
    "diff --git a/merge.patch b/merge.patch",
    "--- /dev/null",
    "+++ b/merge.patch",
    "@@ -0,0 +1,7 @@",
    "+diff --cc app.js",
    "+index 1111111..2222222 3333333",
    "+--- a/app.js",
    "++++ b/app.js",
    "+@@@ -1,1 -1,1 +1,2 @@@",
    "+++ const flag = true;",
    `+++ const token = "${TOKEN}";`,
  ].join("\n");

  const hits = parseLogPatch(patch, defaultConfig).filter((f) => f.ruleId === "github-token");
  assert.strictEqual(hits.length, 1, "the hunk after a +++ line must still be scanned");
  assert.strictEqual(hits[0].file, "merge.patch", "the hunk still belongs to merge.patch");
  assert.strictEqual(hits[0].line, 7, "and the added line it sits on is line 7");
});

test("added lines after a +++ line keep the right file and line number", () => {
  // A fix that restores detection but leaves attribution wrong is still a
  // verdict the check did not earn: it breaks the report, editor navigation,
  // and the file:rule:value dedup key.
  const patch = [
    commitHeader("iii999", "commit a merge patch"),
    "+++ b/merge.patch",
    "@@ -0,0 +1,2 @@",
    "+++ const flag = true;",
    `+const token = "${TOKEN}";`,
  ].join("\n");

  const hits = parseLogPatch(patch, defaultConfig).filter((f) => f.ruleId === "github-token");
  assert.strictEqual(hits.length, 1, "the added line after a +++ line must be scanned");
  assert.strictEqual(hits[0].file, "merge.patch", "not the text of the +++ line");
  assert.strictEqual(hits[0].line, 2, "the +++ line still consumed one added line");
});

test("counts commits scanned via the progress callback", () => {
  const patch = [commitHeader("h1"), commitHeader("h2"), commitHeader("h3")].join("\n");
  let last = 0;
  parseLogPatch(patch, defaultConfig, (n) => (last = n));
  assert.strictEqual(last, 3);
});

test("empty patch yields no findings", () => {
  assert.strictEqual(parseLogPatch("", defaultConfig).length, 0);
});

suite("\nhistory.ts — streaming a real repository");

function withRepo(fn: (dir: string, git: (...a: string[]) => void) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-hist-"));
  const git = (...args: string[]) => {
    const res = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    if (res.status !== 0) throw new Error(`git ${args.join(" ")}: ${res.stderr}`);
  };
  git("init", "-q");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  return fn(dir, git).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

test("finds a secret that was committed and later deleted", async () => {
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "app.js"), `const t = "${TOKEN}";\n`);
    git("add", "app.js");
    git("commit", "-qm", "add token");
    rmSync(path.join(dir, "app.js"));
    git("add", "-A");
    git("commit", "-qm", "remove it");

    const findings = await scanHistory({ config: mergeConfig({}), repoRoot: dir });
    assert.ok(
      findings.some((f) => f.ruleId === "github-token"),
      "a clean working tree says nothing about what is in the object store"
    );
  });
});

test("a committed merge patch does not hide the secret after its +++ line", async () => {
  // The same defect at the layer the user sees: git renders every "++ " line
  // of the committed patch as "+++ ", and the scan reported the repository
  // clean while this token sat in the object store.
  await withRepo(async (dir, git) => {
    writeFileSync(
      path.join(dir, "merge.patch"),
      [
        "diff --cc app.js",
        "index 1111111..2222222 3333333",
        "--- a/app.js",
        "+++ b/app.js",
        "@@@ -1,1 -1,1 +1,2 @@@",
        "++ const flag = true;",
        `++ const token = "${TOKEN}";`,
        "",
      ].join("\n")
    );
    git("add", "merge.patch");
    git("commit", "-qm", "add merge patch");

    const findings = await scanHistory({ config: mergeConfig({}), repoRoot: dir });
    const hits = findings.filter((f) => f.ruleId === "github-token");
    assert.strictEqual(hits.length, 1, "a repository carrying this token must not scan clean");
    assert.strictEqual(hits[0].file, "merge.patch");
    assert.strictEqual(hits[0].line, 7);
  });
});

test("progress is reported while the scan runs, not after", async () => {
  await withRepo(async (dir, git) => {
    for (let i = 0; i < 5; i++) {
      writeFileSync(path.join(dir, `f${i}.js`), `const v = ${i};\n`);
      git("add", "-A");
      git("commit", "-qm", `commit ${i}`);
    }
    const seen: number[] = [];
    await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      onProgress: (commits) => seen.push(commits),
    });
    assert.ok(seen.length >= 5, `expected progress per commit, saw ${seen.length}`);
    assert.deepStrictEqual(seen, [...seen].sort((a, b) => a - b), "and monotonically");
  });
});

test("the scan is asynchronous", async () => {
  // It ran through spawnSync, blocking the extension host for the whole scan
  // while a withProgress notification sat there never updating.
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "app.js"), "const v = 1;\n");
    git("add", "-A");
    git("commit", "-qm", "seed");
    const pending = scanHistory({ config: mergeConfig({}), repoRoot: dir });
    assert.ok(pending instanceof Promise, "a synchronous scan cannot be cancelled or yield");
    await pending;
  });
});

test("an already-aborted scan consumes nothing", async () => {
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "app.js"), `const t = "${TOKEN}";\n`);
    git("add", "app.js");
    git("commit", "-qm", "add token");

    const controller = new AbortController();
    controller.abort();
    let commits = 0;
    const findings = await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      signal: controller.signal,
      onProgress: (n) => (commits = n),
    });
    assert.strictEqual(commits, 0, "an aborted scan must not read the history anyway");
    assert.deepStrictEqual(findings, []);
  });
});

/**
 * A history large enough that `git log -p` cannot be delivered in one chunk:
 * ~126 kB over 40 commits, against a 64 kB pipe. The newest commit carries the
 * credential, so it is the first one parsed and lands before the abort.
 */
function buildCancelFixture(git: (...a: string[]) => void, dir: string): void {
  for (let i = 0; i < 40; i++) {
    writeFileSync(path.join(dir, `f${i}.js`), `const v = ${i};\n`.repeat(200));
    git("add", "-A");
    git("commit", "-qm", `commit ${i}`);
  }
  writeFileSync(path.join(dir, "leak.js"), `const t = "${TOKEN}";\n`);
  git("add", "-A");
  git("commit", "-qm", "the newest commit, parsed first");
}

test("cancelling stops progress at the abort point, exactly", async () => {
  // The old assertion was `reached < 40`, which is a proxy for "SIGTERM
  // truncated git's output" and holds only when the kill wins a race against
  // git writing the rest. Whenever git finished first the parser reached all
  // 40 and the test failed, which is what CI saw once. Cancellation's promise
  // is that the scan stops, so that is what is asserted here — exactly.
  await withRepo(async (dir, git) => {
    buildCancelFixture(git, dir);
    const controller = new AbortController();
    let calls = 0;
    let reached = 0;
    let afterAbort = 0;
    await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      signal: controller.signal,
      onProgress: (commits) => {
        calls++;
        reached = commits;
        if (controller.signal.aborted) afterAbort++;
        if (commits >= 2 && !controller.signal.aborted) controller.abort();
      },
    });
    assert.ok(controller.signal.aborted, "the fixture never triggered the abort it is testing");
    assert.strictEqual(reached, 2, `expected to stop at the abort point, reached ${reached}`);
    assert.strictEqual(calls, 2, `expected exactly two progress callbacks, saw ${calls}`);
    assert.strictEqual(afterAbort, 0, `${afterAbort} progress callback(s) fired after abort`);
  });
});

test("neither the rest of the delivered chunk nor later chunks resume parsing", async () => {
  // The abort fires inside the per-line loop of one chunk, and more chunks
  // follow it. Both paths must stop: the control below proves the scan really
  // does have 41 commits to deliver when it is not cancelled.
  await withRepo(async (dir, git) => {
    buildCancelFixture(git, dir);
    const full = await scanHistory({ config: mergeConfig({}), repoRoot: dir });
    let fullCommits = 0;
    await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      onProgress: (commits) => (fullCommits = commits),
    });
    assert.strictEqual(fullCommits, 41, `control: the uncancelled scan should see 41 commits, saw ${fullCommits}`);

    const controller = new AbortController();
    let reached = 0;
    const partial = await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      signal: controller.signal,
      onProgress: (commits) => {
        reached = commits;
        if (commits >= 2 && !controller.signal.aborted) controller.abort();
      },
    });
    assert.strictEqual(reached, 2, `parsing continued past the abort: reached ${reached} of 41`);
    // The partial result is a sub-multiset of the full one, compared as whole
    // objects rather than by count or by fingerprint alone.
    const remaining = new Map<string, number>();
    for (const f of full) {
      const k = JSON.stringify(f);
      remaining.set(k, (remaining.get(k) ?? 0) + 1);
    }
    for (const f of partial) {
      const k = JSON.stringify(f);
      const n = remaining.get(k) ?? 0;
      assert.ok(n > 0, `a cancelled scan invented a finding absent from the full scan: ${f.ruleId}`);
      remaining.set(k, n - 1);
    }
  });
});

test("a finding parsed before the abort survives in the partial result", async () => {
  await withRepo(async (dir, git) => {
    buildCancelFixture(git, dir);
    const controller = new AbortController();
    const partial = await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      signal: controller.signal,
      onProgress: (commits) => {
        if (commits >= 2 && !controller.signal.aborted) controller.abort();
      },
    });
    assert.ok(
      partial.some((f) => f.value === TOKEN),
      "cancelling discarded a finding the scan had already parsed"
    );
  });
});

/**
 * Delivery-controlled cancellation.
 *
 * The real-git tests above prove the observable contract but cannot control how
 * git's output is chunked, so they cannot show *which* guard stopped the scan.
 * This one drives the same production code with delivery pinned: one chunk that
 * continues past the abort point, a second chunk delivered afterwards, and a
 * trailing partial line left in the carry.
 *
 * `spawn` is a named import in history.ts, so the call reads the property from
 * the module object each time; replacing it here needs no seam in the source and
 * adds nothing to the public API. It is restored in `finally`.
 */
function fakeGit(killed: string[]): { child: any; deliver: (chunk: string) => void; close: () => void } {
  const { EventEmitter } = require("events") as typeof import("events");
  const child: any = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stdout.setEncoding = () => undefined;
  child.stderr = new EventEmitter();
  child.stderr.setEncoding = () => undefined;
  child.kill = (signal: string) => {
    killed.push(signal);
    return true;
  };
  return {
    child,
    deliver: (chunk: string) => child.stdout.emit("data", chunk),
    close: () => child.emit("close", null, "SIGTERM"),
  };
}

/** A distinct, correctly shaped token per commit; built here, never a stored literal. */
const tokenN = (n: number) => `ghp_${"0123456789abcdefghijklmnopqrstuvwxyzA".slice(0, 35)}${n}`;

test("cancelling stops the rest of the delivered chunk, later chunks and the carry", async () => {
  const cp = require("child_process") as typeof import("child_process");
  const realSpawn = cp.spawn;
  const killed: string[] = [];
  const fake = fakeGit(killed);
  (cp as { spawn: unknown }).spawn = () => fake.child;
  try {
    await withRepo(async (dir) => {
      const hunk = (file: string, value: string) =>
        [
          `diff --git a/${file} b/${file}`,
          "--- /dev/null",
          `+++ b/${file}`,
          "@@ -0,0 +1,1 @@",
          `+const t = "${value}";`,
        ].join("\n");

      // One chunk that keeps going after the abort: commit 2's header triggers
      // it, and commits 3-6 follow in the same delivery.
      const chunk1 =
        [
          commitHeader("c1".padEnd(12, "0"), "first"),
          hunk("first.js", tokenN(1)),
          commitHeader("c2".padEnd(12, "0"), "second"),
          hunk("second.js", tokenN(2)),
          commitHeader("c3".padEnd(12, "0"), "third"),
          hunk("third.js", tokenN(3)),
          commitHeader("c4".padEnd(12, "0"), "fourth"),
          hunk("fourth.js", tokenN(4)),
        ].join("\n") + `\n+const carried = "${tokenN(9)}";`; // no trailing newline: this stays in carry
      const chunk2 =
        [commitHeader("c5".padEnd(12, "0"), "fifth"), hunk("fifth.js", tokenN(5))].join("\n") + "\n";

      const controller = new AbortController();
      let calls = 0;
      const pending = scanHistory({
        config: mergeConfig({}),
        repoRoot: dir,
        signal: controller.signal,
        onProgress: (commits) => {
          calls++;
          if (commits >= 2 && !controller.signal.aborted) controller.abort();
        },
      });
      // Handlers are attached synchronously after spawn; deliver on the next tick.
      await new Promise((r) => setImmediate(r));
      fake.deliver(chunk1);
      fake.deliver(chunk2);
      fake.close();
      const findings = await pending;
      const values = findings.map((f) => f.value);

      assert.ok(controller.signal.aborted, "the fixture never aborted");
      assert.strictEqual(calls, 2, `expected exactly two progress callbacks, saw ${calls}`);
      assert.ok(values.includes(tokenN(1)), "a finding parsed before the abort was discarded");
      // The rest of the chunk the abort landed in.
      for (const n of [3, 4]) {
        assert.ok(!values.includes(tokenN(n)), `commit ${n} was parsed after the abort, from the same chunk`);
      }
      // A chunk delivered after cancellation.
      assert.ok(!values.includes(tokenN(5)), "a chunk delivered after the abort was parsed");
      // The trailing partial line: the carry must not be parsed at close either.
      assert.ok(!values.includes(tokenN(9)), "the carried partial line was parsed after cancellation");
      assert.deepStrictEqual(killed, ["SIGTERM"], `expected one SIGTERM, saw ${JSON.stringify(killed)}`);
    });
  } finally {
    (cp as { spawn: unknown }).spawn = realSpawn;
  }
});

test("cancelling removes the abort listener it registered", async () => {
  const { getEventListeners } = require("events") as typeof import("events");
  await withRepo(async (dir, git) => {
    buildCancelFixture(git, dir);
    const controller = new AbortController();
    await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      signal: controller.signal,
      onProgress: (commits) => {
        if (commits >= 2 && !controller.signal.aborted) controller.abort();
      },
    });
    assert.strictEqual(
      getEventListeners(controller.signal, "abort").length,
      0,
      "the abort listener outlived the scan"
    );
  });
});

test("a failure with no stderr names what happened", () => {
  // Exceeding maxBuffer returned status null, SIGTERM and an EMPTY stderr, so
  // the message was literally "git log failed: unknown error" for the most
  // likely large-repo failure there is.
  const killed = describeGitFailure(null, "SIGTERM", "");
  assert.doesNotMatch(killed, /unknown error/);
  assert.match(killed, /SIGTERM/, "name the signal that actually ended it");

  const exited = describeGitFailure(129, null, "");
  assert.doesNotMatch(exited, /unknown error/);
  assert.match(exited, /129/, "name the status it actually exited with");
});

test("a failure with stderr reports what git said", () => {
  const message = describeGitFailure(128, null, "fatal: bad revision 'nope..alsonope'\n");
  assert.match(message, /bad revision/);
});

test("a scan of a directory that is not a repository rejects", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-nogit-hist-"));
  try {
    let rejected = false;
    try {
      await scanHistory({ config: mergeConfig({}), repoRoot: dir });
    } catch {
      rejected = true;
    }
    assert.strictEqual(rejected, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("maxCommits still bounds the scan", async () => {
  await withRepo(async (dir, git) => {
    for (let i = 0; i < 4; i++) {
      writeFileSync(path.join(dir, `f${i}.js`), `const v = ${i};\n`);
      git("add", "-A");
      git("commit", "-qm", `commit ${i}`);
    }
    let commits = 0;
    await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      maxCommits: 2,
      onProgress: (n) => (commits = n),
    });
    assert.strictEqual(commits, 2);
  });
});

suite("\nhistory.ts — a throw while reading git output");

test("a parser failure rejects the promise instead of killing the process", async () => {
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "app.js"), `const t = "${TOKEN}";\n`);
    git("add", "app.js");
    git("commit", "-qm", "add token");

    // scanText compiles config.allowValues on every call, so an invalid pattern
    // throws from inside the stdout "data" handler. Nothing about this test is
    // specific to that route: an exception thrown while consuming a child
    // process's stdout escapes the Promise executor entirely, so it becomes an
    // uncaught exception and the promise never settles. Any future throw in the
    // parser does the same thing.
    const broken = { ...mergeConfig({}), allowValues: ["[unclosed"] };

    await assert.rejects(
      () => scanHistory({ config: broken, repoRoot: dir }),
      (err: Error) => {
        assert.match(err.message, /history scan/i, "the error should name what failed");
        assert.match(err.message, /unterminated character class/i, "and carry the underlying cause");
        return true;
      }
    );
  });
});

test("the git process is killed when the parser throws", async () => {
  await withRepo(async (dir, git) => {
    for (let i = 0; i < 3; i++) {
      writeFileSync(path.join(dir, `f${i}.js`), `const t = "${TOKEN}${i}";\n`);
      git("add", "-A");
      git("commit", "-qm", `commit ${i}`);
    }
    const broken = { ...mergeConfig({}), allowValues: ["[unclosed"] };
    const before = childCount();
    await scanHistory({ config: broken, repoRoot: dir }).catch(() => undefined);
    // A rejected scan that leaves git reading pack files is the leak the signal
    // handling exists to prevent; the same must hold when the parser is what
    // failed.
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(
      childCount() <= before,
      "git should not still be running after the scan rejected"
    );
  });
});

function childCount(): number {
  const res = spawnSync("bash", ["-c", "pgrep -f 'git log -p' | wc -l"], { encoding: "utf8" });
  return Number(res.stdout.trim()) || 0;
}

suite("\nhistory.ts — revRange never becomes a git option");

/**
 * `revRange` is pushed into `git log`'s argv as its own element.
 *
 * spawn is called with an array and no shell, so there is nothing to inject a
 * command into -- and that is not enough, because git parses its own arguments
 * and `git log --output=<path>` writes a file. The CLI happens to be covered
 * already: parseArgs refuses a flag-shaped value for every option, a rule added
 * so `--format --verify` would stop swallowing the next flag. That is a
 * usability fix standing in for a security guard, one edit away from not being
 * one, and it protects exactly one caller.
 *
 * The guard belongs here, at the shared spawn site, so a caller that does not
 * go through parseArgs is covered by the same code.
 */

const CLI_BIN = path.join(__dirname, "..", "out", "cli.js");

/** Records every git argv this process produces, without preventing it. */
function watchingSpawns<T>(body: () => T): { argvs: string[][]; value: T } {
  const cp = require("child_process");
  const realSpawn = cp.spawn;
  const realSpawnSync = cp.spawnSync;
  const argvs: string[][] = [];
  cp.spawn = (...a: any[]) => (argvs.push(a[1] ?? []), realSpawn(...a));
  cp.spawnSync = (...a: any[]) => (argvs.push(a[1] ?? []), realSpawnSync(...a));
  try {
    return { argvs, value: body() };
  } finally {
    cp.spawn = realSpawn;
    cp.spawnSync = realSpawnSync;
  }
}

const HOSTILE: Array<[string, unknown]> = [
  ["writes a file", "--output=/tmp/secretloop-revrange-should-not-exist"],
  ["short option", "-n999999"],
  ["upload-pack", "--upload-pack=/bin/sh"],
  ["exec", "--exec=/bin/sh"],
  ["bare separator", "--"],
  ["shell metacharacters", "main..HEAD; rm -rf /"],
  ["command substitution", "HEAD..$(id)"],
  ["pathspec magic", ":(literal)secrets"],
  ["rev:path", "HEAD:.env"],
  ["an embedded space", "main..HEAD --all"],
  ["a newline", "main..HEAD\n--output=/tmp/x"],
  ["a glob", "refs/heads/*"],
  ["empty", ""],
  ["not a string", 42],
];

test("every option-shaped range is refused before git starts", async () => {
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    git("add", "app.js");
    git("commit", "-qm", "one");

    for (const [label, value] of HOSTILE) {
      const { argvs, value: promise } = watchingSpawns(() =>
        scanHistory({ config: mergeConfig({}), repoRoot: dir, revRange: value as string })
      );
      let threw: unknown = null;
      try {
        await promise;
      } catch (err) {
        threw = err;
      }
      assert.ok(
        threw instanceof InvalidRevRangeError,
        `${label} was accepted: ${threw === null ? "no error" : String(threw)}`
      );
      // The assertion is on argv, not on "no process ran": callers legitimately
      // ask git for the repository root before this point, with arguments the
      // caller cannot influence.
      const reached = argvs.filter((a) => a.includes(String(value)) || a.includes("log"));
      assert.deepStrictEqual(reached, [], `${label} reached git's argv: ${JSON.stringify(argvs)}`);
    }
  });
});

test("the file git would have written does not exist", async () => {
  const target = "/tmp/secretloop-revrange-should-not-exist";
  rmSync(target, { force: true });
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    git("add", "app.js");
    git("commit", "-qm", "one");
    await scanHistory({
      config: mergeConfig({}),
      repoRoot: dir,
      revRange: `--output=${target}`,
    }).then(
      () => assert.ok(false, "the scan completed instead of refusing"),
      (err) => assert.ok(err instanceof InvalidRevRangeError)
    );
    // And that git really would have written it, so the guard is measured
    // against a live capability rather than a supposed one.
    spawnSync("git", ["log", "--oneline", `--output=${target}.proof`], { cwd: dir });
    assert.ok(
      existsSync(`${target}.proof`),
      "git no longer writes --output files; re-derive the guard's justification"
    );
    rmSync(`${target}.proof`, { force: true });
  });
  assert.ok(!existsSync(target), "the guard let git write a file");
});

test("the shapes real rev-ranges take are still accepted", async () => {
  for (const range of [
    "main..HEAD",
    "origin/main..HEAD",
    "HEAD~3",
    "HEAD~5..HEAD",
    "v1.0.0..v2.0.0",
    "refs/heads/topic",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "HEAD^..HEAD",
    "main...topic",
    "^main",
    "HEAD@{2}",
    "@{upstream}..HEAD",
    "my-branch_2..HEAD",
  ]) {
    assert.strictEqual(validateRevRange(range), null, `${range} is legitimate and was refused`);
  }
});

test("a valid range still reaches git and still scans", async () => {
  await withRepo(async (dir, git) => {
    // Three commits, the token in the middle one, so HEAD~2..HEAD is both a
    // real range and one that has to reach git for the token to be found.
    writeFileSync(path.join(dir, "base.js"), "const a = 1;\n");
    git("add", "base.js");
    git("commit", "-qm", "base");
    writeFileSync(path.join(dir, "app.js"), `const t = "${TOKEN}";\n`);
    git("add", "app.js");
    git("commit", "-qm", "add token");
    writeFileSync(path.join(dir, "b.js"), "const b = 2;\n");
    git("add", "b.js");
    git("commit", "-qm", "third");

    const { argvs, value: promise } = watchingSpawns(() =>
      scanHistory({ config: mergeConfig({}), repoRoot: dir, revRange: "HEAD~2..HEAD" })
    );
    const findings = await promise;
    assert.ok(
      argvs.some((a) => a.includes("HEAD~2..HEAD")),
      `the range never reached git's argv: ${JSON.stringify(argvs)}`
    );
    assert.ok(
      findings.some((f) => f.ruleId === "github-token"),
      "a valid range stopped finding what it used to find"
    );
  });
});

test("the CLI turns the refusal into exit 2 and names the flag", async () => {
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
    git("add", "app.js");
    git("commit", "-qm", "one");
    // A value the argument parser accepts -- it does not begin with "-" -- so
    // this exercises the spawn-site guard rather than parseArgs.
    const res = spawnSync(
      "node",
      [CLI_BIN, "history", "--path", dir, "--rev-range", "main..HEAD; rm -rf /"],
      { encoding: "utf8" }
    );
    assert.strictEqual(res.status, 2, `expected exit 2, got ${res.status}: ${res.stderr}`);
    assert.match(res.stderr, /--rev-range/, `the message does not name the flag: ${res.stderr}`);
    assert.strictEqual(res.stdout, "", "a refused scan printed a report");
  });
});

finish();
