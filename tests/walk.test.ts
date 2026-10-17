import { isTracked, listFilesWithExclusions, getStagedFiles } from "../src/walk";
import { mergeConfig } from "../src/config";
import { unquoteGitPath } from "../src/history";
import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";

/** A throwaway git repo. Real git, because the answer depends on real index state. */
function withRepo(fn: (dir: string, git: (...args: string[]) => void) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-walk-test-"));
  const git = (...args: string[]) => {
    const res = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    if (res.status !== 0) throw new Error(`git ${args.join(" ")}: ${res.stderr}`);
  };
  try {
    git("init", "-q");
    git("config", "user.email", "test@example.com");
    git("config", "user.name", "test");
    fn(dir, git);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

suite("walk.ts — isTracked");

test("a committed file is tracked", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    git("add", ".env");
    git("commit", "-qm", "add env");
    assert.strictEqual(isTracked(dir, ".env"), "tracked");
  });
});

test("gitignoring a tracked file does not untrack it", () => {
  // The whole point: .gitignore has no effect on what git already tracks, so
  // adding the path to .gitignore leaves the secret being committed.
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    git("add", ".env");
    git("commit", "-qm", "add env");
    writeFileSync(path.join(dir, ".gitignore"), ".env\n");
    git("add", ".gitignore");
    git("commit", "-qm", "ignore env");
    assert.strictEqual(isTracked(dir, ".env"), "tracked");
  });
});

test("a file in a subdirectory is tracked", () => {
  // envFilePath is a setting; someone can point it at config/.env.
  withRepo((dir, git) => {
    mkdirSync(path.join(dir, "config"));
    writeFileSync(path.join(dir, "config", ".env"), "SECRET=1\n");
    git("add", "config/.env");
    git("commit", "-qm", "add nested env");
    assert.strictEqual(isTracked(dir, "config/.env"), "tracked");
  });
});

test("an untracked file is untracked", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, "seed.txt"), "x\n");
    git("add", "seed.txt");
    git("commit", "-qm", "seed");
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    assert.strictEqual(isTracked(dir, ".env"), "untracked");
  });
});

test("a path that does not exist is untracked, not an error", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, "seed.txt"), "x\n");
    git("add", "seed.txt");
    git("commit", "-qm", "seed");
    assert.strictEqual(isTracked(dir, "nowhere/.env"), "untracked");
  });
});

test("git rm --cached untracks it, so the remedy we recommend actually works", () => {
  // If this said "tracked" we would refuse to extract right after the user did
  // exactly what the error message told them to do.
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    git("add", ".env");
    git("commit", "-qm", "add env");
    git("rm", "-q", "--cached", ".env");
    assert.strictEqual(isTracked(dir, ".env"), "untracked");
  });
});

test("a file deleted from the worktree but still in the index is tracked", () => {
  // Not the same as a staged deletion. The index entry survives, so writing the
  // file back recreates something git still commits.
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    git("add", ".env");
    git("commit", "-qm", "add env");
    unlinkSync(path.join(dir, ".env"));
    assert.strictEqual(isTracked(dir, ".env"), "tracked");
  });
});

test("glob characters in the path are matched literally", () => {
  // envFilePath is user-supplied. Without :(literal), asking about the
  // untracked path env[X].env matches the tracked envX.env and reports
  // "tracked" for a file that is not there.
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, "envX.env"), "SECRET=1\n");
    git("add", "envX.env");
    git("commit", "-qm", "add env");
    assert.strictEqual(isTracked(dir, "env[X].env"), "untracked");
  });
});

test("outside a git repository the answer is unknown, not untracked", () => {
  // Unknown must not block, for the same reason unknown is not "dead" in the
  // liveness work: a check that could not run has proven nothing.
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-nogit-"));
  try {
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    assert.strictEqual(isTracked(dir, ".env"), "unknown");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

suite("\nwalk.ts — file names git quotes");

/*
 * git C-quotes a path it prints one per line when the path holds a byte it considers special: anything outside ASCII
 * (under the default core.quotePath), a double quote, a backslash, a tab. Read line by line, the quoted form —
 * `"caf\303\251.js"` — names no file, so the scan dropped it and counted it as "resolved outside the scan root",
 * and history filed its content under the quoted string. Windows forbids `"`, tab and `\` in a name, so there
 * only the non-ASCII case can exist.
 */
const QUOTED_NAMES = process.platform === "win32" ? ["café.js"] : ["café.js", 'quo"te.js', "back\\slash.js", "tab\tname.js"];
const ALL_NAMES = ["plain.js", ...QUOTED_NAMES].sort();
const QUOTED_LINE = () => "pass" + 'word = "Qm7vR2xKp9Lw4Tz8Hc3N"\n';
const WALK_CLI = path.join(__dirname, "..", "out", "cli.js");

function withQuotedRepo(fn: (dir: string, git: (...args: string[]) => void) => void): void {
  withRepo((dir, git) => {
    for (const n of ALL_NAMES) writeFileSync(path.join(dir, n), QUOTED_LINE(), "utf8");
    fn(dir, git);
  });
}

function cliJson(dir: string, ...args: string[]): { findings: Array<{ file: string }>; incomplete: boolean; summary: any } {
  const r = spawnSync("node", [WALK_CLI, ...args, "--format", "json", "--fail-on", "never"], { cwd: dir, encoding: "utf8" });
  assert.strictEqual(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}

const filesOf = (j: { findings: Array<{ file: string }> }) => [...new Set(j.findings.map((f) => f.file))].sort();

test("unquoteGitPath reads git's C quoting back to the real name", () => {
  assert.strictEqual(unquoteGitPath('"b/caf\\303\\251.js"'), "b/café.js");
  assert.strictEqual(unquoteGitPath('"b/quo\\"te.js"'), 'b/quo"te.js');
  assert.strictEqual(unquoteGitPath('"b/back\\\\slash.js"'), "b/back\\slash.js");
  assert.strictEqual(unquoteGitPath('"b/tab\\tname.js"'), "b/tab\tname.js");
  assert.strictEqual(unquoteGitPath("b/plain.js"), "b/plain.js", "an unquoted path is returned as it is");
  assert.strictEqual(unquoteGitPath('"b/\\a\\b\\f\\n\\r\\v"'), "b/\u0007\b\f\n\r\u000b");
});

test("the git-backed listing names every file, quoted or not, and excludes none", () => {
  withQuotedRepo((dir, git) => {
    git("add", "-A");
    const l = listFilesWithExclusions(dir, mergeConfig({}));
    assert.deepStrictEqual([...l.files].sort(), ALL_NAMES);
    assert.strictEqual(l.outsideExcluded, 0, "a quoted name was counted as outside the scan root");
  });
});

test("the staged list names every staged file, quoted or not", () => {
  withQuotedRepo((dir, git) => {
    git("add", "-A");
    const staged = getStagedFiles(dir);
    assert.ok("files" in staged, JSON.stringify(staged));
    assert.deepStrictEqual([...(staged as { files: string[] }).files].sort(), ALL_NAMES);
  });
});

test("the CLI scan and staged scan report quoted names and stay complete", () => {
  withQuotedRepo((dir, git) => {
    git("add", "-A");
    for (const cmd of [["staged"], ["scan", "."]]) {
      const j = cliJson(dir, ...cmd);
      assert.deepStrictEqual(filesOf(j), ALL_NAMES, `${cmd[0]} missed a quoted name`);
      assert.strictEqual(j.incomplete, false, `${cmd[0]}: ${JSON.stringify(j.summary.coverage?.limitations)}`);
    }
  });
});

test("a history scan files each finding under the real name, not git's quoted form", () => {
  withQuotedRepo((dir, git) => {
    git("add", "-A");
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "x");
    const j = cliJson(dir, "history");
    assert.deepStrictEqual(filesOf(j), ALL_NAMES, `history paths: ${JSON.stringify(filesOf(j))}`);
  });
});

finish();
