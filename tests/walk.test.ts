import { isTracked } from "../src/walk";
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

finish();
