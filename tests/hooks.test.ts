// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import { called, calls, reset, setWorkspaceFolder } from "./stubs/vscode";
import { installPrecommitHook, refreshHookVersionStamp, hookBody } from "../src/hooks";
import * as assert from "node:assert";
import { test, suite, finish } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync, readFileSync, chmodSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";

/** The slice of ExtensionContext the installer reads. */
function context(extensionPath: string): any {
  mkdirSync(path.join(extensionPath, "out"), { recursive: true });
  // Stand-in for the bundled CLI; the installer only copies it.
  writeFileSync(
    path.join(extensionPath, "out", "cli.js"),
    '#!/usr/bin/env node\nconsole.log("[cli] scanned " + process.argv[2]);\nprocess.exit(Number(process.env.FAKE_CLI_EXIT || 0));\n'
  );
  return { extensionPath };
}

/** Runs the installed pre-commit hook the way git would. */
function runHook(dir: string, env: Record<string, string> = {}) {
  const res = spawnSync("sh", [path.join(dir, ".git", "hooks", "pre-commit")], {
    cwd: dir,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  return { status: res.status, output: `${res.stdout ?? ""}${res.stderr ?? ""}` };
}

async function withRepo(fn: (dir: string, git: (...a: string[]) => void) => Promise<void>) {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-hooks-test-"));
  const git = (...args: string[]) => {
    const res = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    if (res.status !== 0) throw new Error(`git ${args.join(" ")}: ${res.stderr}`);
  };
  try {
    git("init", "-q");
    git("config", "user.email", "test@example.com");
    git("config", "user.name", "test");
    mkdirSync(path.join(dir, ".git", "hooks"), { recursive: true });
    setWorkspaceFolder(dir);
    await fn(dir, git);
  } finally {
    setWorkspaceFolder(undefined);
    rmSync(dir, { recursive: true, force: true });
  }
}

function warningText(): string {
  const call = calls.find((c) => c.api === "window.showWarningMessage");
  return String(call?.args[0] ?? "");
}

suite("hooks.ts — installing the pre-commit hook");

test("installing warns when the env file is already tracked", async () => {
  // The hook scans staged changes, so a secret already committed to a tracked
  // .env never appears in one — the repo looks clean at every future commit.
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    git("add", ".env");
    git("commit", "-qm", "track env");
    reset();

    await installPrecommitHook(context(dir), ".env", "1.0.0");

    assert.strictEqual(called("window.showWarningMessage"), true, "the gap must be surfaced");
    assert.match(warningText(), /tracked/i);
    assert.match(warningText(), /git rm --cached \.env/);
  });
});

test("installing still succeeds — the warning does not block", async () => {
  // Installing a hook is not the moment a secret gets exposed, and the hook is
  // worth having either way.
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    git("add", ".env");
    git("commit", "-qm", "track env");
    reset();

    await installPrecommitHook(context(dir), ".env", "1.0.0");

    assert.strictEqual(called("workspace.fs.writeFile"), true, "the hook is still written");
    assert.strictEqual(called("window.showInformationMessage"), true, "and reported installed");
  });
});

test("no warning when the env file is untracked", async () => {
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "seed.txt"), "x\n");
    git("add", "seed.txt");
    git("commit", "-qm", "seed");
    writeFileSync(path.join(dir, ".env"), "SECRET=1\n");
    reset();

    await installPrecommitHook(context(dir), ".env", "1.0.0");

    assert.strictEqual(called("window.showWarningMessage"), false);
    assert.strictEqual(called("window.showInformationMessage"), true);
  });
});

test("a tracked env file in a subdirectory is warned about too", async () => {
  await withRepo(async (dir, git) => {
    mkdirSync(path.join(dir, "config"));
    writeFileSync(path.join(dir, "config", ".env"), "SECRET=1\n");
    git("add", "config/.env");
    git("commit", "-qm", "track nested env");
    reset();

    await installPrecommitHook(context(dir), "config/.env", "1.0.0");

    assert.strictEqual(called("window.showWarningMessage"), true);
    assert.match(warningText(), /config\/\.env/);
  });
});

suite("\nhooks.ts — the hook does not depend on the extension's install path");

test("the hook body embeds no versioned extension directory", () => {
  // It used to bake in .../publisher.secretloop-0.1.0/out/cli.js, a path that is
  // deleted by every extension update — after which every commit fails with
  // "Cannot find module" until someone works out why.
  const body = hookBody();
  assert.doesNotMatch(body, /secretloop-\d+\.\d+\.\d+/, "no version-stamped path");
  assert.doesNotMatch(body, /\.vscode/, "no extension directory at all");
  assert.match(body, /rev-parse --git-dir/, "the git dir is resolved at run time");
});

test("installing copies the CLI into the git dir and stamps its version", async () => {
  await withRepo(async (dir) => {
    const ext = mkdtempSync(path.join(tmpdir(), "secretloop-ext-"));
    try {
      await installPrecommitHook(context(ext), ".env", "9.9.9");
      assert.ok(existsSync(path.join(dir, ".git", "secretloop", "cli.js")), "CLI copied");
      assert.strictEqual(
        readFileSync(path.join(dir, ".git", "secretloop", "cli.version"), "utf8").trim(),
        "9.9.9"
      );
    } finally {
      rmSync(ext, { recursive: true, force: true });
    }
  });
});

test("the installed hook runs the copied CLI", async () => {
  await withRepo(async (dir) => {
    const ext = mkdtempSync(path.join(tmpdir(), "secretloop-ext-"));
    try {
      await installPrecommitHook(context(ext), ".env", "1.0.0");
      const run = runHook(dir);
      assert.match(run.output, /\[cli\] scanned staged/, "the scan must actually run");
      assert.strictEqual(run.status, 0);
    } finally {
      rmSync(ext, { recursive: true, force: true });
    }
  });
});

test("a failing scan still blocks the commit", async () => {
  await withRepo(async (dir) => {
    const ext = mkdtempSync(path.join(tmpdir(), "secretloop-ext-"));
    try {
      await installPrecommitHook(context(ext), ".env", "1.0.0");
      const run = runHook(dir, { FAKE_CLI_EXIT: "1" });
      assert.strictEqual(run.status, 1, "a found secret must fail the hook");
    } finally {
      rmSync(ext, { recursive: true, force: true });
    }
  });
});

test("a missing CLI fails open with a clear message, never blocking commits", async () => {
  // Failing closed here means our own tooling going missing blocks every commit
  // in the repo, which is solved with a permanent --no-verify habit.
  await withRepo(async (dir) => {
    const ext = mkdtempSync(path.join(tmpdir(), "secretloop-ext-"));
    try {
      await installPrecommitHook(context(ext), ".env", "1.0.0");
      unlinkSync(path.join(dir, ".git", "secretloop", "cli.js"));
      const run = runHook(dir);
      assert.strictEqual(run.status, 0, "must not block the commit");
      assert.match(run.output, /SecretLoop/);
      assert.match(run.output, /skipping/i, "and must say the scan did not happen");
    } finally {
      rmSync(ext, { recursive: true, force: true });
    }
  });
});

test("a stale copy warns but still scans", async () => {
  // Staleness you cannot see is the thing that bites; staleness you can see is
  // a prompt to re-run the install command.
  await withRepo(async (dir) => {
    const ext = mkdtempSync(path.join(tmpdir(), "secretloop-ext-"));
    try {
      await installPrecommitHook(context(ext), ".env", "1.0.0");
      refreshHookVersionStamp(dir, "2.0.0");
      const run = runHook(dir);
      assert.match(run.output, /1\.0\.0/, "names the copied version");
      assert.match(run.output, /2\.0\.0/, "and the installed one");
      assert.match(run.output, /\[cli\] scanned staged/, "a stale scan is better than none");
      assert.strictEqual(run.status, 0);
    } finally {
      rmSync(ext, { recursive: true, force: true });
    }
  });
});

test("matching versions produce no staleness warning", async () => {
  await withRepo(async (dir) => {
    const ext = mkdtempSync(path.join(tmpdir(), "secretloop-ext-"));
    try {
      await installPrecommitHook(context(ext), ".env", "1.0.0");
      refreshHookVersionStamp(dir, "1.0.0");
      const run = runHook(dir);
      assert.doesNotMatch(run.output, /out of date|stale/i);
    } finally {
      rmSync(ext, { recursive: true, force: true });
    }
  });
});

test("the version stamp is only refreshed where our hook is installed", () => {
  // Never create .git/secretloop in a repo that never asked for a hook.
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-nohook-"));
  try {
    mkdirSync(path.join(dir, ".git"), { recursive: true });
    refreshHookVersionStamp(dir, "1.0.0");
    assert.ok(!existsSync(path.join(dir, ".git", "secretloop")), "no directory is created");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

finish();
