// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import { called, calls, reset, setWorkspaceFolder } from "./stubs/vscode";
import { installPrecommitHook } from "../src/hooks";
import * as assert from "node:assert";
import { test, suite, finish } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";

/** The slice of ExtensionContext hookBody reads. */
function context(extensionPath: string): any {
  return { extensionPath };
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

    await installPrecommitHook(context(dir), ".env");

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

    await installPrecommitHook(context(dir), ".env");

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

    await installPrecommitHook(context(dir), ".env");

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

    await installPrecommitHook(context(dir), "config/.env");

    assert.strictEqual(called("window.showWarningMessage"), true);
    assert.match(warningText(), /config\/\.env/);
  });
});

finish();
