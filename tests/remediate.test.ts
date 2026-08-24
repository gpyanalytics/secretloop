// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import { calls, called, firstCall, reset } from "./stubs/vscode";
import { redactInPlace, extractToEnv } from "../src/remediate";
import { Finding } from "../src/scanner";
import * as assert from "node:assert";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { setWorkspaceFolder } from "./stubs/vscode";

// harness.ts takes `() => void` and would count an async body as passing while
// swallowing its failure, so this file carries its own awaiting harness — the
// same arrangement verify.test.ts uses.
let passed = 0;
let failed = 0;

async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    passed++;
    console.log(`  ok - ${name}`);
  } catch (err: any) {
    failed++;
    console.log(`  FAIL - ${name}`);
    console.log(`    ${err.message}`);
  }
}

function finding(): Finding {
  return {
    ruleId: "github-token",
    description: "GitHub Personal Access Token",
    value: "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    startIndex: 14,
    endIndex: 54,
    confidence: "format-match",
    severity: "critical",
    line: 1,
  };
}

/** The slice of TextDocument redactInPlace touches. */
function document(): any {
  return {
    uri: { fsPath: "/repo/src/app.ts", scheme: "file" },
    languageId: "typescript",
    positionAt: (offset: number) => ({ line: 0, character: offset }),
  };
}

async function main() {
  // Fail closed: a file that never reaches its summary must not report success.
  process.exitCode = 1;

  console.log("remediate.ts — redaction and the clipboard");

  await test("redacting does not put the secret on the clipboard", async () => {
    // The system clipboard is readable by every running application and syncs
    // across devices on macOS and Windows. Copying a live credential there is
    // not a side effect a "Redact this secret" action should have.
    reset();
    await redactInPlace(document(), finding());
    assert.strictEqual(
      called("env.clipboard.writeText"),
      false,
      "the default redact path must never touch the clipboard"
    );
  });

  await test("redacting still replaces the secret in the document", async () => {
    reset();
    await redactInPlace(document(), finding());
    const replace = firstCall("WorkspaceEdit.replace");
    assert.ok(replace, "the document edit must still happen");
    assert.strictEqual(replace![2], "[REDACTED_BY_SECRETLOOP]");
    assert.strictEqual(called("workspace.applyEdit"), true);
  });

  await test("the redact message does not claim a clipboard copy happened", async () => {
    reset();
    await redactInPlace(document(), finding());
    const message = String(firstCall("window.showInformationMessage")?.[0] ?? "");
    assert.doesNotMatch(
      message,
      /clipboard/i,
      "telling someone their secret is on the clipboard when it is not is worse than saying nothing"
    );
  });

  await test("copying is available, but only when explicitly asked for", async () => {
    reset();
    await redactInPlace(document(), finding(), { copyToClipboard: true });
    assert.strictEqual(called("env.clipboard.writeText"), true);
    assert.deepStrictEqual(firstCall("env.clipboard.writeText"), [
      "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    ]);
  });

  await test("the copy happens before the document is edited", async () => {
    // Reading the value out of the document after replacing it would return the
    // placeholder, so ordering here is correctness, not preference.
    reset();
    await redactInPlace(document(), finding(), { copyToClipboard: true });
    const copyAt = calls.findIndex((c) => c.api === "env.clipboard.writeText");
    const editAt = calls.findIndex((c) => c.api === "workspace.applyEdit");
    assert.ok(copyAt >= 0 && editAt >= 0);
    assert.ok(copyAt < editAt, "copy must precede the edit");
  });

  await test("the message says so when a copy did happen", async () => {
    reset();
    await redactInPlace(document(), finding(), { copyToClipboard: true });
    const message = String(firstCall("window.showInformationMessage")?.[0] ?? "");
    assert.match(message, /clipboard/i);
  });

  console.log("\nremediate.ts — extracting into a tracked .env");

  /** A throwaway git repo, with the stub reporting it as the open folder. */
  async function withRepo(fn: (dir: string, git: (...a: string[]) => void) => Promise<void>) {
    const dir = mkdtempSync(path.join(tmpdir(), "secretloop-remediate-test-"));
    const git = (...args: string[]) => {
      const res = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
      if (res.status !== 0) throw new Error(`git ${args.join(" ")}: ${res.stderr}`);
    };
    try {
      git("init", "-q");
      git("config", "user.email", "test@example.com");
      git("config", "user.name", "test");
      setWorkspaceFolder(dir);
      await fn(dir, git);
    } finally {
      setWorkspaceFolder(undefined);
      rmSync(dir, { recursive: true, force: true });
    }
  }

  await test("extracting into a git-tracked .env is refused", async () => {
    // gitignore does not untrack, so writing the secret here would commit it —
    // out of a file the developer is looking at, into one they believe is safe.
    await withRepo(async (dir, git) => {
      writeFileSync(path.join(dir, ".env"), "EXISTING=1\n");
      git("add", ".env");
      git("commit", "-qm", "track env");
      reset();

      await extractToEnv(document(), finding(), ".env");

      assert.ok(
        !readFileSync(path.join(dir, ".env"), "utf8").includes("ghp_"),
        "the secret must not reach a tracked file"
      );
      assert.strictEqual(called("workspace.applyEdit"), false, "and the source must be untouched");
      const message = String(firstCall("window.showErrorMessage")?.[0] ?? "");
      assert.match(message, /tracked/i);
      assert.match(message, /git rm --cached/, "the message must carry the exact remedy");
    });
  });

  await test("the refusal happens before anything is written", async () => {
    // The check costs nothing precisely because no write has happened yet, so
    // there is no partial state to unwind.
    await withRepo(async (dir, git) => {
      writeFileSync(path.join(dir, ".env"), "EXISTING=1\n");
      git("add", ".env");
      git("commit", "-qm", "track env");
      reset();

      await extractToEnv(document(), finding(), ".env");

      assert.strictEqual(called("workspace.fs.writeFile"), false, "no file may be written");
      assert.strictEqual(readFileSync(path.join(dir, ".env"), "utf8"), "EXISTING=1\n");
      assert.ok(!existsSync(path.join(dir, ".gitignore")), "and no .gitignore is created");
    });
  });

  await test("extracting into an untracked .env proceeds", async () => {
    await withRepo(async (dir, git) => {
      writeFileSync(path.join(dir, "seed.txt"), "x\n");
      git("add", "seed.txt");
      git("commit", "-qm", "seed");
      reset();

      await extractToEnv(document(), finding(), ".env");

      assert.match(readFileSync(path.join(dir, ".env"), "utf8"), /ghp_/, "the secret moves to .env");
      assert.strictEqual(called("workspace.applyEdit"), true, "and the source reference is replaced");
    });
  });

  await test("a tracked .env in a subdirectory is refused too", async () => {
    // envFilePath is a setting; config/.env must resolve the same way.
    await withRepo(async (dir, git) => {
      mkdirSync(path.join(dir, "config"));
      writeFileSync(path.join(dir, "config", ".env"), "EXISTING=1\n");
      git("add", "config/.env");
      git("commit", "-qm", "track nested env");
      reset();

      await extractToEnv(document(), finding(), "config/.env");

      assert.ok(!readFileSync(path.join(dir, "config", ".env"), "utf8").includes("ghp_"));
      assert.match(String(firstCall("window.showErrorMessage")?.[0] ?? ""), /config\/\.env/);
    });
  });

  await test("a folder that is not a git repo does not block extraction", async () => {
    // Unknown must not block, exactly as unknown is not "dead" in liveness.
    const dir = mkdtempSync(path.join(tmpdir(), "secretloop-nogit-remediate-"));
    try {
      setWorkspaceFolder(dir);
      reset();
      await extractToEnv(document(), finding(), ".env");
      assert.strictEqual(called("workspace.applyEdit"), true, "an unanswerable check must not refuse");
      assert.strictEqual(called("window.showErrorMessage"), false);
    } finally {
      setWorkspaceFolder(undefined);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exitCode = failed > 0 ? 1 : 0;
}

main();
