// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import { calls, called, firstCall, reset } from "./stubs/vscode";
import { redactInPlace, extractToEnv } from "../src/remediate";
import { Finding } from "../src/scanner";
import * as assert from "node:assert";
import { test, suite, finish } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { setWorkspaceFolder, setApplyEditResult } from "./stubs/vscode";

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

const TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

/** Text in which finding()'s span, 14..54, really does hold the secret. */
const SOURCE = `const token ="${TOKEN}";`;

/**
 * The slice of TextDocument the remediations touch.
 *
 * getText is part of it now: a finding carries offsets from the scan that
 * produced it, and the only way to know they still mean anything is to look at
 * the document they will be applied to.
 */
function document(text: string = SOURCE): any {
  return {
    uri: { fsPath: "/repo/src/app.ts", scheme: "file" },
    languageId: "typescript",
    getText: () => text,
    positionAt: (offset: number) => ({ line: 0, character: offset }),
  };
}

suite("remediate.ts — redaction and the clipboard");

test("redacting does not put the secret on the clipboard", async () => {
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

test("redacting still replaces the secret in the document", async () => {
  reset();
  await redactInPlace(document(), finding());
  const replace = firstCall("WorkspaceEdit.replace");
  assert.ok(replace, "the document edit must still happen");
  assert.strictEqual(replace![2], "[REDACTED_BY_SECRETLOOP]");
  assert.strictEqual(called("workspace.applyEdit"), true);
});

test("the redact message does not claim a clipboard copy happened", async () => {
  reset();
  await redactInPlace(document(), finding());
  const message = String(firstCall("window.showInformationMessage")?.[0] ?? "");
  assert.doesNotMatch(
    message,
    /clipboard/i,
    "telling someone their secret is on the clipboard when it is not is worse than saying nothing"
  );
});

test("copying is available, but only when explicitly asked for", async () => {
  reset();
  await redactInPlace(document(), finding(), { copyToClipboard: true });
  assert.strictEqual(called("env.clipboard.writeText"), true);
  assert.deepStrictEqual(firstCall("env.clipboard.writeText"), [
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
  ]);
});

test("the copy happens before the document is edited", async () => {
  // Reading the value out of the document after replacing it would return the
  // placeholder, so ordering here is correctness, not preference.
  reset();
  await redactInPlace(document(), finding(), { copyToClipboard: true });
  const copyAt = calls.findIndex((c) => c.api === "env.clipboard.writeText");
  const editAt = calls.findIndex((c) => c.api === "workspace.applyEdit");
  assert.ok(copyAt >= 0 && editAt >= 0);
  assert.ok(copyAt < editAt, "copy must precede the edit");
});

test("the message says so when a copy did happen", async () => {
  reset();
  await redactInPlace(document(), finding(), { copyToClipboard: true });
  const message = String(firstCall("window.showInformationMessage")?.[0] ?? "");
  assert.match(message, /clipboard/i);
});

suite("\nremediate.ts — extracting into a tracked .env");

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

test("extracting into a git-tracked .env is refused", async () => {
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

test("the refusal happens before anything is written", async () => {
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

test("extracting into an untracked .env proceeds", async () => {
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

test("a tracked .env in a subdirectory is refused too", async () => {
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

test("a folder that is not a git repo does not block extraction", async () => {
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

suite("\nremediate.ts — an edit that did not happen is not a success");

// A finding's offsets come from the scan that produced it. The document can
// move underneath them: the 400ms scan debounce leaves a window where the
// lightbulb still carries pre-edit offsets, and positionAt clamps rather than
// throwing, so a stale span silently addresses the wrong characters.
const SHIFTED = `// a line added above\n${SOURCE}`;

test("redacting refuses when the span no longer holds the secret", async () => {
  reset();
  await redactInPlace(document(SHIFTED), finding());
  assert.strictEqual(
    called("workspace.applyEdit"),
    false,
    "a stale span addresses the wrong characters; nothing may be replaced"
  );
});

test("a refused redaction does not report a redaction", async () => {
  reset();
  await redactInPlace(document(SHIFTED), finding());
  const info = String(firstCall("window.showInformationMessage")?.[0] ?? "");
  assert.doesNotMatch(info, /redacted/i, "the secret is still in the file");
  const error = String(firstCall("window.showErrorMessage")?.[0] ?? "");
  assert.match(error, /scan/i, "and the user is told to re-scan");
});

test("a stale span is refused before the clipboard is touched", async () => {
  // Copy-then-redact copies first, so the secret would be on a syncing
  // clipboard for a redaction that was never going to happen.
  reset();
  await redactInPlace(document(SHIFTED), finding(), { copyToClipboard: true });
  assert.strictEqual(called("env.clipboard.writeText"), false);
});

test("an applyEdit that returns false is not reported as a redaction", async () => {
  // VS Code declines an edit to a read-only file, and the return value is the
  // only way to hear about it.
  reset();
  setApplyEditResult(false);
  await redactInPlace(document(), finding());
  const info = String(firstCall("window.showInformationMessage")?.[0] ?? "");
  assert.doesNotMatch(info, /redacted/i);
  assert.match(String(firstCall("window.showErrorMessage")?.[0] ?? ""), /not|could/i);
});

test("a failed copy-then-redact says the clipboard still holds the secret", async () => {
  reset();
  setApplyEditResult(false);
  await redactInPlace(document(), finding(), { copyToClipboard: true });
  assert.strictEqual(called("env.clipboard.writeText"), true, "the copy did happen");
  assert.match(
    String(firstCall("window.showErrorMessage")?.[0] ?? ""),
    /clipboard/i,
    "so the report must account for where the secret now is"
  );
});

suite("\nremediate.ts — .env is written only once the source edit lands");

test("a failed edit leaves nothing in .env", async () => {
  // The old order wrote .env first, so a declined edit put the credential in a
  // second file and announced "reference inserted".
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "seed.txt"), "x\n");
    git("add", "seed.txt");
    git("commit", "-qm", "seed");
    reset();
    setApplyEditResult(false);

    await extractToEnv(document(), finding(), ".env");

    const envPath = path.join(dir, ".env");
    assert.ok(
      !existsSync(envPath) || !readFileSync(envPath, "utf8").includes("ghp_"),
      "a secret must not be duplicated into .env by an extraction that failed"
    );
    const info = String(firstCall("window.showInformationMessage")?.[0] ?? "");
    assert.doesNotMatch(info, /moved to/i);
  });
});

test("a stale span refuses extraction before any write", async () => {
  await withRepo(async (dir, git) => {
    writeFileSync(path.join(dir, "seed.txt"), "x\n");
    git("add", "seed.txt");
    git("commit", "-qm", "seed");
    reset();

    await extractToEnv(document(SHIFTED), finding(), ".env");

    assert.strictEqual(called("workspace.applyEdit"), false);
    assert.ok(!existsSync(path.join(dir, ".env")), "no .env is created");
    assert.ok(!existsSync(path.join(dir, ".gitignore")), "and no .gitignore either");
  });
});

finish();
