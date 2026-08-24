// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import { calls, called, firstCall, reset } from "./stubs/vscode";
import { redactInPlace } from "../src/remediate";
import { Finding } from "../src/scanner";
import * as assert from "node:assert";

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

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exitCode = failed > 0 ? 1 : 0;
}

main();
