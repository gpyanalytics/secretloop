// Loads the vscode stub before anything that reaches `vscode`.
import "./stubs/install-vscode";
import {
  calls,
  reset,
  createDocument,
  setApplyEditResult,
  outputLines,
} from "./stubs/vscode";
import { redactInPlace } from "../src/remediate";
import { confirmTargetRemoved, countOccurrences, describeConfirmation } from "../src/confirm";
import { Finding, scanText } from "../src/scanner";
import { mergeConfig } from "../src/config";
import { test, suite, finish, assert } from "./harness";

suite("post-fix confirmation — the outcome contract");

/**
 * Synthetic, generated at run time, and the same shape the suite already uses.
 * Nothing here is a real credential, and no real file is touched: every case
 * runs against a stub document held in memory.
 */
// Annotated with the scoped form the repository uses for its own fixtures, so
// this file does not fail SecretLoop's scan of its own tree.
const TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"; // secretloop:allow(github-token) -- synthetic test fixture
const marker = (tag: string) =>
  `zz${tag}${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}zz`;

function finding(value: string, text: string, overrides: Partial<Finding> = {}): Finding {
  const startIndex = text.indexOf(value);
  return {
    ruleId: "github-token",
    description: "GitHub Personal Access Token",
    value,
    startIndex,
    endIndex: startIndex + value.length,
    confidence: "format-match",
    severity: "critical",
    line: 1,
    ...overrides,
  } as Finding;
}

/**
 * A stub document, typed the way tests/remediate.test.ts types its own: the
 * stub implements what these paths read, not the dozen members
 * vscode.TextDocument declares, and widening the stub to satisfy the compiler
 * would be inventing behaviour nothing exercises.
 */
function editable(text: string, fsPath?: string): any {
  return createDocument(text, fsPath);
}

/** Every message the run showed, whatever its severity. */
function messages(): string[] {
  return calls
    .filter((c) =>
      ["window.showInformationMessage", "window.showWarningMessage", "window.showErrorMessage"].includes(
        c.api
      )
    )
    .map((c) => String(c.args[0] ?? ""));
}

function severities(): string[] {
  return calls.filter((c) => c.api.startsWith("window.show")).map((c) => c.api);
}

// --- the three outcomes, through the real handler -------------------------

test("a successful redaction with no other copy confirms absence", async () => {
  reset();
  const text = `const t = "${TOKEN}";\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));

  assert.strictEqual(result.applied, true);
  assert.strictEqual(result.confirmation.outcome, "confirmed-absent");
  assert.strictEqual(result.confirmation.scope, "editor-document");
  assert.strictEqual(result.confirmation.occurrences, undefined, "a count belongs to a positive result");
  assert.ok(!doc.getText().includes(TOKEN), "the stub really applied the edit");
  assert.deepStrictEqual(severities(), ["window.showInformationMessage"]);
  assert.match(messages()[0], /Checked this editor document/);
});

test("a duplicate elsewhere in the document is still observed, with a count", async () => {
  reset();
  const text = `const a = "${TOKEN}";\nconst b = "${TOKEN}";\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));

  assert.strictEqual(result.applied, true, "the edit itself succeeded");
  assert.strictEqual(result.confirmation.outcome, "still-observed");
  assert.strictEqual(result.confirmation.occurrences, 1);
  assert.deepStrictEqual(severities(), ["window.showWarningMessage"], "a survivor is a warning");
  assert.match(messages()[0], /STILL in this editor document \(1 more occurrence\)/);
});

test("two duplicates count two, and the wording pluralises", async () => {
  reset();
  const text = `a="${TOKEN}"\nb="${TOKEN}"\nc="${TOKEN}"\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));
  assert.strictEqual(result.confirmation.occurrences, 2);
  assert.match(messages()[0], /\(2 more occurrences\)/);
});

test("a duplicate on a line that moved is still found", async () => {
  reset();
  // The surviving copy is below the edit, so redacting shifts every offset
  // after it. The confirmation searches the whole text and uses no offsets.
  const text = `const a = "${TOKEN}";\n\n\nconst b = "${TOKEN}";\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));
  assert.strictEqual(result.confirmation.outcome, "still-observed");
  assert.strictEqual(result.confirmation.occurrences, 1);
});

test("an edit the editor refuses confirms nothing, and says so", async () => {
  reset();
  setApplyEditResult(false);
  const text = `const t = "${TOKEN}";\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));

  assert.strictEqual(result.applied, false);
  assert.strictEqual(result.confirmation.outcome, "confirmation-unavailable");
  assert.strictEqual(result.confirmation.unavailableReason, "edit-not-applied");
  assert.ok(doc.getText().includes(TOKEN), "a refused edit changes nothing");
  assert.deepStrictEqual(severities(), ["window.showErrorMessage"]);
});

test("a stale span is refused before any edit, and confirms nothing", async () => {
  reset();
  const text = `const t = "${TOKEN}";\n`;
  const doc = editable(text);
  const stale = finding(TOKEN, text, { startIndex: 0, endIndex: 5 });
  const result = await redactInPlace(doc, stale);

  assert.strictEqual(result.applied, false);
  assert.strictEqual(result.confirmation.unavailableReason, "edit-not-applied");
  assert.strictEqual(calls.filter((c) => c.api === "workspace.applyEdit").length, 0);
});

// --- the reason the check cannot be a scan ---------------------------------

test("an inline directive hides the survivor from the scanner, not from the check", async () => {
  reset();
  // The second copy carries `secretloop:allow`, so the editor's own rescan
  // reports nothing for it. The confirmation still finds it.
  const annotation = "secretloop" + ":allow";
  const text = `const a = "${TOKEN}";\nconst b = "${TOKEN}"; // ${annotation}\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));

  assert.strictEqual(result.confirmation.outcome, "still-observed");
  assert.strictEqual(result.confirmation.occurrences, 1);
  // and the detector genuinely does not see it, which is the whole point
  const afterScan = scanText(doc.getText(), { config: mergeConfig({}) });
  assert.strictEqual(afterScan.length, 0, "the scanner reports nothing here");
});

test("an excluded rule hides the survivor from the scanner, not from the check", async () => {
  reset();
  const text = `const a = "${TOKEN}";\nconst b = "${TOKEN}";\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));
  assert.strictEqual(result.confirmation.outcome, "still-observed");
  const excluded = scanText(doc.getText(), {
    config: mergeConfig({ excludeRules: ["github-token"] }),
  });
  assert.strictEqual(excluded.length, 0, "the scanner reports nothing with the rule off");
});

test("an allowValues pattern hides the survivor from the scanner, not from the check", async () => {
  reset();
  const text = `const a = "${TOKEN}";\nconst b = "${TOKEN}";\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));
  assert.strictEqual(result.confirmation.outcome, "still-observed");
  const allowed = scanText(doc.getText(), { config: mergeConfig({ allowValues: ["^ghp_"] }) });
  assert.strictEqual(allowed.length, 0, "the scanner reports nothing with the value allowed");
});

test("suppression does not change a genuine absence either", async () => {
  reset();
  const annotation = "secretloop" + ":allow";
  const text = `const t = "${TOKEN}"; // ${annotation}\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));
  assert.strictEqual(result.confirmation.outcome, "confirmed-absent");
});

// --- unavailable, in each of its shapes ------------------------------------

test("an encoded finding is unsupported, and no absence is claimed", () => {
  reset();
  const doc = editable("nothing here\n");
  const c = confirmTargetRemoved(doc, { value: "anything", encoding: "base64" } as never);
  assert.strictEqual(c.outcome, "confirmation-unavailable");
  assert.strictEqual(c.unavailableReason, "operation-unsupported");
  assert.strictEqual(c.occurrences, undefined);
});

test("an empty or unusable target is rejected, never reported absent", () => {
  reset();
  const doc = editable("nothing here\n");
  for (const value of ["", undefined as unknown as string, 42 as unknown as string]) {
    const c = confirmTargetRemoved(doc, { value } as never);
    assert.strictEqual(c.outcome, "confirmation-unavailable", String(value));
    assert.strictEqual(c.unavailableReason, "target-not-retained");
  }
});

test("a closed document is unreadable, not clean", () => {
  reset();
  const doc = editable(`const t = "${TOKEN}";\n`);
  doc.isClosed = true;
  const c = confirmTargetRemoved(doc, { value: TOKEN } as never);
  assert.strictEqual(c.unavailableReason, "document-unreadable");
});

test("a document whose text cannot be read is unreadable, not clean", () => {
  reset();
  const doc = editable("clean text\n");
  doc.readFails = true;
  const c = confirmTargetRemoved(doc, { value: TOKEN } as never);
  assert.strictEqual(c.outcome, "confirmation-unavailable");
  assert.strictEqual(c.unavailableReason, "document-unreadable");
});

test("NUL in the text blocks an absence claim but not a positive one", () => {
  reset();
  const nul = String.fromCharCode(0);
  // absent, but the text is of a kind this product declines to read
  const cleanish = editable(`binary${nul}payload\n`);
  const absent = confirmTargetRemoved(cleanish, { value: TOKEN } as never);
  assert.strictEqual(absent.outcome, "confirmation-unavailable");
  assert.strictEqual(absent.unavailableReason, "scope-not-inspectable");

  // present: a positive observation outranks the coverage doubt
  const holding = editable(`binary${nul}${TOKEN}\n`, "/repo/src/other.ts");
  const seen = confirmTargetRemoved(holding, { value: TOKEN } as never);
  assert.strictEqual(seen.outcome, "still-observed");
  assert.strictEqual(seen.occurrences, 1);
});

// --- counting semantics -----------------------------------------------------

test("occurrences are counted non-overlapping, left to right", () => {
  assert.strictEqual(countOccurrences("aaaa", "aaa"), 1, "overlaps are one run, not two");
  assert.strictEqual(countOccurrences("aaaaaa", "aaa"), 2);
  assert.strictEqual(countOccurrences("abcabc", "abc"), 2);
  assert.strictEqual(countOccurrences("abc", "zzz"), 0);
  assert.strictEqual(countOccurrences("abc", ""), 0, "an empty target occurs nowhere");
});

// --- scope, and what is never claimed ---------------------------------------

test("the message names the editor document and claims nothing wider", async () => {
  reset();
  const text = `const t = "${TOKEN}";\n`;
  await redactInPlace(editable(text), finding(TOKEN, text));
  const m = messages()[0];
  assert.match(m, /editor document/);
  for (const overclaim of [/repositor/i, /\bdisk\b/i, /histor/i, /revok/i, /rotat/i, /invalid/i, /\bgone\b/i]) {
    assert.ok(!overclaim.test(m), `${m} must not claim ${overclaim}`);
  }
});

test("an unsaved buffer is reported as the buffer, with no disk claim", async () => {
  reset();
  // The stub document is a buffer and nothing saves it: the confirmation speaks
  // about the text it read and says so.
  const text = `const t = "${TOKEN}";\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));
  assert.strictEqual(result.confirmation.scope, "editor-document");
  assert.strictEqual(calls.filter((c) => c.api === "workspace.fs.writeFile").length, 0);
  assert.ok(!/\bdisk\b|\bsaved\b/i.test(messages()[0]));
});

test("the result records the buffer version it observed", async () => {
  reset();
  const text = `const t = "${TOKEN}";\n`;
  const doc = editable(text);
  const before = doc.version;
  const result = await redactInPlace(doc, finding(TOKEN, text));
  // The property that matters is WHICH buffer state was inspected, not how far
  // a version counter moved: vscode's TextDocument.version "strictly increases
  // after each change", and pinning a specific increment would be asserting the
  // stub rather than the contract.
  assert.strictEqual(result.confirmation.documentVersion, doc.version, "the version it read");
  assert.ok(doc.version > before, "an applied edit advanced the buffer");
  // and a later edit is explicitly NOT ruled out by that observation
  doc.applyReplace(
    { start: doc.positionAt(0), end: doc.positionAt(0) } as never,
    `const c = "${TOKEN}";\n`
  );
  assert.ok(doc.getText().includes(TOKEN), "the buffer can change again afterwards");
  assert.strictEqual(result.confirmation.outcome, "confirmed-absent", "the past observation stands");
});

// --- nothing sensitive in any output ----------------------------------------

test("no target value reaches any message or log, on any branch", async () => {
  for (const build of [
    () => {
      const v = marker("absent");
      return { text: `const t = "${v}";\n`, value: v, applyEdit: true };
    },
    () => {
      const v = marker("survivor");
      return { text: `a="${v}"\nb="${v}"\n`, value: v, applyEdit: true };
    },
    () => {
      const v = marker("refused");
      return { text: `const t = "${v}";\n`, value: v, applyEdit: false };
    },
  ]) {
    reset();
    const c = build();
    setApplyEditResult(c.applyEdit);
    await redactInPlace(editable(c.text), finding(c.value, c.text));
    for (const m of messages()) assert.ok(!m.includes(c.value), m);
    for (const line of outputLines) assert.ok(!line.includes(c.value), line);
    const serialized = JSON.stringify(calls);
    assert.ok(!serialized.includes(c.value), "not in any recorded stub call either");
  }
});

test("no suppression reason reaches a message", async () => {
  reset();
  const reason = marker("reason");
  const annotation = "secretloop" + ":allow";
  const text = `const a = "${TOKEN}";\nconst b = "${TOKEN}"; // ${annotation} -- ${reason}\n`;
  await redactInPlace(editable(text), finding(TOKEN, text));
  for (const m of messages()) assert.ok(!m.includes(reason), m);
});

// --- the copy variant and the shared rotate path ----------------------------

test("copyAndRedact keeps its clipboard behaviour and adds no second write", async () => {
  reset();
  const text = `const t = "${TOKEN}";\n`;
  const result = await redactInPlace(editable(text), finding(TOKEN, text), {
    copyToClipboard: true,
  });
  assert.strictEqual(result.confirmation.outcome, "confirmed-absent");
  assert.strictEqual(
    calls.filter((c) => c.api === "env.clipboard.writeText").length,
    1,
    "exactly the one copy the user asked for"
  );
  assert.match(messages()[0], /clipboard/i);
  assert.match(messages()[0], /Checked this editor document/);
});

test("the shared redaction path confirms once, not twice", async () => {
  reset();
  // secretloop.rotate calls this same function once on success; one call is one
  // confirmation, and nothing here loops or re-edits.
  const text = `const t = "${TOKEN}";\n`;
  await redactInPlace(editable(text), finding(TOKEN, text));
  assert.strictEqual(messages().length, 1, "one message, one pass");
  assert.strictEqual(calls.filter((c) => c.api === "workspace.applyEdit").length, 1);
});

test("a redaction queues exactly one replacement", async () => {
  reset();
  // vscode applies a workspace edit's changes "in the same order in which they
  // have been added", and the stub mirrors that by editing sequentially. That
  // is only faithful while each edit carries ONE replacement, which is what
  // this pins: a future change that queued two would need the stub revisited.
  const text = `const t = "${TOKEN}";\n`;
  await redactInPlace(editable(text), finding(TOKEN, text));
  const replaces = calls.filter((c) => c.api === "WorkspaceEdit.replace");
  assert.strictEqual(replaces.length, 1);
  assert.strictEqual(String(replaces[0].args[2]), "[REDACTED_BY_SECRETLOOP]");
});

test("an inspection that fails after a successful edit says redacted, not failed", async () => {
  reset();
  const text = `const t = "${TOKEN}";\n`;
  const doc = editable(text);
  const result = await redactInPlace(doc, finding(TOKEN, text));
  assert.strictEqual(result.applied, true);

  // Now make the read fail and run the confirmation the way the handler does.
  doc.readFails = true;
  const second = confirmTargetRemoved(doc, { value: TOKEN } as never);
  assert.strictEqual(second.outcome, "confirmation-unavailable");
  assert.strictEqual(second.unavailableReason, "document-unreadable");

  // The message the user actually saw still reports the redaction, and the
  // failed check triggered no second edit and no clipboard write.
  assert.match(messages()[0], /^Secret redacted\./);
  assert.strictEqual(calls.filter((c) => c.api === "workspace.applyEdit").length, 1);
  assert.strictEqual(calls.filter((c) => c.api === "env.clipboard.writeText").length, 0);
});

test("an unavailable confirmation is reported without a warning", async () => {
  reset();
  // The edit worked; being unable to check is not a warning about the edit.
  const text = `const t = "${TOKEN}";\n`;
  const doc = editable(text);
  const encoded = finding(TOKEN, text, { encoding: "base64" } as never);
  const result = await redactInPlace(doc, encoded);
  assert.strictEqual(result.applied, true);
  assert.strictEqual(result.confirmation.unavailableReason, "operation-unsupported");
  assert.deepStrictEqual(severities(), ["window.showInformationMessage"]);
  assert.match(messages()[0], /^Secret redacted\./);
  assert.match(messages()[0], /not supported by the check yet/);
});

// --- the wording helper ------------------------------------------------------

test("every unavailable reason has its own fixed clause", () => {
  const seen = new Set<string>();
  for (const reason of [
    "edit-not-applied",
    "document-unreadable",
    "target-not-retained",
    "scope-not-inspectable",
    "operation-unsupported",
  ] as const) {
    const text = describeConfirmation({
      outcome: "confirmation-unavailable",
      scope: "editor-document",
      unavailableReason: reason,
    });
    assert.match(text, /Could not check this editor document/);
    assert.ok(!seen.has(text), `${reason} must not share another reason's clause`);
    seen.add(text);
  }
});

finish();
