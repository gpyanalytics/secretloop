// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import { calls, called, firstCall, reset } from "./stubs/vscode";
import { test, suite, finish, assert } from "./harness";

suite("tests/stubs — the vscode stub itself");

// These tests are deliberately synchronous. The stub records a call before it
// yields, so nothing here needs awaiting — and harness.ts takes `() => void`,
// so an async body would be counted as passing and its failure swallowed.
const vscode = require("./stubs/vscode");

test("a module that imports vscode resolves to the stub", () => {
  // Loading any extension-facing source is the whole point of the shim; if this
  // throws MODULE_NOT_FOUND the infrastructure is broken, not the source.
  const remediate = require("../src/remediate");
  assert.strictEqual(typeof remediate.redactInPlace, "function");
});

test("stubbed calls are recorded in order", () => {
  reset();
  void vscode.env.clipboard.writeText("SECRET");
  void vscode.window.showInformationMessage("hello");
  assert.deepStrictEqual(
    calls.map((c: { api: string }) => c.api),
    ["env.clipboard.writeText", "window.showInformationMessage"]
  );
});

test("call arguments are captured", () => {
  reset();
  void vscode.env.clipboard.writeText("SECRET");
  assert.deepStrictEqual(firstCall("env.clipboard.writeText"), ["SECRET"]);
});

test("called() reports whether an API was reached", () => {
  reset();
  assert.strictEqual(called("env.clipboard.writeText"), false, "nothing called yet");
  void vscode.env.clipboard.writeText("SECRET");
  assert.strictEqual(called("env.clipboard.writeText"), true);
});

test("reset clears recorded calls between tests", () => {
  void vscode.env.clipboard.writeText("SECRET");
  reset();
  assert.strictEqual(calls.length, 0);
});

finish();
