// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import { setConfiguration, resetConfiguration } from "./stubs/vscode";
import { setting, resolveSetting, describeOrigin } from "../src/settings";
import { test, suite, finish, assert } from "./harness";

suite("settings.ts — where a value came from");

test("a package default is reported as a default", () => {
  resetConfiguration();
  setConfiguration("secretloop", "enableLiveVerification", { defaultValue: false });
  const resolved = resolveSetting<boolean>("enableLiveVerification", false);
  assert.strictEqual(resolved.value, false);
  assert.strictEqual(resolved.origin.kind, "default");
});

test("an explicit user value wins over the package default, and says so", () => {
  // Exactly the case that took three rounds to find: a leftover user setting is
  // indistinguishable from a package default when only the value is reported.
  resetConfiguration();
  setConfiguration("secretloop", "enableLiveVerification", {
    defaultValue: false,
    globalValue: true,
  });
  const resolved = resolveSetting<boolean>("enableLiveVerification", false);
  assert.strictEqual(resolved.value, true, "the explicit value wins, which is correct");
  assert.strictEqual(resolved.origin.kind, "explicit");
  assert.strictEqual(resolved.origin.kind === "explicit" && resolved.origin.scope, "user");
  assert.strictEqual(resolved.origin.kind === "explicit" && resolved.origin.namespace, "secretloop");
});

test("the narrowest explicit scope wins and is named", () => {
  resetConfiguration();
  setConfiguration("secretloop", "entropyThreshold", {
    defaultValue: 4.3,
    globalValue: 5,
    workspaceValue: 6,
    workspaceFolderValue: 7,
  });
  const resolved = resolveSetting<number>("entropyThreshold", 4.3);
  assert.strictEqual(resolved.value, 7);
  assert.strictEqual(resolved.origin.kind === "explicit" && resolved.origin.scope, "workspace folder");
});

test("a workspace value is named when no folder value exists", () => {
  resetConfiguration();
  setConfiguration("secretloop", "entropyThreshold", { defaultValue: 4.3, workspaceValue: 6 });
  const resolved = resolveSetting<number>("entropyThreshold", 4.3);
  assert.strictEqual(resolved.value, 6);
  assert.strictEqual(resolved.origin.kind === "explicit" && resolved.origin.scope, "workspace");
});

test("a deprecated secretguard value names that namespace", () => {
  resetConfiguration();
  setConfiguration("secretloop", "enableLiveVerification", { defaultValue: false });
  setConfiguration("secretguard", "enableLiveVerification", { defaultValue: false, globalValue: true });
  const resolved = resolveSetting<boolean>("enableLiveVerification", false);
  assert.strictEqual(resolved.value, true);
  assert.strictEqual(resolved.origin.kind === "explicit" && resolved.origin.namespace, "secretguard");
});

test("an explicit false is still explicit, not a fallthrough", () => {
  // ?? must not treat a deliberate `false` as absent.
  resetConfiguration();
  setConfiguration("secretloop", "enableLiveVerification", { defaultValue: true, globalValue: false });
  const resolved = resolveSetting<boolean>("enableLiveVerification", true);
  assert.strictEqual(resolved.value, false);
  assert.strictEqual(resolved.origin.kind, "explicit");
});

test("describeOrigin reads as something a log line can carry", () => {
  const explicit = describeOrigin("enableLiveVerification", {
    kind: "explicit",
    namespace: "secretloop",
    scope: "user",
  });
  assert.match(explicit, /user/);
  assert.match(explicit, /secretloop\.enableLiveVerification/);
  assert.match(describeOrigin("entropyThreshold", { kind: "default" }), /default/i);
});

test("setting() still returns exactly what it always did", () => {
  resetConfiguration();
  setConfiguration("secretloop", "enableLiveVerification", { defaultValue: false, globalValue: true });
  assert.strictEqual(setting<boolean>("enableLiveVerification", false), true);
  resetConfiguration();
  setConfiguration("secretloop", "envFilePath", { defaultValue: ".env" });
  assert.strictEqual(setting<string>("envFilePath", ".env"), ".env");
});

finish();
