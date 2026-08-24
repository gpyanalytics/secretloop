// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import {
  decideVerificationPrompt,
  claimsStartupNotice,
  PromptState,
} from "../src/extension";
import { Finding } from "../src/scanner";
import { MigrationOutcome } from "../src/rotate";
import { test, suite, finish, assert } from "./harness";

function finding(ruleId: string): Finding {
  return {
    ruleId,
    description: ruleId === "github-token" ? "GitHub Personal Access Token" : ruleId,
    value: "x",
    startIndex: 0,
    endIndex: 1,
    confidence: "format-match",
    severity: "critical",
    line: 1,
  };
}

/** Nothing suppressing: a fresh session that has shown no notices. */
function freshState(overrides: Partial<PromptState> = {}): PromptState {
  return {
    startupNoticeShown: false,
    declinedThisSession: false,
    promptShown: false,
    declinedPermanently: false,
    ...overrides,
  };
}

suite("extension.ts — verification prompt gating");

test("a verifiable finding in a fresh session offers the prompt", () => {
  // The reported bug: a ghp_ token present, github-token verifiable, provider
  // named "GitHub", and no prompt ever appeared.
  const gate = decideVerificationPrompt([finding("github-token")], freshState());
  assert.strictEqual(gate.show, true, "nothing here should suppress the offer");
  assert.ok(gate.show && gate.provider === "GitHub");
  assert.ok(gate.show && gate.description === "GitHub Personal Access Token");
});

test("each suppression names itself", () => {
  // Every reason is logged, so a silent prompt is never again a mystery.
  const cases: Array<[Partial<PromptState>, string]> = [
    [{ startupNoticeShown: true }, "startup-notice-already-shown"],
    [{ declinedThisSession: true }, "declined-this-session"],
    [{ promptShown: true }, "already-prompted-this-session"],
    [{ declinedPermanently: true }, "declined-permanently"],
  ];
  for (const [state, reason] of cases) {
    const gate = decideVerificationPrompt([finding("github-token")], freshState(state));
    assert.strictEqual(gate.show, false, `${reason} must suppress`);
    assert.strictEqual(gate.show === false && gate.reason, reason);
  }
});

test("nothing verifiable is a named reason, not a silent return", () => {
  const gate = decideVerificationPrompt([finding("private-key-block")], freshState());
  assert.strictEqual(gate.show, false);
  assert.strictEqual(gate.show === false && gate.reason, "no-verifiable-finding");
});

test("no findings at all is a named reason", () => {
  const gate = decideVerificationPrompt([], freshState());
  assert.strictEqual(gate.show, false);
  assert.strictEqual(gate.show === false && gate.reason, "no-verifiable-finding");
});

test("the first verifiable finding is the one offered", () => {
  const gate = decideVerificationPrompt(
    [finding("private-key-block"), finding("github-token")],
    freshState()
  );
  assert.strictEqual(gate.show, true);
  assert.ok(gate.show && gate.provider === "GitHub");
});

suite("\nextension.ts — which migration outcomes claim the startup notice");

test("only a completed migration claims it", () => {
  // The suspected cause of the silent prompt was the absent branch claiming the
  // startup notice, which would suppress the offer for every user who never had
  // a credential in settings. It does not — pinned here so it cannot start to.
  const migrated: MigrationOutcome = {
    status: "migrated",
    moved: [{ key: "secretloop.awsAdminAccessKeyId", scope: "user" }],
  };
  assert.strictEqual(claimsStartupNotice(migrated), true, "it shows a warning, so it claims");
});

test("absent does not claim the startup notice", () => {
  const absent: MigrationOutcome = { status: "absent", inspected: ["a", "b", "c", "d"] };
  assert.strictEqual(
    claimsStartupNotice(absent),
    false,
    "the common case must not suppress the verification offer"
  );
});

test("already-stored does not claim the startup notice", () => {
  assert.strictEqual(claimsStartupNotice({ status: "already-stored" }), false);
});

finish();
