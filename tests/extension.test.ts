// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import {
  decideVerificationPrompt,
  claimsStartupNotice,
  describePromptReset,
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

suite("\nextension.ts — resetting prompt preferences");

test("clearing a permanent decline says what was undone", () => {
  // Someone who clicked Never had no way back: nothing could clear globalState.
  const outcome = describePromptReset({ hadPermanentDecline: true, verificationEnabled: false });
  assert.strictEqual(outcome.clearedPermanent, true);
  assert.match(outcome.message, /never/i, "name the answer being undone");
  assert.match(outcome.message, /offer|prompt|ask/i);
});

test("with nothing to clear it says so rather than implying it undid something", () => {
  const outcome = describePromptReset({ hadPermanentDecline: false, verificationEnabled: false });
  assert.strictEqual(outcome.clearedPermanent, false);
  assert.match(outcome.message, /nothing|no .*(preference|decline)|was not/i);
});

test("when verification is already on, it says no prompt will appear", () => {
  // Resetting prompt state cannot produce a prompt there is nothing to ask for,
  // and silently doing nothing visible would read as the command failing.
  const outcome = describePromptReset({ hadPermanentDecline: true, verificationEnabled: true });
  assert.match(outcome.message, /already (on|enabled)/i);
});

test("the message never claims to have touched credentials or baselines", () => {
  // A command that resets more than its name implies is its own hazard.
  for (const verificationEnabled of [true, false]) {
    for (const hadPermanentDecline of [true, false]) {
      const { message } = describePromptReset({ hadPermanentDecline, verificationEnabled });
      // Word boundaries matter: a bare /secret/ matches "SecretLoop" itself.
      assert.doesNotMatch(
        message,
        /\bcredentials?\b|\bkeychain\b|\bsecrets?\b|\bbaselines?\b|\bfingerprints?\b/i,
        message
      );
    }
  }
});

finish();
