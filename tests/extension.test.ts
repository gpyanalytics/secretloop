// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import {
  decideVerificationPrompt,
  claimsStartupNotice,
  describePromptReset,
  diagnosticMessage,
  severityForTier,
  offersRotation,
  rotateActionTitle,
  workspaceScanSummary,
  stagedScanNotice,
  PromptState,
} from "../src/extension";
import { Finding, UnknownReason } from "../src/scanner";
import { UNKNOWN_REASONS } from "../src/report";
import { MigrationOutcome } from "../src/rotate";
import { DiagnosticSeverity } from "./stubs/vscode";
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

suite("\nextension.ts — the editor carries the liveness verdict");

/**
 * The verdicts verify.ts actually emits, with the detail strings it writes.
 * Taken from a real run against stubbed provider responses rather than
 * invented, so the editor is tested against its true input.
 */
const LIVE_DETAIL = "Active GitHub token. Scopes: repo";
const DEAD_DETAIL = "GitHub token is invalid or already revoked.";

const UNKNOWN_DETAILS: Record<UnknownReason, string> = {
  network:
    "The check timed out before reaching the provider. Liveness could not be determined — " +
    "this is a connectivity problem, not a verdict on the credential.",
  "provider-refused":
    "GitHub refused the check (403), which it returns for a revoked credential and for a " +
    "live one lacking permission alike. Liveness could not be determined — check this " +
    "credential directly.",
  "provider-unavailable":
    "GitHub rate-limited the check (429). Liveness could not be determined; retry later.",
  "missing-pair":
    "No AWS secret access key found alongside this access key ID, and AWS cannot be asked " +
    "about one without the other. Liveness could not be determined.",
  // verify.ts never emits this reason: it is the bucket report.ts and cli.ts put
  // an unknown with no reason into, so the finding carries verifyReason undefined.
  "no-verifier": "",
};

const ALL_REASONS = Object.keys(UNKNOWN_REASONS) as UnknownReason[];

function base(): Finding {
  return {
    ruleId: "github-token",
    description: "GitHub Personal Access Token",
    value: "ghp_" + "a".repeat(36),
    startIndex: 0,
    endIndex: 40,
    confidence: "format-match",
    severity: "critical",
    line: 1,
  };
}

const liveFinding = (): Finding => ({
  ...base(),
  confidence: "verified-live",
  verifyStatus: "live",
  verifyDetail: LIVE_DETAIL,
});

const deadFinding = (): Finding => ({
  ...base(),
  verifyStatus: "dead",
  verifyDetail: DEAD_DETAIL,
});

const unknownFinding = (reason: UnknownReason): Finding => ({
  ...base(),
  verifyStatus: "unknown",
  // no-verifier is the default bucket, never a reason verify.ts writes down.
  verifyReason: reason === "no-verifier" ? undefined : reason,
  verifyDetail: UNKNOWN_DETAILS[reason] || undefined,
});

const neverVerified = (): Finding => base();

/** What the editor itself wrote, with verify.ts's own sentence taken back out. */
function authoredPart(f: Finding): string {
  const message = diagnosticMessage(f);
  return f.verifyDetail ? message.split(f.verifyDetail).join(" ") : message;
}

test("LIVE rendering is unchanged — this one is a no-change guard, not a red test", () => {
  const f = liveFinding();
  assert.match(diagnosticMessage(f), /LIVE secret confirmed/);
  assert.match(diagnosticMessage(f), /currently active/i);
  assert.strictEqual(severityForTier(f), DiagnosticSeverity.Error);
});

test("a never-verified finding still reads as unverified — also a no-change guard", () => {
  const f = neverVerified();
  assert.match(diagnosticMessage(f), /not yet verified/i);
  assert.strictEqual(severityForTier(f), DiagnosticSeverity.Warning);
});

test("a DEAD credential is not described as awaiting verification", () => {
  // It was verified. The check ran and came back negative. "not yet verified
  // live" describes a check that has not happened.
  const message = diagnosticMessage(deadFinding());
  assert.doesNotMatch(message, /not yet verified/i, message);
  assert.match(message, /no longer active|dead|revoked|inactive/i, message);
  assert.match(message, /still|remains|present/i, "and it is still sitting in the source");
});

test("a DEAD credential is quieter than an unchecked one, not equal to it", () => {
  assert.strictEqual(severityForTier(deadFinding()), DiagnosticSeverity.Information);
});

test("every UNKNOWN reason reaches the diagnostic, with its reason and its detail", () => {
  // The diagnostic message IS the hover in VS Code, and verify.ts documents
  // `detail` as "shown in the diagnostic hover". Nothing shows it today.
  for (const reason of ALL_REASONS) {
    const f = unknownFinding(reason);
    const message = diagnosticMessage(f);
    assert.match(
      message,
      /not determined|undetermined|could not determine|unknown/i,
      `${reason}: ${message}`
    );
    assert.ok(
      message.includes(UNKNOWN_REASONS[reason].label),
      `${reason}: must name the reason — expected "${UNKNOWN_REASONS[reason].label}" in: ${message}`
    );
    if (f.verifyDetail) {
      assert.ok(
        message.includes(f.verifyDetail),
        `${reason}: must carry the detail verify.ts wrote for the hover — got: ${message}`
      );
    }
  }
});

test("a refused check is raised to Error, matching what SARIF already gives it", () => {
  // report.ts sarifLevel: provider-refused is error regardless of severity,
  // because a 403 means the provider evaluated the credential and declined —
  // it leans live, and no retry resolves it.
  assert.strictEqual(
    severityForTier(unknownFinding("provider-refused")),
    DiagnosticSeverity.Error
  );
});

test("the other four UNKNOWN reasons stay at Warning", () => {
  for (const reason of ALL_REASONS.filter((r) => r !== "provider-refused")) {
    assert.strictEqual(
      severityForTier(unknownFinding(reason)),
      DiagnosticSeverity.Warning,
      `${reason} taught us nothing, so it is worth what its format was worth`
    );
  }
});

test("the rotate quick-fix follows the verdict, not the confidence tier", () => {
  assert.strictEqual(offersRotation(liveFinding()), true, "a live credential must offer revocation");
  assert.strictEqual(
    offersRotation(unknownFinding("provider-refused")),
    true,
    "a 403 leans live and no retry resolves it — someone has to open the provider console"
  );
  assert.strictEqual(offersRotation(deadFinding()), false, "there is nothing left to revoke");
  assert.strictEqual(offersRotation(neverVerified()), false, "no check ran, so claim nothing");
  for (const reason of ALL_REASONS.filter((r) => r !== "provider-refused")) {
    assert.strictEqual(
      offersRotation(unknownFinding(reason)),
      false,
      `${reason} says nothing about the credential`
    );
  }
});

test("the rotate quick-fix label does not claim a verdict the check did not earn", () => {
  // The label is a user-visible surface like any other. Offering rotation on a
  // refused check is right; calling that credential LIVE on the lightbulb is
  // the boolean's old sentence wearing a quick-fix label.
  assert.strictEqual(
    rotateActionTitle(liveFinding()),
    "SecretLoop: Rotate / revoke this LIVE credential",
    "the confirmed-live label is unchanged — this assertion is a no-change guard"
  );

  const refused = rotateActionTitle(unknownFinding("provider-refused"));
  assert.notStrictEqual(
    refused,
    rotateActionTitle(liveFinding()),
    "a refused check and a confirmed-live one must not read the same"
  );
  assert.doesNotMatch(refused, /confirmed/i, refused);
  // Case-SENSITIVE on purpose. The shouty all-caps LIVE is how this codebase
  // asserts a confirmed verdict; banning /live/i instead would outlaw honest
  // phrasing like "possibly live" — the same over-broad guard as the /secret/i
  // pattern that once matched "SecretLoop" itself.
  assert.doesNotMatch(refused, /\bLIVE\b/, refused);
  assert.match(
    refused,
    /inspect|possibly|may be|might be|could be|unconfirmed/i,
    `the label has to say what the verdict actually was — ${refused}`
  );
});

test("UNKNOWN is never worded like DEAD", () => {
  // The founding case: a boolean reported a 403 as "invalid or revoked", which
  // is the sentence someone reads when deciding NOT to rotate a live key. A fix
  // that renders UNKNOWN but words it like DEAD must fail here.
  const dead = diagnosticMessage(deadFinding());
  for (const reason of ALL_REASONS) {
    const f = unknownFinding(reason);
    assert.notStrictEqual(diagnosticMessage(f), dead, `${reason} must not read as DEAD`);
    // Checked against what the editor itself wrote: verify.ts's own detail for
    // provider-refused contains the word "revoked" on purpose, saying a 403
    // looks the same for a revoked key and a live one.
    assert.doesNotMatch(
      authoredPart(f),
      /revoked|no longer active|invalid\b/i,
      `${reason}: the editor must not assert revocation it did not establish`
    );
  }
});

test("the five UNKNOWN reasons are told apart from one another", () => {
  // They share an outcome but not a remedy. One is an egress fix and another is
  // a person opening a provider console; a single "unknown" wording buries that.
  const messages = ALL_REASONS.map((r) => diagnosticMessage(unknownFinding(r)));
  assert.strictEqual(
    new Set(messages).size,
    ALL_REASONS.length,
    `each reason needs its own remedy on screen, got:\n${messages.join("\n")}`
  );
});

suite("\nextension.ts — scan summaries count what was actually established");

/** One of each: live, refused, dead, never checked. */
function mixedFindings(): Finding[] {
  return [liveFinding(), unknownFinding("provider-refused"), deadFinding(), neverVerified()];
}

test("the workspace summary counts four buckets, as the report does", () => {
  const summary = workspaceScanSummary(mixedFindings(), 4);
  assert.doesNotMatch(
    summary,
    /3 unverified/i,
    `a dead credential and a refused check were both checked — ${summary}`
  );
  assert.match(summary, /\b1\b[^.]*live/i, summary);
  assert.match(summary, /needing a look|needs a look|need a look|undetermined/i, summary);
  assert.match(summary, /\b1\b[^.]*unverified/i, summary);
  assert.match(summary, /\bdead\b|no longer active/i, summary);
});

test("the staged warning does not file a checked credential under unverified", () => {
  const notice = stagedScanNotice([
    unknownFinding("provider-refused"),
    deadFinding(),
    neverVerified(),
  ]);
  assert.notStrictEqual(notice.level, "none", "three findings staged must say something");
  const message = notice.level === "none" ? "" : notice.message;
  assert.doesNotMatch(message, /3 unverified/i, message);
  assert.match(message, /needing a look|needs a look|need a look|undetermined/i, message);
  assert.match(message, /\bdead\b|no longer active/i, message);
});


finish();
