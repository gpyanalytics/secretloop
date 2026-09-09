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
  maskClipboardText,
  stagedScanNotice,
  effectiveConfig,
  PromptState,
} from "../src/extension";
import { Finding, UnknownReason } from "../src/scanner";
import { mergeConfig } from "../src/config";
import { scanWorkspaceScan } from "../src/workspace";
import { emptyArchiveAccounting } from "../src/archive";
import { UNKNOWN_REASONS } from "../src/report";
import { MigrationOutcome } from "../src/rotate";
import { DiagnosticSeverity, setConfiguration, resetConfiguration } from "./stubs/vscode";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { test, suite, finish, assert } from "./harness";
import { positiveSamples } from "./fixtures";

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
  "unsupported-transform":
    "This finding was recovered by decoding a base64-encoded value in the source. " +
    "Verification of encoded findings is not supported: the encoded text is not the " +
    "credential, and SecretLoop does not keep the decoded form, so nothing was sent to " +
    "GitHub. Liveness could not be determined — confirm it in the provider's own dashboard.",
  "unsupported-container":
    "This finding is inside an archive member (zip container dist/bundle.zip, member " +
    "src/config.env). Archive-member findings are not verified in this version: the member " +
    "cannot be re-read from disk to confirm what would be sent, so nothing was sent to GitHub. " +
    "Liveness could not be determined — confirm it in the provider's own dashboard.",
  "ambiguous-issuer":
    "This credential format is issued by Stripe, Clerk and WorkOS, and nothing in the value " +
    "says which one issued this key. It was NOT sent to any of them, because checking it " +
    "would mean handing a live credential to a provider that may not have issued it. " +
    "Confirm it in the issuing provider's own dashboard.",
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


// ---------------------------------------------------------------------------
suite("\nextension.ts — masking the clipboard");

/**
 * The command handler is read-act-tell; every decision is here. Both defects
 * this covers lived inside an inline closure where no test could reach them.
 */

test("an inline directive does not leave the credential on the clipboard", () => {
  const gh = positiveSamples["github-token"];
  for (const input of [
    `token = "${gh}" # gitleaks:allow`,
    `# secretloop:allow\ntoken = "${gh}"`,
    `token = "${gh}" // secretloop-ignore`,
  ]) {
    const outcome = maskClipboardText(input);
    assert.strictEqual(
      outcome.kind,
      "masked",
      `reported "${outcome.message}" and left the credential on the clipboard`
    );
    if (outcome.kind !== "masked") continue;
    assert.ok(!outcome.masked.includes(gh), `the credential survived:\n${outcome.masked}`);
    assert.strictEqual(outcome.count, 1);
    assert.match(outcome.message, /masked 1 secret\(s\)/);
  }
});

test('a suppressed credential is never reported as "no secrets found"', () => {
  // The CLI said "masked 0 finding(s)", which is at least ambiguous. The editor
  // said "no secrets found in the clipboard" -- an affirmative claim, made in
  // the one case where the annotation is there BECAUSE the value is real.
  const outcome = maskClipboardText(`token = "${positiveSamples["github-token"]}" # gitleaks:allow`);
  assert.notStrictEqual(outcome.kind, "nothing-found");
  assert.doesNotMatch(outcome.message, /no secrets found/);
});

test("clipboard masking uses the defaults, so no workspace config can widen it", () => {
  // Structural: the handler takes no config argument and the function builds
  // its own from defaultConfig, so there is no path for a `.secretloop.json`
  // carrying excludeRules or `allowValues: [".*"]` to reach it. Previously it
  // called configForFolder(requireWorkspaceRoot() ?? process.cwd(), ...).
  assert.strictEqual(maskClipboardText.length, 1, "maskClipboardText grew a config parameter");
  const { readFileSync } = require("fs") as typeof import("fs");
  const src = readFileSync(require("path").join(__dirname, "..", "src", "extension.ts"), "utf8");
  const body = src.slice(src.indexOf("export function maskClipboardText"));
  const end = body.indexOf("\nfunction configForFolder");
  assert.ok(end > 0, "maskClipboardText moved; this check needs re-anchoring");
  assert.doesNotMatch(
    body.slice(0, end),
    /configForFolder|loadConfig/,
    "clipboard masking reads a project config again"
  );
});

test("an ordinary credential still masks, and clean text still reports nothing", () => {
  // The other direction, so "always mask" cannot pass by masking everything.
  const gh = positiveSamples["github-token"];
  const masked = maskClipboardText(`const t = "${gh}";`);
  assert.strictEqual(masked.kind, "masked");
  const clean = maskClipboardText("const a = 1;\nconst b = 2;");
  assert.strictEqual(clean.kind, "nothing-found");
  assert.match(clean.message, /no secrets found/);
});

suite("\nextension.ts — entropyPassEnabled precedence");

/**
 * Project file > editor setting > shipped default (false).
 *
 * effectiveConfig is the whole rule set, split out of workspaceConfig so it can
 * be reached without a TextDocument. `folderPath === undefined` is the
 * no-workspace case, which before this change had no opt-in at all: the setting
 * was declared in package.json and never read.
 */
function withProject(config: object | null, run: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "sl-ext-cfg-"));
  try {
    if (config !== null) {
      writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify(config), "utf8");
    }
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The setting as VS Code would report it, package default included. */
function setEntropySetting(entry: { defaultValue?: unknown; globalValue?: unknown }): void {
  resetConfiguration();
  setConfiguration("secretloop", "entropyPassEnabled", entry);
}

test("no workspace + setting absent -> OFF", () => {
  setEntropySetting({ defaultValue: false });
  assert.strictEqual(effectiveConfig(undefined, 4.3, false).entropyPassEnabled, false);
});

test("no workspace + setting false -> OFF", () => {
  setEntropySetting({ defaultValue: false, globalValue: false });
  assert.strictEqual(effectiveConfig(undefined, 4.3, false).entropyPassEnabled, false);
});

test("no workspace + setting true -> ON", () => {
  // The case that had no opt-in before the setting was wired.
  setEntropySetting({ defaultValue: false, globalValue: true });
  assert.strictEqual(effectiveConfig(undefined, 4.3, true).entropyPassEnabled, true);
});

test("workspace + config absent + setting absent -> OFF", () => {
  setEntropySetting({ defaultValue: false });
  withProject(null, (dir) => {
    assert.strictEqual(effectiveConfig(dir, 4.3, false).entropyPassEnabled, false);
  });
});

test("workspace + config absent + setting true -> ON", () => {
  setEntropySetting({ defaultValue: false, globalValue: true });
  withProject(null, (dir) => {
    assert.strictEqual(effectiveConfig(dir, 4.3, true).entropyPassEnabled, true);
  });
  // Also when a config file exists but is silent on this field: "absent" is
  // about the field, not about the file.
  withProject({ excludeRules: [] }, (dir) => {
    assert.strictEqual(effectiveConfig(dir, 4.3, true).entropyPassEnabled, true);
  });
});

test("workspace + config true + setting false -> ON", () => {
  // Explicit project config beats the editor setting.
  setEntropySetting({ defaultValue: false, globalValue: false });
  withProject({ entropyPassEnabled: true }, (dir) => {
    assert.strictEqual(effectiveConfig(dir, 4.3, false).entropyPassEnabled, true);
  });
});

test("workspace + config false + setting true -> OFF", () => {
  // The direction that only works because `raw` is consulted rather than the
  // merged boolean: merged false is ambiguous, raw false is not.
  setEntropySetting({ defaultValue: false, globalValue: true });
  withProject({ entropyPassEnabled: false }, (dir) => {
    assert.strictEqual(effectiveConfig(dir, 4.3, true).entropyPassEnabled, false);
  });
});

test("a JSON null in the project file is not an opt-out, matching mergeConfig", () => {
  // mergeConfig folds the default in with `??`, so `null` there means "not set"
  // exactly as `undefined` does. The editor's precedence test has to agree: an
  // `=== undefined` check would treat a null as an explicit project opt-out the
  // merge never performed, and the user's own setting would be silently vetoed
  // by a field the project did not actually decide.
  setEntropySetting({ defaultValue: false, globalValue: true });
  withProject({ entropyPassEnabled: null }, (dir) => {
    assert.strictEqual(
      effectiveConfig(dir, 4.3, true).entropyPassEnabled,
      true,
      "a null project field must defer to the editor setting"
    );
  });
  // And the two neighbouring cases still hold, so the null case is not a hole
  // punched through the precedence rules.
  withProject({ entropyPassEnabled: false }, (dir) => {
    assert.strictEqual(
      effectiveConfig(dir, 4.3, true).entropyPassEnabled,
      false,
      "explicit false + setting true must stay false"
    );
  });
  setEntropySetting({ defaultValue: false, globalValue: false });
  withProject({ entropyPassEnabled: true }, (dir) => {
    assert.strictEqual(
      effectiveConfig(dir, 4.3, false).entropyPassEnabled,
      true,
      "explicit true + setting false must stay true"
    );
  });
});

test("mergeConfig itself treats null as absent, which is what the editor mirrors", () => {
  // Pins the semantic the test above depends on. If mergeConfig ever stopped
  // using `??` here, this fails first and names the reason.
  assert.strictEqual(
    mergeConfig({ entropyPassEnabled: null as unknown as boolean }).entropyPassEnabled,
    false,
    "null must fall through to the default, not be coerced to an opt-out"
  );
});

test("the editor setting cannot widen an unrelated project policy", () => {
  // entropyThreshold's existing deferral still works alongside the new field.
  setEntropySetting({ defaultValue: false, globalValue: true });
  withProject({ entropyThreshold: 5.5, entropyPassEnabled: false }, (dir) => {
    const config = effectiveConfig(dir, 4.3, true);
    assert.strictEqual(config.entropyThreshold, 5.5, "project threshold must win");
    assert.strictEqual(config.entropyPassEnabled, false, "project opt-out must win");
  });
});


// ---------------------------------------------------------------------------
suite("\nextension.ts — secretloop.excludePaths reaches the walk");

/**
 * The same defect class as entropyPassEnabled above: the setting was declared
 * in package.json and never read, so a user could exclude a path in editor
 * settings, see no error, and have the files scanned anyway.
 *
 * These drive the real editor configuration builder and the real traversal, not
 * a hand-built ScanConfig: effectiveConfig reads the setting through the same
 * `setting<T>` helper the extension uses at run time, and scanWorkspaceScan is
 * the walk every editor entry point runs.
 *
 * Fixture directories are deliberately neutral. `vendor/` and `dist/` are in
 * baseExcludePaths, so a test using them would pass without the fix.
 */
function excludeFixture(project: object | null): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sl-ext-excl-"));
  mkdirSync(path.join(dir, "reports"), { recursive: true });
  mkdirSync(path.join(dir, "notes"), { recursive: true });
  writeFileSync(path.join(dir, "app.js"), "const ok = 1;\n", "utf8");
  // Built at run time from the corpus rather than written as a literal.
  writeFileSync(path.join(dir, "reports", "lib.js"), `const t = "${positiveSamples["github-token"]}";\n`, "utf8");
  writeFileSync(path.join(dir, "notes", "memo.js"), `const t = "${positiveSamples["github-token"]}";\n`, "utf8");
  if (project !== null) writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify(project), "utf8");
  return dir;
}

function withExcludeFixture(project: object | null, run: (dir: string) => void): void {
  const dir = excludeFixture(project);
  try {
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The setting as VS Code reports it, package default included. */
function setExcludeSetting(entry: { defaultValue?: unknown; globalValue?: unknown; workspaceValue?: unknown; workspaceFolderValue?: unknown }): void {
  resetConfiguration();
  setConfiguration("secretloop", "excludePaths", entry);
}

/** Repo-relative paths the walk actually reads, through the editor's own config. */
function walked(dir: string): string[] {
  return scanWorkspaceScan(dir, effectiveConfig(dir, 4.3, false))
    .scanned.map((f) => f.path)
    .sort();
}

test("a VS Code setting excludes an otherwise scanned file", () => {
  setExcludeSetting({ defaultValue: [], workspaceValue: ["reports/**"] });
  withExcludeFixture(null, (dir) => {
    const files = walked(dir);
    assert.ok(!files.includes("reports/lib.js"), `the setting did not exclude it: ${files.join(", ")}`);
    assert.ok(files.includes("app.js"), "an unrelated file stopped being scanned");
  });
});

test("an unrelated file keeps its finding when the setting excludes another path", () => {
  setExcludeSetting({ defaultValue: [], workspaceValue: ["reports/**"] });
  withExcludeFixture(null, (dir) => {
    const scanned = scanWorkspaceScan(dir, effectiveConfig(dir, 4.3, false)).scanned;
    const notes = scanned.find((f) => f.path === "notes/memo.js");
    assert.ok(notes, "notes/memo.js was excluded too");
    assert.ok(
      notes.findings.some((f) => f.ruleId === "github-token"),
      "the planted finding outside the excluded path was lost"
    );
  });
});

test("a project-file exclusion is still honoured", () => {
  setExcludeSetting({ defaultValue: [] });
  withExcludeFixture({ excludePaths: ["reports/**"] }, (dir) => {
    assert.ok(!walked(dir).includes("reports/lib.js"), "the project file stopped excluding");
  });
});

test("the editor setting and the project file both apply", () => {
  setExcludeSetting({ defaultValue: [], workspaceValue: ["notes/**"] });
  withExcludeFixture({ excludePaths: ["reports/**"] }, (dir) => {
    const files = walked(dir);
    assert.ok(!files.includes("reports/lib.js"), "the project-file exclusion was dropped");
    assert.ok(!files.includes("notes/memo.js"), "the editor exclusion was dropped");
    assert.ok(files.includes("app.js"), "an unrelated file stopped being scanned");
  });
});

test("the editor setting cannot un-exclude what the project file excluded", () => {
  // Raise-only, the same contract the CLI flags follow.
  setExcludeSetting({ defaultValue: [], workspaceValue: [] });
  withExcludeFixture({ excludePaths: ["reports/**"] }, (dir) => {
    assert.ok(!walked(dir).includes("reports/lib.js"), "an empty editor list widened the scan");
  });
});

test("no setting leaves the walk exactly as it was", () => {
  setExcludeSetting({ defaultValue: [] });
  withExcludeFixture(null, (dir) => {
    const files = walked(dir);
    assert.ok(files.includes("reports/lib.js") && files.includes("notes/memo.js") && files.includes("app.js"),
      `default settings changed the walk: ${files.join(", ")}`);
  });
});

test("the resolved value applies to every folder of a multi-root workspace", () => {
  // secretloop.excludePaths is declared without a scope, so VS Code resolves it
  // at window scope: one resolved list, applied to each folder alike. Per-folder
  // overrides would need a scope change, which this fix deliberately does not make.
  setExcludeSetting({ defaultValue: [], workspaceValue: ["reports/**"] });
  withExcludeFixture(null, (a) => {
    withExcludeFixture(null, (b) => {
      for (const dir of [a, b]) {
        assert.ok(!walked(dir).includes("reports/lib.js"), "a folder did not receive the resolved list");
      }
    });
  });
});

test("changing the setting changes the next scan", () => {
  withExcludeFixture(null, (dir) => {
    setExcludeSetting({ defaultValue: [] });
    assert.ok(walked(dir).includes("reports/lib.js"), "precondition: the file is scanned with no setting");
    setExcludeSetting({ defaultValue: [], workspaceValue: ["reports/**"] });
    assert.ok(!walked(dir).includes("reports/lib.js"), "the next scan did not pick the new setting up");
  });
});

test("the no-workspace branch reads the setting too", () => {
  setExcludeSetting({ defaultValue: [], globalValue: ["reports/**"] });
  assert.ok(
    effectiveConfig(undefined, 4.3, false).excludePaths.includes("reports/**"),
    "effectiveConfig(undefined) dropped the editor exclusions"
  );
});

test("every editor entry point builds its config through the same builder", () => {
  // Structural: the read lives in configForFolder, so scanWorkspace, the staged
  // scan and scanDocument all inherit it. A future caller cannot forget to pass it.
  const { readFileSync: read } = require("fs") as typeof import("fs");
  const body = read(path.join(__dirname, "..", "src", "extension.ts"), "utf8");
  const builders = body.match(/configForFolder\(/g) ?? [];
  assert.ok(builders.length >= 4, `expected the three callers plus the definition, saw ${builders.length}`);
  // The read lives in the builder, not at the call sites, so scanWorkspace, the
  // staged scan and scanDocument all inherit it and a new caller cannot omit it.
  const start = body.indexOf("function configForFolder(");
  const end = body.indexOf("\nfunction ", start + 1);
  const builderBody = body.slice(start, end === -1 ? undefined : end);
  assert.match(builderBody, /editorExcludePaths\(\)/, "configForFolder does not read the setting");
  assert.match(body, /function editorExcludePaths\(\)[\s\S]{0,400}setting<[^>]*>\("excludePaths"/,
    "editorExcludePaths does not go through the resolved VS Code setting");
});


// ---------------------------------------------------------------------------
suite("\nextension.ts — the workspace summary discloses suppressions");

/**
 * The CLI scope sentence and the MCP `scope` object both report inline and
 * fixture suppressions; the editor summary did not, although workspace.ts
 * already carries both counters on every ScannedFile. A scan that silently
 * dropped findings read exactly like one with nothing to drop.
 *
 * Wording and clause order are describeScope's, not this test's: the assertions
 * below pin the exact sentences the CLI already emits.
 */
const INLINE_CLAUSE = (n: number) => `; ${n} finding(s) suppressed by inline directives`;
const FIXTURE_CLAUSE = (n: number) =>
  `; ${n} generic finding(s) suppressed in test/fixture paths (--include-fixtures to report them)`;

test("inline suppressions alone are disclosed, with the exact count", () => {
  const summary = workspaceScanSummary([], 4, 0, 0, 0, undefined, 2, 0);
  assert.ok(summary.includes(INLINE_CLAUSE(2)), `missing the inline clause: ${summary}`);
  assert.ok(!summary.includes("suppressed in test/fixture paths"), "a fixture clause appeared from nowhere");
  assert.strictEqual(summary, `SecretLoop: no secrets found across 4 file(s)${INLINE_CLAUSE(2)}.`);
});

test("fixture suppressions alone are disclosed, with the exact count", () => {
  const summary = workspaceScanSummary([], 4, 0, 0, 0, undefined, 0, 3);
  assert.ok(summary.includes(FIXTURE_CLAUSE(3)), `missing the fixture clause: ${summary}`);
  assert.ok(!summary.includes("inline directives"), "an inline clause appeared from nowhere");
  assert.strictEqual(summary, `SecretLoop: no secrets found across 4 file(s)${FIXTURE_CLAUSE(3)}.`);
});

test("both suppression kinds appear together, in describeScope's order", () => {
  const summary = workspaceScanSummary([], 4, 0, 0, 0, undefined, 2, 3);
  const inline = summary.indexOf(INLINE_CLAUSE(2));
  const fixture = summary.indexOf(FIXTURE_CLAUSE(3));
  assert.ok(inline > 0 && fixture > 0, `a clause is missing: ${summary}`);
  assert.ok(inline < fixture, "inline must precede fixture, as the CLI orders them");
});

test("zero counts add no clause and leave the sentence byte-identical", () => {
  const before = workspaceScanSummary([], 4, 0, 0, 0, undefined);
  const withZeros = workspaceScanSummary([], 4, 0, 0, 0, undefined, 0, 0);
  assert.strictEqual(withZeros, before, "zero counts changed the sentence");
  assert.strictEqual(withZeros, "SecretLoop: no secrets found across 4 file(s).");
});

test("suppression clauses coexist with the API-document and archive clauses", () => {
  const archives = { ...emptyArchiveAccounting(), containersOpened: 1, membersScanned: 2 };
  const summary = workspaceScanSummary([], 4, 0, 0, 5, archives, 2, 3);
  for (const part of [INLINE_CLAUSE(2), FIXTURE_CLAUSE(3), "5 API description document(s)", "1 archive(s) opened"]) {
    assert.ok(summary.includes(part), `missing ${part} in: ${summary}`);
  }
  // Ordering is describeScope's: inline, fixture, api documents, archives.
  assert.ok(
    summary.indexOf(INLINE_CLAUSE(2)) < summary.indexOf(FIXTURE_CLAUSE(3)) &&
      summary.indexOf(FIXTURE_CLAUSE(3)) < summary.indexOf("5 API description document(s)") &&
      summary.indexOf("5 API description document(s)") < summary.indexOf("1 archive(s) opened"),
    `clause order changed: ${summary}`
  );
});

test("the totals aggregate across scanned files, over the real scan population", () => {
  // Two files, each with one inline-suppressed finding: the caller sums per-file
  // counters exactly as the MCP scope object does.
  const dir = mkdtempSync(path.join(tmpdir(), "sl-ext-supp-"));
  try {
    const token = positiveSamples["github-token"];
    writeFileSync(path.join(dir, "a.js"), `const t = "${token}"; // secretloop:allow\n`, "utf8");
    writeFileSync(path.join(dir, "b.js"), `const t = "${token}"; // gitleaks:allow\n`, "utf8");
    writeFileSync(path.join(dir, "c.js"), "const ok = 1;\n", "utf8");
    const scanned = scanWorkspaceScan(dir, mergeConfig({})).scanned;
    const suppressed = scanned.reduce((n, f) => n + (f.suppressed ?? 0), 0);
    const fixtureSuppressed = scanned.reduce((n, f) => n + (f.fixtureSuppressed ?? 0), 0);
    assert.strictEqual(suppressed, 2, "the per-file inline counters did not add up");
    assert.strictEqual(fixtureSuppressed, 0, "nothing should be fixture-suppressed here");
    const findings = scanned.flatMap((f) => f.findings);
    assert.strictEqual(findings.length, 0, "the suppressed findings leaked into the report");
    const summary = workspaceScanSummary(findings, scanned.length, 0, 0, 0, undefined, suppressed, fixtureSuppressed);
    assert.ok(summary.includes(INLINE_CLAUSE(2)), `the aggregate did not reach the sentence: ${summary}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the workspace command feeds both totals into the summary", () => {
  // Structural, in the manner of the clipboard test above: the reduce has to
  // exist at the call site, or the formatter is fed zeros for ever.
  const { readFileSync: read } = require("fs") as typeof import("fs");
  const body = read(path.join(__dirname, "..", "src", "extension.ts"), "utf8");
  const start = body.indexOf("async function scanWorkspace()");
  const end = body.indexOf("\nasync function ", start + 1);
  const scanBody = body.slice(start, end === -1 ? undefined : end);
  assert.match(scanBody, /\(s\.suppressed \?\? 0\)/, "scanWorkspace does not total the inline suppressions");
  assert.match(scanBody, /\(s\.fixtureSuppressed \?\? 0\)/, "scanWorkspace does not total the fixture suppressions");
  assert.match(scanBody, /workspaceScanSummary\([\s\S]{0,200}suppressed/, "the totals never reach the summary");
});

finish();
