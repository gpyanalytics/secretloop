import * as vscode from "vscode";
import { scanText, maskFindings, Finding } from "./scanner";
import {
  loadConfig,
  mergeConfig,
  defaultConfig,
  BASELINE_VERSION,
  SecretLoopConfig,
} from "./config";
import { redactInPlace, extractToEnv } from "./remediate";
import { isVerifiable, verifyFindings, verificationProvider, VerificationCache } from "./verify";
import {
  rotateFinding,
  migrateAwsAdminCredentials,
  AWS_ADMIN_ACCESS_KEY_ID,
  AWS_ADMIN_SECRET_ACCESS_KEY,
  LegacyCredentialStore,
  MigrationOutcome,
} from "./rotate";
import { installPrecommitHook, uninstallPrecommitHook, refreshHookVersionStamp } from "./hooks";
import { setting, resolveSetting, describeOrigin, SETTINGS_NAMESPACE } from "./settings";
import { UNKNOWN_REASONS, describeScope } from "./report";
import { ScannedFile, scanFiles, scanWorkspaceScan, verifyScannedFiles } from "./workspace";
import * as path from "path";


const diagnosticCollection = vscode.languages.createDiagnosticCollection("secretloop");
const findingsByDocument = new Map<string, Finding[]>();
/**
 * Verification outcomes, shared across every scan in this session. A document
 * is re-scanned on open and after every 400ms of typing, so without this an
 * open file means the same credential is sent to its provider over and over.
 */
const verificationCache = new VerificationCache();

/**
 * Set at activation so a scan can reach globalState for the "Never" answer.
 */
let extensionContext: vscode.ExtensionContext | undefined;
/** Persisted across sessions: the user asked never to be offered verification. */
const VERIFICATION_PROMPT_DECLINED_KEY = "secretloop.verificationPromptDeclinedForever";
/** "Not now" — forgotten when the window closes. */
let verificationDeclinedThisSession = false;
/** Several open documents scan at once; only one prompt should reach the user. */
let verificationPromptShown = false;
/**
 * A startup notice has already claimed the user's attention this session.
 *
 * Migration fires once ever and tells the user to rotate an exposed credential;
 * the verification prompt fires on the first checkable finding. Both land during
 * activation, and stacking them means the important one gets dismissed with the
 * other. Migration wins — it is actionable and it never comes back — and the
 * verification offer waits for the next session.
 */
let startupNoticeShown = false;

/**
 * Diagnostics a user can actually read.
 *
 * console.log goes to the Debug Console, which only exists while debugging — a
 * published install has no way to see what the migration decided or why a
 * prompt stayed silent. An OutputChannel is visible from View > Output.
 */
let output: vscode.OutputChannel | undefined;

function log(message: string): void {
  output?.appendLine(message);
}

export function activate(context: vscode.ExtensionContext) {
  extensionContext = context;
  output = vscode.window.createOutputChannel("SecretLoop");
  context.subscriptions.push(output);
  context.subscriptions.push(diagnosticCollection);

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => scanDocument(doc)),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (setting<boolean>("autoScanOnSave", true)) scanDocument(doc);
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
      findingsByDocument.delete(doc.uri.toString());
    })
  );

  let debounceTimer: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => scanDocument(e.document), 400);
    })
  );

  // Before the first scan, so a migration notice cannot be stacked underneath
  // the verification prompt that scanning can raise.
  void runAwsCredentialMigration(context).then(() => {
    vscode.workspace.textDocuments.forEach((doc) => scanDocument(doc));
  });

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new SecretCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("secretloop.redact", async (docUri: vscode.Uri, finding: Finding) => {
      const doc = await vscode.workspace.openTextDocument(docUri);
      await redactInPlace(doc, finding);
      scanDocument(doc);
    }),
    vscode.commands.registerCommand(
      "secretloop.copyAndRedact",
      async (docUri: vscode.Uri, finding: Finding) => {
        const doc = await vscode.workspace.openTextDocument(docUri);
        await redactInPlace(doc, finding, { copyToClipboard: true });
        scanDocument(doc);
      }
    ),
    vscode.commands.registerCommand("secretloop.extractToEnv", async (docUri: vscode.Uri, finding: Finding) => {
      const doc = await vscode.workspace.openTextDocument(docUri);
      const envPath = setting<string>("envFilePath", ".env");
      await extractToEnv(doc, finding, envPath);
      scanDocument(doc);
    }),
    vscode.commands.registerCommand("secretloop.rotate", async (docUri: vscode.Uri, finding: Finding) => {
      const choice = await vscode.window.showWarningMessage(
        `Rotate/revoke this ${finding.description}? This may perform a real action against the provider.`,
        { modal: true },
        "Rotate"
      );
      if (choice !== "Rotate") return;

      const outcome = await rotateFinding(finding, context.secrets);
      if (outcome.success) {
        vscode.window.showInformationMessage(`SecretLoop: ${outcome.message}`);
        const doc = await vscode.workspace.openTextDocument(docUri);
        // Never copies: the credential was just revoked, so putting it on a
        // syncing clipboard is all cost and no use.
        await redactInPlace(doc, finding);
        scanDocument(doc);
      } else {
        vscode.window.showWarningMessage(`SecretLoop: ${outcome.message}`);
      }
    }),
    vscode.commands.registerCommand("secretloop.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("secretloop.scanStagedFiles", warnOnStagedSecrets),
    vscode.commands.registerCommand("secretloop.installPrecommitHook", () =>
      installPrecommitHook(
        context,
        setting<string>("envFilePath", ".env"),
        extensionVersion(context)
      )
    ),
    vscode.commands.registerCommand("secretloop.uninstallPrecommitHook", uninstallPrecommitHook),
    vscode.commands.registerCommand("secretloop.scanHistory", scanGitHistory),
    vscode.commands.registerCommand("secretloop.writeBaseline", writeBaseline),
    vscode.commands.registerCommand("secretloop.setAwsAdminCredentials", () =>
      promptForAwsAdminCredentials(context)
    ),
    /**
     * Mask the clipboard, on demand and only on demand.
     *
     * The clipboard is read HERE and nowhere else in this extension: no
     * listener, no interval, no read on activation. A secret scanner that
     * watched the clipboard would be indistinguishable from the thing it warns
     * about, so the restriction is structural rather than a promise, and
     * tests/mask.test.ts greps the source to hold it.
     */
    vscode.commands.registerCommand("secretloop.maskClipboard", async () => {
      const text = await vscode.env.clipboard.readText();
      const outcome = maskClipboardText(text);
      if (outcome.kind === "too-large") {
        vscode.window.showErrorMessage(`SecretLoop: ${outcome.message}`);
        return;
      }
      if (outcome.kind === "nothing-found") {
        vscode.window.showInformationMessage(`SecretLoop: ${outcome.message}`);
        return;
      }
      await vscode.env.clipboard.writeText(outcome.masked);
      vscode.window.showInformationMessage(`SecretLoop: ${outcome.message}`);
    }),

    vscode.commands.registerCommand("secretloop.resetPromptPreferences", async () => {
      // Scoped to prompt state only: the persisted decline and this session's
      // flags. Stored credentials, baselines and the enableLiveVerification
      // setting are deliberately untouched — the last is a real choice the user
      // made and is visible in the Settings UI, not a prompt preference.
      const hadPermanentDecline =
        context.globalState.get<boolean>(VERIFICATION_PROMPT_DECLINED_KEY) === true;
      await context.globalState.update(VERIFICATION_PROMPT_DECLINED_KEY, undefined);
      verificationDeclinedThisSession = false;
      verificationPromptShown = false;
      startupNoticeShown = false;

      const outcome = describePromptReset({
        hadPermanentDecline,
        verificationEnabled: setting<boolean>("enableLiveVerification", false),
      });
      log(`SecretLoop: prompt preferences reset (cleared permanent decline: ${outcome.clearedPermanent}).`);
      vscode.window.showInformationMessage(outcome.message);
    }),
    vscode.commands.registerCommand("secretloop.clearAwsAdminCredentials", async () => {
      await context.secrets.delete(AWS_ADMIN_ACCESS_KEY_ID);
      await context.secrets.delete(AWS_ADMIN_SECRET_ACCESS_KEY);
      vscode.window.showInformationMessage("SecretLoop: AWS admin credentials removed from the keychain.");
    })
  );


  // Lets an installed hook notice its copy of the scanner is behind. Writes
  // nothing in a repository that never asked for a hook.
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    try {
      refreshHookVersionStamp(folder.uri.fsPath, extensionVersion(context));
    } catch {
      // A read-only or absent git directory is not worth interrupting startup.
    }
  }
}

/** The running extension's version, for stamping a repository's scanner copy. */
function extensionVersion(context: vscode.ExtensionContext): string {
  return (context.extension?.packageJSON?.version as string) ?? "unknown";
}

async function scanDocument(document: vscode.TextDocument) {
  if (document.uri.scheme !== "file") return;

  const threshold = setting<number>("entropyThreshold", 4.3);
  const verification = resolveSetting<boolean>("enableLiveVerification", false);
  const verificationEnabled = verification.value;

  const config = workspaceConfig(document, threshold);
  const relPath = vscode.workspace.asRelativePath(document.uri, false);
  const findings = scanText(document.getText(), { config, filePath: relPath });
  findingsByDocument.set(document.uri.toString(), findings);
  renderDiagnostics(document, findings);

  if (!verificationEnabled) {
    await offerVerification(document, findings);
    return;
  }

  // Which branch was taken, and on whose authority. Without the origin, an
  // inherited user setting looks exactly like the shipped default.
  log(
    `SecretLoop: live verification is on (${describeOrigin("enableLiveVerification", verification.origin)}); ` +
      `checking ${findings.filter((f) => isVerifiable(f.ruleId)).length} of ${findings.length} finding(s) in ${relPath}.`
  );

  // Verification is async and network-bound; render initial diagnostics
  // immediately above, then upgrade confidence in place as results land so
  // the editor never blocks on network calls.
  const fullText = document.getText();
  const sent: Finding[] = [];
  await verifyFindings(
    findings,
    { fullText, fetchImpl: fetch },
    { cache: verificationCache, onOutbound: (f) => sent.push(f) }
  );

  if (sent.length > 0) {
    const providers = [...new Set(sent.map((f) => verificationProvider(f.ruleId) ?? f.ruleId))].sort();
    log(`SecretLoop: sent ${sent.length} credential(s) to ${providers.join(", ")} from ${relPath}.`);
  }

  // Only re-render if this document is still the latest scan for its URI
  // (guards against stale async results from rapid edits).
  if (findingsByDocument.get(document.uri.toString()) === findings) {
    renderDiagnostics(document, findings);
  }
}

/**
 * Offers live verification the first time a scan turns up a credential that
 * could actually be checked.
 *
 * Verification is off by default because it sends the detected credential to a
 * third party, and a freshly cloned repository may hold credentials belonging
 * to someone else entirely. But a setting nobody discovers stays off forever
 * and the feature ships dark, so the offer is made at the one moment its value
 * is concrete: a real credential, a named provider, a decision the user can
 * actually weigh.
 */
export interface PromptState {
  startupNoticeShown: boolean;
  declinedThisSession: boolean;
  promptShown: boolean;
  declinedPermanently: boolean;
}

export type PromptSuppression =
  | "startup-notice-already-shown"
  | "declined-this-session"
  | "already-prompted-this-session"
  | "declined-permanently"
  | "no-verifiable-finding"
  | "no-provider-name";

export type PromptGate =
  | { show: true; ruleId: string; description: string; provider: string }
  | { show: false; reason: PromptSuppression };

/**
 * Whether to offer live verification, and when not, exactly why.
 *
 * Pure, and every refusal is named rather than being an early return, because
 * a prompt that silently never appears is otherwise undiagnosable from outside
 * — which is precisely how it was reported.
 */
export function decideVerificationPrompt(findings: Finding[], state: PromptState): PromptGate {
  if (state.startupNoticeShown) return { show: false, reason: "startup-notice-already-shown" };
  if (state.declinedThisSession) return { show: false, reason: "declined-this-session" };
  if (state.promptShown) return { show: false, reason: "already-prompted-this-session" };
  if (state.declinedPermanently) return { show: false, reason: "declined-permanently" };

  const candidate = findings.find((f) => isVerifiable(f.ruleId));
  if (!candidate) return { show: false, reason: "no-verifiable-finding" };

  const provider = verificationProvider(candidate.ruleId);
  // Never ask permission to contact an unnamed party.
  if (!provider) return { show: false, reason: "no-provider-name" };

  return { show: true, ruleId: candidate.ruleId, description: candidate.description, provider };
}

async function offerVerification(document: vscode.TextDocument, findings: Finding[]): Promise<void> {
  const gate = decideVerificationPrompt(findings, {
    startupNoticeShown,
    declinedThisSession: verificationDeclinedThisSession,
    promptShown: verificationPromptShown,
    declinedPermanently:
      extensionContext?.globalState.get<boolean>(VERIFICATION_PROMPT_DECLINED_KEY) === true,
  });

  if (!gate.show) {
    log(`SecretLoop: live verification is off; prompt not offered (${gate.reason}).`);
    return;
  }
  const candidate = { ruleId: gate.ruleId, description: gate.description };
  const provider = gate.provider;

  log(`SecretLoop: offering verification for ${candidate.ruleId} via ${provider}.`);
  verificationPromptShown = true;
  const choice = await vscode.window.showInformationMessage(
    `SecretLoop can confirm whether this ${candidate.description} is still active ` +
      `by making a read-only call to ${provider}. Enable live verification?`,
    "Enable",
    "Not now",
    "Never"
  );

  // Above the branching on purpose. Enable and Never both returned before a log
  // at the end, so the two most consequential answers left no trace — Never
  // worst of all, since it writes a permanent flag nothing can clear. One log
  // site cannot drift out of step with the branches.
  log(`SecretLoop: verification offer answered with ${choice ?? "(dismissed)"}.`);

  if (choice === "Enable") {
    await vscode.workspace
      .getConfiguration(SETTINGS_NAMESPACE)
      .update("enableLiveVerification", true, vscode.ConfigurationTarget.Global);
    await scanDocument(document); // re-run now that verification is allowed
    return;
  }

  if (choice === "Never") {
    await extensionContext?.globalState.update(VERIFICATION_PROMPT_DECLINED_KEY, true);
    return;
  }

  // "Not now", or the notification was dismissed.
  verificationDeclinedThisSession = true;
}

function renderDiagnostics(document: vscode.TextDocument, findings: Finding[]) {
  const diagnostics: vscode.Diagnostic[] = findings.map((f) => {
    const range = new vscode.Range(document.positionAt(f.startIndex), document.positionAt(f.endIndex));
    const diag = new vscode.Diagnostic(range, diagnosticMessage(f), severityForTier(f));
    diag.code = f.ruleId;
    diag.source = "SecretLoop";
    return diag;
  });
  diagnosticCollection.set(document.uri, diagnostics);
}

export function diagnosticMessage(f: Finding): string {
  // The verdict outranks the confidence tier. `confidence` only ever records
  // LIVE — verifyFindings upgrades it on nothing else — so reading it alone
  // rendered dead, all five unknowns and never-checked as one sentence.
  if (f.verifyStatus === "dead") {
    return (
      `Confirmed dead: ${f.description}. The provider says this credential no longer works, ` +
      `but it is still in your source. Remove it.`
    );
  }
  if (f.verifyStatus === "unknown") {
    // Labels come from report.ts so the editor and the report cannot drift into
    // describing the same reason two ways.
    const { label, remedy } = UNKNOWN_REASONS[f.verifyReason ?? "no-verifier"];
    // verify.ts writes `detail` for exactly this line — it is the remedy in the
    // provider's own words. The report's generic remedy stands in only for a
    // finding that reached here without one, which no verifier produces; it is
    // a lowercase fragment written to follow an em-dash in a list, so standing
    // alone it has to be made to read as a sentence.
    const why = f.verifyDetail ?? `${remedy.charAt(0).toUpperCase()}${remedy.slice(1)}.`;
    return `Possible secret: ${f.description} — liveness unknown: ${label}. ${why}`;
  }

  switch (f.confidence) {
    case "verified-live":
      return `LIVE secret confirmed: ${f.description}. This credential is currently active.`;
    case "format-match":
      return `Possible secret: ${f.description} (format match, not yet verified live).`;
    case "entropy-heuristic":
      return `Possible secret: ${f.description}. Low-confidence heuristic match — review before acting.`;
  }
}

export function severityForTier(f: Finding): vscode.DiagnosticSeverity {
  // Quieter than unchecked, and deliberately not silent: not an emergency, but
  // still a credential sitting in the source. Matches the report's SARIF note.
  if (f.verifyStatus === "dead") return vscode.DiagnosticSeverity.Information;
  // A 403 means the provider evaluated the credential and declined, which leans
  // live and which no retry resolves. report.ts's sarifLevel already raises this
  // one case to error whatever the rule's severity; the editor now agrees rather
  // than showing it as indistinguishable from a never-checked format match.
  if (f.verifyStatus === "unknown" && f.verifyReason === "provider-refused") {
    return vscode.DiagnosticSeverity.Error;
  }

  switch (f.confidence) {
    case "verified-live":
      return vscode.DiagnosticSeverity.Error;
    case "format-match":
      return vscode.DiagnosticSeverity.Warning;
    case "entropy-heuristic":
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Whether the rotate/revoke quick-fix is offered for a finding.
 *
 * A refused check earns it as much as a confirmed live one: 403 is the case
 * that leans live and that no retry resolves, so someone has to open the
 * provider console. Redact and extract-to-`.env` only move the string out of
 * the file; neither revokes anything.
 *
 * The isVerifiable conjunct stays — an unknown with no verifier behind it has
 * no provider path to offer.
 */
export function offersRotation(f: Finding): boolean {
  if (!isVerifiable(f.ruleId)) return false;
  return (
    f.confidence === "verified-live" ||
    (f.verifyStatus === "unknown" && f.verifyReason === "provider-refused")
  );
}

/**
 * The label on the rotate/revoke quick-fix.
 *
 * offersRotation fires on a refused check as well as a confirmed live one, and
 * the two do not warrant the same sentence. A lightbulb reading "this LIVE
 * credential" over a 403 is the boolean's old mistake in a new place: the label
 * would be stating the verdict the check explicitly failed to reach.
 */
export function rotateActionTitle(f: Finding): string {
  if (f.confidence === "verified-live") {
    return "SecretLoop: Rotate / revoke this LIVE credential";
  }
  return "SecretLoop: Inspect / revoke this possibly-active credential";
}

export class SecretCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(document: vscode.TextDocument, range: vscode.Range): vscode.CodeAction[] {
    const findings = findingsByDocument.get(document.uri.toString()) ?? [];
    const actions: vscode.CodeAction[] = [];

    for (const finding of findings) {
      const findingRange = new vscode.Range(
        document.positionAt(finding.startIndex),
        document.positionAt(finding.endIndex)
      );
      if (!findingRange.intersection(range)) continue;

      if (offersRotation(finding)) {
        const rotateAction = new vscode.CodeAction(
          rotateActionTitle(finding),
          vscode.CodeActionKind.QuickFix
        );
        rotateAction.isPreferred = true;
        rotateAction.command = {
          command: "secretloop.rotate",
          title: "Rotate",
          arguments: [document.uri, finding],
        };
        actions.push(rotateAction);
      }

      const redactAction = new vscode.CodeAction("SecretLoop: Redact this secret", vscode.CodeActionKind.QuickFix);
      redactAction.command = { command: "secretloop.redact", title: "Redact", arguments: [document.uri, finding] };
      actions.push(redactAction);

      // Named for its risk, and offered second. The clipboard is readable by
      // every running application and syncs across devices, so this is a
      // deliberate choice for one secret rather than a standing preference.
      const copyRedactAction = new vscode.CodeAction(
        "SecretLoop: Copy to clipboard, then redact",
        vscode.CodeActionKind.QuickFix
      );
      copyRedactAction.command = {
        command: "secretloop.copyAndRedact",
        title: "Copy and redact",
        arguments: [document.uri, finding],
      };
      actions.push(copyRedactAction);

      const extractAction = new vscode.CodeAction(
        "SecretLoop: Move to .env and reference it",
        vscode.CodeActionKind.QuickFix
      );
      extractAction.command = {
        command: "secretloop.extractToEnv",
        title: "Extract to .env",
        arguments: [document.uri, finding],
      };
      actions.push(extractAction);
    }

    return actions;
  }
}

async function scanWorkspace() {
  const root = requireWorkspaceRoot();
  if (!root) return;

  const config = configForFolder(root, setting<number>("entropyThreshold", 4.3));
  const buffers = openBuffers(root);
  const { scanned, generatedExcluded, outsideExcluded } = scanWorkspaceScan(root, config, {
    textFor: (p) => buffers.get(p),
  });
  log(
    `SecretLoop: workspace scan covered ${scanned.length} file(s) under ${root}` +
      (generatedExcluded > 0 ? `; ${generatedExcluded} generated file(s) excluded` : "") +
      (outsideExcluded > 0 ? `; ${outsideExcluded} file(s) resolved outside the root` : "") +
      "."
  );

  await verifyScan(scanned, "the workspace scan");
  for (const file of scanned) renderScannedFile(root, file);

  const findings = scanned.flatMap((s) => s.findings);
  vscode.window.showInformationMessage(
    workspaceScanSummary(findings, scanned.length, generatedExcluded, outsideExcluded)
  );
}

/**
 * The four buckets the text report leads with, in its order and its words.
 *
 * Two buckets could not carry the verdict: a confirmed-dead credential and a
 * refused check were both counted as "unverified", which is the one thing
 * neither of them is.
 */
function livenessCounts(findings: Finding[]): string {
  const live = findings.filter((f) => f.verifyStatus === "live").length;
  const needsLook = findings.filter((f) => f.verifyStatus === "unknown").length;
  const unchecked = findings.filter((f) => f.verifyStatus === undefined).length;
  const dead = findings.filter((f) => f.verifyStatus === "dead").length;
  return (
    `${findings.length} finding(s): ${live} confirmed live, ${needsLook} needing a look, ` +
    `${unchecked} unverified, ${dead} dead`
  );
}

/** The workspace-scan summary line, separated from showing it so it can be read back. */
export function workspaceScanSummary(
  findings: Finding[],
  fileCount: number,
  generatedExcluded = 0,
  outsideExcluded = 0
): string {
  // Through describeScope, so the editor and the CLI cannot describe the same
  // scan differently — the same reason workspace.ts exists at all.
  const scope = describeScope(fileCount, "file", { generatedExcluded, outsideExcluded });
  return findings.length > 0
    ? `SecretLoop: scanned ${scope}. ${livenessCounts(findings)}.`
    : `SecretLoop: no secrets found across ${scope}.`;
}

async function warnOnStagedSecrets() {
  if (!setting<boolean>("blockCommitOnSecret", true)) return;

  const root = requireWorkspaceRoot();
  if (!root) return;

  const gitExtension = vscode.extensions.getExtension("vscode.git")?.exports;
  if (!gitExtension) {
    vscode.window.showWarningMessage("SecretLoop: Git extension not available.");
    return;
  }

  // Same guards as everywhere else. This used to open each staged document
  // directly, skipping the size and binary checks the CLI's `staged` command
  // applies — the same divergence scanWorkspace had.
  const staged: string[] = [];
  for (const repo of gitExtension.getAPI(1).repositories) {
    for (const change of repo.state.indexChanges) {
      staged.push(path.relative(root, change.uri.fsPath).split(path.sep).join("/"));
    }
  }

  const config = configForFolder(root, setting<number>("entropyThreshold", 4.3));
  const buffers = openBuffers(root);
  const scanned = scanFiles(root, staged, config, { textFor: (p) => buffers.get(p) });
  log(`SecretLoop: staged scan covered ${scanned.length} of ${staged.length} staged file(s).`);

  await verifyScan(scanned, "the staged scan");
  for (const file of scanned) renderScannedFile(root, file);

  const findings = scanned.flatMap((s) => s.findings);
  const notice = stagedScanNotice(findings);

  if (notice.level === "error") {
    vscode.window
      .showErrorMessage(notice.message, "Scan Workspace")
      .then((choice) => {
        if (choice === "Scan Workspace") vscode.commands.executeCommand("secretloop.scanWorkspace");
      });
  } else if (notice.level === "warning") {
    vscode.window.showWarningMessage(notice.message);
  }
}

/**
 * What the staged scan tells the user, and how loudly. Which channel it goes to
 * is part of the verdict, not a detail of showing it, so both travel together.
 */
export type StagedScanNotice =
  | { level: "error" | "warning"; message: string }
  | { level: "none" };

export function stagedScanNotice(findings: Finding[]): StagedScanNotice {
  if (findings.length === 0) return { level: "none" };

  // The channel still escalates on a confirmed live credential and nothing
  // else. What changed is what the quieter message is allowed to claim.
  const live = findings.filter((f) => f.verifyStatus === "live").length;
  if (live > 0) {
    return {
      level: "error",
      message: `SecretLoop: ${live} LIVE secret(s) staged for commit. Strongly recommend fixing before pushing.`,
    };
  }
  return {
    level: "warning",
    message: `SecretLoop: staged for commit — ${livenessCounts(findings)}. Review before committing.`,
  };
}

export function deactivate() {
  diagnosticCollection.clear();
  diagnosticCollection.dispose();
}

/**
 * Resolves effective config for a document: `.secretloop.json` at the
 * workspace root wins on project policy (allowlists, excluded rules), while the
 * VS Code setting still drives the entropy threshold if the project doesn't
 * pin one. Keeping the editor and the CLI on the same config file is what stops
 * "it passed locally but CI flagged it" — the fastest way to lose trust in a
 * scanner.
 */
function workspaceConfig(document: vscode.TextDocument, threshold: number): SecretLoopConfig {
  const folder = vscode.workspace.getWorkspaceFolder(document.uri);
  if (!folder) return mergeConfig({ entropyThreshold: threshold });
  return configForFolder(folder.uri.fsPath, threshold);
}

/** The same resolution, for the commands that work on a folder rather than a document. */
/**
 * What masking the clipboard would do, decided without touching the clipboard.
 *
 * Split out from the command handler so the property can be tested at all: the
 * handler's only remaining job is read, act, tell. Two defects lived in here
 * and neither was reachable by a test while this was an inline closure.
 */
export type ClipboardMaskOutcome =
  | { kind: "too-large"; message: string }
  | { kind: "nothing-found"; message: string }
  | { kind: "masked"; masked: string; count: number; message: string };

export function maskClipboardText(text: string): ClipboardMaskOutcome {
  // The defaults, not the workspace's config. What gets masked is a property of
  // the transform, and a `.secretloop.json` carrying excludeRules or
  // `allowValues: [".*"]` used to pass every credential on the clipboard
  // through untouched under a toast reading "no secrets found". The CLI's
  // `mask` made the same mistake; both now build their rule set from one place
  // no file on disk can widen.
  const config = { ...defaultConfig };
  if (Buffer.byteLength(text, "utf8") > config.maxFileSizeBytes) {
    return {
      kind: "too-large",
      message:
        `clipboard is too large to mask (limit ${config.maxFileSizeBytes} bytes). ` +
        `Nothing was changed.`,
    };
  }
  // Same defaults as `secretloop mask`: named rules only. Masking every digest
  // and UUID on the clipboard destroys what was being copied while protecting
  // nothing.
  const findings = scanText(text, {
    config: { ...config, entropyPassEnabled: false, includeFixtures: true },
    // A `# gitleaks:allow` beside a credential on the clipboard used to leave
    // it there and then say "no secrets found" -- an affirmative claim, made
    // about the exact case where the annotation exists BECAUSE the value
    // beside it is real. See ScanOptions.honorInlineDirectives.
    honorInlineDirectives: false,
  });
  if (findings.length === 0) {
    return { kind: "nothing-found", message: "no secrets found in the clipboard." };
  }
  return {
    kind: "masked",
    masked: maskFindings(text, findings),
    count: findings.length,
    message: `masked ${findings.length} secret(s) in the clipboard.`,
  };
}

function configForFolder(folderPath: string, threshold: number): SecretLoopConfig {
  try {
    const loaded = loadConfig(folderPath);
    // A project that hasn't set a threshold defers to the user's editor setting.
    if (loaded.entropyThreshold === defaultConfig.entropyThreshold) {
      loaded.entropyThreshold = threshold;
    }
    return loaded;
  } catch (err) {
    vscode.window.showWarningMessage(`SecretLoop: ${(err as Error).message}`);
    return mergeConfig({ entropyThreshold: threshold });
  }
}

/** Unsaved editor buffers, keyed by the path a scan will look them up under. */
function openBuffers(root: string): Map<string, string> {
  const buffers = new Map<string, string>();
  for (const doc of vscode.workspace.textDocuments) {
    if (doc.uri.scheme !== "file" || !doc.uri.fsPath.startsWith(root)) continue;
    buffers.set(path.relative(root, doc.uri.fsPath).split(path.sep).join("/"), doc.getText());
  }
  return buffers;
}

/** Line starts for a scanned text, so offsets become positions without a TextDocument. */
function positionsFor(text: string): (offset: number) => vscode.Position {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (offset: number) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return new vscode.Position(lo, offset - starts[lo]);
  };
}

/** Publishes diagnostics for a file that was scanned without being opened. */
function renderScannedFile(root: string, scanned: ScannedFile): void {
  const at = positionsFor(scanned.text);
  const uri = vscode.Uri.file(path.join(root, scanned.path));
  diagnosticCollection.set(
    uri,
    scanned.findings.map((f) => {
      const diag = new vscode.Diagnostic(
        new vscode.Range(at(f.startIndex), at(f.endIndex)),
        diagnosticMessage(f),
        severityForTier(f)
      );
      diag.code = f.ruleId;
      diag.source = "SecretLoop";
      return diag;
    })
  );
}

/**
 * Verifies a completed scan in one pass and records what was transmitted.
 *
 * Shared by the workspace and staged commands: both are batch scans, and both
 * want the outbound count to be the total for the whole scan rather than a
 * running per-file figure.
 */
async function verifyScan(scanned: ScannedFile[], label: string): Promise<void> {
  const verification = resolveSetting<boolean>("enableLiveVerification", false);
  if (!verification.value) return;

  const checkable = scanned.flatMap((s) => s.findings).filter((f) => isVerifiable(f.ruleId));
  if (checkable.length === 0) return;

  log(
    `SecretLoop: live verification is on (${describeOrigin("enableLiveVerification", verification.origin)}); ` +
      `checking ${checkable.length} finding(s) across ${label}.`
  );
  const sent = await verifyScannedFiles(scanned, fetch, { cache: verificationCache });
  if (sent.length > 0) {
    const providers = [...new Set(sent.map((f) => verificationProvider(f.ruleId) ?? f.ruleId))].sort();
    log(`SecretLoop: sent ${sent.length} credential(s) to ${providers.join(", ")} across ${label}.`);
  }
}


/**
 * Reads and clears explicitly-set configuration values across every scope.
 *
 * Only explicit values count: a package default is not a credential someone
 * typed, and the manifest entries are gone anyway. Clearing targets the scope
 * that actually held the value, so a Workspace-scoped credential is removed
 * from the `.vscode/settings.json` it was committed in.
 */
function legacyCredentialStore(): LegacyCredentialStore {
  const scopes: Array<[scope: string, target: vscode.ConfigurationTarget]> = [
    ["workspace folder", vscode.ConfigurationTarget.WorkspaceFolder],
    ["workspace", vscode.ConfigurationTarget.Workspace],
    ["user", vscode.ConfigurationTarget.Global],
  ];

  const split = (key: string) => {
    const dot = key.indexOf(".");
    return { namespace: key.slice(0, dot), name: key.slice(dot + 1) };
  };

  return {
    read(key) {
      const { namespace, name } = split(key);
      const inspected = vscode.workspace.getConfiguration(namespace).inspect<string>(name);
      if (!inspected) return undefined;
      const found =
        inspected.workspaceFolderValue ?? inspected.workspaceValue ?? inspected.globalValue;
      if (!found) return undefined;
      const scope = inspected.workspaceFolderValue
        ? "workspace folder"
        : inspected.workspaceValue
          ? "workspace"
          : "user";
      return { value: found, scope };
    },
    describes(key) {
      const { namespace, name } = split(key);
      return vscode.workspace.getConfiguration(namespace).inspect<string>(name) !== undefined;
    },
    async clear(key) {
      const { namespace, name } = split(key);
      const config = vscode.workspace.getConfiguration(namespace);
      for (const [, target] of scopes) {
        try {
          await config.update(name, undefined, target);
        } catch {
          // Not every scope exists (no folder open, no workspace file); the
          // ones that do are what matter.
        }
      }
    },
  };
}

/**
 * Moves any AWS admin credential still in settings into the OS keychain.
 *
 * Confirmed against a running extension host: a value planted under
 * secretloop.awsAdminAccessKeyId, a key removed from the manifest, was read and
 * migrated. Both outcomes stay logged anyway, so "found nothing" can never
 * quietly become "could not look".
 */
async function runAwsCredentialMigration(context: vscode.ExtensionContext): Promise<void> {
  let outcome: MigrationOutcome;
  try {
    outcome = await migrateAwsAdminCredentials(context.secrets, legacyCredentialStore());
  } catch (err) {
    log(`SecretLoop: AWS admin credential migration failed: ${(err as Error).message}`);
    return;
  }

  if (outcome.status === "already-stored") {
    log("SecretLoop: AWS admin credentials already in the keychain; no migration needed.");
    return;
  }

  if (outcome.status === "absent") {
    // "Found nothing" is a verdict, and a verdict is only worth what the check
    // behind it was. Saying how many keys were actually readable is what stops
    // this becoming a confident report from something that could not look —
    // the same shape as a 403 read as a revocation.
    const unreadable = outcome.inspected.filter((k) => outcome.descriptors?.[k] === false);
    if (unreadable.length > 0) {
      log(
        `SecretLoop: could not read ${unreadable.length} of ${outcome.inspected.length} settings ` +
          `keys (${unreadable.join(", ")}), so "no credential found" does not hold for those. ` +
          `A plaintext credential could be sitting in one of them unseen.`
      );
    } else {
      log(
        `SecretLoop: no AWS admin credential in settings. All ${outcome.inspected.length} keys ` +
          `were readable and unset: ${outcome.inspected.join(", ")}.`
      );
    }
    return;
  }

  const moved = outcome.moved.map((m) => `${m.key} (${m.scope})`).join(", ");
  log(`SecretLoop: migrated AWS admin credentials out of settings: ${moved}.`);
  startupNoticeShown = claimsStartupNotice(outcome);
  vscode.window.showWarningMessage(
    `SecretLoop moved your AWS admin credentials from settings into the OS keychain and cleared the setting (${moved}). ` +
      `Treat the old value as exposed and rotate that IAM key: a credential that has been in settings.json may already be in ` +
      `Settings Sync, a committed .vscode/settings.json, or a dotfiles repository, and clearing it removes only today's copy.`
  );
}

export interface PromptResetOutcome {
  /** True when a persisted "Never" was actually cleared. */
  clearedPermanent: boolean;
  message: string;
}

/**
 * What resetting prompt preferences did, phrased for the user.
 *
 * Deliberately says nothing about credentials, baselines or stored secrets,
 * because it touches none of them — a command that resets more than its name
 * implies is its own hazard, and a message implying more than it did is the
 * same hazard with extra steps.
 */
export function describePromptReset(input: {
  hadPermanentDecline: boolean;
  verificationEnabled: boolean;
}): PromptResetOutcome {
  const cleared = input.hadPermanentDecline
    ? `Cleared your "Never" answer, so SecretLoop can offer live verification again.`
    : `There was no "Never" answer to clear; nothing was suppressing the offer.`;

  // Resetting cannot produce a prompt there is nothing to ask for, and a
  // command that appears to do nothing reads as a broken one.
  const caveat = input.verificationEnabled
    ? " Live verification is already on, so no offer will appear until you turn it off."
    : "";

  return { clearedPermanent: input.hadPermanentDecline, message: `SecretLoop: ${cleared}${caveat}` };
}

/**
 * Whether a migration outcome takes the session's one startup-notice slot.
 *
 * Only a completed migration does: it raises a warning telling the user to
 * rotate an exposed credential, which must not be stacked under anything else.
 * "absent" and "already-stored" say nothing to the user, so they must not
 * suppress the verification offer — that would silence it for every user who
 * never had a credential in settings, which is nearly everyone.
 */
export function claimsStartupNotice(outcome: MigrationOutcome): boolean {
  return outcome.status === "migrated";
}

/** Collects the admin credentials without them ever touching a settings file. */
async function promptForAwsAdminCredentials(context: vscode.ExtensionContext): Promise<void> {
  const keyId = await vscode.window.showInputBox({
    title: "SecretLoop: AWS admin access key ID",
    prompt: "An identity with iam:UpdateAccessKey, used only to deactivate leaked keys. Stored in your OS keychain.",
    ignoreFocusOut: true,
  });
  if (!keyId) return;

  const secret = await vscode.window.showInputBox({
    title: "SecretLoop: AWS admin secret access key",
    prompt: "Paired with the access key ID above. Stored in your OS keychain, never in a settings file.",
    password: true,
    ignoreFocusOut: true,
  });
  if (!secret) return;

  await context.secrets.store(AWS_ADMIN_ACCESS_KEY_ID, keyId);
  await context.secrets.store(AWS_ADMIN_SECRET_ACCESS_KEY, secret);
  vscode.window.showInformationMessage(
    "SecretLoop: AWS admin credentials stored in the OS keychain."
  );
}

/** Resolves the workspace root, or reports why we can't act without one. */
function requireWorkspaceRoot(): string | undefined {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showErrorMessage("SecretLoop: open a folder first.");
    return undefined;
  }
  return folder.uri.fsPath;
}

/**
 * Scans committed history. A secret deleted in a later commit is still in the
 * object store and still fetchable by anyone who cloned the repo, so a clean
 * working tree says nothing about whether the repo has leaked.
 */
async function scanGitHistory(): Promise<void> {
  const root = requireWorkspaceRoot();
  if (!root) return;

  const { scanHistory, isGitRepo } = await import("./history");
  if (!isGitRepo(root)) {
    vscode.window.showErrorMessage("SecretLoop: this folder is not a git repository.");
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "SecretLoop: scanning git history",
      // Only possible now the scan is genuinely async. A full-history scan on a
      // large repository is exactly what someone wants to stop.
      cancellable: true,
    },
    async (progress, token) => {
      const abort = new AbortController();
      token.onCancellationRequested(() => abort.abort());
      const config = loadConfig(root);
      let findings: Finding[] = [];
      try {
        // Throttled: a 20k-commit repository would otherwise drive 20k UI
        // updates, which is worse than useless.
        let lastReported = 0;
        findings = await scanHistory({
          config,
          repoRoot: root,
          signal: abort.signal,
          onProgress: (commits, found) => {
            if (commits - lastReported < 100) return;
            lastReported = commits;
            progress.report({ message: `${commits} commits scanned, ${found} finding(s)` });
          },
        });
      } catch (err) {
        vscode.window.showErrorMessage(`SecretLoop: ${(err as Error).message}`);
        return;
      }

      if (findings.length === 0) {
        vscode.window.showInformationMessage("SecretLoop: no secrets found in git history.");
        return;
      }

      const { render } = await import("./report");
      const doc = await vscode.workspace.openTextDocument({
        content: render(findings, "text", { redact: true, root }),
        language: "plaintext",
      });
      await vscode.window.showTextDocument(doc, { preview: false });
      vscode.window.showWarningMessage(
        `SecretLoop: ${findings.length} secret(s) found in git history. ` +
          "Rotate them — removing the file in a later commit does not remove them from the repo."
      );
    }
  );
}

/**
 * Writes every current finding to a baseline file. Lets a team adopt scanning
 * on a repo that already has findings and still fail CI on anything new —
 * without that, adoption means either a permanently red build or no scanning.
 */
async function writeBaseline(): Promise<void> {
  const root = requireWorkspaceRoot();
  if (!root) return;

  const config = loadConfig(root);
  const { listFiles, readTextFile } = await import("./walk");
  const fingerprints = new Set<string>();
  for (const rel of listFiles(root, config)) {
    const text = readTextFile(root, rel, config);
    if (text === null) continue;
    for (const f of scanText(text, { config, filePath: rel })) {
      if (f.fingerprint) fingerprints.add(f.fingerprint);
    }
  }

  const target = vscode.Uri.joinPath(vscode.Uri.file(root), ".secretloop-baseline.json");
  const body = JSON.stringify({ version: BASELINE_VERSION, fingerprints: [...fingerprints] }, null, 2) + "\n";
  await vscode.workspace.fs.writeFile(target, Buffer.from(body, "utf8"));
  vscode.window.showInformationMessage(
    `SecretLoop: baselined ${fingerprints.size} existing finding(s). New secrets will still be reported.`
  );
}


