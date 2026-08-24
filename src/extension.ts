import * as vscode from "vscode";
import { scanText, Finding, ConfidenceTier } from "./scanner";
import { loadConfig, mergeConfig, defaultConfig, legacyConfigNotice, SecretLoopConfig } from "./config";
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
import { installPrecommitHook, uninstallPrecommitHook } from "./hooks";
import { setting, SETTINGS_NAMESPACE } from "./settings";


const diagnosticCollection = vscode.languages.createDiagnosticCollection("secretloop");
const findingsByDocument = new Map<string, Finding[]>();
/** Workspaces already warned about a legacy config file — warn once, not per scan. */
const legacyConfigWarned = new Set<string>();
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

export function activate(context: vscode.ExtensionContext) {
  extensionContext = context;
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
      installPrecommitHook(context, setting<string>("envFilePath", ".env"))
    ),
    vscode.commands.registerCommand("secretloop.uninstallPrecommitHook", uninstallPrecommitHook),
    vscode.commands.registerCommand("secretloop.scanHistory", scanGitHistory),
    vscode.commands.registerCommand("secretloop.writeBaseline", writeBaseline),
    vscode.commands.registerCommand("secretloop.setAwsAdminCredentials", () =>
      promptForAwsAdminCredentials(context)
    ),
    vscode.commands.registerCommand("secretloop.clearAwsAdminCredentials", async () => {
      await context.secrets.delete(AWS_ADMIN_ACCESS_KEY_ID);
      await context.secrets.delete(AWS_ADMIN_SECRET_ACCESS_KEY);
      vscode.window.showInformationMessage("SecretLoop: AWS admin credentials removed from the keychain.");
    })
  );

  registerLegacyCommandAliases(context);


  vscode.window.showInformationMessage("SecretLoop is active and watching for secrets.");
}

async function scanDocument(document: vscode.TextDocument) {
  if (document.uri.scheme !== "file") return;

  const threshold = setting<number>("entropyThreshold", 4.3);
  const verificationEnabled = setting<boolean>("enableLiveVerification", false);

  const config = workspaceConfig(document, threshold);
  const relPath = vscode.workspace.asRelativePath(document.uri, false);
  const findings = scanText(document.getText(), { config, filePath: relPath });
  findingsByDocument.set(document.uri.toString(), findings);
  renderDiagnostics(document, findings);

  if (!verificationEnabled) {
    await offerVerification(document, findings);
    return;
  }

  // Verification is async and network-bound; render initial diagnostics
  // immediately above, then upgrade confidence in place as results land so
  // the editor never blocks on network calls.
  const fullText = document.getText();
  await verifyFindings(findings, { fullText, fetchImpl: fetch }, { cache: verificationCache });

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
async function offerVerification(document: vscode.TextDocument, findings: Finding[]): Promise<void> {
  if (startupNoticeShown) return; // a migration notice already spoke this session
  if (verificationDeclinedThisSession || verificationPromptShown) return;
  if (extensionContext?.globalState.get<boolean>(VERIFICATION_PROMPT_DECLINED_KEY)) return;

  const candidate = findings.find((f) => isVerifiable(f.ruleId));
  if (!candidate) return;

  const provider = verificationProvider(candidate.ruleId);
  if (!provider) return; // never ask permission to contact an unnamed party

  verificationPromptShown = true;
  const choice = await vscode.window.showInformationMessage(
    `SecretLoop can confirm whether this ${candidate.description} is still active ` +
      `by making a read-only call to ${provider}. Enable live verification?`,
    "Enable",
    "Not now",
    "Never"
  );

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
    const diag = new vscode.Diagnostic(range, diagnosticMessage(f), severityForTier(f.confidence));
    diag.code = f.ruleId;
    diag.source = "SecretLoop";
    return diag;
  });
  diagnosticCollection.set(document.uri, diagnostics);
}

function diagnosticMessage(f: Finding): string {
  switch (f.confidence) {
    case "verified-live":
      return `LIVE secret confirmed: ${f.description}. This credential is currently active.`;
    case "format-match":
      return `Possible secret: ${f.description} (format match, not yet verified live).`;
    case "entropy-heuristic":
      return `Possible secret: ${f.description}. Low-confidence heuristic match — review before acting.`;
  }
}

function severityForTier(tier: ConfidenceTier): vscode.DiagnosticSeverity {
  switch (tier) {
    case "verified-live":
      return vscode.DiagnosticSeverity.Error;
    case "format-match":
      return vscode.DiagnosticSeverity.Warning;
    case "entropy-heuristic":
      return vscode.DiagnosticSeverity.Hint;
  }
}

class SecretCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(document: vscode.TextDocument, range: vscode.Range): vscode.CodeAction[] {
    const findings = findingsByDocument.get(document.uri.toString()) ?? [];
    const actions: vscode.CodeAction[] = [];

    for (const finding of findings) {
      const findingRange = new vscode.Range(
        document.positionAt(finding.startIndex),
        document.positionAt(finding.endIndex)
      );
      if (!findingRange.intersection(range)) continue;

      if (finding.confidence === "verified-live" && isVerifiable(finding.ruleId)) {
        const rotateAction = new vscode.CodeAction(
          "SecretLoop: Rotate / revoke this LIVE credential",
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
  const files = await vscode.workspace.findFiles("**/*", "**/{node_modules,dist,out,.git,build}/**");
  let liveCount = 0;
  let otherCount = 0;

  for (const uri of files) {
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      await scanDocument(doc);
      const findings = findingsByDocument.get(doc.uri.toString()) ?? [];
      liveCount += findings.filter((f) => f.confidence === "verified-live").length;
      otherCount += findings.filter((f) => f.confidence !== "verified-live").length;
    } catch {
      // binary or unreadable; skip
    }
  }

  const total = liveCount + otherCount;
  vscode.window.showInformationMessage(
    total > 0
      ? `SecretLoop: ${liveCount} verified LIVE secret(s), ${otherCount} unverified/heuristic finding(s) across the workspace.`
      : "SecretLoop: no secrets found in workspace scan."
  );
}

async function warnOnStagedSecrets() {
  if (!setting<boolean>("blockCommitOnSecret", true)) return;

  const gitExtension = vscode.extensions.getExtension("vscode.git")?.exports;
  if (!gitExtension) {
    vscode.window.showWarningMessage("SecretLoop: Git extension not available.");
    return;
  }
  const api = gitExtension.getAPI(1);
  let liveCount = 0;
  let otherCount = 0;

  for (const repo of api.repositories) {
    for (const change of repo.state.indexChanges) {
      try {
        const doc = await vscode.workspace.openTextDocument(change.uri);
        await scanDocument(doc);
        const findings = findingsByDocument.get(doc.uri.toString()) ?? [];
        liveCount += findings.filter((f) => f.confidence === "verified-live").length;
        otherCount += findings.filter((f) => f.confidence !== "verified-live").length;
      } catch {
        // skip unreadable/binary
      }
    }
  }

  if (liveCount > 0) {
    vscode.window
      .showErrorMessage(
        `SecretLoop: ${liveCount} LIVE secret(s) staged for commit. Strongly recommend fixing before pushing.`,
        "Scan Workspace"
      )
      .then((choice) => {
        if (choice === "Scan Workspace") vscode.commands.executeCommand("secretloop.scanWorkspace");
      });
  } else if (otherCount > 0) {
    vscode.window.showWarningMessage(
      `SecretLoop: ${otherCount} unverified possible secret(s) staged. Review before committing.`
    );
  }
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
  try {
    const notice = legacyConfigNotice(folder.uri.fsPath);
    if (notice && !legacyConfigWarned.has(folder.uri.fsPath)) {
      legacyConfigWarned.add(folder.uri.fsPath);
      vscode.window.showWarningMessage(`SecretLoop: ${notice}`);
    }
    const loaded = loadConfig(folder.uri.fsPath);
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
 * See migrateAwsAdminCredentials in rotate.ts for the caveat this depends on:
 * reading an unregistered key through inspect() is documented to work but has
 * not been confirmed against a running extension host. Both outcomes are logged
 * so a manual check can tell "found nothing" from "there was nothing".
 */
async function runAwsCredentialMigration(context: vscode.ExtensionContext): Promise<void> {
  let outcome: MigrationOutcome;
  try {
    outcome = await migrateAwsAdminCredentials(context.secrets, legacyCredentialStore());
  } catch (err) {
    console.log(`SecretLoop: AWS admin credential migration failed: ${(err as Error).message}`);
    return;
  }

  if (outcome.status === "already-stored") {
    console.log("SecretLoop: AWS admin credentials already in the keychain; no migration needed.");
    return;
  }

  if (outcome.status === "absent") {
    console.log(
      `SecretLoop: no AWS admin credential found in settings. Inspected: ${outcome.inspected.join(", ")}.`
    );
    return;
  }

  const moved = outcome.moved.map((m) => `${m.key} (${m.scope})`).join(", ");
  console.log(`SecretLoop: migrated AWS admin credentials out of settings: ${moved}.`);
  startupNoticeShown = true;
  vscode.window.showWarningMessage(
    `SecretLoop moved your AWS admin credentials from settings into the OS keychain and cleared the setting (${moved}). ` +
      `Treat the old value as exposed and rotate that IAM key: a credential that has been in settings.json may already be in ` +
      `Settings Sync, a committed .vscode/settings.json, or a dotfiles repository, and clearing it removes only today's copy.`
  );
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
    { location: vscode.ProgressLocation.Notification, title: "SecretLoop: scanning git history", cancellable: false },
    async (progress) => {
      const config = loadConfig(root);
      let findings: Finding[] = [];
      try {
        findings = scanHistory({
          config,
          repoRoot: root,
          onProgress: (commits, found) =>
            progress.report({ message: `${commits} commits scanned, ${found} finding(s)` }),
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
  const body = JSON.stringify({ version: 1, fingerprints: [...fingerprints] }, null, 2) + "\n";
  await vscode.workspace.fs.writeFile(target, Buffer.from(body, "utf8"));
  vscode.window.showInformationMessage(
    `SecretLoop: baselined ${fingerprints.size} existing finding(s). New secrets will still be reported.`
  );
}


/**
 * Commands are canonically `secretloop.*` — that is what the manifest declares
 * and the Command Palette shows. Each pre-rebrand `secretguard.*` id stays
 * registered as a forwarder, because a command id is a contract with the user's
 * own `keybindings.json` and `tasks.json`; dropping the old ids would break
 * custom keybindings with no error message pointing at the cause.
 */
const ALIASED_COMMANDS = [
  "redact",
  "copyAndRedact",
  "extractToEnv",
  "rotate",
  "scanWorkspace",
  "scanStagedFiles",
  "installPrecommitHook",
  "uninstallPrecommitHook",
  "scanHistory",
  "writeBaseline",
];

function registerLegacyCommandAliases(context: vscode.ExtensionContext): void {
  for (const name of ALIASED_COMMANDS) {
    context.subscriptions.push(
      vscode.commands.registerCommand(`secretguard.${name}`, (...args: unknown[]) =>
        vscode.commands.executeCommand(`secretloop.${name}`, ...args)
      )
    );
  }
}
