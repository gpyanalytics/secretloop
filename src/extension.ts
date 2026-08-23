import * as vscode from "vscode";
import { scanText, Finding, ConfidenceTier } from "./scanner";
import { loadConfig, mergeConfig, defaultConfig, legacyConfigNotice, SecretLoopConfig } from "./config";
import { redactInPlace, extractToEnv } from "./remediate";
import { isVerifiable, verifyFinding } from "./verify";
import { rotateFinding } from "./rotate";
import { installPrecommitHook, uninstallPrecommitHook } from "./hooks";
import { setting } from "./settings";


const diagnosticCollection = vscode.languages.createDiagnosticCollection("secretloop");
const findingsByDocument = new Map<string, Finding[]>();
/** Workspaces already warned about a legacy config file — warn once, not per scan. */
const legacyConfigWarned = new Set<string>();

export function activate(context: vscode.ExtensionContext) {
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

  vscode.workspace.textDocuments.forEach((doc) => scanDocument(doc));

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

      const outcome = await rotateFinding(finding);
      if (outcome.success) {
        vscode.window.showInformationMessage(`SecretLoop: ${outcome.message}`);
        const doc = await vscode.workspace.openTextDocument(docUri);
        await redactInPlace(doc, finding);
        scanDocument(doc);
      } else {
        vscode.window.showWarningMessage(`SecretLoop: ${outcome.message}`);
      }
    }),
    vscode.commands.registerCommand("secretloop.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("secretloop.scanStagedFiles", warnOnStagedSecrets),
    vscode.commands.registerCommand("secretloop.installPrecommitHook", () => installPrecommitHook(context)),
    vscode.commands.registerCommand("secretloop.uninstallPrecommitHook", uninstallPrecommitHook),
    vscode.commands.registerCommand("secretloop.scanHistory", scanGitHistory),
    vscode.commands.registerCommand("secretloop.writeBaseline", writeBaseline)
  );

  registerLegacyCommandAliases(context);

  vscode.window.showInformationMessage("SecretLoop is active and watching for secrets.");
}

async function scanDocument(document: vscode.TextDocument) {
  if (document.uri.scheme !== "file") return;

  const threshold = setting<number>("entropyThreshold", 4.3);
  const verificationEnabled = setting<boolean>("enableLiveVerification", true);

  const config = workspaceConfig(document, threshold);
  const relPath = vscode.workspace.asRelativePath(document.uri, false);
  const findings = scanText(document.getText(), { config, filePath: relPath });
  findingsByDocument.set(document.uri.toString(), findings);
  renderDiagnostics(document, findings);

  if (!verificationEnabled) return;

  // Verification is async and network-bound; render initial diagnostics
  // immediately above, then upgrade confidence in place as results land so
  // the editor never blocks on network calls.
  const fullText = document.getText();
  await Promise.all(
    findings.map(async (finding) => {
      if (!isVerifiable(finding.ruleId)) return;
      const result = await verifyFinding(finding, { fullText, fetchImpl: fetch });
      if (result === null) return; // unknown; leave as format-match
      finding.verified = result.verified;
      if (result.verified) finding.confidence = "verified-live";
    })
  );

  // Only re-render if this document is still the latest scan for its URI
  // (guards against stale async results from rapid edits).
  if (findingsByDocument.get(document.uri.toString()) === findings) {
    renderDiagnostics(document, findings);
  }
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
