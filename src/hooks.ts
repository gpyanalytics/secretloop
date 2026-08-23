import * as vscode from "vscode";
import * as path from "path";

const HOOK_MARKER = "# Installed by SecretLoop.";

/**
 * The pre-rebrand marker. Install and uninstall both still recognize it, so a
 * hook written by an older version is neither treated as a stranger's hook
 * (which would refuse to remove it) nor duplicated by a second install.
 */
const LEGACY_HOOK_MARKER = "# Installed by SecretGuard.";

/** True when this hook was written by either this tool or its predecessor. */
function isOurHook(existing: string): boolean {
  return existing.includes(HOOK_MARKER) || existing.includes(LEGACY_HOOK_MARKER);
}

export async function installPrecommitHook(context: vscode.ExtensionContext): Promise<void> {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage("SecretLoop: open a workspace folder first.");
    return;
  }

  const gitDir = vscode.Uri.file(path.join(workspaceFolder.uri.fsPath, ".git"));
  try {
    await vscode.workspace.fs.stat(gitDir);
  } catch {
    vscode.window.showErrorMessage("SecretLoop: no .git directory found in this workspace.");
    return;
  }

  const hookPath = vscode.Uri.file(path.join(workspaceFolder.uri.fsPath, ".git", "hooks", "pre-commit"));

  let existing = "";
  try {
    const bytes = await vscode.workspace.fs.readFile(hookPath);
    existing = Buffer.from(bytes).toString("utf8");
  } catch {
    // no existing hook
  }

  if (existing.length > 0 && !isOurHook(existing)) {
    const choice = await vscode.window.showWarningMessage(
      "A pre-commit hook already exists that wasn't installed by SecretLoop. Overwriting it will remove whatever it currently does.",
      { modal: true },
      "Append SecretLoop to it",
      "Overwrite anyway"
    );
    if (choice === "Append SecretLoop to it") {
      const appended = existing.trimEnd() + "\n\n" + hookBody(context) + "\n";
      await vscode.workspace.fs.writeFile(hookPath, Buffer.from(appended, "utf8"));
      await makeExecutable(hookPath);
      vscode.window.showInformationMessage("SecretLoop: appended to existing pre-commit hook.");
      return;
    }
    if (choice !== "Overwrite anyway") return; // cancelled
  }

  await vscode.workspace.fs.writeFile(hookPath, Buffer.from(hookBody(context) + "\n", "utf8"));
  await makeExecutable(hookPath);
  vscode.window.showInformationMessage(
    "SecretLoop: pre-commit hook installed. Staged files will be scanned before every commit."
  );
}

export async function uninstallPrecommitHook(): Promise<void> {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) return;

  const hookPath = vscode.Uri.file(path.join(workspaceFolder.uri.fsPath, ".git", "hooks", "pre-commit"));
  let existing = "";
  try {
    const bytes = await vscode.workspace.fs.readFile(hookPath);
    existing = Buffer.from(bytes).toString("utf8");
  } catch {
    vscode.window.showInformationMessage("SecretLoop: no pre-commit hook found to remove.");
    return;
  }

  if (!isOurHook(existing)) {
    vscode.window.showWarningMessage(
      "SecretLoop: the existing pre-commit hook wasn't installed by SecretLoop — leaving it alone."
    );
    return;
  }

  await vscode.workspace.fs.delete(hookPath);
  vscode.window.showInformationMessage("SecretLoop: pre-commit hook removed.");
}

function hookBody(context: vscode.ExtensionContext): string {
  const cliPath = path.join(context.extensionPath, "out", "cli.js");
  return [
    "#!/bin/sh",
    HOOK_MARKER,
    "# To skip for one commit: git commit --no-verify",
    `node "${cliPath}" staged`,
    "exit $?",
  ].join("\n");
}

async function makeExecutable(uri: vscode.Uri): Promise<void> {
  // vscode.workspace.fs has no chmod; shell out for the permission bit.
  const { execFile } = await import("child_process");
  await new Promise<void>((resolve) => {
    execFile("chmod", ["+x", uri.fsPath], () => resolve());
  });
}
