import * as vscode from "vscode";
import * as path from "path";
import { isTracked, findGitDir } from "./walk";
import { mkdirSync, copyFileSync, writeFileSync, existsSync } from "fs";

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

/**
 * Installs the pre-commit hook.
 *
 * `envRelativePath` is passed in rather than read from settings here, so this
 * module stays independent of the settings namespace — and so a test can drive
 * it without stubbing the configuration API.
 */
export async function installPrecommitHook(
  context: vscode.ExtensionContext,
  envRelativePath: string,
  extensionVersion: string
): Promise<void> {
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
      const appended = existing.trimEnd() + "\n\n" + hookBody() + "\n";
      await vscode.workspace.fs.writeFile(hookPath, Buffer.from(appended, "utf8"));
      await makeExecutable(hookPath);
      vscode.window.showInformationMessage("SecretLoop: appended to existing pre-commit hook.");
      return;
    }
    if (choice !== "Overwrite anyway") return; // cancelled
  }

  installScannerCopy(gitDirPath(workspaceFolder.uri.fsPath), context.extensionPath, extensionVersion);
  await vscode.workspace.fs.writeFile(hookPath, Buffer.from(hookBody() + "\n", "utf8"));
  await makeExecutable(hookPath);
  vscode.window.showInformationMessage(
    "SecretLoop: pre-commit hook installed. Staged files will be scanned before every commit."
  );
  warnIfEnvFileTracked(workspaceFolder.uri.fsPath, envRelativePath);
}

/**
 * A tracked env file is a gap this hook cannot close, so say so while the user
 * is thinking about commit-time protection.
 *
 * The hook scans the staged diff. A tracked env file that gets modified is
 * caught — but one whose secret is already committed and unchanged never
 * appears in that diff, so the repository looks clean at every future commit.
 * Only a warning: installing a hook is not the moment a secret gets exposed,
 * and the hook is worth having either way.
 */
/** The repository's git directory, falling back to the conventional layout. */
function gitDirPath(workspaceRoot: string): string {
  return findGitDir(workspaceRoot) ?? path.join(workspaceRoot, ".git");
}

function warnIfEnvFileTracked(root: string, envRelativePath: string): void {
  if (isTracked(root, envRelativePath) !== "tracked") return;
  vscode.window.showWarningMessage(
    `SecretLoop: ${envRelativePath} is tracked by git. The hook scans staged changes, so a secret ` +
      `already committed there will never show up in one. Run \`git rm --cached ${envRelativePath}\` ` +
      `and commit that, then rotate anything it held.`
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

/** Where the repository's own copy of the scanner lives, relative to its git dir. */
const HOOK_SUPPORT_DIR = "secretloop";

/**
 * The pre-commit script.
 *
 * It embeds no path into the extension directory. That directory is version
 * stamped — `publisher.secretloop-0.1.0` — so every extension update deleted the
 * path the hook pointed at, and every commit then failed with "Cannot find
 * module" until someone worked out why. The repository keeps its own copy of the
 * bundled CLI instead, found through `git rev-parse` at run time so worktrees and
 * submodules resolve correctly too.
 *
 * It fails open. A scanner that has gone missing must not block every commit in
 * the repository: that is solved with a permanent `--no-verify` habit, which
 * disables the check even when it works. It still exits non-zero when the scan
 * runs and finds something, which is the case that matters.
 */
export function hookBody(): string {
  return [
    "#!/bin/sh",
    HOOK_MARKER,
    "# To skip for one commit: git commit --no-verify",
    "",
    'GIT_DIR_PATH="$(git rev-parse --git-dir 2>/dev/null)"',
    '[ -n "$GIT_DIR_PATH" ] || GIT_DIR_PATH=".git"',
    `SL_DIR="$GIT_DIR_PATH/${HOOK_SUPPORT_DIR}"`,
    'CLI="$SL_DIR/cli.js"',
    "",
    'if [ ! -f "$CLI" ]; then',
    '  echo "SecretLoop: scanner not found at $CLI; skipping the secret scan for this commit." >&2',
    "  echo \"  Reinstall with 'SecretLoop: Install Pre-commit Hook', or delete .git/hooks/pre-commit.\" >&2",
    "  exit 0",
    "fi",
    "",
    "if ! command -v node >/dev/null 2>&1; then",
    '  echo "SecretLoop: node is not on PATH; skipping the secret scan for this commit." >&2',
    "  exit 0",
    "fi",
    "",
    'if [ -f "$SL_DIR/cli.version" ] && [ -f "$SL_DIR/extension.version" ]; then',
    '  COPIED="$(cat "$SL_DIR/cli.version")"',
    '  INSTALLED="$(cat "$SL_DIR/extension.version")"',
    '  if [ "$COPIED" != "$INSTALLED" ]; then',
    '    echo "SecretLoop: this repository\'s scanner copy is out of date (rules from $COPIED; $INSTALLED is installed)." >&2',
    "    echo \"  Re-run 'SecretLoop: Install Pre-commit Hook' to refresh it.\" >&2",
    "  fi",
    "fi",
    "",
    'exec node "$CLI" staged',
  ].join("\n");
}

/**
 * Copies the bundled CLI into the repository and records the version copied.
 *
 * Re-copying on every install is deliberate; refreshing automatically on
 * activation would mean a ~460KB write per window open. The stamp is what makes
 * the resulting staleness visible rather than silent.
 */
function installScannerCopy(
  gitDir: string,
  extensionPath: string,
  extensionVersion: string
): void {
  const supportDir = path.join(gitDir, HOOK_SUPPORT_DIR);
  mkdirSync(supportDir, { recursive: true });
  copyFileSync(path.join(extensionPath, "out", "cli.js"), path.join(supportDir, "cli.js"));
  writeFileSync(path.join(supportDir, "cli.version"), `${extensionVersion}\n`, "utf8");
  writeFileSync(path.join(supportDir, "extension.version"), `${extensionVersion}\n`, "utf8");
}

/**
 * Records the running extension's version so the hook can notice its copy is
 * behind. Only where our hook is already installed — a repository that never
 * asked for one gets nothing written into its git directory.
 */
export function refreshHookVersionStamp(workspaceRoot: string, extensionVersion: string): void {
  const gitDir = findGitDir(workspaceRoot) ?? path.join(workspaceRoot, ".git");
  const supportDir = path.join(gitDir, HOOK_SUPPORT_DIR);
  if (!existsSync(path.join(supportDir, "cli.js"))) return;
  writeFileSync(path.join(supportDir, "extension.version"), `${extensionVersion}\n`, "utf8");
}

async function makeExecutable(uri: vscode.Uri): Promise<void> {
  // vscode.workspace.fs has no chmod; shell out for the permission bit.
  const { execFile } = await import("child_process");
  await new Promise<void>((resolve) => {
    execFile("chmod", ["+x", uri.fsPath], () => resolve());
  });
}
