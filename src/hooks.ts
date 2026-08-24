import * as vscode from "vscode";
import * as path from "path";
import { isTracked, findGitDir } from "./walk";
import { mkdirSync, copyFileSync, writeFileSync, existsSync, renameSync, chmodSync } from "fs";

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

  const gitDirFsPath = gitDirPath(workspaceFolder.uri.fsPath);
  const foreignPath = savedForeignHookPath(gitDirFsPath);
  let chained = false;

  if (existing.length > 0 && !isOurHook(existing)) {
    // Appending was the old behaviour and it could not keep its promise: a
    // foreign hook ending in `exit 0`, using `set -e`, or calling `exec` never
    // reached the appended lines, and appending shell to a #!/usr/bin/env
    // python3 hook produced a SyntaxError on every commit — destroying a working
    // hook rather than merely failing to extend it.
    if (existsSync(foreignPath)) {
      // Something replaced our hook while a saved one was already held aside.
      // Saving this one would overwrite the original, unrecoverably — and only a
      // person can say which of the two they want.
      vscode.window.showErrorMessage(
        `SecretLoop: a hook is already saved at ${SAVED_FOREIGN_DISPLAY}, and the current ` +
          `pre-commit hook is a different one. Installing now would discard one of them. ` +
          `Keep whichever you want and remove the other, then install again.`
      );
      return;
    }
    mkdirSync(path.dirname(foreignPath), { recursive: true });
    renameSync(hookPath.fsPath, foreignPath);
    chmodSync(foreignPath, 0o755);
    chained = true;
  }

  installScannerCopy(gitDirFsPath, context.extensionPath, extensionVersion);
  await vscode.workspace.fs.writeFile(hookPath, Buffer.from(hookBody() + "\n", "utf8"));
  await makeExecutable(hookPath);
  vscode.window.showInformationMessage(
    chained
      ? `SecretLoop: pre-commit hook installed. Your existing hook was moved to ${SAVED_FOREIGN_DISPLAY} ` +
          `and now runs first; if it passes, staged files are scanned. Uninstalling restores it.`
      : existsSync(foreignPath)
        ? `SecretLoop: pre-commit hook re-installed, still chaining to ${SAVED_FOREIGN_DISPLAY}.`
        : "SecretLoop: pre-commit hook installed. Staged files will be scanned before every commit."
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

  // Restoring matters: this hook may have displaced one of theirs, and deleting
  // ours would leave the repository with no pre-commit hook at all, having
  // quietly eaten the original.
  const foreignPath = savedForeignHookPath(gitDirPath(workspaceFolder.uri.fsPath));
  if (existsSync(foreignPath)) {
    renameSync(foreignPath, hookPath.fsPath);
    chmodSync(hookPath.fsPath, 0o755);
    vscode.window.showInformationMessage(
      `SecretLoop: pre-commit hook removed, and your previous hook restored from ${SAVED_FOREIGN_DISPLAY}.`
    );
    return;
  }

  await vscode.workspace.fs.delete(hookPath);
  vscode.window.showInformationMessage(
    `SecretLoop: pre-commit hook removed. No saved hook was found at ${SAVED_FOREIGN_DISPLAY}, ` +
      `so nothing was restored — a fresh clone is the usual reason, since .git is not cloned.`
  );
}

/** Where the repository's own copy of the scanner lives, relative to its git dir. */
const HOOK_SUPPORT_DIR = "secretloop";

/** The hook we displaced, kept so uninstall can put it back. */
const SAVED_FOREIGN_HOOK = "pre-commit.foreign";
const SAVED_FOREIGN_DISPLAY = ".git/secretloop/pre-commit.foreign";

function savedForeignHookPath(gitDir: string): string {
  return path.join(gitDir, HOOK_SUPPORT_DIR, SAVED_FOREIGN_HOOK);
}

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
    'FOREIGN="$SL_DIR/pre-commit.foreign"',
    "",
    "# The hook this replaced, run first so its behaviour is unchanged: anything",
    "# it did before we existed still happens before we scan, including rewriting",
    "# and re-staging files. Running it as its own process is also what makes it",
    "# unable to skip us — set -e, exit 0 and exec are scoped to it, not to this",
    "# script — and what stops a non-shell hook being destroyed by appending.",
    "# Checked with -x because git ignores a hook it cannot execute.",
    'if [ -x "$FOREIGN" ]; then',
    '  "$FOREIGN" "$@" || exit $?',
    "fi",
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
