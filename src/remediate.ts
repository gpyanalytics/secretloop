import * as vscode from "vscode";
import * as path from "path";
import { Finding } from "./scanner";
import { isTracked } from "./walk";

/** Derives a reasonable env var name from the rule/description, e.g. "AWS_ACCESS_KEY". */
export function suggestEnvVarName(finding: Finding, existingNames: Set<string>): string {
  const base = finding.ruleId
    .replace(/-/g, "_")
    .toUpperCase()
    .replace(/[^A-Z0-9_]/g, "");
  let candidate = base;
  let suffix = 1;
  while (existingNames.has(candidate)) {
    candidate = `${base}_${++suffix}`;
  }
  return candidate;
}

export interface RedactOptions {
  /**
   * Put the original value on the system clipboard before replacing it.
   *
   * Off by default, and deliberately not a setting. The system clipboard is
   * readable by every running application and syncs across devices on macOS and
   * Windows, so copying a live credential there is a real exposure — but it is
   * also genuinely useful when you are moving the value to a password manager.
   * That makes it a per-secret decision, not a per-user preference, so the
   * choice lives in the quick-fix menu where the context is.
   */
  copyToClipboard?: boolean;
}

/**
 * Whether the finding's offsets still address the secret they were found at.
 *
 * A finding carries offsets from the scan that produced it, and the document
 * can move underneath them — the editor debounces a rescan by 400ms, so a
 * lightbulb raised before an edit still carries pre-edit offsets. positionAt
 * clamps rather than throwing, so a stale span quietly addresses whatever
 * happens to sit there now: 24 characters of unrelated code get replaced with
 * the placeholder, the credential stays in the file, and a notification says it
 * is gone.
 *
 * This is the offset bug that d-flag indices fixed in the scanner, one layer
 * up. Fixing where the offset comes from does nothing about how long it stays
 * true.
 */
function spanStillHolds(document: vscode.TextDocument, finding: Finding): boolean {
  return document.getText().slice(finding.startIndex, finding.endIndex) === finding.value;
}

const STALE_SPAN_MESSAGE =
  "SecretLoop: this file has changed since it was scanned, so the finding no longer points at the secret. " +
  "Nothing was modified. Re-scan the file and try again.";

/**
 * Replaces the secret in the document with a redaction placeholder.
 *
 * Returns whether the secret was actually replaced, so a caller does not have
 * to infer it from the absence of a thrown error.
 */
export async function redactInPlace(
  document: vscode.TextDocument,
  finding: Finding,
  options: RedactOptions = {}
): Promise<boolean> {
  // Before the clipboard, not just before the edit. Copy-then-redact copies
  // first, so checking later would put a live credential on a syncing clipboard
  // for a redaction that was never going to happen.
  if (!spanStillHolds(document, finding)) {
    vscode.window.showErrorMessage(STALE_SPAN_MESSAGE);
    return false;
  }

  const copied = options.copyToClipboard === true;
  // Before the edit: afterwards the document holds the placeholder, not the value.
  if (copied) await vscode.env.clipboard.writeText(finding.value);

  const startPos = document.positionAt(finding.startIndex);
  const endPos = document.positionAt(finding.endIndex);
  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, new vscode.Range(startPos, endPos), "[REDACTED_BY_SECRETLOOP]");

  // applyEdit reports a declined edit — a read-only file, a document that moved
  // under it — by returning false. Discarding that return value meant a
  // "Secret redacted." on a file that still contains the secret.
  const applied = await vscode.workspace.applyEdit(edit);
  if (!applied) {
    vscode.window.showErrorMessage(
      copied
        ? "SecretLoop: the edit could not be applied, so the secret is still in the file — and it is now also on your clipboard. Clear the clipboard, and check whether the file is read-only."
        : "SecretLoop: the edit could not be applied, so the secret is still in the file. Check whether it is read-only."
    );
    return false;
  }

  vscode.window.showInformationMessage(
    copied
      ? "Secret redacted and copied to the clipboard. Paste it somewhere safe (like a password manager) now — anything running on this machine can read the clipboard."
      : "Secret redacted. Undo restores it if you still need the value."
  );
  return true;
}

/** Moves the secret into the workspace .env file and replaces the source occurrence with an env reference. */
export async function extractToEnv(
  document: vscode.TextDocument,
  finding: Finding,
  envRelativePath: string
): Promise<boolean> {
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  if (!workspaceFolder) {
    vscode.window.showErrorMessage("SecretLoop: no workspace folder open, can't create .env file.");
    return false;
  }

  // First, and for the same reason the tracked-.env check is early: nothing has
  // been written yet, so refusing costs nothing and leaves no partial state.
  if (!spanStillHolds(document, finding)) {
    vscode.window.showErrorMessage(STALE_SPAN_MESSAGE);
    return false;
  }

  // Before any write. A .gitignore entry has no effect on a file git already
  // tracks, so extracting into one would move the secret out of a file the
  // developer is looking at and into one they now believe is safe — staged for
  // the next commit, with a success notification on screen.
  //
  // Refusing costs nothing here precisely because nothing has been written yet,
  // and the remedy is one command. "unknown" — no git, no repository — is not a
  // reason to refuse: a check that could not run has proven nothing.
  if (isTracked(workspaceFolder.uri.fsPath, envRelativePath) === "tracked") {
    vscode.window.showErrorMessage(
      `SecretLoop: ${envRelativePath} is tracked by git, so putting a secret in it would commit the secret. ` +
        `Adding it to .gitignore does not help — that has no effect on a file git already tracks. ` +
        `Run \`git rm --cached ${envRelativePath}\` and commit that first, then extract again.`
    );
    return false;
  }

  const envUri = vscode.Uri.file(path.join(workspaceFolder.uri.fsPath, envRelativePath));
  let existingEnvText = "";
  const existingNames = new Set<string>();
  try {
    const bytes = await vscode.workspace.fs.readFile(envUri);
    existingEnvText = Buffer.from(bytes).toString("utf8");
    for (const line of existingEnvText.split("\n")) {
      const m = line.match(/^([A-Z0-9_]+)=/);
      if (m) existingNames.add(m[1]);
    }
  } catch {
    // File doesn't exist yet; that's fine.
  }

  const varName = suggestEnvVarName(finding, existingNames);
  const newEnvLine = `${varName}=${finding.value}\n`;
  const updatedEnvText = existingEnvText.length > 0 && !existingEnvText.endsWith("\n")
    ? existingEnvText + "\n" + newEnvLine
    : existingEnvText + newEnvLine;

  // The source edit goes first, and .env is written only once it lands.
  //
  // The old order wrote .env first. A declined edit then left the credential in
  // two files instead of one, under a notification saying it had been moved —
  // an extraction that doubled the exposure and reported success. Reading .env
  // above is safe to do early because it only reads; the value is held in
  // memory here, so nothing is lost by writing it after.
  const replacement = languageAwareEnvReference(document.languageId, varName);
  const startPos = document.positionAt(finding.startIndex);
  const endPos = document.positionAt(finding.endIndex);
  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, new vscode.Range(startPos, endPos), replacement);

  const applied = await vscode.workspace.applyEdit(edit);
  if (!applied) {
    vscode.window.showErrorMessage(
      `SecretLoop: the reference could not be inserted, so nothing was written to ${envRelativePath} ` +
        `and the secret is where it was. Check whether the file is read-only.`
    );
    return false;
  }

  try {
    await vscode.workspace.fs.writeFile(envUri, Buffer.from(updatedEnvText, "utf8"));
  } catch (err) {
    // The source now references a variable that does not exist yet. Say so
    // precisely: the value is still recoverable, but only until the undo stack
    // is gone.
    vscode.window.showErrorMessage(
      `SecretLoop: the reference to ${varName} was inserted, but ${envRelativePath} could not be written ` +
        `(${(err as Error).message}). Undo the edit to recover the value before doing anything else.`
    );
    return false;
  }

  try {
    await ensureGitignored(workspaceFolder.uri, envRelativePath);
  } catch (err) {
    vscode.window.showWarningMessage(
      `SecretLoop: the secret is now in ${envRelativePath}, but .gitignore could not be updated ` +
        `(${(err as Error).message}). Add ${envRelativePath} to it before you commit.`
    );
    return true;
  }

  vscode.window.showInformationMessage(
    `Secret moved to ${envRelativePath} as ${varName} and reference inserted.`
  );
  return true;
}

function languageAwareEnvReference(languageId: string, varName: string): string {
  switch (languageId) {
    case "python":
      return `os.environ["${varName}"]`;
    case "go":
      return `os.Getenv("${varName}")`;
    case "java":
      return `System.getenv("${varName}")`;
    case "ruby":
      return `ENV["${varName}"]`;
    default:
      // JS/TS and generic fallback
      return `process.env.${varName}`;
  }
}

async function ensureGitignored(workspaceRoot: vscode.Uri, envRelativePath: string): Promise<void> {
  const gitignoreUri = vscode.Uri.file(path.join(workspaceRoot.fsPath, ".gitignore"));
  let text = "";
  try {
    const bytes = await vscode.workspace.fs.readFile(gitignoreUri);
    text = Buffer.from(bytes).toString("utf8");
  } catch {
    // no .gitignore yet
  }
  const lines = text.split("\n").map((l) => l.trim());
  if (lines.includes(envRelativePath)) return;
  const updated = text.length > 0 && !text.endsWith("\n") ? text + "\n" : text;
  await vscode.workspace.fs.writeFile(
    gitignoreUri,
    Buffer.from(updated + envRelativePath + "\n", "utf8")
  );
}
