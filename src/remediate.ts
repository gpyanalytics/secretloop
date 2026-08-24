import * as vscode from "vscode";
import * as path from "path";
import { Finding } from "./scanner";

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

/** Replaces the secret in the document with a redaction placeholder. */
export async function redactInPlace(
  document: vscode.TextDocument,
  finding: Finding,
  options: RedactOptions = {}
): Promise<void> {
  const copied = options.copyToClipboard === true;
  // Before the edit: afterwards the document holds the placeholder, not the value.
  if (copied) await vscode.env.clipboard.writeText(finding.value);

  const startPos = document.positionAt(finding.startIndex);
  const endPos = document.positionAt(finding.endIndex);
  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, new vscode.Range(startPos, endPos), "[REDACTED_BY_SECRETLOOP]");
  await vscode.workspace.applyEdit(edit);

  vscode.window.showInformationMessage(
    copied
      ? "Secret redacted and copied to the clipboard. Paste it somewhere safe (like a password manager) now — anything running on this machine can read the clipboard."
      : "Secret redacted. Undo restores it if you still need the value."
  );
}

/** Moves the secret into the workspace .env file and replaces the source occurrence with an env reference. */
export async function extractToEnv(
  document: vscode.TextDocument,
  finding: Finding,
  envRelativePath: string
): Promise<void> {
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  if (!workspaceFolder) {
    vscode.window.showErrorMessage("SecretLoop: no workspace folder open, can't create .env file.");
    return;
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

  await vscode.workspace.fs.writeFile(envUri, Buffer.from(updatedEnvText, "utf8"));
  await ensureGitignored(workspaceFolder.uri, envRelativePath);

  const replacement = languageAwareEnvReference(document.languageId, varName);
  const startPos = document.positionAt(finding.startIndex);
  const endPos = document.positionAt(finding.endIndex);
  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, new vscode.Range(startPos, endPos), replacement);
  await vscode.workspace.applyEdit(edit);

  vscode.window.showInformationMessage(
    `Secret moved to ${envRelativePath} as ${varName} and reference inserted.`
  );
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
