import { Finding, scanText } from "./scanner";
import { SecretLoopConfig } from "./config";
import { listFilesWithExclusions, readTextFileResult, SkipReason } from "./walk";

/**
 * Scanning a tree, through one path for every caller.
 *
 * The editor and the CLI used to enumerate differently: the CLI went through
 * listFiles and readTextFile, honouring excludePaths, maxFileSizeBytes,
 * .gitignore and the binary check, while the editor called
 * findFiles("**\/*", <hardcoded>) and opened every match as a TextDocument.
 * A path excluded in .secretloop.json was therefore scanned in the editor and
 * not in CI — exactly the "passed locally, failed in CI" divergence the config
 * comment claims cannot happen. Nothing here imports vscode, so both sides can
 * use it and neither can drift.
 */
export interface ScannedFile {
  /** Repo-relative, forward-slashed. */
  path: string;
  text: string;
  findings: Finding[];
  /**
   * Findings this file dropped to an inline directive, for the disclosure.
   * Optional so a caller constructing a ScannedFile by hand need not know
   * about it; absent means none were counted, not that none occurred.
   */
  suppressed?: number;
  /** Generic findings dropped because this file is test/fixture material. */
  fixtureSuppressed?: number;
}

export interface ScanFilesOptions {
  /**
   * Text to scan instead of what is on disk.
   *
   * An editor holds unsaved changes that no disk read can see, so without this
   * a workspace scan reports the saved version: it misses a secret the user is
   * looking at, and reports one they have already removed. Returning undefined
   * falls back to disk.
   */
  textFor?: (relPath: string) => string | undefined;
  /**
   * Called once per file that was in scope but produced no text.
   *
   * The counterpart to onSuppressed and onFixtureSuppressed, and the last of
   * the skips that was not disclosed. Only this layer sees a file disappear
   * between the enumeration and the scan, so a caller handed the ScannedFile
   * list cannot reconstruct how many were dropped -- and a scan that read 20 of
   * 500 files reads exactly like one that had 20 files.
   */
  onSkipped?: (reason: SkipReason) => void;
}

/** Scans a caller-supplied list — the staged set, say — through the same guards. */
export function scanFiles(
  root: string,
  files: string[],
  config: SecretLoopConfig,
  options: ScanFilesOptions = {}
): ScannedFile[] {
  const scanned: ScannedFile[] = [];
  for (const relPath of files) {
    // An open buffer wins over disk, and is scanned whatever its size: it is
    // what the user is actually looking at -- and it is never a skip, because
    // it is already text.
    let text = options.textFor?.(relPath);
    if (text === undefined) {
      const read = readTextFileResult(root, relPath, config);
      if (!("text" in read)) {
        options.onSkipped?.(read.skipped);
        continue;
      }
      text = read.text;
    }
    let suppressed = 0;
    let fixtureSuppressed = 0;
    const findings = scanText(text, {
      config,
      filePath: relPath,
      onSuppressed: (n) => (suppressed += n),
      onFixtureSuppressed: (n) => (fixtureSuppressed += n),
    });
    scanned.push({ path: relPath, text, findings, suppressed, fixtureSuppressed });
  }
  return scanned;
}

/** Scans everything in scope for the project, per its own configuration. */
export function scanWorkspaceFiles(
  root: string,
  config: SecretLoopConfig,
  options: ScanFilesOptions = {}
): ScannedFile[] {
  return scanWorkspaceScan(root, config, options).scanned;
}

export interface WorkspaceScan {
  scanned: ScannedFile[];
  /** Files the generated-file group kept out, for the scope disclosure. */
  generatedExcluded: number;
  /**
   * Files whose realpath resolved outside the scan root. Surfaced here because
   * the editor discloses the same sentence the CLI does, and a count the walker
   * produced but nothing carried is a skip nobody is told about.
   */
  outsideExcluded: number;
}

/**
 * The same scan, with the number of generated files it skipped.
 *
 * Separate from scanWorkspaceFiles so every existing caller keeps its return
 * type; a caller that wants to disclose the skips asks for them.
 */
export function scanWorkspaceScan(
  root: string,
  config: SecretLoopConfig,
  options: ScanFilesOptions = {}
): WorkspaceScan {
  const listed = listFilesWithExclusions(root, config);
  return {
    scanned: scanFiles(root, listed.files, config, options),
    generatedExcluded: listed.generatedExcluded,
    outsideExcluded: listed.outsideExcluded,
  };
}
