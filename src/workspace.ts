import { Finding, scanText } from "./scanner";
import { SecretLoopConfig } from "./config";
import { listFilesWithExclusions, readTextFile } from "./walk";
import { VerificationCache, VerifyContext, verifyFindings } from "./verify";

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
    // what the user is actually looking at.
    const text = options.textFor?.(relPath) ?? readTextFile(root, relPath, config);
    if (text === null || text === undefined) continue;
    let suppressed = 0;
    const findings = scanText(text, {
      config,
      filePath: relPath,
      onSuppressed: (n) => (suppressed += n),
    });
    scanned.push({ path: relPath, text, findings, suppressed });
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
  };
}

export interface VerifyScanOptions {
  cache?: VerificationCache;
  concurrency?: number;
  /** Test hook: the context each finding was verified with. */
  onContext?: (finding: Finding, context: VerifyContext) => void;
}

/**
 * Verifies a whole scan in one bounded pass, and reports what actually left.
 *
 * One pass rather than one per file: a workspace scan is the widest fan-out
 * this tool has, and the returned list is the record of how many credentials
 * were transmitted across the entire scan. A per-file count would understate it
 * in the one place accuracy matters most.
 *
 * Context is resolved per finding, since the AWS verifier reads the text of the
 * file its access key came from to find the secret key beside it.
 */
export async function verifyScannedFiles(
  scanned: ScannedFile[],
  fetchImpl: typeof fetch,
  options: VerifyScanOptions = {}
): Promise<Finding[]> {
  const findings = scanned.flatMap((s) => s.findings);
  const texts = new Map(scanned.map((s) => [s.path, s.text]));
  const sent: Finding[] = [];

  await verifyFindings(
    findings,
    (finding) => {
      const context: VerifyContext = {
        fullText: texts.get(finding.file ?? "") ?? "",
        fetchImpl,
      };
      options.onContext?.(finding, context);
      return context;
    },
    {
      cache: options.cache,
      concurrency: options.concurrency,
      onOutbound: (f) => sent.push(f),
    }
  );

  return sent;
}
