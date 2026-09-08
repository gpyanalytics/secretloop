import { Finding, scanText } from "./scanner";
import { SecretLoopConfig } from "./config";
import {
  listFilesWithExclusions,
  readTextFileResult,
  readBinaryCandidate,
  SkipReason,
} from "./walk";
import {
  detectPkcs12Bytes,
  pkcs12HeaderAccepts,
  PKCS12_HEADER_BYTES,
} from "./pkcs12";
import {
  openArchive,
  archiveHeaderAccepts,
  displayPath,
  ArchiveSource,
  ARCHIVE_HEADER_BYTES,
} from "./archive";
import { classifyPath } from "./config";

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
  /**
   * Texts (this file, or its archive members) recognized as API description
   * documents and scanned without the generic entropy pass. 0 or 1 for a plain
   * file; a per-member sum for an archive. Absent means none were counted.
   */
  apiDocumentsScoped?: number;
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
    // The file-level PKCS#12 detector runs first and independently. It has its
    // own non-dereferencing, size-gated read (see readBinaryCandidate), because
    // a DER container is NUL-dense and never survives the text path's binary
    // check -- so no SecretRule could ever see one. Content-driven and
    // extension-independent: a renamed .bin still reports.
    const binary = detectPkcs12(root, relPath, config);

    // The container layer, one level deep, beside the PKCS#12 hook and through
    // the same non-dereferencing, size-gated read. An archive is scanned as
    // ONE file whose findings come from its members; nothing is extracted.
    const archive = binary ? null : scanArchive(root, relPath, config, options);
    if (archive) {
      scanned.push(archive);
      continue;
    }

    // An open buffer wins over disk, and is scanned whatever its size: it is
    // what the user is actually looking at -- and it is never a skip, because
    // it is already text.
    let text = options.textFor?.(relPath);
    if (text === undefined) {
      const read = readTextFileResult(root, relPath, config);
      if (!("text" in read)) {
        // A container the binary detector reported was scanned, so it is not a
        // skip. Counting it as "binary or unreadable" as well would disclose a
        // file as unscanned in the same run that reports a finding from it.
        if (binary) {
          scanned.push({
            path: relPath,
            text: "",
            findings: [binary],
            suppressed: 0,
            fixtureSuppressed: 0,
            apiDocumentsScoped: 0,
          });
          continue;
        }
        options.onSkipped?.(read.skipped);
        continue;
      }
      text = read.text;
    }
    let suppressed = 0;
    let fixtureSuppressed = 0;
    let apiDocumentsScoped = 0;
    const findings = scanText(text, {
      config,
      filePath: relPath,
      onSuppressed: (n) => (suppressed += n),
      onFixtureSuppressed: (n) => (fixtureSuppressed += n),
      onApiDocumentScoped: () => apiDocumentsScoped++,
    });
    scanned.push({
      path: relPath,
      text,
      findings: binary ? [binary, ...findings] : findings,
      suppressed,
      fixtureSuppressed,
      apiDocumentsScoped,
    });
  }
  return scanned;
}

/**
 * The PKCS#12 container check for one path, or null.
 *
 * Kept beside the text scan rather than in a second pipeline: findings from
 * both reach the same ScannedFile list, so report, SARIF, baseline and MCP
 * serialization are untouched.
 */
function detectPkcs12(root: string, relPath: string, config: SecretLoopConfig) {
  const candidate = readBinaryCandidate(
    root,
    relPath,
    config,
    pkcs12HeaderAccepts,
    PKCS12_HEADER_BYTES
  );
  if (!("bytes" in candidate)) return null;
  return detectPkcs12Bytes(candidate.bytes, relPath);
}

/**
 * One outer archive as a ScannedFile, or null when the path is not a supported
 * archive (the caller then treats it exactly as before).
 *
 * Every member goes through the decision a file goes through, in the same
 * order: the PKCS#12 structural detector on its bytes, then the NUL heuristic,
 * then scanText -- which brings the named rules, inline directives, fixture
 * suppression, encoded-v1 decoding and the configured entropy mode with it.
 * The member's display path is what scanText sees as `filePath`, so the
 * project's excludePaths and fixture segments apply to members through the
 * one glob engine that exists. Skipped members are disclosed through the
 * existing skip reasons.
 */
function scanArchive(
  root: string,
  relPath: string,
  config: SecretLoopConfig,
  options: ScanFilesOptions
): ScannedFile | null {
  const candidate = readBinaryCandidate(root, relPath, config, archiveHeaderAccepts, ARCHIVE_HEADER_BYTES);
  if (!("bytes" in candidate)) return null;
  const listing = openArchive(candidate.bytes, relPath, config.maxFileSizeBytes);
  if (!listing) return null;

  const findings: Finding[] = [];
  let suppressed = 0;
  let fixtureSuppressed = 0;
  let apiDocumentsScoped = 0;
  for (const entry of listing.members) {
    const source: ArchiveSource = {
      kind: "archive-member",
      container: relPath,
      containerKind: listing.containerKind,
      member: entry.member,
    };
    const filePath = displayPath(source);
    if (classifyPath(filePath, config) !== "none") continue;

    const container = detectPkcs12Bytes(entry.bytes, filePath, source);
    if (container) findings.push(container);
    if (entry.bytes.subarray(0, 8000).includes(0)) {
      if (!container) options.onSkipped?.("unreadable");
      continue;
    }
    findings.push(
      ...scanText(entry.bytes.toString("utf8"), {
        config,
        filePath,
        source,
        onSuppressed: (n) => (suppressed += n),
        onFixtureSuppressed: (n) => (fixtureSuppressed += n),
        // Classified on the member's own path and text (scanText reads
        // `source.member`), never on the container's name.
        onApiDocumentScoped: () => apiDocumentsScoped++,
      })
    );
  }
  for (let i = 0; i < listing.skipped.oversized; i++) options.onSkipped?.("oversized");
  for (let i = 0; i < listing.skipped.unreadable; i++) options.onSkipped?.("unreadable");
  return { path: relPath, text: "", findings, suppressed, fixtureSuppressed, apiDocumentsScoped };
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
