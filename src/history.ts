import { spawnSync } from "child_process";
import { Finding, scanText } from "./scanner";
import { SecretLoopConfig, isPathExcluded } from "./config";

/**
 * Scans git history for secrets that were committed at some point, even if
 * they've since been deleted from the working tree. This matters because
 * removing a secret in a later commit does nothing — it's still fetchable from
 * the object store by anyone who has ever cloned the repo. A working-tree-only
 * scanner reports "clean" on a repo whose entire credential set is one
 * `git log -p` away.
 */

export interface HistoryScanOptions {
  config: SecretLoopConfig;
  repoRoot: string;
  /** Limit to the most recent N commits. Undefined = full history. */
  maxCommits?: number;
  /** Only scan commits reachable from this rev range, e.g. "origin/main..HEAD". */
  revRange?: string;
  onProgress?: (commitsScanned: number, findingsSoFar: number) => void;
}

export interface CommitInfo {
  sha: string;
  author: string;
  date: string;
  subject: string;
}

const MAX_BUFFER = 512 * 1024 * 1024;

/** Unlikely to appear in a commit subject, and safe in a shell argument. */
const COMMIT_MARKER = "@@SGCOMMIT@@";
const FIELD_SEP = "@@SGF@@";
const LOG_FORMAT = `${COMMIT_MARKER}%H${FIELD_SEP}%an <%ae>${FIELD_SEP}%aI${FIELD_SEP}%s`;

export function isGitRepo(repoRoot: string): boolean {
  const res = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return res.status === 0 && res.stdout.trim() === "true";
}

/**
 * A single `git log -p` pass over the requested range. Spawning per-commit is
 * simpler but gets pathological on real repos, so we stream one diff and parse
 * it. `--unified=0` keeps only added lines, which is what we want: context
 * lines would re-report the same secret once per touching commit.
 */
export function scanHistory(options: HistoryScanOptions): Finding[] {
  const { config, repoRoot } = options;

  const args = [
    "log",
    "-p",
    "--no-merges",
    "--unified=0",
    "--no-color",
    "--full-history",
    `--format=${LOG_FORMAT}`,
  ];
  if (options.maxCommits) args.push(`-n${options.maxCommits}`);
  if (options.revRange) args.push(options.revRange);
  else args.push("--all");

  const res = spawnSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: MAX_BUFFER,
  });
  if (res.status !== 0) {
    throw new Error(`git log failed: ${res.stderr?.trim() || "unknown error"}`);
  }

  return parseLogPatch(res.stdout, config, options.onProgress);
}

/**
 * Parses `git log -p` output into findings. Exported so it can be tested
 * against fixture diffs without needing a real repository.
 */
export function parseLogPatch(
  patch: string,
  config: SecretLoopConfig,
  onProgress?: (commitsScanned: number, findingsSoFar: number) => void
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  let commit: CommitInfo | null = null;
  let currentFile: string | null = null;
  let addedLine = 1;
  let commitsScanned = 0;

  // Buffers consecutive added lines per hunk so multi-line secrets like PEM
  // blocks are scanned as one body rather than line by line.
  let buffer: { text: string; firstLine: number } | null = null;

  const flush = () => {
    const buf = buffer;
    buffer = null;
    if (!buf || !commit || !currentFile) return;
    const local = scanText(buf.text, {
      config,
      filePath: currentFile,
      commit: commit.sha,
    });
    for (const f of local) {
      f.line = buf.firstLine + f.line - 1;
      // The same secret introduced once but touched by many commits should
      // surface once, attributed to the commit we saw it in first.
      const key = f.fingerprint ?? `${currentFile}:${f.ruleId}:${f.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  };

  for (const line of patch.split("\n")) {
    if (line.startsWith(COMMIT_MARKER)) {
      flush();
      const [sha, author, date, ...rest] = line.slice(COMMIT_MARKER.length).split(FIELD_SEP);
      commit = {
        sha: sha ?? "",
        author: author ?? "",
        date: date ?? "",
        subject: rest.join(FIELD_SEP),
      };
      currentFile = null;
      commitsScanned++;
      onProgress?.(commitsScanned, findings.length);
      continue;
    }

    if (line.startsWith("+++ ")) {
      flush();
      const p = line.slice(4).trim();
      currentFile = p === "/dev/null" ? null : p.replace(/^b\//, "");
      if (currentFile && isPathExcluded(currentFile, config)) currentFile = null;
      continue;
    }

    if (line.startsWith("--- ") || line.startsWith("diff --git ") || line.startsWith("index ")) {
      flush();
      continue;
    }

    if (line.startsWith("@@")) {
      flush();
      const m = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      addedLine = m ? Number(m[1]) : 1;
      continue;
    }

    if (currentFile && line.startsWith("+")) {
      const content = line.slice(1);
      if (buffer) buffer.text += "\n" + content;
      else buffer = { text: content, firstLine: addedLine };
      addedLine++;
      continue;
    }

    // Any other line ends the current run of added lines.
    flush();
  }
  flush();

  return findings;
}

/** Resolves commit metadata for reporting, one call for a batch of SHAs. */
export function describeCommits(repoRoot: string, shas: string[]): Map<string, CommitInfo> {
  const out = new Map<string, CommitInfo>();
  if (shas.length === 0) return out;
  const res = spawnSync(
    "git",
    ["show", "--no-patch", `--format=${LOG_FORMAT}`, ...shas],
    { cwd: repoRoot, encoding: "utf8", maxBuffer: MAX_BUFFER }
  );
  if (res.status !== 0) return out;
  for (const line of res.stdout.split("\n")) {
    if (!line.startsWith(COMMIT_MARKER)) continue;
    const [sha, author, date, ...rest] = line.slice(COMMIT_MARKER.length).split(FIELD_SEP);
    out.set(sha, { sha, author, date, subject: rest.join(FIELD_SEP) });
  }
  return out;
}
