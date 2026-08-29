import { readdirSync, statSync, readFileSync } from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import { SecretLoopConfig, classifyPath, isPathExcluded } from "./config";

/**
 * Enumerates candidate files. Prefers `git ls-files` when available so
 * .gitignore is respected for free — scanning ignored build output is both
 * slow and the main source of "why is it flagging my dist bundle" complaints.
 */
export interface FileListing {
  files: string[];
  /**
   * Files skipped by the generated-file group specifically, not by the base
   * exclusions. This is the number the report discloses, so it counts only what
   * this release started skipping.
   */
  generatedExcluded: number;
}

/**
 * Enumeration, with the generated-file skips counted rather than discarded.
 *
 * The count has to come from here because this is the only place that sees a
 * candidate before it is dropped. A caller handed the surviving list cannot
 * reconstruct how many files were removed, and a scan that silently skipped
 * twelve files reads exactly like one that had nothing to skip.
 */
export function listFilesWithExclusions(root: string, config: SecretLoopConfig): FileListing {
  const fromGit = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });

  const candidates =
    fromGit.status === 0
      ? fromGit.stdout.split("\n").filter((l) => l.trim().length > 0)
      : walkDirectory(root, root);

  const files: string[] = [];
  let generatedExcluded = 0;
  for (const rel of candidates) {
    switch (classifyPath(rel, config)) {
      case "none":
        files.push(rel);
        break;
      case "generated":
        generatedExcluded++;
        break;
      default:
        break; // already excluded before this release; not disclosed
    }
  }
  return { files, generatedExcluded };
}

export function listFiles(root: string, config: SecretLoopConfig): string[] {
  return listFilesWithExclusions(root, config).files;
}

/** Applies the generated-file group to a caller-supplied list, e.g. staged files. */
export function filterGenerated(
  files: string[],
  config: SecretLoopConfig
): FileListing {
  const kept: string[] = [];
  let generatedExcluded = 0;
  for (const rel of files) {
    if (classifyPath(rel, config) === "generated") generatedExcluded++;
    else kept.push(rel);
  }
  return { files: kept, generatedExcluded };
}

function walkDirectory(dir: string, root: string, acc: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return acc;
  }
  for (const entry of entries) {
    if (entry === ".git" || entry === "node_modules") continue;
    const full = path.join(dir, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) walkDirectory(full, root, acc);
    else acc.push(path.relative(root, full).split(path.sep).join("/"));
  }
  return acc;
}

/** Reads a file as text, returning null for binaries and oversized blobs. */
export function readTextFile(root: string, relPath: string, config: SecretLoopConfig): string | null {
  const full = path.join(root, relPath);
  try {
    const stat = statSync(full);
    if (!stat.isFile()) return null;
    if (stat.size > config.maxFileSizeBytes) return null;
    const buf = readFileSync(full);
    // A NUL byte in the first block is the standard heuristic for "binary".
    if (buf.subarray(0, 8000).includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

/**
 * Whether git already tracks a path. `unknown` when git could not answer at all
 * — not installed, not a repository — which must never be treated as either
 * answer.
 */
export type TrackedState = "tracked" | "untracked" | "unknown";

/**
 * Answers whether git tracks `relPath`, resolved relative to `root`.
 *
 * Uses plain `git ls-files` rather than `--error-unmatch`: the latter exits 1
 * for an untracked path *and* for a path git could not evaluate, so telling
 * those apart would mean parsing stderr. Here the mapping is unambiguous —
 * exit 0 with output means tracked, exit 0 without means untracked, and any
 * other exit means git could not answer.
 *
 * The pathspec is `:(literal)` because the caller's path comes from a user
 * setting. Without it, asking about `env[X].env` glob-matches a tracked
 * `envX.env` and reports a file as tracked that is not there.
 */
export function isTracked(root: string, relPath: string): TrackedState {
  const pathspec = relPath.split(path.sep).join("/");
  const res = spawnSync("git", ["ls-files", "--", `:(literal)${pathspec}`], {
    cwd: root,
    encoding: "utf8",
  });
  if (res.error || res.status !== 0) return "unknown";
  return res.stdout.trim().length > 0 ? "tracked" : "untracked";
}

/**
 * The staged set, or the reason there isn't one.
 *
 * Two outcomes, kept apart, because the old signature could not tell them
 * apart: a non-zero git exit returned `[]`, which the caller then reported as
 * "0 staged file(s)" and exited 0 on. A transient index lock during a
 * pre-commit hook therefore let the commit through with a clean-looking scan
 * that had never run. That is the same fail-soft composition validateRoot
 * exists to break — a check that could not run has proven nothing.
 */
export type StagedFiles = { files: string[] } | { error: string };

export function getStagedFiles(root: string): StagedFiles {
  const res = spawnSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACM"], {
    cwd: root,
    encoding: "utf8",
  });
  if (res.error) {
    return { error: `could not run git: ${res.error.message}` };
  }
  if (res.status !== 0) {
    return { error: describeStagedFailure(res.status, res.signal, res.stderr ?? "") };
  }
  return { files: res.stdout.split("\n").filter((l) => l.trim().length > 0) };
}

/**
 * Why git could not list the staged set, in terms someone can act on. Mirrors
 * describeGitFailure in history.ts: an empty stderr is not an absence of
 * information, because the status or the signal is the information.
 */
export function describeStagedFailure(
  code: number | null,
  signal: NodeJS.Signals | null,
  stderr: string
): string {
  const said = stderr.trim();
  if (said) return `git could not list staged files: ${said}`;
  if (signal) {
    return `git was killed by ${signal} before it could list staged files.`;
  }
  return (
    `git exited with status ${code} and wrote no error output while listing staged files. ` +
    `Check that this is a git repository and that the index is not locked.`
  );
}

/**
 * The repository's git directory, absolute. A plain `.git` join is wrong in a
 * worktree or submodule, where `.git` is a file pointing elsewhere.
 */
export function findGitDir(start: string): string | null {
  const res = spawnSync("git", ["rev-parse", "--absolute-git-dir"], {
    cwd: start,
    encoding: "utf8",
  });
  if (res.error || res.status !== 0) return null;
  const dir = res.stdout.trim();
  return dir.length > 0 ? dir : null;
}

export function findRepoRoot(start: string): string {
  const res = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: start, encoding: "utf8" });
  if (res.status === 0 && res.stdout.trim()) return res.stdout.trim();
  return start;
}
