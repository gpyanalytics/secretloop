import { readdirSync, statSync, readFileSync } from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import { SecretLoopConfig, isPathExcluded } from "./config";

/**
 * Enumerates candidate files. Prefers `git ls-files` when available so
 * .gitignore is respected for free — scanning ignored build output is both
 * slow and the main source of "why is it flagging my dist bundle" complaints.
 */
export function listFiles(root: string, config: SecretLoopConfig): string[] {
  const fromGit = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });

  const candidates =
    fromGit.status === 0
      ? fromGit.stdout.split("\n").filter((l) => l.trim().length > 0)
      : walkDirectory(root, root);

  return candidates.filter((rel) => !isPathExcluded(rel, config));
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

export function getStagedFiles(root: string): string[] {
  const res = spawnSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACM"], {
    cwd: root,
    encoding: "utf8",
  });
  if (res.status !== 0) return [];
  return res.stdout.split("\n").filter((l) => l.trim().length > 0);
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
