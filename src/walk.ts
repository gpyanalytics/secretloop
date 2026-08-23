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

export function getStagedFiles(root: string): string[] {
  const res = spawnSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACM"], {
    cwd: root,
    encoding: "utf8",
  });
  if (res.status !== 0) return [];
  return res.stdout.split("\n").filter((l) => l.trim().length > 0);
}

export function findRepoRoot(start: string): string {
  const res = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: start, encoding: "utf8" });
  if (res.status === 0 && res.stdout.trim()) return res.stdout.trim();
  return start;
}
