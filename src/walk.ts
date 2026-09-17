import {
  readdirSync,
  statSync,
  lstatSync,
  fstatSync,
  openSync,
  readSync,
  closeSync,
  realpathSync,
  existsSync,
  constants as fsConstants,
} from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import { SecretLoopConfig, classifyPath, isPathExcluded } from "./config";

/**
 * One read request at a time. Bounded so a refusal never allocates in
 * proportion to the file: at most this much is held past the cap.
 */
const READ_CHUNK_BYTES = 64 * 1024;

/**
 * Whether this host's `fs.constants` defines `O_NONBLOCK`. On POSIX it does;
 * on win32 it does not, and nothing here pretends otherwise.
 */
export const NONBLOCKING_OPEN_SUPPORTED = fsConstants.O_NONBLOCK !== undefined;

/**
 * The flags for EVERY content open in this module.
 *
 * WHY. Both readers classify a path before opening it -- `statSync` in the
 * text reader, the non-dereferencing `lstatSync` in the binary reader -- so a
 * FIFO that is already there is refused without any open. But the check and
 * the open are two resolutions of the same name, and a regular file replaced
 * by a FIFO between them reached `openSync(full, "r")`, which on a FIFO with
 * no writer BLOCKS INDEFINITELY. Measured (f1-containment-design, E2): the
 * scanner hung until its process was killed, on darwin and Linux alike.
 *
 * WHAT THIS DOES. `O_NONBLOCK` makes the open of a FIFO (or a device) return
 * at once instead of waiting for a writer; `fstat` on the descriptor then says
 * what was opened, and a non-file is refused before a byte is read. For a
 * regular file the flag changes nothing: reads are unaffected and the cap and
 * classification below run exactly as before (measured, same record, E3).
 *
 * WHAT THIS DOES NOT DO. It is the narrow answer to the demonstrated FIFO
 * block. It is not a containment check -- the open still resolves the name and
 * follows symlinks, and F-1 Concern A remains OPEN -- and it does not make
 * every filesystem operation non-blocking or the scanner immune to a hostile
 * tree. The pre-open type checks stay, because they refuse a static FIFO
 * cheaply and, in the binary reader, refuse a final-component symlink without
 * dereferencing it.
 *
 * WIN32. `fs.constants.O_NONBLOCK` is undefined there, so the flag falls back
 * to a plain read-only open: no FIFO can exist on an NTFS path, and the
 * behaviour on Windows is exactly what it was before this constant existed.
 * That fallback is stated, not described as protection.
 */
export const READ_OPEN_FLAGS: number = fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0);

/**
 * Enumerates candidate files. Prefers `git ls-files` when available so
 * .gitignore is respected for free — scanning ignored build output is both
 * slow and the main source of "why is it flagging my dist bundle" complaints.
 */
export interface FileListing {
  files: string[];
  /**
   * Files skipped because their real location is outside the scan root.
   * Disclosed, never silent.
   */
  outsideExcluded: number;
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
/**
 * Whether a path really lives inside the directory being scanned.
 *
 * git tracks symlinks -- mode 120000 -- so a clone can carry a link to
 * ~/.aws/credentials or /etc/passwd. `git ls-files` lists the link and a plain
 * read follows it, so the target's content was scanned, reported under a path
 * inside the repository, and with --verify transmitted to a provider. On a
 * threat model that assumes a cloned repository may be hostile, a scan that
 * cannot stay inside the directory it was given is not bounded at all.
 *
 * Containment, not symlink avoidance: a link resolving back inside the root is
 * an ordinary file and is still scanned. A path that cannot be resolved -- a
 * broken link -- has no location to check and is dropped rather than raising.
 */
export function isInsideRoot(root: string, relPath: string): boolean {
  let realRoot: string;
  try {
    realRoot = realpathSync(path.resolve(root));
  } catch {
    return false;
  }
  let real: string;
  try {
    real = realpathSync(path.join(realRoot, relPath));
  } catch {
    return false;
  }
  const rel = path.relative(realRoot, real);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

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
  let outsideExcluded = 0;
  for (const rel of candidates) {
    switch (classifyPath(rel, config)) {
      case "none":
        // Checked after the exclusion groups so a node_modules symlink is
        // attributed to the group that was already skipping it, not counted as
        // something this release started excluding.
        if (isInsideRoot(root, rel)) files.push(rel);
        else outsideExcluded++;
        break;
      case "generated":
        generatedExcluded++;
        break;
      default:
        break; // already excluded before this release; not disclosed
    }
  }
  return { files, generatedExcluded, outsideExcluded };
}

export function listFiles(root: string, config: SecretLoopConfig): string[] {
  return listFilesWithExclusions(root, config).files;
}

/** Applies the generated-file group to a caller-supplied list, e.g. staged files. */
export function filterGenerated(
  root: string,
  files: string[],
  config: SecretLoopConfig
): FileListing {
  const kept: string[] = [];
  let generatedExcluded = 0;
  let outsideExcluded = 0;
  for (const rel of files) {
    if (classifyPath(rel, config) === "generated") generatedExcluded++;
    else if (!isInsideRoot(root, rel)) outsideExcluded++;
    else kept.push(rel);
  }
  return { files: kept, generatedExcluded, outsideExcluded };
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

/**
 * Why a file that was in scope produced no text to scan.
 *
 * Separate reasons rather than a boolean, because they do not share a remedy:
 * `oversized` is answered by raising maxFileSizeBytes, `outside` is the
 * containment refusal the walk already counts under its own clause, and the
 * rest are answered by different things or by nothing at all. A single count
 * would have to describe them in one sentence and would name a fix for some of
 * them that does not apply to the others.
 *
 * THE LOAD-BEARING SPLIT IS `binary` VERSUS THE FAILURES. A NUL byte in the
 * first block is a POSITIVE determination that the input is binary, and binary
 * input is outside what a text scanner set out to read -- an intentional
 * exclusion, like a generated file. `not-a-file`, `vanished` and `unreadable`
 * are the opposite: the scanner INTENDED to read the input and could not. They
 * were one bucket, `unreadable`, whose own disclosure said "binary or
 * unreadable" because it genuinely could not tell which had happened. A PNG and
 * a file the process was refused permission to open produced byte-identical
 * output, and both made the report incomplete -- so one image anywhere in a
 * tree made every report from it permanently ineligible for comparison, for a
 * scope decision rather than a failure to look.
 *
 * `unreadable` remains the CONSERVATIVE bucket. Anything that is not one of the
 * positive determinations above lands there and still counts as a coverage
 * limitation, because "we do not know why this did not read" is never evidence
 * that nothing was missed.
 */
export type SkipReason =
  | "oversized"
  /**
   * A NUL byte in the FIRST 8000 BYTES. See readTextFileResult for what this
   * classifier does and does not establish: it is a probe, not a proof, and it
   * never establishes that the file holds no secret.
   */
  | "binary"
  /** stat answered, and the entry is not a regular file (directory, fifo, socket, device). */
  | "not-a-file"
  /** The path was enumerated but was gone by the time the read reached it. */
  | "vanished"
  /** The read itself failed -- permission, I/O -- or the reason is unknown. */
  | "unreadable"
  | "outside";

export type ReadResult = { text: string } | { skipped: SkipReason };

/**
 * Reads a file as text, or says why it could not.
 *
 * The reason is the whole point of this signature. `readTextFile` returned null
 * for four different situations and the caller dropped the file without
 * counting it, so a tree of 500 files where 480 were over the size cap reported
 * "Scanned 20 file(s). No secrets found." -- a scan that could not look, printed
 * in the words of one that found nothing. Every other skip this scanner
 * performs is disclosed; this was the largest one and the only silent one.
 */
/**
 * Reads a whole file from ONE descriptor, with the byte cap enforced WHILE
 * reading.
 *
 * WHY THIS EXISTS. The previous shape was `statSync(full)` then
 * `readFileSync(full)`: two independent resolutions of the same name, and the
 * second had no bound at all -- `readFileSync` takes no maximum-bytes option.
 * The cap therefore described the file `stat` HAPPENED TO SEE, not the bytes
 * actually read. A file that grew between the two calls was read in full at
 * whatever size it had reached. That was reproduced deterministically: a 64-byte
 * cap, a 10-byte file at stat time, 4096 bytes read.
 *
 * WHAT ONE DESCRIPTOR DOES BUY. Every byte comes from the object that was
 * opened, so replacing the PATH after the open cannot change which bytes arrive,
 * and `fstat` describes that same object rather than whatever the name resolves
 * to next.
 *
 * WHAT IT DOES NOT BUY, AND MUST NOT BE READ AS BUYING:
 *   - It does NOT prove the opened object is inside the scan root. `openSync`
 *     resolves the name and follows symlinks like any other resolution, so a
 *     final-component or PARENT-DIRECTORY replacement between the containment
 *     check and this open is still followed. That is F-1 Concern A, and it
 *     remains OPEN. The callers' existing `isInsideRoot` check stays exactly
 *     where it was; this changes nothing about containment in either direction.
 *   - It is NOT a snapshot. A writer holding the same file can still change the
 *     bytes between two reads of this descriptor. A descriptor fixes WHICH
 *     object is read, never what is in it.
 *
 * The cap is enforced in the loop, not by the `fstat` size check above it: that
 * check is an optimization that avoids reading an already-huge file, and the
 * loop does not trust it.
 */
function readBoundedFile(
  full: string,
  limit: number,
  /**
   * TEST-ONLY SEAM, mirroring `compare.ts`'s reader. Runs after the descriptor
   * is open and before the first read, so a regression can change the file
   * deterministically at exactly the point the old code was vulnerable --
   * without sleeping, racing or patching `fs`. Production callers pass nothing.
   */
  afterOpen?: () => void
): { bytes: Buffer } | { skipped: SkipReason } {
  let fd: number;
  try {
    // Non-blocking where the platform has the flag (see READ_OPEN_FLAGS): a
    // FIFO swapped in since the caller's type check no longer holds the open.
    fd = openSync(full, READ_OPEN_FLAGS);
  } catch {
    // Matches the previous classification: a name that cannot be opened is not
    // distinguishable here from one that cannot be read.
    return { skipped: "unreadable" };
  }
  try {
    // The OPENED object is classified here, whatever the name resolved to
    // between the caller's check and this open. A FIFO or device that got
    // through is refused before any read, and the descriptor is closed below.
    const st = fstatSync(fd);
    if (!st.isFile()) return { skipped: "not-a-file" };
    // Optimization only. The loop below is the guard.
    if (st.size > limit) return { skipped: "oversized" };

    // THE CAP MUST BE A USABLE NUMBER FROM HERE ON, because it sizes an
    // allocation. `loadConfig` does not validate `maxFileSizeBytes` -- it is
    // `raw.maxFileSizeBytes ?? default` -- so a project file saying
    // `"maxFileSizeBytes": "abc"` reaches this function as a string. JSON
    // cannot express NaN, but an embedder calling the API directly can.
    //
    // Refuse rather than compute with it. Without this line `"abc" + 1` is
    // `"abc1"`, `Math.min` of that is NaN, and `Buffer.allocUnsafe(NaN)` throws
    // into the catch below -- the same refusal, but by accident and with no
    // way to read the intent. Note the comparison is deliberately `>= 0` and
    // not `Number.isFinite`: `Infinity` is a real way to say "no cap" and both
    // the previous code and this one honour it.
    //
    // This is the one behaviour this change does NOT preserve: the previous
    // reader ignored an unusable cap and read the file whole. Refusing is the
    // fail-closed direction, it is disclosed as a skip rather than silent, and
    // it does not invent a limit -- but it is a difference, and it is
    // documented as one.
    if (!(limit >= 0)) return { skipped: "unreadable" };

    afterOpen?.();

    // Bounded by the cap as well as by the chunk size, so a small configured
    // limit does not allocate a large buffer to read a few bytes. The `+ 1` is
    // the OVERFLOW PROBE: it is the single byte past the limit that lets
    // "exactly the limit" and "one byte over" be distinguished.
    const chunkSize = Math.min(READ_CHUNK_BYTES, limit + 1);
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const buf = Buffer.allocUnsafe(chunkSize);
      // A short read is normal and is not end-of-file; only 0 is.
      const n = readSync(fd, buf, 0, chunkSize, null);
      if (n === 0) break;
      total += n;
      // At most one chunk is ever read past the cap. That bounded overflow is
      // what lets "exactly the limit" and "one byte over" be told apart, and the
      // buffer is discarded before anything classifies or scans it.
      if (total > limit) return { skipped: "oversized" };
      chunks.push(buf.subarray(0, n));
    }
    return { bytes: Buffer.concat(chunks, total) };
  } catch {
    return { skipped: "unreadable" };
  } finally {
    // Closed on every path: success, refusal and throw alike.
    try {
      closeSync(fd);
    } catch {
      /* already closed or invalid; nothing further to do */
    }
  }
}

export function readTextFileResult(
  root: string,
  relPath: string,
  config: SecretLoopConfig,
  /** TEST-ONLY SEAM. See readBoundedFile. Production callers pass nothing. */
  afterOpen?: () => void
): ReadResult {
  // Enforced at the read as well as at the walk. A caller with its own file
  // list -- the staged set, or anything that never goes through listFiles --
  // would otherwise follow a link straight out of the root.
  if (!isInsideRoot(root, relPath)) {
    // isInsideRoot answers false for two different things: a path that resolves
    // OUTSIDE the root, and one that does not resolve at all. Conflating them is
    // right at the walk, where both mean "not a file this scan owns" -- and
    // wrong here, because these land in different clauses. A file deleted
    // between enumeration and read would otherwise be disclosed as a symlink
    // escaping the scan root, which is the same class of overstatement as
    // counting a node_modules skip against the generated-file group.
    return { skipped: existsSync(path.join(root, relPath)) ? "outside" : "vanished" };
  }
  const full = path.join(root, relPath);
  try {
    // CLASSIFY THE TYPE BEFORE OPENING. This stat is NOT the size guard -- the
    // read loop is, and using a stat's SIZE to bound a later read is the exact
    // defect this change removes. It is here for TYPE only, because `openSync`
    // on a FIFO with no writer BLOCKS INDEFINITELY, and this function is reached
    // with caller-supplied paths (the staged set) that never went through the
    // walk. Opening first turned a prompt "not-a-file" into a hang; the binary
    // reader never had that problem because its lstat gate already ran first.
    //
    // A regular file replaced by a FIFO between this stat and the open used to
    // block the open indefinitely; the open is now non-blocking where the
    // platform supports it (READ_OPEN_FLAGS) and the opened object is
    // classified again from its descriptor. Containment between this check and
    // the open -- F-1 Concern A -- is a separate question and remains OPEN.
    const stat = statSync(full);
    if (!stat.isFile()) return { skipped: "not-a-file" };

    // ONE DESCRIPTOR for the content. `fstat` describes the opened object and
    // every byte comes from it, with the cap enforced while reading -- see
    // readBoundedFile. The oversized/unreadable classifications are the same
    // ones this function has always returned; what changed is that the cap now
    // bounds the READ instead of describing a separate stat.
    const read = readBoundedFile(full, config.maxFileSizeBytes, afterOpen);
    if (!("bytes" in read)) return read;
    const buf = read.bytes;
    // THE BINARY CLASSIFIER, AND EXACTLY WHAT IT IS.
    //
    // It tests one thing: does a NUL byte occur in the first 8000 bytes. That
    // is the standard heuristic, it is what `git diff` uses, and it is a
    // POSITIVE determination rather than a failure -- which is why it gets its
    // own reason instead of being disclosed as an inability to inspect.
    //
    // It is NOT a proof that the file is binary, and it is emphatically NOT a
    // proof that the file holds no secret. Its real boundary:
    //
    //   - UTF-16 and UTF-32 TEXT IS CLASSIFIED BINARY. Their encodings pad
    //     ASCII with NUL, so a UTF-16 file carrying a live credential lands
    //     here. Such a file would not scan usefully anyway -- the read below is
    //     UTF-8 only and no decoder is selected by BOM or content -- so it is
    //     out of the supported scan scope either way. It is still SKIPPED,
    //     still DISCLOSED, and nothing here says it was clean.
    //   - TEXT CARRYING AN EMBEDDED NUL is classified binary. Note what that
    //     does and does not mean: the WHOLE FILE HAS ALREADY BEEN READ into
    //     `buf` by the line above -- every byte, before and after the NUL. What
    //     does not happen is SCANNING: the buffer is discarded here and never
    //     reaches scanText, so no rule ever sees the content. A 47 KB source
    //     file with one NUL near the top is read in full and scanned not at
    //     all. "Not read" would be wrong; "not scanned" is the fact.
    //   - A BINARY FILE WHOSE FIRST 8000 BYTES HAPPEN TO CARRY NO NUL is NOT
    //     classified binary. It takes the text path and is scanned as text.
    //
    // This is why the skip stays disclosed in the scope sentence even though it
    // no longer makes the report incomplete. The disclosure is the only thing
    // that tells a reader a credential could be sitting where nothing looked.
    if (buf.subarray(0, 8000).includes(0)) return { skipped: "binary" };
    // Decoding is deliberately LOSSY and never fails here: invalid UTF-8 becomes
    // U+FFFD and the file is still scanned. There is therefore no "decoding
    // failure" skip -- nothing is withheld from the rules on that ground, so
    // nothing is withheld from coverage either.
    return { text: buf.toString("utf8") };
  } catch {
    // Permission, I/O, or anything unanticipated. Stays conservative.
    return { skipped: "unreadable" };
  }
}

export type BinaryCandidate = { bytes: Buffer } | { skipped: SkipReason };

/**
 * The binary detector's OWN candidate read, deliberately separate from the
 * text path above.
 *
 * Two differences from readTextFileResult, both required by the frozen PKCS#12
 * design and neither of which changes text scanning:
 *
 *   NON-DEREFERENCING. This uses `lstatSync`, not `statSync`, so a symlink is
 *   rejected as a candidate before any byte is read. The text path follows an
 *   in-root link on purpose; the binary detector must not, or one container
 *   would report twice under two paths. `isInsideRoot` is still consulted, but
 *   only to establish containment.
 *
 *   SIZE BEFORE READ. The effective `maxFileSizeBytes` gate runs against the
 *   entry's own size and rejects before opening for content. The default is an
 *   operational default, not a parser ceiling: an operator who raises it is
 *   supported, so nothing here assumes a bound smaller than the configured one.
 *
 * `headerAccepts` is an optional cheap prefilter. Only the first
 * `headerBytes` are read for it, so scanning a large tree does not pay a full
 * read per file for a format almost no file has.
 */
export function readBinaryCandidate(
  root: string,
  relPath: string,
  config: SecretLoopConfig,
  headerAccepts?: (head: Buffer, size: number) => boolean,
  headerBytes = 16,
  /** TEST-ONLY SEAM. See readBoundedFile. Production callers pass nothing. */
  afterOpen?: () => void
): BinaryCandidate {
  if (!isInsideRoot(root, relPath)) {
    return { skipped: existsSync(path.join(root, relPath)) ? "outside" : "vanished" };
  }
  const full = path.join(root, relPath);
  try {
    // lstat: the entry itself, never its target.
    const stat = lstatSync(full);
    // A symlink lands here too, by design (see above). "not a regular file" is
    // the same answer for both, and this reason is never counted: the caller
    // discards a candidate skip and lets the text path account for the file.
    if (!stat.isFile()) return { skipped: "not-a-file" };
    if (stat.size > config.maxFileSizeBytes) return { skipped: "oversized" };
    if (headerAccepts) {
      const head = Buffer.alloc(Math.min(headerBytes, stat.size));
      // The same non-blocking open as the bulk read, for the same reason: this
      // probe is a second resolution of the name after the lstat gate, and a
      // FIFO swapped in between them blocked here too (measured). The opened
      // object is classified before its head is read; the descriptor is closed
      // on every path.
      const fd = openSync(full, READ_OPEN_FLAGS);
      try {
        if (!fstatSync(fd).isFile()) return { skipped: "not-a-file" };
        readSync(fd, head, 0, head.length, 0);
      } finally {
        closeSync(fd);
      }
      // Not this format. Not a failure and never counted -- the caller discards
      // every candidate skip -- but named honestly rather than as "unreadable".
      if (!headerAccepts(head, stat.size)) return { skipped: "not-a-file" };
    }
    // The lstat gate above is DELIBERATELY KEPT: it does not dereference, so a
    // final-component symlink present at that moment is still refused as
    // "not-a-file". Replacing it with fstat-on-an-open-descriptor would have
    // silently removed that refusal. Only the unbounded bulk read is replaced.
    const read = readBoundedFile(full, config.maxFileSizeBytes, afterOpen);
    if (!("bytes" in read)) return read;
    return { bytes: read.bytes };
  } catch {
    return { skipped: "unreadable" };
  }
}

/**
 * The same read, for callers that only need the text. Kept so the extension's
 * own reader and the containment tests are unchanged by the reason above.
 */
export function readTextFile(root: string, relPath: string, config: SecretLoopConfig): string | null {
  const result = readTextFileResult(root, relPath, config);
  return "text" in result ? result.text : null;
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
