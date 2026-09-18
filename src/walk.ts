import {
  readdirSync,
  statSync,
  lstatSync,
  fstatSync,
  openSync,
  readSync,
  closeSync,
  realpathSync,
  readlinkSync,
  existsSync,
  constants as fsConstants,
  BigIntStats,
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
  /**
   * The name resolved outside the scan root -- before the open (a symlink,
   * as always) or, on Linux, after it: the kernel's own record of the OPENED
   * object's location lay outside the root at the check that precedes the
   * first read. See readChecked.
   */
  | "outside"
  /**
   * The object that was opened is not the object that was inspected and
   * approved one syscall earlier: its device or inode differs. A positive
   * observation of a SUBSTITUTION, and only that -- the substitute may be
   * outside the root or an inside file an editor just saved atomically over
   * the name, and the identity check cannot tell which. That is why this is
   * not reported as `outside` (a location it did not observe) and not as
   * `unreadable` (a reason it does know). Nothing is read from such an object.
   */
  | "replaced";

export type ReadResult = { text: string } | { skipped: SkipReason };

/**
 * What happened to ONE content descriptor's two checks. Recorded per
 * descriptor, never per file: a file may be opened by up to three readers and
 * each open is checked, and accounted for, on its own.
 *
 *   verified     the check ran on this descriptor and passed
 *   refused      the check ran and observed a violation; the file was refused
 *   unavailable  the platform or the object gave the check nothing to work with;
 *                the read continued under the remaining checks and says so
 *   failed       the attempt to obtain the evidence itself failed; the file was
 *                refused (`unreadable`) -- a failure is not an absence
 *   not-reached  the descriptor was refused before this check ran
 *
 * `verified` is written only after the comparison or the link read actually
 * succeeded on the descriptor in hand. It is never inferred from the platform
 * name or from an earlier descriptor.
 */
export type CheckOutcome = "verified" | "refused" | "unavailable" | "failed" | "not-reached";

export interface OpenedFileCheck {
  /** Pre-open (dev, ino) of the inspected object against `fstat` of the opened one. */
  identity: CheckOutcome;
  /** Linux only: the kernel's path for the descriptor, inside the root by component boundary. */
  kernelPath: CheckOutcome;
}

/** Counts of one check's outcomes over a scan. Sums to `opened`. */
export interface CheckCounts {
  verified: number;
  refused: number;
  unavailable: number;
  failed: number;
  notReached: number;
}

/**
 * The per-scan accounting of every content descriptor the readers opened.
 * Counts only, and counts only ever grow, so a later verified descriptor
 * cannot erase an earlier gap: a capability that stops working part-way
 * through a scan leaves the earlier `verified` and the later `unavailable`
 * side by side rather than averaged into a label.
 *
 * `opened: 0` is a positive statement (this scan opened nothing). A producer
 * that never runs these readers -- the history scan -- omits the object
 * entirely, which is this codebase's existing way of saying "not established".
 */
export interface OpenedFileChecks {
  opened: number;
  identity: CheckCounts;
  kernelPath: CheckCounts;
}

function emptyCheckCounts(): CheckCounts {
  return { verified: 0, refused: 0, unavailable: 0, failed: 0, notReached: 0 };
}

export function emptyOpenedFileChecks(): OpenedFileChecks {
  return { opened: 0, identity: emptyCheckCounts(), kernelPath: emptyCheckCounts() };
}

function countOutcome(counts: CheckCounts, outcome: CheckOutcome): void {
  switch (outcome) {
    case "verified": counts.verified++; break;
    case "refused": counts.refused++; break;
    case "unavailable": counts.unavailable++; break;
    case "failed": counts.failed++; break;
    case "not-reached": counts.notReached++; break;
    default: {
      const never: never = outcome;
      void never;
    }
  }
}

/** Adds one descriptor's record to the scan's accounting. */
export function recordOpenedFileCheck(acc: OpenedFileChecks, check: OpenedFileCheck): void {
  acc.opened++;
  countOutcome(acc.identity, check.identity);
  countOutcome(acc.kernelPath, check.kernelPath);
}

/**
 * Hooks a reader accepts. `afterOpen` is the TEST-ONLY SEAM every bounded-read
 * test already uses: it runs after the descriptor is open and checked and
 * before the first read. `onOpenedFileCheck` is the production accounting
 * callback, fired exactly once per opened descriptor from the reader's
 * `finally`, whatever the outcome. A bare function is accepted as `afterOpen`
 * so the existing call sites are unchanged.
 */
export interface ReadHooks {
  afterOpen?: () => void;
  onOpenedFileCheck?: (check: OpenedFileCheck) => void;
}
export type ReadHooksArg = (() => void) | ReadHooks | undefined;

function hooksOf(arg: ReadHooksArg): ReadHooks {
  if (arg === undefined) return {};
  return typeof arg === "function" ? { afterOpen: arg } : arg;
}

/**
 * The reader's own containment locator: the same two resolutions as
 * isInsideRoot, returning the canonical root and the resolved name so the
 * readers can inspect and open the RESOLVED object rather than resolving the
 * name a third time. `isInsideRoot` itself is left byte-identical: it is one
 * of the functions the security review pins.
 *
 * Splits the two ways resolution can fail exactly as the readers always have:
 * a name that resolves OUTSIDE is a containment refusal, one that does not
 * resolve at all is a file that vanished.
 */
function locateInsideRoot(
  root: string,
  relPath: string
): { realRoot: string; real: string } | { skipped: "outside" | "vanished" } {
  const outsideOrGone = (): { skipped: "outside" | "vanished" } => ({
    skipped: existsSync(path.join(root, relPath)) ? "outside" : "vanished",
  });
  let realRoot: string;
  try {
    realRoot = realpathSync(path.resolve(root));
  } catch {
    return outsideOrGone();
  }
  let real: string;
  try {
    real = realpathSync(path.join(realRoot, relPath));
  } catch {
    return outsideOrGone();
  }
  const rel = path.relative(realRoot, real);
  if (rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))) return { realRoot, real };
  return { skipped: "outside" };
}

/**
 * Whether a kernel-recorded path lies under the canonical root BY PATH
 * COMPONENT, on the raw bytes.
 *
 * Never a bare string prefix: `<root>2/x` starts with `<root>` and is a
 * sibling directory, not a child (measured as the prefix trap B1 in
 * f1-containment-design-review). Never normalised and never stripped: proc(5)
 * appends " (deleted)" to the link of an unlinked file, and the raw string
 * still begins with `<root>/`, so a deleted inside file is accepted as inside
 * and a deleted outside file is still refused. Compared as bytes so a name the
 * kernel reports in a non-UTF-8 encoding is not mangled on the way in.
 */
export function kernelPathInside(kernelPath: Buffer, realRoot: string): boolean {
  const root = Buffer.from(realRoot, "utf8");
  if (kernelPath.equals(root)) return true;
  const prefix = realRoot.endsWith("/") ? root : Buffer.concat([root, Buffer.from("/")]);
  return kernelPath.length > prefix.length && kernelPath.subarray(0, prefix.length).equals(prefix);
}

/**
 * The kernel's own record of where an open descriptor points, or why there is
 * none. Only Linux procfs semantics are read here: `/proc/self/fd/N` is
 * documented (proc(5)) as the kernel's path for the file, and no other
 * platform's `/proc` is given that meaning. On Linux the answer is MEASURED per
 * descriptor, never assumed from the platform name:
 *
 *   - the link reads             -> its raw bytes
 *   - it does not, and there is no readable /proc/self/fd directory
 *                                -> `unavailable` (the capability is absent;
 *                                   disclosed, read continues)
 *   - it does not, but /proc/self/fd is there
 *                                -> `failed` (evidence for THIS descriptor
 *                                   could not be obtained; that is a signal,
 *                                   and the file is refused)
 */
function kernelPathOf(fd: number): { path: Buffer } | { outcome: "unavailable" | "failed" } {
  if (process.platform !== "linux") return { outcome: "unavailable" };
  try {
    return { path: readlinkSync(`/proc/self/fd/${fd}`, { encoding: "buffer" }) };
  } catch {
    let present = false;
    try {
      present = statSync("/proc/self/fd").isDirectory();
    } catch {
      present = false;
    }
    return { outcome: present ? "failed" : "unavailable" };
  }
}

/** The pre-open identity of the inspected object. Bigint: an NTFS file index is 64 bits. */
interface ObjectIdentity {
  dev: bigint;
  ino: bigint;
}

/**
 * Reads a whole file from ONE CHECKED descriptor, with the byte cap enforced
 * WHILE reading.
 *
 * THE SEQUENCE, in this order and no other (f1-containment-design-review,
 * sequence-options-acceptance, steps 5-9; the pre-open steps are the callers'):
 *
 *   5  open, non-blocking where the platform has the flag (READ_OPEN_FLAGS)
 *   6  fstat the DESCRIPTOR; refuse a non-file; size optimisation; cap sanity
 *   7  IDENTITY: the descriptor's (dev, ino) must equal the identity the caller
 *      captured with lstat one syscall before the open. A mismatch is a
 *      substitution and the file is refused as `replaced`. An inspected object
 *      reporting (0, 0) has no identity to compare; that is recorded as
 *      `unavailable` and the read continues.
 *   8  KERNEL PATH (Linux): the kernel's path for the descriptor must lie under
 *      the canonical root by component boundary (kernelPathInside). Outside is
 *      refused as `outside`. No procfs: `unavailable`, disclosed, continue.
 *      procfs present but this link unreadable: `failed`, refused.
 *   9  the reads -- the optional header probe and then the bulk read -- from
 *      THIS descriptor, positionally, with the cap enforced in the loop.
 *
 * WHAT THIS ESTABLISHES, EXACTLY -- PER DESCRIPTOR, AS RECORDED. For a
 * descriptor the record says `kernelPath: verified`: its kernel-recorded
 * location, AT THE INSTANT OF THE CHECK THAT IMMEDIATELY PRECEDES THE FIRST
 * READ, lay inside the root, and no byte was read before that check. For a
 * descriptor the record says `identity: verified`: every byte read came from
 * the object inspected one syscall before the open. Neither claim extends to
 * a descriptor recorded `unavailable`: such a descriptor IS READ, under the
 * remaining checks only, and the accounting says so; nothing is inferred for
 * it. A descriptor recorded `refused` or `failed` yields no byte at all.
 *
 * WHAT IT DOES NOT ESTABLISH, stated so nothing above is read as more:
 *   - location AT THE OPEN. An outside object opened through a replaced parent
 *     and renamed under the root before step 8 passes both checks and is read
 *     (measured: f1-containment-design-review-addendum-timing, MI1/MI2). Only an
 *     open that cannot escape the root -- openat2(RESOLVE_BENEATH), which Node
 *     does not expose -- would make the open the guarantee.
 *   - location THROUGHOUT THE READ. An inside object moved out after step 8 is
 *     still read (MO1); the reads are not re-validated.
 *   - the parent case without a kernel path. On darwin and win32 a parent
 *     replaced between realpath and the caller's lstat is captured as approved
 *     and passes step 7; step 8 is unavailable there. Risk reduction, disclosed.
 *   - content. A descriptor fixes which object is read, never what it holds.
 *
 * ONE DESCRIPTOR SERVES THE HEADER PROBE AND THE BULK READ. The probe used to
 * open on its own, and handed the acceptor 16 bytes of whatever that open
 * resolved to before any bulk-read check could act (measured, same addendum).
 * Now the head is read from the descriptor that passed the checks, and the
 * bulk read continues from the same one. No acceptor receives a byte before
 * the checks that apply to the descriptor it came from.
 */
function readChecked(
  name: string,
  realRoot: string,
  expected: ObjectIdentity,
  limit: number,
  hooks: ReadHooks,
  header?: { bytes: number; accepts: (head: Buffer, size: number) => boolean }
): { bytes: Buffer } | { skipped: SkipReason } {
  let fd: number;
  try {
    fd = openSync(name, READ_OPEN_FLAGS);
  } catch {
    // Matches the previous classification: a name that cannot be opened is not
    // distinguishable here from one that cannot be read. Nothing was opened,
    // so nothing is recorded.
    return { skipped: "unreadable" };
  }
  // Written as each step actually completes; reported from the finally below.
  const check: OpenedFileCheck = { identity: "not-reached", kernelPath: "not-reached" };
  try {
    let st: BigIntStats;
    try {
      st = fstatSync(fd, { bigint: true });
    } catch {
      // The evidence itself could not be obtained. A failure, not an absence,
      // and the file is refused.
      check.identity = "failed";
      return { skipped: "unreadable" };
    }
    // The OPENED object is classified here, whatever the name resolved to
    // between the caller's check and this open. A FIFO or device that got
    // through is refused before any read, and the descriptor is closed below.
    if (!st.isFile()) return { skipped: "not-a-file" };
    const size = Number(st.size);
    // Optimization only. The loop below is the guard.
    if (size > limit) return { skipped: "oversized" };

    // THE CAP MUST BE A USABLE NUMBER FROM HERE ON, because it sizes an
    // allocation. `loadConfig` does not validate `maxFileSizeBytes` -- it is
    // `raw.maxFileSizeBytes ?? default` -- so a project file saying
    // `"maxFileSizeBytes": "abc"` reaches this function as a string. JSON
    // cannot express NaN, but an embedder calling the API directly can.
    // Refuse rather than compute with it; `Infinity` is a real way to say
    // "no cap" and is honoured. This is the fail-closed direction and it is
    // disclosed as a skip rather than silent.
    if (!(limit >= 0)) return { skipped: "unreadable" };

    // 7  IDENTITY. Compared as bigints: a double loses the low bits of a
    // 64-bit NTFS file index, and two files that differ only there would
    // otherwise compare equal.
    if (expected.dev === 0n && expected.ino === 0n) {
      check.identity = "unavailable";
    } else if (st.dev !== expected.dev || st.ino !== expected.ino) {
      check.identity = "refused";
      return { skipped: "replaced" };
    } else {
      check.identity = "verified";
    }

    // 8  KERNEL PATH.
    const kp = kernelPathOf(fd);
    if ("path" in kp) {
      if (kernelPathInside(kp.path, realRoot)) {
        check.kernelPath = "verified";
      } else {
        check.kernelPath = "refused";
        return { skipped: "outside" };
      }
    } else {
      check.kernelPath = kp.outcome;
      if (kp.outcome === "failed") return { skipped: "unreadable" };
    }

    hooks.afterOpen?.();

    // 9  THE READS, positionally, so the header probe and the bulk read are
    // independent of the descriptor's file position on every platform.
    if (header) {
      const head = Buffer.alloc(Math.min(header.bytes, size));
      let got = 0;
      while (got < head.length) {
        const n = readSync(fd, head, got, head.length - got, got);
        if (n === 0) break;
        got += n;
      }
      // Not this format. Not a failure and never counted -- the caller discards
      // every candidate skip -- but named honestly rather than as "unreadable".
      if (!header.accepts(head.subarray(0, got), size)) return { skipped: "not-a-file" };
    }

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
      const n = readSync(fd, buf, 0, chunkSize, total);
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
    // Reported on every path too, after the close, exactly once per open.
    hooks.onOpenedFileCheck?.(check);
  }
}

export function readTextFileResult(
  root: string,
  relPath: string,
  config: SecretLoopConfig,
  /** A bare function is the TEST-ONLY `afterOpen` seam; an object may also carry the accounting callback. */
  hooks?: ReadHooksArg
): ReadResult {
  // Enforced at the read as well as at the walk. A caller with its own file
  // list -- the staged set, or anything that never goes through listFiles --
  // would otherwise follow a link straight out of the root.
  //
  // Two different failures are kept apart: a path that resolves OUTSIDE the
  // root, and one that does not resolve at all. A file deleted between
  // enumeration and read would otherwise be disclosed as a symlink escaping
  // the scan root, which is the same class of overstatement as counting a
  // node_modules skip against the generated-file group.
  const located = locateInsideRoot(root, relPath);
  if ("skipped" in located) return located;
  const { realRoot, real } = located;
  try {
    // 4  INSPECT THE RESOLVED OBJECT BEFORE OPENING, and capture its identity.
    // `lstat` on the resolved name, not `stat` on the enumerated one: the
    // resolution above already followed every in-root link, so a symlink
    // swapped in at the final component after it is a non-file here and is
    // refused without being followed. This is a TYPE check and an identity
    // capture; the size guard is the read loop.
    //
    // A regular file replaced by a FIFO between here and the open used to
    // block the open indefinitely; the open is non-blocking where the platform
    // supports it (READ_OPEN_FLAGS) and the opened object is classified again
    // from its descriptor. What the name resolves to between here and the open
    // is what the identity and kernel-path checks in readChecked are about.
    const stat = lstatSync(real, { bigint: true });
    if (!stat.isFile()) return { skipped: "not-a-file" };

    // ONE DESCRIPTOR for the content, checked before the first read. The
    // oversized/unreadable classifications are the ones this function has
    // always returned; `replaced` and the post-open `outside` are the checks'.
    const read = readChecked(real, realRoot, { dev: stat.dev, ino: stat.ino }, config.maxFileSizeBytes, hooksOf(hooks));
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
 *   NON-DEREFERENCING. This uses `lstatSync` on the ENUMERATED name, so a
 *   symlink is rejected as a candidate before any byte is read. The text path
 *   follows an in-root link on purpose; the binary detector must not, or one
 *   container would report twice under two paths. Containment is still
 *   established first, exactly as in the text path.
 *
 *   SIZE BEFORE READ. The effective `maxFileSizeBytes` gate runs against the
 *   entry's own size and rejects before opening for content. The default is an
 *   operational default, not a parser ceiling: an operator who raises it is
 *   supported, so nothing here assumes a bound smaller than the configured one.
 *
 * `headerAccepts` is an optional cheap prefilter. Only the first `headerBytes`
 * are read for it -- FROM THE SAME CHECKED DESCRIPTOR the bulk read then
 * continues from (see readChecked), so the acceptor never sees a byte of an
 * object the checks have not covered. One open per candidate.
 */
export function readBinaryCandidate(
  root: string,
  relPath: string,
  config: SecretLoopConfig,
  headerAccepts?: (head: Buffer, size: number) => boolean,
  headerBytes = 16,
  /** A bare function is the TEST-ONLY `afterOpen` seam; an object may also carry the accounting callback. */
  hooks?: ReadHooksArg
): BinaryCandidate {
  const located = locateInsideRoot(root, relPath);
  if ("skipped" in located) return located;
  const full = path.join(root, relPath);
  try {
    // lstat: the entry itself, never its target. DELIBERATELY KEPT as the
    // gate: it does not dereference, so a final-component symlink present at
    // this moment is refused as "not-a-file" without being followed. It is
    // also the identity capture the open is checked against.
    const stat = lstatSync(full, { bigint: true });
    // A symlink lands here too, by design (see above). "not a regular file" is
    // the same answer for both, and this reason is never counted: the caller
    // discards a candidate skip and lets the text path account for the file.
    if (!stat.isFile()) return { skipped: "not-a-file" };
    if (Number(stat.size) > config.maxFileSizeBytes) return { skipped: "oversized" };
    const read = readChecked(
      full,
      located.realRoot,
      { dev: stat.dev, ino: stat.ino },
      config.maxFileSizeBytes,
      hooksOf(hooks),
      headerAccepts ? { bytes: headerBytes, accepts: headerAccepts } : undefined
    );
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
