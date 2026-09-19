/**
 * MACOS EXTENDED-ACL INSPECTION FOR THE CONSENT STORE.
 *
 * Why this exists. On Linux the POSIX ACL mask and the group bits of `st_mode` move together, so
 * `(mode & 0o077) === 0` already excludes every effective named-user and named-group entry —
 * measured, both directions, with no escape hatch. macOS is NFSv4-style and has no mask, so the
 * mode says nothing at all about extended entries. Measured with the product's own writer: under
 * a parent carrying `file_inherit`/`directory_inherit` ACEs, `writeRecord` produced a store and a
 * pending directory at mode 0700 and a record at mode 0600, every one of them carrying
 * `everyone inherited allow …`, and Node reported only `700`, `700` and `600`. The record granted
 * `everyone` read and write while the product believed it was private.
 *
 * The policy, approved as D-ACL-2, is deliberately blunt: **any** extended ACE on a store
 * directory or a record refuses. That is a support restriction, not a claim that every ACL is
 * unsafe — on Linux a masked entry grants nothing, and macOS configurations that grant nobody
 * anything are refused here all the same. `docs/mcp.md` names the legitimate cases this rejects.
 * Nothing is ever repaired: see the refusal guidance for why removing an ACE would be worse.
 *
 * WHAT THIS IS NOT. The inspection is path-based. `/bin/ls` has no file-descriptor form, so this
 * and the product's later `openSync` are two lookups of the same name, not two uses of one
 * descriptor. It does not make the lifecycle atomic, it says nothing about who could read the
 * object before this call, and it cannot revoke a descriptor another process already holds.
 */

import { execFileSync } from "child_process";
import { remainingMs, spendHelperBytes, spendHelperCall } from "./consent-budget";

/**
 *   extended-acl         the object carries at least one extended ACL entry
 *   acl-tool-unavailable /bin/ls is missing, is not executable, or could not be started
 *   acl-unreadable       the inspection ran but its answer could not be trusted: it failed,
 *                        timed out, exceeded a bound, or did not validate
 */
export type MacAclProblem = "extended-acl" | "acl-tool-unavailable" | "acl-unreadable";

export type MacAclVerdict = { ok: true } | { ok: false; problem: MacAclProblem };

/** The object to inspect, split so the uncontrolled part of the path is never printed. */
export interface MacAclTarget {
  /** Passed as the child's working directory. Never appears in the output. */
  parent: string;
  /** Passed as the only operand. Must survive `isInspectableBasename`. */
  basename: string;
}

/** Absolute and literal. Never resolved through PATH. */
const LS = "/bin/ls";

const TIMEOUT_MS = 5_000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_ACE_LINES = 128;

/**
 * `ls -lden` emits one header line and then one line per ACE. Both are pinned, because a
 * positive "no ACEs" answer is only worth having if it came from output that fully validated.
 */
const MODE_LINE = /^[-dlbcps][-rwxSsTt]{9}[@+.]?\s/;
// Measured form: ` <index>: <principal> [inherited] allow|deny <comma,separated,perms>`.
// The `inherited` qualifier is real and was missed by a first, stricter version of this pattern
// — a test caught it. It failed CLOSED (the object was still refused) but reported the wrong
// reason, so the grammar tolerates qualifiers between the principal and allow/deny while keeping
// the tail strict. Anything that still does not match refuses.
const ACE_LINE = /^ \d+: .+ (?:allow|deny) [a-z_,]+$/;

/**
 * A basename this code is willing to hand to the tool.
 *
 * The output is line-oriented, so a name containing a newline would split the header across two
 * lines and make an ACE line indistinguishable from a filename continuation — measured. Record
 * names come from `readdir` of the pending directory, which is exactly what an adversary with
 * write access there controls, so this is not hypothetical. Such a name is REFUSED rather than
 * inspected: a record that cannot be inspected is not a record that can be trusted.
 */
export function isInspectableBasename(basename: string): boolean {
  return basename.length > 0 && !/[\n\r\0]/.test(basename);
}

/**
 * Validate the tool's answer, or reject it. Exported for tests, which drive it with fabricated
 * output to reach bounds a filesystem fixture cannot construct.
 *
 * Every rejection is an `acl-unreadable`, never "no ACEs". Ambiguity must not read as absence.
 */
export function parseLsAclOutput(
  stdout: string,
  expectedBasename: string
): { ok: true; aceCount: number; allowCount: number } | { ok: false } {
  if (typeof stdout !== "string") return { ok: false };
  if (Buffer.byteLength(stdout, "utf8") > MAX_OUTPUT_BYTES) return { ok: false };

  const lines = stdout.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  if (lines.length === 0) return { ok: false };

  const header = lines[0];
  if (!MODE_LINE.test(header)) return { ok: false };
  // The load-bearing check. The name the tool printed must be EXACTLY the basename that was
  // asked for. If any part of the path had leaked into the output, or the header had been
  // truncated, or a continuation line had appeared, this is what catches it.
  if (!header.endsWith(" " + expectedBasename)) return { ok: false };

  const aces = lines.slice(1);
  if (aces.length > MAX_ACE_LINES) return { ok: false };
  let allowCount = 0;
  for (const line of aces) {
    if (!ACE_LINE.test(line)) return { ok: false };
    // One token of the grammar that is already validated strictly, and no more: an entry is
    // either an `allow` or a `deny`. This is NOT an evaluation of rights or principals.
    if (/ allow /.test(line)) allowCount++;
  }
  return { ok: true, aceCount: aces.length, allowCount };
}

/** Swappable for tests only, so bounded-failure behaviour can be driven without a real tool. */
export type LsRunner = (target: MacAclTarget) => { ok: true; stdout: string } | { ok: false; problem: MacAclProblem };
let runner: LsRunner | undefined;

export function setLsRunnerForTests(fn: LsRunner | undefined): void {
  runner = fn;
}

function runLs(target: MacAclTarget): ReturnType<LsRunner> {
  // Charged BEFORE the child starts, so an exhausted allowance stops the work rather than
  // reporting it afterwards. Throws out of here; the public entry point translates it.
  spendHelperCall();
  if (runner) return runner(target);
  let stdout: string;
  try {
    stdout = execFileSync(LS, ["-lden", "--", target.basename], {
      cwd: target.parent,
      encoding: "utf8",
      // The child gets what is LEFT of the operation, not a fresh full timeout each time.
      // Otherwise 512 children at five seconds each is not a bounded operation.
      timeout: remainingMs(TIMEOUT_MS),
      // The child is killed outright rather than asked politely, so a wedged inspection cannot
      // outlive the call.
      killSignal: "SIGKILL",
      maxBuffer: MAX_OUTPUT_BYTES,
      // A fixed, minimal environment: the C locale so the text is the text that was measured,
      // and a PATH that is never consulted anyway because the executable is absolute.
      env: { LC_ALL: "C", PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { status?: number | null };
    // The tool itself being absent or unusable is a different answer from the tool running and
    // failing, because the first is an environment SecretLoop does not support and the second
    // may be the object's own fault.
    if (e.code === "ENOENT" || e.code === "EACCES" || e.code === "ENOTDIR") {
      return { ok: false, problem: "acl-tool-unavailable" };
    }
    return { ok: false, problem: "acl-unreadable" };
  }
  spendHelperBytes(Buffer.byteLength(stdout, "utf8"));
  return { ok: true, stdout };
}

/**
 * How strict to be about entries that are present.
 *
 *   "any"          no extended entry at all. For the STORE and its records, which SecretLoop
 *                  creates itself: a pristine object is achievable there, so it is required.
 *   "allow-only"   entries are tolerated as long as none of them is an `allow`. For ANCESTORS,
 *                  which are pre-existing system state nobody chose.
 *
 * WHY "allow-only" EXISTS, and it is not a convenience. Measured: every stock macOS home
 * directory carries `0: group:everyone deny delete`, which Apple puts there by default. It grants
 * nobody anything -- a deny entry can only remove access, never add it. Requiring ancestors to
 * have no entry at all therefore refuses EVERY unmodified macOS installation, which a
 * GitHub-hosted runner demonstrated by refusing its own `/Users/runner` during the packaging
 * smoke. Telling users to delete an entry Apple ships would be worse advice than the message.
 *
 * RATIFIED. D-ACL-2 approved "refuse any extended ACE" for the STORE and its records, and that is
 * unchanged. This conservative ancestor rule is now approved separately and on its own terms:
 * refuse any `allow` entry on an ancestor, including one that names only the owner; do not refuse
 * a valid deny-only entry merely because it exists; and still refuse anything malformed,
 * unsupported or ambiguous.
 *
 * Refusing an owner-only `allow` is a COMPATIBILITY RESTRICTION, not a finding. It is not evidence
 * that the entry grants an attacker anything — it grants only the owner. It is refused because
 * deciding otherwise would mean resolving a principal UUID to a uid and evaluating rights, which
 * is far more interpretation of this output than anything else here does, and getting that wrong
 * fails open. The cost is documented in docs/mcp.md rather than hidden.
 */
export type AceStrictness = "any" | "allow-only";

/** One object. Any doubt refuses. */
export function inspectMacAcl(target: MacAclTarget, strictness: AceStrictness = "any"): MacAclVerdict {
  if (!isInspectableBasename(target.basename)) return { ok: false, problem: "acl-unreadable" };
  const run = runLs(target);
  if (!run.ok) return { ok: false, problem: run.problem };
  const parsed = parseLsAclOutput(run.stdout, target.basename);
  if (!parsed.ok) return { ok: false, problem: "acl-unreadable" };
  const offending = strictness === "any" ? parsed.aceCount : parsed.allowCount;
  if (offending > 0) return { ok: false, problem: "extended-acl" };
  return { ok: true };
}

/** Every target, stopping at the first refusal. */
export function checkMacAcl(targets: MacAclTarget[], strictness: AceStrictness = "any"): MacAclVerdict {
  for (const target of targets) {
    const verdict = inspectMacAcl(target, strictness);
    if (!verdict.ok) return verdict;
  }
  return { ok: true };
}
