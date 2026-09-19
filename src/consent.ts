import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "fs";
import { createHash, randomBytes } from "crypto";
import { homedir } from "os";
import * as path from "path";
import {
  CheckTarget,
  checkWindowsStore,
  currentUserSid,
  protectDirectory,
  WindowsAclProblem,
} from "./consent-acl-win";

/**
 * Durable consent records for a single credential verification.
 *
 * Verification is the one thing SecretLoop does that sends a credential to a
 * third party, and an MCP client is not a person. So the authorization for it
 * cannot travel over the protocol in any form: no consent argument, no token, no
 * "the user already approved" claim in a tool call. It lives on disk, written by
 * the server and flipped to approved only by a human answering a prompt in their
 * own terminal.
 *
 * A record commits to a HASH of the credential, never the credential. That is
 * what makes the consent specific: approving "the GitHub token in src/app.ts"
 * authorizes exactly the bytes that were there when the human looked, so a
 * repository that swaps the value afterwards gets nothing sent on its behalf.
 *
 * The trust boundary is the OS user. Anything running as you can read and write
 * these files, so this defends against a hostile repository and a compromised
 * or over-eager agent — not against malware already running as you. The README
 * says so in those words.
 */

export const CONSENT_VERSION = 1;

/** How long an approval stays good. Short: it authorizes one action, now. */
export const APPROVAL_TTL_MS = 5 * 60_000;

export type ConsentState = "pending" | "approved";

export interface ConsentRecord {
  version: number;
  id: string;
  state: ConsentState;
  fingerprint: string;
  /** The canonical (realpath'd) workspace root the finding was resolved in. */
  path: string;
  /** Repo-relative file, for re-resolving the finding from disk. */
  file: string;
  line: number;
  ruleId: string;
  provider: string;
  /** SHA-256 of the credential value. The commitment — never the value. */
  commitment: string;
  createdAt: string;
  approvedAt?: string;
  expiresAt?: string;
}

/**
 * Where records live. Overridable for tests only — never from a tool argument,
 * which would let a client point the server at a directory of its own forgeries.
 */
let consentRoot: string | undefined;

export function setConsentRootForTests(dir: string | undefined): void {
  consentRoot = dir;
}

export function consentDir(): string {
  return consentRoot ?? path.join(homedir(), ".secretloop");
}

export function pendingDir(): string {
  return path.join(consentDir(), "pending");
}

/**
 * Why the store was refused. A closed set, so a caller can show a bounded
 * sentence without echoing a path, a record, a commitment or an OS message.
 *
 *   not-a-directory  the store path exists and is not a directory
 *   symlink          the store path or its pending directory is a symbolic
 *                    link (a junction on Windows); nothing is followed
 *   foreign-owner    a directory is owned by another account; it is never
 *                    chmod'ed and never trusted
 *   permissive       a directory this account owns was found readable or
 *                    writable by others and could NOT be repaired to 0700
 *   inaccessible     the directory could not be inspected at all
 */
export type ConsentStoreProblem =
  | "not-a-directory"
  | "not-a-regular-file"
  | "oversized-record"
  | "record-permissive"
  | "symlink"
  | "foreign-owner"
  | "permissive"
  | "inaccessible"
  // Windows only. The security descriptor is what protects a record there, so these name
  // the ways it can fail. See src/consent-acl-win.ts for the rules and the adversary class.
  | "identity-unreadable"
  | "unsupported-location"
  | "unsafe-parent"
  | "foreign-principal"
  | "deny-ace"
  | "null-dacl"
  | "empty-dacl"
  | "owner-not-granted"
  | "insufficient-rights"
  | "owner-unreadable"
  | "acl-tooling-unavailable"
  | "acl-inspection-failed"
  | "acl-inspection-malformed"
  | "acl-enforcement-failed";

/**
 * Thrown by every consent operation when the store fails its private-store
 * checks. Carries only the problem code and a fixed sentence: the path is the
 * user's own home directory and needs no echoing, and an OS error message can
 * carry a path.
 */
export class ConsentStoreError extends Error {
  constructor(public readonly problem: ConsentStoreProblem) {
    super(describeStoreProblem(problem));
    this.name = "ConsentStoreError";
  }
}

/** The one sentence callers show. Fixed text per problem; nothing interpolated. */
export function describeStoreProblem(problem: ConsentStoreProblem): string {
  const where = "the consent store (.secretloop under your home directory)";
  switch (problem) {
    case "not-a-directory":
      return `${where} exists but is not a directory, so consent records cannot be trusted.`;
    case "symlink":
      return `${where}, or its pending directory, is a symbolic link, so consent records cannot be trusted; SecretLoop does not follow it.`;
    case "foreign-owner":
      // Widened because a RECORD can now fail this too: the directories may be perfectly private
      // while one file inside them is not, and sending the reader to inspect the wrong object is
      // its own kind of wrong answer. The closing clause stays true of both.
      return `${where}, its pending directory, or a record in it, is owned by another account, so consent records cannot be trusted; SecretLoop does not change its permissions.`;
    case "permissive":
      return `${where}, or its pending directory, is readable or writable by other accounts and SecretLoop could not make it private (0700), so consent records cannot be trusted.`;
    case "record-permissive":
      // Deliberately NOT the directory sentence: no repair is attempted on a record, and 0700 is a
      // directory's mode. Saying SecretLoop "could not make it private" would describe an attempt
      // that never happened.
      return `a consent record in ${where} is readable or writable by other accounts, so consent records cannot be trusted; SecretLoop refuses it rather than changing its permissions.`;
    case "not-a-regular-file":
      return `a consent record in ${where} is not a regular file, so consent records cannot be trusted.`;
    case "oversized-record":
      return `a consent record in ${where} is far larger than any record SecretLoop writes, so consent records cannot be trusted.`;
    case "inaccessible":
      return `${where} could not be inspected, so consent records cannot be trusted.`;
    case "identity-unreadable":
      return `SecretLoop could not determine which Windows account it is running as, so consent records cannot be trusted.`;
    case "unsupported-location":
      return `${where} is on a kind of location SecretLoop has not established these checks for (a network or UNC path), so consent records cannot be trusted.`;
    case "unsafe-parent":
      return `a directory on the path to ${where} can be replaced or re-permissioned by another account, so consent records cannot be trusted.`;
    case "foreign-principal":
      return `${where}, its pending directory, or a record in it grants access to another account, so consent records cannot be trusted.`;
    case "deny-ace":
      return `${where}, its pending directory, or a record in it carries an access-control entry SecretLoop does not accept, so consent records cannot be trusted.`;
    case "null-dacl":
      return `${where}, its pending directory, or a record in it has no access control at all and is open to every account, so consent records cannot be trusted.`;
    case "empty-dacl":
      return `${where}, its pending directory, or a record in it grants access to no one, so consent records cannot be trusted.`;
    case "owner-not-granted":
      return `${where}, its pending directory, or a record in it does not grant access to your own account, so consent records cannot be trusted.`;
    case "insufficient-rights":
      return `${where}, or its pending directory, does not give your own account the access SecretLoop needs, so consent records cannot be trusted.`;
    case "owner-unreadable":
      return `${where}, its pending directory, or a record in it could not be inspected, so consent records cannot be trusted.`;
    case "acl-tooling-unavailable":
      return `SecretLoop could not run the built-in Windows tools it uses to inspect permissions, so consent records cannot be trusted.`;
    case "acl-inspection-failed":
      return `SecretLoop could not complete its inspection of the Windows permissions on ${where}, so consent records cannot be trusted.`;
    case "acl-inspection-malformed":
      return `SecretLoop did not understand the Windows permission information it was given for ${where}, so consent records cannot be trusted.`;
    case "acl-enforcement-failed":
      return `SecretLoop could not apply owner-only Windows permissions to a newly created ${where}, so consent records cannot be trusted.`;
  }
}

/**
 * Fixed guidance, safe to print beside the sentence above. Windows has its own text because
 * the remedy is different there: permissions are an access-control list, not a mode.
 */
export const CONSENT_STORE_GUIDANCE_WINDOWS =
  "Inspect .secretloop in your profile folder yourself, with icacls: it, its pending directory and the " +
  "records in it should be owned by you and grant only you, SYSTEM and Administrators, and every folder " +
  "on the way to it should be one no other account can rename or re-permission. Move a store you did not " +
  "create aside rather than deleting or loosening it, then ask the client to request the verification again.";

/** The guidance for the platform this process is running on. */
export function consentStoreGuidance(): string {
  return process.platform === "win32" ? CONSENT_STORE_GUIDANCE_WINDOWS : CONSENT_STORE_GUIDANCE;
}

/** Fixed guidance, safe to print beside the sentence above. */
export const CONSENT_STORE_GUIDANCE =
  "Inspect .secretloop in your home directory yourself: it and its pending directory should be real " +
  "directories owned by you with mode 0700. Move a store you did not create aside rather than deleting or " +
  "loosening it, then ask the client to request the verification again.";

/**
 * THE STORE POLICY, checked before every consent operation -- reads, listing,
 * approval, claim, deletion and writes -- not only when a record is created.
 *
 * Accepted on POSIX, for BOTH `consentDir()` and `pendingDir()`:
 *   - an actual directory reached by `lstat` (a symbolic link is refused, and
 *     nothing behind it is inspected, repaired or written);
 *   - owned by the effective user (`process.geteuid()`);
 *   - no group or other bits set (`mode & 0o077 === 0`). A directory THIS
 *     account owns that has such bits is repaired with `chmod 0700` and then
 *     re-checked; a directory another account owns is never chmod'ed.
 *
 * Why fail closed here: `ensureDir` used to swallow a failed chmod, so a store
 * that could not be made private was used as if it were. Measured
 * (consent-file-security-assessment): in a root-owned world-writable store,
 * another ordinary user could list record ids, plant files beside them and
 * rename records away; the 0600 record itself stayed unreadable. Records are a
 * map of which credentials exist where, and an approval in a store others can
 * alter is not one this code should act on.
 *
 * WHAT THIS DOES NOT ESTABLISH, stated so it is not read as more:
 *   - It inspects the final components only. The path above `.secretloop` is
 *     the home directory, whose permissions are the user's and are not
 *     inspected or changed here; a component swapped between this check and
 *     the operation that follows is not caught. That window is open to any
 *     account that can write the home directory -- normally only this account
 *     and root, which is the documented trust boundary; a home directory that
 *     is itself writable by others widens it, and this check does not see that.
 *   - Mode bits do not show POSIX ACL entries (Linux setfacl, macOS chmod +a).
 *     A directory with mode 0700 and an ACL granting another account passes,
 *     and that account can then read, plant or replace records. So "only this
 *     account can reach the records" is established here only up to the mode
 *     bits and ownership; no claim is made about ACLs on POSIX.
 *   - Windows: ownership and mode fields from Node are not meaningful and are
 *     not consulted; only the symbolic-link/junction refusal applies. The
 *     records' protection there is the inherited ACL of the profile directory
 *     (measured: the default profile denied another ordinary user; a
 *     permissive parent let another account read a record). No ACL is set or
 *     verified here; that remains an open release decision.
 */
export function assertPrivateStore(): void {
  assertStoreScope({ includePending: true, records: [] });
}

/**
 * What an operation is about to touch. The Windows check covers the ancestor chain, the
 * directories and the named records in one pass, so the caller states its scope rather than
 * asking directory by directory.
 */
interface StoreScope {
  includePending: boolean;
  /** Record files this operation will read, trust, replace, claim or delete. */
  records: string[];
}

/**
 * The store policy for this platform.
 *
 * POSIX is unchanged: the two directories, by mode bits and ownership. Record FILES are not
 * inspected there — that remains a separate scope, as the notes above say.
 *
 * Windows applies the descriptor rules in `./consent-acl-win`: the whole ancestor chain, both
 * directories, and EVERY record in scope. A directory that passes licenses nothing about its
 * children: a record planted by another account and later caught by a parent's protection has
 * its inherited access list rewritten to look private while its owner stays the attacker, so
 * ownership is checked per record. That attack was measured before this was written.
 */
function assertStoreScope(scope: StoreScope): void {
  if (process.platform !== "win32") {
    assertPrivateDir(consentDir());
    if (scope.includePending) assertPrivateDir(pendingDir());
    return;
  }
  const userSid = currentUserSid();
  if (!userSid) throw new ConsentStoreError("identity-unreadable");
  const targets: CheckTarget[] = [{ path: consentDir(), kind: "directory" }];
  if (scope.includePending) targets.push({ path: pendingDir(), kind: "directory" });
  for (const record of scope.records) targets.push({ path: record, kind: "record" });
  const verdict = checkWindowsStore(consentDir(), targets, userSid);
  if (!verdict.ok) throw new ConsentStoreError(translateAclProblem(verdict.problem));
}

/** The descriptor rules speak of reparse points; the store has always called that a symlink. */
function translateAclProblem(problem: WindowsAclProblem): ConsentStoreProblem {
  return problem === "reparse-point" ? "symlink" : problem;
}

/**
 * True when the readers may answer "no record" without a store check: the
 * path does not exist and is not a symbolic link. A dangling link is not
 * "absent" -- it is a link, and the check refuses it.
 */
function absent(p: string): boolean {
  return !existsSync(p) && !isSymlink(p);
}

/** One directory against the policy above. */
function assertPrivateDir(dir: string): void {
  let st;
  try {
    st = lstatSync(dir);
  } catch {
    throw new ConsentStoreError("inaccessible");
  }
  if (st.isSymbolicLink()) throw new ConsentStoreError("symlink");
  if (!st.isDirectory()) throw new ConsentStoreError("not-a-directory");
  if (process.platform === "win32" || typeof process.geteuid !== "function") return;
  if (st.uid !== process.geteuid()) throw new ConsentStoreError("foreign-owner");
  if ((st.mode & 0o077) !== 0) {
    // Owner-owned and permissive: repair, then re-verify rather than assume.
    try {
      chmodSync(dir, 0o700);
    } catch {
      throw new ConsentStoreError("permissive");
    }
    let after;
    try {
      after = lstatSync(dir);
    } catch {
      throw new ConsentStoreError("inaccessible");
    }
    if (after.isSymbolicLink() || !after.isDirectory() || after.uid !== process.geteuid() || (after.mode & 0o077) !== 0) {
      throw new ConsentStoreError("permissive");
    }
  }
}

/** SHA-256 of a credential value. The only form a value takes on disk. */
export function commitmentOf(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * A record's identity: the pair it authorizes.
 *
 * Derived rather than random so a repeated first call finds the record it
 * already wrote instead of littering the directory with duplicates a human
 * would have to approve one by one.
 */
export function recordId(fingerprint: string, canonicalPath: string): string {
  return createHash("sha256")
    // NUL separator, written as an escape rather than as the literal byte it
    // was: a raw NUL inside a template literal is invisible in an editor and
    // does not survive being retyped, which is a poor property for something
    // that decides which consent record authorizes which credential. NUL
    // itself is the right choice - it cannot occur in a path or a fingerprint,
    // so no two different pairs can collide by concatenation.
    .update(`${canonicalPath}\0${fingerprint}`, "utf8")
    .digest("hex")
    .slice(0, 32);
}

function recordPath(id: string): string {
  return path.join(pendingDir(), `${id}.json`);
}

/**
 * Creates the store with owner-only permissions, then PROVES it.
 *
 * 0700 on the directory and 0600 on each file. These hold a hash rather than a
 * credential, so a leak is not immediately a key — but it is a list of which
 * credentials exist, where, and which provider they belong to, which is a map
 * worth denying to other accounts on a shared machine.
 *
 * First use creates both directories. Any later state goes through
 * assertPrivateStore, which repairs an owner-owned permissive directory and
 * refuses everything else. The earlier version swallowed a failed chmod and
 * continued; it no longer does.
 */
function ensureDir(): void {
  // A symbolic link at either level would be FOLLOWED by a recursive mkdir
  // and by the chmod; refuse before creating anything behind it.
  for (const dir of [consentDir(), pendingDir()]) {
    try {
      if (lstatSync(dir).isSymbolicLink()) throw new ConsentStoreError("symlink");
    } catch (err) {
      if (err instanceof ConsentStoreError) throw err;
      /* absent: created below */
    }
  }
  if (process.platform === "win32") {
    ensureDirWindows();
    return;
  }
  try {
    mkdirSync(pendingDir(), { recursive: true, mode: 0o700 });
  } catch {
    throw new ConsentStoreError("inaccessible");
  }
  assertPrivateStore();
}

/**
 * Creating the store on Windows.
 *
 * The parent chain is established BEFORE anything is created, which is the whole point: an
 * account that cannot write the parent cannot pre-create the store name, plant a record beside
 * it, or hold a handle to a directory that does not yet exist. Applying an access list later
 * would not have done that — it does not revoke a handle anyone already holds.
 *
 * A store that already exists is verified, never repaired. If this call created a directory and
 * a later step fails, it removes ONLY what it created, and only with a non-recursive rmdir, so
 * nothing pre-existing can be deleted. A directory that something else has meanwhile written to
 * will refuse to go, and is left in place rather than emptied.
 */
function ensureDirWindows(): void {
  const userSid = currentUserSid();
  if (!userSid) throw new ConsentStoreError("identity-unreadable");

  // One inspection before anything is created: the ancestor chain always, and the store itself
  // when it is already there. A store this call did not create is therefore judged BEFORE
  // anything is put inside it, rather than being written into and refused afterwards -- and
  // because both travel in the same call, that costs no extra subprocess.
  const before = checkWindowsStore(
    consentDir(),
    existsSync(consentDir()) ? [{ path: consentDir(), kind: "directory" as const }] : [],
    userSid
  );
  if (!before.ok) throw new ConsentStoreError(translateAclProblem(before.problem));

  let madeStore = false;
  let madePending = false;
  const undo = (): void => {
    if (madePending) {
      try {
        rmdirSync(pendingDir());
      } catch {
        /* not empty, or gone: left exactly as found */
      }
    }
    if (madeStore) {
      try {
        rmdirSync(consentDir());
      } catch {
        /* not empty, or gone: left exactly as found */
      }
    }
  };

  if (!existsSync(consentDir())) {
    try {
      mkdirSync(consentDir());
      madeStore = true;
    } catch {
      throw new ConsentStoreError("inaccessible");
    }
    const protection = protectDirectory(consentDir(), userSid);
    if (!protection.ok) {
      undo();
      throw new ConsentStoreError(translateAclProblem(protection.problem));
    }
  }
  if (!existsSync(pendingDir())) {
    try {
      mkdirSync(pendingDir());
      madePending = true;
    } catch {
      undo();
      throw new ConsentStoreError("inaccessible");
    }
  }
  const verdict = checkWindowsStore(
    consentDir(),
    [
      { path: consentDir(), kind: "directory" },
      { path: pendingDir(), kind: "directory" },
    ],
    userSid
  );
  if (!verdict.ok) {
    undo();
    throw new ConsentStoreError(translateAclProblem(verdict.problem));
  }
}

export function writeRecord(record: ConsentRecord): void {
  ensureDir();
  const target = recordPath(record.id);
  // Replacing a record that fails the checks would quietly repair unsafe state. Refuse instead,
  // so the user is told. On POSIX this scope carries no record checks and the call is a no-op
  // beyond the directory rules already applied by ensureDir.
  assertStoreScope({ includePending: true, records: [target] });
  // Written to a temp name and renamed, so a reader never sees a half-written
  // record — and created with the mode rather than chmod'ed afterwards, which
  // would leave a window where it is world-readable.
  const tmp = `${target}.tmp.${process.pid}.${randomBytes(6).toString("hex")}`;
  writeFileSync(tmp, JSON.stringify(record, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
  renameSync(tmp, target);
  try {
    chmodSync(target, 0o600);
  } catch {
    /* best effort; the create mode already applied */
  }
}

/**
 * A consent record is a small object with a fixed set of fields. A deliberately long one — a
 * nested file inside a long workspace path, with every optional field present — serializes to
 * about 600 bytes. 64 KiB is a hundredfold margin, and it bounds what a file sitting at a record
 * path can cost this process. Before this bound the reader would have read a file of any size.
 */
const MAX_RECORD_BYTES = 64 * 1024;

/**
 * Reads a record through ONE descriptor, deciding what the object is before any byte of it is
 * read, and refusing anything that is not a record this account wrote privately.
 *
 * Why a descriptor rather than `lstat` then `readFileSync`: the two would name the path twice and
 * decide on the first while reading the second. Here the classification and the read are the same
 * open file, so what is judged is what is read.
 *
 * `O_NONBLOCK` is the difference between refusing a named pipe and hanging on one: measured before
 * this change, `readRecord` on a FIFO at a record path never returned and had to be killed.
 * `O_NOFOLLOW` refuses a symbolic link at the FINAL component — the record name itself. It says
 * nothing about the directories above it, which are the store's own checks, and it is not a
 * defence against a parent being replaced.
 *
 * Returns null when there is no record. Throws `ConsentStoreError` when something IS there and
 * fails the checks: "nothing here" and "this cannot be trusted" are different answers, and a
 * caller that treated the second as the first would report no pending request and hide a refusal.
 */
function readRecordText(file: string): string | null {
  // Both flags are POSIX; on Windows they are undefined, and the descriptor rules in
  // ./consent-acl-win have already judged the record before this is reached.
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const nonBlock = fsConstants.O_NONBLOCK ?? 0;
  let fd: number;
  try {
    fd = openSync(file, fsConstants.O_RDONLY | noFollow | nonBlock);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    // O_NOFOLLOW reports a symbolic link as ELOOP on Linux and macOS.
    if (code === "ELOOP" || code === "EMLINK") throw new ConsentStoreError("symlink");
    // The open is the authority for a record this account can read. When it is DENIED, the
    // descriptor can say nothing, so one `lstat` names the reason. It cannot change the outcome —
    // the record is refused either way — so a component swapped between the two alters the wording
    // of a refusal and nothing else. A record owned by another account is the common case here:
    // it is unreadable precisely because it belongs to someone else.
    if (code === "EACCES" || code === "EPERM") {
      try {
        const owner = lstatSync(file);
        if (typeof process.geteuid === "function" && owner.uid !== process.geteuid()) {
          throw new ConsentStoreError("foreign-owner");
        }
      } catch (inner) {
        if (inner instanceof ConsentStoreError) throw inner;
        /* the reason cannot be named; fall through */
      }
    }
    throw new ConsentStoreError("inaccessible");
  }
  try {
    let st;
    try {
      st = fstatSync(fd);
    } catch {
      throw new ConsentStoreError("inaccessible");
    }
    if (!st.isFile()) throw new ConsentStoreError("not-a-regular-file");
    if (process.platform !== "win32" && typeof process.geteuid === "function") {
      if (st.uid !== process.geteuid()) throw new ConsentStoreError("foreign-owner");
      if ((st.mode & 0o077) !== 0) throw new ConsentStoreError("record-permissive");
    }
    if (st.size > MAX_RECORD_BYTES) throw new ConsentStoreError("oversized-record");
    const buffer = Buffer.alloc(Number(st.size));
    let read = 0;
    while (read < buffer.length) {
      let n: number;
      try {
        n = readSync(fd, buffer, read, buffer.length - read, read);
      } catch {
        throw new ConsentStoreError("inaccessible");
      }
      if (n === 0) break;
      read += n;
    }
    return buffer.subarray(0, read).toString("utf8");
  } finally {
    // Every path through this function closes the descriptor, including the refusals above.
    try {
      closeSync(fd);
    } catch {
      /* already gone */
    }
  }
}

/**
 * Parses a record. Returns null when there is no record or its contents are malformed; throws
 * ConsentStoreError when the object at that path fails the checks in `readRecordText`.
 */
function parseRecord(file: string): ConsentRecord | null {
  const text = readRecordText(file);
  if (text === null) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Partial<ConsentRecord>;
  const strings: Array<keyof ConsentRecord> = [
    "id",
    "fingerprint",
    "path",
    "file",
    "ruleId",
    "provider",
    "commitment",
    "createdAt",
  ];
  for (const key of strings) {
    if (typeof r[key] !== "string" || (r[key] as string).length === 0) return null;
  }
  if (r.version !== CONSENT_VERSION) return null;
  if (r.state !== "pending" && r.state !== "approved") return null;
  if (typeof r.line !== "number" || !Number.isFinite(r.line)) return null;
  // A commitment that is not a SHA-256 hex digest cannot have been written by
  // this code, so the record is a forgery or corrupt either way.
  if (!/^[0-9a-f]{64}$/.test(r.commitment as string)) return null;
  if (r.state === "approved" && typeof r.expiresAt !== "string") return null;
  return r as ConsentRecord;
}

/**
 * The record for `id`, null when there is none. Throws ConsentStoreError when
 * the store fails its checks: "no record" and "the store cannot be trusted"
 * are different answers, and a caller that treated the second as the first
 * would write a fresh pending record into a store it should not use.
 */
export function readRecord(id: string): ConsentRecord | null {
  // A store that has never been created holds no record, and so does a
  // store whose pending directory is gone (it is recreated on the next
  // write); whatever IS there, or is a link pretending to be, must pass the
  // checks first. "Absent" never means "unsafe", and the reverse.
  if (absent(consentDir())) return null;
  const pendingAbsent = absent(pendingDir());
  const file = recordPath(id);
  // Order matters, and not in the obvious way. The check SKIPS a target that is not there, so
  // naming a record that does not yet exist protects nothing: it would be created, found, and
  // parsed without ever having been looked at. Deciding here that there is no record ends the
  // call before anything is parsed, so nothing unchecked can be read. What remains is the
  // ordinary check-then-use window -- a record present now and replaced before the read -- which
  // naming it does NOT close, and which no path-based inspection can.
  // `existsSync` follows a link, so a DANGLING one at a record path read as "no record" here while
  // `listRecords`, which finds the name by enumeration, refused it as a link. The two readers must
  // agree. `absent()` is the existing test for "not there, and not a link pretending to be".
  const present = !pendingAbsent && !absent(file);
  assertStoreScope({ includePending: !pendingAbsent, records: present ? [file] : [] });
  if (pendingAbsent || !present) return null;
  // No second existence test: the open inside parseRecord is the one that decides, so the object
  // judged is the object read rather than one named a moment earlier.
  const parsed = parseRecord(file);
  // The same rule listRecords applies, so the two readers agree: a record whose
  // contents disagree with the name it is filed under is not one this code
  // wrote. No caller reads record.id today — toolVerify derives the id from the
  // request and re-checks every field against it — so this closes no known hole.
  // It keeps the invariant true for the next caller, who may not re-derive.
  if (!parsed || parsed.id !== id) return null;
  return parsed;
}

/**
 * Every readable record. Malformed files are skipped, not fatal; an unsafe
 * store throws ConsentStoreError (see readRecord). A store that does not exist
 * yet is simply empty.
 */
export function listRecords(): ConsentRecord[] {
  if (absent(consentDir())) return [];
  const pendingAbsent = absent(pendingDir());
  assertStoreScope({ includePending: !pendingAbsent, records: [] });
  if (pendingAbsent) return [];
  let entries: string[];
  try {
    entries = readdirSync(pendingDir());
  } catch {
    return [];
  }
  // The names come from a directory that has just passed its checks; every record they name is
  // then checked on its own before any of it is parsed. Two passes, because the second cannot be
  // built until the first has approved the directory it reads the names from -- and the second
  // pass covers exactly the entries this call is about to parse, taken from the SAME listing, so
  // the set checked and the set read cannot drift apart.
  assertStoreScope({
    includePending: true,
    records: entries.filter((e) => e.endsWith(".json")).map((e) => path.join(pendingDir(), e)),
  });
  const out: ConsentRecord[] = [];
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    const parsed = parseRecord(path.join(pendingDir(), entry));
    // A record whose filename disagrees with its own id is not one this code
    // wrote; treating it as valid would let a planted file authorize anything.
    if (parsed && `${parsed.id}.json` === entry) out.push(parsed);
  }
  return out;
}

export function findByFingerprint(fingerprint: string): ConsentRecord[] {
  return listRecords().filter((r) => r.fingerprint === fingerprint);
}

function isSymlink(p: string): boolean {
  try {
    return lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
}

export function deleteRecord(id: string): void {
  const target = recordPath(id);
  assertStoreScope({ includePending: true, records: [target] });
  rmSync(target, { force: true });
}

export function isExpired(record: ConsentRecord, now = Date.now()): boolean {
  if (record.state !== "approved" || !record.expiresAt) return false;
  const at = Date.parse(record.expiresAt);
  return !Number.isFinite(at) || at <= now;
}

/**
 * Claims a record for one use, atomically.
 *
 * rename is the primitive: it either moves the file or fails because someone
 * else moved it first, and there is no interval in which two callers both
 * believe they hold it. unlink would leave that interval open, and a check-then-
 * delete would leave it wide.
 *
 * Callers must invoke this BEFORE the provider call, so a replay loses the race
 * rather than the credential being sent twice. Returns false when the record was
 * already claimed, already gone, or never existed.
 */
export function consumeRecord(id: string): boolean {
  const from = recordPath(id);
  // The claim happens before the credential is transmitted, so the record it claims is checked
  // here too, not only the directories around it.
  assertStoreScope({ includePending: true, records: [from] });
  const to = `${from}.consumed.${process.pid}.${randomBytes(6).toString("hex")}`;
  try {
    renameSync(from, to);
  } catch {
    return false;
  }
  rmSync(to, { force: true });
  return true;
}

/** File mode of a record, for the test that asserts 0600. */
export function recordMode(id: string): number | null {
  try {
    return statSync(recordPath(id)).mode & 0o777;
  } catch {
    return null;
  }
}

export function approveRecord(
  record: ConsentRecord,
  commitment: string,
  now = Date.now()
): ConsentRecord {
  const approved: ConsentRecord = {
    ...record,
    state: "approved",
    // The CURRENT value's hash, not the one the record was created with. If the
    // credential changed between the request and the human looking at it, what
    // they saw and approved is what is on disk now.
    commitment,
    approvedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + APPROVAL_TTL_MS).toISOString(),
  };
  writeRecord(approved);
  return approved;
}
