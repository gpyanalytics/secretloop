import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "fs";
import { createHash, randomBytes } from "crypto";
import { homedir } from "os";
import * as path from "path";

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
  | "symlink"
  | "foreign-owner"
  | "permissive"
  | "inaccessible";

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
      return `${where}, or its pending directory, is owned by another account, so consent records cannot be trusted; SecretLoop does not change its permissions.`;
    case "permissive":
      return `${where}, or its pending directory, is readable or writable by other accounts and SecretLoop could not make it private (0700), so consent records cannot be trusted.`;
    case "inaccessible":
      return `${where} could not be inspected, so consent records cannot be trusted.`;
  }
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
 *     the home directory, whose permissions are the user's and are not changed
 *     here; a component swapped between this check and the operation that
 *     follows is not caught. That window is open only to an account that can
 *     already write those paths, which is the same-user trust boundary the
 *     documentation states.
 *   - Mode bits do not show POSIX ACL entries (Linux setfacl, macOS chmod +a).
 *     A directory with mode 0700 and an ACL granting another account passes.
 *     No claim is made about ACLs on POSIX.
 *   - Windows: ownership and mode fields from Node are not meaningful and are
 *     not consulted; only the symbolic-link/junction refusal applies. The
 *     records' protection there is the inherited ACL of the profile directory
 *     (measured: the default profile denied another ordinary user; a
 *     permissive parent let another account read a record). No ACL is set or
 *     verified here; that remains an open release decision.
 */
export function assertPrivateStore(): void {
  for (const dir of [consentDir(), pendingDir()]) {
    let st;
    try {
      st = lstatSync(dir);
    } catch {
      throw new ConsentStoreError("inaccessible");
    }
    if (st.isSymbolicLink()) throw new ConsentStoreError("symlink");
    if (!st.isDirectory()) throw new ConsentStoreError("not-a-directory");
    if (process.platform === "win32" || typeof process.geteuid !== "function") continue;
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
  try {
    mkdirSync(pendingDir(), { recursive: true, mode: 0o700 });
  } catch {
    throw new ConsentStoreError("inaccessible");
  }
  assertPrivateStore();
}

export function writeRecord(record: ConsentRecord): void {
  ensureDir();
  const target = recordPath(record.id);
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

/** Parses a record, returning null for anything malformed. Never throws. */
function parseRecord(file: string): ConsentRecord | null {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
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
  // A store that has never been created holds no record; a store that IS
  // there, or is a link pretending to be, must pass the checks first.
  if (!existsSync(consentDir()) && !isSymlink(consentDir())) return null;
  assertPrivateStore();
  const file = recordPath(id);
  if (!existsSync(file)) return null;
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
  if (!existsSync(consentDir()) && !isSymlink(consentDir())) return [];
  assertPrivateStore();
  let entries: string[];
  try {
    entries = readdirSync(pendingDir());
  } catch {
    return [];
  }
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
  assertPrivateStore();
  rmSync(recordPath(id), { force: true });
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
  assertPrivateStore();
  const from = recordPath(id);
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
