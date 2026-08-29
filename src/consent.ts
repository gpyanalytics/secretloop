import {
  chmodSync,
  existsSync,
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
 * Creates the store with owner-only permissions.
 *
 * 0700 on the directory and 0600 on each file. These hold a hash rather than a
 * credential, so a leak is not immediately a key — but it is a list of which
 * credentials exist, where, and which provider they belong to, which is a map
 * worth denying to other accounts on a shared machine.
 */
function ensureDir(): void {
  mkdirSync(pendingDir(), { recursive: true, mode: 0o700 });
  try {
    chmodSync(consentDir(), 0o700);
    chmodSync(pendingDir(), 0o700);
  } catch {
    // A pre-existing directory we cannot chmod is not worth refusing over; the
    // file mode below is the control that matters.
  }
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

export function readRecord(id: string): ConsentRecord | null {
  const file = recordPath(id);
  if (!existsSync(file)) return null;
  return parseRecord(file);
}

/** Every readable record. Malformed files are skipped, not fatal. */
export function listRecords(): ConsentRecord[] {
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

export function deleteRecord(id: string): void {
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
