import { gunzipSync, inflateRawSync } from "zlib";

/**
 * Archive containers, one layer deep.
 *
 * Contract frozen in archive-v1-preimplementation-freeze-v0.4.0.md (benchmark
 * workspace, Phase A.1 amendment governs). This module turns ONE outer file
 * into in-memory members and nothing else: it never writes to disk, never
 * resolves a member name against any filesystem, never opens a member that is
 * itself an archive, and never decrypts. The caller (workspace.scanFiles)
 * scans each member exactly as it would scan a file of the same bytes.
 *
 * Supported shapes, exactly one per outer file: [zip], [tar], [gzip],
 * [gzip -> tar]. A gzip stream wrapping a ustar container is one conventional
 * artifact, not nesting; a gzip or zip INSIDE a member is a second layer and
 * stays opaque.
 *
 * Pure: no I/O, no clock, no randomness. Members come back in central-
 * directory / header order, so identical input yields identical output.
 *
 * What the parser says about itself follows the archive-coverage-disclosure
 * contract: every entry it declines is counted under a bounded reason, records
 * that are not members are counted as such, and a walk that stops says so.
 */

export type ContainerKind = "zip" | "tar" | "gzip" | "tgz";

/**
 * The canonical identity of an archive member. The display path
 * `<container>!/<member>` is DERIVED from this and never parsed back: a real
 * file literally named `a.zip!/m.txt` gets no `source`, so the two cannot
 * collide in a fingerprint even though their display strings are equal.
 */
export interface ArchiveSource {
  kind: "archive-member";
  /** Outer repo-relative path, as the walker produced it. */
  container: string;
  containerKind: ContainerKind;
  /** Normalized member path (sanitizeMemberName), or the gzip stream name. */
  member: string;
}

/** Frozen limits. Not configurable: adding a knob was explicitly out of scope. */
export const MAX_MEMBERS_PER_ARCHIVE = 10_000;
export const MAX_MEMBER_PATH_CHARS = 1024;
export const MAX_DECOMPRESSION_RATIO = 100;
/** Enough header for the ustar magic at offset 257. */
export const ARCHIVE_HEADER_BYTES = 265;
export const MEMBER_SEPARATOR = "!/";

export interface ArchiveMember {
  member: string;
  bytes: Buffer;
}

/**
 * Why a container that carried archive magic was not opened. Bounded, stable
 * codes (archive-coverage-disclosure A.1 §4): `unsupported-feature` is ZIP64;
 * `malformed` is everything the parser could not read as the format it claims.
 */
export type ContainerNotOpenedReason = "unsupported-feature" | "malformed";

/**
 * Why an enumerated entry was not offered as a member. Each code names exactly
 * the branch that produced it and nothing finer: every integrity failure is one
 * `malformed`. `binary` is decided by the caller (the NUL heuristic), never here.
 */
export type MemberRefusalReason =
  | "unsupported-feature"
  | "encrypted"
  | "unsupported-compression"
  | "unsafe-name"
  | "duplicate-name"
  | "non-regular-entry"
  | "malformed"
  | "oversized"
  | "binary";

/** Why a walk ended before the container's last entry. */
export type EnumerationStopReason = "member-cap" | "decompression-budget" | "truncated" | "malformed-header";

export interface ArchiveEnumeration {
  complete: boolean;
  /** Present only when `complete` is false. */
  reason?: EnumerationStopReason;
  /**
   * Entries the container DECLARES (ZIP central directory) that were never
   * inspected because the walk stopped. A tar declares nothing, so a stopped
   * tar walk leaves this at 0 and its remainder is unknown.
   */
  declaredNotInspected: number;
}

export interface ArchiveListing {
  containerKind: ContainerKind;
  members: ArchiveMember[];
  /** Entries enumerated and not offered, counted by the reason that refused them. */
  refused: Partial<Record<MemberRefusalReason, number>>;
  /** Zero-length regular members: enumerated, nothing to scan, fully covered. */
  empty: number;
  /**
   * tar pax (`x`/`g`) and GNU long-name (`L`/`K`) records. They are not members;
   * v1 does not apply their extensions to the entry that follows (declared limit).
   */
  metadataEntries: number;
  enumeration: ArchiveEnumeration;
}

/** A container whose magic was recognised but which the parser declined. */
export interface ArchiveNotOpened {
  notOpened: ContainerNotOpenedReason;
}

/** `null` means "not an archive at all"; the caller then treats the file as before. */
export type ArchiveOutcome = ArchiveListing | ArchiveNotOpened;

/**
 * The scan-level roll-up of container outcomes (A.1 §4). Counts only: no path,
 * no member name, no value. `members.scanned` is content offered to the text
 * scanner or reported by the PKCS#12 member detector.
 */
export interface ArchiveAccounting {
  containersOpened: number;
  containersNotOpened: Partial<Record<ContainerNotOpenedReason, number>>;
  members: {
    scanned: number;
    empty: number;
    excluded: number;
    refused: Partial<Record<MemberRefusalReason, number>>;
  };
  metadataEntries: number;
  enumeration: {
    incompleteContainers: number;
    declaredNotInspected: number;
    unknownRemainderContainers: number;
    byReason: Partial<Record<EnumerationStopReason, number>>;
  };
}

export function emptyArchiveAccounting(): ArchiveAccounting {
  return {
    containersOpened: 0,
    containersNotOpened: {},
    members: { scanned: 0, empty: 0, excluded: 0, refused: {} },
    metadataEntries: 0,
    enumeration: { incompleteContainers: 0, declaredNotInspected: 0, unknownRemainderContainers: 0, byReason: {} },
  };
}

function addCounts<K extends string>(into: Partial<Record<K, number>>, from: Partial<Record<K, number>>): void {
  for (const k of Object.keys(from) as K[]) into[k] = (into[k] ?? 0) + (from[k] ?? 0);
}

/** Adds `from` into `into`, field by field. */
export function mergeArchiveAccounting(into: ArchiveAccounting, from: ArchiveAccounting): void {
  into.containersOpened += from.containersOpened;
  addCounts(into.containersNotOpened, from.containersNotOpened);
  into.members.scanned += from.members.scanned;
  into.members.empty += from.members.empty;
  into.members.excluded += from.members.excluded;
  addCounts(into.members.refused, from.members.refused);
  into.metadataEntries += from.metadataEntries;
  into.enumeration.incompleteContainers += from.enumeration.incompleteContainers;
  into.enumeration.declaredNotInspected += from.enumeration.declaredNotInspected;
  into.enumeration.unknownRemainderContainers += from.enumeration.unknownRemainderContainers;
  addCounts(into.enumeration.byReason, from.enumeration.byReason);
}

/** Sum of a reason-count record. */
export function countOf(rec: Partial<Record<string, number>>): number {
  return Object.values(rec).reduce<number>((n, v) => n + (v ?? 0), 0);
}

/** True when the scan met at least one recognised container, opened or not. */
export function hasArchiveActivity(a: ArchiveAccounting): boolean {
  return a.containersOpened + countOf(a.containersNotOpened) > 0;
}

export function displayPath(source: ArchiveSource): string {
  return `${source.container}${MEMBER_SEPARATOR}${source.member}`;
}

/**
 * The synthetic member name of a pure gzip stream: the outer basename with its
 * final `.gz` or `.tgz` removed. Derived from the outer path ONLY -- the gzip
 * FNAME header is attacker-controlled metadata and never becomes a name.
 */
export function gzipStreamName(outerPath: string): string {
  const base = outerPath.slice(outerPath.lastIndexOf("/") + 1);
  for (const suffix of [".tgz", ".gz"]) {
    if (base.length > suffix.length && base.endsWith(suffix)) return base.slice(0, -suffix.length);
  }
  return base;
}

/** Cheap prefilter for readBinaryCandidate: magic bytes only, extension ignored. */
export function archiveHeaderAccepts(head: Buffer, size: number): boolean {
  if (head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b) {
    // Local file header, or an empty archive that is only its end record.
    return (head[2] === 0x03 && head[3] === 0x04) || (head[2] === 0x05 && head[3] === 0x06);
  }
  if (head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b) return true;
  return size >= 512 && isUstar(head);
}

function isUstar(b: Buffer): boolean {
  return b.length >= 262 && b.toString("latin1", 257, 262) === "ustar";
}

/**
 * The frozen member-name rules (§6.1). Returns the normalized name, or null
 * for anything that must be skipped. Normalization is only backslash -> slash
 * and one leading `./`; nothing else is rewritten, so a traversal can never
 * be "fixed" into an apparently safe name.
 */
export function sanitizeMemberName(raw: string): string | null {
  if (/[\u0000-\u001f\u007f]/.test(raw)) return null; // control characters, NUL included
  let name = raw.replace(/\\/g, "/");
  if (name.startsWith("./")) name = name.slice(2);
  if (name.length === 0 || name === "." || name === "/") return null;
  if (name.length > MAX_MEMBER_PATH_CHARS) return null;
  if (name.startsWith("/")) return null;
  if (/^[A-Za-z]:/.test(name)) return null;
  if (name.endsWith("/")) return null; // a directory, not content
  if (name.split("/").some((segment) => segment === "..")) return null;
  return name;
}

/**
 * Opens one container. Null means "not a supported archive" -- bad magic, no
 * central directory, corrupt stream, ZIP64 -- and the caller then treats the
 * file exactly as it did before this module existed. Never throws: any
 * unexpected condition inside the parsers is caught here and reported as null.
 *
 * `maxMemberBytes` is the caller's maxFileSizeBytes: a member is bounded like
 * a file. The archive's total decompression budget is MAX_DECOMPRESSION_RATIO
 * times the outer size, and no allocation ever trusts a declared size beyond
 * those two bounds.
 */
export function openArchive(bytes: Buffer, outerPath: string, maxMemberBytes: number): ArchiveOutcome | null {
  const budget = bytes.length * MAX_DECOMPRESSION_RATIO;
  // Recognition first, so a container that fails to parse is reported as one
  // (A.1 §3) rather than vanishing into the text path unremarked. The parsing
  // decisions below are the v1 ones; only what they report about themselves grew.
  let kind: "zip" | "gzip" | "tar" | null = null;
  if (bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b) kind = "zip";
  else if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) kind = "gzip";
  else if (bytes.length >= 512 && isUstar(bytes)) kind = "tar";
  if (kind === null) return null;
  try {
    if (kind === "zip") return parseZip(bytes, budget, maxMemberBytes);
    if (kind === "gzip") return openGzip(bytes, outerPath, budget, maxMemberBytes);
    return parseTar(bytes, "tar", budget, maxMemberBytes);
  } catch {
    return { notOpened: "malformed" };
  }
}

const COMPLETE: ArchiveEnumeration = { complete: true, declaredNotInspected: 0 };

function bump<K extends string>(rec: Partial<Record<K, number>>, k: K): void {
  rec[k] = (rec[k] ?? 0) + 1;
}

function listing(kind: ContainerKind, members: ArchiveMember[]): ArchiveListing {
  return { containerKind: kind, members, refused: {}, empty: 0, metadataEntries: 0, enumeration: { ...COMPLETE } };
}

// ------------------------------------------------------------------- gzip

function openGzip(bytes: Buffer, outerPath: string, budget: number, maxMemberBytes: number): ArchiveOutcome {
  // Pure-gzip bound first: the output IS the member, so it is capped like a
  // file. Only when that overflows is the larger tgz bound tried, and only to
  // find out whether the stream is a tar whose members are bounded one by one.
  const streamCap = Math.min(maxMemberBytes, budget);
  const oversizedStream = (): ArchiveListing => {
    const l = listing("gzip", []);
    l.refused.oversized = 1;
    return l;
  };
  let out: Buffer;
  try {
    out = gunzipSync(bytes, { maxOutputLength: Math.max(1, streamCap) });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ERR_BUFFER_TOO_LARGE" || budget <= streamCap) {
      return isTooLarge(err) ? oversizedStream() : { notOpened: "malformed" };
    }
    let wide: Buffer;
    try {
      wide = gunzipSync(bytes, { maxOutputLength: budget });
    } catch (e) {
      return isTooLarge(e) ? oversizedStream() : { notOpened: "malformed" };
    }
    if (!isUstar(wide)) return oversizedStream();
    return parseTar(wide, "tgz", budget, maxMemberBytes);
  }
  if (isUstar(out)) return parseTar(out, "tgz", budget, maxMemberBytes);
  return listing("gzip", [{ member: gzipStreamName(outerPath), bytes: out }]);
}

function isTooLarge(err: unknown): boolean {
  return (err as NodeJS.ErrnoException)?.code === "ERR_BUFFER_TOO_LARGE";
}

// -------------------------------------------------------------------- tar

const BLOCK = 512;

function parseOctal(b: Buffer, start: number, length: number): number | null {
  let s = b.toString("latin1", start, start + length);
  const nul = s.indexOf("\0");
  if (nul >= 0) s = s.slice(0, nul);
  s = s.trim();
  if (s.length === 0) return 0;
  if (!/^[0-7]{1,11}$/.test(s)) return null;
  return parseInt(s, 8);
}

function cString(b: Buffer, start: number, length: number): string {
  const s = b.toString("utf8", start, start + length);
  const nul = s.indexOf("\0");
  return nul >= 0 ? s.slice(0, nul) : s;
}

function checksumValid(hdr: Buffer): boolean {
  const declared = parseOctal(hdr, 148, 8);
  if (declared === null) return false;
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : hdr[i];
  return sum === declared;
}

function parseTar(b: Buffer, kind: "tar" | "tgz", budget: number, maxMemberBytes: number): ArchiveListing {
  const l = listing(kind, []);
  const seen = new Set<string>();
  let offset = 0;
  let entries = 0;
  let total = 0;
  // A tar declares no entry count, so a stop here always leaves an unknown
  // remainder; the reason is recorded and declaredNotInspected stays 0.
  const stop = (reason: EnumerationStopReason): void => {
    l.enumeration = { complete: false, reason, declaredNotInspected: 0 };
  };
  while (offset + BLOCK <= b.length) {
    const hdr = b.subarray(offset, offset + BLOCK);
    if (hdr.every((x) => x === 0)) break; // end-of-archive block
    if (!checksumValid(hdr)) {
      stop("malformed-header"); // the walk stops at the first bad header
      break;
    }
    const size = parseOctal(hdr, 124, 12);
    if (size === null) {
      stop("malformed-header");
      break;
    }
    const dataOffset = offset + BLOCK;
    const extent = Math.ceil(size / BLOCK) * BLOCK;
    if (dataOffset + extent > b.length) {
      bump(l.refused, "malformed"); // truncated inside this member's data
      stop("truncated");
      break;
    }
    entries++;
    if (entries > MAX_MEMBERS_PER_ARCHIVE) {
      stop("member-cap");
      break;
    }
    const type = hdr[156];
    let rawName = cString(hdr, 0, 100);
    if (isUstar(hdr)) {
      const prefix = cString(hdr, 345, 155);
      if (prefix.length > 0) rawName = `${prefix}/${rawName}`;
    }
    const regular = type === 0x30 || type === 0x00; // '0' or NUL
    const directory = type === 0x35; // '5'
    // pax extended/global headers and GNU long name/link records: metadata about
    // the next entry, not members. Their extensions are not applied (v1 limit).
    const metadata = type === 0x78 || type === 0x67 || type === 0x4c || type === 0x4b; // 'x' 'g' 'L' 'K'
    if (directory) {
      offset = dataOffset + extent;
      continue; // structure, not content
    }
    if (metadata) {
      l.metadataEntries++;
      offset = dataOffset + extent;
      continue;
    }
    if (!regular) {
      // symlink, hardlink, char/block device, fifo, vendor types
      bump(l.refused, "non-regular-entry");
      offset = dataOffset + extent;
      continue;
    }
    const name = sanitizeMemberName(rawName);
    if (name === null) {
      bump(l.refused, "unsafe-name");
    } else if (seen.has(name)) {
      bump(l.refused, "duplicate-name");
    } else if (size > maxMemberBytes) {
      seen.add(name);
      bump(l.refused, "oversized");
    } else if (total + size > budget) {
      stop("decompression-budget");
      break; // decompression budget spent; nothing after this is offered
    } else {
      seen.add(name);
      total += size;
      if (size > 0) l.members.push({ member: name, bytes: b.subarray(dataOffset, dataOffset + size) });
      else l.empty++;
    }
    offset = dataOffset + extent;
  }
  return l;
}

// -------------------------------------------------------------------- zip

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const ZIP64_MARK16 = 0xffff;
const ZIP64_MARK32 = 0xffffffff;

function findEocd(b: Buffer): number {
  // The end record is 22 bytes plus a comment of at most 65535.
  const floor = Math.max(0, b.length - 22 - 0xffff);
  for (let i = b.length - 22; i >= floor; i--) {
    if (b.readUInt32LE(i) === SIG_EOCD) return i;
  }
  return -1;
}

function parseZip(b: Buffer, budget: number, maxMemberBytes: number): ArchiveOutcome {
  const malformed: ArchiveNotOpened = { notOpened: "malformed" };
  if (b.length < 22) return malformed;
  const eocd = findEocd(b);
  if (eocd < 0) return malformed;
  const entryCount = b.readUInt16LE(eocd + 10);
  const cdSize = b.readUInt32LE(eocd + 12);
  const cdOffset = b.readUInt32LE(eocd + 16);
  if (entryCount === ZIP64_MARK16 || cdSize === ZIP64_MARK32 || cdOffset === ZIP64_MARK32) return { notOpened: "unsupported-feature" }; // ZIP64
  if (cdOffset + cdSize > eocd) return malformed;

  const l = listing("zip", []);
  const seen = new Set<string>();
  let pos = cdOffset;
  let total = 0;
  // The central directory declares entryCount, so a stop here leaves a KNOWN
  // number of entries that were never inspected: the current one and the rest.
  const stop = (reason: EnumerationStopReason, i: number): void => {
    l.enumeration = { complete: false, reason, declaredNotInspected: entryCount - i };
  };
  for (let i = 0; i < entryCount; i++) {
    if (pos + 46 > cdOffset + cdSize || b.readUInt32LE(pos) !== SIG_CENTRAL) return malformed; // corrupt directory
    const flags = b.readUInt16LE(pos + 8);
    const method = b.readUInt16LE(pos + 10);
    const crc = b.readUInt32LE(pos + 16);
    const csize = b.readUInt32LE(pos + 20);
    const usize = b.readUInt32LE(pos + 24);
    const nameLen = b.readUInt16LE(pos + 28);
    const extraLen = b.readUInt16LE(pos + 30);
    const commentLen = b.readUInt16LE(pos + 32);
    const externalAttr = b.readUInt32LE(pos + 38);
    const localOffset = b.readUInt32LE(pos + 42);
    if (pos + 46 + nameLen > cdOffset + cdSize) return malformed;
    const rawName = b.toString(flags & 0x0800 ? "utf8" : "latin1", pos + 46, pos + 46 + nameLen);
    pos += 46 + nameLen + extraLen + commentLen;

    if (i >= MAX_MEMBERS_PER_ARCHIVE) {
      stop("member-cap", i);
      break;
    }
    const isDir = rawName.endsWith("/") || (externalAttr & 0x10) !== 0 || ((externalAttr >>> 16) & 0o170000) === 0o040000;
    if (isDir) continue;
    if (csize === ZIP64_MARK32 || usize === ZIP64_MARK32 || localOffset === ZIP64_MARK32) { bump(l.refused, "unsupported-feature"); continue; }
    if (flags & 0x0001) { bump(l.refused, "encrypted"); continue; } // encrypted: never decrypted
    if (method !== 0 && method !== 8) { bump(l.refused, "unsupported-compression"); continue; }
    const name = sanitizeMemberName(rawName);
    if (name === null) { bump(l.refused, "unsafe-name"); continue; }
    if (seen.has(name)) { bump(l.refused, "duplicate-name"); continue; }
    if (usize > maxMemberBytes) { seen.add(name); bump(l.refused, "oversized"); continue; }
    if (total + usize > budget) { stop("decompression-budget", i); break; }

    if (localOffset + 30 > b.length || b.readUInt32LE(localOffset) !== SIG_LOCAL) { bump(l.refused, "malformed"); continue; }
    const dataStart = localOffset + 30 + b.readUInt16LE(localOffset + 26) + b.readUInt16LE(localOffset + 28);
    if (dataStart + csize > b.length) { bump(l.refused, "malformed"); continue; }
    seen.add(name);
    if (usize === 0) { l.empty++; continue; } // nothing to scan; counted toward the entry cap only

    let out: Buffer;
    if (method === 0) {
      if (csize !== usize) { bump(l.refused, "malformed"); continue; }
      out = b.subarray(dataStart, dataStart + usize);
    } else {
      try {
        out = inflateRawSync(b.subarray(dataStart, dataStart + csize), { maxOutputLength: usize });
      } catch {
        bump(l.refused, "malformed");
        continue;
      }
      if (out.length !== usize) { bump(l.refused, "malformed"); continue; }
    }
    if (crc32(out) !== crc) { bump(l.refused, "malformed"); continue; }
    total += usize;
    l.members.push({ member: name, bytes: out });
  }
  return l;
}

// ------------------------------------------------------------------ crc32
// Node only gained zlib.crc32 in 22.2; the supported floor is 18.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
