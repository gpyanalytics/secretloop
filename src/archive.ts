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

export interface ArchiveListing {
  containerKind: ContainerKind;
  members: ArchiveMember[];
  /**
   * Entries that were in the container but not offered, by the existing skip
   * reasons: `oversized` for a member over the size cap, `unreadable` for
   * everything else (encrypted, unsupported method, unsafe name, duplicate,
   * truncated, CRC mismatch, non-regular entry, beyond the member cap).
   */
  skipped: { oversized: number; unreadable: number };
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
export function openArchive(bytes: Buffer, outerPath: string, maxMemberBytes: number): ArchiveListing | null {
  try {
    const budget = bytes.length * MAX_DECOMPRESSION_RATIO;
    if (bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b) return parseZip(bytes, budget, maxMemberBytes);
    if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return openGzip(bytes, outerPath, budget, maxMemberBytes);
    if (bytes.length >= 512 && isUstar(bytes)) return parseTar(bytes, "tar", budget, maxMemberBytes);
    return null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------- gzip

function openGzip(bytes: Buffer, outerPath: string, budget: number, maxMemberBytes: number): ArchiveListing | null {
  // Pure-gzip bound first: the output IS the member, so it is capped like a
  // file. Only when that overflows is the larger tgz bound tried, and only to
  // find out whether the stream is a tar whose members are bounded one by one.
  const streamCap = Math.min(maxMemberBytes, budget);
  let out: Buffer;
  try {
    out = gunzipSync(bytes, { maxOutputLength: Math.max(1, streamCap) });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ERR_BUFFER_TOO_LARGE" || budget <= streamCap) {
      return isTooLarge(err) ? { containerKind: "gzip", members: [], skipped: { oversized: 1, unreadable: 0 } } : null;
    }
    let wide: Buffer;
    try {
      wide = gunzipSync(bytes, { maxOutputLength: budget });
    } catch (e) {
      return isTooLarge(e) ? { containerKind: "gzip", members: [], skipped: { oversized: 1, unreadable: 0 } } : null;
    }
    if (!isUstar(wide)) return { containerKind: "gzip", members: [], skipped: { oversized: 1, unreadable: 0 } };
    return parseTar(wide, "tgz", budget, maxMemberBytes);
  }
  if (isUstar(out)) return parseTar(out, "tgz", budget, maxMemberBytes);
  return { containerKind: "gzip", members: [{ member: gzipStreamName(outerPath), bytes: out }], skipped: { oversized: 0, unreadable: 0 } };
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
  const members: ArchiveMember[] = [];
  const skipped = { oversized: 0, unreadable: 0 };
  const seen = new Set<string>();
  let offset = 0;
  let entries = 0;
  let total = 0;
  while (offset + BLOCK <= b.length) {
    const hdr = b.subarray(offset, offset + BLOCK);
    if (hdr.every((x) => x === 0)) break; // end-of-archive block
    if (!checksumValid(hdr)) break; // the walk stops at the first bad header
    const size = parseOctal(hdr, 124, 12);
    if (size === null) break;
    const dataOffset = offset + BLOCK;
    const extent = Math.ceil(size / BLOCK) * BLOCK;
    if (dataOffset + extent > b.length) {
      skipped.unreadable++; // truncated inside this member's data
      break;
    }
    entries++;
    if (entries > MAX_MEMBERS_PER_ARCHIVE) {
      skipped.unreadable++;
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
    if (directory) {
      offset = dataOffset + extent;
      continue; // structure, not content
    }
    if (!regular) {
      // symlink, hardlink, char/block device, fifo, GNU long-name, pax headers
      skipped.unreadable++;
      offset = dataOffset + extent;
      continue;
    }
    const name = sanitizeMemberName(rawName);
    if (name === null || seen.has(name)) {
      skipped.unreadable++;
    } else if (size > maxMemberBytes) {
      seen.add(name);
      skipped.oversized++;
    } else if (total + size > budget) {
      skipped.unreadable++;
      break; // decompression budget spent; nothing after this is offered
    } else {
      seen.add(name);
      total += size;
      if (size > 0) members.push({ member: name, bytes: b.subarray(dataOffset, dataOffset + size) });
    }
    offset = dataOffset + extent;
  }
  return { containerKind: kind, members, skipped };
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

function parseZip(b: Buffer, budget: number, maxMemberBytes: number): ArchiveListing | null {
  if (b.length < 22) return null;
  const eocd = findEocd(b);
  if (eocd < 0) return null;
  const entryCount = b.readUInt16LE(eocd + 10);
  const cdSize = b.readUInt32LE(eocd + 12);
  const cdOffset = b.readUInt32LE(eocd + 16);
  if (entryCount === ZIP64_MARK16 || cdSize === ZIP64_MARK32 || cdOffset === ZIP64_MARK32) return null; // ZIP64
  if (cdOffset + cdSize > eocd) return null;

  const members: ArchiveMember[] = [];
  const skipped = { oversized: 0, unreadable: 0 };
  const seen = new Set<string>();
  let pos = cdOffset;
  let total = 0;
  for (let i = 0; i < entryCount; i++) {
    if (pos + 46 > cdOffset + cdSize || b.readUInt32LE(pos) !== SIG_CENTRAL) return null; // corrupt directory
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
    if (pos + 46 + nameLen > cdOffset + cdSize) return null;
    const rawName = b.toString(flags & 0x0800 ? "utf8" : "latin1", pos + 46, pos + 46 + nameLen);
    pos += 46 + nameLen + extraLen + commentLen;

    if (i >= MAX_MEMBERS_PER_ARCHIVE) {
      skipped.unreadable += entryCount - i;
      break;
    }
    const isDir = rawName.endsWith("/") || (externalAttr & 0x10) !== 0 || ((externalAttr >>> 16) & 0o170000) === 0o040000;
    if (isDir) continue;
    if (csize === ZIP64_MARK32 || usize === ZIP64_MARK32 || localOffset === ZIP64_MARK32) { skipped.unreadable++; continue; }
    if (flags & 0x0001) { skipped.unreadable++; continue; } // encrypted: never decrypted
    if (method !== 0 && method !== 8) { skipped.unreadable++; continue; }
    const name = sanitizeMemberName(rawName);
    if (name === null || seen.has(name)) { skipped.unreadable++; continue; }
    if (usize > maxMemberBytes) { seen.add(name); skipped.oversized++; continue; }
    if (total + usize > budget) { skipped.unreadable++; break; }

    if (localOffset + 30 > b.length || b.readUInt32LE(localOffset) !== SIG_LOCAL) { skipped.unreadable++; continue; }
    const dataStart = localOffset + 30 + b.readUInt16LE(localOffset + 26) + b.readUInt16LE(localOffset + 28);
    if (dataStart + csize > b.length) { skipped.unreadable++; continue; }
    seen.add(name);
    if (usize === 0) continue; // nothing to scan; counted toward the entry cap only

    let out: Buffer;
    if (method === 0) {
      if (csize !== usize) { skipped.unreadable++; continue; }
      out = b.subarray(dataStart, dataStart + usize);
    } else {
      try {
        out = inflateRawSync(b.subarray(dataStart, dataStart + csize), { maxOutputLength: usize });
      } catch {
        skipped.unreadable++;
        continue;
      }
      if (out.length !== usize) { skipped.unreadable++; continue; }
    }
    if (crc32(out) !== crc) { skipped.unreadable++; continue; }
    total += usize;
    members.push({ member: name, bytes: out });
  }
  return { containerKind: "zip", members, skipped };
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
