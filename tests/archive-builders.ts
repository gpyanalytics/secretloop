import { deflateRawSync, gzipSync } from "zlib";
import { crc32 } from "../src/archive";

/**
 * Deterministic in-memory archive builders for the archive tests. Every field
 * a real tool would vary (timestamps, uid/gid, mode, extra fields) is pinned,
 * so a test's archive is the same bytes every run.
 */

export interface ZipEntry {
  name: string;
  data: Buffer;
  /** 0 stored, 8 deflate; anything else is written as-is (unsupported). */
  method?: number;
  /** General-purpose flags; bit 0 marks the entry encrypted. */
  flags?: number;
  /** Override the stored CRC (to simulate corruption). */
  crc?: number;
  /** Override the declared uncompressed size. */
  usize?: number;
  /** Payload bytes as written to the container (defaults to the compressed data). */
  payload?: Buffer;
  dir?: boolean;
}

function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n & 0xffff, 0);
  return b;
}
function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

/** A ZIP with a full central directory, entries in the given order. */
export function buildZip(entries: ZipEntry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.dir && !e.name.endsWith("/") ? `${e.name}/` : e.name, "utf8");
    const method = e.method ?? 8;
    const data = e.dir ? Buffer.alloc(0) : e.data;
    const payload = e.payload ?? (method === 8 ? deflateRawSync(data) : data);
    const crc = e.crc ?? crc32(data);
    const usize = e.usize ?? data.length;
    const flags = (e.flags ?? 0) | 0x0800; // UTF-8 names
    const local = Buffer.concat([
      u32(0x04034b50), u16(20), u16(flags), u16(method), u16(0), u16(0x21),
      u32(crc), u32(payload.length), u32(usize), u16(name.length), u16(0), name, payload,
    ]);
    const central = Buffer.concat([
      u32(0x02014b50), u16(20), u16(20), u16(flags), u16(method), u16(0), u16(0x21),
      u32(crc), u32(payload.length), u32(usize), u16(name.length), u16(0), u16(0), u16(0), u16(0),
      u32(e.dir ? (0o755 << 16) | 0x10 : 0o644 << 16), u32(offset), name,
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(cd.length), u32(offset), u16(0)]);
  return Buffer.concat([...locals, cd, eocd]);
}

export interface TarEntry {
  name: string;
  data?: Buffer;
  /** '0' regular (default), '5' dir, '2' symlink, '1' hardlink, '3' char dev, 'L' GNU longname, 'x' pax */
  type?: string;
  linkname?: string;
  /** Corrupt the checksum field. */
  badChecksum?: boolean;
}

function octal(n: number, width: number): Buffer {
  return Buffer.from(n.toString(8).padStart(width - 1, "0") + "\0", "latin1");
}

/** A ustar archive with pinned metadata and a two-block terminator. */
export function buildTar(entries: TarEntry[], terminate = true): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const data = e.data ?? Buffer.alloc(0);
    const hdr = Buffer.alloc(512, 0);
    let name = e.name;
    let prefix = "";
    if (name.length > 100) {
      const cut = name.lastIndexOf("/", 155);
      prefix = name.slice(0, cut);
      name = name.slice(cut + 1);
    }
    hdr.write(name, 0, 100, "utf8");
    octal(e.type === "5" ? 0o755 : 0o644, 8).copy(hdr, 100);
    octal(0, 8).copy(hdr, 108);
    octal(0, 8).copy(hdr, 116);
    octal(e.type === "5" ? 0 : data.length, 12).copy(hdr, 124);
    octal(0, 12).copy(hdr, 136);
    hdr.write("        ", 148, 8, "latin1");
    hdr.write(e.type ?? "0", 156, 1, "latin1");
    if (e.linkname) hdr.write(e.linkname, 157, 100, "utf8");
    hdr.write("ustar\0", 257, 6, "latin1");
    hdr.write("00", 263, 2, "latin1");
    if (prefix) hdr.write(prefix, 345, 155, "utf8");
    let sum = 0;
    for (const b of hdr) sum += b;
    if (e.badChecksum) sum += 7;
    Buffer.from(sum.toString(8).padStart(6, "0") + "\0 ", "latin1").copy(hdr, 148);
    blocks.push(hdr);
    // Regular files carry data; so do GNU long-name and pax entries, whose
    // "data" is the extension record the header's size field announces.
    if (e.type === undefined || e.type === "0" || data.length > 0) {
      const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512, 0);
      data.copy(padded);
      blocks.push(padded);
    }
  }
  if (terminate) blocks.push(Buffer.alloc(1024, 0));
  return Buffer.concat(blocks);
}

/** gzip with an optional FNAME header (which gzipSync cannot write). */
export function buildGzip(data: Buffer, fname?: string): Buffer {
  const plain = gzipSync(data, { level: 6 });
  if (!fname) {
    // Pin MTIME to zero so the bytes are stable.
    plain.writeUInt32LE(0, 4);
    return plain;
  }
  const raw = deflateRawSync(data, { level: 6 });
  const header = Buffer.concat([
    Buffer.from([0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0x00, 0x03]),
    Buffer.from(fname, "latin1"),
    Buffer.from([0]),
  ]);
  return Buffer.concat([header, raw, u32(crc32(data)), u32(data.length)]);
}
