import { test, suite, finish, assert } from "./harness";
import {
  openArchive,
  archiveHeaderAccepts,
  sanitizeMemberName,
  gzipStreamName,
  displayPath,
  MAX_MEMBERS_PER_ARCHIVE,
  MAX_MEMBER_PATH_CHARS,
  MAX_DECOMPRESSION_RATIO,
  MEMBER_SEPARATOR,
} from "../src/archive";
import { buildZip, buildTar, buildGzip } from "./archive-builders";

/**
 * The pure container layer, against archive-v1-preimplementation-freeze-v0.4.0.md
 * (Phase A.1). Nothing here touches the filesystem or the scanner.
 */

const MAX = 1_000_000; // maxFileSizeBytes default, the member cap
const text = (s: string) => Buffer.from(s, "utf8");
const README = text("# readme\nordinary text\n");

suite("archive.ts — frozen constants and helpers");

test("limits are the frozen values", () => {
  assert.strictEqual(MAX_MEMBERS_PER_ARCHIVE, 10_000);
  assert.strictEqual(MAX_MEMBER_PATH_CHARS, 1024);
  assert.strictEqual(MAX_DECOMPRESSION_RATIO, 100);
  assert.strictEqual(MEMBER_SEPARATOR, "!/");
});

test("display path is container + !/ + member and is never parsed back", () => {
  assert.strictEqual(
    displayPath({ kind: "archive-member", container: "a/b.zip", containerKind: "zip", member: "c/d.txt" }),
    "a/b.zip!/c/d.txt"
  );
});

test("gzip stream name derives from the outer path only", () => {
  assert.strictEqual(gzipStreamName("x/logs.gz"), "logs");
  assert.strictEqual(gzipStreamName("x/site.tar.gz"), "site.tar");
  assert.strictEqual(gzipStreamName("bundle.tgz"), "bundle");
  assert.strictEqual(gzipStreamName("weird.tgz.gz"), "weird.tgz");
  assert.strictEqual(gzipStreamName(".gz"), ".gz"); // nothing sensible to strip
});

test("header prefilter admits zip, empty zip, gzip and ustar; rejects everything else", () => {
  assert.ok(archiveHeaderAccepts(Buffer.from([0x50, 0x4b, 0x03, 0x04]), 100));
  assert.ok(archiveHeaderAccepts(Buffer.from([0x50, 0x4b, 0x05, 0x06]), 22));
  assert.ok(archiveHeaderAccepts(Buffer.from([0x1f, 0x8b, 0x08]), 20));
  const tar = buildTar([{ name: "a.txt", data: README }]);
  assert.ok(archiveHeaderAccepts(tar.subarray(0, 265), tar.length));
  assert.ok(!archiveHeaderAccepts(tar.subarray(0, 265), 300), "a tar needs at least one block");
  assert.ok(!archiveHeaderAccepts(text("plain text file that is not an archive").subarray(0, 265), 50));
  assert.ok(!archiveHeaderAccepts(Buffer.from([0x50, 0x4b, 0x07, 0x08]), 100));
});

// ---------------------------------------------------------------------------
suite("archive.ts — member path safety (§6.1)");

test("safe names pass through with only backslash and ./ normalization", () => {
  assert.strictEqual(sanitizeMemberName("a/b/c.txt"), "a/b/c.txt");
  assert.strictEqual(sanitizeMemberName("./a/b.txt"), "a/b.txt");
  assert.strictEqual(sanitizeMemberName("a\\b\\c.txt"), "a/b/c.txt");
  assert.strictEqual(sanitizeMemberName("a/./b.txt"), "a/./b.txt"); // not rewritten, not unsafe
});

for (const bad of ["../x", "a/../b", "nested/../../x", "..", "/abs/x", "\\abs\\x", "C:\\x", "c:/x", "", ".", "/", "dir/", "a\u0000b", "a\nb", "a\u007fb", "d/" + "x".repeat(1100)]) {
  test(`unsafe name is skipped, never rewritten: ${JSON.stringify(bad.slice(0, 20))}`, () => {
    assert.strictEqual(sanitizeMemberName(bad), null);
  });
}

test("exactly 1024 characters is allowed; 1025 is not", () => {
  assert.ok(sanitizeMemberName("x".repeat(1024)));
  assert.strictEqual(sanitizeMemberName("x".repeat(1025)), null);
});

// ---------------------------------------------------------------------------
suite("archive.ts — ZIP");

const secret = text("# cfg\nTOKEN=abc\n");

test("stored and deflated members come back byte-exact, in central-directory order", () => {
  const z = buildZip([{ name: "a.txt", data: README, method: 0 }, { name: "d/b.txt", data: secret, method: 8 }]);
  const l = openArchive(z, "x.zip", MAX)!;
  assert.strictEqual(l.containerKind, "zip");
  assert.deepStrictEqual(l.members.map((m) => m.member), ["a.txt", "d/b.txt"]);
  assert.ok(l.members[0].bytes.equals(README) && l.members[1].bytes.equals(secret));
  assert.deepStrictEqual(l.skipped, { oversized: 0, unreadable: 0 });
});

test("an empty archive (end record only) is a valid archive with no members", () => {
  const l = openArchive(buildZip([]), "e.zip", MAX)!;
  assert.deepStrictEqual(l.members, []);
});

test("directory entries are structure, not content, and are not counted as skipped", () => {
  const l = openArchive(buildZip([{ name: "a", data: Buffer.alloc(0), dir: true }, { name: "a/b.txt", data: README }]), "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["a/b.txt"]);
  assert.strictEqual(l.skipped.unreadable, 0);
});

test("encrypted entry (flag bit 0) is skipped and counted; never decrypted", () => {
  const l = openArchive(buildZip([{ name: "s.txt", data: secret, method: 0, flags: 1 }, { name: "r.txt", data: README }]), "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["r.txt"]);
  assert.strictEqual(l.skipped.unreadable, 1);
});

test("unsupported compression method is skipped and counted", () => {
  const l = openArchive(buildZip([{ name: "s.txt", data: secret, method: 12, payload: text("not bzip2 really") }, { name: "r.txt", data: README }]), "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["r.txt"]);
  assert.strictEqual(l.skipped.unreadable, 1);
});

test("unsafe member names are skipped and counted, one safe member survives", () => {
  const names = ["../s1", "/abs/s2", "C:\\abs\\s3", "nested/../../s4", "a/../s5", ""];
  const l = openArchive(buildZip([...names.map((name) => ({ name, data: secret })), { name: "safe/ok.txt", data: README }]), "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["safe/ok.txt"]);
  assert.strictEqual(l.skipped.unreadable, names.length);
});

test("duplicate normalized names: first wins, later occurrences skipped and counted", () => {
  const l = openArchive(buildZip([{ name: "dup.txt", data: README }, { name: "dup.txt", data: secret }, { name: ".\\dup.txt", data: secret }]), "x.zip", MAX)!;
  assert.strictEqual(l.members.length, 1);
  assert.ok(l.members[0].bytes.equals(README));
  assert.strictEqual(l.skipped.unreadable, 2);
});

test("a member over the size cap is skipped as oversized before any inflate", () => {
  const big = Buffer.alloc(MAX + 1, 0x61);
  const l = openArchive(buildZip([{ name: "big.txt", data: big }, { name: "r.txt", data: README }]), "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["r.txt"]);
  assert.deepStrictEqual(l.skipped, { oversized: 1, unreadable: 0 });
});

test("the decompression budget (100 x outer) stops processing; later members are never inflated", () => {
  const zeros = Buffer.alloc(200_000, 0);
  const z = buildZip([{ name: "z1", data: zeros }, { name: "z2", data: zeros }, { name: "z3", data: zeros }, { name: "last.txt", data: secret }]);
  assert.ok(z.length * MAX_DECOMPRESSION_RATIO < 3 * zeros.length, "fixture must exceed the ratio");
  const l = openArchive(z, "bomb.zip", MAX)!;
  assert.ok(l.members.every((m) => m.member !== "last.txt"), "member after the budget must not be offered");
  assert.ok(l.skipped.unreadable >= 1);
});

test("the member cap: entry 10,001 onward is never processed and the parse terminates", () => {
  const entries = [];
  for (let i = 0; i < MAX_MEMBERS_PER_ARCHIVE + 5; i++) entries.push({ name: `m/${i}`, data: Buffer.alloc(0), method: 0 });
  entries.push({ name: "last.txt", data: secret, method: 0 });
  const l = openArchive(buildZip(entries), "many.zip", MAX)!;
  assert.deepStrictEqual(l.members, [], "empty entries carry nothing and the secret sits beyond the cap");
  assert.strictEqual(l.skipped.unreadable, 6);
});

test("a member whose name exceeds 1024 characters is skipped", () => {
  const l = openArchive(buildZip([{ name: "d/" + "x".repeat(1100), data: secret }, { name: "r.txt", data: README }]), "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["r.txt"]);
});

test("CRC mismatch skips the member", () => {
  const l = openArchive(buildZip([{ name: "s.txt", data: secret, crc: 0xdeadbeef }, { name: "r.txt", data: README }]), "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["r.txt"]);
  assert.strictEqual(l.skipped.unreadable, 1);
});

test("declared size that the inflated output does not match skips the member", () => {
  const l = openArchive(buildZip([{ name: "s.txt", data: secret, usize: secret.length + 5 }, { name: "r.txt", data: README }]), "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["r.txt"]);
});

test("truncated archive and corrupted end record are not archives at all", () => {
  const z = buildZip([{ name: "s.txt", data: secret }, { name: "r.txt", data: README }]);
  assert.strictEqual(openArchive(z.subarray(0, z.length >> 1), "t.zip", MAX), null);
  const bad = Buffer.from(z);
  bad.write("XXXX", bad.lastIndexOf(Buffer.from("PK\x05\x06", "latin1")), "latin1");
  assert.strictEqual(openArchive(bad, "m.zip", MAX), null);
});

test("ZIP64 markers make the archive unsupported", () => {
  const z = buildZip([{ name: "s.txt", data: secret }]);
  const eocd = z.lastIndexOf(Buffer.from("PK\x05\x06", "latin1"));
  z.writeUInt32LE(0xffffffff, eocd + 16);
  assert.strictEqual(openArchive(z, "z64.zip", MAX), null);
});

test("local header outside the buffer skips that member without throwing", () => {
  const z = buildZip([{ name: "s.txt", data: secret }, { name: "r.txt", data: README }]);
  const cd = z.indexOf(Buffer.from("PK\x01\x02", "latin1"));
  z.writeUInt32LE(z.length + 100, cd + 42); // first entry's local offset points past the end
  const l = openArchive(z, "x.zip", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["r.txt"]);
});

// ---------------------------------------------------------------------------
suite("archive.ts — TAR");

test("ustar regular members come back byte-exact; directories are structure", () => {
  const t = buildTar([{ name: "src", type: "5" }, { name: "src/a.txt", data: secret }, { name: "README", data: README }]);
  const l = openArchive(t, "x.tar", MAX)!;
  assert.strictEqual(l.containerKind, "tar");
  assert.deepStrictEqual(l.members.map((m) => m.member), ["src/a.txt", "README"]);
  assert.ok(l.members[0].bytes.equals(secret));
});

test("symlink, hardlink, device, GNU long-name and pax entries are skipped and counted; targets never read", () => {
  const t = buildTar([
    { name: "passwd", type: "2", linkname: "../../etc/passwd" },
    { name: "hl", type: "1", linkname: "README" },
    { name: "dev", type: "3" },
    { name: "././@LongLink", type: "L", data: text("x".repeat(300)) },
    { name: "pax", type: "x", data: text("30 path=some/where\n") },
    { name: "data.txt", data: secret },
  ]);
  const l = openArchive(t, "x.tar", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["data.txt"]);
  assert.strictEqual(l.skipped.unreadable, 5);
});

test("a bad header checksum stops the walk; earlier members are kept", () => {
  const t = buildTar([{ name: "a.txt", data: README }, { name: "b.txt", data: secret, badChecksum: true }, { name: "c.txt", data: secret }]);
  const l = openArchive(t, "x.tar", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["a.txt"]);
});

test("a bad checksum on the FIRST header means no candidate at all", () => {
  const t = buildTar([{ name: "a.txt", data: README, badChecksum: true }]);
  const l = openArchive(t, "x.tar", MAX)!;
  assert.deepStrictEqual(l.members, []);
});

test("data truncated inside a member skips that member; the complete one before it is kept", () => {
  const t = buildTar([{ name: "a.txt", data: README }, { name: "b.txt", data: secret }], false);
  const cut = t.subarray(0, 512 + 512 + 512 + 5);
  const l = openArchive(cut, "x.tar", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["a.txt"]);
  assert.strictEqual(l.skipped.unreadable, 1);
});

test("a member declared larger than the cap is skipped and the walk continues", () => {
  const big = Buffer.alloc(MAX + 1, 0x61);
  const t = buildTar([{ name: "big.txt", data: big }, { name: "r.txt", data: README }]);
  const l = openArchive(t, "x.tar", 500_000)!; // cap below the member, above README
  assert.deepStrictEqual(l.members.map((m) => m.member), ["r.txt"]);
  assert.strictEqual(l.skipped.oversized, 1);
});

test("unsafe and duplicate names in a tar follow the same rules as zip", () => {
  const t = buildTar([{ name: "../s1", data: secret }, { name: "/abs/s2", data: secret }, { name: "dup.txt", data: README }, { name: "dup.txt", data: secret }, { name: "ok.txt", data: README }]);
  const l = openArchive(t, "x.tar", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), ["dup.txt", "ok.txt"]);
  assert.ok(l.members[0].bytes.equals(README));
  assert.strictEqual(l.skipped.unreadable, 3);
});

test("ustar prefix + name reconstructs a long path; two zero blocks alone are not a tar", () => {
  const long = "a/".repeat(60) + "leaf.txt"; // > 100 chars, uses the prefix field
  const l = openArchive(buildTar([{ name: long, data: secret }]), "x.tar", MAX)!;
  assert.deepStrictEqual(l.members.map((m) => m.member), [long]);
  assert.strictEqual(openArchive(Buffer.alloc(1024, 0), "empty.tar", MAX), null);
  assert.strictEqual(openArchive(Buffer.alloc(2048, 0x41), "noise.tar", MAX), null);
});

test("an archive stored as a tar member is returned opaquely as bytes; the layer never opens it", () => {
  const inner = buildZip([{ name: "inner.txt", data: secret }]);
  const l = openArchive(buildTar([{ name: "inner.zip", data: inner }]), "x.tar", MAX)!;
  assert.strictEqual(l.members.length, 1);
  assert.ok(l.members[0].bytes.equals(inner), "bytes, not members: depth stays 1");
});

// ---------------------------------------------------------------------------
suite("archive.ts — gzip and tgz");

test("pure gzip: one member named from the outer path; FNAME is ignored", () => {
  const l = openArchive(buildGzip(secret, "../../etc/creds"), "logs/app.log.gz", MAX)!;
  assert.strictEqual(l.containerKind, "gzip");
  assert.deepStrictEqual(l.members.map((m) => m.member), ["app.log"]);
  assert.ok(l.members[0].bytes.equals(secret));
  assert.ok(JSON.stringify(l).indexOf("creds") === -1);
});

test("concatenated gzip members with different FNAMEs decode to ONE stream in order, one identity", () => {
  const cat = Buffer.concat([buildGzip(README, "a.txt"), buildGzip(secret, "b.txt")]);
  const l = openArchive(cat, "cases/x.gz", MAX)!;
  assert.strictEqual(l.members.length, 1);
  assert.strictEqual(l.members[0].member, "x");
  assert.ok(l.members[0].bytes.equals(Buffer.concat([README, secret])));
  assert.ok(!JSON.stringify(l).includes("a.txt") && !JSON.stringify(l).includes("b.txt"));
});

test("truncated, corrupt and non-gzip inputs are not candidates", () => {
  const g = buildGzip(secret, "config.env");
  assert.strictEqual(openArchive(g.subarray(0, g.length - 12), "t.gz", MAX), null);
  const corrupt = Buffer.from(g);
  corrupt.fill(0xff, 10 + "config.env".length + 1, 10 + "config.env".length + 11);
  assert.strictEqual(openArchive(corrupt, "c.gz", MAX), null);
  assert.strictEqual(openArchive(text("not gzip at all, just text"), "n.gz", MAX), null);
});

test("a stream over the member cap is skipped as oversized (bounded by maxOutputLength, never fully allocated)", () => {
  const big = Buffer.alloc(MAX + 100, 0x61);
  const l = openArchive(buildGzip(big), "big.gz", MAX)!;
  assert.deepStrictEqual(l.members, []);
  assert.deepStrictEqual(l.skipped, { oversized: 1, unreadable: 0 });
});

test("gzip of a ustar is tgz: tar member paths are the identities, the wrapper's FNAME never is", () => {
  const t = buildTar([{ name: "pkg/settings.yaml", data: secret }, { name: "pkg/README.md", data: README }]);
  const l = openArchive(buildGzip(t, "should-not-appear.tar"), "site.tar.gz", MAX)!;
  assert.strictEqual(l.containerKind, "tgz");
  assert.deepStrictEqual(l.members.map((m) => m.member), ["pkg/settings.yaml", "pkg/README.md"]);
  assert.ok(!JSON.stringify(l).includes("should-not-appear"));
});

test("a .tgz whose payload is not a tar is handled as pure gzip (content-driven)", () => {
  const l = openArchive(buildGzip(secret), "cases/odd.tgz", MAX)!;
  assert.strictEqual(l.containerKind, "gzip");
  assert.deepStrictEqual(l.members.map((m) => m.member), ["odd"]);
});

test("tgz intermediate may exceed the member cap while every member stays under it", () => {
  // Pseudo-random printable members compress poorly, so the gzip stays well
  // inside the 100x budget while the tar itself is over the member cap.
  const noisy = (seed: number) => {
    const out = Buffer.alloc(200_000);
    let x = seed;
    for (let i = 0; i < out.length; i++) { x = (1103515245 * x + 12345) & 0x7fffffff; out[i] = 0x21 + ((x >> 16) % 90); }
    return out;
  };
  const t = buildTar([{ name: "a", data: noisy(1) }, { name: "b", data: noisy(2) }, { name: "c", data: noisy(3) }]);
  const outer = buildGzip(t);
  assert.ok(t.length > 500_000 && outer.length * MAX_DECOMPRESSION_RATIO > t.length, "fixture: tar over the member cap, under the ratio budget");
  const l = openArchive(outer, "x.tgz", 500_000)!;
  assert.strictEqual(l.containerKind, "tgz");
  assert.deepStrictEqual(l.members.map((m) => m.member), ["a", "b", "c"]);
});

test("gzip of a gzip is opaque: the inner stream is returned as bytes, never decoded", () => {
  const inner = buildGzip(secret, "config.env");
  const l = openArchive(buildGzip(inner), "x.gz.gz", MAX)!;
  assert.strictEqual(l.members.length, 1);
  assert.ok(l.members[0].bytes.equals(inner));
});

// ---------------------------------------------------------------------------
suite("archive.ts — determinism and safety");

test("identical input yields identical listings, and parsing never throws on garbage", () => {
  const z = buildZip([{ name: "a.txt", data: README }, { name: "b/c.txt", data: secret, method: 0 }]);
  assert.deepStrictEqual(openArchive(z, "x.zip", MAX), openArchive(z, "x.zip", MAX));
  for (let seed = 1; seed <= 25; seed++) {
    const noise = Buffer.alloc(700);
    let x = seed;
    for (let i = 0; i < noise.length; i++) { x = (1103515245 * x + 12345) & 0x7fffffff; noise[i] = (x >> 16) & 0xff; }
    noise[0] = 0x50; noise[1] = 0x4b; noise[2] = 0x03; noise[3] = 0x04;
    assert.doesNotThrow(() => openArchive(noise, "n.zip", MAX));
    noise[0] = 0x1f; noise[1] = 0x8b;
    assert.doesNotThrow(() => openArchive(noise, "n.gz", MAX));
  }
});

finish();
