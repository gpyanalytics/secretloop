import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, rmSync, writeFileSync, symlinkSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { createHash } from "crypto";
import { scanWorkspaceFiles } from "../src/workspace";
import { mergeConfig, defaultConfig } from "../src/config";
import { Finding } from "../src/scanner";

/**
 * The frozen PKCS#12 file-level detector.
 *
 * Design is frozen in pkcs12-freeze-7155977.md
 * (SHA-256 432db5a1ab18395e8cfc12fb34e30ec93a1da3c015eb56f89ea72f743aff4825).
 * Sections cited below are that document's.
 *
 * Every fixture is ASSEMBLED AT RUNTIME from a test-local DER encoder. No
 * .pfx/.p12/binary blob is committed: a committed container would change the
 * self-scan population by design (E.6), and there is no crypto dependency.
 *
 * These tests drive the PUBLIC pipeline (scanWorkspaceFiles, and the
 * checkout-local CLI / MCP surface) rather than importing the detector module.
 * That is deliberate: before the detector exists the positives fail as missing
 * findings rather than as a module-load error, so RED is per-test and legible.
 */

const RULE = "pkcs12-private-key";
const DESC = "PKCS#12 keystore containing private-key material";

// --------------------------------------------------------------- DER encoder

function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const out: number[] = [];
  let v = n;
  while (v > 0) {
    out.unshift(v & 0xff);
    v >>>= 8;
  }
  return Buffer.from([0x80 | out.length, ...out]);
}
function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}
const seq = (...parts: Buffer[]) => tlv(0x30, Buffer.concat(parts));
const octet = (c: Buffer) => tlv(0x04, c);
const explicit0 = (c: Buffer) => tlv(0xa0, c);
const int = (n: number) => tlv(0x02, Buffer.from([n]));

/** Minimal dotted-OID encoder; sufficient for the fixed OIDs used here. */
function oid(dotted: string): Buffer {
  const p = dotted.split(".").map(Number);
  const body: number[] = [p[0] * 40 + p[1]];
  for (const n of p.slice(2)) {
    const chunk: number[] = [n & 0x7f];
    let v = n >>> 7;
    while (v > 0) {
      chunk.unshift((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    body.push(...chunk);
  }
  return tlv(0x06, Buffer.from(body));
}

const OID_DATA = "1.2.840.113549.1.7.1";
const OID_SIGNED = "1.2.840.113549.1.7.2";
const OID_ENVELOPED = "1.2.840.113549.1.7.3";
const OID_ENCRYPTED = "1.2.840.113549.1.7.6";
const OID_KEYBAG = "1.2.840.113549.1.12.10.1.1";
const OID_SHROUDED = "1.2.840.113549.1.12.10.1.2";
const OID_CERTBAG = "1.2.840.113549.1.12.10.1.3";
const OID_SAFECONTENTSBAG = "1.2.840.113549.1.12.10.1.6";

/** Opaque filler that is itself well-formed DER, so nothing fails by accident. */
const filler = (n: number, b = 0x41) => octet(Buffer.alloc(n, b));

/** SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY } */
const bag = (bagId: string, value: Buffer) => seq(oid(bagId), explicit0(value));
const keyBag = (n = 48) => bag(OID_KEYBAG, filler(n, 0x4b));
const shroudedBag = (n = 48) => bag(OID_SHROUDED, filler(n, 0x53));
const certBag = (n = 40) => bag(OID_CERTBAG, filler(n, 0x43));

/** SafeContents ::= SEQUENCE OF SafeBag */
const safeContents = (...bags: Buffer[]) => seq(...bags);

/** plaintext pkcs7-data ContentInfo carrying SafeContents */
const dataSafe = (sc: Buffer) => seq(oid(OID_DATA), explicit0(octet(sc)));

/** accepted opaque inner sibling: contentType + bounded [0] content wrapper */
const opaqueSafe = (ct: string, n = 64) => seq(oid(ct), explicit0(seq(filler(n, 0x4f))));

/** AuthenticatedSafe ::= SEQUENCE OF ContentInfo */
const authSafeSeq = (...cis: Buffer[]) => seq(...cis);

/** PFX with outer pkcs7-data authSafe. */
function pfx(...contentInfos: Buffer[]): Buffer {
  const as = authSafeSeq(...contentInfos);
  return seq(int(3), seq(oid(OID_DATA), explicit0(octet(as))));
}
/** PFX whose OUTER authSafe contentType is pkcs7-signedData (C.2c). */
function pfxOuterSigned(inner: Buffer): Buffer {
  // A structurally valid SignedData-shaped envelope whose encapsulated content
  // would expose `inner` if it were traversed. It is never traversed.
  const encap = seq(oid(OID_DATA), explicit0(octet(authSafeSeq(inner))));
  const signedData = seq(int(1), seq(), encap);
  return seq(int(3), seq(oid(OID_SIGNED), explicit0(signedData)));
}

// ------------------------------------------------------------------ harness

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-pkcs12-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Scan a temp tree through the real workspace pipeline. */
function scanDir(dir: string, cfg = defaultConfig): Finding[] {
  return scanWorkspaceFiles(dir, cfg).flatMap((f) => f.findings);
}
const p12 = (findings: Finding[]) => findings.filter((f) => f.ruleId === RULE);

/** Write one container and return only its pkcs12 findings. */
function scanOne(bytes: Buffer, name = "candidate.pfx", cfg = defaultConfig): Finding[] {
  let out: Finding[] = [];
  withDir((dir) => {
    writeFileSync(path.join(dir, name), bytes);
    out = p12(scanDir(dir, cfg));
  });
  return out;
}

/** Every frozen field of a positive finding (D.2, D.3, D.3a). */
function assertPositive(f: Finding, bytes: Buffer, file: string, label: string): void {
  assert.strictEqual(f.ruleId, RULE, `${label}: ruleId`);
  assert.strictEqual(f.description, DESC, `${label}: description`);
  assert.strictEqual(f.severity, "critical", `${label}: severity`);
  assert.strictEqual(f.confidence, "format-match", `${label}: confidence`);
  assert.strictEqual(f.file, file, `${label}: file`);
  assert.strictEqual(f.line, 1, `${label}: line`);
  assert.strictEqual(f.startIndex, 0, `${label}: startIndex`);
  assert.strictEqual(f.endIndex, bytes.length, `${label}: endIndex`);
  assert.strictEqual(
    f.value,
    `PKCS#12 keystore, ${bytes.length} bytes, private-key material present`,
    `${label}: canonical bag-neutral descriptor`
  );
  assert.ok(!/shrouded key bag present/.test(f.value), `${label}: superseded descriptor`);
}

// ===========================================================================
suite("pkcs12 — 1. shrouded key + C.7 sibling / final-emission semantics");

test("sibling handling and final emission (C.7 A-H)", () => {
  // A. direct plaintext shrouded key -> exactly ONE finding
  const a = pfx(dataSafe(safeContents(shroudedBag())));
  const fa = scanOne(a);
  assert.strictEqual(fa.length, 1, "A: expected exactly one finding");
  assertPositive(fa[0], a, "candidate.pfx", "A");

  // B. accepted opaque encryptedData BEFORE a later direct-key safe
  const b = pfx(opaqueSafe(OID_ENCRYPTED), dataSafe(safeContents(shroudedBag())));
  assert.strictEqual(scanOne(b).length, 1, "B: opaque-then-key");

  // C. plaintext certBag-only safe BEFORE a later direct-key safe
  const c = pfx(dataSafe(safeContents(certBag())), dataSafe(safeContents(shroudedBag())));
  assert.strictEqual(scanOne(c).length, 1, "C: certBag-only then key");

  // D. direct key safe BEFORE a later accepted opaque encryptedData sibling
  const d = pfx(dataSafe(safeContents(shroudedBag())), opaqueSafe(OID_ENCRYPTED));
  assert.strictEqual(scanOne(d).length, 1, "D: key then opaque");

  // E. accepted opaque envelopedData BEFORE a later direct-key safe.
  //    SYNTHETIC branch coverage: A.3 measured envelopedData at 0 of 8.
  const e = pfx(opaqueSafe(OID_ENVELOPED), dataSafe(safeContents(shroudedBag())));
  assert.strictEqual(scanOne(e).length, 1, "E: envelopedData then key (synthetic)");

  // F. direct key safe BEFORE a later accepted opaque envelopedData sibling
  const f = pfx(dataSafe(safeContents(shroudedBag())), opaqueSafe(OID_ENVELOPED));
  assert.strictEqual(scanOne(f).length, 1, "F: key then envelopedData (synthetic)");

  // G. key first, then LATER required structure malformed -> provisional B2 discarded.
  //    The trailing sibling declares 48 content bytes but only 8 follow inside
  //    the enclosing AuthenticatedSafe bound, so a required later structure is
  //    genuinely malformed rather than merely having different content.
  const keySafe = dataSafe(safeContents(shroudedBag()));
  const overrunSibling = Buffer.concat([Buffer.from([0x30, 0x30]), Buffer.alloc(8, 0x41)]);
  const asBad = tlv(0x30, Buffer.concat([keySafe, overrunSibling]));
  const bad = seq(int(3), seq(oid(OID_DATA), explicit0(octet(asBad))));
  assert.strictEqual(scanOne(bad).length, 0, "G: malformed later structure must cancel B2");

  // H. key first, then an OUT-OF-C.2b-SET inner sibling (inner pkcs7-signedData)
  const h = pfx(dataSafe(safeContents(shroudedBag())), opaqueSafe(OID_SIGNED));
  assert.strictEqual(scanOne(h).length, 0, "H: out-of-set inner sibling must fail candidate");
});

// ===========================================================================
suite("pkcs12 — 2. actual plain keyBag branch and multiplicity");

test("plain keyBag and container-level multiplicity (B.3, C.7)", () => {
  // A. an ACTUAL keyBag OID, not a renamed shrouded fixture (C.7 coverage rule)
  const a = pfx(dataSafe(safeContents(keyBag())));
  const fa = scanOne(a);
  assert.strictEqual(fa.length, 1, "A: plain keyBag must report");
  assertPositive(fa[0], a, "candidate.pfx", "A");

  // B. two qualifying DIRECT bags in the SAME SafeContents -> ONE finding
  const b = pfx(dataSafe(safeContents(keyBag(), shroudedBag())));
  assert.strictEqual(scanOne(b).length, 1, "B: two bags, one safe");

  // C. qualifying DIRECT bags in TWO plaintext safes -> ONE finding
  const c = pfx(dataSafe(safeContents(keyBag())), dataSafe(safeContents(shroudedBag())));
  assert.strictEqual(scanOne(c).length, 1, "C: two key-bearing safes");

  // D. direct key + safeContentsBag whose NESTED SafeContents holds another key
  const nested = safeContents(shroudedBag());
  const d = pfx(
    dataSafe(safeContents(keyBag(), bag(OID_SAFECONTENTSBAG, nested)))
  );
  const fd = scanOne(d);
  assert.strictEqual(fd.length, 1, "D: direct key + nested key -> one finding");
  assertPositive(fd[0], d, "candidate.pfx", "D");
});

// ===========================================================================
suite("pkcs12 — 3. certificate-only container");

test("a valid certificate-only PFX does not report (B, C.3)", () => {
  const c = pfx(dataSafe(safeContents(certBag(), certBag(56))));
  assert.strictEqual(scanOne(c).length, 0, "certificate-only must not report");
});

// ===========================================================================
suite("pkcs12 — 4. frozen known false-negative classes");

test("opaque-only, nested-only and outer-signedData-only are deliberate FNs", () => {
  // A. accepted opaque pkcs7-encryptedData is the ONLY place key-like material
  //    lives. C.2b's minimum accepted-opaque contract is satisfied, so this is
  //    a real accepted-opaque sibling and not an out-of-set OID.
  //    DELIBERATE FALSE NEGATIVE: encrypted/opaque-only key material (C.7).
  const a = pfx(opaqueSafe(OID_ENCRYPTED, 96));
  assert.strictEqual(scanOne(a).length, 0, "A: encryptedData-only must not report");

  // B. same class via accepted opaque pkcs7-envelopedData.
  //    DELIBERATE FALSE NEGATIVE: encrypted/opaque-only key material (C.7).
  const b = pfx(opaqueSafe(OID_ENVELOPED, 96));
  assert.strictEqual(scanOne(b).length, 0, "B: envelopedData-only must not report");

  // C. structurally valid safeContentsBag whose NESTED SafeContents holds the
  //    only qualifying key, with no qualifying DIRECT key elsewhere.
  //    DELIBERATE FALSE NEGATIVE: nested safeContentsBag-only (C.2a).
  const nested = safeContents(shroudedBag());
  const c = pfx(dataSafe(safeContents(certBag(), bag(OID_SAFECONTENTSBAG, nested))));
  assert.strictEqual(scanOne(c).length, 0, "C: nested-only must not report");

  // D. outer authSafe contentType = pkcs7-signedData, wrapping a structurally
  //    valid envelope whose encapsulated content would expose a qualifying
  //    AuthenticatedSafe/direct-key path if SignedData were traversed.
  //    DELIBERATE FALSE NEGATIVE: outer-signedData-only (C.2c).
  const d = pfxOuterSigned(dataSafe(safeContents(shroudedBag())));
  assert.strictEqual(scanOne(d).length, 0, "D: outer signedData-only must not report");
});

// ===========================================================================
suite("pkcs12 — 5. structural bagId position, never a byte search");

test("a key OID inside a certBag payload does not earn B2 (A.2, C.7)", () => {
  // Valid certificate-only container whose certBag payload OCTET STRING
  // CONTAINS the exact encoded pkcs8ShroudedKeyBag OID bytes. No qualifying
  // OID sits at a structural SafeBag.bagId position.
  const planted = octet(Buffer.concat([Buffer.alloc(8, 0x43), oid(OID_SHROUDED), Buffer.alloc(8, 0x43)]));
  const c = pfx(dataSafe(safeContents(bag(OID_CERTBAG, planted))));
  assert.ok(
    c.includes(oid(OID_SHROUDED)),
    "fixture must actually embed the key OID bytes, or it proves nothing"
  );
  assert.strictEqual(
    scanOne(c).length,
    0,
    "a detector that byte-greps the container instead of reading SafeBag.bagId fails here"
  );
});

// ===========================================================================
suite("pkcs12 — 6. content-driven scope and non-dereferencing symlink policy");

test("extension-independent detection; candidate bytes never read via symlink (C.4, C.4a)", () => {
  const bytes = pfx(dataSafe(safeContents(shroudedBag())));

  // A. renamed .bin
  const fa = scanOne(bytes, "keystore.bin");
  assert.strictEqual(fa.length, 1, "A: .bin must report");
  assertPositive(fa[0], bytes, "keystore.bin", "A");

  // B. no extension at all
  const fb = scanOne(bytes, "keystore");
  assert.strictEqual(fb.length, 1, "B: extensionless must report");
  assertPositive(fb[0], bytes, "keystore", "B");

  // C/D. a symlink alias beside the real regular file.
  withDir((dir) => {
    writeFileSync(path.join(dir, "real.pfx"), bytes);
    symlinkSync(path.join(dir, "real.pfx"), path.join(dir, "alias.pfx"));
    const found = p12(scanDir(dir));
    const paths = found.map((f) => f.file).sort();
    // D: exactly one finding, under the real regular path.
    assert.deepStrictEqual(paths, ["real.pfx"], `expected only the real path, got ${paths}`);
    // C: nothing was obtained through the alias.
    assert.ok(!paths.includes("alias.pfx"), "candidate bytes must never come through a symlink");
  });
});

// ===========================================================================
suite("pkcs12 — 7. invalid and unrelated inputs");

test("PEM text, random bytes, unrelated DER and prefilter negatives (C.3)", () => {
  const pem = Buffer.from(
    "-----BEGIN CERTIFICATE-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END CERTIFICATE-----\n"
  );
  assert.strictEqual(scanOne(pem, "text.p12").length, 0, "PEM under .p12 must not report");

  // Deterministic non-DER bytes; first byte deliberately not 0x30.
  const rnd = Buffer.alloc(512);
  for (let i = 0; i < rnd.length; i++) rnd[i] = (i * 37 + 11) & 0xff;
  rnd[0] = 0x99;
  assert.strictEqual(scanOne(rnd, "noise.pfx").length, 0, "random bytes must not report");

  // Unrelated DER: a certificate-shaped SEQUENCE whose second element is a
  // SEQUENCE (tbsCertificate), not INTEGER 3.
  const cert = seq(seq(int(2), filler(24)), seq(oid("1.2.840.113549.1.1.11")), filler(32));
  assert.strictEqual(scanOne(cert, "cert.der").length, 0, "unrelated DER must not report");

  // version != 3
  const v9 = seq(int(9), seq(oid(OID_DATA), explicit0(octet(authSafeSeq(dataSafe(safeContents(shroudedBag())))))));
  assert.strictEqual(scanOne(v9, "v9.pfx").length, 0, "version != 3 must not report");

  // version position is not an INTEGER
  const notInt = seq(octet(Buffer.from([3])), seq(oid(OID_DATA), explicit0(octet(authSafeSeq(dataSafe(safeContents(shroudedBag())))))));
  assert.strictEqual(scanOne(notInt, "notint.pfx").length, 0, "non-INTEGER version must not report");
});

// ===========================================================================
suite("pkcs12 — 8. binary fingerprint semantics");

test("identity follows container bytes, not descriptor wording (D.4)", () => {
  const base = pfx(dataSafe(safeContents(shroudedBag())));

  // A. same bytes, same path, two scans -> identical fingerprint
  const one = scanOne(base)[0];
  const two = scanOne(base)[0];
  assert.ok(one && two, "A: fixture must report");
  assert.strictEqual(one.fingerprint, two.fingerprint, "A: fingerprint must be stable");

  // B. one byte changed inside the key bag payload, container still valid
  const changed = Buffer.from(base);
  const at = changed.indexOf(Buffer.alloc(8, 0x53));
  assert.ok(at > 0, "B: fixture payload not located");
  changed[at] = 0x54;
  const three = scanOne(changed)[0];
  assert.ok(three, "B: mutated fixture must still report");
  assert.notStrictEqual(one.fingerprint, three.fingerprint, "B: fingerprint must change");

  // C. SAME-SIZE change, container still structurally valid
  assert.strictEqual(changed.length, base.length, "C: mutation must preserve size");
  assert.strictEqual(
    three.value,
    one.value,
    "C: descriptor shape may be unchanged while identity changes"
  );

  // The raw container SHA-256 context must never be the rendered value.
  const sha = createHash("sha256").update(base).digest("hex");
  assert.ok(!one.value.includes(sha), "raw container SHA-256 must not be rendered");
  assert.ok(one.fingerprint && !one.fingerprint.includes(sha), "raw context must not be verbatim");
});

// ===========================================================================
suite("pkcs12 — 9. C.6 parser and resource properties");

test("malformed length, indefinite length, size boundary, bad bagId, many peers", () => {
  // Case 1 — declared length exceeds available bytes
  const over = Buffer.concat([Buffer.from([0x30, 0x82, 0x7f, 0xff]), Buffer.alloc(32, 0x41)]);
  assert.strictEqual(scanOne(over, "over.pfx").length, 0, "case 1: length overrun");

  // Case 2 — indefinite outer length (0x80), rejected by C.2 step 1
  const indef = Buffer.concat([Buffer.from([0x30, 0x80]), int(3), Buffer.from([0x00, 0x00])]);
  assert.strictEqual(scanOne(indef, "indef.pfx").length, 0, "case 2: indefinite length");

  // Case 3 — effective configurable size boundary, operator-exact.
  // Two independently valid B2 containers whose sizes differ by exactly one.
  let A = pfx(dataSafe(safeContents(shroudedBag(48))));
  let B = pfx(dataSafe(safeContents(shroudedBag(49))));
  assert.strictEqual(B.length, A.length + 1, `case 3: need len(B)==len(A)+1, got ${A.length}/${B.length}`);
  const cfgA = mergeConfig({ maxFileSizeBytes: A.length });
  assert.strictEqual(scanOne(A, "a.pfx", cfgA).length, 1, "case 3: at-limit must be admitted");
  assert.strictEqual(scanOne(B, "b.pfx", cfgA).length, 0, "case 3: limit+1 must be rejected");
  assert.strictEqual(defaultConfig.maxFileSizeBytes, 1_000_000, "case 3: untouched default");

  // Case 4 — malformed element at a SafeBag structural position: the bagId
  // slot holds a SEQUENCE instead of an OBJECT IDENTIFIER.
  const badBag = seq(seq(int(1)), explicit0(filler(16)));
  const c4 = pfx(dataSafe(safeContents(badBag)));
  assert.strictEqual(scanOne(c4, "badbag.pfx").length, 0, "case 4: malformed bagId position");

  // Case 5 — many direct peers with the ONE qualifying bag LAST.
  const PEERS = 5000;
  const peers: Buffer[] = [];
  for (let i = 0; i < PEERS; i++) peers.push(certBag(8));
  peers.push(shroudedBag());
  const many = pfx(dataSafe(safeContents(...peers)));
  const fm = scanOne(many, "many.pfx");
  assert.strictEqual(fm.length, 1, `case 5: key-last among ${PEERS} peers must report once`);
  assertPositive(fm[0], many, "many.pfx", "case 5");
  // The peer count is stress evidence only, never a supported maximum.
});

// ===========================================================================
suite("pkcs12 — 10. privacy: no payload leakage on any output surface");

test("sentinel, container encodings and raw context never reach output (D.5)", () => {
  const SENTINEL = "ZZQXSENTINELQXZZ";
  const payload = Buffer.concat([
    Buffer.alloc(8, 0x53),
    Buffer.from(SENTINEL, "ascii"),
    Buffer.alloc(8, 0x53),
  ]);
  const bytes = pfx(dataSafe(safeContents(bag(OID_SHROUDED, octet(payload)))));
  assert.ok(bytes.includes(Buffer.from(SENTINEL, "ascii")), "sentinel must be in the fixture");

  const hex = bytes.toString("hex");
  const b64 = bytes.toString("base64");
  const sha = createHash("sha256").update(bytes).digest("hex");
  const sentHex = Buffer.from(SENTINEL, "ascii").toString("hex");
  const sentB64 = Buffer.from(SENTINEL, "ascii").toString("base64");
  const expected = `PKCS#12 keystore, ${bytes.length} bytes, private-key material present`;

  /** Assert without ever printing fixture bytes on failure. */
  function assertClean(surface: string, text: string): void {
    assert.ok(!text.includes(SENTINEL), `${surface}: sentinel plaintext leaked`);
    assert.ok(!text.includes(sentHex), `${surface}: sentinel hex leaked`);
    assert.ok(!text.includes(sentB64), `${surface}: sentinel base64 leaked`);
    assert.ok(!text.includes(hex), `${surface}: full container hex leaked`);
    assert.ok(!text.includes(b64), `${surface}: full container base64 leaked`);
    assert.ok(!text.includes(sha), `${surface}: raw container SHA-256 context leaked`);
  }

  withDir((dir) => {
    writeFileSync(path.join(dir, "leak.pfx"), bytes);
    const CLI = path.join(__dirname, "..", "out", "cli.js");

    for (const fmt of ["text", "json", "sarif"]) {
      const r = spawnSync(process.execPath, [CLI, "scan", "--format", fmt, "--fail-on", "never"], {
        cwd: dir,
        encoding: "utf8",
      });
      const all = `${r.stdout}\n${r.stderr}`;
      assertClean(`--format ${fmt}`, all);
      assert.ok(all.includes(expected), `--format ${fmt}: descriptor missing`);
    }

    // MCP serialization path.
    const mcp = require("../src/mcp-core");
    mcp.setAllowedRoots([dir]);
    const res = mcp.toolScan({ path: dir });
    const text = JSON.stringify(res);
    assertClean("mcp toolScan", text);
    assert.ok(text.includes(expected), "mcp toolScan: descriptor missing");
  });
});

finish();
