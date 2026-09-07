import { createHash } from "crypto";
import { Finding } from "./scanner";
import { createFingerprint } from "./config";

/**
 * PKCS#12 keystore detector — file-level, binary, non-recursive.
 *
 * Design frozen in pkcs12-freeze-7155977.md (SHA-256 432db5a1…4825). This is
 * deliberately NOT a SecretRule: DER is NUL-dense, so a PFX never reaches
 * scanText, and rules.ts stays at 109 (§C.5, §D.1).
 *
 * The claim is B2 (§B): the container carries readable private-key material.
 * Evidence is a DIRECT keyBag or pkcs8ShroudedKeyBag decoded at the structural
 * SafeBag.bagId position (§C.2a). Nothing here ever searches the buffer for OID
 * bytes: an OID occurring inside a certificate payload, inside ciphertext, or
 * anywhere but a bagId slot does not count.
 *
 * Never decrypts, never uses or guesses a password, never emits payload bytes.
 *
 * PARSER SHAPE (§C.6). The call graph is acyclic — `detectPkcs12Bytes` calls
 * only the flat readers `readLen`/`readTlv`/`oidEquals`, none of which call
 * anything. There is no direct or mutual recursion, no nesting stack, no parse
 * tree, and no collection whose size grows with nesting depth or peer count:
 * the only retained state is a handful of numeric cursors and one boolean.
 * Both peer loops advance strictly and monotonically and never revisit a
 * consumed region.
 */

export const PKCS12_RULE_ID = "pkcs12-private-key";
export const PKCS12_DESCRIPTION = "PKCS#12 keystore containing private-key material";

// ContentInfo contentTypes. Outer and inner sets are deliberately separate
// (§C.2b, §C.2c) and must never be conflated.
const OID_DATA = Buffer.from("06092A864886F70D010701", "hex"); // 1.2.840.113549.1.7.1
const OID_SIGNED_DATA = Buffer.from("06092A864886F70D010702", "hex"); // ...1.7.2
const OID_ENVELOPED_DATA = Buffer.from("06092A864886F70D010703", "hex"); // ...1.7.3
const OID_ENCRYPTED_DATA = Buffer.from("06092A864886F70D010706", "hex"); // ...1.7.6

// SafeBag bagIds that constitute B2 evidence (§C.2a).
const OID_KEY_BAG = Buffer.from("060B2A864886F70D010C0A0101", "hex"); // ...12.10.1.1
const OID_SHROUDED_KEY_BAG = Buffer.from("060B2A864886F70D010C0A0102", "hex"); // ...12.10.1.2

const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_CONTEXT_0 = 0xa0;

/** How many header bytes the prefilter needs: tag + up to 5 length octets. */
export const PKCS12_HEADER_BYTES = 6;

interface Tlv {
  tag: number;
  /** First byte of the element itself (its tag octet). */
  start: number;
  /** First content byte. */
  cs: number;
  /** One past the last content byte. */
  ce: number;
  /** First byte after this element — always > the index it was read from. */
  next: number;
}

/**
 * ASN.1 definite length. Indefinite form (0x80) is rejected outright: PKCS#12
 * is DER, and §C.2 step 1 accepts only short form and 1–4 byte long form.
 */
function readLen(b: Buffer, i: number, end: number): { len: number; next: number } | null {
  if (i >= end) return null;
  const n = b[i];
  if (n < 0x80) return { len: n, next: i + 1 };
  const k = n & 0x7f;
  if (k === 0 || k > 4 || i + 1 + k > end) return null;
  let len = 0;
  for (let j = 0; j < k; j++) len = len * 256 + b[i + 1 + j];
  return { len, next: i + 1 + k };
}

/** One TLV, bounded by `end`. Returns null rather than throwing on any overrun. */
function readTlv(b: Buffer, i: number, end: number): Tlv | null {
  if (i >= end) return null;
  const tag = b[i];
  // Low-tag-number form only; every tag this schema needs is single-byte.
  if ((tag & 0x1f) === 0x1f) return null;
  const l = readLen(b, i + 1, end);
  if (!l) return null;
  const cs = l.next;
  const ce = cs + l.len;
  if (ce > end || ce < cs) return null;
  return { tag, start: i, cs, ce, next: ce };
}

/**
 * True when the element at `t` is exactly this encoded OID.
 *
 * Anchored at the element's own start, so it is a comparison at a structural
 * position and never a search: the same OID bytes sitting inside a certificate
 * payload or inside ciphertext are not at any `t.start` this walk visits.
 */
function oidEquals(b: Buffer, t: Tlv, oid: Buffer): boolean {
  if (t.next - t.start !== oid.length) return false;
  return b.compare(oid, 0, oid.length, t.start, t.next) === 0;
}

/**
 * Cheap admission prefilter: outer SEQUENCE whose declared extent is exactly
 * the whole candidate. Reads only the first bytes, so a scan of a large tree
 * does not pay a full read per file.
 */
export function pkcs12HeaderAccepts(head: Buffer, size: number): boolean {
  if (head.length < 2 || head[0] !== TAG_SEQUENCE) return false;
  const l = readLen(head, 1, head.length);
  if (!l) return false;
  return l.next + l.len === size;
}

/**
 * The structural walk. Returns true when the container satisfies B1 and B2 via
 * the supported outer pkcs7-data branch, false otherwise. Never throws.
 */
function containsDirectPlaintextKeyBag(b: Buffer): boolean {
  const outer = readTlv(b, 0, b.length);
  // §C.2 steps 1–2: outer SEQUENCE, definite length, extent == whole candidate.
  if (!outer || outer.tag !== TAG_SEQUENCE || outer.next !== b.length) return false;

  // §C.2 step 3: version INTEGER, length 1, value 3.
  const version = readTlv(b, outer.cs, outer.ce);
  if (!version || version.tag !== TAG_INTEGER) return false;
  if (version.ce - version.cs !== 1 || b[version.cs] !== 3) return false;

  // §C.2 step 4: authSafe ContentInfo. macData, if present, simply follows and
  // is not required (§C.2 step 6).
  const authSafe = readTlv(b, version.next, outer.ce);
  if (!authSafe || authSafe.tag !== TAG_SEQUENCE) return false;

  const outerType = readTlv(b, authSafe.cs, authSafe.ce);
  if (!outerType || outerType.tag !== TAG_OID) return false;
  // §C.2c: pkcs7-data is the only B2-inspectable outer branch. signedData is
  // accepted by the outer B1 predicate but its payload is opaque here, so key
  // material reachable only through it is a known false negative. Any other
  // outer OID fails the predicate. Both yield no finding.
  if (!oidEquals(b, outerType, OID_DATA)) return false;

  const outerContent = readTlv(b, outerType.next, authSafe.ce);
  if (!outerContent || outerContent.tag !== TAG_CONTEXT_0) return false;
  const outerOctets = readTlv(b, outerContent.cs, outerContent.ce);
  if (!outerOctets || outerOctets.tag !== TAG_OCTET_STRING) return false;

  const authenticatedSafe = readTlv(b, outerOctets.cs, outerOctets.ce);
  if (!authenticatedSafe || authenticatedSafe.tag !== TAG_SEQUENCE) return false;

  // Provisional B2 (§C.7). Fixed-size state: one boolean, whatever the input.
  let b2Seen = false;

  // Peer loop 1 — direct AuthenticatedSafe siblings, in structural order.
  let q = authenticatedSafe.cs;
  const qEnd = authenticatedSafe.ce;
  while (q < qEnd) {
    const sibling = readTlv(b, q, qEnd);
    if (!sibling || sibling.tag !== TAG_SEQUENCE) return false;
    // Strict progress and containment (§C.6 property c).
    if (sibling.next <= q || sibling.next > qEnd) return false;

    const sibType = readTlv(b, sibling.cs, sibling.ce);
    if (!sibType || sibType.tag !== TAG_OID) return false;

    if (oidEquals(b, sibType, OID_DATA)) {
      // Accepted plaintext sibling: enter and walk its DIRECT SafeBags. A safe
      // holding no key is consumed and processing continues (§C.7); it is not
      // a rejection. localhost_modern_nomac.pfx is the measured instance.
      const content = readTlv(b, sibType.next, sibling.ce);
      if (!content || content.tag !== TAG_CONTEXT_0) return false;
      const octets = readTlv(b, content.cs, content.ce);
      if (!octets || octets.tag !== TAG_OCTET_STRING) return false;
      const safeContents = readTlv(b, octets.cs, octets.ce);
      if (!safeContents || safeContents.tag !== TAG_SEQUENCE) return false;

      // Peer loop 2 — direct SafeBags. Never descends into a bagValue, so a
      // safeContentsBag is recognised by its bagId and its nested SafeContents
      // is left opaque (§C.2a).
      let r = safeContents.cs;
      const rEnd = safeContents.ce;
      while (r < rEnd) {
        const safeBag = readTlv(b, r, rEnd);
        if (!safeBag || safeBag.tag !== TAG_SEQUENCE) return false;
        if (safeBag.next <= r || safeBag.next > rEnd) return false;
        const bagId = readTlv(b, safeBag.cs, safeBag.ce);
        if (!bagId || bagId.tag !== TAG_OID) return false;
        if (oidEquals(b, bagId, OID_KEY_BAG) || oidEquals(b, bagId, OID_SHROUDED_KEY_BAG)) {
          // Provisional only: never emit or return here (§C.7).
          b2Seen = true;
        }
        r = safeBag.next;
      }
    } else if (
      oidEquals(b, sibType, OID_ENCRYPTED_DATA) ||
      oidEquals(b, sibType, OID_ENVELOPED_DATA)
    ) {
      // Accepted opaque sibling (§C.2b): bound the required content wrapper,
      // never inspect the payload, never decrypt, advance to the validated end.
      const content = readTlv(b, sibType.next, sibling.ce);
      if (!content || content.tag !== TAG_CONTEXT_0) return false;
    } else {
      // Out of the exact three-member inner set — whole-candidate structural
      // failure, NOT an opaque skip (§C.2b). Inner signedData lands here.
      return false;
    }

    q = sibling.next;
  }
  if (q !== qEnd) return false;

  // Emitted only after the whole required walk succeeded (§C.7).
  return b2Seen;
}

/**
 * A finding for `bytes` if the container qualifies, else null.
 *
 * The value is a synthesized, non-secret descriptor (§D.3a) — bag-neutral,
 * because either bagId may earn B2. Identity comes from the container-byte
 * digest through the existing `context` strategy (§D.4); that digest is never
 * rendered.
 */
export function detectPkcs12Bytes(bytes: Buffer, relPath: string): Finding | null {
  if (!pkcs12HeaderAccepts(bytes.subarray(0, PKCS12_HEADER_BYTES), bytes.length)) return null;
  if (!containsDirectPlaintextKeyBag(bytes)) return null;

  const value = `PKCS#12 keystore, ${bytes.length} bytes, private-key material present`;
  const context = createHash("sha256").update(bytes).digest("hex");
  return {
    ruleId: PKCS12_RULE_ID,
    description: PKCS12_DESCRIPTION,
    value,
    startIndex: 0,
    endIndex: bytes.length,
    confidence: "format-match",
    severity: "critical",
    line: 1,
    file: relPath,
    fingerprintStrategy: "context",
    fingerprint: createFingerprint({
      filePath: relPath,
      ruleId: PKCS12_RULE_ID,
      strategy: "context",
      value: "",
      context,
    }),
  };
}
