import { TextDecoder } from "util";

/**
 * Encoded-candidate discovery and one-layer decoding.
 *
 * Contract frozen in encoded-v1-preimplementation-freeze-v0.4.0.md (benchmark
 * workspace). This module finds spans of source text that LOOK like standard
 * Base64, hexadecimal or URL percent-encoding, decodes each one strictly and
 * exactly once, and hands the decoded text back so the caller can run the
 * existing named SecretRules over it. It never decides what a secret is, never
 * decodes the output of a decode, and never keeps decoded text past the call.
 *
 * Pure: no I/O, no clock, no randomness. Identical input yields identical
 * candidates in identical order.
 */

export type EncodedTransform = "base64" | "hex" | "url-percent";

/**
 * Frozen evaluation order. When one span decodes under more than one transform
 * (a 40-character git SHA is valid hex AND valid base64), the scanner keeps the
 * first transform that yields a given rule on that span, and this order is
 * what "first" means.
 */
export const TRANSFORM_ORDER: readonly EncodedTransform[] = ["base64", "hex", "url-percent"];

/**
 * Below this, decoded bytes are not offered to the rules. The shortest in-scope
 * corpus positive decodes to 20 bytes and the shortest whole match any current
 * rule appears able to produce is 15 (slack-token). 12 sits under both.
 */
export const MIN_DECODED_BYTES = 12;

/** A single encoded run longer than this is not a candidate at all. */
export const MAX_ENCODED_CHARS = 4096;

/**
 * Defensive invariant, not a filter: no supported transform expands, so every
 * run that passes MAX_ENCODED_CHARS decodes to at most this many bytes. It is
 * enforced anyway so a future transform that does expand cannot amplify memory
 * silently. Mixed percent input is the reason it equals the source cap rather
 * than 3072: 4096 chars with one escape decode to 4094 bytes.
 */
export const MAX_DECODED_BYTES = 4096;

export interface EncodedCandidate {
  transform: EncodedTransform;
  /** Offsets into the ORIGINAL text. The finding this yields owns this span. */
  start: number;
  end: number;
  /** text.slice(start, end): what a finding's `value` will be. */
  source: string;
  /** Strict UTF-8 decode of the candidate. Never stored on a Finding. */
  decoded: string;
}

// Maximal runs. A run abutting ordinary text with no delimiter is offered as a
// whole and decodes to nothing useful, which is the frozen bnd-adjacent-text
// semantics: there is no attempt to find a "clean" token inside a word.
const BASE64_RUN = /[A-Za-z0-9+/]{16,}={0,2}/g;
const HEX_RUN = /[0-9A-Fa-f]{24,}/g;
// Unreserved bytes, `+` kept literal (this is percent-decoding, not
// form-decoding), and `%`. Reserved bytes end the run: an encodeURIComponent
// output escapes them, so a candidate made of them is one that was never
// percent-encoded.
const PERCENT_RUN = /[A-Za-z0-9\-._~+%]+/g;
const PERCENT_ESCAPE = /%[0-9A-Fa-f]{2}/;
const HEX_DIGIT = /^[0-9A-Fa-f]$/;

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Decoded bytes as text, or null when they are not text.
 *
 * Strict UTF-8 -- invalid sequences reject the candidate rather than being
 * replaced, because a U+FFFD-laced string is something no rule was written for.
 * NUL rejects for the same reason the walker's binary heuristic does: this is
 * the boundary between "text" and "bytes", and it has to agree with the one
 * scanning already draws.
 */
function asText(bytes: Buffer): string | null {
  if (bytes.length < MIN_DECODED_BYTES || bytes.length > MAX_DECODED_BYTES) return null;
  if (bytes.includes(0)) return null;
  try {
    return utf8.decode(bytes);
  } catch {
    return null;
  }
}

function decodeBase64(source: string): string | null {
  // Node's decoder is permissive: it skips characters it does not know and
  // stops at the first `=`. Re-encoding closes every one of those holes at
  // once -- wrong length, non-canonical trailing bits, over- or under-padding
  // all fail to round-trip.
  if (source.length % 4 !== 0) return null;
  const bytes = Buffer.from(source, "base64");
  if (bytes.toString("base64") !== source) return null;
  return asText(bytes);
}

function decodeHex(source: string): string | null {
  if (source.length % 2 !== 0) return null;
  const bytes = Buffer.from(source, "hex");
  // Buffer stops silently at the first non-hex character.
  if (bytes.length * 2 !== source.length) return null;
  return asText(bytes);
}

function decodePercent(source: string): string | null {
  if (!PERCENT_ESCAPE.test(source)) return null; // no escape: not encoded
  const out: number[] = [];
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch !== "%") {
      out.push(source.charCodeAt(i)); // the run class is ASCII by construction
      continue;
    }
    const hi = source[i + 1];
    const lo = source[i + 2];
    // `%4` at the end, `%ZZ`, `%not`: one malformed escape rejects the whole
    // candidate. There is no lenient reading of a broken escape.
    if (hi === undefined || lo === undefined || !HEX_DIGIT.test(hi) || !HEX_DIGIT.test(lo)) {
      return null;
    }
    out.push(parseInt(hi + lo, 16));
    i += 2;
  }
  return asText(Buffer.from(out));
}

/**
 * One transform, applied once, strictly. Null means "not a candidate under this
 * transform" for any reason -- malformed, out of bounds, not text. Never throws.
 */
export function decodeCandidate(transform: EncodedTransform, source: string): string | null {
  if (source.length > MAX_ENCODED_CHARS) return null;
  try {
    switch (transform) {
      case "base64":
        return decodeBase64(source);
      case "hex":
        return decodeHex(source);
      case "url-percent":
        return decodePercent(source);
    }
  } catch {
    return null;
  }
}

function runsOf(text: string, pattern: RegExp): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  pattern.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    if (m[0].length === 0) {
      pattern.lastIndex++;
      continue;
    }
    spans.push([m.index, m.index + m[0].length]);
  }
  return spans;
}

/**
 * Every decodable span in `text`, in TRANSFORM_ORDER and then text order.
 *
 * Input is always original source text. Nothing here is ever called on a
 * candidate's own decoded output -- that is the one-layer bound, and it is
 * structural rather than a flag: the only caller is the scanner's encoded pass,
 * which runs rules over `decoded` and nothing else.
 */
export function findEncodedCandidates(text: string): EncodedCandidate[] {
  const out: EncodedCandidate[] = [];
  for (const transform of TRANSFORM_ORDER) {
    const pattern =
      transform === "base64" ? BASE64_RUN : transform === "hex" ? HEX_RUN : PERCENT_RUN;
    for (const [start, end] of runsOf(text, pattern)) {
      // Padding beyond two `=` is not "a candidate plus some equals signs"; it
      // is a malformed candidate, and the regex has already stopped consuming.
      if (transform === "base64" && text[end] === "=") continue;
      const source = text.slice(start, end);
      const decoded = decodeCandidate(transform, source);
      if (decoded === null) continue;
      out.push({ transform, start, end, source, decoded });
    }
  }
  return out;
}
