/**
 * Calculates Shannon entropy of a string. High entropy (~4.3+ for base64-ish
 * strings of reasonable length) is a strong signal of randomly generated
 * secrets, as opposed to natural language or predictable identifiers.
 */
export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of input) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = input.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Quoted tokens and bare assignment values both get considered. Restricting to
// quoted strings alone misses .env files and YAML, which is where secrets
// actually tend to live.
const QUOTED_TOKEN = /["'`]([A-Za-z0-9+/=_\-.]{20,})["'`]/g;
const BARE_ASSIGNMENT = /(?:^|\s)[A-Za-z_][A-Za-z0-9_]*\s*[:=]\s*([A-Za-z0-9+/=_\-.]{20,})(?=\s|$)/gm;

export interface EntropyMatch {
  value: string;
  index: number;
  entropy: number;
}

/**
 * Structured strings that clear the entropy bar but are never credentials.
 * These are the single biggest source of entropy-scanner noise; every one of
 * them is a class of finding that would otherwise train users to ignore alerts.
 */
const STRUCTURAL_FALSE_POSITIVES: RegExp[] = [
  /^[0-9a-f]{40}$/i,                                          // git SHA-1
  /^[0-9a-f]{64}$/i,                                          // SHA-256 digest / lockfile integrity
  /^sha(?:256|512)-/,                                         // SRI hash
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
  /^data:[a-z]+\/[a-z0-9.+-]+;base64,/i,                      // inline data URI
  /^(?:[A-Za-z]:)?[\\/](?:[\w.-]+[\\/])+[\w.-]+$/,            // filesystem path
  /^https?:\/\//i,                                            // bare URL (credential URLs have their own rule)
  // Hashed asset filename. The stem carries a dot because a content-hashed
  // bundle name has inner dots -- main.<hash>.chunk.js -- and without it this
  // filter recognised only the simplest form of the shape it is named for.
  // Three benchmark false positives, all of them main.<20 hex>.chunk.js.
  //
  // The extension alternation still anchors the end, so this stays "a name
  // ending in a known asset extension" rather than "anything with a dot in
  // it"; a high-entropy value ending .exe or .sql still reports.
  /^[A-Za-z0-9+/=_.-]*\.(?:js|ts|css|png|jpg|svg|woff2?|json|map)$/i,
  /^[0-9.]+$/,                                                // version / numeric
  /^(?:[A-Fa-f0-9]{2}:){5,}[A-Fa-f0-9]{2}$/,                  // MAC / fingerprint

  // URLs and paths, added in 0.1.1. The three above them cover a *bare* URL and
  // an *absolute* path, and between them they missed 148 of 362 entropy
  // findings on the real-noise corpus. Two reasons, both structural:
  //
  //  - The capture alphabet has no ":", so "https://host/x" is never captured
  //    whole. What reaches here is the "//host/x" remainder, which the
  //    ^https?:// filter cannot see and the absolute-path filter rejects
  //    because its second character is a slash.
  //  - Relative paths ("../node_modules/react-native/Libraries/RCTRequired")
  //    never start with a slash at all.
  //
  // Every pattern is anchored and segment-shaped rather than "contains a
  // slash", because base64 contains slashes: a looser rule silently ate real
  // high-entropy blobs, which is the one failure mode that matters here. Base64
  // padding and "+" cannot appear in any segment these accept.
  /^\/\/[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\//,                  // protocol-relative URL
  /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\/[\w./-]*$/,              // host/path with no scheme
  // Relative filesystem path -- narrowed in 0.1.1 after it was measured eating
  // credentials. It was `^(?:[\w.-]+/)+[\w.-]+$`, which any 40-character base64
  // key satisfies as soon as it contains a slash and no + or =: 23.12% of 200k
  // random keys, invisible to the tier that exists for credentials no named
  // rule can catch.
  //
  // A path now has to look like one -- an extension-bearing final segment, or an
  // explicit ./ ../ / or drive-letter prefix. That is 0.823% of the same keys.
  //
  // The cost, measured and accepted: a relative path with neither a prefix nor
  // an extension (`react-native/Libraries/TurboModule/RCTExport`) reports again.
  // Predicates that catch it -- adding a >=3-separator arm -- cost 1.802%, more
  // than doubling the false-negative surface to remove one false-positive shape.
  /^(?:(?:[\w.-]+\/)+[\w-]+\.[A-Za-z][A-Za-z0-9]{0,9}|(?:\.{1,2}\/|\/|[A-Za-z]:[\\/])[\w.-]+(?:\/[\w.-]+)*)$/,
];

function isStructuralFalsePositive(value: string): boolean {
  return STRUCTURAL_FALSE_POSITIVES.some((r) => r.test(value));
}

/**
 * A string of only one character class (all-lowercase-hex, all-digits) carries
 * less real randomness than its Shannon score suggests, so it needs a higher
 * bar. Mixed-case-plus-digits-plus-symbols is the shape real tokens have.
 */
function charsetDiversity(value: string): number {
  let classes = 0;
  if (/[a-z]/.test(value)) classes++;
  if (/[A-Z]/.test(value)) classes++;
  if (/[0-9]/.test(value)) classes++;
  if (/[+/=_\-.]/.test(value)) classes++;
  return classes;
}

export function findHighEntropyStrings(text: string, threshold: number): EntropyMatch[] {
  const matches: EntropyMatch[] = [];
  const seen = new Set<number>();

  for (const pattern of [QUOTED_TOKEN, BARE_ASSIGNMENT]) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(text)) !== null) {
      const value = m[1];
      const index = m.index + m[0].lastIndexOf(value);
      if (seen.has(index)) continue;

      if (isStructuralFalsePositive(value)) continue;
      if (charsetDiversity(value) < 2) continue;

      const entropy = shannonEntropy(value);
      // Single-charset strings need a clearly higher score to qualify.
      const effectiveThreshold = charsetDiversity(value) === 2 ? threshold + 0.2 : threshold;
      if (entropy >= effectiveThreshold) {
        seen.add(index);
        matches.push({ value, index, entropy });
      }
    }
  }

  return matches.sort((a, b) => a.index - b.index);
}
