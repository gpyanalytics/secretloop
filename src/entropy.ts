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
  // Absolute filesystem path. The segment repetition is [\w.-]* rather than +
  // as of 0.1.2: a doubled slash makes one segment empty, and dyld image paths
  // in a crash report are full of them
  // (".../Frameworks//CoreData.framework/CoreData"). Measured delta from
  // allowing it: 0.3488% -> 0.3817% of random 40-character base64 keys.
  /^(?:[A-Za-z]:)?[\\/](?:[\w.-]*[\\/])+[\w.-]+$/,
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

  // Symbols, added in 0.1.2. A crash report is a symbol table, and a symbol
  // table is high-entropy structured text -- 80 of the Objective-C validation
  // corpus's 132 tree findings and 22 of its history findings were mangled
  // names out of two committed crash-report fixtures.
  // One value alone accounted for 10 locations.
  //
  // Itanium ABI: the grammar says a mangled name begins _Z, and the four
  // productions that actually occur in the wild are N (nested), L (internal
  // linkage), S (substitution) and T (vtable/typeinfo). Up to three leading
  // underscores because Objective-C block trampolines carry ___Z.
  //
  // Anchored, so a credential merely containing "_ZN" is untouched. Measured at
  // 0.0010% of random JWT-shaped values -- two in 200,000 base64url strings
  // that happen to open "_ZN"/"_ZL"/"_ZS"/"_ZT" -- and 0.0000% of every other
  // credential shape tested. `jwt` is a named rule and fires independently.
  /^_{1,3}Z[NLST]/,
  // Plain C/ObjC symbols from the same reports, which are not mangled at all:
  // _BlockUntilNextEventMatchingListInModeWithFilter.
  //
  // Kept deliberately narrow -- a leading underscore AND letters/underscores
  // only. No digits and no base64 punctuation, which is what keeps it away from
  // generated credentials: 0.0000% across every sampled shape. A broader
  // "identifier-looking" predicate was measured and rejected outright; see the
  // note on bare identifiers below.
  /^_[A-Za-z][A-Za-z_]*$/,

  // Source filenames and #import targets, added in 0.1.2. 17 tree findings and
  // 27 history findings on the Objective-C validation corpus, every one the
  // operand of an #import in a .m/.mm/.c file -- an ObjC source file importing
  // an ObjC header filename. The value is a filename the
  // compiler resolves, never a credential.
  //
  // Closed extension alternation, anchored at the end, exactly like the hashed
  // asset filename filter above: "a name ending in a known source extension",
  // not "anything with a dot in it". A high-entropy value ending .exe, .sql,
  // .pem or .key still reports.
  //
  // The stem class excludes = and /, so a base64 blob cannot reach the
  // alternation by accident. Measured 0.0000% across every credential shape.
  /^[A-Za-z_][\w+-]*(?:\.[\w+-]+)*\.(?:h|hh|hpp|hxx|m|mm|c|cc|cpp|cxx|swift)$/i,

  // Absolute path whose segments may carry "+", added in 0.1.2 for
  // "/usr/lib/libc++.1.dylib" and "/usr/lib/libc++abi.dylib" -- 7 tree and 84
  // history findings on the Objective-C validation corpus, all dyld image paths
  // out of a committed crash report.
  //
  // Separate from the arm above because "+" is the character base64 uses and
  // the path arm above must not learn it. The final segment MUST carry an
  // extension, and that requirement is the entire safety margin: with it this
  // arm skips 0.0000% of random 40-character base64 keys, without it 0.68%.
  // Together with the empty-segment change above the whole 0.1.2 path delta is
  // 0.3488% -> 0.3684%, or 0.0196%.
  /^(?:[A-Za-z]:)?[\\/](?:[\w.+-]*[\\/])+[\w+-]+(?:\.[\w+-]+)+$/,

  // Build-setting assignment captured whole, added in 0.1.2:
  // "CLANG_DEBUG_INFORMATION_LEVEL=default" out of scripts/build-xcframework.sh.
  // 4 tree and 10 history findings on the Objective-C validation corpus.
  //
  // The "=" is the signal. Base64 uses "=" only as trailing padding, so an "="
  // with something after it is not padding -- hence [^=] rather than a bare "=",
  // which is what keeps an all-uppercase base64 blob ending in "=" reporting.
  /^[A-Z][A-Z0-9_]*=[^=]/,
];

/**
 * A dotted identifier chain: reverse-DNS bundle ids, build products, and
 * property accesses like `process.env.BUILDKITE_MESSAGE`.
 *
 * A predicate rather than a regex because the shape ALONE is not safe. A JWT is
 * three dot-separated base64url segments -- structurally identical to
 * `com.apple.Foo` -- and the chain pattern by itself skips 56.96% of JWT-shaped
 * values. That is a credential blind spot, not a precision fix.
 *
 * The second condition is what makes it safe: every segment must itself score
 * BELOW the entropy bar. Structured text is assembled from low-entropy parts;
 * a secret is not. With it, the measured skip rate on JWT-shaped values is
 * 0.0000%, and on github, AWS, Slack and 32-byte base64 values it is 0.0000%
 * too, while every real false positive on both benchmark corpora is still
 * covered.
 *
 * Do not reduce this to a regex. The entropy condition is the matcher.
 */
function isDottedIdentifierChain(value: string, threshold: number): boolean {
  if (!/^[A-Za-z_$][\w$-]*(?:\.[A-Za-z_$][\w$-]*)+$/.test(value)) return false;
  const segments = value.split(".").filter(Boolean);
  return segments.length >= 2 && segments.every((seg) => shannonEntropy(seg) < threshold);
}

/**
 * NOT a matcher, and deliberately so.
 *
 * A bare-identifier filter would remove the ~23 remaining ObjC-constant
 * findings on the Objective-C validation corpus's history (long framework
 * constant names). Every predicate that catches them was
 * measured against 200,000 samples of each credential shape and every one is
 * disqualifying:
 *
 *   ^[A-Z][A-Z0-9_]*$          skips 100.0000% of AWS access key ids
 *   ^[A-Za-z_][A-Za-z0-9_]*$   skips 100.0000% of AWS ids and ghp_ tokens
 *   ^[A-Za-z._-]+$             skips 3.6650% of AWS ids, 0.2140% of ghp_
 *   ^[a-z][a-zA-Z]*$           skips 0.0645% of 32-character base64
 *
 * AKIAIOSFODNN7EXAMPLE *is* SCREAMING_SNAKE_CASE. Leaving that noise visible
 * beats risking a false negative, so those findings are accepted as noise. If a
 * future release wants them gone, the answer is context (the string is an
 * argument to a known ObjC API), never the value's shape.
 */

function isStructuralFalsePositive(value: string, threshold: number): boolean {
  if (STRUCTURAL_FALSE_POSITIVES.some((r) => r.test(value))) return true;
  return isDottedIdentifierChain(value, threshold);
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

/**
 * Is the string at `index` the operand of an import, rather than a value?
 *
 * The only filter here that reads POSITION instead of shape, and the choice is
 * load-bearing twice.
 *
 * Safety. The values this exists for -- 'react-native/Libraries/TurboModule/
 * RCTExport', imported by a React Native binding module and declared by
 * react-native-internals.d.ts -- are relative paths with no ./ prefix and no
 * extension. 0.1.1 measured every value-shape predicate that catches that at
 * >= 1.802% of random keys, against the 0.823% it accepted, and recorded the
 * trade rather than paying it. Position costs nothing instead: `const token =
 * "ghp_..."` is not an import whatever the value looks like.
 *
 * Honesty. tests/detection.test.ts pins that same value as MUST-FIRE in the
 * form `m = "..."`, which is not import position -- so it still fires and that
 * test still passes untouched. A shape-based fix would have forced it red.
 *
 * Entropy-tier only. Named provider rules never consult position, so a
 * credential written where a specifier belongs still reports.
 */
const IMPORT_POSITION =
  /(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(?\s*|\bdeclare\s+module\s+|\bexport\s+\*\s+from\s+)$/;

function isModuleSpecifier(text: string, index: number): boolean {
  // 80 characters is well past the longest keyword run this matches, and
  // bounding it keeps the scan linear on very long single-line files -- crash
  // report JSON is exactly that.
  const before = text.slice(Math.max(0, index - 80), index).replace(/["\'`]\s*$/, "");
  return IMPORT_POSITION.test(before);
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

      if (isStructuralFalsePositive(value, threshold)) continue;
      if (isModuleSpecifier(text, index)) continue;
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
