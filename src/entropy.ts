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
 * Ordered character runs, added in 0.1.4 (N7a).
 *
 * Shannon entropy is blind to ordering: it counts how often each character
 * occurs and never looks at what follows what. A printed alphabet is therefore
 * the highest-scoring string there is -- every character exactly once -- and the
 * first external run of this tool on a real frontend monorepo reported one, an
 * email-validation character class, at entropy 6.02. No credential scores that.
 *
 * Two statistics, and a candidate is rejected on either:
 *
 *   longest_run   the longest strictly monotonic run, each character's code one
 *                 above (or, separately, one below) the last. The reported
 *                 alphabet carries runs of 26, 26 and 10.
 *   seq_fraction  adjacent pairs one apart, over all adjacent pairs. This
 *                 catches the shape a run length cannot see -- consecutive
 *                 pairs written in alternating directions, where no run ever
 *                 reaches 3 and half the pairs are still sequential.
 *
 * The thresholds are 6 and 0.40. The pair fraction sits high deliberately:
 * small alphabets produce sequential pairs by chance far more often than base64
 * does, and 0.40 is well clear of what a 16-symbol alphabet reaches.
 *
 * Measured before enabling, over the 140,000-sample realistic-token corpus at
 * seed 20260831 (bench/entropy-vetoes.ts): 0 rejected by run length, 0 by pair
 * fraction, 0.0000% loss. Bare hex was added to that corpus for this fix
 * because the 0.1.3 one carried none: 0 of 20,000 64-character samples and 1 of
 * 20,000 32-character samples, and an independent 200,000-draw run puts the
 * 32-character rate at 0.0010%. That value could not have been a candidate
 * anyway -- lowercase hex is two character classes, so it faces the 4.5 bar,
 * and a 16-symbol alphabet cannot exceed 4.0 bits.
 *
 * Entropy-tier only. Named provider rules never consult this.
 */
const ORDERED_RUN_MIN = 6;
const SEQUENTIAL_PAIR_FRACTION = 0.4;

export interface OrderedRunStats {
  /** Characters in the longest run of consecutive character codes. */
  longestRun: number;
  /** Adjacent pairs one code apart, over all adjacent pairs. */
  sequentialFraction: number;
}

export function orderedRunStats(value: string): OrderedRunStats {
  let longestRun = 1;
  let current = 1;
  let direction = 0;
  let sequential = 0;
  for (let i = 1; i < value.length; i++) {
    const delta = value.charCodeAt(i) - value.charCodeAt(i - 1);
    if (delta === 1 || delta === -1) {
      sequential++;
      // A change of direction ends the run and starts a new two-character one:
      // "abcba" is two runs of three, not one run of five.
      current = delta === direction ? current + 1 : 2;
      direction = delta;
      if (current > longestRun) longestRun = current;
    } else {
      direction = 0;
      current = 1;
    }
  }
  const pairs = value.length - 1;
  return { longestRun, sequentialFraction: pairs > 0 ? sequential / pairs : 0 };
}

export function hasOrderedRun(value: string): boolean {
  const stats = orderedRunStats(value);
  return (
    stats.longestRun >= ORDERED_RUN_MIN ||
    stats.sequentialFraction >= SEQUENTIAL_PAIR_FRACTION
  );
}

/**
 * Identifier paths, added in 0.1.4 (N7b).
 *
 * The other half of the first external report: a Storybook title,
 * "Components/NavSidebar/TabOverflowMenu", at entropy 4.39. Slash-separated
 * CamelCase is how a whole ecosystem names things -- stories, routes, i18n
 * keys, GraphQL operations -- and each segment being a word makes the string
 * score like a token while carrying no randomness at all.
 *
 * All three conditions must hold, and the narrowness is the point:
 *
 *   1. at least two "/" separators
 *   2. every segment is letters only, no digits
 *   3. at least one segment has a lowercase-to-uppercase transition
 *
 * Condition 2 carries the safety. Identifier paths rarely have mid-segment
 * digits and random tokens almost always do, so it is what keeps this away from
 * a base64 payload -- and from a 40-character AWS secret key with no
 * AWS_SECRET_ACCESS_KEY anchor, which has no named rule and depends on this
 * tier entirely. Do NOT widen the segment class to admit digits or punctuation
 * without measuring the cost first; the existing path filters in
 * STRUCTURAL_FALSE_POSITIVES record what happens when a path predicate is
 * allowed to be roomy.
 *
 * Measured before enabling, over the same 140,000-sample realistic-token corpus
 * as N7a (bench/entropy-vetoes.ts, seed 20260831): 5,202 samples carry two or
 * more slashes -- 3.7157%, so the veto is genuinely exercised rather than
 * vacuously safe -- and 0 of them satisfy all three conditions. 0.0000% loss.
 *
 * Entropy-tier only, like every other filter in this file.
 */
export function isIdentifierPath(value: string): boolean {
  const segments = value.split("/");
  if (segments.length < 3) return false;
  if (!segments.every((seg) => /^[A-Za-z]+$/.test(seg))) return false;
  return segments.some((seg) => /[a-z][A-Z]/.test(seg));
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

/**
 * N8 -- the key-context gate. OFF by default; see the note on
 * `keyContextRequired` in config.ts for why that default is a measurement
 * result rather than caution.
 *
 * When enabled, a QUOTED string literal is reported by this tier only if the
 * identifier it is assigned to carries a secret-like word.
 *
 * Whole words only. `author` is not `auth`, `keyboard` is not `key`, `bypass`
 * is not `pass` and `design` is not `sign`; substring matching turns each of
 * those into a silent false negative, which is the worst kind this tier can
 * produce because nothing in the output says a value was dropped.
 *
 * `api`, `hash` and `sign` are deliberately absent. They are too common in
 * identifiers that hold no credential (`apiVersion`, `hashCode`, `signal`) to
 * carry the gate, and `api` in particular would open it for most of a client
 * library.
 */
const KEY_CONTEXT_WORDS = new Set([
  "key",
  "token",
  "secret",
  "pass",
  "passwd",
  "password",
  "pwd",
  "auth",
  "cred",
  "credential",
  "credentials",
  "bearer",
  "private",
  "session",
  "cookie",
  "signature",
  "signing",
  "salt",
]);

/**
 * Splits an identifier into words on camel, snake, kebab and digit boundaries.
 *
 * The `(?<=[A-Z])(?=[A-Z][a-z])` alternative is what makes an acronym run
 * divide correctly: without it `APIToken` is one word and the gate never sees
 * `token`.
 */
export function splitIdentifierWords(identifier: string): string[] {
  return identifier
    .split(
      /[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])/
    )
    .filter(Boolean);
}

/** True when any whole word of the identifier is in the list. */
export function identifierSuggestsSecret(identifier: string): boolean {
  return splitIdentifierWords(identifier).some((w) => KEY_CONTEXT_WORDS.has(w.toLowerCase()));
}

/**
 * The identifier a quoted candidate is assigned to, or null.
 *
 * THE ONE INVARIANT: the search region ends before the candidate's opening
 * quote and never crosses a newline, so the identifier is always source text
 * strictly OUTSIDE the candidate's span. This is not a stylistic preference.
 * The previous attempt at this gate resolved the identifier out of the
 * candidate itself -- an FCM registration token reads `AAAA<id>:APA91b<rest>`,
 * the bare-assignment pattern split it at the token's own colon, and a real
 * credential was gated on half of itself. A value cannot be evidence about
 * itself, so no part of it is read here.
 *
 * Returns null on anything unclear, and null means fall through: the gate only
 * ever suppresses when it has a confident, outside-the-span identifier.
 */
export function resolveQuotedIdentifier(text: string, quoteIndex: number): string | null {
  const lineStart = text.lastIndexOf("\n", quoteIndex - 1) + 1;
  if (quoteIndex <= lineStart) return null;
  const before = text.slice(lineStart, quoteIndex);
  // An optional closing quote so a JSON key (`"api_key": "<value>"`) resolves
  // the same way a YAML or JS one does.
  const m = /["'`]?([A-Za-z_$][A-Za-z0-9_$]*)["'`]?\s*(?::=|[:=])\s*$/.exec(before);
  return m ? m[1] : null;
}

export interface EntropyScanOptions {
  /** N8. When true, a quoted candidate needs a secret-like identifier. */
  keyContextRequired?: boolean;
}

export function findHighEntropyStrings(
  text: string,
  threshold: number,
  options: EntropyScanOptions = {}
): EntropyMatch[] {
  const matches: EntropyMatch[] = [];
  const seen = new Set<number>();

  for (const pattern of [QUOTED_TOKEN, BARE_ASSIGNMENT]) {
    const quoted = pattern === QUOTED_TOKEN;
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(text)) !== null) {
      const value = m[1];
      const index = m.index + m[0].lastIndexOf(value);
      if (seen.has(index)) continue;

      // N8. Quoted literals only: a bare assignment, a .env line and a value
      // inside a larger token are never gated, which is also what keeps the
      // FCM shape out of reach of this gate entirely -- it reaches this tier
      // through BARE_ASSIGNMENT, not through a quoted literal.
      if (options.keyContextRequired && quoted) {
        const identifier = resolveQuotedIdentifier(text, index - 1);
        if (identifier !== null && !identifierSuggestsSecret(identifier)) continue;
      }

      if (isStructuralFalsePositive(value, threshold)) continue;
      if (hasOrderedRun(value)) continue;
      if (isIdentifierPath(value)) continue;
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
