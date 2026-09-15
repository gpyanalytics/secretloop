import { createHash } from "crypto";
import { spawnSync } from "child_process";
import type { SecretLoopConfig } from "./config";
import { rules } from "./rules";
import { ArchiveAccounting, countOf } from "./archive";

/**
 * Identities that a later comparison of two reports needs before it may say
 * anything at all about change.
 *
 * The rule that shapes every decision here: **absent means unknown, and unknown
 * means not comparable.** A comparison that cannot establish two scans looked at
 * the same population with the same rules must refuse to call a finding new or
 * gone -- and the only way to guarantee that is for this file to omit a field it
 * cannot determine rather than emit a placeholder. `null` would be worse than
 * useless: two reports that both say `"root": null` compare equal on a naive
 * read, which is exactly the false "resolved" this metadata exists to prevent.
 *
 * Nothing here is secret-derived. The digests cover configuration structure and
 * rule definitions; `allowValues` is the one configured field whose CONTENT is
 * never hashed, because a project may legitimately have written a literal
 * credential into it, and a digest over a small guessable input is an oracle,
 * not anonymisation.
 */

/**
 * Bumped when the MEANING of any comparison-bearing field changes.
 *
 * A consumer that does not recognise the version must treat the report as
 * incomparable rather than guess. Adding a purely descriptive field does not
 * bump it; changing what `incomplete` counts, or what a digest covers, does.
 *
 * 1 -> 2 added `scopeDigest`, so a version-1 report could not be shown to have
 * examined any particular population.
 *
 * 2 -> 3 NARROWED WHAT `incomplete` COUNTS. Binary input (see the classifier's
 * documented boundary in walk.ts) is now an intentional exclusion rather than a
 * coverage limitation, so a version-3
 * report can say `incomplete: false` where version 2 said `true` for the same
 * tree. The two booleans do not mean the same thing, and comparison requires
 * `incomplete: false` on BOTH sides -- so without this bump a version-2 report
 * and a version-3 report would have qualified as equivalent on a field whose
 * meaning had changed underneath them. Rejecting on the version is the only
 * thing that stops that, because the value itself still type-checks.
 *
 * 3 -> 4 ADDED A REQUIRED FIELD, `binaryDigest`, closing the hole that the
 * 2 -> 3 exemption opened. Under 3 a file could cross into the binary set
 * between two scans and its findings would vanish with every comparison field
 * still equal -- measured: insert one NUL into a file holding a credential,
 * without touching the credential, and the pair stays eligible while the
 * finding disappears. Version 4 makes the excluded SET part of eligibility, so
 * that pair is incomparable. The set of required fields changed, which is the
 * named trigger for a bump on its own.
 */
export const REPORT_SCHEMA_VERSION = 4;

/**
 * The version of the scope representation `scopeDigest` covers.
 *
 * Carried INSIDE the digest input, so a change to what a scope means produces a
 * different digest rather than a silently comparable one. It is separate from
 * the report schema version because the two can move independently.
 */
export const SCOPE_CONTRACT_VERSION = 1;

/**
 * The version of the binary-exclusion representation `binaryDigest` covers.
 *
 * Carried INSIDE the digest input for the same reason as the scope version: a
 * change to what an exclusion set means must produce a different digest rather
 * than a silently comparable one.
 */
export const BINARY_CONTRACT_VERSION = 1;

/** The comparison-bearing fields. Every optional one means "unknown" when absent. */
export interface ComparisonMetadata {
  schemaVersion: number;
  /** Omitted when the caller supplied none -- an empty version cannot be told from a real one. */
  toolVersion?: string;
  /** Portable repository identity. Omitted when the scan root is not a git repository. */
  root?: string;
  /** Covers the effective configuration, excluding `allowValues` content. */
  configDigest: string;
  /** Covers the rule definitions this build would apply. */
  ruleSetDigest: string;
  /**
   * Covers the configured exclusions. Omitted whenever a suppression mechanism
   * was active that this digest cannot identify -- see `suppressionsUnidentified`.
   */
  suppressionDigest?: string;
  /**
   * Covers WHICH POPULATION the scan examined. Omitted when the selection could
   * not be established.
   */
  scopeDigest?: string;
  /**
   * Covers WHICH FILES WERE EXCLUDED AS BINARY, so a file crossing into or out
   * of that set breaks a pair instead of reading as a finding appearing or
   * disappearing. Omitted when the scan could not establish the exclusion set.
   */
  binaryDigest?: string;
  /** True when the scan could not look at something it set out to look at. */
  incomplete: boolean;
}

/** What the scan could not cover. Descriptive; `incomplete` is derived from it. */
export interface CoverageFacts {
  /** Files enumerated but skipped for exceeding maxFileSizeBytes. */
  oversizedExcluded?: number;
  /**
   * Files classified BINARY and intentionally not scanned.
   *
   * Descriptive and disclosed, but NOT a coverage limitation: a text scanner
   * declining binary input is a scope decision, not a failure to look. See
   * coverageLimitations, and walk.ts for what the classifier does and does not
   * establish -- it never establishes that the file held no secret.
   */
  binaryExcluded?: number;
  /** Files the scan intended to read and could not: permission, I/O, unknown. */
  unreadableExcluded?: number;
  /** Paths enumerated that were not regular files by the time they were read. */
  notAFileExcluded?: number;
  /** Paths that were gone by the time the read reached them. */
  vanishedExcluded?: number;
  /** Files refused because a symlink resolved outside the scan root. */
  outsideExcluded?: number;
  /** Archive accounting, when the scan met a container. */
  archives?: ArchiveAccounting;
  /** The scan was stopped before it finished. */
  cancelled?: boolean;
}

/** Suppression mechanisms that were active, for the descriptive block and the digest gate. */
export interface SuppressionFacts {
  /** Number of configured `allowValues` regexes. Content is never read here. */
  allowValuesCount: number;
  /** A baseline file was applied to this scan. */
  baselineApplied: boolean;
  /** Findings dropped by an inline `secretloop:allow` directive. */
  inlineSuppressed: number;
}

function digest(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex").slice(0, 16);
}

/**
 * A canonical serialization, so two runs with the same effective inputs digest
 * identically regardless of how the objects were built.
 *
 * Object keys are sorted, and string arrays are sorted too: `excludePaths` is a
 * set in everything but type, and two projects that list the same globs in a
 * different order are running the same scan. Sorting the ARRAY is safe for
 * exactly that reason and is not applied to anything order-sensitive, of which
 * the digest inputs below contain none.
 */
function canonical(value: unknown): string {
  if (Array.isArray(value)) {
    const parts = value.map((v) => canonical(v));
    return `[${[...parts].sort().join(",")}]`;
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

/**
 * The effective configuration, after project file and CLI flags.
 *
 * `allowValues` is represented by its COUNT and never its content. A project
 * that allowlists a literal credential would otherwise have that value hashed
 * into a field published in CI logs, and a digest over a short guessable string
 * confirms a guess -- the count still makes a change to the list visible,
 * because a changed count changes the digest, and a same-length change is
 * caught by the suppression gate below, which refuses to emit an identity at
 * all while any allowValues entry is in play.
 */
export function configDigest(config: SecretLoopConfig): string {
  // `excludeReasons` leaves with `allowValues`, and for a stricter reason than
  // privacy: a reason is a comment about an exclusion, not the exclusion. A
  // digest that moved when somebody documented why a rule is off would report a
  // configuration change where none happened, and two scans of the identical
  // configuration would stop comparing equal over an edit to a sentence.
  const { allowValues, excludeReasons, ...rest } = config;
  void excludeReasons;
  return digest(canonical({ ...rest, allowValuesCount: allowValues.length }));
}

/**
 * The rule definitions this build would apply.
 *
 * Keyed on what changes detection -- pattern, flags, floors, allowlists,
 * severity -- and not on the human description, so a wording fix does not make
 * two scans incomparable. The tool version alone is not enough: a patched or
 * locally built binary can carry a different rule set at the same version.
 */
export function ruleSetDigest(): string {
  const shape = rules
    .map((r) => ({
      id: r.id,
      pattern: r.regex.source,
      flags: r.regex.flags,
      fullMatch: r.fullMatch,
      severity: r.severity,
      entropy: r.entropy ?? null,
      keywords: r.keywords ?? null,
      generic: r.generic ?? false,
      fingerprintStrategy: r.fingerprintStrategy ?? null,
      allowlist: (r.allowlist ?? []).map((x) => x.source),
      matchAllowlist: (r.matchAllowlist ?? []).map((x) => x.source),
      postPrefixEntropy: r.postPrefixEntropy
        ? { prefix: r.postPrefixEntropy.prefix.source, min: r.postPrefixEntropy.min }
        : null,
    }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return digest(canonical(shape));
}

/**
 * A portable identity for the scanned repository.
 *
 * The root commit, not the path: the absolute path is local to one machine and
 * publishing it in a report that travels to CI logs and dashboards discloses a
 * directory layout for no benefit, while the same repository cloned elsewhere
 * must still compare equal to itself.
 *
 * THE DIGEST IS NOT CONCEALMENT. A root commit is public for any repository the
 * reader can clone, so anyone holding this report can compute the same digest
 * for a candidate repository and confirm a match in one command. It is a
 * CONFIRMABLE IDENTIFIER: it avoids publishing a local path, and it does not
 * hide which repository was scanned. Do not rely on it to do so.
 *
 * IT IDENTIFIES AN ANCESTRY, NOT A TREE. A fork shares its upstream's root
 * commit, so a fork and its upstream produce the SAME identity however far they
 * have diverged. Equal `root` therefore means "same ancestry", never "same
 * content" and never "same scan scope" -- see the scope limitation in
 * docs/reports.md, which this field does not address.
 *
 * The identity also depends on which commits are reachable from HEAD: an orphan
 * branch gives a different one, and merging an unrelated history adds a root and
 * changes it. Those all fail in the safe direction -- different rather than
 * wrongly equal.
 *
 * Returns undefined -- meaning UNKNOWN -- when the root is not a git repository
 * or has no commits. A scan of a plain directory therefore has no root identity,
 * which is the honest outcome: nothing about a bare path establishes that two
 * scans covered the same population.
 *
 * A shallow clone reports its grafted root, so a shallow and a full clone of
 * one repository do NOT share an identity. That is a false negative -- they
 * compare as incomparable rather than as equal -- and it fails in the safe
 * direction.
 */
export function repositoryIdentity(root: string): string | undefined {
  const res = spawnSync("git", ["rev-list", "--max-parents=0", "HEAD"], {
    cwd: root,
    encoding: "utf8",
  });
  if (res.status !== 0) return undefined;
  const roots = res.stdout
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .sort();
  if (roots.length === 0) return undefined;
  return `git:${digest(roots.join(","))}`;
}

/**
 * Whether every suppression mechanism in play is one the configuration digest
 * identifies, and the digest itself when it is.
 *
 * Three mechanisms are deliberately treated as UNIDENTIFIABLE:
 *
 *  - `allowValues`, whose content is never hashed (see configDigest);
 *  - an applied baseline, whose entries are value-derived fingerprints, so a
 *    digest of them would be a new secret-derived hash;
 *  - inline `secretloop:allow` directives, which live in the scanned source. A
 *    COUNT of them is not an identity: two scans can suppress the same number of
 *    findings in different places, and treating equal counts as equal
 *    suppression is precisely how a still-present secret comes to read as
 *    resolved.
 *
 * When any is active the digest is omitted. That only PREVENTS anything if the
 * comparator requires the field: the reviewed design's reference model lists
 * only toolVersion, root, configDigest and ruleSetDigest as required, so under
 * that model alone a withheld suppression identity changes nothing. The
 * normative required-field list a comparator must enforce is in
 * docs/reports.md; omission here is the producer's half of it, not an
 * enforcement mechanism on its own.
 *
 * The gate counts EFFECTS, not the presence of a directive: a `secretloop:allow`
 * that suppressed nothing leaves the identity intact, because nothing was
 * hidden from that scan. If the same directive later suppresses a finding, that
 * scan's count is non-zero and its identity is withheld, so no pair in which
 * anything was actually hidden can be declared comparable.
 */
export function suppressionIdentity(
  config: SecretLoopConfig,
  facts: SuppressionFacts
): { digest?: string; unidentified: string[] } {
  const unidentified: string[] = [];
  if (facts.allowValuesCount > 0) {
    unidentified.push("allowValues entries are configured and their content is never hashed");
  }
  if (facts.baselineApplied) {
    unidentified.push("a baseline was applied and its entries are value-derived fingerprints");
  }
  if (facts.inlineSuppressed > 0) {
    unidentified.push("findings were suppressed by inline directives in the scanned source");
  }
  if (unidentified.length > 0) return { unidentified };
  return {
    digest: digest(
      canonical({
        excludePaths: config.excludePaths,
        generatedExcludePaths: config.generatedExcludePaths,
        includePaths: config.includePaths,
        excludeRules: config.excludeRules,
        includeFixtures: config.includeFixtures,
        includeApiDocumentEntropy: config.includeApiDocumentEntropy,
        keyContextRequired: config.keyContextRequired,
        maxFileSizeBytes: config.maxFileSizeBytes,
      })
    ),
    unidentified,
  };
}

/**
 * What the scan selected, as executed.
 *
 * `history` carries the commits that were actually read, reported by the parser
 * that read them. It deliberately does NOT carry the rev-range string or the
 * commit cap: those are the REQUEST, and two different requests can select the
 * same commits. `HEAD~2..HEAD`, an explicit SHA range covering the same two
 * commits, and `--max-commits 2` on a two-commit repository are one selection
 * and compare equal. A range string is not a selection, and equal commit COUNTS
 * are not either -- two disjoint ranges of the same length are the case this
 * field exists to reject.
 */
export type ScopeSelection =
  | { mode: "worktree" }
  | { mode: "staged" }
  | { mode: "history"; commits: string[] };

/**
 * A digest of the scan's selection, or undefined when it could not be
 * established.
 *
 * The modes examine different populations of the same repository, so they must
 * never share an identity: a working-tree scan and a history scan of one
 * repository are different questions.
 *
 * STAGED SCANS GET NO IDENTITY AT ALL, and the reason is a demonstrated failure
 * rather than caution. A staged scan's population is the index, which changes
 * with `git add` and `git reset` and not with the file. Stage a file holding a
 * secret and scan: the finding is reported. Unstage the same byte-identical
 * file and scan again: nothing is reported -- while the secret is still sitting
 * in the working tree, and a working-tree scan still finds it. With a mode-only
 * identity those two reports carried the SAME scope digest, the same everything
 * else, and both complete, so the pair was eligible and the second report read
 * as the finding being gone.
 *
 * Making the identity track the staged file set instead would not fix it: the
 * index is working-tree state, so every pair would differ and nothing would ever
 * compare. What the pair actually needs is a comparator that labels a staged
 * report as a snapshot of the index and refuses to read its absences as
 * disappearances -- which is a comparator design, not a digest. Until that
 * exists, withholding is the honest answer: a staged report is INELIGIBLE, the
 * same way a report with an unidentifiable suppression state is.
 *
 * WHAT THIS DOES NOT DO. It does not distinguish two working-tree scans of the
 * same repository at different moments, and it is not meant to: detecting that
 * the content changed is the whole purpose of a later comparison, and folding
 * the tree state or HEAD into the scope would make every pair incomparable and
 * answer nothing.
 *
 * HISTORY IS STRICTER, ON PURPOSE. Two history scans compare only when they read
 * exactly the same commits. A commit added since the earlier scan changes the
 * set and makes the pair incomparable rather than reporting the new commit's
 * findings as "new". That is conservative and is stated as a first-version
 * limitation in docs/reports.md, not as a permanent contract.
 */
export function scopeIdentity(selection: ScopeSelection | undefined): string | undefined {
  if (!selection) return undefined;
  // See above: the index is not a selection rule, and a mode-only identity made
  // an unstaged-but-unchanged secret read as resolved.
  if (selection.mode === "staged") return undefined;
  if (selection.mode === "history") {
    // A history scan whose selection was never reported cannot be identified.
    // Undefined is the honest answer; an empty set is a REAL selection (a range
    // that matched no commit) and is not the same thing.
    if (!Array.isArray(selection.commits)) return undefined;
  }
  return `scope:${digest(canonical({ v: SCOPE_CONTRACT_VERSION, ...selection }))}`;
}

/**
 * The identity of the set of files EXCLUDED AS BINARY.
 *
 * WHY THIS EXISTS. Once a binary exclusion stopped making a report incomplete,
 * a file could cross into the binary set between two scans and its findings
 * would simply vanish from the second report with every comparison field still
 * equal. Measured on the real build: a UTF-8 file holding a credential, then
 * ONE NUL byte inserted without touching the credential -- the finding is gone,
 * `incomplete` is still false, all eight other fields match, and a conforming
 * consumer reads the credential as REMOVED while it sits on disk. This digest
 * is what makes that pair incomparable, because the excluded set changed.
 *
 * WHAT IT COVERS. A canonical, sorted, deduplicated set of REPOSITORY-RELATIVE
 * paths, carried with `BINARY_CONTRACT_VERSION` inside the digest input.
 *
 * THE INPUT CONTRACT: CANONICAL, REPOSITORY-RELATIVE, `/`-SEPARATED.
 *
 * Callers pass paths as the enumeration produced them, and the enumeration is
 * where the originating path semantics are known. `walkDirectory` in walk.ts
 * already converts the platform separator at that boundary
 * (`path.relative(...).split(path.sep).join("/")`), so a Windows run hands this
 * function `/` exactly as a POSIX run does, and `git ls-files` emits `/` on
 * every platform. Nothing legitimate reaches here with a backslash in it.
 *
 * WHICH IS WHY A BACKSLASH IS REFUSED RATHER THAN REWRITTEN. This function used
 * to replace `\` with `/`. On POSIX a backslash is a legal FILENAME character,
 * so that rewrite mapped a real file named `dir\file.png` onto the unrelated
 * real path `dir/file.png` and handed both the same identity -- two genuinely
 * different exclusion sets reading as one. It cannot be repaired by guessing:
 * arriving here, a backslash is either a literal name or a path that skipped
 * the boundary conversion, and the two are indistinguishable. Silently
 * reinterpreting a literal POSIX filename as a separator is the one thing this
 * function must never do, so the whole set is refused instead.
 *
 * NORMALIZATION, so two runs of the same tree agree:
 *   - a leading `./` is stripped;
 *   - duplicates collapse (a Set), and order is irrelevant -- the caller may
 *     report exclusions in any order, including a different order per run;
 *   - NOTHING ELSE is rewritten. Case is preserved, because distinct
 *     case-sensitive filenames are distinct files; Unicode is not normalized,
 *     because NFC and NFD are different names and deciding they are one is a
 *     filesystem question this function cannot answer.
 *
 * REFUSED OUTRIGHT, returning undefined for the WHOLE set:
 *   - any path containing a backslash (above);
 *   - an ABSOLUTE path, a drive path (`C:/...`) or a UNC path, rather than
 *     publishing a local directory layout into a report that travels;
 *   - a NON-CANONICAL spelling -- a `.` or `..` segment, a repeated separator,
 *     a trailing separator -- because one file would otherwise have two
 *     identities depending on how the producer spelled it;
 *   - an empty string, or anything that is not a string.
 *
 * REFUSAL IS ALL-OR-NOTHING, AND THAT IS THE POINT. One unrepresentable path
 * withholds the entire digest. The problematic path is never dropped so the
 * rest can be hashed -- that would publish a confident identity for a SUBSET
 * while claiming to describe the set -- and the empty-set digest is never
 * substituted, which would claim nothing was excluded. Withholding makes the
 * pair ineligible, which is the safe direction.
 *
 * WHAT IT DOES NOT COVER. No file CONTENT is hashed, no credential, and no
 * absolute path. It is a set of names and nothing else.
 *
 * IT IS NOT ANONYMISATION. Paths in a repository are often predictable --
 * `docs/icon.png`, `assets/logo.gif` -- so a reader holding a candidate list can
 * test guesses against this digest exactly as they can against `root`. It is a
 * comparison identity, not concealment, and nothing here should be read as
 * hiding which files were excluded.
 *
 * THE EMPTY SET IS A REAL IDENTITY, not an absence: a scan that excluded
 * nothing binary gets a digest, and two such scans compare. `undefined` means
 * something different and stronger -- the producer could not establish the set
 * at all -- and under the contract that makes the pair ineligible.
 */
export function binaryIdentity(paths: readonly string[] | undefined): string | undefined {
  // Not "no exclusions": no ACCOUNTING. A producer that cannot observe its own
  // exclusion events must not claim the empty set, which would compare equal to
  // a scan that genuinely excluded nothing.
  if (!paths) return undefined;
  const normalized = new Set<string>();
  for (const raw of paths) {
    if (typeof raw !== "string" || raw === "") return undefined;
    // AMBIGUOUS, so refused before anything else is decided. See the contract
    // above: this is a literal filename character on POSIX and a separator the
    // enumeration has already converted on Windows, and nothing here can tell
    // which one arrived. It also covers `C:\x` and `\\server\share\x`.
    if (raw.includes("\\")) return undefined;
    const rel = raw.startsWith("./") ? raw.slice(2) : raw;
    if (rel === "") return undefined;
    // An absolute, drive or UNC path means the caller handed us something that
    // is not repository-relative. Withholding is the honest answer; publishing
    // it would put a local layout into the report. (`//server/share` starts
    // with `/`, so the first test covers UNC in its slash spelling too.)
    if (rel.startsWith("/") || /^[A-Za-z]:\//.test(rel)) return undefined;
    // Non-canonical spellings of one path would otherwise get two identities,
    // and `..` could name something outside the root the producer was given.
    if (rel.includes("//") || rel.endsWith("/")) return undefined;
    if (rel.split("/").some((segment) => segment === "." || segment === "..")) return undefined;
    normalized.add(rel);
  }
  const sorted = [...normalized].sort();
  return `binary:${digest(canonical({ v: BINARY_CONTRACT_VERSION, paths: sorted }))}`;
}

/**
 * The reasons this scan did not cover everything it set out to cover.
 *
 * Deliberate policy -- generated-file exclusions, fixture suppression, API
 * document scoping, configured excludePaths -- is NOT incompleteness. Those are
 * decisions, they are identified by the configuration digest, and a change to
 * any of them already makes a pair incomparable. What lands here is the scan
 * failing to reach something it intended to read: a file too large, a file it
 * could not read, a path that was not a file or was gone, a symlink refused by
 * the containment guard, an archive it could not finish enumerating, and a run
 * that was stopped.
 *
 * `binaryExcluded` IS DELIBERATELY ABSENT FROM THIS FUNCTION. Binary input is
 * the same kind of fact as a generated file: a scope decision, not a
 * failure to look. It stays fully disclosed in the scope sentence -- an
 * intentional skip is still a skip the reader must know about -- but it does
 * not make the report incomplete. It used to: binary and "could not read it"
 * shared one bucket, so a single PNG made every report from that tree
 * permanently ineligible for comparison.
 *
 * This is why REPORT_SCHEMA_VERSION moved to 3. `incomplete` now counts a
 * strictly narrower set of facts, and a version-2 report that says
 * `incomplete: true` may be describing nothing worse than an image. Two
 * meanings of one boolean must never silently qualify as equivalent.
 *
 * Everything that is NOT a positive determination stays here, including the
 * conservative `unreadable` bucket: not knowing why an input did not read is
 * never evidence that nothing was missed.
 */
export function coverageLimitations(facts: CoverageFacts): string[] {
  const out: string[] = [];
  const {
    oversizedExcluded = 0,
    unreadableExcluded = 0,
    notAFileExcluded = 0,
    vanishedExcluded = 0,
    outsideExcluded = 0,
    archives,
    cancelled = false,
  } = facts;
  if (cancelled) out.push("the scan was stopped before it finished");
  if (oversizedExcluded > 0) {
    out.push(`${oversizedExcluded} file(s) not scanned — larger than maxFileSizeBytes`);
  }
  if (unreadableExcluded > 0) {
    out.push(`${unreadableExcluded} file(s) not scanned — could not be read`);
  }
  if (notAFileExcluded > 0) {
    out.push(`${notAFileExcluded} path(s) not scanned — not a regular file`);
  }
  if (vanishedExcluded > 0) {
    out.push(`${vanishedExcluded} file(s) not scanned — gone before they could be read`);
  }
  if (outsideExcluded > 0) {
    out.push(`${outsideExcluded} file(s) not scanned — resolved outside the scan root`);
  }
  if (archives) {
    const refused = countOf(archives.members.refused);
    const notOpened = countOf(archives.containersNotOpened);
    if (refused > 0) out.push(`${refused} archive member(s) not scanned`);
    if (notOpened > 0) out.push(`${notOpened} archive container(s) not opened`);
    if (archives.enumeration.incompleteContainers > 0) {
      out.push(
        `${archives.enumeration.incompleteContainers} archive(s) not fully enumerated`
      );
    }
  }
  return out;
}
