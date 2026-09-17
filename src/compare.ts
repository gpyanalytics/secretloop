import { openSync, fstatSync, readSync, closeSync, statSync, constants as fsConstants } from "fs";
import { REPORT_SCHEMA_VERSION, scopeIdentity } from "./report-metadata";
import { rulesById } from "./rules";
import { ENTROPY_RULE_ID } from "./scanner";
import { PKCS12_RULE_ID } from "./pkcs12";

/**
 * Comparison of two saved JSON reports.
 *
 * WHAT THIS IS FOR. The comparison metadata has existed since schema 2 so that a
 * later tool could decide whether two reports may be compared AT ALL. Until now
 * nothing enforced those rules, so the rules were a document. This is the
 * enforcement, and it is deliberately the smallest thing that can be honest:
 * it reads two files, decides eligibility, and either reports a difference or
 * refuses.
 *
 * WHAT IT REFUSES TO DO, ON PURPOSE. It never rescans, never verifies liveness,
 * never calls a provider and never touches a file it is comparing. Both inputs
 * are treated as UNTRUSTED: they may have travelled through CI logs, artifact
 * stores and other people's machines before arriving here.
 *
 * THE GOVERNING INVARIANT, inherited from the scanner: "could not look" must
 * never read as "found nothing". A pair that cannot be compared is reported as
 * INCOMPARABLE with its reasons, and never as a clean comparison with an empty
 * difference -- those look identical to a script and mean opposite things.
 *
 * THE TRUST BOUNDARY, stated plainly because it is easy to overstate what this
 * module does. It validates the CLAIMS a report makes about itself. It does not
 * authenticate the report, and it cannot:
 *
 *   - there is no signature, MAC or provenance of any kind on a report, so
 *     anyone who can write a file can write one that satisfies every rule here;
 *   - every identity checked below is a value the producer PUT in the file. A
 *     forged report can carry the supported scope digest, a matching config
 *     digest and `incomplete: false` while describing a scan that never ran;
 *   - passing these checks therefore means "these two reports are internally
 *     consistent and declare compatible scans", never "these two scans really
 *     happened and really covered what they say".
 *
 * That is the correct boundary for this tool -- the metadata was designed to
 * stop ACCIDENTAL mis-comparison, not to resist a forger -- but a caller
 * comparing reports from an untrusted source is trusting that source, not this
 * module.
 */

/** Refuse a file larger than this before reading it. A report is text. */
export const MAX_REPORT_BYTES = 64 * 1024 * 1024;

/** Refuse a findings array longer than this. Bounded work on hostile input. */
export const MAX_FINDINGS = 200_000;

/**
 * How many invalid findings are described IN DETAIL for each report.
 *
 * PER SIDE, not shared, and that is the point: a single allowance would let one
 * hostile report fill it and hide every error in the other, so a user fixing
 * the first side would then discover the second only on the next run. Each side
 * gets its own budget, so errors from both are always visible.
 *
 * Every finding is still INSPECTED -- the walk is bounded by MAX_FINDINGS -- so
 * the counts reported are exact. Only the per-error detail is capped, which is
 * what keeps output bounded on hostile input.
 */
export const MAX_FINDING_DIAGNOSTICS_PER_SIDE = 10;

/**
 * The COMPLETE fingerprint structure the producer emits, per
 * `createFingerprint` in src/config.ts:
 *
 *     <normalized path>:<ruleId>:<16 lowercase hex>
 *
 * Parsed from the RIGHT, because only the last two separators are structural: a
 * path legitimately contains colons on every platform, and `normalizePath` maps
 * the platform separator to `/` without touching anything else. So the path
 * segment is whatever remains, and no pattern is imposed on it.
 *
 * The rule id IS constrained: every id the build can emit -- all 110 in
 * src/rules.ts plus `generic-high-entropy` and `pkcs12-private-key` -- matches
 * this grammar, and the same identity shape is what the baseline file stores.
 */
const RULE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * The rule ids this build can actually emit -- MEMBERSHIP, not merely grammar.
 *
 * The grammar above accepts any lowercase alphanumeric run, so an arbitrary
 * string smuggled into the rule segment of a fingerprint passed it and was then
 * printed. Reproduced through the CLI in both formats before this check
 * existed: an unknown 26-character marker appeared verbatim in the text output
 * and in the JSON `ruleId` field.
 *
 * Derived from the EXISTING AUTHORITIES rather than copied, so there is no
 * second list to drift:
 *   - `rulesById`        every rule in src/rules.ts
 *   - `ENTROPY_RULE_ID`  the generic entropy tier, defined in src/scanner.ts
 *   - `PKCS12_RULE_ID`   the structural keystore detector, in src/pkcs12.ts
 *
 * These are module constants. Reading them starts no scan, opens no network
 * connection and verifies nothing with a provider.
 */
const SUPPORTED_RULE_IDS: ReadonlySet<string> = new Set<string>([
  ...rulesById.keys(),
  ENTROPY_RULE_ID,
  PKCS12_RULE_ID,
]);
const FINGERPRINT_DIGEST = /^[0-9a-f]{16}$/;
const MAX_FINGERPRINT_CHARS = 4096;

/**
 * Control characters, DEL, and the bidirectional overrides that let text render
 * as something other than what it is.
 *
 * Checked on the FINGERPRINT AT INTAKE rather than scrubbed on the way out,
 * because the fingerprint is the matching key: scrubbing it would silently
 * change which findings match each other. Rejecting instead keeps matching
 * exact and keeps the output safe, and it fails in the conservative direction —
 * a report carrying such a fingerprint is refused, not quietly compared.
 */
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/;

/**
 * Field-specific validity, exactly as `docs/reports.md` states it. A shared
 * shape is not enough: `root` and `scopeDigest` carry different prefixes, and a
 * bare 16-hex string is valid for a config digest and invalid for a scope one.
 */
const FIELD_PATTERNS: Record<string, RegExp> = {
  root: /^git:[0-9a-f]{16}$/,
  configDigest: /^[0-9a-f]{16}$/,
  ruleSetDigest: /^[0-9a-f]{16}$/,
  suppressionDigest: /^[0-9a-f]{16}$/,
  scopeDigest: /^scope:[0-9a-f]{16}$/,
  binaryDigest: /^binary:[0-9a-f]{16}$/,
};

/**
 * The ONE scope identity this contract supports, taken from the SHARED
 * AUTHORITY rather than written out as a constant.
 *
 * `scopeIdentity` is the same function the producer uses, and the scope contract
 * version is hashed INSIDE its input. So this value moves automatically if
 * either the representation or `SCOPE_CONTRACT_VERSION` changes, and a report
 * written under a different scope contract stops matching instead of silently
 * comparing. A hard-coded `scope:4a9f…` would have frozen today's answer and
 * drifted the moment the producer changed.
 *
 * This is POSITIVE validation: the comparator asserts which scope it supports,
 * rather than inferring one from other fields happening to be absent.
 */
const SUPPORTED_SCOPE = scopeIdentity({ mode: "worktree" });

/** The identity fields that must be EQUAL across the pair, in report order. */
const IDENTITY_FIELDS = [
  "toolVersion",
  "root",
  "configDigest",
  "ruleSetDigest",
  "suppressionDigest",
  "scopeDigest",
  "binaryDigest",
] as const;

/** Machine-readable reason codes. Text is derived from these, never the reverse. */
export type ReasonCode =
  | "unreadable-input"
  | "oversized-input"
  | "malformed-json"
  | "not-an-object"
  | "missing-field"
  | "invalid-field"
  | "unsupported-schema"
  | "mixed-schema"
  | "incomplete-coverage"
  | "identity-mismatch"
  | "unsupported-scope"
  | "malformed-findings"
  | "malformed-finding-identity"
  | "diagnostics-truncated";

export interface Reason {
  code: ReasonCode;
  /** Which report the reason is about: "before", "after", or "both". */
  side: "before" | "after" | "both";
  /** The metadata field or structural element at fault. Never report content. */
  field?: string;
  /**
   * A short, SAFE explanation. Never contains report content, a credential, a
   * path from the report, or anything else the input supplied -- only field
   * names this module chose and values it validated as digests or integers.
   */
  detail: string;
}

/**
 * A finding as the comparator is willing to talk about it.
 *
 * Built field by field from validated input. The report's own objects are NEVER
 * copied through: an input object can carry any key at all, including a `value`
 * holding an unredacted credential, and spreading it would launder that
 * straight into the comparator's output.
 *
 * `value`, `redactedValue` and every other content-bearing field are
 * deliberately ABSENT. A comparator does not need a secret's text to say the
 * finding is still there, and a field named "redacted" is a claim by the input,
 * not a fact.
 */
/**
 * THE PRESENTATION BOUNDARY.
 *
 * A report is UNTRUSTED INPUT. It may have been produced by another tool, edited
 * by hand, or travelled through CI logs and artifact stores before arriving
 * here. Echoing a report-supplied path or any other arbitrary string can carry a
 * credential straight into a terminal, a CI log or an exported JSON artifact,
 * where it outlives the comparison.
 *
 * So INTERNAL MATCHING AND EXTERNAL PRESENTATION DELIBERATELY USE DIFFERENT
 * REPRESENTATIONS. Matching uses the full raw fingerprint, byte for byte,
 * because changing it would change which findings pair up. Presentation uses
 * only the constrained fields below, and DISCARDS the rest rather than
 * rewriting it.
 *
 * A credential-shaped path is therefore ACCEPTED INTERNALLY -- it matches
 * normally and is never rejected for its contents -- and simply never appears
 * in output. It is not detected, and no claim is made that it was.
 *
 * WHAT THIS DOES AND DOES NOT ESTABLISH. Constraining the output fields limits
 * WHAT CAN BE ECHOED: a rule id must be one this build emits, a severity one of
 * four words, a digest 16 hex characters, a line a number. That is a bound on
 * the channel, NOT a proof about content -- no check here, and no check
 * anywhere, can establish that arbitrary text contains no secret, and none is
 * claimed to. Nor does validating this metadata AUTHENTICATE the report: every
 * value was written by whoever produced the file.
 */
export interface FindingRef {
  /**
   * The rule that matched, taken from the fingerprint. Required to be a member
   * of `SUPPORTED_RULE_IDS` -- the grammar alone accepts any lowercase
   * alphanumeric run and is NOT a vocabulary.
   */
  ruleId: string;
  /**
   * The 16-hex tail of the fingerprint: fixed shape, and a VERBATIM SUBSTRING of
   * the identity already in the report -- not a new identifier, and nothing is
   * hashed here. It is enough to find the finding again in either report.
   */
  digest: string;
  line: number | null;
  severity: string | null;
}

export interface AmbiguityNote {
  ruleId: string;
  digest: string;
  beforeCount: number;
  afterCount: number;
}

/**
 * DISTINCT identities that happen to display the same `ruleId` and `digest`.
 *
 * A DIFFERENT THING FROM `AmbiguityNote`, and deliberately reported separately:
 *
 *   - `AmbiguityNote` is ONE identity seen several times -- the same full
 *     fingerprint repeated within a report, which the digest cannot tell apart
 *     because it does not cover the line.
 *   - This is SEVERAL identities that look alike on screen. The digest covers
 *     the matched value and not the path, so one credential found by one rule
 *     in several files yields several distinct fingerprints sharing one
 *     displayed pair.
 *
 * Conflating them would be wrong in both directions: the first is a count the
 * comparator refuses to interpret, the second is a display collision over
 * findings it has already told apart correctly.
 *
 * `distinctIdentities` counts the distinct FULL fingerprints involved across
 * both reports. It is a count, not an identifier: no path, no fingerprint and
 * nothing positional is published, and nothing new is hashed.
 */
export interface SharedReferenceNote {
  ruleId: string;
  digest: string;
  /** How many distinct full identities share this displayed pair. Always > 1. */
  distinctIdentities: number;
}

export interface ComparisonResult {
  /** True only for an eligible pair that was actually compared. */
  comparable: boolean;
  /** Empty when comparable. Never empty when not. */
  reasons: Reason[];
  /** Present only when comparable. */
  added: FindingRef[];
  persisting: FindingRef[];
  noLongerObserved: FindingRef[];
  /**
   * Fingerprints occurring more than once in either report. Reported rather
   * than guessed at -- see `groupByFingerprint`.
   */
  ambiguousIdentity: AmbiguityNote[];
  /**
   * Displayed references that stand for more than one distinct identity. Empty
   * when every displayed pair in this result is unique.
   */
  sharedDisplayReferences: SharedReferenceNote[];
}

interface LoadedReport {
  meta: Record<string, unknown>;
  findings: unknown[];
}

/** The severities the scanner defines. Anything else is not echoed. */
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);

/**
 * The location and rule, taken FROM THE FINGERPRINT rather than from the
 * report's own `file` and `ruleId` fields.
 *
 * Those fields are free-form untrusted strings, and stripping control
 * characters from them is not enough: a report whose fingerprint is perfectly
 * clean can still carry a live credential in `file` or `ruleId`, and echoing
 * them printed it. Measured on the success path, which is worse -- an eligible
 * comparison that leaks.
 *
 * The fingerprint is already validated (shape, length, no control characters)
 * and is already printed, because it is the identity. Deriving the display
 * fields from it means the comparator echoes exactly ONE untrusted string per
 * finding instead of four, and the location it shows is guaranteed to be the
 * one it matched on rather than a parallel claim that may disagree.
 *
 * Shape is `<path>:<ruleId>:<16 hex>`, split from the RIGHT because a path may
 * itself contain colons.
 */
function parseFingerprint(
  fingerprint: string
): { pathPart: string; ruleId: string; digest: string } | null {
  const lastColon = fingerprint.lastIndexOf(":");
  if (lastColon <= 0) return null;
  const digest = fingerprint.slice(lastColon + 1);
  if (!FINGERPRINT_DIGEST.test(digest)) return null;
  const ruleColon = fingerprint.lastIndexOf(":", lastColon - 1);
  if (ruleColon < 0) return null;
  const ruleId = fingerprint.slice(ruleColon + 1, lastColon);
  if (!RULE_ID.test(ruleId)) return null;
  const pathPart = fingerprint.slice(0, ruleColon);
  if (pathPart.length === 0) return null;
  return { pathPart, ruleId, digest };
}

/** Structure parsed and the rule is one this build emits. */
function supportedIdentity(fingerprint: string): { ruleId: string; digest: string } | null {
  const parts = parseFingerprint(fingerprint);
  if (!parts) return null;
  if (!SUPPORTED_RULE_IDS.has(parts.ruleId)) return null;
  return { ruleId: parts.ruleId, digest: parts.digest };
}

/** Strip anything that could break a terminal or forge structure in output. */
function safeText(value: unknown, max = 512): string {
  if (typeof value !== "string") return "";
  // Control characters, DEL, and the bidirectional overrides that let a hostile
  // path render as a different path than it is.
  return value
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "")
    .slice(0, max);
}

/**
 * Reads and structurally validates one report file.
 *
 * Size is checked with `stat` BEFORE the read, so a hostile 4 GB file costs a
 * stat rather than 4 GB of memory.
 */
/** Chunk size for the bounded read. Also the bound on overflow past the cap. */
const READ_CHUNK = 1 << 20;

/** Test seam. Not reachable from the CLI, which never passes options. */
export interface LoadOptions {
  /** Overrides MAX_REPORT_BYTES so limit tests need no giant fixture. */
  maxBytes?: number;
  /** Runs after the descriptor is opened and inspected, before any read. */
  afterOpen?: () => void;
}

export function loadReport(
  path: string,
  side: "before" | "after",
  options: LoadOptions = {}
): { report: LoadedReport } | { reasons: Reason[] } {
  const limit = options.maxBytes ?? MAX_REPORT_BYTES;
  const oversized = (): { reasons: Reason[] } => ({
    reasons: [
      { code: "oversized-input", side, detail: `report is larger than the ${limit}-byte limit` },
    ],
  });

  let raw: string;
  // ONE DESCRIPTOR for inspection and reading.
  //
  // The previous shape was `statSync(path)` followed by `readFileSync(path)`:
  // two independent resolutions of the same name, with no bound on the second.
  // A file that grew, or a path replaced, between the two was read in full
  // whatever its size -- the cap described the file that WAS there, not the
  // bytes that were actually read.
  //
  // Now `fstat` inspects the OPENED OBJECT and every byte comes from that same
  // descriptor, so a later rename or replacement of the path cannot change what
  // is read, and growth is caught because the cap is enforced DURING the read
  // rather than before it.
  let fd: number;
  try {
    // Non-blocking where the platform defines the flag. A report path that IS
    // a FIFO with no writer made this open wait indefinitely -- measured
    // through the built CLI in both argument positions -- because `open` on a
    // FIFO waits for a writer. With `O_NONBLOCK` the open returns at once and
    // the `fstat` below refuses the non-file as it always did, before any
    // read. A regular file is unaffected. This reader has no pre-open check,
    // so there is no stat-to-open window here; the case is the static one.
    //
    // On win32 `fs.constants.O_NONBLOCK` is undefined, the flag is 0 and this
    // is a plain read-only open -- exactly the previous behaviour, stated as a
    // fallback and not as protection; no FIFO can exist on an NTFS path.
    fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0));
  } catch {
    // The OS message can carry the path and the reason; neither is needed.
    return { reasons: [{ code: "unreadable-input", side, detail: "could not be opened" }] };
  }
  try {
    // Classifies the OPENED object before any byte is read; a FIFO or device
    // that the non-blocking open let through is refused here and the
    // descriptor is closed in the finally below.
    const st = fstatSync(fd);
    if (!st.isFile()) {
      return { reasons: [{ code: "unreadable-input", side, detail: "not a regular file" }] };
    }
    // An optimization only: it rejects an already-huge file without reading it.
    // It is NOT the guard -- the loop below is, and it does not trust this.
    if (st.size > limit) return oversized();
    options.afterOpen?.();

    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const buf = Buffer.allocUnsafe(READ_CHUNK);
      const n = readSync(fd, buf, 0, READ_CHUNK, null);
      if (n === 0) break;
      total += n;
      // Enforced while reading. At most one chunk is ever read past the cap,
      // which is the bounded overflow that lets "exactly the limit" and "one
      // byte over" be told apart, and the input is rejected BEFORE parsing.
      if (total > limit) return oversized();
      chunks.push(buf.subarray(0, n));
    }
    raw = Buffer.concat(chunks, total).toString("utf8");
  } catch {
    return { reasons: [{ code: "unreadable-input", side, detail: "could not be read" }] };
  } finally {
    // Closed on every path: success, rejection and throw alike.
    try {
      closeSync(fd);
    } catch {
      /* already closed or invalid; nothing further to do */
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Deliberately NOT the parser's message: it quotes the offending input.
    return { reasons: [{ code: "malformed-json", side, detail: "not valid JSON" }] };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { reasons: [{ code: "not-an-object", side, detail: "top level is not a JSON object" }] };
  }
  const obj = parsed as Record<string, unknown>;

  const findings = obj.findings;
  if (!Array.isArray(findings)) {
    return { reasons: [{ code: "malformed-findings", side, detail: "`findings` is not an array" }] };
  }
  if (findings.length > MAX_FINDINGS) {
    return {
      reasons: [
        { code: "malformed-findings", side, detail: `more than ${MAX_FINDINGS} findings` },
      ],
    };
  }
  return { report: { meta: obj, findings } };
}

/**
 * Validates the nine required comparison fields of ONE report.
 *
 * Absent and invalid are separate codes because they have different causes: a
 * missing field means the producer could not establish it, and an invalid one
 * means something rewrote it.
 */
function validateOne(meta: Record<string, unknown>, side: "before" | "after"): Reason[] {
  const reasons: Reason[] = [];

  const version = meta.schemaVersion;
  if (version === undefined || version === null) {
    reasons.push({ code: "missing-field", side, field: "schemaVersion", detail: "absent" });
  } else if (typeof version !== "number" || !Number.isInteger(version)) {
    reasons.push({ code: "invalid-field", side, field: "schemaVersion", detail: "not an integer" });
  } else if (version !== REPORT_SCHEMA_VERSION) {
    // Covers 1, 2, 3 and every unknown future version in one rule. Guessing at
    // a version this build does not implement is how two different meanings of
    // one field come to compare as though they agreed.
    reasons.push({
      code: "unsupported-schema",
      side,
      field: "schemaVersion",
      detail: `schema ${version} is not supported; this build implements ${REPORT_SCHEMA_VERSION}`,
    });
  }

  if (meta.toolVersion === undefined || meta.toolVersion === null) {
    reasons.push({ code: "missing-field", side, field: "toolVersion", detail: "absent" });
  } else if (typeof meta.toolVersion !== "string") {
    reasons.push({ code: "invalid-field", side, field: "toolVersion", detail: "not a string" });
  } else if (meta.toolVersion.trim() === "") {
    reasons.push({ code: "invalid-field", side, field: "toolVersion", detail: "empty" });
  }

  for (const [field, pattern] of Object.entries(FIELD_PATTERNS)) {
    const value = meta[field];
    if (value === undefined || value === null) {
      reasons.push({ code: "missing-field", side, field, detail: "absent" });
      continue;
    }
    if (typeof value !== "string") {
      reasons.push({ code: "invalid-field", side, field, detail: "not a string" });
      continue;
    }
    if (!pattern.test(value)) {
      // The value is not echoed: a field this malformed is exactly the one an
      // attacker would use to smuggle text into an operator's terminal.
      reasons.push({ code: "invalid-field", side, field, detail: "malformed" });
      continue;
    }
    if (field === "scopeDigest" && value !== SUPPORTED_SCOPE) {
      // WELL-FORMED BUT NOT A SUPPORTED SCOPE. Two history reports over the
      // same commits carry equal, valid scope digests, and equality alone would
      // have admitted them the moment anything supplied the other fields. This
      // contract compares WORKING-TREE scans, so it says so and checks it.
      //
      // The digest is safe to echo: it has already been matched against
      // `scope:<16 hex>`, so it cannot carry anything but hex.
      reasons.push({
        code: "unsupported-scope",
        side,
        field,
        detail:
          `scope ${value} is not the supported working-tree scope ` +
          `(${SUPPORTED_SCOPE ?? "unavailable"})`,
      });
    }
  }

  const incomplete = meta.incomplete;
  if (incomplete === undefined || incomplete === null) {
    reasons.push({ code: "missing-field", side, field: "incomplete", detail: "absent" });
  } else if (typeof incomplete !== "boolean") {
    reasons.push({ code: "invalid-field", side, field: "incomplete", detail: "not a boolean" });
  } else if (incomplete !== false) {
    // `true === true` must NOT permit comparison. Two scans that both failed to
    // cover their scope are not thereby comparable; they are both unreliable.
    reasons.push({
      code: "incomplete-coverage",
      side,
      field: "incomplete",
      detail: "the scan did not cover everything it set out to",
    });
  }

  return reasons;
}

/**
 * One finding's identity, or null when it has none the comparator can use.
 *
 * A finding without a usable fingerprint cannot be matched, and silently
 * dropping it would under-report a difference in whichever direction happens to
 * be convenient. The caller refuses the whole comparison instead.
 */
/**
 * Why one finding's identity was refused.
 *
 * Two causes, distinguished so a reader knows which to fix: a fingerprint that
 * does not parse against the structure at all, and one that parses but names a
 * rule this build does not emit. Both refuse the comparison; neither is ever
 * described by quoting the offending value.
 */
type IdentityFailure = "structure" | "unsupported-rule";

function refOf(
  raw: unknown
): { key: string; ref: FindingRef } | { failure: IdentityFailure } {
  const bad = (failure: IdentityFailure) => ({ failure });
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return bad("structure");
  const f = raw as Record<string, unknown>;
  const fp = f.fingerprint;
  if (typeof fp !== "string") return bad("structure");
  if (fp.length === 0 || fp.length > MAX_FINGERPRINT_CHARS) return bad("structure");
  if (UNSAFE_CHARS.test(fp)) return bad("structure");
  const line = typeof f.line === "number" && Number.isFinite(f.line) ? f.line : null;
  // Location comes from the fingerprint, not from the report's own fields --
  // see locationOf. `severity` is admitted only from the scanner's own set, so
  // an arbitrary string cannot ride out through it either.
  const structure = parseFingerprint(fp);
  if (!structure) return bad("structure");
  if (!SUPPORTED_RULE_IDS.has(structure.ruleId)) return bad("unsupported-rule");
  const parts = structure;
  const severity = typeof f.severity === "string" && SEVERITIES.has(f.severity) ? f.severity : null;
  // The PATH IS DELIBERATELY NOT CARRIED. See the note on FindingRef above and
  // the policy in docs/reports.md: matching uses the full raw fingerprint,
  // presentation uses only fields of fixed, closed shape.
  // `key` is the FULL RAW fingerprint and is used for matching ONLY. It is
  // never sanitized (that would change what matches what) and never printed.
  return { key: fp, ref: { ruleId: parts.ruleId, digest: parts.digest, line, severity } };
}

/**
 * Groups findings by fingerprint, KEEPING THE COUNT.
 *
 * This is where a Set would have been wrong. Fingerprints are keyed on
 * (path, ruleId, value) and deliberately NOT on line number, so one credential
 * appearing three times in a file is three findings carrying ONE fingerprint.
 * A `Set` would silently turn that into one, and a change from three
 * occurrences to one would then read as "persisting, nothing happened".
 *
 * The identity available in a report cannot distinguish those occurrences, so
 * this does not pretend to: it counts them, and the caller reports any
 * fingerprint seen more than once as an explicit ambiguity rather than guessing
 * what the count change meant.
 */
function inspectFindings(
  findings: unknown[],
  side: "before" | "after"
): {
  groups: Map<string, { ref: FindingRef; count: number }>;
  reasons: Reason[];
  invalidCount: number;
} {
  const groups = new Map<string, { ref: FindingRef; count: number }>();
  const reasons: Reason[] = [];
  let invalidCount = 0;

  // EVERY finding is inspected, so `invalidCount` is exact and may be stated as
  // a total. Only the per-error DETAIL is capped. The walk is bounded by
  // MAX_FINDINGS, which loadReport enforces before this is reached.
  for (let i = 0; i < findings.length; i++) {
    const parsed = refOf(findings[i]);
    if ("failure" in parsed) {
      invalidCount += 1;
      if (reasons.length < MAX_FINDING_DIAGNOSTICS_PER_SIDE) {
        reasons.push({
          code: "malformed-finding-identity",
          side,
          // `field` carries the array index so an error is addressable without
          // naming anything the report supplied. The index is this module's own
          // counter over the input array, not a value from the report, and it
          // is deliberately NOT an identifier that means anything in another
          // report -- the same index in a different file is a different finding.
          field: `findings[${i}]`,
          detail:
            parsed.failure === "unsupported-rule"
              ? "names a rule this build does not support"
              : "has no usable fingerprint",
        });
      }
      continue;
    }
    const existing = groups.get(parsed.key);
    if (existing) existing.count += 1;
    else groups.set(parsed.key, { ref: parsed.ref, count: 1 });
  }

  // Truncation is stated, never implied by a short list.
  const listed = reasons.length;
  if (invalidCount > listed) {
    reasons.push({
      code: "diagnostics-truncated",
      side,
      field: "findings",
      detail:
        `${invalidCount} invalid finding(s) in total; ${listed} described above and ` +
        `${invalidCount - listed} not listed`,
    });
  }
  return { groups, reasons, invalidCount };
}

/**
 * Compares two already-loaded reports.
 *
 * ELIGIBILITY IS DECIDED FIRST, AND COMPLETELY. No difference is computed for an
 * ineligible pair -- not even internally -- so there is no way for a
 * difference to leak into output beside an "incomparable" verdict.
 *
 * WORKING-TREE SCOPE IS CHECKED POSITIVELY. Each report's `scopeDigest` must
 * EQUAL `scopeIdentity({ mode: "worktree" })`, computed here from the same
 * shared authority the producer uses. Presence of the nine fields is not
 * enough, and neither is the two reports agreeing with each other: two history
 * scans over the same commits carry equal, well-formed scope digests, so
 * equality alone would admit them. Because `SCOPE_CONTRACT_VERSION` is hashed
 * inside that function's input, a report written under a different scope
 * contract stops matching automatically rather than comparing silently.
 *
 * Nothing is inferred from a field being absent, and nothing is read from the
 * prose scope sentence.
 */
export function compareReports(before: LoadedReport, after: LoadedReport): ComparisonResult {
  const reasons: Reason[] = [
    ...validateOne(before.meta, "before"),
    ...validateOne(after.meta, "after"),
  ];

  // Mixed versions, including a supported side paired with an unsupported one.
  // Reported separately from "unsupported": a 4-and-5 pair and a 3-and-3 pair
  // fail for different reasons and a reader should be told which.
  const vb = before.meta.schemaVersion;
  const va = after.meta.schemaVersion;
  if (Number.isInteger(vb) && Number.isInteger(va) && vb !== va) {
    reasons.push({
      code: "mixed-schema",
      side: "both",
      field: "schemaVersion",
      detail: `the reports declare different schema versions (${vb} and ${va})`,
    });
  }

  // Identity equality, only for fields that were individually valid: reporting
  // "differs" about a field already reported malformed is noise.
  const invalid = new Set(
    reasons.filter((r) => r.field && r.code !== "incomplete-coverage").map((r) => r.field as string)
  );
  for (const field of IDENTITY_FIELDS) {
    if (invalid.has(field)) continue;
    if (before.meta[field] !== after.meta[field]) {
      reasons.push({
        code: "identity-mismatch",
        side: "both",
        field,
        detail: `${field} differs between the reports`,
      });
    }
  }

  if (reasons.length > 0) {
    return {
      comparable: false,
      reasons,
      added: [],
      persisting: [],
      noLongerObserved: [],
      ambiguousIdentity: [],
      sharedDisplayReferences: [],
    };
  }

  // BOTH sides are inspected before refusing. Stopping at the first invalid
  // finding meant a user fixed one report, reran, and only then learned the
  // other was broken too. Metadata is still validated first and matching still
  // never happens for an ineligible pair -- this only widens the DIAGNOSTICS.
  const gb = inspectFindings(before.findings, "before");
  const ga = inspectFindings(after.findings, "after");
  if (gb.invalidCount > 0 || ga.invalidCount > 0) {
    return {
      comparable: false,
      // Deterministic order: every before-side reason in ascending index order,
      // then every after-side reason, each followed by its truncation note.
      reasons: [...gb.reasons, ...ga.reasons],
      added: [],
      persisting: [],
      noLongerObserved: [],
      ambiguousIdentity: [],
      sharedDisplayReferences: [],
    };
  }

  const added: FindingRef[] = [];
  const persisting: FindingRef[] = [];
  const noLongerObserved: FindingRef[] = [];
  const ambiguousIdentity: AmbiguityNote[] = [];

  for (const [fp, entry] of ga.groups) {
    const prior = gb.groups.get(fp);
    if (prior) persisting.push(entry.ref);
    else added.push(entry.ref);
  }
  for (const [fp, entry] of gb.groups) {
    if (!ga.groups.has(fp)) noLongerObserved.push(entry.ref);
  }
  for (const [fp, entry] of gb.groups) {
    const other = ga.groups.get(fp);
    if (entry.count > 1 || (other && other.count > 1)) {
      ambiguousIdentity.push({
        ruleId: entry.ref.ruleId,
        digest: entry.ref.digest,
        beforeCount: entry.count,
        afterCount: other?.count ?? 0,
      });
    }
  }
  for (const [fp, entry] of ga.groups) {
    if (!gb.groups.has(fp) && entry.count > 1) {
      ambiguousIdentity.push({
        ruleId: entry.ref.ruleId,
        digest: entry.ref.digest,
        beforeCount: 0,
        afterCount: entry.count,
      });
    }
  }

  // Distinct identities that will PRINT the same way. Computed over the union
  // of full keys from both sides, so a collision spanning the two reports is
  // caught as readily as one inside either.
  const identitiesByReference = new Map<string, { ref: FindingRef; keys: Set<string> }>();
  for (const groups of [gb.groups, ga.groups]) {
    for (const [key, entry] of groups) {
      const reference = `${entry.ref.ruleId}:${entry.ref.digest}`;
      const seen = identitiesByReference.get(reference);
      if (seen) seen.keys.add(key);
      else identitiesByReference.set(reference, { ref: entry.ref, keys: new Set([key]) });
    }
  }
  const sharedDisplayReferences: SharedReferenceNote[] = [];
  for (const { ref, keys } of identitiesByReference.values()) {
    if (keys.size > 1) {
      sharedDisplayReferences.push({
        ruleId: ref.ruleId,
        digest: ref.digest,
        distinctIdentities: keys.size,
      });
    }
  }

  const byFp = (x: { ruleId: string; digest: string }, y: { ruleId: string; digest: string }) => {
    const a = `${x.ruleId}:${x.digest}`;
    const b = `${y.ruleId}:${y.digest}`;
    return a < b ? -1 : a > b ? 1 : 0;
  };
  added.sort(byFp);
  persisting.sort(byFp);
  noLongerObserved.sort(byFp);
  ambiguousIdentity.sort(byFp);
  sharedDisplayReferences.sort(byFp);

  return {
    comparable: true,
    reasons: [],
    added,
    persisting,
    noLongerObserved,
    ambiguousIdentity,
    sharedDisplayReferences,
  };
}

/**
 * The wording is part of the contract.
 *
 * "No longer observed" is the ONLY thing the data supports. It means the
 * finding is absent from the later comparable report -- not fixed, not removed,
 * not rotated, not revoked, and not absent from anywhere else. Every one of
 * those would be a claim about the world that two scan reports cannot make.
 */
export const NO_LONGER_OBSERVED_CAVEAT =
  "No longer observed means absent from the later report. It does not mean fixed, " +
  "removed, rotated or revoked, and it makes no claim about files excluded from " +
  "either scan or about renamed findings.";

export function renderText(result: ComparisonResult): string {
  if (!result.comparable) {
    const lines = ["These reports cannot be compared.", ""];
    for (const r of result.reasons) {
      const where = r.side === "both" ? "both reports" : `the ${r.side} report`;
      lines.push(`  ${r.code}${r.field ? ` (${r.field})` : ""} — ${where}: ${r.detail}`);
    }
    lines.push("");
    // Said explicitly, because the dangerous misreading of an incomparable
    // result is "nothing changed".
    lines.push("No difference is reported: an ineligible pair says nothing about");
    lines.push("what changed between the two scans, in either direction.");
    return lines.join("\n") + "\n";
  }

  const lines = [
    `${result.added.length} new, ${result.persisting.length} persisting, ` +
      `${result.noLongerObserved.length} no longer observed.`,
  ];
  const section = (title: string, refs: FindingRef[]) => {
    if (refs.length === 0) return;
    lines.push("", `${title.toUpperCase()} (${refs.length})`);
    for (const f of refs) {
      const at = f.line === null ? "" : ` line ${f.line}`;
      lines.push(`  [${f.severity ?? "unknown"}] ${f.ruleId}${at} — ${f.digest}`);
    }
  };
  section("new", result.added);
  section("persisting", result.persisting);
  section("no longer observed", result.noLongerObserved);

  if (result.sharedDisplayReferences.length > 0) {
    lines.push("", `SHARED DISPLAY REFERENCE (${result.sharedDisplayReferences.length})`);
    lines.push("  More than one DISTINCT finding is shown under each reference below.");
    lines.push("  They were told apart correctly and counted separately above; it is");
    lines.push("  only the printed pair that collides, because the digest covers the");
    lines.push("  matched value and not the file.");
    lines.push("  Scanned paths are omitted from this output on purpose, so looking a");
    lines.push("  pair up in the original report may return MORE THAN ONE match.");
    for (const r of result.sharedDisplayReferences) {
      lines.push(`    ${r.ruleId} — ${r.digest} — ${r.distinctIdentities} distinct findings`);
    }
  }

  if (result.ambiguousIdentity.length > 0) {
    lines.push("", `AMBIGUOUS IDENTITY (${result.ambiguousIdentity.length})`);
    lines.push("  ONE identity seen several times -- a different thing from the shared");
    lines.push("  references above. A fingerprint covers (path, rule, value) and NOT the");
    lines.push("  line, so one credential repeated in a file shares one identity.");
    lines.push("  Occurrence-level changes below are NOT tracked and are not reported");
    lines.push("  either way:");
    for (const a of result.ambiguousIdentity) {
      lines.push(`    ${a.ruleId} — ${a.digest} — ${a.beforeCount} before, ${a.afterCount} after`);
    }
  }

  if (result.noLongerObserved.length > 0) {
    lines.push("", NO_LONGER_OBSERVED_CAVEAT);
  }
  return lines.join("\n") + "\n";
}

export function renderJson(result: ComparisonResult): string {
  const body = result.comparable
    ? {
        tool: "secretloop",
        comparable: true,
        summary: {
          new: result.added.length,
          persisting: result.persisting.length,
          noLongerObserved: result.noLongerObserved.length,
          ambiguousIdentity: result.ambiguousIdentity.length,
          sharedDisplayReferences: result.sharedDisplayReferences.length,
        },
        new: result.added,
        persisting: result.persisting,
        noLongerObserved: result.noLongerObserved,
        ambiguousIdentity: result.ambiguousIdentity,
        // ADDITIVE. Distinct identities that print alike -- never a change to
        // the meaning of an existing field, and unrelated to
        // REPORT_SCHEMA_VERSION, which versions the input scan reports rather
        // than this tool's own output.
        sharedDisplayReferences: result.sharedDisplayReferences,
        caveat: NO_LONGER_OBSERVED_CAVEAT,
      }
    : {
        tool: "secretloop",
        comparable: false,
        reasons: result.reasons,
        // No difference keys at all, not even empty ones: an empty `new` array
        // beside `comparable: false` is exactly the shape a careless consumer
        // reads as "compared, nothing new".
      };
  return JSON.stringify(body, null, 2) + "\n";
}
