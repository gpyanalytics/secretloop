import { Finding } from "./scanner";

/**
 * Did the fix actually remove the credential from the text it was applied to?
 *
 * A redaction that reports success has said one thing: the edit was applied.
 * That is not the same as the credential being gone, and the difference is not
 * academic -- a second copy three lines down survives an edit that succeeded,
 * under a notification saying the secret was redacted.
 *
 * WHY THIS DOES NOT RE-SCAN. The editor already re-scans after every fix, and
 * that rescan runs the detector under the project configuration: an inline
 * `secretloop:allow`, an `excludeRules` entry, an `allowValues` pattern or a
 * fixture path all make a credential vanish from it while it sits in the buffer
 * untouched. Absence from a filtered detector run is a statement about what the
 * detector reports under a configuration, not about whether the credential is
 * there. So this asks the only question that answers itself: does the exact
 * text we were about to remove still occur?
 *
 * That also makes it immune to a rule being disabled, reconfigured or removed
 * between the scan and the fix.
 */
export type ConfirmationOutcome =
  | "confirmed-absent"
  | "still-observed"
  | "confirmation-unavailable";

/** Why no claim could be made. Never a stand-in for "absent". */
export type ConfirmationUnavailableReason =
  /** The fix itself did not happen, so there is nothing to confirm. */
  | "edit-not-applied"
  /** The document could not be read: closed, disposed, or getText threw. */
  | "document-unreadable"
  /** No usable target value was held for this operation. */
  | "target-not-retained"
  /** The text cannot be inspected in a way that would support an absence claim. */
  | "scope-not-inspectable"
  /** This kind of finding has no confirmation under the first-slice contract. */
  | "operation-unsupported";

/**
 * What was established, and about what.
 *
 * `scope` is stated on every result and is deliberately narrow: ONE document's
 * editor text, as read immediately after the edit. Not the file on disk -- the
 * buffer may be unsaved and nothing here saves it -- not other documents, not
 * the working tree, not the index, not git history, not any archive, and not
 * the provider.
 */
export interface FixConfirmation {
  outcome: ConfirmationOutcome;
  scope: "editor-document";
  /**
   * Occurrences of the target still in the inspected text. Present only on
   * `still-observed`, where it is at least 1. A count, never a location.
   */
  occurrences?: number;
  /**
   * The buffer version the observation was made against, when the document
   * reports one. Internal: it says WHICH text was inspected, and it is never
   * shown to anyone. A later version can differ -- see the note on snapshots
   * below.
   */
  documentVersion?: number;
  unavailableReason?: ConfirmationUnavailableReason;
}

/** The only scope this slice can inspect completely, named once. */
const SCOPE = "editor-document" as const;

function unavailable(
  reason: ConfirmationUnavailableReason,
  documentVersion?: number
): FixConfirmation {
  return {
    outcome: "confirmation-unavailable",
    scope: SCOPE,
    unavailableReason: reason,
    ...(documentVersion !== undefined ? { documentVersion } : {}),
  };
}

/** The confirmation for a fix that never happened. */
export function notApplied(): FixConfirmation {
  return unavailable("edit-not-applied");
}

/**
 * Occurrences of `target` in `text`, counted NON-OVERLAPPING, left to right.
 *
 * The distinction matters for a degenerate target: "aaa" occurs twice in
 * "aaaa" if overlaps count and once if they do not. Non-overlapping is the
 * right answer here because the number is offered to a person as "how many more
 * of these are in this file" -- each one is a distinct run of characters they
 * would have to remove, and two overlapping matches are one such run.
 *
 * An empty target is not searched for: it "occurs" everywhere and means
 * nothing. Callers reject it before reaching here.
 */
export function countOccurrences(text: string, target: string): number {
  if (target.length === 0) return 0;
  let count = 0;
  let from = 0;
  for (;;) {
    const at = text.indexOf(target, from);
    if (at === -1) return count;
    count++;
    from = at + target.length;
  }
}

/**
 * The minimum a document must offer to be inspected. Modelled on
 * vscode.TextDocument, narrowed to what this file reads, so the helper can be
 * tested without one.
 */
export interface InspectableDocument {
  getText(): string;
  isClosed?: boolean;
  version?: number;
}

/**
 * NUL makes text something this product declines to read.
 *
 * A file whose bytes contain NUL is classified binary by the walker and is not
 * scanned at all. Claiming a credential is absent from a document the rest of
 * SecretLoop would refuse to look at states more than was established, so the
 * absence claim is withheld. A POSITIVE observation is not withheld: finding
 * the value there is a fact regardless of what else the text contains.
 */
// Built, never written: a literal NUL in this source file would make the file
// itself binary to the scanner that reads this repository.
const NUL = String.fromCharCode(0);

/**
 * Inspect one document for the exact value a fix was supposed to remove.
 *
 * PRECEDENCE, in this order and for this reason:
 *   1. unsupported kinds are decided before anything is inspected, so no
 *      observation is made and none is implied;
 *   2. a positive observation outranks every coverage doubt -- if the value is
 *      there, nothing about incomplete inspection makes it absent;
 *   3. any doubt yields `confirmation-unavailable`;
 *   4. only a clean, complete inspection yields `confirmed-absent`.
 * A doubt is never resolved into absence.
 *
 * THE TARGET is the value the caller already holds in memory for the operation
 * -- the same string the pre-edit staleness check compares against. It is
 * passed in, used, and dropped. It is never persisted, logged, printed,
 * transmitted or hashed: no new digest of credential material exists anywhere
 * in this feature, and the value-derived fingerprint is deliberately not used,
 * because matching one would need a detector to produce it and detector
 * coverage is exactly what must not be trusted here.
 *
 * A BOUNDED READ IS NOT A SNAPSHOT. The result is an observation of the text
 * this call read, at the version recorded on it -- `TextDocument.version`
 * "strictly increase[s] after each change", so it identifies WHICH buffer state
 * was inspected. It cannot rule out an edit landing afterwards, another process
 * writing the file, an unsaved buffer differing from disk, or a copy anywhere
 * else.
 *
 * IT CLAIMS NO CAUSATION. "This document no longer contains the value" is not
 * "the edit removed it": another change can land between applyEdit resolving
 * and this read, and `applyEdit` reports success without any version check --
 * the API has none to offer. The two facts are reported side by side and joined
 * by nothing, deliberately. What this does catch, and what the old flow could
 * not, is the opposite case: an edit that lands on the wrong text, or a second
 * copy the fix never touched, both of which show up here as still-observed.
 */
export function confirmTargetRemoved(
  document: InspectableDocument,
  finding: Pick<Finding, "value" | "encoding">
): FixConfirmation {
  // An encoded finding's `value` is the ENCODED source span, so a search for it
  // can only speak about that spelling. A decoded copy elsewhere in the
  // document would not be found, and reporting absence from a search that
  // cannot see the other spelling would be the wrong kind of reassuring.
  if (finding.encoding !== undefined) return unavailable("operation-unsupported");

  const target = finding.value;
  // Rejected, not reported absent. An empty or non-string target establishes
  // nothing, and "we searched for nothing and did not find it" must never
  // render as a clean result.
  if (typeof target !== "string" || target.length === 0) {
    return unavailable("target-not-retained");
  }

  let text: string;
  let version: number | undefined;
  try {
    if (document.isClosed === true) return unavailable("document-unreadable");
    text = document.getText();
    version = document.version;
  } catch {
    return unavailable("document-unreadable");
  }
  if (typeof text !== "string") return unavailable("document-unreadable", version);

  const occurrences = countOccurrences(text, target);
  if (occurrences > 0) {
    return {
      outcome: "still-observed",
      scope: SCOPE,
      occurrences,
      ...(version !== undefined ? { documentVersion: version } : {}),
    };
  }

  if (text.includes(NUL)) return unavailable("scope-not-inspectable", version);

  return {
    outcome: "confirmed-absent",
    scope: SCOPE,
    ...(version !== undefined ? { documentVersion: version } : {}),
  };
}

/**
 * The sentence appended to a fix's own message.
 *
 * Fixed wording plus a validated count, and nothing else: no path, no value, no
 * fingerprint, no rule id, and no text out of the repository. Every sentence
 * names the scope, because "checked this file" and "the secret is gone" are
 * different claims and only the first one was established.
 */
export function describeConfirmation(confirmation: FixConfirmation): string {
  switch (confirmation.outcome) {
    case "confirmed-absent":
      return "Checked this editor document: the value is no longer in its text.";
    case "still-observed": {
      const n = confirmation.occurrences ?? 0;
      return (
        `The same value is STILL in this editor document (${n} more ` +
        `occurrence${n === 1 ? "" : "s"}). Check for another copy.`
      );
    }
    default:
      return `Could not check this editor document: ${reasonClause(confirmation)}`;
  }
}

/** One fixed clause per reason. Never interpolates anything but the reason. */
function reasonClause(confirmation: FixConfirmation): string {
  switch (confirmation.unavailableReason) {
    case "edit-not-applied":
      return "nothing was edited.";
    case "document-unreadable":
      return "its text could not be read.";
    case "target-not-retained":
      return "there was no usable value to check for.";
    case "scope-not-inspectable":
      return "its text cannot be inspected the way this check needs.";
    case "operation-unsupported":
      return "this kind of finding is not supported by the check yet.";
    default:
      return "the check could not run.";
  }
}
