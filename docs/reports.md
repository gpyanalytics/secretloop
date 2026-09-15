# The JSON report — schema, identities and what they do not establish

`--format json` produces a machine-readable report. Alongside the findings it
carries **comparison metadata**: identities that let a later tool decide whether
two reports may be compared at all.

The comparison command does not exist yet. This page documents the metadata it
will require, because the metadata has to be in reports **before** the tool can
use them — a report written today is the "before" side of tomorrow's comparison.

**Status: merged, not yet released.** This metadata is on `main` and is **not in
any published package** — published 0.5.1 does not emit it. The `toolVersion`
value in the example below is illustrative, not a claim about which release
carries these fields.

## Shape

```jsonc
{
  "tool": "secretloop",

  // Comparison-bearing. See the rule below: an absent key means UNKNOWN.
  "schemaVersion": 3,
  "toolVersion": "0.5.1",
  "root": "git:af829fc833133fca",
  "configDigest": "3071344b11905ec5",
  "ruleSetDigest": "c6f8fdd1265654d9",
  "suppressionDigest": "9b1c…",     // omitted when suppression cannot be identified
  // omitted for a staged scan, when the selection cannot be established,
  // and when a history scan was interrupted
  "scopeDigest": "scope:4a9f5bca…",
  "incomplete": false,

  "summary": {
    "total": 0,
    "scope": "…",                    // the prose sentence, unchanged
    "scannedCount": 0,
    "scopeNoun": "file",
    "coverage": {                    // DESCRIPTIVE, not comparison-bearing
      "limitations": [],
      "suppression": {
        "allowValuesCount": 0,
        "baselineApplied": false,
        "inlineSuppressed": 0,
        "unidentified": []
      }
    },
    "confirmedLive": 0,
    "bySeverity": {},
    "byLiveness": {}
  },

  "findings": [ /* unchanged */ ]
}
```

**The findings array is untouched.** Its fields, their order and the fingerprint
are exactly what they were; `column` remains internal and does not appear here.

## The rule that shapes everything: absent means unknown

**A field SecretLoop could not determine is omitted, not set to `null`.**

This is not a stylistic choice. Two reports that both say `"root": null` compare
equal on a naive read, and a comparison would conclude that two unrelated trees
covered the same population — which is how a secret that is still present comes
to be reported as gone. An absent key cannot be mistaken for a match.

A consumer must therefore treat **any missing comparison field as grounds to
refuse the comparison**, never as "the same". The same applies to a
`schemaVersion` it does not recognise.

## Comparison-bearing fields

| field | meaning | absent when |
|---|---|---|
| `schemaVersion` | the meaning of the fields below | never |
| `toolVersion` | which SecretLoop produced the report | the caller supplied none |
| `root` | the scanned repository's ancestry — shared by forks, so not a unique identity | the scan root is not a git repository, or has no commits |
| `configDigest` | the effective configuration | never |
| `ruleSetDigest` | the rule definitions this build applies | never |
| `suppressionDigest` | the configured exclusions | any suppression mechanism was active that cannot be identified |
| `scopeDigest` | **which population the scan examined** | the scan was `staged`, the selection could not be established, or the scan stopped early |
| `incomplete` | the scan could not cover what it set out to | never |

`schemaVersion` is bumped when the **meaning** of one of these changes — what a
digest covers, what `incomplete` counts, or the set of required fields. Adding a
descriptive field does not bump it. **It is `3`**:

- version 1 had no `scopeDigest`, so a version-1 report cannot be shown to have
  examined any particular population;
- version 2 counted **binary input as a coverage failure**, so its
  `incomplete: true` may describe nothing worse than a PNG. Version 3 counts
  only the scan failing to read something it intended to read.

A consumer implementing this contract accepts `3` and rejects everything else,
including `2` and `1`. **This is the whole reason the version moved.** The
boolean still type-checks and still reads `true` or `false`, so nothing but the
version stops a version-2 report and a version-3 report from comparing across
two different meanings of the same field.

### `root` is a shared-ancestry marker, not a repository identity

It is a digest of the repository's **root commit**, prefixed `git:`.

- **No absolute path is published.** A report travels to CI logs and dashboards;
  a local directory layout has no business in one.
- **It is portable.** The same repository cloned on another machine, or checked
  out in CI, produces the same identity. A path could not.
- **A shallow clone reports its grafted root**, so a shallow and a full clone of
  one repository do *not* share an identity. They compare as incomparable rather
  than as equal — a false negative, which is the safe direction.

**The digest is not concealment.** A root commit is public for any repository the
reader can clone, so anyone holding the report can compute the same digest for a
candidate repository and confirm a match in one command. Treat `root` as a
**confirmable identifier**: it keeps a local directory layout out of the report,
and it does not hide which repository was scanned.

**It identifies an ancestry, not a repository and not a tree.** A fork shares its
upstream's root commit, so **a fork and its upstream produce the same `root`**
however far they have diverged. Equal `root` means "same ancestry" — never "same
repository", never "same content", never "same scan scope", and it is not
anonymisation.

Two same-ancestry forks may be compared **only when every other eligibility
condition also holds** — the same configuration, rule set, suppression state,
selection and completeness. `root` on its own establishes nothing. And a
comparison of such a pair still makes **no claim about renaming, resolution or
remediation**: a finding absent from the second report was not observed there,
which is not the same as fixed, moved, rotated or revoked.

The identity also depends on what is reachable from `HEAD`: an orphan branch
yields a different one, and merging an unrelated history adds a root and changes
it. Both fail in the safe direction — different rather than wrongly equal.

### `scopeDigest` identifies the selection, not the request

The modes examine different populations of one repository and never share an
identity: a working-tree scan and a history scan are different questions.

**A staged scan gets no scope identity at all, so a staged report is never
comparable.** That is a measured decision, not caution. A staged scan's
population is the *index*, which moves with `git add` and `git reset` rather than
with the file:

1. stage a file holding a secret, scan — the finding is reported;
2. unstage the byte-identical file, scan again — nothing is reported, while the
   secret is still in the working tree and a working-tree scan still finds it.

With a mode-only identity those two reports carried the same `scopeDigest`, the
same everything else, and both complete — so the pair was eligible and the second
report read as the finding being *gone*.

Tracking staged file selection could permit comparison when the selection remains
identical, including across content changes. This version keeps staged reports
ineligible pending an explicit staged-snapshot comparison contract.

What such a pair actually needs is a comparator that labels a staged report as a
**snapshot of the index** and refuses to read its absences as disappearances.
That is a comparator design, not a digest, and it does not exist. Until it does,
the identity is withheld — the same answer this contract gives to an
unidentifiable suppression state.

For **history** the digest covers **the commits that were actually read** —
reported by the parser that read them, not reconstructed from the range string
the caller passed in. That distinction is the whole point:

- **a range string is not a selection.** `--all`, `--no-merges`, `--full-history`
  and `-n` decide together what `git log` emits, and only the parser sees the
  result;
- **equal commit counts are not a selection either.** Two disjoint ranges of the
  same length produce the same count and the same scope sentence. That pair was
  demonstrably comparable before this field existed, and reported still-present
  secrets as gone.

**Equivalent selections compare equal.** Because the identity is the commit *set*,
`HEAD~1..HEAD`, an explicit SHA range naming the same commit, and
`--max-commits 1` on the same repository all produce the same `scopeDigest`. The
rev-range string and the commit cap are deliberately **not** in the digest: they
are the request, and two requests that read the same commits describe one scan.

**Different commit sets are incomparable — in this first version.** A commit
added since the earlier scan changes the set, so the pair is rejected rather than
having the new commit's findings reported as new. That is conservative and
deliberate: attributing a difference correctly across two different commit
populations is the job of a comparison this metadata does not yet support.

**A commit that produced no finding is still part of the selection.** The digest
covers every commit the parser read, not only the ones that yielded something, so
two different finding-free ranges do not collide.

**An empty selection is a real selection.** A range that matched no commit has a
determinate scope digest, distinct from every non-empty one. It is not the same
as an *unavailable* selection, which omits the key.

**A scan that stopped early reports neither.** If a history scan is cancelled,
what it read is a part of what was asked for: a truthful record of what was
parsed and a false record of what was selected. Such a run reports **no**
selection and marks its coverage incomplete, so it fails both the scope check and
the completeness check rather than describing a scan nobody ran.

**What it deliberately does not do.** It does not distinguish two working-tree
scans of the same repository taken at different moments, and must not: detecting
that the content changed is the *purpose* of a later comparison, and folding the
tree state or `HEAD` into the scope would make every pair incomparable and answer
nothing.

The representation is versioned inside the digest (`SCOPE_CONTRACT_VERSION`), so
changing what a scope means produces a different digest rather than a silently
comparable one.

### The digests carry no secret

`configDigest` covers the effective configuration — after the project file and
after any CLI flag — with one deliberate exception:

**`allowValues` content is never hashed.** A project may legitimately have
written a literal credential into its allowlist. A digest over a short, guessable
input is an oracle for confirming a guess, not anonymisation. The digest carries
the allowlist's **count**, so a change to its size is visible, and the
suppression rule below covers the rest.

`ruleSetDigest` covers each rule's pattern, flags, floors, allowlists and
severity — not its human description, so a wording fix does not make two scans
incomparable. Version alone would not be enough: a locally built binary can carry
a different rule set at the same version.

### `suppressionDigest` is withheld rather than guessed

It covers the configured exclusions: `excludePaths`, `generatedExcludePaths`,
`includePaths`, `excludeRules`, `includeFixtures`, `includeApiDocumentEntropy`,
`keyContextRequired` and `maxFileSizeBytes`.

It is **omitted entirely** whenever any of these was active:

| mechanism | why it cannot be identified |
|---|---|
| a non-empty `allowValues` | its content is never hashed, for the reason above |
| an applied baseline | its entries are value-derived fingerprints, and a digest of them would be a new secret-derived hash |
| inline `secretloop:allow` directives | they live in the scanned source. A **count** is not an identity — two scans can suppress the same number of findings in different places, and reading equal counts as equal suppression is exactly how a suppressed finding comes to look resolved |

`summary.coverage.suppression.unidentified` names every reason that applied.

The gate counts **effects, not presence**: a `secretloop:allow` that suppressed
nothing leaves the identity intact, because nothing was hidden from that scan. If
the same directive later suppresses a finding, that scan's count is non-zero and
its identity is withheld — so no pair in which anything was actually hidden can
be declared comparable. A configured `allowValues` entry or a supplied baseline
withholds the identity **even when it matched nothing**, because neither can be
shown to have had no effect without reading content this deliberately never
reads.

**Withholding only prevents anything if the comparator requires the field.** The
reviewed design's reference model requires just `toolVersion`, `root`,
`configDigest` and `ruleSetDigest` — under that model alone, a withheld
suppression identity changes nothing at all. The normative list below is what a
comparator must enforce; omission by the producer is one half of the contract,
not an enforcement mechanism on its own.

SecretLoop's own repository uses inline directives, so its reports carry no
suppression identity.

### `incomplete` covers the gaps, not the decisions

`incomplete` is true when the scan could not look at something it **set out to
look at**: a file over `maxFileSizeBytes`, a file it could not read, a path that
was not a regular file or had vanished, a symlink refused by the containment
guard, an archive it could not finish enumerating, a container it could not
open, or a run that was stopped.

Deliberate policy is **not** incompleteness. Generated-file exclusions, fixture
suppression, API-document scoping and configured `excludePaths` are decisions;
they are identified by `configDigest`, and a change to any of them already makes
a pair incomparable. Calling them "incomplete" too would say nothing.

**Binary input is a decision, not a gap.** A text scanner declining a
PNG is the same kind of fact as declining a generated file: it is disclosed, and
it does not make the report incomplete. Until version 3 it did — binary input
and "the read failed" shared one reason — so a single image made every report
from that tree permanently ineligible for comparison. Scanning SecretLoop's own
repository is the example: 17 files skipped, every one of them classified binary,
and the report said `incomplete: true`.

**A binary skip is still disclosed.** The scope sentence names it —
`N file(s) not scanned — binary` — because a reader must still know the scan did
not look. What changed is what the skip *means*, not whether it is reported.

#### What "binary" actually means here

The classifier tests exactly one thing: **does a NUL byte occur in the first
8,000 bytes.** That is the standard heuristic, and it is a probe rather than a
proof. Its boundary, stated precisely:

- **UTF-16 and UTF-32 text is classified binary.** Those encodings pad ASCII
  with NUL, so a UTF-16 file carrying a live credential is skipped as binary.
  Such a file would not scan usefully in any case — the reader is UTF-8 only and
  selects no decoder from a BOM or from content — so it is outside the supported
  scan scope either way.
- **Text carrying an embedded NUL is classified binary.** The file is still read
  in full — the classifier runs on bytes already in memory — but none of its
  content is *scanned*, before or after the NUL. In this repository
  `tests/verify-consent.test.ts` is a 47 KB TypeScript source carrying one NUL
  at offset 1867, so 96% of it goes unscanned.
- **A binary file whose first 8,000 bytes happen to carry no NUL is not
  classified binary.** It takes the text path and is scanned as text.

**A binary skip does not establish that the file contains no secret.** It
establishes only that the scanner did not look. That is precisely why the skip
remains disclosed in the scope sentence after ceasing to make the report
incomplete: `incomplete` now answers "did anything the scan intended to read
fail", and the scope sentence answers "what did it decline to read at all".
Reading a clean report without reading its scope sentence was never safe, and
this change does not make it safe.

**An inspection that FAILED is still a gap**, including for binary formats the
scanner does support. An archive whose parser declined it, and a file the
PKCS#12 prefilter admitted but could not conclusively inspect, both remain
coverage limitations.

`summary.coverage.limitations` lists the reasons in human-readable form.

## Required-field validation — what a comparator must enforce

**Omission by the producer is not an enforcement mechanism.** This page's
producer omits what it cannot determine; a comparator must still reject
everything else. Before comparing two reports it MUST check, for each of

    schemaVersion  toolVersion  root  configDigest  ruleSetDigest
    suppressionDigest  scopeDigest  incomplete

**All eight are required.** Per field:

| field | valid when | and |
|---|---|---|
| `schemaVersion` | an integer, and **exactly `3`** | equal in both |
| `toolVersion` | a non-empty string | equal in both |
| `root` | a non-empty string matching `git:<16 hex>` | equal in both |
| `configDigest` | a non-empty string of 16 hex characters | equal in both |
| `ruleSetDigest` | a non-empty string of 16 hex characters | equal in both |
| `suppressionDigest` | a non-empty string of 16 hex characters | equal in both |
| `scopeDigest` | a non-empty string matching `scope:<16 hex>` | equal in both |
| `incomplete` | a boolean | **`false` in BOTH reports** |

Reject when a field is **missing**, **null**, of the **wrong type**, **empty or
whitespace-only**, **malformed**, or **unsupported**.

**`incomplete` is not an equality check.** `true === true` must *not* permit
comparison: two scans that both failed to cover their scope are not thereby
comparable, they are both unreliable. The condition is `false` on both sides.

**Rejecting means every identity is demoted to incomparable**, with the reasons
listed — never that some findings are still reported as new or gone.

**A shared absence is still an absence.** Two reports that both omit `root`, both
set it to `null`, both set it to `""`, or both declare `schemaVersion: 99` are
**not** comparable. Equality is necessary and not sufficient; the field must be
determinate and valid first.

**A legacy seven-field report does not silently qualify.** A report written
against schema version 1 carries no `scopeDigest`, so nothing establishes which
population it examined. It is rejected twice over — on the missing field and on
the unsupported version — and never by accident.

The reference model shipped with the frozen design (`D/model_compare.py`)
implements only the *present-and-equal* half over four fields, and measured
against the table above it accepts `null`, a wrong type, an empty string, an
unrecognised `schemaVersion`, a missing `suppressionDigest` and a missing
`scopeDigest`. **That gap is in the model, not in this producer** — but the
producer cannot close it, which is why the list is normative here.

## Descriptive fields

`summary.coverage` is descriptive only. It explains `incomplete`; it does not
decide it, and **two equal coverage blocks do not make two scans comparable**.
Nothing in it may be used as an identity — least of all `inlineSuppressed`, for
the reason in the table above.

## Compatibility

- **Additive.** Every pre-existing field keeps its name, position and meaning.
  No consumer that reads `tool`, `summary` or `findings` needs to change.
- **Older reports stay readable.** A report produced before this metadata
  existed parses exactly as it always did. It is simply **ineligible for
  comparison**, because the fields a comparison requires are absent — and absent
  means unknown.
- **A report from a caller that supplies no metadata** — the editor's text
  report, or any embedder calling `render()` directly — carries no metadata keys
  at all, rather than empty ones.
- **SARIF and the text report are unchanged.** So is the baseline file format,
  which this does not touch and never silently migrates.

## Known limitations

**Metadata alone does not establish that two scans are comparable.** It
establishes that they *may* be compared: same tool, rules, configuration,
suppression state, ancestry and selection, with both scans complete. Whether the
difference between two eligible reports *means* anything is a separate judgement
this metadata does not make.

**Two working-tree scans of one repository are not distinguished by time or
content.** That is deliberate — see `scopeDigest` above. Two scans taken months
apart are eligible, which is exactly what a change comparison needs.

**A history comparison is all-or-nothing in this version.** Any difference in the
selected commit set makes the pair incomparable, so the common workflow of
"scan the last 50 commits, then scan again next week" does not compare. Reporting
a difference correctly across two different commit populations needs attribution
this contract does not yet carry.

**Staged reports are never comparable.** They carry no scope identity, for the
reason set out under `scopeDigest` above. Making them comparable requires a
comparator that treats a staged report as an index snapshot and labels its
absences accordingly; that design does not exist, and until it does the contract
declines rather than guesses.

**`root` is shared ancestry only.** A fork and its upstream share it. Eligibility
still requires every other field to match, but nothing here distinguishes a fork
from the repository it came from.

**No claim is made about renaming, resolution or remediation.** Absence from a
later report means it was not observed there. It never means fixed, moved,
rotated or revoked.

**A binary exclusion can turn a found secret into an eligible absence — the
contract is not yet safe against this, and the correction is proposed below.**

Scan a UTF-8 file holding a credential: it is found, and the report is complete.
Insert one NUL byte anywhere in the first 8,000 bytes **without touching the
credential** and scan again. The file is now classified binary, so the finding
disappears; and because a binary exclusion no longer counts toward `incomplete`,
the second report still says `incomplete: false`. All eight required fields are
equal across the pair, so the pair is **eligible**, and a consumer would read
the credential as *gone* while it sits on disk unchanged. Under schema 2 the
second report was `incomplete: true` and the pair was correctly incomparable.

Two things that do **not** fix it:

- **A prose warning.** `summary.scope` is the only place the exclusion appears,
  and a consumer must never parse the scope sentence to decide eligibility.
- **Equal binary-skip counts.** A count is not an identity: one file entering
  the binary set while another leaves it keeps the count equal and hides exactly
  the substitution that matters. The count is also not machine-readable today.

**Proposed correction — not implemented.** Add a ninth comparison-bearing field,
`binaryDigest`, over the **sorted set of paths excluded as binary**, following
the rules the other identities already follow: absent means unknown, and it must
be **present, valid and equal in both** reports. Then the pair above becomes
incomparable because the set changed from empty to one path, while two scans
that exclude the same images still compare — which is the benefit this change
exists to deliver. Because it adds a required field, it would move
`schemaVersion` to **4**.

Until that exists, **treat any report disclosing a binary exclusion as
ineligible.** That is the conservative reading, and it restores the schema-2
safety property without putting binary input back into `incomplete`.

**A supported keystore whose inspection failed cannot be named as such.**
`detectPkcs12Bytes` returns nothing both for a well-formed PKCS#12 carrying no
plaintext key bag — a successful inspection that found nothing — and for one its
structural walk declined. The two are indistinguishable at the source, and the
header prefilter only asserts "outer DER SEQUENCE spanning the file", which many
DER objects satisfy without being keystores. So any file the prefilter admits
that yields no finding is treated **conservatively**: it keeps the
`could not be read` reason and still makes the report incomplete. That is
deliberately cautious — a plain DER certificate is reported the same way — and
naming the case precisely needs a detector that reports *why* it declined, which
is a parser change and is **not implemented here**.

**Archive member refusals are still aggregated.** A member refused as `binary`
is counted alongside members refused as `encrypted` or `malformed` in one
`N archive member(s) not scanned` clause, so a container holding only binary
members still reports incomplete. Separating them would change the archive
accounting's aggregate counts, which is a larger change than this one and is
**not implemented here**.

**Identifying suppression content is unresolved.** Making a baselined,
allowlisted or inline-suppressed project comparable needs a way to identify those
suppressions that does not publish a new secret-derived hash. No such scheme is
adopted here; the safe half — withholding the identity — is what ships.

**No comparison output exists.** Nothing here reports a finding as new,
persisting or gone, and nothing here claims a finding was resolved. "No longer
observed" will never mean revoked, safe, rotated or fixed.
