# The JSON report — schema, identities and what they do not establish

`--format json` produces a machine-readable report. Alongside the findings it
carries **comparison metadata**: identities that let a comparing tool decide
whether two reports may be compared at all.

`secretloop compare` reads two such reports and enforces that metadata. It is
implemented and documented under [The comparator](#the-comparator) below, and it
admits **working-tree reports only**: a history or staged report is refused, not
compared.

**Status: shipped in 0.6.0.** npm, Open VSX and the VS Code Marketplace all serve
**0.6.0**. This metadata and the `compare` command are **new in 0.6.0**: 0.5.1
emits no comparison metadata and has no `compare` command, so nothing on this page
describes what 0.5.1 does. The `toolVersion` value in the example below is
illustrative, not a claim about which release carries these fields.

## Shape

```jsonc
{
  "tool": "secretloop",

  // Comparison-bearing. See the rule below: an absent key means UNKNOWN.
  "schemaVersion": 4,
  "toolVersion": "0.5.1",
  "root": "git:af829fc833133fca",
  "configDigest": "3071344b11905ec5",
  "ruleSetDigest": "c6f8fdd1265654d9",
  "suppressionDigest": "9b1c…",     // omitted when suppression cannot be identified
  // omitted for a staged scan, when the selection cannot be established,
  // and when a history scan was interrupted
  "scopeDigest": "scope:4a9f5bca…",
  // the set of files excluded as binary. An EMPTY set is a real identity;
  // omitted when the producer cannot establish the set at all (history)
  "binaryDigest": "binary:3fd006a9…",
  "incomplete": false,

  "summary": {
    "total": 0,
    "scope": "…",                    // the prose sentence, unchanged
    "scannedCount": 0,
    "scopeNoun": "file",
    "coverage": {                    // DESCRIPTIVE, not comparison-bearing
      "limitations": [],
      // Unreleased: per-descriptor check accounting for the readers this scan
      // ran (see coverage.md, "Opened-file checks"); absent for a history scan
      "openedFileChecks": {
        "opened": 6,
        "identity":   { "verified": 6, "refused": 0, "unavailable": 0, "failed": 0, "notReached": 0 },
        "kernelPath": { "verified": 0, "refused": 0, "unavailable": 6, "failed": 0, "notReached": 0 }
      },
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
| `binaryDigest` | **which files were excluded as binary** | the producer cannot observe its own exclusion events (a `history` scan), or the scan stopped early |
| `incomplete` | the scan could not cover what it set out to | never |

`schemaVersion` is bumped when the **meaning** of one of these changes — what a
digest covers, what `incomplete` counts, or the set of required fields. Adding a
descriptive field does not bump it. **It is `4`**:

- version 1 had no `scopeDigest`, so a version-1 report cannot be shown to have
  examined any particular population;
- version 2 counted **binary input as a coverage failure**, so its
  `incomplete: true` may describe nothing worse than a PNG;
- version 3 stopped counting it, and thereby allowed a file to cross **into**
  the binary set between two scans while every comparison field stayed equal —
  so a still-present credential could read as removed;
- version 4 adds **`binaryDigest`**, making the excluded set part of
  eligibility, which closes that.

**Versions 1, 2 and 3 are unsupported by this contract.** A consumer
implementing it accepts `4` and rejects everything else. The boolean fields
still type-check under every version, so nothing but the version number stops
reports written against different meanings from comparing as though they agreed.

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

**Equivalent selections produce equal digests.** Because the identity is the
commit *set*, `HEAD~1..HEAD`, an explicit SHA range naming the same commit, and
`--max-commits 1` on the same repository all produce the same `scopeDigest`. The
rev-range string and the commit cap are deliberately **not** in the digest: they
are the request, and two requests that read the same commits describe one scan.

**Equal digests are not eligibility.** This section says what a history digest
*means* — which selections would be the same selection. It does not say such a
pair may be compared, and an earlier wording here implied it did. The shipped
comparator refuses **every** history report as an unsupported scope, identical
selection included — see [Known limitations](#known-limitations).

Two different commit sets do also produce two different digests, but that is the
lesser reason, and in practice it is never even reached: the scope refusal is
raised per side first, and a field already refused is excluded from the
cross-report equality pass, so two history `scopeDigest` values are never
compared with each other at all.

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
open, or a run that was stopped. **Unreleased:** also a file whose opened
descriptor was not the object just inspected (`replaced`), or whose
kernel-recorded location was outside the root at the check before its first
read (`outside`), or whose check evidence could not be obtained (`unreadable`).
These add causes without changing what the boolean means, in the conservative
direction — a report that would once have read a substituted object and said
`incomplete: false` now says `true` — so `REPORT_SCHEMA_VERSION` stays 4. A
check that was **unavailable** on the platform is disclosed in
`summary.coverage.openedFileChecks` and does **not** make the report incomplete.

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
    suppressionDigest  scopeDigest  binaryDigest  incomplete

**All nine are required.** Per field:

| field | valid when | and |
|---|---|---|
| `schemaVersion` | an integer, and **exactly `4`** | equal in both |
| `toolVersion` | a non-empty string | equal in both |
| `root` | a non-empty string matching `git:<16 hex>` | equal in both |
| `configDigest` | a non-empty string of 16 hex characters | equal in both |
| `ruleSetDigest` | a non-empty string of 16 hex characters | equal in both |
| `suppressionDigest` | a non-empty string of 16 hex characters | equal in both |
| `scopeDigest` | a non-empty string matching `scope:<16 hex>` | equal in both |
| `binaryDigest` | a non-empty string matching `binary:<16 hex>` | equal in both |
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
the unsupported version — and never by accident. A version-3 report is rejected
the same way: it carries no `binaryDigest`, so nothing establishes which files
it declined to look at.

### What an eligible pair does and does not establish

A pair that passes all nine checks may be compared **only over the scanned scope
the two reports share**. Specifically:

- **"No longer observed" never means removed, fixed, rotated or revoked.** It
  means the later scan did not see it. Nothing in this contract can distinguish
  a deleted credential from one that moved, was renamed, or stopped being
  scanned for a reason the metadata does not capture.
- **Excluded files may still contain credentials.** An unchanged `binaryDigest`
  says the same *set of paths* was excluded from both scans. It says **nothing
  about their contents**. Those bytes were **read but never scanned**: the
  classifier tests a buffer the read already filled and then discards it, so no
  rule ever sees the content. "Not read" would be wrong; "not scanned" is the
  fact, and either way the contents may have changed completely between the two
  scans. A credential can be added to an excluded file and no comparison will
  ever see it.
- **Staged reports remain ineligible.** They carry no `scopeDigest`, and that is
  unchanged here.
- **Ambiguous archive and keystore cases remain conservative.** A container the
  parser declined, and a file the PKCS#12 prefilter admitted but could not
  conclusively inspect, are still coverage limitations, so such reports are
  ineligible on `incomplete` before `binaryDigest` is ever consulted. Archive
  members refused as binary are counted in the archive accounting, not in
  `binaryDigest`.
- **A `history` report carries no `binaryDigest` at all** and is therefore
  ineligible under this contract. A history scan reads blobs and emits no
  file-level exclusion events, so it cannot establish the set. Claiming the
  empty set there would be metadata invented for a mode that never produced it.

**The paths `binaryDigest` accepts.** A canonical, repository-relative,
`/`-separated path, exactly as the enumeration produces it. A leading `./` is
stripped and duplicates collapse; nothing else is rewritten.

- **Where native separators are converted.** At the enumeration, not here. The
  directory walk emits `path.relative(root, file).split(path.sep).join("/")`, so
  a Windows producer's `\` **separators** become `/` at the one place where the
  originating path semantics are known, and `git ls-files` emits `/` on every
  platform. No separator reaches the digest as a `\`.
- **A literal backslash still reaches it, and legitimately.** On POSIX `\` is an
  ordinary filename character and `path.sep` is `/`, so that same conversion
  correctly leaves a backslash that is part of a **name** alone: the fallback
  directory walk really does emit `dir\file.png` for a file called that. Such a
  filename is valid on POSIX. It is this *representation* that cannot express
  it, because the representation uses `/` as its separator and has no escape for
  a literal one.
- **So it is refused, never reinterpreted.** Rewriting `\` to `/` mapped a real
  file named `dir\file.png` onto the unrelated real path `dir/file.png` and gave
  two different exclusion sets one identity. Refusal is not a claim that such a
  path cannot arrive — it is the only answer available when a valid filename
  falls outside what the identity can encode.
- **Non-canonical spellings are refused** — a `.` or `..` segment, a repeated
  separator, a trailing separator — because one file would otherwise get two
  identities depending on how it was spelled. Absolute, drive (`C:/…`) and UNC
  paths are refused as before.
- **Case and Unicode are left alone.** Distinct case-sensitive filenames stay
  distinct, and NFC and NFD spellings are different names: normalizing either
  would decide a filesystem question this contract cannot answer.
- **Refusal withholds the WHOLE digest.** One unrepresentable path means no
  `binaryDigest` at all. The path is never dropped so the rest can be hashed,
  and the empty-set digest is never substituted — the first would publish a
  confident identity for a subset, the second would claim nothing was excluded.
  A withheld digest makes the pair ineligible, which is the safe direction.

**What the git route does, and what it is not.** `git ls-files` C-quotes a path
containing a backslash (`"dir\\file.png"`) whatever `core.quotePath` is set to, so
the git-backed enumeration is handed a path that does not exist, the containment
guard refuses it, and that refusal is already a coverage limitation making the
report `incomplete`. **This is a formatting behaviour of one producer, not a
containment guarantee**, and nothing in the identity may depend on it: the
fallback directory walk, used when `git ls-files` cannot answer, has no such
behaviour and forwards the real name. That is the route where the identity had
to stop collapsing.

**The representation is versioned inside the digest** (`BINARY_CONTRACT_VERSION`),
like the scope contract. It moved **1 → 2** when backslash rewriting was removed,
because a version-1 report and a version-2 report of *different* trees could
otherwise carry the same digest and compare as though their exclusion sets
matched. Every digest therefore changed: a report written before that change is
incomparable with one written after, **even for an unchanged tree**, and the
comparator reports `identity-mismatch (binaryDigest)`. That is the intended
cost — an ineligible pair says nothing, while a silently equal one says
something false. It does **not** repair reports two version-1 builds already
wrote: those still compare with each other and still carry the collapsed
identity.

**`binaryDigest` is not anonymisation.** It hashes a set of repository-relative
paths, and repository paths are often predictable — `docs/icon.png`,
`assets/logo.gif`. Anyone holding a candidate list can test guesses against the
digest exactly as they can against `root`. It publishes no file content, no
credential and no absolute path, but it is a comparison identity, not
concealment, and nothing here should be read as hiding which files were
excluded.

### The comparator

`secretloop compare <before.json> <after.json>` enforces every rule above. It
reads two saved reports and nothing else: it never rescans, never verifies
liveness, never contacts a provider and never writes to a scanned file.

**The read is bounded by the descriptor, not by the name.** Each report is
opened once; the opened object is inspected with `fstat` and every byte is read
from that same descriptor, with the byte cap enforced **while reading** rather
than only before it. At most one chunk is ever read past the cap, which is what
lets "exactly the limit" and "one byte over" be told apart, and an oversized
report is rejected **before parsing**. The descriptor is closed on every path,
including failures. An initial size check remains, but only as an optimization
that avoids reading an already-huge file — it is not the guard.

This means a file that grows, or a path that is replaced, after inspection
cannot cause an unbounded read. It does **not** mean the comparator holds an
immutable or authenticated snapshot: another process writing to the same file
can still change what a *later* run sees, and nothing here proves the bytes read
came from the scan they claim to describe.

Exit codes distinguish the three outcomes that must never be confused:

| code | meaning |
|---|---|
| `0` | compared, and nothing is new |
| `1` | compared, and there are new findings |
| `2` | unusable input — missing argument, unreadable file, malformed JSON |
| `3` | **not comparable** — the input was fine and the contract refused |

`3` exists because folding a refusal into `0` would make "these reports cannot
be compared" and "nothing changed" the same signal. For an ineligible pair the
JSON output carries **no difference keys at all**, not even empty ones.

**How working-tree scope is enforced.** The comparator admits working-tree
reports only, and it **validates that positively**: each report's `scopeDigest`
must equal the identity the shared `scopeIdentity({ mode: "worktree" })`
produces. Presence of the nine fields is not enough, and neither is the two
reports agreeing with each other — two history scans over the same commits carry
equal, well-formed scope digests, and equality alone would have admitted them.

The expected value is taken from the **same function the producer uses**, never
written out as a constant. The scope contract version is hashed inside that
function's input, so a report written under a different `SCOPE_CONTRACT_VERSION`
stops matching automatically rather than comparing silently, and the check
cannot drift from the producer.

Consequently a `history` report **cannot** be made eligible by supplying the one
field it lacks: its scope digest still says history, and it is rejected as an
unsupported scope. A `staged` report given a plausible-looking scope identity is
rejected the same way. Nothing is inferred from a field being absent, and
nothing is read from the prose scope sentence.

**What this does not do: it is not authentication.** A report carries no
signature and no provenance, so every identity checked here is a value its
producer put in the file. Anyone who can write a file can write one that
satisfies every rule above, including the supported scope digest. Passing these
checks means "these two reports are internally consistent and declare compatible
scans" — never "these scans really happened and really covered what they claim".
That is the right boundary for metadata designed to prevent *accidental*
mis-comparison, but a caller comparing reports from an untrusted source is
trusting that source, not this contract.

**No report-supplied free text is ever printed.** A report is untrusted input,
so the comparator builds its output from fields of fixed, closed shape only:

Each column below says what **bounds** the field — a closed shape or a closed
vocabulary. A bounded field is not a field proven to carry no secret; that
distinction is the point of the paragraph after the table.

| shown | what bounds it |
|---|---|
| `ruleId` | taken from the fingerprint and required to be **one of the rule ids this build emits** — membership, not merely grammar |
| `digest` | the 16-hex tail of the fingerprint — fixed shape, and a verbatim substring of the identity already in the report |
| `line` | a number |
| `severity` | admitted only from the scanner's own set |

**The scanned path is deliberately not shown, and neither is the raw
fingerprint.** A path is arbitrary text, and **no format check can establish
that arbitrary text contains no secret** — a credential-shaped path passes every
pattern a display filter could apply. Rather than claim otherwise, the
comparator does not print it. Such a path is **accepted internally**: it matches
normally, is never rejected for its contents, and simply never reaches output.
It is not detected, and nothing here claims it was.

**A rule id must be a member of the supported set, not merely grammatical.** The
set is derived from the existing authorities — every rule in `src/rules.ts`, plus
the generic entropy tier and the structural keystore detector — so there is no
second list to drift. A grammar check alone accepts any lowercase alphanumeric
run and is not a vocabulary; relying on one let an arbitrary string in a
fingerprint's rule segment be printed. A finding naming an unsupported rule now
**rejects the whole comparison**, under the same policy as any other unusable
identity: no partial results, and the id itself is never echoed.

Constraining these fields bounds **what can be echoed**. It is not a proof about
content, and validating metadata does not authenticate a report. `value` and `redactedValue` are never emitted
either; a field named "redacted" is a claim by the input, not a fact, and the
report's own `file` and `ruleId` fields are ignored entirely in favour of the
identity that was actually matched on.

To locate a finding, look up its `ruleId` and `digest` in whichever report you
already hold. Neither value is new — the digest is a substring of the fingerprint
the report already carries — and **no new secret-derived identifier is
computed**; nothing is hashed here.

**The displayed pair narrows the search; it does not uniquely identify a
finding.** The digest covers the matched *value*, not the path, so the same
credential found by the same rule in two different files produces the **same**
`ruleId` and `digest` while being two distinct identities. Matching is unaffected
— it uses the full raw fingerprint, so those two remain separate results — but
the output cannot tell you which file each one came from, and a lookup may return
more than one row.

**Matching is unaffected.** Eligibility and matching use the **full raw
fingerprint**, exactly as it appears in the report. It is never sanitized,
truncated or normalised before matching — that would change which findings pair
up. Presentation is a separate step that discards rather than rewrites.

A finding whose identity cannot be parsed against the full structure
(`<path>:<ruleId>:<16 hex>`) is **never silently dropped**: it rejects the whole
comparison, which is reported as `malformed-finding-identity`.

Validation errors name the field at fault and never quote its value.

**Two different kinds of ambiguity, reported separately.**

- **A shared displayed reference** is several *distinct* findings that print the
  same `ruleId` and `digest`. They were told apart correctly and counted
  separately; only the printed pair collides. The output says so explicitly —
  that more than one distinct finding is shown under that reference, that
  scanned paths are omitted on purpose, and that looking the pair up in the
  original report may return more than one match. In JSON this is the additive
  `sharedDisplayReferences` array, each entry carrying `ruleId`, `digest` and
  `distinctIdentities` — a count, never an identifier, with no path, no
  fingerprint and nothing newly hashed.
- **An ambiguous identity** is *one* finding seen several times, reported in
  `ambiguousIdentity` with its before and after counts.

They are never merged: the first is a display collision over findings the
comparator has already distinguished, the second a count it refuses to
interpret.

`sharedDisplayReferences` is **additive**. No existing field changed meaning,
and it is unrelated to `schemaVersion`, which versions the input scan reports
rather than this tool's own output.

**Invalid findings are collected from both reports, within a bound.** A refusal
lists every invalid finding it can, from **both** sides, identified by side and
array index with a stable reason code and a cause — "has no usable fingerprint"
or "names a rule this build does not support". The rejected value, path,
fingerprint and rule id are never quoted.

Each side has its **own** diagnostic budget, so a report full of errors cannot
fill the allowance and hide every error in the other. Every finding is still
inspected, so a stated total is exact; when more errors exist than are listed, a
`diagnostics-truncated` reason says how many in total and how many were omitted.
The comparison is still refused as a whole, with **no partial differences**,
exit 3, and the same top-level keys `tool`, `comparable` and `reasons`.

The budget is **10 detailed diagnostics per report**, and **each** side that
exceeds it gets its own `diagnostics-truncated` note. The cap bounds how much
detail is *printed*, not how much is *examined*: every finding within the
existing input limits — the report byte cap and the findings-array cap — is
inspected, which is why a stated total is exact rather than a lower bound.

The trade-off is deliberate rather than measured: a larger number would describe
more errors per run, a smaller one would keep refusals terser, and 10 is a
judgement about what stays readable while still showing a useful batch. Nothing
here claims it is an optimal value.

**A diagnostic's array index is a position, not an identity.** `findings[3]`
means the fourth element of *that* input array, zero-based. It is not a stable
identifier: the same index in the other report, or in the same report after an
edit, is a different finding.

**Metadata rejection can stop inspection before any finding is read.**
Eligibility is decided first, so a pair refused on its metadata carries no
finding diagnostics at all — not because its findings are valid, but because
they were never examined.

**Duplicate identities are reported, not resolved.** A fingerprint covers
(path, rule, value) and deliberately not the line, so one credential repeated in
a file is several findings under one identity. The comparator counts occurrences
and reports any fingerprint seen more than once as an explicit ambiguity; it
does not claim what a count change meant, because the identity cannot support
that distinction.

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

`summary.coverage.openedFileChecks` (**Unreleased**) is descriptive in the same
way. Two complete reports whose blocks differ — one scanned on Linux with the
kernel-path check verified, one on macOS with it unavailable — remain
comparable, exactly as every report written before the block existed compares
today; the difference is visible in each report and is not an identity. A
check **refusal** makes the report `incomplete` and therefore ineligible,
because the scan did not cover that file. The comparator reads nothing from
this block.

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

**History reports are never comparable in this version — not even for an
identical selection.** The comparator admits working-tree reports only and
validates that positively, so a history report is refused as an unsupported scope
however its commit set compares. Two history scans over exactly the same commits
carry equal, well-formed `scopeDigest` values, and **equality alone does not
establish eligibility**: the digest says which population was examined, not that
the population is one this contract supports. A history report also carries no
`binaryDigest` at all, so it is refused twice over.

Admitting history would need both a supported history scope and attribution
across two commit populations, and neither exists here. So the workflow of "scan
the last 50 commits, then scan again next week" does not compare — and neither
does re-scanning exactly the same commits.

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

**A binary exclusion could turn a found secret into an eligible absence — fixed
in schema 4 by `binaryDigest`.**

Under schema 3: scan a UTF-8 file holding a credential, then insert one NUL byte
anywhere in the first 8,000 bytes **without touching the credential**. The file
is now classified binary, the finding disappears, and — because a binary
exclusion no longer counts toward `incomplete` — the second report still said
`incomplete: false`. All eight required fields were equal, so the pair was
**eligible** and a consumer would have read the credential as *gone* while it
sat on disk unchanged.

`binaryDigest` closes this: the excluded set changed from empty to one path, so
the two digests differ and the pair is incomparable. Two scans that exclude the
same images still compare, which is the benefit the schema-3 change exists to
deliver.

Two things that would **not** have fixed it, and are not relied on:

- **A prose warning.** `summary.scope` is prose, and a consumer must never parse
  it to decide eligibility.
- **Equal binary-skip counts.** A count is not an identity: one file entering
  the binary set while another leaves it keeps the count equal and hides exactly
  the substitution that matters. `binaryDigest` covers the *set of paths*, so
  that substitution changes it.

What remains true, and is not a defect this field can fix: an unchanged
`binaryDigest` says the same paths were excluded, **not** that their contents
are unchanged. See [What an eligible pair does and does not
establish](#what-an-eligible-pair-does-and-does-not-establish).

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

**A comparison output exists; a resolution claim does not.** `compare` reports
findings as new, persisting or no longer observed — that is what it is for — and
not one of those words is a claim about the credential. **"No longer observed"
means the later report does not contain it**, and never that it was resolved,
removed, revoked, rotated, fixed or made safe. Nothing in this contract can
distinguish a deleted credential from one that moved, was renamed, or stopped
being scanned for a reason the metadata does not capture.
