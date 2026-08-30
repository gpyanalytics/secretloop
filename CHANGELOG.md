# Changelog

## 0.1.2 — unreleased

One safety fix, one precision pass, and remediation guidance on the surfaces
that had none. No rule IDs, thresholds or fingerprints changed, so existing
baselines keep matching. The only output change is additive: SARIF results gain
a `properties.remediation` field.

### Fixed — fixture-path suppression could hide a real credential

0.1.1 stopped reporting *generic-tier* findings in test, fixture and example
paths. "Generic tier" was `generic-high-entropy` **or** `genericRuleIds`, and
that set's single member is `generic-api-key-assignment` — a `high` severity
`format-match`, and the only rule covering providers with no named format. So
`api_key = "…"` in a test file was hidden at default settings, in the place
credentials most often leak.

It was worse than one hidden rule. Suppression runs inside `scanText`, and
verification runs afterwards over what `scanText` returned, so a
**verified-live** credential in a fixture path had no path by which it could
ever report.

The two policies had been fused only because `generic: true` was introduced for
overlap tiebreaking and then reused for suppression. They are separate now:
suppression covers the entropy pass alone. **Suppress the guess, never the
certainty.**

This surfaces findings that were previously hidden, and on a repository that
keeps credentials in fixtures that is a large number. bugsnag-js gains 64
working-tree and 84 history `generic-api-key-assignment` findings — 9 and 23
distinct values, mostly one test API key repeated across fixture JSON. They were
always in those files; 0.1.1 was not showing them. That is the fix working, not
a regression. bugsnag-cocoa gains one, because its suite lives in `Tests/` and
the path match is case-sensitive — see below.

Known and unchanged: the fixture-path match is case-sensitive, so `Tests/` is
not recognised where `tests/` is. Recorded in the code rather than fixed here,
because making it case-insensitive *widens* suppression and this release
narrows it. It is safe to do later precisely because of the split above.

### Fewer findings — the entropy tier skips structured text

Entropy false positives are not random: they are structured text that happens
to score well. Each matcher below is paired with an assertion that real
credentials still report through it.

- **Mangled and plain C/ObjC symbols.** A crash report is a symbol table.
- **Source filenames and `#import` targets** — a closed extension list, so a
  high-entropy value ending `.pem` or `.key` still reports.
- **Absolute paths with doubled slashes or `+` segments** — dyld image paths.
  Not a new filter; the existing one could not match an empty segment or a `+`.
- **Dotted identifier chains** — reverse-DNS bundle ids, build products,
  `process.env.X`, `this.foo.Bar` — **only when every segment is itself
  low-entropy.** A JWT is three dot-separated base64url segments, so the shape
  alone would have skipped 56.96% of them; the segment condition takes that to
  0.0000%.
- **Whole `NAME=value` build settings**, keyed on an `=` that is not base64
  padding.
- **Module specifiers, by syntactic position** — the operand of `from`,
  `require`, `import` or `declare module`. Position rather than shape, because
  a shape-based rule for these costs 1.802% of random keys, and because
  `const token = "ghp_…"` is not an import whatever the value looks like.
- **Xcode `.xcscheme` files join the generated group.** Their noise is
  build-target names, which are bare identifiers and cannot be matched by shape
  safely.

There is deliberately **no bare-identifier matcher**. Every predicate that would
clear the remaining ObjC-constant noise skips 100% of AWS access key ids or
`ghp_` tokens — `AKIAIOSFODNN7EXAMPLE` is SCREAMING_SNAKE_CASE. That noise stays
visible on purpose, and the reasoning sits beside the code.

Measured on both checkouts with `--fail-on never`, split by tier because the two
halves of this release move in opposite directions: the entropy tier is the
precision work, and the format-match column is the safety fix surfacing findings
0.1.1 hid.

| corpus | entropy | format-match | total |
|---|---|---|---|
| bugsnag-js working tree | 4 → **0** | 0 → **64** | 4 → 64 |
| bugsnag-js history | 26 → **19** | 2 → **86** | 28 → 105 |
| bugsnag-cocoa working tree | 132 → **0** | 1 → 1 | 133 → 1 |
| bugsnag-cocoa history | 196 → **23** | 3 → **6** | 199 → 29 |

A rising total is the expected result on a repository that keeps credentials in
fixtures. Read the entropy column for the noise reduction and the format-match
column for what was being hidden.

Every specific-rule finding, and the `high` API key in bugsnag-cocoa's
`BugsnagEvent1.json`, still reports. Fingerprints are unchanged for all 48
findings present in both the 0.1.1 and 0.1.2 scans.

### Remediation guidance

A finding now says what to do about it. Previously only the editor knew — the
CLI, JSON and SARIF surfaces reported a credential and suggested nothing, which
is the half of "detect, verify, remediate" that CI actually reads.

- **The text report and SARIF carry guidance** on a genuine finding: remove the
  credential from source and load it from an environment variable instead. In
  SARIF it is per result, in `properties.remediation`; rule metadata is
  untouched, so nothing about a rule changes with the files a scan covered.
- **VS Code offers the matching quick-fix** where it applies — *Move to `.env`
  and reference it*, alongside redact and, for a credential that verified live,
  rotate. **The `.env` write happens only when you invoke that quick-fix.**
  Nothing is written automatically, and a scan never writes anything.
- **Fixture findings still report, and carry no relocation advice.** Now that
  format-match findings in test paths are visible, telling someone to move
  `YOUR_BROWSER_API_KEY` out of a fixture and into `.env` would be wrong advice
  — so the finding appears without it, and the editor withholds only that one
  action there. Redact and rotate stay available, because a credential that is
  genuinely live in a test file is the most dangerous thing this tool finds.
- JSON is unchanged.

## 0.1.1

Precision and honesty, plus four narrowly-scoped detection fixes found by
benchmarking against gitleaks and TruffleHog. Every other rule, rule ID and
threshold is unchanged.

### Fewer findings
- **Generated files are skipped by default** — lockfiles (`*.lock`, including
  CocoaPods `Podfile.lock`), Gradle and Maven wrappers, Xcode project files and
  SARIF reports. Scan them anyway with `--include-generated`, which bypasses
  this group only: `node_modules`, `package-lock.json` and minified bundles are
  never scanned, as before. On the benchmark's real-noise corpus this removed
  408 of 855 history findings.
- **URLs and file paths no longer look like secrets.** The entropy pass already
  skipped bare URLs and absolute paths; it now also skips protocol-relative
  URLs (`//cdn.example.com/…`) and relative paths
  (`../node_modules/react-native/…`). A further 148 history findings. Genuine
  high-entropy values are unaffected, including base64 containing slashes.
- **Repeated values are reported once.** One credential copied into forty files
  is one thing to rotate, so the text report groups occurrences of the same
  value into a single entry listing every location. Counts, JSON and SARIF are
  unchanged — one result per occurrence, every fingerprint intact — so existing
  baselines and dashboards are unaffected.

On the real-noise corpus: history 855 → 299 findings (82 grouped entries);
working tree 239 → 150 findings (30 grouped entries).

### Detection

Four fixes, each found by benchmarking against gitleaks 8.30.1 and TruffleHog
3.97.1 on a labelled corpus of 60 planted credentials and 120 decoys. The
benchmark ships as `bench/` — `npm run bench` reproduces every number below.

- **Passwords containing punctuation are now detected.** The generic
  assignment rule's capture class allowed only `A-Za-z0-9_-/+=.`, so
  `password = "p4ss!w@rd#value"` was invisible to the one rule whose keyword
  list names passwords twice. Measured in isolation: 10 of 10 detected when the
  passwords were alphanumeric, 2 of 10 once punctuation was added.
- **`key := "value"` is now detected.** The separator pattern consumed a single
  character, so Go's short variable declaration left the `=` unmatched and the
  rule did not fire — measured at 0 of 10 against 10 of 10 for the `=` form. All
  103 rules were audited rather than the two the benchmark happened to plant;
  22 shared the defect and all 22 are fixed. The entropy pass had been covering
  it, so this only ever affected people who turned the entropy pass off, which
  is what the example config recommends for a noisy codebase.
- **The jwt.io demo token is recognised as a documentation sample.** The token
  every JWT tutorial pastes was reported as a credential. It is matched on its
  payload — the `John Doe` demo claims — so changing the algorithm in the header
  does not defeat it.
- **Hashed bundle filenames no longer look like secrets.** `main.<hash>.chunk.js`
  slipped past the filter written to catch exactly that shape, because the
  filter's stem could not contain a dot.
- **AWS's published documentation secret key is recognised as a sample.** The
  counterpart to `AKIAIOSFODNN7EXAMPLE`, which was already caught by the
  `EXAMPLE` pattern. This one carries no such marker, so it is matched
  literally. It had never been recognised -- the entropy pass's relative-path
  filter was dropping it by accident, because the value contains two slashes and no `+`
  or `=`, and narrowing that filter uncovered it. Both tiers drop it: the
  `aws-secret-key` rule reads the same shared list the entropy pass does, so
  the sample is not merely demoted from one tier to the other.

Measured on the benchmark corpus, working tree, before → after:

| tier | precision | recall |
|---|---|---|
| default (entropy on) | 0.768 → 1.000 | 0.860 → 1.000 |
| named rules only | 0.808 → 1.000 | 0.840 → 1.000 |

Every planted credential is now found, and no decoy is reported.

The same corpus measures the two entropy-pass changes further down this
release. On 185 KLOC of real code with no known secrets, the false-positive
count went 150 → 151 across the four fixes above -- one code expression in a
test fixture, from the widened password class -- and then 151 → 4 (0.022 per
KLOC) once findings in fixture paths were suppressed and the relative-path
filter was narrowed.

Narrowing that filter is what exposed the AWS sample: it had been eating
23.18% of random 40-character base64 keys, real ones included, and the
documentation sample along with them. The replacement predicate eats 0.823%.

The benchmark itself was measuring one of its own artifacts. `_history_plan.json`
— the generator's record of the ten history-only plants, values in plaintext —
was written inside the corpus root, so `git add -A` put it in the object store
before a later `git rm` took it out of the working tree. The history scan found
it there and the scorer counted it as false positives, capping corpus A history
precision at 0.857 by construction. Both scratch files now live beside the
corpus rather than inside it; all four arms measure 1.000 precision and 1.000
recall. Detection did not change — only what the corpus was asking the scanner
to explain.

No rule ID, keyword, entropy threshold or allowlist outside these five changed.

### Honesty about what was and was not looked at
- **Redaction hardened for short secrets.** Masking revealed the first and last
  four characters at every length above eight, which showed eight of a
  nine-character value — the length range where human-chosen passwords live.
  Values of 9–15 characters now show only a two-character prefix and never a
  suffix. Values of 8 or fewer are still fully masked; 16 and above are
  unchanged.
- **Scan scope is now disclosed in JSON and SARIF**, not only in the text
  report. JSON gains `summary.scope`, `summary.scannedCount` and
  `summary.scopeNoun`; SARIF gains a standard `invocations` entry carrying the
  same sentence. CI reads exactly these two formats, so this is where the
  guarantee that "nothing was scanned" never reads as "nothing was found"
  matters most. Existing keys are unchanged; the new ones are additive.
  Note for SARIF consumers: **every SARIF document now carries an `invocations`
  block**, including scans with nothing unusual to disclose. Anything that
  enumerates a run's top-level properties will see one more than before.
- **Inline suppressions are counted and disclosed.** A scan that dropped
  findings to `secretloop:allow` or `gitleaks:allow` now says so:
  `; 3 finding(s) suppressed by inline directives`. The directives themselves
  behave exactly as before in a scan. `secretloop mask` no longer honours them
  at all -- see *A directive cannot silence the scrubber* below.
  **Scoped to the CLI.** The editor's workspace-scan summary carries the
  generated-file and symlink counts but not this one or the fixture-suppression
  count, so a workspace scan in VS Code still under-discloses relative to
  `secretloop scan` on the same repository. Tracked for 0.1.2; the CLI is where
  CI reads, which is why it went first.
- **Staged scans fail loudly when git cannot answer.** `secretloop staged`
  treated a failed `git diff --cached` as an empty index, so a locked index
  during a pre-commit hook exited 0 on a scan that never ran. It now exits 2 and
  says why.

### Masking, and what a scan admits it did not read

Four fixes from an external review of this release. The first three are why
0.1.1 had not been published; the fourth is what let one of them stay invisible.

- **A directive cannot silence the scrubber.** `secretloop mask` and the
  editor's *Mask Secrets in Clipboard* scanned through the same path a repository
  scan uses, so an inline `# gitleaks:allow` beside a credential suppressed the
  match -- and a suppressed match never enters the finding list, so there was
  nothing to redact and nothing to count. The credential went to stdout under a
  summary reading `masked 0 finding(s)`; the editor left it on the clipboard and
  said *no secrets found in the clipboard*. The annotation is there precisely
  because the value beside it is real, which is what makes honouring it in a
  transform the wrong reading: it is a triage decision about a repository, and a
  stream someone piped through a scrubber is not that repository's findings.
  Scanning is unchanged and still honours every directive it always did.

- **A project config cannot disable masking.** Both mask paths built their
  configuration from the repository you happened to be standing in, so a
  `.secretloop.json` carrying `"allowValues": [".*"]` or an `excludeRules` list
  turned `kubectl logs prod | secretloop mask | pbcopy` into a passthrough,
  again reporting zero. Rule selection for masking now comes from the shipped
  defaults and nothing on disk widens it. A malformed config still cannot stop a
  mask, which was the only property the old fallback was defending.

- **A scan says how many files it could not read.** Files skipped for exceeding
  `maxFileSizeBytes`, for looking binary, or for being unreadable at the read
  were dropped without being counted, and the scanned count is the number of
  files that survived -- so a tree of 500 files where 480 sat over the size cap
  reported `Scanned 20 file(s). No secrets found.` Every other skip this scanner
  performs already named itself; this was the last silent one and, on a real
  repository, the largest. Two new clauses, in text, JSON and SARIF alike:
  `; 12 file(s) not scanned — larger than maxFileSizeBytes (raise it in
  .secretloop.json to cover them)` and `; 3 file(s) not scanned — binary or
  unreadable`. Kept apart because only one of them names a fix. A file supplied
  from an unsaved editor buffer is scanned, not counted as a skip.

- **`mask` reports a malformed invocation.** `main()` dispatched the mask
  command before the argument check, and that check is the only reader of what
  the parser collected -- so every parse error was discarded for the one command
  whose failure mode is an unmasked secret. `secretloop mask --entropoy` masked
  with the generic tier off and exited 0. Argument errors are now reported
  before any command runs, and mask exits 2 having written nothing.

### Corrections
- **A non-zero exit says what it means.** `--fail-on` prints to stderr when it
  fails a build: `exit 1: findings at or above the fail-on threshold (this is
  the CI gate, not an error)`. Report output on stdout is byte-identical.
- **A corrupt baseline now names the file** — `Could not parse
  .secretloop-baseline.json: …` instead of a bare parser error.
- **`--verify` and `--write-baseline` together are now refused.** The
  combination sent every detected credential to its provider and then wrote the
  baseline and exited before reporting, so every verdict was discarded. Nothing
  leaked and the outbound record counted each call honestly — it was network
  traffic carrying live credentials in service of nothing. It now exits 2 and
  says to write the baseline first, then verify against it.
- **A revision range can no longer be read by git as an option.** `--rev-range`
  is checked against the characters rev-ranges are made of before it reaches
  `git log`'s arguments, where a value like `--output=<path>` would have made
  git write a file. The CLI's argument parser already refused flag-shaped
  values, so no released version was exploitable through it; the check now sits
  at the point where the argument is used, which covers every caller rather
  than the one that goes through the parser.
- **A credential is verified once even when several checks start at once.** The
  result cache could only help after a result existed, so concurrent checks of
  the same credential each contacted the provider. A second check now waits for
  the first. Counts of what was sent are unchanged in meaning — they have
  always recorded what actually left the machine, and now less does.
- **`.secretloop.example.json` claimed a fallback that never shipped.** It said
  a `.secretguard.json` from before the rebrand would still be read if no
  `.secretloop.json` existed. No release ever did this: `resolveConfigFile`
  has only ever looked for `.secretloop.json`. The comment is corrected, and no
  fallback was added. If you are carrying a `.secretguard.json`, rename it.
