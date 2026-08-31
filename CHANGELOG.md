# Changelog

## 0.1.4 — unreleased

One misattribution fix and six new provider rules — 103 rules to 109. No
existing rule ID changed, no existing threshold changed, and no output format
changed.

Every format below was verified against the provider's own documentation before
its pattern was written. Four further providers were surveyed and **not** built,
and that is recorded here too.

### Fixed — OpenRouter keys were reported as OpenAI keys

`openai-api-key` matches `sk-` followed by 32 or more characters from a class
that includes everything an OpenRouter key puts after `sk-`, so every
`sk-or-…` key was reported under the wrong provider. That is worse than a
generic finding: the provider selects the verifier, names the consent prompt and
picks the rotation link, so the finding sent you to the wrong console.

Fixed the way the same overlap was already fixed for Anthropic — an allowlist
entry on the broader rule, `/^sk-or-/` beside `/^sk-ant-/`. OpenAI's own key
shapes are unaffected.

### Six new provider rules

Every format below was verified against the provider's own documentation before
its pattern was written. **Four further providers were surveyed and dropped** —
see below.

| rule | severity | prefix | documented by |
|---|---|---|---|
| `openrouter-api-key` | critical | `sk-or-` | OpenRouter docs and blog |
| `vercel-access-token` | high | `vcp_` `vci_` `vca_` `vcr_` `vck_` | Vercel access-token docs and changelog |
| `supabase-secret-key` | critical | `sb_secret_` | Supabase API-keys guide |
| `neon-api-key` | critical | `napi_` | Neon changelog |
| `tailscale-api-key` | critical | `tskey-api-` `tskey-client-` `tskey-scim-` `tskey-webhook-` | Tailscale key-prefix reference |
| `tailscale-auth-key` | critical | `tskey-auth-` | Tailscale key-prefix reference |

Tailscale is two rules rather than one because an API token administers the
tailnet while a pre-authentication key provisions a device onto it — different
blast radius, different revocation path.

**Supabase publishable keys are never reported.** The documentation calls them
safe to expose in source, so flagging one would be a false positive by
definition; a test asserts the publishable form produces nothing.

**Minimum lengths are conservative floors, not documented values** — none of
these providers publishes a length, and a floor set too long silently misses
real credentials.

Each rule carries a post-prefix entropy floor set to the highest value that lost
nothing across **10,000,000** uniform draws at that rule's own minimum length:
3.00 for Vercel, 2.75 for Supabase and both Tailscale rules, 3.50 for Neon.
`openrouter-api-key` ships **without** a floor, and that is measured rather than
overlooked: its variable portion is hexadecimal, and at the rule's minimum
length a 3.75 floor would reject **85.0968%** of legitimate keys, 3.00 would
reject 0.0111%, and only 2.50 reaches zero — where it excludes nothing the
length requirement does not already exclude.

Measured on 200,000 samples of ordinary repository content — random alphanumeric,
hex and base64 runs, snake_case and camelCase identifiers, file paths, UUIDs and
prose — **every new rule fired 0 times**, against a 0.001% rejection budget.

### Measured and not built — four providers with no safe pattern

Reported because the absence is the result, not an omission.

**MongoDB Atlas, Deno Deploy and Render** publish no page stating their
credential format. Third-party write-ups describe one, and that is not evidence
a detector can rest on.

**Resend** is the more interesting case: its prefix *is* documented, and it was
still dropped. `re_` is three characters, and the only published example carries
an internal underscore, so the pattern's character class must accept `_` — which
makes `re_<snake_case_identifier>` the same shape as a key. Entropy cannot
separate them: across 20,000 realistic 30-character identifiers, **81.7% of
snake_case and 94.5% of camelCase** clear 3.50, already the highest floor that
keeps real keys. Excluding `_` takes the collision to zero and stops matching
real Resend keys too. A documented prefix turns out to be necessary but not
sufficient.

### Honest about a format three providers share

`stripe-secret-key` now reads *"Stripe / Clerk / WorkOS secret key (format
shared by all three)"*. Clerk and WorkOS both issue secret keys as
`sk_live_`/`sk_test_`, and Clerk's documentation says the shape is deliberately
familiar. No pattern separates them, so none is attempted — but a finding that
said "Stripe" and meant Clerk sent someone to rotate a key in a dashboard that
does not hold it.

## 0.1.3

Two false-positive fixes. Both come from a twenty-repository survey run against
0.1.2 **after** it shipped — a different and much broader exercise than the two
SDK checkouts 0.1.2 was tuned against, and no part of it changed 0.1.2.

No rule ID changed and no existing threshold changed. No output format changed.
Findings that survive these fixes keep their fingerprints: across this
repository and the source files below, 283 findings are present before and
after with byte-identical fingerprints, and nothing new appeared.

### Fixed — fixed-prefix rules matched low-diversity runs

A rule that matches a fixed literal prefix followed by a character class has a
problem when every character of that prefix also belongs to the class: the
pattern then describes one unbroken run of one alphabet, and any long enough run
of that alphabet satisfies it.

`twitter-bearer-token` is the extreme case — twenty-one `A` characters in front
of `[A-Za-z0-9%]{50,}`. In one public repository it produced **7,129 findings at
`high` severity from five files** of assembly padding and committed test data.
The existing repeated-character guard did not catch them: it requires the value
to be a single character repeated, and padding with two stray bytes in it is
not. A `high` severity rule firing seven thousand times on padding is the
fastest way to teach someone to ignore alerts.

**The variable portion after the prefix must now clear an entropy floor.** One
mechanism, applied to the eight rules that share the defect, rather than eight
separate exceptions — `atlassian-api-token`, `facebook-access-token`,
`github-fine-grained-pat`, `intercom-token`, `jfrog-token`, `pypi-token`,
`square-access-token` (one of its two branches) and `twitter-bearer-token`. Of
103 rules, 55 are fixed-prefix and 28 carry the precondition; the floor is
enabled only where the variable run is long enough for a threshold to be shown
safe. It fails open: a rule that declares nothing is untouched, and a prefix
that stops matching leaves the finding reported rather than dropped.

The threshold is measured, not chosen. Two populations, both on the portion
after the prefix:

| population | Shannon entropy |
|---|---|
| the false positives above, re-scanned from the source files | 0.040 – 3.337 bits |
| 100,000,000 uniformly random tokens at the tightest enabled configuration | **4.1649 bits minimum** |

The floor sits at 3.75 — the midpoint, 0.413 bits above the worst false positive
and 0.415 below the least random of a hundred million legitimate tokens.

Distinct-character count was measured and **rejected** as the discriminator: the
least diverse of those tokens carried 21 distinct characters and the worst false
positive carried 29, so the two populations overlap on diversity and separate
only on entropy.

Measured on a 200,000-sample synthetic corpus (deterministic, one recorded
seed), with every value drawn from the character class the rule's own pattern
declares:

- **legitimate-token loss: 0 of 140,000 — 0.0000%.** Per rule, at both the
  documented token length and the shortest length the pattern accepts.
- every false-positive-shaped sample the scanner reported before the change is
  rejected after it, across all eight rules
- no finding was added anywhere
- on the five source files: **7,129 findings before, 0 after**

Known boundary, stated rather than hidden: a variable run drawn from a
16-symbol alphabet at 50–60 characters straddles the floor. None of these eight
providers issues tokens of that shape, which is why the rules that do — such as
`sentry-auth-token`, whose run is declared over 65 symbols but issued as hex —
are deliberately not on the list.

### Fewer findings — `go.work.sum` is excluded, like `go.sum`

`go.sum` has always been excluded. Go workspaces (Go 1.18+) put the same content
in a second filename — module paths, versions and checksums — and that one was
never listed. One public repository produced **44 entropy findings from a single
`go.work.sum`**, every one a module digest. Measured on that file: 44 before, 0
after.

It joins the base exclusion group, beside `go.sum` rather than in the
generated-file group, so the two files answer `--include-generated` the same
way: **neither is restored by it**, which has always been true of `go.sum`. The
alternative would have made the flag scan one and not the other, a difference
nobody could predict from the filenames.

### Measured and not fixed — fixed-prefix matches inside base64 assets

The same survey found `square-access-token` and `facebook-access-token` matching
inside base64 blobs embedded in a vector image and a machine-learning resource
file — five findings — and suggested the entropy floor above would cover them
too. **Measurement rejected that, and they are unchanged.**

Those values carry 4.33 to 4.81 bits over 95 to 119 characters. The least random
of 10,000,000 uniformly random legitimate tokens of the same length carries
4.885. A gap of 0.075 bits sits *inside* the legitimate distribution's own tail,
so no threshold separates the two populations, and one that appeared to would be
fitted to a pair of samples rather than to a property of credentials. A test
asserts these still match, so lowering the threshold to reach them fails loudly
instead of quietly trading real credentials for five findings.

A different mechanism might address them. None is proposed here on this
evidence.

## 0.1.2

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
keeps credentials in fixtures that is a large number. A large open-source
JavaScript SDK gains 64
working-tree and 84 history `generic-api-key-assignment` findings — 9 and 23
distinct values, mostly one test API key repeated across fixture JSON. They were
always in those files; 0.1.1 was not showing them. That is the fix working, not
a regression. A large open-source Objective-C SDK gains one, because its suite
lives in `Tests/` and
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
| JS SDK (tree) | 4 → **0** | 0 → **64** | 4 → 64 |
| JS SDK (history) | 26 → **19** | 2 → **86** | 28 → 105 |
| ObjC SDK (tree) | 132 → **0** | 1 → 1 | 133 → 1 |
| ObjC SDK (history) | 196 → **23** | 3 → **6** | 199 → 29 |

A rising total is the expected result on a repository that keeps credentials in
fixtures. Read the entropy column for the noise reduction and the format-match
column for what was being hidden.

Every specific-rule finding, and the `high` API key in one project's test
fixtures, still reports. Fingerprints are unchanged for all 48
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
