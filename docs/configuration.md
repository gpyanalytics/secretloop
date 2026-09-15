# Configuration

One file, `.secretloop.json` at the repository root, read identically by the
CLI, the VS Code extension and the MCP server. Only that filename is read; there
is no fallback to any other name. A documented template ships in the repository
as `.secretloop.example.json`.

Applies to **published 0.5.1**.

## Keys

| key | default | meaning |
|---|---|---|
| `entropyThreshold` | `4.3` | Shannon entropy bar for the generic high-entropy tier. Single-charset strings need 0.2 more. |
| `excludePaths` | `[]` | Globs never scanned. **Added to** the built-in excludes (`node_modules`, lockfiles, minified bundles, `dist`), never replacing them. |
| `generatedExcludePaths` | shipped list | **Replaces** the built-in generated-file group (lockfiles, wrappers, SARIF reports). Empty keeps the shipped list; `--include-generated` scans them for one run. |
| `includePaths` | `[]` | When non-empty, restricts the scan to these globs. |
| `excludeRules` | `[]` | Rule ids disabled project-wide. For one line, prefer an inline directive. |
| `allowValues` | `[]` | Regexes matched against the detected value. For fixtures and documented samples. An entry that is not a valid regular expression is rejected, and the error quotes the pattern, so use a prefix or shape here rather than a whole credential. |
| `maxFileSizeBytes` | `1000000` | Files larger than this are skipped and counted in the scope sentence. On `main` the same bound applies to each archive member. |
| `entropyPassEnabled` | `false` | Turn on the generic high-entropy tier. Off by default since 0.4.0. |
| `includeFixtures` | `false` | Report generic high-entropy findings in test, fixture and example paths. Named rules and `generic-api-key-assignment` already report there. |
| `keyContextRequired` | `false` | Gate quoted generic-entropy findings on a secret-like identifier. Same as `--key-context`. |
| `includeApiDocumentEntropy` | `false` | With the entropy tier on, also run it inside recognized OpenAPI, Swagger and AsyncAPI documents. Same as `--include-api-document-entropy`. |

Globs use `*` (never crossing `/`) and `**`. Paths are repo-relative with
forward slashes.

## Precedence

For every raise-only switch (`entropyPassEnabled`, `includeFixtures`,
`keyContextRequired`, `includeGenerated` and `includeApiDocumentEntropy`):

1. A CLI flag turns the switch **on** for that run.
2. Otherwise the project file decides.
3. Otherwise the shipped default applies.

In VS Code, an explicit project-file value wins over the editor setting; the
editor setting applies only when the project file is silent. See
[VS Code settings](vscode.md#settings).

`excludePaths` is different, and deliberately so: it is a list, not a switch, so
the editor setting is **added to** the project file's list rather than replacing
it. The scan excludes the built-in defaults, plus every
glob in `.secretloop.json`, plus every glob in `secretloop.excludePaths`. An
editor setting can therefore narrow a scan but never widen one, and an empty
setting changes nothing. The globs use the same syntax and the same
repository-relative base in both places, and `includePaths` still outranks every
exclusion whichever list it came from — an explicit include wins over a
built-in, project-file or editor exclusion alike. Published 0.5.0 declared this
setting without reading it; 0.5.1 reads it.

The MCP server reads the project file of the repository it scans and reports
which rules it excluded and whether the entropy tier was on, so an absence of
findings can be read against what was actually looked for.

## Suppressing findings

False-positive fatigue is what gets scanners muted, so suppression is
first-class and every suppression is disclosed in the scope sentence.

- **Inline.** `secretloop:allow` or `secretloop-ignore` on the finding's line or
  the line above it. `gitleaks:allow` is honoured too, so a repository already
  annotated for gitleaks needs no re-annotation. Suppressed spans are counted:
  *N finding(s) suppressed by inline directives*. `mask` ignores directives on
  purpose.
- **Baseline.** `--write-baseline` accepts everything present today so only new
  findings fail. See the [CLI reference](cli.md#baselines).
- **Project file.** `allowValues` for a specific published sample,
  `excludeRules` to turn a rule off, `excludePaths` for a directory.

### Recording why

Every mechanism above can say *why*, and none of them has to. An annotation
written before this existed keeps working unchanged, and a suppression with no
reason is still a suppression — a required reason would invalidate every
annotation already in the tree and turn adoption into a migration.

```
secretloop:allow                                    every rule on the line
secretloop:allow(aws-access-key)                    only that rule
secretloop:allow -- vendor sample, rotated 2026-03  the reason, recorded
secretloop:allow(aws-access-key) -- vendor sample   both
```

- **Scope narrows, never widens.** Naming rules suppresses only those; a second
  finding on the same line from a rule you did not name is still reported. A
  bare directive — no bracket attached to it — means every rule, exactly as it
  always has.
- **An attempted scope that does not parse is refused whole, and suppresses
  nothing.** That covers an empty `secretloop:allow()`, a missing closing
  bracket, a character a rule id cannot contain, and any id this build does not
  have. It is deliberately *not* treated as the bare form: someone who typed
  brackets meant to narrow, and reading their mistake as "suppress everything"
  would let a typo widen suppression silently. A refused directive raises a
  diagnostic on stderr and the findings under it are reported.
- **A scope is all-or-nothing.** `secretloop:allow(aws-access-key,not-a-rule)`
  suppresses neither: half a scope is not an instruction anyone wrote. Rule ids
  are checked against the rules this build actually ships.
- **The bracket must be attached.** `secretloop:allow(github-token)` is a scope;
  `secretloop:allow (see TICKET-12)` is a bare directive followed by prose, and
  keeps working as it always did.

A refusal is reported on stderr with a stable code and nothing quoted from the
line that caused it — the annotation is your source, and the diagnostic ends up
in CI logs. Note that a directive is a line of text wherever it appears: a
document that shows a malformed example, including this one, raises the
diagnostic when that file is scanned. It changes no exit code, and it is saying
something true — that annotation would suppress nothing.
- **`gitleaks:allow` takes neither.** It is another tool's directive with
  another tool's meaning; it keeps suppressing everything on its line, and text
  written after it produces a diagnostic instead of a reason.
- **Reasons are capped at 200 characters**, truncated with a diagnostic rather
  than rejected, with control characters and `<`/`>` replaced by spaces at parse
  time.
- **The baseline** accepts `{"fingerprint": "...", "reason": "..."}` beside the
  plain strings it has always held. Reading both needs no migration and writes
  nothing back: `--write-baseline` still writes strings. An entry the loader
  cannot read is skipped and named — never fatal, because a baseline that
  refuses to load un-accepts every finding in it at once.
  Diagnostics name the entry by its **zero-based position** and carry a stable
  code (`[baseline-entry-malformed]`, `[reason-truncated]`). They never print the
  fingerprint, the path inside it, the reason or the rejected value: they go to
  stderr, and stderr ends up in CI logs. For the same reason a file that is not
  valid JSON is reported as such without the parser's message, which quotes the
  bytes around the error.
- **The project file** accepts `{"rule": "...", "reason": "..."}` in
  `excludeRules` and `{"pattern": "...", "reason": "..."}` in `excludePaths`.
  Before this, an object written there was read as a glob, matched nothing and
  excluded nothing, silently.

What this is **not**: a reason is user-editable metadata, not an approval.
Nothing checks it, nothing expires it, and it carries no authority — it is a
comment, and it stands entirely apart from verification consent, which is a
durable, human-approved, single-use record for transmitting a credential.

**Disclosure is a count, and only a count.** The scope sentence qualifies the
number it already printed — *2 finding(s) suppressed by inline directives, 1
with a recorded reason* — and prints nothing new when no reason was recorded.
`reportCoverage.suppression` gains a matching `inlineSuppressedWithReason`.

**The reason text itself is never published.** Not in the text report, not in
JSON, not in SARIF, not over MCP, and not in a log line. A reason describes the
credential it was written beside — *"old staging key, rotate after the
migration"* — so printed next to a count of what was hidden it is a lead on a
secret the scan deliberately withheld, and nothing stops someone writing the
credential itself into it.

Neither sanitising nor wrapping changes that. Sanitising bounds the length and
the characters; it is not evidence that the text contains no credential. An
untrusted-content wrapper marks provenance; it is not an authorization boundary
and does not prevent disclosure. The reason stays where its author put it, on
the line, for the reviewer who is reading that line.

Recording why also changes **no identity**: `configDigest` drops
`excludeReasons` the way it drops `allowValues` content, so documenting an
exclusion never makes two scans of the same configuration compare unequal.
- **Fixture paths.** With the entropy tier on, `generic-high-entropy` findings under `test`,
  `tests`, `__test__`, `__tests__`, `__mocks__`, `__snapshots__`, `__fixtures__`,
  `fixtures`, `snapshots` and `examples` segments are held back and counted unless
  `includeFixtures` is set. The comparison is case-sensitive: `Tests/` is not
  recognised, and that is recorded as a known limitation rather than changed,
  because widening what is hidden needs its own measurement. Only that tier is held
  back: `generic-api-key-assignment` reports in fixture paths either way. To
  inspect what the entropy tier finds in those paths, see
  [Inspecting fixtures and test data](cli.md#inspecting-fixtures-and-test-data).

### Why fake keys in test fixtures are still reported

A scanner cannot tell that they are fake: a credential-shaped string in a fixture
and one in production code are the same bytes. Named provider rules therefore
report everywhere, deliberately — a real token pasted into a test file is a real
leaked token, and fixture directories are exactly where one gets pasted "just to
check something". Only the generic entropy tier stands down in fixture paths.
There is no flag that suppresses named-rule findings in fixtures; use an inline
directive, a baseline, or `allowValues`, each of which leaves a reviewable
record. The best fix is to generate fixture credentials at runtime instead of
committing a literal; this repository does that for its own tests, which is why
scanning itself reports nothing from them.

## Built-in filters

Before any configuration applies, structural filters drop git SHAs, SHA-256
digests, lockfile integrity hashes, UUIDs, data URIs, file paths, version
strings, published documentation samples (AWS's `AKIAIOSFODNN7EXAMPLE`, the
jwt.io demo token, Stripe's sample key), template and shell expansions
(`${NAME}`, `$NAME`, `{NAME}`), and the `example.com`/`.net`/`.org` hosts in URL
credentials. The entropy tier additionally rejects ordered runs, identifier
paths, module specifiers and dotted identifier chains.

## Example

```json
{
  "excludePaths": ["testdata/**", "docs/examples/**"],
  "excludeRules": ["bcrypt-hash"],
  "allowValues": ["^sk_test_"],
  "entropyPassEnabled": true,
  "includeFixtures": false,
  "maxFileSizeBytes": 1000000
}
```
