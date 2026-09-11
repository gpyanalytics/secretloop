# Configuration

One file, `.secretloop.json` at the repository root, read identically by the
CLI, the VS Code extension and the MCP server. Only that filename is read; there
is no fallback to any other name. A documented template ships in the repository
as `.secretloop.example.json`.

Applies to **published 0.5.0**.

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
it **(unreleased)**. The scan excludes the built-in defaults, plus every
glob in `.secretloop.json`, plus every glob in `secretloop.excludePaths`. An
editor setting can therefore narrow a scan but never widen one, and an empty
setting changes nothing. The globs use the same syntax and the same
repository-relative base in both places, and `includePaths` still outranks every
exclusion whichever list it came from — an explicit include wins over a
built-in, project-file or editor exclusion alike. In published 0.5.0 the editor
setting is declared but not read.

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
