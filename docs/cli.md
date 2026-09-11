# CLI reference

The `secretloop` command is the same engine the extension and the MCP server run.
All three read the same `.secretloop.json`, so "passed locally, failed in CI"
cannot come from a different rule set.

Applies to **published 0.5.1**.

## Commands

| command | what it does |
|---|---|
| `scan` | Scan the working tree (the default when no command is given). |
| `staged` | Scan staged changes only. This is what the pre-commit hook runs. |
| `history` | Scan git history for secrets committed at any point, including ones deleted later. |
| `mask` | Read stdin, write it back with every secret replaced by `[REDACTED:<rule-id>]`. |
| `approve <fingerprint>` | Authorize one credential verification that an MCP client requested. Interactive only. |
| `help` / `version` | Print the help text or the version. |

## Options

| option | applies to | meaning |
|---|---|---|
| `--verify` | scan, staged, history | Confirm liveness against each supported provider before reporting. Sends the credential to its provider. Off by default. |
| `--format <text\|json\|sarif>` | scan, staged, history | Output format. SARIF feeds GitHub code scanning. Default `text`. |
| `-o, --output <file>` | scan, staged, history | Write the report to a file instead of stdout. |
| `--fail-on <any\|verified\|critical\|high\|never>` | scan, staged, history | Which findings cause exit `1`. Default `any`. `verified` requires `--verify`. |
| `--baseline <file>` | scan, staged, history | Ignore findings whose fingerprint is in the baseline. |
| `--write-baseline <file>` | scan, staged, history | Write every current finding's fingerprint to the file and exit `0`. |
| `--path <dir>` | all scans | Directory to scan. Default: the current directory. |
| `--include-entropy` | scan, staged, history | Also report generic high-entropy findings. Off by default since 0.4.0. |
| `--include-fixtures` | scan, staged, history | Also report *generic high-entropy* findings in test, fixture and example paths. Named rules and `generic-api-key-assignment` already report there. |
| `--include-generated` | scan, staged, history | Also scan generated files (lockfiles, Gradle/Maven wrappers, Xcode project files, SARIF reports). Never re-enables `node_modules`, `package-lock.json` or minified bundles. |
| `--key-context` | scan, staged, history | Report a *quoted* generic high-entropy string only if the identifier it is assigned to carries a secret-like word. Off by default. |
| `--include-api-document-entropy` | scan, staged | With `--include-entropy`, also run the entropy heuristic inside recognized OpenAPI, Swagger and AsyncAPI documents. Named rules are unaffected. Not applicable to history or mask. |
| `--max-commits <n>` | history | Scan only the most recent `n` commits. |
| `--rev-range <range>` | history | Scan a git revision range, for example `origin/main..HEAD`. |
| `--entropy` | mask only | Also mask generic high-entropy strings in the piped stream. Off by default, which is the opposite of a scan. |
| `--no-redact` | scan, staged, history | Print full secret values. Dangerous in CI logs. |

`--include-entropy`, `--include-fixtures`, `--include-generated`,
`--key-context` and `--include-api-document-entropy` are raise-only: a flag can
turn something on for one run, never off. The project file decides the
baseline; see [Configuration](configuration.md#precedence).

## Exit codes

| code | meaning |
|---|---|
| `0` | Nothing met the `--fail-on` gate. |
| `1` | Something did. stderr says how many findings met the threshold, which threshold, and where the report went. |
| any other | A real failure: an unreadable configuration, a bad flag, a scan that could not run, an unsupported Node version. |

The count on exit `1` is the number that **met the threshold**, not the number
found: a scan with forty medium findings and one critical reports one finding
under `--fail-on critical`.

A scan that could not read anything is not a clean result and says so: an
empty staged set prints *nothing was scanned, so this is not a clean result*
and still exits `0`, while a `staged` run outside a git repository exits `2`.

## `--fail-on verified`

Fails on a **confirmed-live** credential and on one whose check **reached no
verdict**: the provider was unreachable, answered 403, rate-limited the request,
or the paired credential was missing. It does not fail on rules that have no
verifier at all, because only 17 rules can be checked against a provider and
counting the rest would make the flag behave like `--fail-on any`.

This is stricter than it once was. A runner without network egress used to pass:
every check returned unknown, nothing was marked live, and the gate had nothing
to fire on. Such a run now fails and prints why:

```
secretloop: --fail-on verified could not vouch for 3 credential(s):
  2 — could not reach the provider: a connectivity problem, not a verdict on
      the credential — fix egress and re-run
  1 — the provider refused the check: a live-but-scoped credential and a
      revoked one look identical here — inspect these directly
```

`--fail-on verified` without `--verify` is rejected with exit `2` rather than
silently exiting `0`.

## Report-only runs

```bash
secretloop scan --format sarif -o results.sarif --fail-on never
```

Always exits `0` and still writes every finding. Use it for an adoption run, a
scheduled report, or a step whose findings you want visible but not blocking.

## Baselines

```bash
secretloop scan --write-baseline .secretloop-baseline.json
secretloop scan --baseline .secretloop-baseline.json --fail-on high
```

A baseline stores fingerprints, never values. A fingerprint is
`path:rule-id:digest`, where the digest is a truncated SHA-256 of the value, or
of the secret-free context for rules whose capture can be a human-chosen
password. Reformatting a file does not resurrect an accepted finding; moving the
value, changing it, or a rule reporting it under a different id does. A corrupt
baseline is refused by name: `Could not parse .secretloop-baseline.json: …`.

## The scope sentence

Every report ends with what the scan read and what it did not:

```
24686 file(s); 53 generic finding(s) suppressed in test/fixture paths
(--include-fixtures to report them); 11 file(s) not scanned — larger than
maxFileSizeBytes (raise it in .secretloop.json to cover them); 1018 file(s)
not scanned — binary or unreadable
```

On `main` the sentence also counts API description documents the entropy tier
did not look at and, when archives are met, containers opened, members scanned,
members refused, entries not inspected, and containers that would not open.
[Coverage](coverage.md) explains each clause.

## `mask`

```bash
kubectl logs pod | secretloop mask | pbcopy
```

Reads stdin, writes the masked stream to stdout, and the count of what it masked
to stderr. Inline `secretloop:allow` and `gitleaks:allow` directives are
deliberately **not** honoured here: a directive is a triage decision about a
repository, and a stream someone asked to be scrubbed is not that repository.
Named rules only unless `--entropy` is passed.

## `approve`

```bash
secretloop approve <fingerprint>
```

The human half of consented verification. It shows the provider, the file and
line, the masked value, and states that the credential will leave the machine
and that an MCP client asked for it, then waits for `y` or `N`. It refuses to run
without an interactive terminal, so it cannot be piped or scripted, and an input
that ends (Ctrl-D) is a no. Approval is one credential, one file, one provider,
one use, five minutes. See [Verification](verification.md#the-consent-gate).

## Inspecting fixtures and test data

To look at what the generic entropy heuristic finds in test, fixture and mock
data — the run people usually mean by "inspect my fixtures":

```bash
secretloop scan --path ./tests --include-entropy --include-fixtures \
  --format json --fail-on never
```

This is the authoritative description of that workflow; other pages link here.

What each part does, and what it does **not** do:

- **Named provider rules stay enabled.** `--include-fixtures` does not switch
  anything off. A real GitHub token committed to `tests/` is reported as
  `github-token` whether or not you pass it — that is the point: a leaked
  credential in a fixture is still leaked.
- **`--include-fixtures` lifts the fixture-path suppression of the generic
  high-entropy tier, and only that tier.** Without it, `generic-high-entropy`
  findings under recognized test, fixture and example path segments are dropped
  and the scan says how many. **`generic-api-key-assignment` is not suppressed
  there** — it is a high-severity format match, and it reports in fixture paths
  with or without this flag. The segment list and its case sensitivity are in
  [Configuration](configuration.md#suppressing-findings).
- **API-document entropy is a separate control.** Recognized OpenAPI, Swagger
  and AsyncAPI documents are still skipped by the entropy heuristic unless you
  also pass `--include-api-document-entropy`. `--include-fixtures` does not
  imply it, and the scan reports how many documents were skipped.
- **Your existing exclusions still apply.** `excludePaths`, `baseExcludePaths`,
  generated-file exclusions, `maxFileSizeBytes` and `includePaths` precedence
  are unchanged by either flag. So are inline suppressions
  (`secretloop:allow`, `secretloop-ignore`, `gitleaks:allow`), which stay
  suppressed and counted, and the built-in placeholder and documentation-sample
  value filters, which drop obvious non-secrets before anything is reported.
  **An inspection run is not a way to see everything the scanner considered.**
- **`--fail-on never` only makes findings non-blocking**, so an inspection in a
  script does not exit `1` and read like a failure. It does not suppress
  operational failures: an unreadable configuration, a bad flag or a scan that
  could not run still exits non-zero. See [Exit codes](#exit-codes).
- **`--format json`** is convenient because it lets you filter the result with
  any JSON tool — for example to the entropy tier alone, by `ruleId` or by the
  `entropy-heuristic` confidence tier. The text report already separates the
  tiers by rule id, severity and tier.

**What this run does not establish.** It does not check whether any value is
live: liveness requires `--verify`, which is a separate, consent-gated action
(see [Verification](verification.md)). And it is not a completeness claim —
excluded paths, unreadable files, suppressed findings and filtered placeholders
all mean the report is what this configuration surfaced, not everything that is
there. Read the scope line the scan prints before drawing a conclusion from an
empty result.

## Examples

```bash
secretloop scan --verify --format sarif -o results.sarif
secretloop history --max-commits 500 --verify
secretloop scan --baseline .secretloop-baseline.json --verify --fail-on verified
secretloop scan --include-entropy --include-fixtures      # the noisiest, most complete run
```
