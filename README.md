# SecretLoop

**Find exposed secrets, check whether supported credentials are live, and fix them where you found them.**

SecretLoop is a secret scanner with three interfaces on one engine: a **command-line tool** for
repositories, pre-commit hooks and CI; a **VS Code extension** that turns findings into diagnostics with
quick-fixes; and an **MCP server** that lets an AI assistant work with findings without ever seeing a raw
value. Scans run on your machine. The only network request SecretLoop ever makes is a verification of one
supported credential against that credential's own provider, and only after you ask for it.
A GPY Analytics product.

This README describes SecretLoop **0.7.1**. The [changelog](https://github.com/gpyanalytics/secretloop/blob/main/CHANGELOG.md)
lists what each version changed, and the [documentation hub](https://github.com/gpyanalytics/secretloop/blob/main/docs/README.md)
records which version each distribution channel currently serves.

## Install

**Command line** — Node 18 or newer.

```bash
npx secretloop scan            # run it once, installing nothing
npm install -g secretloop      # install it for hooks and CI
```

**VS Code** — install **SecretLoop** from the
[Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=gpyanalytics.secretloop)
or [Open VSX](https://open-vsx.org/extension/gpyanalytics/secretloop), or from a downloaded file:

```bash
code --install-extension secretloop-0.7.1.vsix
```

**MCP** — register the server with your client. For Claude Code:

```bash
claude mcp add secretloop -- npx -y --package=secretloop secretloop-mcp
```

`--package=secretloop` is required: `secretloop-mcp` is a command inside the `secretloop` package, not a
package of its own. JSON configuration for other clients is in the
[MCP guide](https://github.com/gpyanalytics/secretloop/blob/main/docs/mcp.md).

**Upgrading to 0.7.0.** Detection is unchanged: the same tree reports the same findings it did under 0.6.0,
and a baseline or consent record made under 0.6.0 still matches. What changed is what a scan refuses and
discloses: the consent store is checked before it is trusted and refused when it is not private, the
scanner checks the file it actually opened before and, on Linux, after reading it, and the JSON report's
`schemaVersion` is now `5`. **A 0.6.0 report cannot be compared with a 0.7.0 report, and two 0.6.0 reports
cannot be compared under this version.** Scan both sides again with 0.7.0; nothing converts a saved
report.

**Upgrading to 0.7.1.** A dependency and security maintenance release with no intended change to detection or
behaviour. Because the comparator requires equal tool versions, a 0.7.0 report and a 0.7.1 report are not comparable
either: regenerate both with 0.7.1.

## Quick start: a safe local scan

```bash
cd your-repository
npx secretloop scan
```

This reads the working tree, contacts nothing, and prints a report like this one (recorded on macOS on a
two-file repository holding one synthetic token):

```
Scanned 2 file(s); 6 descriptor(s) opened for content: identity 6 verified; kernel path 6 unavailable; kernel path after read 2 unavailable, 4 not reached. 1 finding(s): 0 confirmed live, 0 needing a look, 1 unverified, 0 dead.

UNVERIFIED (1) — matched a known format or entropy heuristic; no liveness check was run.
  [critical] GitHub Personal Access Token (github-token)
    app.js:1
    value: ghp_********************F8KT
```

How to read it:

- **The first sentence is the scope.** It says what was read, what was skipped and why, and what the
  per-file checks did. A clean report is a statement about exactly that scope, not about the repository.
- **Every finding is masked.** You see the rule, severity, file and line, and the first and last
  characters of the value. The full value never appears in output, logs or MCP responses.
- **`unverified` means no liveness check ran**, not "safe". Verification is a separate, explicit step
  (`--verify`) that sends the credential to its provider; see
  [verification](https://github.com/gpyanalytics/secretloop/blob/main/docs/verification.md) before using it.
- **Exit codes gate a build.** `0` means nothing met the `--fail-on` threshold (default: any finding);
  `1` means something did; any other code is a failure to run.

```bash
npx secretloop scan --format sarif -o results.sarif --fail-on high   # for GitHub code scanning
npx secretloop scan --format json -o before.json --fail-on never     # a report to compare later
```

## Commands

Every top-level command, verified against the CLI's own help text. Flags, defaults and exit codes are in the
[CLI reference](https://github.com/gpyanalytics/secretloop/blob/main/docs/cli.md).

| command | what it does | writes | network |
|---|---|---|---|
| `scan` | Scan the working tree (the default when no command is given). | a report only with `-o`; a baseline only with `--write-baseline` | none, unless you pass `--verify` |
| `staged` | Scan the staged changes only; this is what the pre-commit hook runs. | as `scan` | none, unless you pass `--verify` |
| `history` | Scan git history for secrets committed at any point, including ones deleted later. | as `scan` | none, unless you pass `--verify` |
| `mask` | Read stdin and write it back with every recognised secret replaced by `[REDACTED:<rule-id>]`. | stdout only | none |
| `approve <fingerprint>` | Authorise **one** credential verification that an MCP client requested: one credential, one file, one provider, one use, five minutes. Interactive terminal only; it cannot be piped or scripted. | a consent record under `~/.secretloop` | none itself; the MCP server makes the single provider request after your approval |
| `compare <before.json> <after.json>` | Compare two saved JSON reports and list what is new, persisting and no longer observed. Refuses pairs the report contract does not admit (different versions, settings or incomplete coverage). | nothing | none; it never rescans |
| `help` | Print the help text. The version is a flag: `secretloop --version`. | nothing | none |

```bash
cat deploy.log | npx secretloop mask | pbcopy        # redact a log before pasting it into an assistant
npx secretloop compare before.json after.json        # exit 0 nothing new, 1 new findings, 3 not comparable
```

## What it detects

110 named rules with a keyword prescreen, over plain text, one layer of base64, hex and percent-encoded
values, and the members of ZIP, tar and gzip containers opened in memory. An optional generic high-entropy
tier (`--include-entropy`) is off by default because it is noisy. 18 rules have a verifier covering 15
providers; 17 of them can put a credential on the wire, and one is refused because its format is issued by
more than one company. Details: [coverage](https://github.com/gpyanalytics/secretloop/blob/main/docs/coverage.md).

## VS Code

Findings appear as diagnostics as you type. The lightbulb offers **redact**, **extract to `.env`** with a
`process.env` reference, and **rotate**, which opens the provider's console; only Slack revocation and AWS
access-key deactivation are API calls, and the AWS one uses admin credentials you store yourself. Live
verification is a setting that is off until you turn it on. Commands, settings and the pre-commit hook:
[VS Code guide](https://github.com/gpyanalytics/secretloop/blob/main/docs/vscode.md).

## MCP

Five tools — `secretloop_scan`, `secretloop_list_findings`, `secretloop_get_finding`,
`secretloop_history_scan`, `secretloop_verify` — expose findings with every value masked, over stdio. The
one tool that can transmit a credential answers `CONSENT_REQUIRED` until a human runs `secretloop approve`
in a terminal the assistant cannot reach. Setup for Claude Code, Claude Desktop, Cursor, Copilot and others:
[MCP guide](https://github.com/gpyanalytics/secretloop/blob/main/docs/mcp.md) ·
[integrations](https://github.com/gpyanalytics/secretloop/blob/main/docs/integrations.md).

## Security and limitations

- **What leaves the machine.** Only a credential you chose to verify, only to its own provider, only for
  the 18 rules with a verifier. No telemetry, and the published package declares no runtime dependencies.
- **Consent is a file, checked before it is trusted.** The consent store under `~/.secretloop` must be
  private; a store that is shared, group-writable, owned by another account or on a filesystem without
  ownership (exFAT) is refused, never repaired.
- **Containment is stated narrowly.** Every content read checks that the opened descriptor is the object
  that was inspected; on Linux the kernel-recorded location is also checked before the first read and after
  the last. Those are two points, not a guarantee about the whole read, and macOS and Windows have the
  identity check only.
- **A clean report is not proof of a clean repository.** Read the scope sentence. Findings are format
  matches until verified; `unknown` is not "safe"; archive members and decoded values are never
  transmitted; rotation is not automatic.

Policy, reporting a vulnerability, and the full statement of what is and is not validated:
[SECURITY.md](https://github.com/gpyanalytics/secretloop/blob/main/SECURITY.md).

## Documentation

| | |
|---|---|
| Start here | [Quickstart](https://github.com/gpyanalytics/secretloop/blob/main/docs/quickstart.md) · [Troubleshooting](https://github.com/gpyanalytics/secretloop/blob/main/docs/troubleshooting.md) |
| Use it | [CLI](https://github.com/gpyanalytics/secretloop/blob/main/docs/cli.md) · [VS Code](https://github.com/gpyanalytics/secretloop/blob/main/docs/vscode.md) · [MCP server](https://github.com/gpyanalytics/secretloop/blob/main/docs/mcp.md) · [Integrations](https://github.com/gpyanalytics/secretloop/blob/main/docs/integrations.md) · [Configuration](https://github.com/gpyanalytics/secretloop/blob/main/docs/configuration.md) |
| Understand results | [Coverage](https://github.com/gpyanalytics/secretloop/blob/main/docs/coverage.md) · [Verification](https://github.com/gpyanalytics/secretloop/blob/main/docs/verification.md) · [The JSON report](https://github.com/gpyanalytics/secretloop/blob/main/docs/reports.md) · [Benchmarks](https://github.com/gpyanalytics/secretloop/blob/main/docs/benchmarks.md) |
| Project | [Changelog](https://github.com/gpyanalytics/secretloop/blob/main/CHANGELOG.md) · [Roadmap](https://github.com/gpyanalytics/secretloop/blob/main/docs/project/roadmap.md) · [Decision records](https://github.com/gpyanalytics/secretloop/blob/main/docs/decisions/README.md) · [Development](https://github.com/gpyanalytics/secretloop/blob/main/docs/development.md) |

Recordings of the CLI and MCP flows are in
[docs/demos](https://github.com/gpyanalytics/secretloop/tree/main/docs/demos); every product string in the
MCP recordings is cited to source in
[FACTS-mcp-demo.md](https://github.com/gpyanalytics/secretloop/blob/main/docs/demos/FACTS-mcp-demo.md),
and the recordings predate 0.7.0's longer scope sentence.

## Contributing and license

Contributions are welcome, especially a rule you personally needed:
[CONTRIBUTING.md](https://github.com/gpyanalytics/secretloop/blob/main/CONTRIBUTING.md) and
[development](https://github.com/gpyanalytics/secretloop/blob/main/docs/development.md).
SecretLoop is released under the [MIT License](https://github.com/gpyanalytics/secretloop/blob/main/LICENSE).

SecretLoop — **From leaked to fixed.** A GPY Analytics product.
