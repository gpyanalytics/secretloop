# SecretLoop

**Find exposed secrets, verify supported credentials, and take action.**

Secret scanning for VS Code, the command line, and MCP workflows.
A GPY Analytics product.

This README describes SecretLoop 0.5.0.

SecretLoop scans your working tree, your staged changes or your full git
history on your machine and reports each **finding** with its value masked.
Only when you ask, and only for the credential types it supports, does it make
a read-only call to the provider to say whether that credential is **live**,
**dead** or **unknown**. The same finding carries its own fix in the editor,
and an AI agent can read findings over MCP without ever seeing a raw value.

![SecretLoop scanning a working tree: three findings, each with its severity, rule, masked value, remediation line and fingerprint](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-scan-hero.gif)

## Getting started

**Command line** — needs Node 18 or newer.

```bash
npx secretloop scan            # the working tree
npx secretloop staged          # what you are about to commit
npx secretloop history         # every commit, for secrets already pushed
npm install -g secretloop      # install it for CI and hooks
```

**VS Code** — install **SecretLoop** from the Marketplace, or from a `.vsix`
with `code --install-extension secretloop-0.5.0.vsix`. Findings become
diagnostics as you type, and the lightbulb carries *redact*, *extract to
`.env`* and, where the provider offers an API for it, *rotate*. Verification
stays off until you turn it on.

**MCP** — add the server to your client, for example
`claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "secretloop": {
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"]
    }
  }
}
```

`--package=secretloop` is required: `secretloop-mcp` is a command inside the
`secretloop` package, not a package of its own. For Claude Code, the same
thing on one line:

```bash
claude mcp add secretloop -- npx -y --package=secretloop secretloop-mcp
```

## One example: gate a build

```bash
npx secretloop scan --format sarif -o results.sarif --fail-on high
```

Exit `0` means nothing met the gate; exit `1` means something did, and stderr
names how many findings met which threshold. The SARIF file uploads to GitHub
code scanning. [More CI, pre-commit and client recipes](https://github.com/gpyanalytics/secretloop/blob/main/docs/integrations.md).

**Upgrading.** 0.5.0 scans inside archives and decodes encoded values by
default, so a scan can report findings an earlier version missed, and the
generic entropy tier no longer runs over API description documents unless you
ask. The [changelog](https://github.com/gpyanalytics/secretloop/blob/main/CHANGELOG.md) lists every behaviour change.

## What it does

- **Detect.** 110 named rules with a keyword prescreen, plus an **optional
  generic entropy tier** that is off by default because it is noisy. Beyond
  plain text it decodes base64, hex and percent-encoded values one layer and
  runs the same rules over the result, and it opens ZIP, tar and gzip
  containers in memory to scan each **archive member** — nothing is extracted
  to disk.
- **Verify.** 18 rules have a verifier covering 15 providers, and 17 of those
  can put a credential on the wire. A verification is an **explicit
  verification workflow**: the `--verify` flag on the command line, a setting
  in the editor, or a terminal approval for an MCP request.
- **Remediate.** The finding that failed CI is the one you fix in the editor:
  redact it, move it to `.env` with a `process.env` reference, or open the
  provider's rotation path.
- **Work with agents.** Five MCP tools expose findings with values masked, and
  the one tool that can transmit a credential needs a human approval typed in a
  terminal that the assistant cannot reach.

## Before you paste logs into an AI

```bash
cat deploy.log | npx secretloop mask | pbcopy
```

`mask` rewrites a stream with every recognised credential replaced by
`[REDACTED:<rule-id>]`, so a deploy log keeps the structure an assistant needs
and loses the secrets it does not.

## What it does not claim

- **A clean report is not proof of a clean repository.** Every scan prints what
  it read and what it skipped — files, archive members, refusals by reason, and
  any **incomplete scan coverage** such as a container it could not fully
  enumerate. Read that sentence before trusting a zero.
- **Not every finding is live.** A finding is a format match until a
  verification runs. `unknown` means no verdict was reached, never "safe".
- **Not every credential has a verifier.** A finding matched by a rule without
  one is never transmitted, and neither is an archive member or a value
  recovered by decoding: they are refused before any provider lookup.
- **Rotation is not automatic.** For most providers SecretLoop opens the
  console; only Slack revocation and AWS key deactivation are API calls, and
  the AWS one needs admin credentials you store yourself.
- **The entropy tier costs precision for coverage.** It is off by default, and
  turning it on finds unnamed secrets at the price of substantial noise.

Details: [coverage](https://github.com/gpyanalytics/secretloop/blob/main/docs/coverage.md) · [verification](https://github.com/gpyanalytics/secretloop/blob/main/docs/verification.md).

## How it compares

Measured once, on one frozen benchmark: six pinned open-source repositories,
working tree only, verification off for every tool, one triage policy applied
to all three.

| metric | Gitleaks | TruffleHog | SecretLoop (entropy tier on) |
|---|---|---|---|
| Static precision | 41.5% | 57.25–64.86%\* | 37.7% |
| Files with a validated true positive | 145/145 | 119/145 | 142/145 |

\* A range: 21 TruffleHog findings could not be resolved to a verdict.

That column is the **entropy tier on**, which is not the default. With the
default settings the same corpus gives 167 true positives and 20 false
positives, 89.3% precision, across 137 of the 145 files — higher precision,
lower coverage. This is not a general claim that SecretLoop beats another
scanner: it is one corpus, at one time, and it measures precision and file
coverage, not recall. Nothing was planted, so a credential every tool missed is
counted by none of them. Method, populations, competitor sources and
limitations: [benchmarks](https://github.com/gpyanalytics/secretloop/blob/main/docs/benchmarks.md).

What SecretLoop adds is the loop the name refers to: the finding that failed CI
is the one you fix in the editor, and the one an agent sees over MCP.

<details>
<summary>More demos</summary>

### MCP

![An AI agent scans over MCP, asks to verify a GitHub token, and receives CONSENT_REQUIRED with network null; the human approves in a separate terminal; a replay of the same approval returns UNKNOWN](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mcp-terminal.gif)

![Claude running the SecretLoop MCP tools: masked finding, consent-required verify, human terminal approval, then a single-use verification](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mcp-claude.gif)

![GitHub Copilot Chat running the SecretLoop MCP tools: masked finding, consent-required verify, human terminal approval, then a single-use verification](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mcp-copilot.gif)

Every product string in these recordings is cited to source in
[docs/demos/FACTS-mcp-demo.md](https://github.com/gpyanalytics/secretloop/blob/main/docs/demos/FACTS-mcp-demo.md). The credential
is synthetic and the provider response is simulated — no request is made.

### Command line

![The secretloop CLI help output listing every command and flag](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-help.gif)

![A working-tree scan reporting findings grouped by value](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-scan.gif)

![A git history scan walking commits for credentials](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-history.gif)

![Scanning only the staged changes, as the pre-commit hook does](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-staged.gif)

![Accepting current findings as a baseline so only new secrets report](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-baseline.gif)

![Masking credentials in a log stream before sharing it](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mask.gif)

![A deploy log masked with secretloop mask, then passed to an AI CLI for debugging](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mask-to-copilot-cli.gif)

![Copying a secret to the clipboard and redacting it from the file in one step](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-clipboard-story.gif)

### Illustrative mockups

These two are rendered pictures of the editor, not recordings of it.

![Mockup: a hardcoded key, the SecretLoop quick-fix menu, and the value relocated to .env](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-move-to-env.gif)

![Mockup: a deploy log masked at the terminal, then pasted into an editor chat panel](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mask-to-copilot.gif)

</details>

## Documentation

| | |
|---|---|
| Start here | [Quickstart](https://github.com/gpyanalytics/secretloop/blob/main/docs/quickstart.md) · [Troubleshooting](https://github.com/gpyanalytics/secretloop/blob/main/docs/troubleshooting.md) |
| Use it | [CLI](https://github.com/gpyanalytics/secretloop/blob/main/docs/cli.md) · [VS Code](https://github.com/gpyanalytics/secretloop/blob/main/docs/vscode.md) · [MCP server](https://github.com/gpyanalytics/secretloop/blob/main/docs/mcp.md) · [CI, hooks and clients](https://github.com/gpyanalytics/secretloop/blob/main/docs/integrations.md) · [Configuration](https://github.com/gpyanalytics/secretloop/blob/main/docs/configuration.md) |
| Understand results | [Coverage](https://github.com/gpyanalytics/secretloop/blob/main/docs/coverage.md) · [Verification](https://github.com/gpyanalytics/secretloop/blob/main/docs/verification.md) · [Benchmarks](https://github.com/gpyanalytics/secretloop/blob/main/docs/benchmarks.md) |
| Project | [Changelog](https://github.com/gpyanalytics/secretloop/blob/main/CHANGELOG.md) · [Roadmap](https://github.com/gpyanalytics/secretloop/blob/main/docs/project/roadmap.md) · [Decision records](https://github.com/gpyanalytics/secretloop/blob/main/docs/decisions/README.md) |

The [documentation hub](https://github.com/gpyanalytics/secretloop/blob/main/docs/README.md) indexes every page.

## Security and contributing

Verification sends a credential only to that credential's own provider, only
for the 18 rules that have a verifier, and only after you turn the relevant
switch on. Nothing else is transmitted, there is no telemetry, and the
published package declares no runtime dependencies. Report a vulnerability
through the process in [SECURITY.md](https://github.com/gpyanalytics/secretloop/blob/main/SECURITY.md), not a public issue.

Contributions are welcome, especially a rule you personally needed:
[CONTRIBUTING.md](https://github.com/gpyanalytics/secretloop/blob/main/CONTRIBUTING.md) and
[development](https://github.com/gpyanalytics/secretloop/blob/main/docs/development.md).

---

SecretLoop — **From leaked to fixed.**
A GPY Analytics product.
