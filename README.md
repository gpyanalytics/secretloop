# SecretLoop

**Find the secret. Verify it. Fix it.**

A GPY Analytics product.

SecretLoop finds exposed credentials locally, verifies *supported* credentials
against their provider only after a human explicitly approves it, and puts the
fix where you already work — your editor, your pre-commit hook, your CI, and
your AI coding agent over MCP.

1. **Find locally.** 110 detection rules on `main` (109 in the published
   0.4.0) with a keyword prescreen, plus an opt-in generic high-entropy tier,
   on your machine. Nothing here opens a socket.
2. **Verify with consent.** For the credential types SecretLoop supports, a
   human approves each check before anything leaves the machine.
3. **Remediate in place.** Redact or extract to `.env` from the same finding
   that failed CI.
4. **Expose it safely to agents.** MCP tools that keep the credential masked
   and put verification behind an approval the agent cannot grant itself.

![SecretLoop scanning a working tree: three findings, each with its severity, rule, masked value, remediation line and fingerprint](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-scan-hero.gif)

**Upgrading from 0.3.x?** In 0.4.0 the generic high-entropy tier is opt-in —
see the [changelog](CHANGELOG.md) and
[decision 0001](docs/decisions/0001-entropy-tier-opt-in.md).

## Quickstart

Needs Node 18 or newer. Scan a repository's whole history without installing
anything:

```bash
npx secretloop history --verify
```

`--verify` makes a read-only call to each supported provider to prove whether a
credential still works, so you get a list of things to rotate today rather than
a list of maybes. Drop it to stay entirely offline.

```bash
npx secretloop scan                                   # the working tree
npx secretloop staged                                 # what you are about to commit
npx secretloop scan --format sarif -o results.sarif   # for CI
npm install -g secretloop                             # for CI and hooks
```

For the editor, install **SecretLoop** from the VS Code Marketplace. The
extension scans as you type and puts *redact*, *extract to `.env`* and *rotate*
on the lightbulb. Live verification is off until you turn it on.

The full walk-through, from first scan to a gated build and a connected agent,
is [docs/quickstart.md](docs/quickstart.md).

## Documentation

The [documentation hub](docs/README.md) has one page per topic:

| | |
|---|---|
| Getting started | [Quickstart](docs/quickstart.md) |
| Use SecretLoop | [CLI](docs/cli.md) · [VS Code](docs/vscode.md) · [MCP server](docs/mcp.md) · [CI, hooks and clients](docs/integrations.md) |
| Understand results | [Coverage](docs/coverage.md) · [Configuration](docs/configuration.md) · [Verification](docs/verification.md) · [Troubleshooting](docs/troubleshooting.md) |
| Benchmarks | [Benchmarks](docs/benchmarks.md) |
| Contribute | [Development](docs/development.md) · [CONTRIBUTING](CONTRIBUTING.md) · [Security policy](SECURITY.md) |
| Project & decisions | [Roadmap](docs/project/roadmap.md) · [Backlog](docs/project/backlog.md) · [Market](docs/project/market.md) · [Decision records](docs/decisions/README.md) |

## What's in main and what's published

npm and the VS Code Marketplace serve **0.4.0** (2026-09-08). The `main`
branch carries changes that are merged, tested and benchmarked but **not in any
published package**: one more named rule, one-layer decoding of encoded
credentials, in-memory archive scanning with its coverage disclosure, the
API-document entropy scope, and two MCP message corrections. Release
validation for them is pending. The capability-by-version table lives in the
[documentation hub](docs/README.md#whats-in-main-and-whats-published); every
page marks such facts *main, unreleased*.

## In the editor

- **Findings are diagnostics, and the squiggle carries the verdict.** A format
  match is a warning. A credential confirmed live is an error — and so is one
  the provider refused to answer for, because a 403 leans live and no retry
  resolves it.
- **The quick-fix fits the verdict.** *Rotate / revoke this LIVE credential* on
  a confirmed-live one, *Inspect / revoke this possibly-active credential* on a
  refused check, and on any finding *Redact this secret*, *Copy to clipboard,
  then redact*, or *Move to `.env` and reference it*.
- **Scans run from the Command Palette** — *Scan Entire Workspace*, *Scan
  Staged Files*, and *Scan Git History for Secrets*.
- **Every decision it made is in View > Output > SecretLoop**, including how
  many credentials left the machine and to whom.

Details: [docs/vscode.md](docs/vscode.md).

## The loop

```
   detect  ──►  verify  ──►  remediate / rotate
     │            │                  │
  named rules  15 providers   redact · extract to .env
  + entropy   read-only API    · revoke at the provider
```

1. **Detect** — named rules (110 on `main`, 109 in published 0.4.0) across
   your working tree, staged changes and full git history, plus an optional
   generic high-entropy pass.
2. **Verify** — a read-only call to the provider proves whether the credential
   still works. A dead test token never interrupts you; a live production key
   is escalated. Eighteen rules have a verifier covering fifteen providers,
   seventeen can transmit, and a finding matched by any other rule is never
   transmitted.
3. **Remediate / rotate** — the same finding that failed your CI build appears
   as a lightbulb in your editor with *redact*, *extract to `.env`* and, where
   the provider exposes an API for it, *rotate*.

## Before you paste logs into an AI

`secretloop mask` reads a log on stdin and writes it back with every credential
replaced by `[REDACTED:<rule-id>]`, so a deploy log keeps the structure an
assistant needs and loses the secrets it does not.

```
cat deploy.log | npx secretloop mask | pbcopy
```

## Use SecretLoop from an AI coding agent (MCP)

SecretLoop ships an MCP server, so an assistant you already use can run the
scanner and reason about the results. **There is no AI inside SecretLoop** — no
model, no API key, no LLM dependency.

The gate an assistant cannot talk its way past — the agent asks, SecretLoop
returns `CONSENT_REQUIRED` with `network: null`, and the approval happens in a
terminal the chat cannot type into:

![An AI agent scans over MCP, asks to verify a GitHub token, and receives CONSENT_REQUIRED with network null; the human approves in a separate terminal; a replay of the same approval returns UNKNOWN](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mcp-terminal.gif)

The same flow inside Claude and GitHub Copilot Chat:

![Claude running the SecretLoop MCP tools: masked finding, consent-required verify, human terminal approval, then a single-use verification](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mcp-claude.gif)

![GitHub Copilot Chat running the SecretLoop MCP tools: masked finding, consent-required verify, human terminal approval, then a single-use verification](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mcp-copilot.gif)

Every product string in those demos is cited to source in
[docs/demos/FACTS-mcp-demo.md](docs/demos/FACTS-mcp-demo.md). The credential is
synthetic and the provider response is simulated — no request is made.

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
`secretloop` package, not a package of its own. Configuration for Claude Code,
Claude Desktop, Cursor, Copilot and other clients, the five tools, the
boundary, and the consent gate are in [docs/mcp.md](docs/mcp.md) and
[docs/integrations.md](docs/integrations.md).

## Where this sits against the existing tools

The pragmatic 2026 stack is Gitleaks (fast pre-commit blocking) + TruffleHog
(verified scans) + GitHub Secret Scanning, with GitGuardian on top for regulated
organisations. That is three or four tools for one job, and the seam between
them — *which of these findings is actually live, and how do I fix it?* — is
where the work still falls on a human.

Measured once, on one frozen benchmark: six pinned open-source repositories,
working tree only, verification off for every tool, one triage policy applied
to all of them.

| metric | Gitleaks | TruffleHog | SecretLoop (entropy enabled) |
|---|---|---|---|
| Static precision | 41.5% | 57.25–64.86%\* | 37.7% |
| TP-file coverage | 100.0% (145/145) | 82.1% (119/145) | 97.9% (142/145) |

\* A range: 21 TruffleHog findings could not be resolved to a verdict.

SecretLoop's column was measured with the entropy tier **enabled**, the shipped
default at the time. The **0.4.0 default** on the same corpus is **167 TP / 20
FP (89.3% precision)** at **137/145** files — higher precision, lower coverage.
TP-file coverage is not recall: nothing was planted, so a credential every tool
missed is counted by none. Populations, the changes on `main`, the older
studies and the limitations are in [docs/benchmarks.md](docs/benchmarks.md).
GitHub Secret Scanning and GitGuardian were not benchmarked.

| capability | Gitleaks | TruffleHog | GitHub | GitGuardian | SecretLoop |
|---|---|---|---|---|---|
| Runs without a hosted account | ✅ | ✅ | ❌ | ❌ | ✅ |
| Working-tree, pre-commit and full-history scan | ✅ | ✅ | hosted | hosted | ✅ |
| Validity check against the provider | ❌ | ✅ | ✅ | ✅ | ✅, consent-gated |
| SARIF output | ✅ | ✅ | — | — | ✅ |
| Baseline for existing findings | ✅ | not documented | — | — | ✅ |
| Fix applied in the editor | ❌ | ❌ | ❌ | ❌ | ✅ |
| MCP server for AI agents | ❌ | ❌ | ✅ | ✅ | ✅ |

Competitor rows come from official documentation accessed 2026-09-08 (Gitleaks
and TruffleHog READMEs; GitHub's secret scanning and push protection pages;
GitGuardian's validity-check, MCP and VS Code pages), not from measurement.

<details>
<summary>More demos</summary>

### CLI

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

## Security notes

- Verification sends the detected credential value to the provider's own API
  and nowhere else, and only after the switch for that surface is on:
  `--verify`, the `secretloop.enableLiveVerification` setting, or a terminal
  approval for an MCP request. Eighteen rules have a verifier and seventeen can
  transmit; the `sk_live_`/`sk_test_` shape is withheld because its issuer is
  ambiguous. A finding matched by any other rule is refused for verification
  and never transmitted, including the `encryption-key-assignment` rule on
  `main`, which has no verifier; on `main`, findings inside archive members and
  findings recovered by decoding are refused the same way.
- Results are cached in memory for five minutes keyed by a hash of the
  credential; every call is abandoned after five seconds, and a timed-out check
  is unknown, never "not a secret".
- AWS admin credentials for rotation live in the OS keychain through VS Code's
  secret storage, never in a settings file. If an admin key was ever in
  `settings.json`, treat it as exposed and rotate it.
- Baselines store fingerprints, not values.

The full policy is [SECURITY.md](SECURITY.md); the reasoning is in
[docs/verification.md](docs/verification.md).

## Contributing

Rules you personally needed are welcome; a rule needs a positive fixture and a
changelog entry, and its id never changes. Build, test and evidence conventions
are in [docs/development.md](docs/development.md) and
[CONTRIBUTING.md](CONTRIBUTING.md). The plan is in
[docs/project/roadmap.md](docs/project/roadmap.md): detector parity with
scanners carrying hundreds of rules is explicitly not the goal; the loop the
name refers to is.

---

SecretLoop — **From leaked to fixed.**
A GPY Analytics product.
