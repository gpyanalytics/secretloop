# SecretLoop documentation

One authoritative page per topic. Every page describes **published 0.5.1**, the
current release on npm and the extension channels. The table at the end of this
page summarises what 0.5.0 changed from 0.4.0. 0.5.1 is a maintenance release:
it added or changed no detector rules, and its fixes are listed in the
[changelog](../CHANGELOG.md).

## Getting started

- [Quickstart](quickstart.md) — install nothing, scan a repository, read the
  output, add the pre-commit hook. First use lives here and nowhere else.
- [Troubleshooting](troubleshooting.md) — exit codes, the messages the tool
  prints when it refuses or cannot look, and what to do about each.

## Use SecretLoop

- [CLI reference](cli.md) — every command and flag, with the semantics that are
  easy to get wrong (`--fail-on verified`, `mask --entropy`, baselines).
- [VS Code extension](vscode.md) — diagnostics, quick-fixes, commands, settings,
  the verification prompt, and the AWS admin credential store.
- [MCP server](mcp.md) — the five tools, what crosses the boundary, the consent
  gate, and how archive-member and encoded findings are handled.
- [Integrations](integrations.md) — CI, pre-commit, SARIF, and every MCP client
  configuration in one place.
- [Configuration](configuration.md) — `.secretloop.json`, precedence between the
  project file, editor settings and CLI flags, suppression, baselines.

## Understand results

- [Coverage](coverage.md) — what is scanned (files, staged changes, history,
  archives, encoded spans), what is deliberately not, and how a scan discloses
  what it did not look at.
- [Verification](verification.md) — the liveness tri-state, the reasons an
  outcome is `unknown`, which rules can transmit, and the consent model.

## Benchmarks

- [Benchmarks](benchmarks.md) — the frozen six-repository comparison, the 0.4.0
  default-mode measurement, the recall change on `main`, and the older studies,
  with their populations kept apart.

## Contribute

- [Development](development.md) — building, testing, adding a rule, the
  evidence conventions, release gates, and the open items.
- [Contributing](../CONTRIBUTING.md) — how to send a change.
- [Security policy](../SECURITY.md) — reporting, what leaves the machine.

## Project & decisions

- [Roadmap](project/roadmap.md) · [Backlog](project/backlog.md) ·
  [Market](project/market.md)
- [Decision records](decisions/README.md) — the six design decisions that shape
  detection scope and verification, each with the evidence it rests on.

## What's in main and what's published

Release status, current as of **2026-09-11**. This page is repository-only: it
is not shipped in the npm package or the VS Code extension, so it can carry
status that would go stale inside a published artifact.

npm, Open VSX and the VS Code Marketplace all serve **0.5.1** (2026-09-11),
which is also what `main` carries. The previous release was 0.5.0 (2026-09-09).
Rows marked *refused for
verification* mean a finding of that kind is never sent to a provider on any
surface; a finding matched by a supported plaintext rule can still be
transmitted after the switch or consent workflow described in
[verification](verification.md).

| capability | 0.4.0 | 0.5.0 |
|---|---|---|
| Named rules | 109 | 110 (`encryption-key-assignment`) |
| Generic entropy tier | opt-in (`--include-entropy`) | opt-in; not run over OpenAPI / Swagger / AsyncAPI documents unless `--include-api-document-entropy` |
| Base64 / hex / percent-encoded credentials | not decoded | decoded one layer, rules run over the decoded text; refused for verification (`unsupported-transform`) |
| ZIP / tar / gzip archives | skipped as binary | opened in memory one layer deep; members scanned; member findings refused for verification (`unsupported-container`) |
| Archive coverage disclosure | — | containers, members, refusals and enumeration gaps counted separately from files |
| MCP archive-member handling | — | refusals quote member names through the untrusted-data wrapper; member context reason is accurate |
| Verification, consent gate, remediation, rotation | as documented | unchanged |
