# SecretLoop documentation

One authoritative page per topic. **Published 0.7.2** is the current release on
npm and the extension channels, and it is what these pages describe. Where a
capability is new in 0.6.0 the page says so, so a reader still on 0.5.1 can tell
what they do not have.

The table at the end of this page summarises what 0.5.0 changed from 0.4.0. 0.5.1
was a maintenance release: it added or changed no detector rules, and its fixes
are listed in the [changelog](../CHANGELOG.md).

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

- [The JSON report](reports.md) — the report schema, the comparison identities,
  what `secretloop compare` enforces, and what an eligible pair still does not
  establish.
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

Release status, current as of **2026-10-13**. This page is repository-only: it
is not shipped in the npm package or the VS Code extension, so it can carry
status that would go stale inside a published artifact.

[npm](https://www.npmjs.com/package/secretloop),
[Open VSX](https://open-vsx.org/extension/gpyanalytics/secretloop) and the
[VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=gpyanalytics.secretloop)
all serve **0.7.2** (published 11 October 2026, Asia/Kolkata), released from the
commit tagged `v0.7.2` (`4e63ef62`), which was `main` at publication. Each
channel's package was downloaded after publication and compared byte for byte
with the artifacts built in the release clean room. 0.7.2 is a
reliability-evidence release: no detection, rule, schema or consent-decision
change. Its one product change is four timing markers the Windows consent helper
writes to its own standard error, and it resolves none of the intermittent CI
failures those markers instrument; the
[changelog](../CHANGELOG.md#072--2026-10-11) lists what moved and what stays
open. The previous release was 0.7.1 (2026-10-05), a dependency and security
maintenance release; before that, 0.7.0 (2026-10-04) and 0.6.0 (2026-09-15).

`main` is ahead of the published 0.7.2. What has merged since is a text-report
fix, credential groups in the JSON report, workspace containment for the
editor's live verification and staged scan, a fix for names that begin with
`..`, a fix for file names git quotes, a fix for directory symlinks outside git,
a fix for SARIF locations, text-report hardening against crafted file names, a
fix for file names in history, a development-dependency fix, CI log
hygiene, tests, and a wider release security-review rule
([decision 0008](decisions/0008-consent-review-scope.md)).
The first nine change what SecretLoop does when it runs: the text report no
longer calls two different PKCS#12 keystores "the same value", the JSON report
now says which findings carry the same credential
([credential groups](reports.md#credential-groups)), the VS Code extension no
longer verifies files outside the open workspace
([the verification prompt](vscode.md#the-verification-prompt)), and files whose
names begin with `..` are scanned rather than skipped as outside the root, and
so are files whose names git quotes, which history now also names correctly
([what the scan discloses](coverage.md#what-the-scan-discloses)), and outside
git a scan lists a directory symlink instead of walking through it
([what is scanned](coverage.md#what-is-scanned)), and a SARIF location
percent-encodes the path so it names the right file
([SARIF](integrations.md#sarif)), and the text report prints control and bidi
characters in names and values as visible escapes ([options](cli.md#options)),
and history names a file exactly, spaces included, whatever prefix git is
configured to write. The first two are in `src/report.ts`, the
third in `src/extension.ts`, the fourth in `src/walk.ts`, `src/mcp-core.ts` and
`src/extension.ts`, the fifth in `src/walk.ts` and `src/history.ts`, the sixth
in `src/walk.ts`, the seventh and eighth in `src/report.ts`, and the ninth in
`src/history.ts`, so `out/cli.js`,
`out/mcp.js` and `out/extension.js` all no longer build byte-identical to 0.7.2.
Until the text-report fix, none of it changed what SecretLoop does when it runs.
The packaged
`package.json` is not identical, because its `test` script gains one entry. These
changes were not released on their own. They will ship with the next published
release: expected to be one that changes SecretLoop's behaviour, unless a
security or compatibility fix calls for an earlier release. Its version number
and date are not decided. The [changelog](../CHANGELOG.md#unreleased) lists them, and the
investigations 0.7.2 left open remain open.

0.7.0 changes no detection: rules, fingerprints, thresholds and severities are
those of 0.6.0. What changed is what a scan refuses and discloses — the consent
store is checked before it is trusted, the scanner checks the file it actually
opened before and, on Linux, after reading it, and the JSON report is
`schemaVersion` 5, so reports must be regenerated with 0.7.0 before they can be
compared. The [changelog](../CHANGELOG.md#070--2026-10-04) has the full list and
what is not in this release.

Everything 0.6.0 added is reporting and review: `secretloop compare`, the report
comparison metadata, MCP scope and suppression disclosure, the editor's post-fix
confirmation, and suppression reasons with scoped directives. **No rule,
threshold, severity or fingerprint changed**, so a tree reports the same findings
under 0.6.0 that it did under 0.5.1.

The table below covers 0.4.0 and 0.5.0 only; it predates both 0.5.1 and the
prepared 0.6.0, and is kept as the record of what those two releases changed.
Rows marked *refused for verification* mean a finding of that kind is never sent
to a provider on any surface; a finding matched by a supported plaintext rule can
still be transmitted after the switch or consent workflow described in
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
