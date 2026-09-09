# Development

How the repository is built, tested and changed, and the conventions that keep
its claims honest. Contribution mechanics are in
[CONTRIBUTING.md](../CONTRIBUTING.md); release mechanics are in
[RELEASING.md](../RELEASING.md).

## Build and test

```bash
npm ci
npm run compile          # tsc -p ./
npm run bundle           # esbuild -> out/cli.js, out/mcp.js, out/extension.js
npm test                 # type-checks the suite, then runs every test file
```

`npm test` first runs `scripts/check-build-fresh.js`, which fails when `out/`
is older than `src/`, because several tests drive the built CLI. The suite was 45 files, 1,223 tests and 0 failures in the CI run recorded for
the merge of PR #49 (`main` at `90ddaa0f`); this documentation pass did not
rerun the full suite. It needs no network and plants no real credential —
every fixture is generated at runtime from a fixed seed or built by
concatenation, which is why scanning this repository reports nothing from its
own tests.

CI runs the suite on Node 18 and 20, the packaging smoke checks on Node 22
(`smoke:tarball`, `smoke:vsix`), and a self-scan of the repository with
`.github/secretloop.ci.json`. All four are required checks on `main`.

## Layout

```
src/
  cli.ts            standalone binary: scan / staged / history / mask / approve
  extension.ts      activation, diagnostics, code actions, commands
  mcp.ts            MCP transport; mcp-core.ts holds the tool logic and invariants
  scanner.ts        rule + encoded + entropy passes, tiers, suppression, fingerprints
  rules.ts          the named rules (110) with keyword prescreen and allowlists
  entropy.ts        the generic high-entropy tier and its structural filters
  encoded.ts        one-layer base64 / hex / percent decoding (main)
  archive.ts        zip / tar / gzip / tgz, in memory, one layer (main)
  api-document.ts   OpenAPI / Swagger / AsyncAPI classifier (main)
  pkcs12.ts         file-level PKCS#12 keystore detector
  config.ts         .secretloop.json, globs, fingerprints, baselines
  walk.ts           enumeration, containment, size and binary gates
  workspace.ts      the one scan path shared by CLI, editor and MCP
  history.ts        streaming git log -p parser with argument guards
  verify.ts         the 18 verifiers; verify-meta.ts is metadata only
  consent.ts        durable, single-use consent records
  report.ts         text / JSON / SARIF
  remediate.ts, rotate.ts, hooks.ts, settings.ts, node-guard.ts
tests/              one file per concern; harness.ts is the runner
bench/              benchmark generators, scorers and records
scripts/            build-freshness check and packaging smoke tests
```

## Adding a rule

Add an entry to `src/rules.ts`:

```ts
{
  id: "acme-api-key",
  description: "Acme API Key",
  regex: /\bacme_[A-Za-z0-9]{32}\b/g,   // must carry the g flag
  fullMatch: true,                       // false = the secret is capture group 1
  keywords: ["acme_"],                   // literal prescreen; the regex is skipped without it
  entropy: 3.5,                          // optional floor on the captured value
  allowlist: [/^acme_test_/],            // rule-scoped false positives
  severity: "critical",
}
```

Then add a sample to `positiveSamples` in `tests/fixtures.ts`; `rules.test.ts`
fails if any rule lacks one, if a regex is not global, if a capture rule has no
capture group, if two named rules match the same span anywhere in the corpus,
or if a pattern backtracks catastrophically. Fix a span overlap with an
allowlist, never with a tiebreak. Rule ids are baseline identity: renaming one
invalidates every `excludeRules` entry and every accepted finding, so a rule id
never changes. Update the rule count where the documentation states the
current number (README, `docs/project/*`, `docs/coverage.md`) and add a
changelog entry under **Unreleased**.

## Evidence conventions

Detection, verification and MCP changes in this repository are landed with the
evidence attached, not asserted:

- **RED before GREEN.** A test added or touched for a change is run against the
  unchanged code first and must fail behaviourally; a compile error is not RED,
  and a test that passes either way is worse than none because it is counted.
- **Predeclared expectations.** Benchmark deltas, scope sentences and structured
  accounting are frozen and hashed before a scan runs; comparison checkers are
  exercised on synthetic mutations (a missing addition, an extra finding, a
  changed survivor, a wrong count) and must reject each.
- **Identities, not intent.** Every measurement is bound to the SHA-256 of the
  implementation diff and of the scanner bundle it ran; if code changes, the
  identities are re-recorded before affected gates rerun.
- **Populations stay separate.** Frozen labels are never rewritten; additions
  carry additive label files; historical and full populations are reported side
  by side.
- **A decision you cannot observe is one you cannot verify.** Every suppression,
  skip and refusal names itself in the scope sentence, the Output channel or the
  MCP audit log.
- **Verify the artifact, not the ignore rules.** `npx vsce ls`, `npm pack
  --dry-run` and the packaging smoke tests read what would ship.

The measurement records live in a private benchmark workspace; the public docs
cite them by SHA-256 rather than by path. The [decision records](decisions/README.md)
summarise the evidence behind each scope decision.

## Security-critical surface

Changes to `src/mcp*.ts`, `src/consent.ts`, `src/verify*.ts` or
`src/workspace*.ts` require the adversarial re-review in RELEASING.md §5
against the invariants: consent gate, commitment integrity,
consume-before-transmit, TOCTOU, workspace boundary, untrusted content, no
leak, protocol purity, git argument smuggling. The review for the current
`main` range found two low-severity disclosure issues in the MCP layer, both
fixed in PR #49 with RED-checked tests; its other findings were documented
limitations, not defects.

## Open items

Accurate as of the 0.5.0 preparation (2026-09-09):

- **0.5.0 is prepared and not published.** The version is stamped and the
  RELEASING.md prepublication gates have been run on the candidate; the release
  pull request, the publication steps and the tag remain. Until 0.5.0 is
  published, nothing in this section is in a package a user can install.
- **Dependency advisories: closed.** PR #52 refreshed js-yaml to 4.3.2 and qs
  to 6.16.0 in the lockfile only, resolving the Dependabot alert and the two
  `qs` advisories in the release-tool chain. Full and production audits both
  reported zero on 2026-09-09. Audit results are point-in-time and are re-run
  at each release.
- **A timing-dependent test flaked once in CI.** `history.test.ts` "cancelling
  mid-scan stops it well short of the end" failed on the push-to-main run for
  PR #49's merge and passed on an identical-commit rerun and in every other
  recorded run. The flake is not fixed.
- **Live-host validation.** The VS Code extension host and live MCP clients were
  not exercised for the `main` changes; wiring was compiled and inspected and
  the shared engine is unit-tested.
- **Stale strings in code.** Closed: the MCP `secretloop_scan` description no
  longer states a rule count, and SECURITY.md's supported-version line was
  corrected in the documentation consolidation. The RELEASING.md §6 count check
  now lists every page that states the current count and says which counts are
  deliberately historical.
- The [backlog](project/backlog.md) lists the parked engineering follow-ups.
