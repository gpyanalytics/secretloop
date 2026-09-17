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

The same suite and the same two packaging smokes also run **natively on
Windows** (`test-windows (18)`, `test-windows (20)`, `packaging-windows`;
`windows-latest`, which resolved to Windows Server 2025 10.0.26100, image
`windows-2025-vs2026`, Node 18.20.8, 20.20.2 and 22.23.2, x64, Git for
Windows 2.55.0). These jobs are **not** required checks; they add beside the
Linux jobs and take nothing away. Run 35275794564 at `54787ebb`:
**1,560 passed, 0 failed, 18 skipped** per Node major, identical on both,
from 57 files — the same 1,578 cases the suite runs on POSIX, where the 18
skips run (1,578 passed, 0 failed on Linux in the same run and on darwin at
the same source). No product source changed to reach that; the four
corrections were all in the harness — a hard-coded `/tmp` in
`history.test.ts`, two `.cmd`-shim spawns (`npx`, `node_modules/.bin/esbuild`)
that a shell-less spawn cannot start on win32, and `smoke-vsix.sh` comparing
a CRLF-converted manifest line by line.

A skip is **counted apart from a pass**. `tests/harness.ts` gained `skip`,
and a platform-gated case that used to return early as "ok" now prints
`skip -` with its reason and a separate count in the summary. The 18 cases
Windows does not run, each stated in its own output: a FIFO (no `mkfifo`
target on win32); a name replaced under an open descriptor, in both the
scanner and the comparator readers (Windows deletes the name only when the
last handle closes, so re-creating it fails with `EPERM` — a platform
property, not a reader guarantee; the skip fires only for that refusal, so a
broken fixture still fails); POSIX mode bits on the consent record (its
content — a commitment, never the credential — is still asserted on Windows)
and on a restored hook; the chmod-000 permission path; a filename carrying ESC
and newline, and a directory named with `<` and `>`, both refused by NTFS
(seven MCP archive-disclosure cases share that container fixture); three
backslash-in-filename cases; and a `pgrep` child count. What is **measured**
on Windows and was not before: the walker's `path.sep` conversion into
`binaryIdentity` through the real CLI on both the git and the fallback
enumeration, every bounded-read case that does not need a FIFO or a name
swap, directory removal after every reader outcome (a descriptor leak shows
as a failed `rmSync` on Windows, where the POSIX fd-count probe cannot see
it), and the symlink containment fixtures, which the hosted runner permits
because it runs elevated.

Two limits of that measurement. **One hosted runner is not "Windows
support"**: a non-elevated user without Developer Mode would get `EPERM`
from `symlinkSync`, and the containment suites would fail rather than skip.
And **the pending consent record is not owner-only on Windows**: `mode:
0o600` at write time has no effect there, so the record's protection is the
ACL of the profile directory it lives under, not a mode. That is a real
platform difference in `src/consent.ts`, disclosed here; it is not changed.

## Layout

```
src/
  cli.ts            standalone binary: scan / staged / history / mask / approve
  extension.ts      activation, diagnostics, code actions, commands
  mcp.ts            MCP transport; mcp-core.ts holds the tool logic and invariants
  scanner.ts        rule + encoded + entropy passes, tiers, suppression, fingerprints
  rules.ts          the named rules (110) with keyword prescreen and allowlists
  entropy.ts        the generic high-entropy tier and its structural filters
  encoded.ts        one-layer base64 / hex / percent decoding
  archive.ts        zip / tar / gzip / tgz, in memory, one layer
  api-document.ts   OpenAPI / Swagger / AsyncAPI classifier
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
leak, protocol purity, git argument smuggling.

**Reviewed endpoints.** A §5 review covers the commit it was run against and
nothing later; a change to the surface after that endpoint needs its own
reassessment.

- Up to and including the `v0.5.0` tag (`fd6637d7`): the review found two
  low-severity disclosure issues in the MCP layer, both fixed in PR #49 with
  RED-checked tests; its other findings were documented limitations, not
  defects.
- `fd6637d7..53b5750`: re-reviewed against all nine invariants. The settling
  command reports exactly two changed surface files,
  `src/consent.ts` (PR #59, `readRecord` id-match) and `src/verify.ts`
  (PR #56, GitHub and Slack verification diagnostics). All nine established;
  no defect found. The consent change is **defensive hardening** — no
  reachable bypass was demonstrated, and none is claimed.
- `53b5750..33a21020` (the 0.5.1 candidate source): the settling command
  reports **no changed surface file**. The only changes after the endpoint are
  `docs/development.md`, `tests/verify-diagnostics.test.ts` and lockfile
  version fields, so the review above still applies and **the endpoint is not
  extended**. The dependency updates in that range do change the AWS SDK bytes
  bundled into all three artifacts; that was assessed offline rather than under
  §5, and the changed passive-refresh code is unreachable from both callers,
  each of which passes explicit static credentials.
- `53b5750..403352ef` (the 0.6.0 candidate source): re-reviewed against all nine
  invariants. The settling command reports two changed surface files,
  `src/mcp-core.ts` and `src/workspace.ts`. All nine established; **no
  release-blocking defect found**. Every invariant-bearing function is
  byte-identical to the endpoint — `resolveRoot`, `withinAllowedRoots`,
  `safeReal`, `setAllowedRoots`, `wrapUntrusted`, `quoteUntrusted`,
  `projectFinding`, `redactValue`, `toolVerify`, `toolGetFinding`,
  `isInsideRoot` and `validateRoot` — and `src/consent.ts` and `src/verify.ts`
  have **no diff at all** in the range. The full record is
  `secretloop-benchmark/release-0.6.0-security-review/`.

  **The endpoint is `403352ef`, the reviewed commit — not the release commit.**
  The 0.6.0 release-preparation commit that follows it changes the version,
  `CHANGELOG.md`, `README.md`, `SECURITY.md` and this file, and touches no file
  the settling command names. It was not itself reviewed under §5 and must not
  be described as the endpoint.

**Three commits, kept apart.** 0.6.0 has three commit identities and conflating
them would misdescribe the release:

| | commit | what it is |
|---|---|---|
| review endpoint | `403352ef` | what §5 was run against |
| artifact build | `5686944` | what the published `.tgz` and `.vsix` were built from |
| tag target | `96070bf6` | what `v0.6.0` names, and `main` |

The artifacts were **not** rebuilt for the tag, so `tree(5686944)` —
`563d10bd…` — and `tree(96070bf6)` — `54fbd4d4…` — are **different trees**.
They differ by ten documentation files merged after the build. Whole-tree
equality is therefore false and is not claimed anywhere.

What is claimed, and was verified blob by blob: every **packaging input** is
byte-identical across the two. `package.json`, `package-lock.json`, `.npmignore`,
`.vscodeignore`, `scripts/vsix-manifest.txt`, the bundle source under `src/`, and
the packaged `LICENSE`, `README.md`, `SECURITY.md` and `docs/icon.png` all match,
with zero files changed under `src/`, `scripts/` or `.github/`. So a reader who
checks an installed 0.6.0 against the tag finds the same manifest, ignore lists,
bundle source and shipped documentation; what differs is repository documentation
that is in neither artifact.

That is equivalence of **inputs**, not reproducibility. No rebuild from
`96070bf6` was performed or measured, and `npm pack` and `vsce` embed timestamps,
so a rebuild would not be expected to reproduce the published bytes. Bit-level
provenance belongs to `5686944`. The tag was placed on `96070bf6` rather than the
build commit because RELEASING.md §8 requires `main` and the tag to be in sync,
and §7 records that the tag has drifted behind `main` more than once.

  **Limitations of that review, carried forward:** no actual MCP-client
  execution and no wire-level protocol probe were performed — protocol purity
  was assessed from the manifest and source only; the review predates the
  release artifacts, so every §3 artifact gate was outside it.

## Open items

Accurate as of the 0.6.0 release (published 2026-09-15), except where an entry
names an earlier release:

- **F-1: `src/walk.ts` resolves the file name more than once.** Two concerns
  were recorded under one label. **Concern B (size cap) is CORRECTED in the
  Unreleased candidate. Concern A (containment) remains OPEN.**

  Both were **pre-existing** — every filesystem operation and its order was
  identical at `v0.5.1`, `v0.6.0` and the 0.6.0 documentation merge — and both
  were **demonstrated under controlled interleaving, not in an ordinary run**.
  Reaching either needs an actor with concurrent write access to the scanned
  tree, who can already place content where the scanner will read it. No
  exploitation was observed, and no frequency is claimed.

  A note on an earlier wording here: this said "resolves the file name twice"
  and "byte-identical at `v0.5.1`". Measured, the text path resolves the name
  three times and a full `scanFiles` run performs **seven** operations on one
  path; and the enclosing functions are *not* byte-identical at `v0.5.1` — the
  skip-reason labels changed in 0.6.0 — though every filesystem operation and
  its order is. "Operationally identical" is the accurate phrase.

  **Concern B — CORRECTED (Unreleased).** The cap now bounds the read: one
  descriptor, `fstat` on it, every byte from it, the limit enforced while
  reading. Measured before: a 64-byte cap and 4096 bytes read. See the
  Unreleased changelog entry and
  `secretloop-benchmark/f1-bounded-file-reads/`.

  **Concern A — OPEN.** A path approved by `isInsideRoot` can resolve outside
  the root by the time the read opens it, at the final component *or through a
  replaced parent directory*. **One descriptor does not close this**: `openSync`
  resolves the name and follows symlinks, so the containment decision would have
  to be made about the opened object, or the open would have to not follow
  links. Measured on macOS: `O_NOFOLLOW` refuses a final-component symlink but
  **does not block traversal through a symlinked parent**, so it is not
  sufficient on its own; and Node exposes no `openat` equivalent, so
  descriptor-relative traversal would need a native addon this product will not
  take. The design options and their platform caveats are in
  `secretloop-benchmark/f1-reproduction-design/`. Concern A is **not** a release
  blocker and nothing here promotes it to one.

  **Native Windows validation does not touch either concern.** The bounded
  readers now run on a Windows runner (see *Build and test*), which measures
  the cap, the classifications and descriptor cleanup there. It measures
  nothing about containment: Concern A and the stat-to-open FIFO window are
  exactly as open on Windows as on POSIX, and the fact that Windows refuses
  to replace a name under an open descriptor is a property of that platform's
  delete semantics, not a containment guarantee — the open itself still
  resolves the name. Whether device/inode checks would close Concern A is
  likewise not established by any Windows run.

- **0.5.1 is published.** npm, Open VSX and the VS Code Marketplace all serve
  0.5.1, released from commit `88d2197` and tagged `v0.5.1`. The published npm
  tarball and both extension packages were downloaded and verified byte-identical
  to the artifacts the release gates ran against. The previous release, 0.5.0
  from `fd6637d7` and tagged `v0.5.0`, was verified the same way at the time.
- **Dependency advisories: closed.** PR #52 refreshed js-yaml to 4.3.2 and qs
  to 6.16.0 in the lockfile only, resolving the Dependabot alert and the two
  `qs` advisories in the release-tool chain. Full and production audits both
  reported zero on 2026-09-09, and again on 2026-09-11 for the 0.5.1 release.
  Audit results are point-in-time and are re-run at each release.
- **The timing-dependent cancellation test is fixed, shipped in 0.5.1.**
  `history.test.ts` "cancelling mid-scan stops it well short of the end" failed
  once on the push-to-main run for PR #49's merge. Its assertion was a proxy for
  "SIGTERM truncated git's output", which holds only when the kill wins a race
  against git writing the rest. Cancellation now stops parsing at the abort
  point, so the test asserts an exact commit count and no longer depends on
  delivery timing.
- **Live-host validation.** Real extension-host behaviour was exercised at
  `53b5750` and passed 17/17; that is the source identity that run covers. For
  0.5.1 the **published VSIX was never installed into a running host**. For
  0.6.0 it was: release preparation installed the VSIX into an isolated profile
  and qualified the installed bytes at **11 PASS, 0 FAIL, 3 INFO**, and after
  publication the VSIXs downloaded from Open VSX and the Marketplace were each
  installed into a throwaway profile and verified byte-identical to the frozen
  artifact. Note the boundary: those post-publication installs verified
  **identity**, not behaviour — no command was invoked and no scenario run. A VS
  Code UX review — notifications, diagnostics, prompts — needs a person at a
  screen and has **not** been done. **Actual MCP-client validation remains NOT
  RUN**: the stdio exchanges on record are protocol probes, not a client.
  Neither is a release gate; `RELEASING.md` requires neither.
- **Stale strings in code.** Closed: the MCP `secretloop_scan` description no
  longer states a rule count, and SECURITY.md's supported-version line was
  corrected in the documentation consolidation. The RELEASING.md §6 count check
  now lists every page that states the current count and says which counts are
  deliberately historical.
- The [backlog](project/backlog.md) lists the parked engineering follow-ups.
