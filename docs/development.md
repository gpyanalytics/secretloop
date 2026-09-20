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
Linux jobs and take nothing away.

The same suite and the same packaging smokes also run on **native Windows
ARM64, on a client edition** (`test-windows-arm (20)`, `test-windows-arm (22)`,
`test-windows-arm-two-user`, `packaging-windows-arm`; `windows-11-arm`).
Measured on that runner rather than assumed: **Microsoft Windows 11
Enterprise**, version 10.0.26200 build 26200, `ProductType 1` (workstation, not
Server), OS architecture ARM 64-bit, runner image `win11-arm64`
20260914.169.1, `PROCESSOR_ARCHITECTURE=ARM64` with `PROCESSOR_ARCHITEW6432`
unset, Node **20.20.2** and **22.23.2** from the arm64 tool cache, each
reporting `process.arch=arm64`. The job asserts all of that and **fails**
rather than warns, because an emulated x64 process presented as native ARM64
evidence would be worse than none.

**Node 18 is absent from that matrix and cannot be added.** nodejs.org
publishes no `win-arm64` build for any v18 release — v18.20.8 lists only
`win-x64-*` and `win-x86-*` files, and `win-arm64-*` first appears at v20. The
x64 jobs still cover 18. `engines.node` stays `">=18.0.0"`: it states the
lowest version the code supports, not a promise that every platform and
architecture has a binary for it.

On that runner the suite passes on **both** Node versions, and the two-account
job passes: the product runs as an ordinary local account through
`Start-Process -Credential` while a second ordinary account plays the attacker,
and the elevated builder is neither.

**The packaged npm smoke does not pass there**, and is reported rather than
worked around. Its MCP round trip gives each request 30 s;
`secretloop_verify` returns nothing within that. Measured in the same job, the
equivalent library-level verify completes in **5.8 s** with 7 subprocesses
(three `powershell.exe` inspections at 4,704 / 397 / 529 ms — the first is a
cold start and dominates — two `whoami.exe`, one `icacls.exe`), and the x64
packaged smoke completed the same call in **2.1 s**. So the consent path's own
cost does not account for the ceiling and **the cause is unresolved**. The VSIX
smoke passes on ARM64.

These jobs are **not** required checks either. Run 35275794564 at `54787ebb`:
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
0o600` at write time has no effect there, so the record's protection is its
security descriptor, not a mode. `src/consent-acl-win.ts` is what reads that
descriptor: the owner and access list of the store, of `pending` and of each
record, plus every folder from the drive root down to the store's parent, with
two deliberately different rules — store objects may name only this account,
SYSTEM and Administrators, while ancestors need only deny the power to delete,
rename or re-permission to everyone outside a small platform set. The wider set
above the store is not laxness: a stock `C:\` is owned by
`NT SERVICE\TrustedInstaller` and grants it full control, so the store rule
would refuse every real machine. It was measured
(`windows-consent-acl-revised-validation`), as was the attack it defends: a
record planted by a second ordinary account, once a protected parent rewrote its
*inherited* access list, looked private while its owner stayed the attacker, and
the product trusted it and transmitted.

Inspection runs the in-box `powershell.exe` with a **constant** script delivered
through `-EncodedCommand`, paths supplied on standard input — nothing is
interpolated into PowerShell source, no file is written, and no execution policy
is changed — and returns owner, access list and reparse state for every object in
one bounded call. Only security identifiers are compared, never account names, so
the result does not depend on the display language. `icacls.exe` is used for one
thing: setting the owner-only access list on a directory this process just
created. Missing tooling, a timeout, output past the cap, a non-zero exit, an
unparsable or incomplete answer and a failed enforcement all refuse; there is no
permissive fallback and no new dependency.

What it does not do: applying an access list does not revoke a handle another
process already holds, so the parent-chain check prevents that situation for a
store SecretLoop creates rather than revoking anything; for a store that already
existed these checks describe the present, not its history; and inspection is by
path while the work that follows is by path, so a replacement in between is not
detected by any account that already has the rights to make it. Tested on one
`windows-latest` image (Server 2025, NTFS, x64, Node 20, Windows PowerShell 5.1,
`en-US`) as an ordinary account against a second ordinary account, and on one
`windows-11-arm` image (Windows 11 Enterprise 10.0.26200, client, NTFS, arm64,
Node 20 and 22, `en-US`).

**One hosted image is not universal client support**, and the two results are
different evidence: the ordinary `test-windows*` jobs run **elevated** — GitHub
configures Windows runners as administrators with UAC disabled — so only the
two-account jobs say anything about ordinary-account behaviour. **Local accounts
do not establish domain-account coverage.** Not exercised, and so not claimed:
managed or relocated profiles, network and UNC locations (refused outright),
non-NTFS volumes, non-English hosts, and domain accounts.

Two things the ARM64 run measured that are worth carrying. A consent store under
that image's default workspace temporary directory is **refused**: `C:\a\_temp`
carries `Authenticated Users:(M)`, so the directories above the store really are
modifiable by any authenticated account, and the ancestor rule is right to
refuse. That is a fact about this runner image, not about Windows generally nor
about every x64 or ARM64 machine. And the Windows store check is **slow** there:
one `checkWindowsStore()` measured 6.4 s and 12.3 s on separate runs, both cold,
against a 20 s budget deadline for a whole operation, while a warm invocation in
the same job took 0.55 s. `src/consent-acl-win.ts` does not consult the
operation budget at all, so a Windows consent operation can run past that
deadline without refusing; that gap is open and is tracked in *Open items*.

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

- **The Windows ACL helper is not covered by the operation budget.**
  `src/consent-budget.ts` bounds helper calls, output bytes, directory entries
  and a 20-second deadline across one consent operation, and
  `src/consent-acl-macos.ts` consults it: it charges each invocation, passes
  `remainingMs(...)` to the child and rethrows a budget error rather than
  relabelling it. **`src/consent-acl-win.ts` imports none of that.** Its spawns
  use fixed `HELPER_TIMEOUT_MS` and `ENFORCE_TIMEOUT_MS`, and it never charges
  an invocation, so on Windows a consent operation can run past the deadline
  without refusing. Found while validating ARM64, where the cost is visible: a
  single `checkWindowsStore()` took **12.3 s** on `windows-11-arm`, and the same
  end-to-end verify took **17.9 s** on x64 — both against a 20 s allowance for
  the whole operation. Not a new weakness in the checks themselves; the refusals
  and their reasons are unchanged. Closing it changes subprocess behaviour on
  the authorization path and needs its own §5 review, so it is scoped
  separately rather than folded into a validation change.

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

  **The stat-to-open FIFO window — CORRECTED (Unreleased), on validated
  platforms.** A regular file replaced by a FIFO between a reader's type check
  and its open blocked the open indefinitely (measured in
  `secretloop-benchmark/f1-containment-design/`, E2, darwin and Linux). Every
  content open in the scanner's readers now uses `O_NONBLOCK` where
  `fs.constants` defines it and the
  opened descriptor is classified with `fstat` before any read; the swap is
  refused as `not-a-file` in milliseconds on darwin and Linux. On win32 the
  constant is undefined, the open is a plain read-only open, and behaviour is
  what it was; no FIFO can exist on an NTFS path and no Windows FIFO
  protection is claimed. Narrow claim: the demonstrated FIFO-open block is
  avoided on validated platforms. Not claimed: that filesystem operations are
  non-blocking in general, or that the scanner is immune to a hostile tree.
  Record: `secretloop-benchmark/f1-fifo-nonblocking-open/`.
  The comparator's report-file reader (`src/compare.ts`) received the same
  narrow correction separately: a report path that is a FIFO no longer blocks
  `secretloop compare` on darwin and Linux (exit 2, "not a regular file");
  on win32 the flag is undefined and the open is unchanged. Record:
  `secretloop-benchmark/compare-fifo-nonblocking-open/`.

  **Concern A — OPEN, with check-time hardening in the Unreleased candidate.**
  A path approved by `isInsideRoot` can resolve outside the root by the time
  the read opens it, at the final component *or through a replaced parent
  directory*. **One descriptor does not close this**: `openSync` resolves the
  name and follows symlinks, so the containment decision has to be made about
  the opened object. The Unreleased candidate makes exactly that decision, on
  every content descriptor, before its first read (`readChecked` in
  `src/walk.ts`): identity capture by `lstat` one syscall before the open,
  `fstat` comparison on the descriptor, and on Linux the kernel's own path for
  the descriptor from `/proc/self/fd` checked by path component against the
  canonical root. The binary header probe reads from that same checked
  descriptor; it used to open on its own and handed the acceptor 16 bytes of
  whatever that open resolved to. Every descriptor's outcome is disclosed
  (`openedFileChecks`, see [coverage](coverage.md#opened-file-checks)).

  **What that establishes, and what it does not.** Per descriptor, as the
  block records it: `kernelPath: verified` means no bytes were read before the
  kernel-recorded location, *at the check that immediately precedes the first
  read*, was found inside the root; `identity: verified` means every byte came
  from the object inspected one syscall before the open; `unavailable` means
  the descriptor was read without that check, and is disclosed as such. Measured and recorded (`f1-containment-design-review` and its timing
  addendum), the limits are: an outside object moved under the root after the
  open and before the check is accepted and read (MI1/MI2); an inside object
  moved out after the check is still read (MO1); the identity check alone
  cannot see a parent replaced between path resolution and the capture, so on
  darwin and Windows — no kernel path — that case is read (A2, B1); content can
  change in place. Windows and macOS get risk reduction, not the Linux check.
  Closing the open-time gap needs an open that cannot escape the root —
  `openat2(RESOLVE_BENEATH)` or descriptor-relative traversal — which Node does
  not expose and which would need a native addon this product will not take.
  `O_NOFOLLOW` was measured insufficient (it does not block traversal through a
  symlinked parent). The design options and their platform caveats are in
  `secretloop-benchmark/f1-reproduction-design/` and the three
  `f1-containment-design*` records. Concern A is **not** a release blocker and
  nothing here promotes it to one.

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
