# SecretLoop — Release Checklist

Run every item before publishing any version. This encodes lessons from past
releases rather than good intentions, so each entry says what it is defending
against. Do not skip steps; order matters where noted.

A release that only changes documentation still runs the whole list. `README.md`
and `SECURITY.md` ship inside the packaged artifacts, so a docs change is a
change to what users receive.

## 1. Build and test

- [ ] Full suite green on the required Node versions (CI enforces: `test` on
      18 and 20).
- [ ] `smoke:tarball` and `smoke:vsix` green (CI enforces: the `packaging`
      job, on Node 22).
- [ ] `self-scan` green (CI enforces — the tool scans its own repository).
- [ ] `tsc -p ./` and `tsc -p tsconfig.tests.json` both exit 0.
- [ ] **Clean-room verification:** a fresh sibling worktree — **not** `/tmp`,
      **not** the working tree — then `npm ci` → build → test →
      `npm pack --dry-run` showing exactly the intended files.

      Not the working tree because 0.1.6 shipped a VSIX carrying dev
      dependencies packaged from one, and 0.1.7 existed only to republish it.
      Not `/tmp` because a checkout under `/private/tmp` makes `vsce ls`
      return zero files and `vsce package` fail on an entrypoint that is
      present. Use `../secretloop-pub-<version>`.

## 2. Version bump — use the tool, do not hand-edit

- [ ] `npm version <x.y.z> --no-git-tag-version`. It moves `package.json` and
      **both** `package-lock.json` root version fields. Hand-editing
      `package.json` alone desyncs the lockfile, which has blocked tooling in
      this repository before.
- [ ] The lockfile diff contains *only* those version fields — no dependency
      change.
- [ ] **`"dependencies"` is still ABSENT**, not merely empty. A runtime
      dependency appearing is itself a finding: SecretLoop is
      runtime-dependency-free by design, and that is what keeps `npm audit` at
      zero rather than luck.

      Note `npm audit --package <name>` is not a real flag combination — npm
      ignores it and audits the current directory, reporting build tooling a
      user never installs. To see what a user gets: install the published
      package in an empty directory and audit there.

## 3. Security-tool guards — a reviewer checks these first

Run against the **built artifacts**, not the source tree.

- [ ] Byte-search the built tarball **and** VSIX for any real credential or
      high-entropy literal. The only expected match is a documented sample
      inside a rule's own allowlist — AWS's `AKIAIOSFODNN7EXAMPLE` — which is
      a required fixture, not a leak.
- [ ] Byte-search both artifacts for any employer, reporter or personal name,
      or real email address. **None may appear.**

      Use a search that actually word-splits, and include a term you know is
      present as a control. A shell loop that fails to split its list searches
      for the concatenated string, matches nothing, and reports clean — a
      false negative on the check that matters most.
- [ ] `PRIVATE-FINDINGS.md` and any scratch file are gitignored and absent
      from both packages.
- [ ] `out/mcp.js` is in the npm tarball and **absent** from the VSIX. The
      split is deliberate and documented on both sides: `.vscodeignore`
      excludes it because nothing in the extension host loads it,
      `.npmignore` re-includes it because it backs the `secretloop-mcp` bin.
- [ ] No `node_modules` bundled in the VSIX. The packaged manifest still
      *declares* devDependencies — that is normal; what matters is zero
      bundled `node_modules`.

      A root-level file added this cycle is the case to watch: `.vscodeignore`
      is a denylist, so anything new ships by default. `smoke:vsix` catches it
      by diffing against `scripts/vsix-manifest.txt`, and has done so twice.

## 4. Regression safety

- [ ] **Fingerprint stability.** Existing fingerprints (`path:rule-id:digest`)
      unchanged — a changed fingerprint silently breaks user baselines, and
      the rule id is part of it, so moving a finding between rules changes it
      too.
- [ ] **Detection stability.** Scanner output byte-identical to the prior
      release on a fixed corpus, unless the diff is the explicitly intended
      new rules. Build the prior release in a separate worktree and compare
      ruleId, file, line, fingerprint, severity, confidence and value.
- [ ] **No vacuous tests.** Any test touched or added this cycle FAILS when
      its property is broken (RED-checked). A test that passes either way is
      worse than no test, because it is counted.

## 5. Security review (conditional)

- [ ] **If** this release touches the security-critical surface —
      `src/mcp*.ts`, `src/consent.ts`, `src/verify*.ts`, `src/workspace*.ts`,
      `src/workspace-verify.ts` — an adversarial re-review of the changed
      invariants is complete and findings resolved.

      A large rebase or merge onto that surface **counts as touching it**,
      even with no logical change: verify the invariants survived.
      Detection, precision and rules-only changes do **not** require this.

      `git diff --name-only <previous-tag>..HEAD -- 'src/mcp*.ts'
      src/consent.ts 'src/verify*.ts' 'src/workspace*.ts'` settles it. Empty
      means a prior review still applies.

      The review attacks each invariant rather than confirming it: consent
      gate, commitment integrity, consume-before-transmit, TOCTOU, workspace
      boundary, untrusted content, no-leak, protocol purity, git argument
      smuggling.

## 6. Docs accuracy — verify against shipped source, not memory

- [ ] Rule count matches `grep -c '^    id:' src/rules.ts` — `README.md`,
      `docs/MARKET.md`, `docs/PRIMER.md`, `bench/*`.
- [ ] Verifier numbers use three distinct, non-conflated metrics: *N rules
      with verifiers* / *M providers* / *K can transmit*. Do not write
      "N providers" for the rule count — that is the error that keeps
      recurring.
- [ ] The MCP tool count and list match the tools the server registers.
- [ ] `SECURITY.md` names **all** credential-egress surfaces shipping: the
      `--verify` flag, the `secretloop.enableLiveVerification` setting, and
      the `secretloop approve` consent gate for `secretloop_verify`. Add any
      new one.
- [ ] Install and command examples name the version being released — check
      **after** the bump, since the bump is what silently re-stales them.
- [ ] No new unsupported claims: "only tool", "validated" without a record,
      "works everywhere", "zero false positives", "rare", "best".
- [ ] `CHANGELOG.md`: only the new dated section added; historical numbers
      untouched. They record what shipped at the time and are correct as
      history.

## 7. Release order and mechanics — order matters

- [ ] **Release commits go through a PR** so the required checks actually run.
      A direct push to `main` bypasses the gate, and the gate is the reason
      the checks exist.
- [ ] **Push `main` before `npm publish`.** A version on npm whose source is
      not yet public undercuts `SECURITY.md`'s own invitation to check an
      installed version against the public git tag.
- [ ] `npm publish` from the clean-room checkout — completes 2FA in a browser
      and cannot be scripted — then `npm view secretloop version` confirms it.
- [ ] **Open VSX:** publish with a fresh `OVSX_PAT`.
- [ ] **VS Code Marketplace:** build the VSIX and upload through the publisher
      portal at `marketplace.visualstudio.com/manage/publishers/gpyanalytics`.
      This is the manual route; the Azure PAT route is abandoned. Confirm the
      uploaded VSIX carries the corrected `SECURITY.md`.
- [ ] **Tag the release commit** and push it:
      `git tag -a v<x.y.z>` then `git push origin v<x.y.z>`.

      The tag has drifted behind `main` more than once. Always tag the actual
      release commit, and confirm `git ls-remote --tags origin` dereferences
      to it — `v<x.y.z>^{}` must equal the released commit.
- [ ] All channels end on the **same** version: npm, Open VSX, Marketplace,
      and the tag.

## 8. After publishing

- [ ] `npm view secretloop version` equals the released version.
- [ ] Open VSX and Marketplace listings show it. Marketplace indexing can lag;
      check, do not wait indefinitely.
- [ ] `main` and the tag are pushed and in sync.
- [ ] **Revoke the publish tokens immediately** — the npm token, `OVSX_PAT`,
      any PAT. A live publish credential is precisely what this tool exists to
      catch, and leaving one active would be the worst possible way to learn
      that lesson.
- [ ] Prune stale release worktrees when convenient.

## Note — CI publish (Tier 2), and when to build it

Publishing is manual today, which is what this checklist describes. Automate it
with a tag-triggered CI publish when **any** of the following becomes true:

- releases reach roughly monthly frequency;
- a reviewer requires build provenance before adopting;
- a second publisher is onboarded.

When that happens, build it through **npm OIDC trusted publishing** — provenance
is included and **no npm token is stored**. Keep the extension channels manual.
SHA-pin every action, use an environment-protected workflow, and publish only on
green.

Never store a live publish token in CI for a security tool. The blast radius of
a leaked publish credential is every user who installs the next version, and a
tool whose whole purpose is finding exposed credentials should not be keeping
one where a workflow can read it.
