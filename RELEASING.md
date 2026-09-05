# Releasing SecretLoop

Every item here exists because something went wrong once. Work through it in
order; the ordering is part of the checklist, not a suggestion.

A release that only changes documentation still runs the whole list. The
packaged artifacts contain `README.md` and `SECURITY.md`, so a docs change is a
change to what ships.

## 1. Build and test

- [ ] Full suite green on the required Node versions (CI: `test` on 18 and 20,
      `packaging` on 22).
- [ ] `npm run smoke:tarball` and `npm run smoke:vsix` green — CI runs both in
      the `packaging` job.
- [ ] Self-scan green — CI runs it against this repository on every change.
- [ ] `tsc -p ./` and `tsc -p tsconfig.tests.json` both exit 0.
- [ ] **Clean-room verification.** A fresh checkout at a sibling path, then
      `npm ci` → build → test → `npm pack --dry-run` showing exactly the
      intended files.

      Not the working tree, and **not under `/tmp`**: a checkout under
      `/private/tmp` makes `vsce ls` return zero files and `vsce package` fail
      on an entrypoint that is present. Use `../secretloop-pub-<version>`.

      The working tree is excluded for a reason of its own — 0.1.6 shipped a
      VSIX carrying dev dependencies because it was packaged from one, and
      0.1.7 existed only to republish it.

## 2. Security-tool guards

A scanner that leaks a credential is the worst possible headline, so these are
run against the built artifacts, not the source tree.

- [ ] **No credential leak.** Byte-search the unpacked tarball *and* the
      unpacked VSIX for real provider formats — `ghp_`, `sk-`, `sk_live_`,
      `AKIA`, `xox[baprs]-`, PEM blocks. The one expected match is
      `AKIAIOSFODNN7EXAMPLE`, AWS's published documentation sample, which
      appears inside the AWS rule's own allowlist and must be there.
- [ ] **No name leak.** Byte-search both artifacts for employer names,
      individual or reporter names, private-repository identifiers and real
      email addresses.

      Iterate the search terms one at a time and include a term you know is
      present as a control. A shell loop that silently fails to split its list
      searches for the concatenated string, finds nothing, and reports clean —
      a false negative on the check that matters most.
- [ ] **Scratch files excluded.** `PRIVATE-FINDINGS.md` and any local scratch
      file are gitignored and absent from both packages.
- [ ] **Redaction holds.** The redaction and mask tests pass; scan output never
      prints a raw secret.

## 3. Packaging integrity

- [ ] The VSIX contains no `node_modules`. (The packaged `package.json` still
      *declares* devDependencies — that is normal and harmless; what matters is
      that none are bundled.)
- [ ] The npm tarball contains exactly the intended files, with no stray
      `.vsix`, `.tgz`, `.sarif` or scratch file.
- [ ] `out/mcp.js` is present in the npm tarball and **absent** from the VSIX.
      The split is deliberate and documented on both sides: `.vscodeignore`
      excludes it because nothing in the extension host loads it, and
      `.npmignore` re-includes it because it backs the `secretloop-mcp` bin.
- [ ] Built from a clean checkout, never the working tree.
- [ ] **Runtime dependencies are still absent.** `package.json` has no
      `dependencies` key at all, and `npm ls --omit=dev --depth=0` is empty.

      This replaces "review `npm audit`", which is vacuous here: with no
      runtime dependencies there is no tree to audit, and every advisory npm
      reports belongs to build tooling a user never installs. A runtime
      dependency *appearing* is itself the finding.

      Note that `npm audit --package <name>` is not a real flag combination —
      npm ignores it and audits the current directory instead. To check what a
      user actually gets: install the published package in an empty directory
      and audit there.

## 4. Regression safety

- [ ] **Fingerprint stability.** Existing fingerprints (`path:rule-id:digest`)
      are unchanged. A changed fingerprint silently breaks every user's
      baseline, and the rule id is part of it — so moving a finding between
      rules changes it too.
- [ ] **Detection stability.** Scanner output is byte-identical to the previous
      release on a fixed corpus, unless the diff is exactly the intended new
      rules. Build the previous release in a separate worktree and compare
      ruleId, file, line, fingerprint, severity, confidence and redacted value.
- [ ] **No vacuous tests.** Every test added or touched this cycle has been
      RED-checked: break the property it claims to hold and confirm the test
      fails. A test that passes whether or not the property holds is worse than
      no test, because it is counted.

## 5. Security review (conditional)

- [ ] **If** the release touches `src/mcp*.ts`, `src/consent.ts`,
      `src/verify*.ts`, `src/workspace*.ts` or `src/workspace-verify.ts`: an
      adversarial re-review of the changed invariants is complete and findings
      are resolved.

      A large rebase or merge onto that surface counts as touching it, even
      with no logical change. Detection, precision and rules changes do not.

      `git diff --name-only <previous-tag>..HEAD -- 'src/mcp*.ts'
      src/consent.ts 'src/verify*.ts' 'src/workspace*.ts'` settles it. Empty
      means a prior review still applies.

      The review attacks each invariant rather than confirming it: consent
      gate, commitment integrity, consume-before-transmit, TOCTOU, workspace
      boundary, untrusted content, no-leak, protocol purity, and git argument
      smuggling.

## 6. Docs accuracy

Verified against the shipped source, never from memory.

- [ ] Rule count matches `grep -c '^    id:' src/rules.ts` — in `README.md`,
      `docs/MARKET.md`, `docs/PRIMER.md` and `bench/*`.
- [ ] Verifier numbers use three distinct figures without conflating them:
      *N rules have verifiers*, *covering M providers*, *K of which can
      transmit*. They are not interchangeable, and "N providers" is the
      mistake that keeps recurring.
- [ ] The MCP tool count and list match the tools the server registers.
- [ ] `SECURITY.md` names **all** credential-egress surfaces currently
      shipping: the `--verify` flag, the `secretloop.enableLiveVerification`
      setting, and the `secretloop approve` consent gate for `secretloop_verify`.
      Add any new one.
- [ ] Install and command examples name **the version being released** — check
      this *after* the version bump, since the bump is what makes them stale.
- [ ] No new unsupported claims: "only tool", "works everywhere", "zero false
      positives", or "validated" without a record behind it.
- [ ] Historical numbers in `CHANGELOG.md` are untouched. They record what
      shipped at the time and are correct as history; only the new section is
      added.

## 7. Release mechanics, in order

The ordering matters. Publishing before the source is public means the registry
carries a version nobody can fetch the source for — and `SECURITY.md` invites
reviewers to check an installed version against the public tag.

1. [ ] **Bump the version with the tool:**
       `npm version <version> --no-git-tag-version`.

       Not a hand-edit. `package-lock.json` carries **two** root `version`
       fields alongside `package.json`, and editing one by hand leaves them
       desynced — which has blocked tooling in this repository before. Confirm
       afterwards that the lockfile diff contains *only* those version fields
       and no dependency change.
2. [ ] Date the CHANGELOG heading. This is the freeze.
3. [ ] **Push `main` before publishing.** The commit being released must exist
       on the remote first.
4. [ ] Publish to npm from the clean-room checkout. Expect a 2FA one-time
       password prompt — it needs a browser round-trip and cannot be scripted.
5. [ ] **Tag the release commit**, annotated, and push the tag. Not an earlier
       commit: the tag has drifted behind `main` between releases more than
       once, and a drifted tag no longer describes what was published.
6. [ ] All channels end on the same version — npm, VS Code Marketplace,
       Open VSX.
7. [ ] GPY Analytics attribution; no `Co-Authored-By` trailer on any commit.

## 8. After publishing

- [ ] `npm view secretloop version` matches the released version.
- [ ] The VS Code Marketplace and Open VSX listings show it. Marketplace
      indexing can lag; check, do not wait indefinitely.
- [ ] `main` and the tag are pushed and in sync — `git rev-parse v<version>^{}`
      equals `git rev-parse origin/main`.
- [ ] **Revoke every token used.** Immediately.
- [ ] Remove the clean-room worktree, and prune any left from earlier releases.
