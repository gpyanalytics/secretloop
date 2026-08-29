# SecretLoop — Roadmap

**Locked August 2026.** Supersedes earlier planning drafts. Statuses below
reflect the actual repository, not older plans — several items that appear as
"pending" in older documents are finished and must not be redone.

**The governing rule:**

> Every new feature must either increase user value or provide market evidence.
> If it does neither, don't build it.

**The two sequences this roadmap follows:**

```
business    LOCAL TOOL → REAL USERS → REPEATED USE
                       → REQUEST FOR TEAM VISIBILITY → BACKEND

product     DETECTION → LIVENESS → AGENT EXPOSURE
                      → FAN-OUT → DRIFT → LIFECYCLE
```

The second is only built where the first justifies it.

---

## Done — do not redo

| item | evidence |
|---|---|
| Fingerprint design, baseline v2 | `202984f` — 17 tests, context strategy for password-bearing rules |
| Pre-commit hook, path resolution and chaining | `b1b5191`, `13566e7` |
| History scan streaming | `c9c73d6` — replaced the blocking `spawnSync` |
| Workspace/CLI scan divergence | `6d99ee7` — one enumeration path |
| Duplicate finding merging | `a8bec2a` — named rule wins, `alsoMatched` recorded |
| SecretGuard compatibility layer removed | `03fd981` |
| SARIF key → `secretloopFingerprint/v2` | `8a91d6c` |
| CI exclusion narrowed to fixture files | `af7747f` |
| AWS migration confirmed against a running host | `818a614` |
| Marketplace publisher set | `8379f38` — `gpyanalytics` |
| **Extension-host validation — all five flows** | prompt, quick-fixes, `.env` refusal, hook chain, hook restore |

Every item from the original architecture review is closed. Nothing in the repo
is flagged as unverified.

---

## Phase 0 — Ship hygiene (~30 minutes)

- [ ] GitHub repo description and topics (§Appendix A)
- [ ] Move `BACKLOG.md` and `MARKET.md` into `docs/`
- [ ] Delete the two stale `.vsix` files at the repo root
- [ ] `rm -rf ~/Desktop/sl-scratch`
- [ ] Remove `secretloop.enableLiveVerification` from user settings
- [ ] Verify `gpyanalytics` is claimable at marketplace.visualstudio.com/manage

**Exit:** repo is presentable to a stranger.

---

## Phase 1 — CLI to npm (~half a day)

npm before the Marketplace, deliberately: npm is reversible within 72 hours and
affects nobody's editor. The extension ID is permanent.

### Three decisions

**1. Package name.** First command, before anything else:

```bash
npm view secretloop
```

Available → `npx secretloop history --verify` is the demo line. Taken →
`@gpyanalytics/secretloop`, which works but reads worse out loud.

**2. One package or two.** The repo produces `out/cli.js` and
`out/extension.js`. Publishing both ships extension code to CLI users for no
reason. **Recommended:** same repo, narrow `files` field. One version, one
release.

**3. The `.npmignore` / `.vscodeignore` / `files` interaction.** `vsce` refuses
to run when a `.vscodeignore` and a `files` field both exist. This already
shaped the current packaging — re-check before changing anything, because
getting it wrong breaks the VSIX build in a way that may not surface until
publish time.

### Verify before announcing

- `npm pack --dry-run` — inspect the file list. No extension artefacts, no test
  fixtures, no planning docs, no `.vsix`
- Install the packed tarball into a clean directory and run it
- `npm run package` still produces a working VSIX afterwards
- Full suite green, `tsc` clean on `src/` and `tests/`

**Exit:** `npx secretloop history --verify` works on a stranger's machine.

---

## Phase 2 — Legibility (~2 hours)

**README opening line:**

> Find exposed secrets, verify whether they're still live, and remediate them —
> from your terminal or in VS Code.

**Demo GIF, 20–30 seconds, at the top:**

```
secret found → verify → LIVE → quick fix → remediated
```

Record against a scratch repo with a format-valid but fake token. Nothing real
on screen.

Not a twenty-page security manifesto. Show the product.

**Optional, one evening:** the tri-state liveness write-up. A boolean that could
not say "I don't know", producing the exact sentence someone reads when deciding
*not* to rotate a live key. That post is more compelling than the tool.

---

## Phase 3 — Twenty conversations (~1–2 weeks, ~5 hours)

**The highest-value item here.** It decides whether Phase 5 happens at all.

### Who

Startup CTOs · senior and full-stack engineers · DevSecOps and security
engineers · engineering managers · teams using Claude Code, Cursor or Codex.

Indian startups are the accessible starting point. The thesis is not regional.

### Protocol — five stages, in order

**1. The incident**
> "Walk me through the last time you found a credential somewhere it shouldn't
> have been. What happened?"

Then, without leading:
- **How did you find out?** ← *distinguishes notification from active search; if
  everyone is notified, a scanner's value proposition changes*
- How did you determine whether it was still live?
- Who handled it? How long did it take?
- Where did you look for other copies?

**2. Their tooling**
> "What did you use to find it?"

**3. The uncertainty** ← *the most valuable question in the set*
> "What did you still not know after you'd finished dealing with it?"

Unmet needs surface here and nowhere else.

**4. Their AI environment**
> "Does your team use Claude Code, Cursor, Codex, MCP servers?"

**5. Only if stage 4 said yes**
> "How do you currently know what credentials those tools can access?"

### Rules

- **Never mention fan-out, drift, or any V2 idea before stage 5.** Naming it
  turns discovery into confirmation and you will get twenty polite agreements to
  an idea you planted.
- **No hypotheticals.** "Would you do anything if…" measures politeness. Past
  behaviour is evidence; stated intent is not.
- **Record actual quotes**, especially for stage 3.

### The decision threshold — one criterion, behavioural

> **At least 3 of 20 people independently run SecretLoop after the conversation.**

Only this. Not "8 agreed it was a problem" — everyone agrees, because
disagreeing sounds negligent. Someone typing `npx secretloop` unprompted is
evidence; sympathy is not.

Alongside it, one qualitative read: **what problem appeared repeatedly in stage
3?** That, not your prior, decides which V2 item gets built.

---

## Phase 4 — Marketplace (after CLI feedback)

Publish the extension once several people have run the CLI and you have fixed
whatever their first five minutes revealed. The extension ID
`gpyanalytics.secretloop` is permanent — changing it means every user
reinstalls. Open VSX is a third namespace if you want that channel.

---

## Phase 5 — V2, gated on Phase 3

**Do not start any of this before the evidence exists.**

### 🥇 The two pivots — same data, both directions

**Credential → surfaces** *(fan-out)*

```
GitHub PAT — LIVE
  ├── .env
  ├── claude_desktop_config.json
  ├── .cursor/mcp.json
  └── github MCP config

4 observed locations · 3 agent surfaces
```

**Agent → credentials** *(concentration)*

```
Claude Code
  ├── GitHub PAT    LIVE
  ├── AWS key       LIVE
  ├── Stripe key    UNKNOWN
  ├── PostgreSQL    LIVE
  └── OpenAI key    DEAD

3 live credentials reachable
```

The second sentence — *"Claude Code currently has access to 3 live
credentials"* — is sharper than the first, and it is the **same query read
backwards**. Build both; they cost barely more than one.

**Cheaper than it looks:** fingerprints already key on `sha256(value)`, so the
same credential in four places *already produces matching hashes*. This is close
to a grouping query over data the scanner emits today.

**Effort: days.**

### 🥈 Exposure drift

```
Claude Code: 2 → 7 reachable credentials since Aug 12
  + AWS key
  + Stripe key
  + PostgreSQL URL
```

Reuses the baseline machinery already built, pointed at a different subject.

**Say "+5 credentials since August 12", never "exposure increased 250%".** A
percentage on a base of two is a scary-looking number standing on nothing —
exactly what this project has spent a week removing.

**Effort: days to a week.**

### 🥉 Credential lifecycle

```
FIRST OBSERVED → LIVE → OBSERVED ON AGENT SURFACE
              → EXPOSURE CHANGED → ROTATED → DEAD
```

Requires repeated observations you don't have yet — this is drift plus
retention, not a separate feature. **Only after drift exists.**

Be precise about *observed* versus *happened*. SecretLoop knows when it first
saw something, not when it was created.

### Later, if pulled there

Lifecycle metrics — *median time from discovery to rotation*, *median lifetime
of live credentials reachable by an agent*. Defensible because every input is
observed.

---

## Detection freeze lifted for 0.1.1 — 29 August 2026

0.1.1 was written under a detection freeze: excludes and reporting could change,
rule matching could not. That freeze is **deliberately lifted before publish**,
because a benchmark against gitleaks 8.30.1 and TruffleHog 3.97.1 on a seeded
corpus produced four attributable detection defects, and 0.1.1 is still
unpublished — npm serves 0.1.0 and no `v0.1.1` tag exists, so its detection
behavior is still amendable. Once published it would not be, and the fixes would
have to become 0.1.2.

The lift is **scope-limited to exactly four fixes**: the password-punctuation
capture class, the `:=` separator audit, the jwt.io documentation-sample filter,
and the hashed-asset dot fix. Every other rule, rule ID, keyword, entropy
threshold and allowlist stays frozen — rule IDs in particular, because they are
baseline identity and changing one invalidates every `excludeRules` entry and
every accepted finding in every user config. Each fix requires before/after
evidence on the benchmark corpus, and a fix that cannot show it does not land.

This is not a reopening of detector coverage. `Detector parity with TruffleHog`
below remains out of scope: these four are corrections to rules that already
exist and already claim to match what they miss, not new detectors chasing a
count.

---

## Carried to 0.1.2 — from the external review of 0.1.1

An outside read of `release-0.1.1` produced four publish blockers (all fixed in
this release) and a tail that was deliberately not fixed with them. **The
review's write-up is the spec for each of these**; the one-line summaries here
exist so nobody has to rediscover them.

Nothing below loses a finding relative to 0.1.0. They are ordered by what a
user notices.

| id | item | why it waited |
|---|---|---|
| P1-3 | The editor's workspace-scan summary carries the generated-file and symlink counts but not the inline-suppression or fixture-suppression counts. `WorkspaceScan` never grew the two fields `ScannedFile` already has. | Confined to one surface; the CLI is where CI reads, and the CLI discloses all six. Also: `scanWorkspace` hand-builds a scope string with different wording than `describeScope` produces a few lines later — fold both into one call. |
| P3-1 | **The VSIX manifest pin has no automatic trigger, and packaging from a polluted `node_modules` ships it.** `scripts/vsix-manifest.txt` is an exact 7-file list and `smoke:vsix` diffs the archive against it, but nothing runs it: `prepublishOnly` covers npm only. Measured 29 Aug 2026: with 58 packages in `node_modules` that are in neither `package.json` nor `package-lock.json` (left by an `npm install` on another branch), `vsce package` puts **3,690 node_modules files** into the archive. `npm ci` removes them. | Wiring `prepackage`/`prepublish:vsce` to `smoke:vsix` is one line, but it fails today for that pre-existing reason, so the fix is the gate *plus* deciding what the gate should do about a dirty tree. See the corrected note in `.vscodeignore`. |
| P2-1 | A symlink cycle in a non-git tree enumerates the same file once per depth: one credential in one file became 33 findings with 33 fingerprints, and the scope said `99 file(s)` for one real file. Containment is not breached; `walkDirectory` needs a realpath-visited set. | Non-git walk only, and the fingerprints are platform-dependent, which makes it a baseline-stability bug rather than a detection one. |
| P2-2 | `VerificationCache` keys on `(ruleId, sha256(value))` and ignores the verification context, so an AWS access key ID present in two files — one with the paired secret key, one without — gets whichever verdict started first, and a `missing-pair` UNKNOWN is cached for five minutes over a credential that could have been proven LIVE. | Wrong in the tri-state's own direction, but it needs the same credential in two files with different neighbours. |
| P2-3 | `mask` checks only the first 8000 bytes for NUL, so a file whose first NUL is later is decoded and written back with U+FFFD substitutions — neither the input nor a masked version of it. Same lossiness for any non-UTF-8 text. No secret escapes; offsets are computed on the decoded string. | Corruption, not disclosure. Fix is to scan the whole buffer and compare the re-encoded bytes. |
| P2-4 | Four structural entropy filters can never fire, because the capture alphabet `[A-Za-z0-9+/=_\-.]` excludes `:` `;` `,` `\`: the data-URI, bare-URL and MAC filters, plus the drive-letter and backslash branches of the filesystem-path filter. The bare-URL one is already documented as unreachable in the comment beneath it and left in the list anyway. | Documentation and deletion. Dead entries in a filter list are a hazard because the next exception gets written next to one that has never run. |
| P2-5 | The entropy tier cannot report an all-hex or all-digit credential at any length: `charsetDiversity === 2` raises the bar to 4.5 and hex tops out at `log2(16) = 4.0`. The 0.823% miss rate this release quotes is measured at 40 characters only — it is 4.1% at 32 and 96.5% at 20, against a `{20,}` minimum that advertises coverage the threshold cannot deliver. | Documentation. Named rules cover the known hex providers; a self-issued 64-hex service token is invisible to both tiers and the README should say so. |
| P3-2 | `README.md` never mentions `mask` — not once. It is the headline new command of 0.1.1, it has a surprising default (`--entropy` off), and the README is also the npm page and the Marketplace listing. | |
| P3-3 | `checkAllowValues` puts the offending pattern verbatim into its error message, and an `allowValues` entry is frequently the credential being allowed. Report the index instead. | |
| P3-4 | `describeCommits` in `history.ts` is exported and has no caller in `src/`. It is also the one `git` spawn site that splices caller-derived strings into argv with no `--` separator. | |
| P3-5 | Fixture-path suppression now drops generic-tier findings under `tests/`, `bench/` and `examples/` in the CI self-scan too, regardless of `.github/secretloop.ci.json`'s per-file exclusion list — so that file's careful scoping covers a smaller surface than its comment describes. Named rules still fire. | |

---

## Permanently out of scope

| idea | why not |
|---|---|
| Detector parity with TruffleHog (800+) | Nobody switches scanners for parity. Add coverage only where a user actually hits a gap. |
| AI-security everything-platform (prompt injection, malware, MCP suite) | Crowded — Cisco, Snyk, GitGuardian, Varonis are all there. |
| Agent Exposure Score 0–100 | Unfalsifiable composite. Prefer facts: *4 live, 3 surfaces, +2 since baseline*. |
| Capability mapping ("grants IAM write") | Needs privileged introspection or a maintained catalog of every MCP server. The 800-verifier trap in new clothes. |
| Backend / dashboard | Only after users ask for team visibility unprompted. A year, probably a co-founder. |
| Automated rotation | Needs `iam:CreateAccessKey`, `iam:DeleteAccessKey`. Enormous trust ask; a bug takes down production. |

---

## The strategy in four sentences

**V1** — SecretLoop finds secrets, proves whether they're live, and helps
remediate them.

**V1.5** — Put it in developers' hands and learn what actually hurts after a
credential leak.

**V2** — If validated, own the relationship between credential → liveness →
agent surfaces → fan-out → exposure drift.

**V3** — Only if customers demand it, turn that visibility into organisation-wide
governance.

Each stopping point leaves something real. Stopping after Phase 3 leaves a
shipped tool and twenty conversations of market knowledge — an outcome, not a
half-finished project.

---

## Appendix A — Repo metadata

**Description:**
> Finds exposed secrets, verifies whether they're still live, and helps you
> rotate them — VS Code extension and CLI.

**Topics:** `secret-scanning` `security` `devsecops` `vscode-extension`
`credentials` `sarif` `pre-commit`

---

## Appendix B — If Phase 3 comes back negative

SecretLoop's value is then as a demonstration of engineering judgment, and on
that front it is strong: a commit history of security fixes, each with written
rationale, RED/GREEN evidence, and design tradeoffs argued out.

Priorities in that mode are cheaper and overlap Phases 0–2 entirely — demo GIF,
the tri-state write-up, CLI on npm, clean README. Days, not months, and worth
doing regardless.

---

## Appendix C — The constraint

A salaried job and two other brands. Nights and weekends against funded
competitors with contributors. Not a reason not to do it — a reason to build in
an order where each phase is independently useful.
