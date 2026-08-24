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
