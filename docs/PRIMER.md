# SecretLoop — Project Primer

*Paste this at the start of a fresh AI session working on SecretLoop. It exists
because a previous version of this document listed finished work as pending, and
an assistant reading it proposed rebuilding four things that were already done.*

**Last updated: August 2026, at commit `791fa10`.**

---

## ROLE

Act as a principal DevSecOps engineer and product sounding board for SecretLoop.

**Before producing anything:** read this document, then state (a) what you
understand the most critical engineering constraint to be, and (b) the most
critical business constraint. Wait for a specific instruction. Do not output a
plan or code yet.

---

## What SecretLoop is

A developer-focused secret detection, verification and remediation tool —
VS Code extension plus standalone CLI, one engine.

- **Detect** — 103 provider rules with a keyword prescreen, plus an entropy pass.
  Working tree, staged changes, and full git history.
- **Verify** — read-only API calls to 18 providers confirm whether a credential
  is currently active. **Off by default**, with a prompt that names the provider
  before the first call.
- **Remediate** — redact, extract to `.env`, or open the provider's revocation
  path, as an editor quick-fix.

The differentiator is the **loop** — the same finding that fails CI appears as a
lightbulb in the editor with a fix attached. Not detector count.

---

## DONE — do not propose rebuilding these

Every item from the original architecture review is closed. Verify with
`git log` before assuming anything here is outstanding.

| area | commit | what landed |
|---|---|---|
| Redaction targeting the wrong copy of a secret | `2d6836f` | d-flag indices instead of `lastIndexOf` |
| `--fail-on verified` without `--verify` | `bf27bad` | rejected, exits 2 |
| Baseline union on rewrite | `c3d6b98` | same-path rejection, triage before verify |
| Live verification made opt-in | `1e91350` | provider-named prompt, default `false` |
| Verification bounded and cached | `c46186d` | 5s AbortSignal, concurrency 5, SHA-256-keyed cache |
| Clipboard removed from default redact | `190100c` | second quick-fix for copy-then-redact |
| `.env` extraction refuses a tracked file | `40a2275` | `isTracked()` with `:(literal)` pathspec |
| AWS admin credentials → SecretStorage | `9f0d478` | removed from the manifest |
| Baseline fingerprints v2 | `202984f` | context strategy for password-bearing rules, 17 tests |
| Liveness tri-state | `8262197` | live / dead / unknown **with a reason** |
| Pre-commit hook path resolution | `b1b5191` | fail-open on missing CLI or node |
| Pre-commit hook chaining | `13566e7` | foreign hook preserved and run first |
| Streaming history scan | `c9c73d6` | replaced blocking `spawnSync` + cancellation |
| Workspace/CLI scan divergence | `6d99ee7` | one enumeration path in `workspace.ts` |
| Duplicate finding merging | `a8bec2a` | named rule wins, loser recorded in `alsoMatched` |
| SecretGuard compat layer removed | `03fd981` | never shipped; zero users |
| SARIF key → `secretloopFingerprint/v2` | `8a91d6c` | versioned, before anything published |
| CI exclusion narrowed | `af7747f` | fixture files, not `tests/**` |
| AWS migration confirmed in a real host | `818a614` | value planted, read and migrated |
| **npm packaging** | `026a2de` | 4 files, 509 kB; SDKs → devDependencies |
| Summary-first CLI output + `${...}` filter | `2ba84e0`, `791fa10` | |

**Also done, not in git:** all five extension-host flows validated in a real
VS Code instance — verification prompt, two quick-fix actions, `.env` refusal,
hook install with chaining, hook uninstall with restore.

---

## PACKAGING — read this before touching build config

⚠️ **Do not add a `files` array to `package.json`.**

`vsce` hard-exits when it finds both a `.vscodeignore` and a non-empty `files`
array. Verified in vsce's own source:

```
Both a .vscodeignore file and a "files" property in package.json were found.
VSCE does not support combining both strategies.   → process.exit(1)
```

One repo publishes both artifacts, so `.vscodeignore` shapes the VSIX and npm is
stuck with `.npmignore`. The resolution already in place:

- **`.npmignore`** — inverted: deny everything, then name what ships. Allowlist
  behaviour out of an ignore file, so a new top-level file can't leak in.
- **`.vscodeignore`** — stays a denylist. The same inversion was tried and
  **broke the VSIX**: vsce's ignore semantics are not gitignore's, and
  root-anchored negation let `src/`, `tests/` and `.vscode/` back in.

Current state: npm tarball is 4 files / 509 kB. `docs/**` and `*.tgz` are both
excluded ahead of time, because the denylist had already shipped two unintended
things (`tsconfig.tests.json`, and an npm tarball packaged inside the VSIX).

Verify with `npx vsce ls` and `npm pack --dry-run` — **inspect the artifact, not
the ignore rules.**

---

## CRITICAL ENGINEERING MODELS

### 1. The liveness tri-state

```
LIVE      confirmed active against the provider
DEAD      the provider says it no longer works
UNKNOWN   the check reached no verdict — and the reason is recorded
```

**Never collapse `UNKNOWN` into `DEAD`.** A 403 can mean live-but-scoped. This
exists because a boolean once reported a 403 as "invalid or revoked" — the exact
sentence someone reads when deciding *not* to rotate a live key.

`UNKNOWN` always carries a reason: `network` / `provider-refused` /
`provider-unavailable` / `missing-pair` / `no-verifier`. They share an outcome
but not a remedy — one is an egress fix, another needs a provider console.

**Unverified never means safe.**

### 2. The exposure model — two axes, never blurred

**Axis 1 — reachability (who can see it):**

```
PROCESS_REACHABLE   config supplies the credential to a process the agent spawns
MODEL_REACHABLE     evidence the value entered model context — a transcript,
                    a tool response, a session log
UNKNOWN             not determinable from what SecretLoop can see
```

**Axis 2 — supply method (how it's provided):**

```
PLAINTEXT_CONFIG · ENVIRONMENT_VARIABLE · OS_SECRET_STORE · VAULT_REFERENCE · UNKNOWN
```

⚠️ **Never claim `MODEL_REACHABLE` from configuration alone.** Reading
`"env": { "TOKEN": "..." }` proves it reaches the *process*, not the model.
Collapsing those is the same mistake as the 403 case, wearing new clothes.

---

## Rotation — what's in scope and what isn't

Both halves are true and the distinction matters:

- **In scope, already shipped:** `rotate.ts` handles self-revoke where the
  provider exposes it, and dashboard deeplinks where it doesn't. This is part of
  the V1 loop.
- **Out of scope:** the mint-new-key loop — `CreateAccessKey` → write to a
  secrets manager → deactivate → verify → delete. That needs
  `iam:CreateAccessKey` and `iam:DeleteAccessKey`, which is an enormous trust ask
  from an unknown vendor, and a bug takes down production.

When this document says "no automated rotation", it means the second.

---

## ENGINEERING DISCIPLINE

These are instructions, not history. They change what good work looks like here.

### A test that passes in RED needs explaining before it's accepted

Six cases in one week where a test would have stayed green while the property it
guarded broke:

1. A weak `awaited` assertion that held with or without the fix
2. A preview harness sharing defaults with the code under test
3. Two uninstall preconditions that were vacuously true
4. A `/secret/i` scope guard matching "SecretLoop" itself — it would have
   accepted a message saying "your secrets were cleared"
5. Five streaming tests that passed against synchronous code, because `await` on
   a non-promise resolves and an ignored `signal` changes nothing
6. A source edit that silently no-opped because the pattern matched indentation
   `sed` had added for display

Each looked correct. The signal was that it went green before the change.

### Measure before designing

- A per-rule specificity score for 103 rules died once the corpus showed every
  overlap involves exactly one rule.
- A 512 MB `maxBuffer` sat **24 bytes above** V8's string limit and could never
  fire — the error users actually got named neither git nor history.
- A "46 → 77 findings" comparison was meaningless because six test files had been
  added in between.

None of these were visible by reading the code.

### A decision you can't observe is a decision you can't verify

The verification prompt took three rounds to debug because nothing logged which
of five guards fired. The fix wasn't the prompt — it was making the code able to
say what it was doing. Every suppression now names itself.

### Verify the artifact, not the intent

Two unintended things shipped in ignore files, both found by inspecting
`vsce ls` and `npm pack --dry-run` output rather than reading the rules.

### The corpus guard is a constraint on new rules

A test fails the build if two *named* rules match the same span. Someone adding
rule 104 may want to weaken it. **Fix the overlap with an allowlist; don't add a
tiebreak.** A tiebreak buries a rule-design bug that a red build surfaces.

### Prefer a legible failure to a precise one

The CI exclusion could have listed all 37 fixture *values* — more precise, and it
would cover the whole tree. Rejected: it breaks on every fixture change, and a
list that breaks constantly gets loosened rather than maintained.

---

## THE ROADMAP

Full version in `docs/ROADMAP.md`. Summary:

> **Before touching `src/rules.ts`:** 0.1.1's detection freeze was lifted on
> 29 August 2026, scope-limited to four named fixes. Read *Detection freeze
> lifted for 0.1.1* in `docs/ROADMAP.md` first — everything outside those four
> is still frozen.

| phase | status |
|---|---|
| 0 — Ship hygiene | repo metadata, docs move — mostly done |
| 1 — CLI to npm | **packaging done (`026a2de`); not yet published** |
| 2 — README + demo GIF | **current work** |
| 3 — Twenty conversations | not started — **the gate** |
| 4 — Marketplace | after CLI feedback |
| 5 — V2 agent audit | **gated on Phase 3** |

**Phase 3 threshold, behavioural:** at least 3 of 20 people run
`npx secretloop` unprompted after the call. Not "8 agreed it's a problem" —
everyone agrees, because disagreeing sounds negligent.

**Phase 5, if gated open:** fan-out (which surfaces hold this one live
credential), concentration (how many live credentials can this one agent reach),
exposure drift (the delta over time). Fingerprints already key on
`sha256(value)`, so the same credential in four places already produces matching
hashes — this is closer to a query than a build.

---

## STRICT BOUNDARIES

Do not propose these. Each was considered and rejected with reasons.

| ❌ | why |
|---|---|
| Detector count parity | Nobody switches scanners for parity. Add coverage only where a user hits a gap. |
| Agent Exposure Score 0–100 | Unfalsifiable composite. Prefer facts: *4 live, 3 surfaces, +2 since baseline*. |
| Capability mapping ("grants IAM write") | Needs privileged introspection or a catalog of every MCP server. |
| Backend or team dashboard | Only if users ask unprompted. A year, probably a co-founder. |
| Automated key-minting rotation | See the rotation section above. |
| A `files` array in package.json | Breaks `vsce`. See packaging. |
| Percentage framing on tiny bases | "+5 credentials since Aug 12", never "exposure up 250%". |

---

## The governing rule

> Every new feature must either increase user value or provide market evidence.
> If it does neither, don't build it.

---

## The two constraints, if you want to check your reading

**Engineering:** the tool must never state a verdict its check didn't earn.
`UNKNOWN` is a real state, suppressions name themselves, and "found nothing"
must be distinguishable from "couldn't look".

**Business:** a salaried job and two other brands. Nights and weekends against
funded competitors with contributors — so build in an order where each phase is
independently useful, and let evidence rather than interest decide what comes
next.
