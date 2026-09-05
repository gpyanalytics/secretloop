# SecretLoop — Backlog

Parked work, and the trigger that would un-park each item. The governing rule:
**build when real usage points the way, not from a market chart or a feature
idea.** Everything here is deliberately not started, and this file exists so
that stays a decision rather than a thing nobody got round to.

## Native editor ports (demand-gated)

Two surfaces already reach editors other than VS Code, with no new work:

- **The CLI.** `secretloop scan` runs in any editor's integrated terminal, and
  reads the same `.secretloop.json` the extension does — so a JetBrains or
  Neovim user gets identical verdicts, just without the inline UI.
- **The MCP server.** Standard MCP over stdio, so it connects to any client
  that supports a local stdio server: VS Code with Copilot, Cursor, Windsurf,
  Cline, Zed, Claude Desktop. See the README for the per-client configuration
  — the invocation is the same everywhere; only the file and the key differ.

So the gap is narrower than "SecretLoop is VS Code only" suggests. What is
missing in other editors is the *native inline experience* — diagnostics on the
line, quick-fixes, Mask Clipboard — and nothing else.

Build a native port only when a real user asks for that specific editor.

- **JetBrains** (IntelliJ, PyCharm, WebStorm, GoLand, Rider) — the highest
  value and the highest cost. Largest non-VS-Code base and the one that lines
  up with enterprise and IT-services work; also a separate plugin API in
  Kotlin/Java, a separate marketplace, and a UI rewrite rather than a port.
  First in line if demand shows.
- **Zed** — the MCP path is already documented and shipped, so connectivity is
  not the open question. What remains unproven is whether anyone wants the
  inline UI on top of it. Do not start editor-specific work until someone says
  the MCP integration is not enough.
- **Neovim / Vim** — served by the CLI today. A native plugin is nice to have,
  and low priority.
- **Sublime Text / Emacs** — the CLI serves them. Skip until asked.

**Trigger:** a real user names the editor. Until then, parked.

## Rules and detection (evidence-gated)

Today: **109 rules**; **18** of them have verifiers, covering **15 providers**,
**17** of which can actually transmit. Coverage of the common stack is broad,
and the gap against gitleaks, GitGuardian and TruffleHog is real but narrower
than the raw numbers imply — detector *count* is not a quality measure, and
`docs/MARKET.md` says so plainly rather than hiding it.

- **AI providers** (Cohere, DeepSeek, Mistral, xAI) were evaluated and
  **deferred**: none publishes a distinctive credential format precise enough
  to write a named rule against, and DeepSeek's `sk-` prefix collides with the
  existing OpenAI rule — the same collision class that produced the OpenRouter
  misattribution fix in 0.1.5. The entropy tier still catches these when the
  value is high-entropy near a keyword.
- **Lower-tier candidates with plausibly distinctive formats** — Alibaba Cloud,
  Jenkins, Fastly, GoCardless among them — are not yet format-verified. That
  verification is the work, not the regex.

**Trigger:** a real user hits a real gap — a provider SecretLoop missed on
their repository — or a provider publishes a stable distinctive format. Build
only what a user needs, through the same format-verification gate every shipped
rule went through. Never a guessed pattern to move the count.

## Paid and organisation tier (usage-gated)

The commercial ladder is designed and not built: a commercial licence and SLA
first, then organisation policy, audit and team visibility, then enterprise
SSO, RBAC and compliance, and cross-repository intelligence later.

Three boundaries hold whatever gets built:

- The cloud or organisation layer is **never** a dependency of the local path.
  Scanning, verification and remediation keep working with no account and no
  network.
- **No embedded language model**, ever. The client's assistant reasons over
  SecretLoop's deterministic evidence; the scanner decides what a finding is.
- Organisational scale is the reason to pay. **Access to the MCP layer is not**
  — it ships in the free tool and stays there.

**Trigger:** sustained real usage, and a user for whom organisation-scale
features justify paying. Not before.

## Engineering follow-ups

Small, none urgent.

- **`readRecord` id-match hardening** (`src/consent.ts`). `listRecords` refuses
  a record whose filename disagrees with its own `id`; `readRecord` does not
  make the same check. Reaching it requires write access to the consent
  directory, which is outside the documented trust boundary — the OS user
  account — and the fingerprint, path and commitment checks catch the attempt
  anyway. Not a break; a rainy-day symmetry fix.
- **`RELEASING.md`** — the release checklist exists as a working artifact and
  should be committed: build and test, security-tool guards, packaging
  integrity, regression safety, docs accuracy, and the conditional adversarial
  review when a release touches the MCP, consent, verify or workspace surface.
- **Tag at the release commit.** The tag has drifted behind `main` between
  releases more than once. Tag the commit being released, not an earlier one.
- **Prune stale worktrees** left over from previous releases.
