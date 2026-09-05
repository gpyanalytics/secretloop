# SecretLoop — Market Gaps and Upgrade Paths

**Revision 2 — August 2026.** Supersedes revision 1. The correction in §4 is
kept visible rather than quietly rewritten, because the reasoning trail matters
more than looking right the first time.

Market figures gathered by search; sources named inline. Treat anything with a
number attached as worth re-checking before acting on it.

---

## 0. The one sentence

> **SecretLoop tells developers which live credentials their AI agents can
> reach, where those credentials came from, and how they are being supplied —
> without pretending to know what it cannot prove.**

That last clause is not marketing. It is the through-line of every good
engineering decision in this codebase: the liveness tri-state that can say
"unknown", the six named reasons a prompt was suppressed, the descriptor
discriminator that distinguishes "found nothing" from "could not look", the
fingerprint that stopped claiming stability it did not have.

Naming the principle makes it transferable to the next feature.

---

## 1. The competitive floor

The fact that constrains everything else:

| tool | detection | verification | cost |
|---|---|---|---|
| **TruffleHog** | regex + entropy + plugins | **800+ active verifiers** | free, open source |
| **GitGuardian** | 450+ detectors plus generic | paid tiers only | **free ≤25 devs**; ~$8–15k/yr for 10–20 devs |
| **GitHub Secret Scanning** | partner patterns | partner-notified | free on public repos; GHAS for private |
| **Gitleaks** | ~150 rules | none | free, open source |
| **SecretLoop** | 109 rules | 15 providers, **tri-state** | free |

**GitGuardian's free tier covers 25 developers.** Almost every startup you would
naturally talk to is already covered for free by a better-funded competitor. The
SMB segment is not underserved — it is un-monetisable.

---

## 2. Where SecretLoop genuinely wins today

**The loop.** SecretLoop finds a secret, checks whether it's live, and offers
rotation as a quick-fix right where the developer is working.
GitGuardian does guided rotation from a dashboard. TruffleHog verifies and stops.

**The liveness tri-state.** Every other tool has a binary verified/unverified.
That is the exact bug fixed in this codebase — a 403 reading as "revoked" when
it can equally mean live-but-scoped. Real correctness advantage, invisible in a
feature table.

**Where it loses, plainly:** 109 rules against 800. 18 rules have verifiers
(covering 15 providers), 17 of which can transmit — against 800. No
org layer at all.

---

## 3. Do not chase the 800

Detection rules are cheap — a regex, keywords, a fixture: ~15 minutes each.
Verifiers are not: each of the 18 required finding the right read-only endpoint
and understanding what its status codes mean. The 403 bug came out of a set of
18. One person doing 800 properly is not a plan.

**And winning that race would not help.** Reach 800 and TruffleHog is at 1,200.
Nobody switches scanners for parity. Breadth is precisely the axis where a
funded incumbent with contributors beats a solo builder, and where the customer
already has a better free option.

### The reframe that matters

Stop competing on:

> *How many things can SecretLoop detect?*

Start competing on:

> **Where can SecretLoop apply the secret intelligence it already has?**

The same engine — 109 rules, 18 rules with verifiers across 15 providers,
tri-state liveness, fingerprints,
baselines — can be pointed at repo, `.env`, MCP config, agent config, agent
rules, skills, logs, sessions. The 109 rules stop being a weakness and become
sufficient infrastructure for a surface nobody has covered well.

**Pragmatic exception:** add detectors for the top ~50 things that actually
appear in your target stacks, verify the ones with easy endpoints, stop. One
week. Closes embarrassing gaps without entering a race you lose.

---

## 4. The gaps — corrected

> ### ⚠️ Correction to revision 1
>
> Revision 1 claimed secrets in AI agent surfaces were **"genuinely
> unclaimed."** That was wrong by August 2026 and is retracted.
>
> - **GitHub** shipped MCP-session secret scanning (announced 17 March 2026),
>   explicitly treating AI coding agent sessions as a distinct attack surface
>   requiring dedicated credential scanning. Also added 37 new detectors across
>   22 providers in March.
> - **GitGuardian** ships agent skills for Claude Code, Cursor and Codex, and
>   markets developer-endpoint and NHI security.
> - **Snyk's agent-scan** is among the inspection scanners analysing MCP tool
>   definitions, arguments and responses.
>
> Three funded players are in the space. The claim to make now is narrower and
> much harder to knock down:
>
> **Detection of secrets in agent surfaces is being commoditised by GitHub,
> GitGuardian and Snyk. Correlating detection with liveness and local
> reachability — with no backend and no provider-permission catalog — is not.**

### The premise is better validated than revision 1 had it

GitGuardian's State of Secrets Sprawl 2026 found **24,008 unique secrets in
MCP-related configuration files** on public GitHub, of which **2,117 were still
valid** — 8.8% of all MCP-related findings.

And the root cause is structural, not carelessness: **official MCP quickstart
documentation shows API keys hardcoded directly in configuration examples**, so
developers copy the pattern, substitute their real key, and commit it. When
insecure credential handling is normalised in official quickstarts, sprawl
follows at ecosystem speed.

Supporting figures worth knowing:

- AI-assisted commits leak secrets at **~3.2%, roughly 2× baseline**
- AI-service credential leaks rose **~81% year over year**
- **29M** secrets hit public GitHub in 2025; most never revoked
- **64%** of secrets leaked in 2022 were still valid in 2026
- Across 6,943 developer machines: each live secret appeared in ~8 different
  locations — `.env` files, shell history, IDE configs, cached tokens, build
  artifacts

### Gap A — Credential reachability, not agent-file scanning

Everyone can now say *"secret found in MCP config."* Nobody says:

> **"This live credential is reachable by this agent, through this tool, from
> this configuration surface, and here is how it is being supplied."**

```
LIVE GitHub PAT
      ↓  source: claude_desktop_config.json
      ↓  supplied as: GITHUB_TOKEN
      ↓  agent: Claude Code
      ↓  tool: github MCP server
      ↓  exposure: PROCESS_REACHABLE
```

Every element of that is computable from local configuration files. No catalog,
no privileged calls, no backend.

### Gap B — Credential provenance

The same credential has radically different exposure depending on where it came
from:

```
~/.aws/credentials → MCP server → agent          (machine-wide, outside any repo)
.env → repository → MCP → agent                  (in-repo, gitignored)
agent session → tool call → log/cache            (transient, hardest to find)
```

Provenance is a local, deterministic property. Worth reporting.

### Gap C — Agent-scoped credential lifetime

Already nearly free — fingerprints, git history and rotation events exist. The
metric becomes agent-specific:

> *"Your AI agents currently have access to 3 live credentials older than 90
> days, 2 of which have never been rotated."*

Better than any composite score.

---

## 5. The exposure model — three states, not two

This is the correction that matters most, and it is the same mistake the
liveness tri-state exists to prevent.

Reading `"env": { "GITHUB_TOKEN": "ghp_..." }` in an MCP config proves the
credential reaches the **process**. It does *not* prove the value ever entered
model context. Those are different observations requiring different evidence.

```
PROCESS_REACHABLE   proven: config supplies the credential to a process the agent spawns
MODEL_REACHABLE     proven: evidence the value appeared in agent context —
                    a transcript, a tool response, a session log
UNKNOWN             not determinable from what SecretLoop can see
```

**Do not collapse these.** Claiming `MODEL_REACHABLE` from configuration alone
would be exactly the overclaim that made a 403 read as "revoked" — a state that
cannot say "I could not tell", reporting a verdict it does not have.

### A separate axis: how the credential is supplied

Keep this distinct from *who can see it*. Two axes, not one enum:

```
PLAINTEXT_CONFIG      value literally in the JSON
ENVIRONMENT_VARIABLE  referenced as ${VAR}, value elsewhere
OS_SECRET_STORE       keychain reference
VAULT_REFERENCE       secret-manager reference
UNKNOWN
```

Blurring the two axes in the output is how a report stops meaning anything.

### Why this makes remediation better

Not: *"move the secret to an env var"* — which is sometimes still wrong.

Instead: *"This credential is supplied directly in MCP configuration. Consider a
secret store or a mechanism that does not place the credential value in agent
configuration at all."*

That is advice correct for the agent context specifically, which nobody else is
giving.

---

## 6. The product boundary

**SecretLoop is not:**

- the scanner with the most detectors
- another MCP security scanner
- another SAST/SCA platform
- another agent risk score
- a provider-permission catalog

**SecretLoop is:** a local credential-exposure analyser for AI-assisted
development, answering six questions:

1. What credentials are present?
2. Which are actually **live**?
3. Which agents and processes can reach them?
4. Where did each credential come from?
5. How is each being supplied?
6. Can model exposure be **proven**, or is it **unknown**?

```
             SECRETLOOP
                  │
        ┌─────────┴─────────┐
    Credential           Agent
        │                   │
    LIVE / DEAD /      Reachability
     UNKNOWN                │
        └─────────┬─────────┘
                  ↓
          Exposure evidence
                  ↓
             Remediation
```

---

## 7. Three features to lock

### 7a. `secretloop agent audit` — the flagship

```
SecretLoop Agent Audit
────────────────────────────────────

Agents discovered             3
MCP servers                   8
Credential references        17

LIVE                          9
DEAD                          3
UNKNOWN                       5

Agent-reachable LIVE          7
Model exposure UNKNOWN        4

CRITICAL

GitHub PAT
  Status:    LIVE
  Agent:     Claude Code
  Tool:      github MCP
  Source:    claude_desktop_config.json
  Supplied:  PLAINTEXT_CONFIG
  Exposure:  PROCESS_REACHABLE

AWS credential
  Status:    LIVE
  Agent:     Cursor
  Tool:      aws MCP
  Source:    ~/.aws/credentials
  Supplied:  ENVIRONMENT_VARIABLE
  Exposure:  PROCESS_REACHABLE
```

No composite score. No capability claim. Evidence only.

### 7b. Credential handling classification

The two axes from §5. The most SecretLoop-shaped addition on this list: it turns
remediation advice into something correct for the context rather than generic.

### 7c. Agent-exposed credential lifetime

Gap C. Cheap, and the resulting sentence is a genuine product insight.

### Explicitly rejected

**Capability mapping** — *"this token grants IAM write"* — requires either
privileged introspection (`iam:SimulatePrincipalPolicy`: a new permission ask,
and outbound calls the opt-in work exists to control) or a maintained catalog of
what every MCP server can do. That catalog is the 800-verifier trap in new
clothes.

**A composite exposure score** — every security product has a 0–100 number and
nobody trusts them, because the weighting is unfalsifiable. This project spent a
week removing numbers that claimed more than they knew. Do not add one at the
top of the output.

---

## 8. Roadmap — reordered

Revision 1 put rotation third. Agent audit now goes before it.

```
1. Ship the CLI to npm
        ↓
2. History + verification    (npx secretloop history --verify)
        ↓
3. Agent audit               ← moved up
        ↓
4. Agent credential lifetime
        ↓
5. One-provider rotation (AWS)
        ↓
6. Backend — only if users ask
```

**Why audit before rotation.** Not merely that rotation is dangerous. The two
ask for *categorically different trust*:

| step | what it asks of the user |
|---|---|
| audit | nothing — local files, no account, no permissions |
| rotation | `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `secretsmanager:PutSecretValue` |

Putting a zero-trust step between "installed it" and "gave it destructive
permissions" is the whole sequencing argument. Audit is the natural bridge.

### Cost estimates

| step | cost |
|---|---|
| CLI to npm | days |
| Agent audit — reachability half | 1–2 days (reuses `walk.ts`, `scanText`) |
| JSON-path-aware rules | ~1 week |
| Handling classification | days |
| Lifetime metric | days |
| AWS rotation, done properly | a month |
| Backend | a year, probably a co-founder |

**On rotation, when you get there:** `@aws-sdk/client-iam` is already a
dependency and the full loop exists — `CreateAccessKey` → write to Secrets
Manager → `UpdateAccessKey` to inactive → verify nothing broke →
`DeleteAccessKey`. The sequencing *is* the product design: deactivate-then-delete
with a grace window, plus a dry-run mode. A bug that deletes the wrong key takes
down production, so it needs to be very good before it is public.

---

## 9. Verify the premise before building any of it

**One hour, and it gates §7 entirely.**

Open your own `claude_desktop_config.json`, and any `.cursor/mcp.json` you have.
Confirm credentials actually sit there in plaintext, and note the exact shape
they take. Everything above is reasoning from reports, not from having looked.

If the shape differs from what the reports imply, the JSON-path rules change and
the estimates change with them.

**Also note:** scanning `$HOME` is a meaningful expansion of what this tool
touches. Explicit paths only, never a blanket home walk, probably opt-in — held
to the same standard as everything else in this codebase.

---

## 10. Twenty conversations

Still the highest-value item on any list here.

- *Have you ever leaked a credential?*
- *What happened next?*

If the second answer is consistently **"we found out weeks later and nobody
tracked whether it got rotated"** — the thesis holds and the roadmap is worth
running.

If it is **"GitHub caught it and Slack-ed us"** — you are competing with free,
and §11 is the honest mode.

~15 minutes each. A week of calendar, 4–5 hours of actual time. Cheaper than any
single item in §8, and it decides which of them are worth doing at all.

---

## 11. The other mode: portfolio rather than product

If the conversations come back negative, SecretLoop's value is as a
demonstration of engineering judgment — and on that front it is genuinely
strong. A commit history of security fixes, each with written rationale,
RED/GREEN evidence, and design tradeoffs argued out, beats most people's entire
GitHub.

The priorities in that mode are completely different and much cheaper:

- **README demo GIF** — thirty seconds, top of the file
- **Write up the tri-state liveness design** — a boolean that could not say "I
  don't know", producing the exact sentence someone reads when deciding *not* to
  rotate a live key. That is a better story than the tool
- **Ship the CLI to npm** — free, instant, what people actually try
- **Finish the pre-publish checklist** — shipped counts for more than impressive

Worth doing regardless, since they also serve the product path.

---

## 12. The constraint worth stating out loud

A salaried job and two other brands. Nights and weekends against funded
competitors with contributors.

Not a reason not to do it — a reason to build in an order where **each step is
independently useful**, so that stopping at step 3 still leaves something real.
That is why §8's sequencing matters more than any individual feature.
