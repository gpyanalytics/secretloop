# SecretLoop

**From leaked to fixed.**

A GPY Analytics product.

SecretLoop is a developer-focused secret detection, verification and remediation
tool. It finds exposed credentials, checks whether they are actually live, and
helps you rotate and remediate them — in your editor, your pre-commit hook, and
your CI.

![SecretLoop scanning a working tree: three findings, each with its severity, rule, masked value, remediation line and fingerprint](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-scan-hero.gif)

## Quickstart

Needs Node 18 or newer — the liveness checks use the runtime's built-in `fetch`.

Scan a repository's whole history without installing anything:

```bash
npx secretloop history --verify
```

`--verify` makes a read-only call to each provider to prove whether a credential
still works, so you get a list of things to rotate today rather than a list of
maybes. Drop it to stay entirely offline.

```bash
npx secretloop scan                  # the working tree
npx secretloop staged                # what you are about to commit
npx secretloop scan --format sarif -o results.sarif   # for CI
```

Install it properly if you want it in CI or a pre-commit hook:

```bash
npm install -g secretloop
```

For the editor, install **SecretLoop** from the VS Code Marketplace, or from a
`.vsix`:

```bash
code --install-extension secretloop-0.1.0.vsix
```

The extension scans as you type and puts *redact*, *extract to `.env`* and
*rotate* on the lightbulb. Live verification is off until you turn it on — it
sends the credential to its provider, and a repository you just cloned may hold
someone else's.

## In the editor

The extension puts the same engine where you are already looking:

- **Findings are diagnostics, and the squiggle carries the verdict.** A format
  match is a warning. A credential confirmed live is an error — and so is one
  the provider refused to answer for, because a 403 leans live and no retry
  resolves it. The hover says which of those happened and what to do about it.
- **The quick-fix fits the verdict.** *Rotate / revoke this LIVE credential* on
  a confirmed-live one, *Inspect / revoke this possibly-active credential* on a
  refused check, and on any finding *Redact this secret*, *Copy to clipboard,
  then redact*, or *Move to `.env` and reference it*.
- **Scans run from the Command Palette** — *Scan Entire Workspace*, *Scan
  Staged Files*, and *Scan Git History for Secrets*, which opens the whole
  report as a document.
- **Every decision it made is in View > Output > SecretLoop**, including how
  many credentials left the machine and to whom.

## The loop

Most tools stop after the first step. The whole point of SecretLoop is the
handoff between them:

```
   detect  ──►  verify  ──►  remediate / rotate
     │            │                  │
  100+ rules  15 providers    redact · extract to .env
  + entropy   read-only API    · revoke at the provider
```

1. **Detect** — 100+ provider rules plus an entropy pass, across your working
   tree, staged changes, and full git history.
2. **Verify** — a read-only call to the provider proves whether the credential
   still works. A dead test token never interrupts you; a live production key
   is escalated.
3. **Remediate / rotate** — the same finding that failed your CI build appears
   as a lightbulb in your editor with *redact*, *extract to `.env`*, and, where
   the provider exposes an API for it, *rotate*.

## In VS Code

The same engine runs as you type: a finding becomes a diagnostic, and the lightbulb
carries *SecretLoop: Redact this secret*, *SecretLoop: Copy to clipboard, then redact*
and *SecretLoop: Move to `.env` and reference it*. That last one rewrites the literal to
a `process.env` reference, writes the value into `.env`, and adds `.env` to `.gitignore`
before it reports success.

A walkthrough is under *More demos* below, as a mockup rather than a recording.

## Before you paste logs into an AI

`secretloop mask` reads a log on stdin and writes it back with every credential replaced
by `[REDACTED:<rule-id>]`, so a deploy log keeps the structure an assistant needs and
loses the secrets it does not. The summary of what was masked goes to stderr, which
leaves the masked log clean to pipe onward.

```
cat deploy.log | npx secretloop mask | pbcopy
```

Both the terminal recording and an editor-side mockup are under *More demos* below.

<details>
<summary>More demos</summary>

### CLI

**`secretloop --help`**

![The secretloop CLI help output listing every command and flag](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-help.gif)

**`secretloop scan`**

![A working-tree scan reporting findings grouped by value](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-scan.gif)

**`secretloop history`**

![A git history scan walking commits for credentials](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-history.gif)

**`secretloop scan --staged`**

![Scanning only the staged changes, as the pre-commit hook does](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-staged.gif)

**`secretloop --write-baseline`**

![Accepting current findings as a baseline so only new secrets report](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-baseline.gif)

**`secretloop mask`**

![Masking credentials in a log stream before sharing it](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mask.gif)

**Masking a log before handing it to an AI CLI**

![A deploy log masked with secretloop mask, then passed to an AI CLI for debugging](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mask-to-copilot-cli.gif)

**Copy, then redact**

![Copying a secret to the clipboard and redacting it from the file in one step](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-clipboard-story.gif)

### Illustrative mockups

These two are **staged mockups, not UI recordings.** They show the shape of the
workflow; several on-screen strings are narration rather than text the tool renders.
They are kept here, and out of the sections above, until they are re-recorded against
the shipped UI.

**Move a secret to `.env` from the lightbulb**

![Mockup: a hardcoded key, the SecretLoop quick-fix menu, and the value relocated to .env](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-move-to-env.gif)

**Masking a log before pasting it into an editor assistant**

![Mockup: a deploy log masked at the terminal, then pasted into an editor chat panel](https://raw.githubusercontent.com/gpyanalytics/secretloop/main/docs/demos/secretloop-mask-to-copilot.gif)

</details>

## Where this sits against the existing tools

The pragmatic 2026 stack is gitleaks (fast pre-commit blocking) + TruffleHog
(verified history scans) + GitHub Secret Scanning, with GitGuardian on top for
regulated orgs. That's three or four tools for one job, and the seam between
them — *"which of these findings is actually live, and how do I fix it?"* — is
where the work still falls on a human.

| | gitleaks | TruffleHog | GitGuardian | SecretLoop |
|---|---|---|---|---|
| Working-tree + pre-commit scan | ✅ | ✅ | ✅ | ✅ |
| Full git history scan | ✅ | ✅ | ✅ | ✅ |
| Live credential verification | ❌ | ✅ | ✅ | ✅ (17 rules) |
| SARIF / CI output | ✅ | ✅ | ✅ | ✅ |
| Baseline for existing findings | ✅ | ❌ | ✅ | ✅ |
| Fix applied in the editor | ❌ | ❌ | ❌ | ✅ |
| One-click rotate at the provider | ❌ | ❌ | partial | ✅ where the API allows |
| Detector count | ~160 | ~800 | ~450 | 100+ |
| Price for a small team | free | free tier | enterprise | free |

**Read that table honestly.** On raw detector count SecretLoop is behind, and
that gap matters more than any UX advantage if a rule you need is missing. What
it does that none of the others do is close the loop: the same finding that
appears in CI appears as a lightbulb in your editor with *redact*, *extract to
`.env`*, and *rotate* attached to it.

## What it does

- **Detect** — 100+ provider rules with a keyword prescreen (so a large rule set
  stays fast), plus an entropy pass for credentials with no recognizable format.
- **Verify, when you ask for it** — read-only API calls to 15 providers confirm
  whether a credential is *currently active*. A dead test token never interrupts
  you.

  **This is off by default, and deliberately so.** Verifying a credential means
  sending it to a third party, and a repository you have just cloned may hold
  credentials belonging to someone else entirely — failed auth attempts show up
  in *their* audit logs, not yours. The first time a scan finds a credential
  SecretLoop could check, it offers to turn verification on and names the
  provider it would contact. In CI, `--verify` is explicit for the same reason.

  Every step of that is recorded in **View > Output > SecretLoop** — which
  branch was taken and on whose authority, whether an offer was made and how it
  was answered, and how many credentials actually left the machine and to whom:

  ```
  live verification is on (user setting secretloop.enableLiveVerification);
    checking 1 of 2 finding(s) in app.js.
  sent 1 credential(s) to GitHub from app.js.
  ```

  Cache hits are not counted as sends, so that number never overstates what was
  transmitted.

  Answering **Never** is permanent, so **SecretLoop: Reset Prompt Preferences**
  in the Command Palette undoes it. It clears that answer and this session's
  prompt state, and nothing else — not stored credentials, not baselines, and
  not `secretloop.enableLiveVerification`, which is a setting you change in the
  Settings UI rather than a prompt preference.
- **Confidence-tiered findings**, not one flat severity level:
  - 🟡 **Format match** — matches a known credential format, liveness not
    checked. **This is the default tier**: with verification off, every
    format-matched credential lands here, as a warning-level diagnostic.
  - 🔴 **Verified live** — confirmed active against the provider. Only reachable
    once verification is enabled (or `--verify` is passed). Surfaces as an
    error-level diagnostic — as does a check the provider refused with a 403,
    which leans live and which no retry resolves.
  - ⚪ **Entropy heuristic** — high-entropy string with no known format. Shown
    as a hint, never as an error.
  - ⚫ **Confirmed dead** — checked, and the provider says it no longer works.
    Reported quietly and last: not urgent, but still a credential sitting in
    your source, and "dead" is a claim about today.

  When a check runs but reaches no verdict, the finding is *unresolved* rather
  than safe, and SecretLoop records why — the provider was unreachable, refused
  the check with a 403, was rate-limited, or a paired credential was missing.
  Those share an outcome but not a remedy: one is an egress fix, another needs
  someone to open a provider console. Unverified never means safe.
- **Scan history** — a secret deleted in a later commit is still in the object
  store and still fetchable by anyone who has ever cloned the repo. A clean
  working tree says nothing about whether the repo has leaked.
- **Fix** — redact, extract to `.env`, or rotate at the provider, as a quick-fix
  in the editor.

## CLI

The same engine ships as a standalone binary, so CI and non-VS-Code editors get
identical results to the extension (both read the same `.secretloop.json` —
"passed locally, failed in CI" is how a scanner loses trust).

```
secretloop scan                  # working tree
secretloop staged                # staged changes (used by the pre-commit hook)
secretloop history               # every commit, for secrets already pushed

  --verify                        # confirm liveness before reporting
  --format text|json|sarif        # SARIF feeds GitHub code scanning
  --fail-on any|verified|critical|high|never
  --baseline <file>               # ignore already-accepted findings
  --write-baseline <file>         # accept everything currently found
  --rev-range origin/main..HEAD   # history: scan only this range
```

Typical CI use — fail the build on credentials that still work, and on any the
scan could not vouch for:

```bash
secretloop scan --verify --fail-on verified --format sarif -o results.sarif
```

`--fail-on verified` fails on a **confirmed-live** credential and on one whose
check **reached no verdict** — a provider that could not be reached, answered
403, or rate-limited the request. It does *not* fail on rules that have no
verifier at all: only 17 rules can be checked against a provider, and counting
the rest would make this flag behave exactly like `--fail-on any`.

> **This is stricter than it used to be.** A runner without network egress
> previously passed green: every check returned "unknown", nothing was ever
> marked live, and the gate had nothing to fire on — with live credentials
> sitting in the repository. Such a run now fails, and prints why on stderr:
>
> ```
> secretloop: --fail-on verified could not vouch for 3 credential(s):
>   2 — could not reach the provider: a connectivity problem, not a verdict on
>       the credential — fix egress and re-run
>   1 — the provider refused the check: a live-but-scoped credential and a
>       revoked one look identical here — inspect these directly
> ```
>
> If a build starts failing after an upgrade, that message names the cause. The
> usual fix is allowing egress to the provider APIs on the runner; `--fail-on
> high` remains available if you would rather gate on format alone.

Because the flag depends on a verification pass having run, `--fail-on verified`
without `--verify` is rejected outright rather than silently exiting 0.

### Exit codes

`0` — nothing met the gate. `1` — something did. Any other code is a real
failure: an unreadable config, a bad flag, a scan that could not run.

Exit 1 is the gate doing its job, not a crash, so it says so on stderr — how
many findings met the threshold, which threshold that was, and where the report
went:

```
secretloop: exit 1 — 3 finding(s) at or above --fail-on high (CI gate).
  Report written to results.sarif. Use --fail-on never for a report-only run.
```

The count is the number that **met the threshold**, not the number found: a
scan with forty mediums and one critical reports one finding under `--fail-on
critical`. The second line appears only when `-o` was given; without it there is
no file to point at.

**Report-only runs.** To scan and publish results without ever failing the
build — an adoption run on a repository with pre-existing findings, a scheduled
report, a step whose findings you want visible but not blocking:

```bash
secretloop scan --format sarif -o results.sarif --fail-on never
```

That always exits 0 and still writes every finding. When you are ready to gate,
`--write-baseline` accepts what is already there so only new findings fail:

```bash
secretloop scan --write-baseline .secretloop-baseline.json
secretloop scan --baseline .secretloop-baseline.json --fail-on high
```

## Use SecretLoop from an AI coding agent (MCP)

SecretLoop ships an MCP server, so an AI assistant you already use can run the
scanner and reason about the results. **There is no AI inside SecretLoop** — no
model, no API key, no LLM dependency. The assistant does the explaining; the
deterministic scanner does the finding, and only the scanner decides what a
finding is.

Add it to `claude_desktop_config.json` (Claude Desktop) or `.cursor/mcp.json`
(Cursor):

```json
{
  "mcpServers": {
    "secretloop": {
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"]
    }
  }
}
```

`--package=secretloop` is required, not decorative: `secretloop-mcp` is a
command inside the `secretloop` package rather than a package of its own, and
`npx -y secretloop-mcp` would go looking for a package by that name and fail.

For Claude Code, the same thing on one line:

```bash
claude mcp add secretloop -- npx -y --package=secretloop secretloop-mcp
```

### GitHub Copilot

Same server, different file. **VS Code** reads `.vscode/mcp.json`, where the
top-level key is `servers` rather than `mcpServers`:

```json
{
  "servers": {
    "secretloop": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"]
    }
  }
}
```

**Visual Studio 2022 17.14+ and Visual Studio 2026** take the same shape and
discover it automatically, checking `%USERPROFILE%\.mcp.json`, then
`<SolutionDir>\.vs\mcp.json`, `<SolutionDir>\.mcp.json`,
`<SolutionDir>\.vscode\mcp.json`, and `<SolutionDir>\.cursor\mcp.json`. Put it in
`<SolutionDir>\.mcp.json` if you want it tracked in source control, and add that
file to **Solution Items** so Visual Studio reloads it when you edit it.

In both, MCP tools are available to Copilot **only in agent mode** — pick
**Agent** from the mode dropdown at the bottom of the chat pane.

### Other MCP clients

SecretLoop's MCP server uses the standard MCP protocol over stdio and can be
connected to MCP-compatible clients that support local stdio servers. Every
client below launches the *same* server — the invocation never changes, only the
file it goes in and the key it goes under:

```
npx -y --package=secretloop secretloop-mcp
```

**Verified in a VS Code + GitHub Copilot agent-mode session during
development.**

**Documented, not individually validated:** the clients below. Each one's
documented configuration supports connecting a local stdio MCP server, and the
connection path is taken from that client's own current documentation.
SecretLoop has not individually validated these clients, and the experience will
not be identical across them — clients differ in how they surface tools, how
they ask for approval, and how much of a result they show.

Config keys genuinely differ between clients, so copy the shape for *your*
client rather than adapting another's.

**Windsurf** — `mcpServers`, in `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "secretloop": {
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"]
    }
  }
}
```

**Cline** — also `mcpServers`, either through the MCP Servers panel or by
editing the settings file directly (`~/.cline/mcp.json` for the CLI; the IDE
extension exposes the same thing through its settings):

```json
{
  "mcpServers": {
    "secretloop": {
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"]
    }
  }
}
```

**Zed** — a different key, `context_servers`, in Zed's settings file (`zed: open
settings file`, or Settings → AI → MCP Servers → Add Server → Add Local Server):

```json
{
  "context_servers": {
    "secretloop": {
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"],
      "env": {}
    }
  }
}
```

Config paths and key names are the ones each client documented when this was
written (checked 2026-09-05):
[Windsurf](https://docs.devin.ai/desktop/cascade/mcp) ·
[Cline](https://docs.cline.bot/mcp/configuring-mcp-servers) ·
[Zed](https://zed.dev/docs/ai/mcp). Clients move these; if a path here does not
match what you see, that client's own MCP documentation is the authority, and
the server invocation above is the only part that is ours.

### The five tools

| Tool | What it does |
|---|---|
| `secretloop_scan` | Scans the working tree. Optional globs narrow it. |
| `secretloop_list_findings` | Filters the last scan's findings by severity, rule or liveness. |
| `secretloop_get_finding` | One finding in full, with masked source context. |
| `secretloop_history_scan` | Scans git history, bounded by a commit and time limit. |
| `secretloop_verify` | Asks a provider whether one credential is still live — only after a human approves it. |

The first four are **read-only**: no writes, no rotation, no config or baseline
changes, and nothing destructive.

`secretloop_verify` is the exception, and the only tool that can send anything.
It transmits a credential to that credential's own provider, and only after the
consent gate is satisfied: the first call returns `CONSENT_REQUIRED` and
transmits nothing, and a person runs `secretloop approve <fingerprint>` in a
terminal before a second call can run the check. It is **opt-in, one-time, and
approved by a human in a terminal** — never by the assistant and never by a tool
argument. [Verifying a credential is live](#verifying-a-credential-is-live-secretloop_verify)
sets out the whole flow.

### What crosses the boundary, and what does not

- **No credential is transmitted without a human approving that one credential.**
  Liveness verification is the only thing in SecretLoop that contacts a third
  party, and `secretloop_verify` is the only tool that can reach it. An
  assistant cannot authorise it: the first call transmits nothing and returns
  `CONSENT_REQUIRED`, and the check runs only after a person has run
  `secretloop approve <fingerprint>` in a terminal. Every other tool sends
  nothing anywhere.
- **Values are redacted, always.** Every value is masked the same way the CLI
  masks it — the format prefix and the last four characters, as in
  `ghp_****…6789`, never the credential. There is no flag, argument or tool that
  unredacts, including in the source context returned by
  `secretloop_get_finding`.
- **Repository content comes back as data, not instructions.** Source lines are
  returned inside an `<untrusted-repository-content>` block, line-prefixed, with
  every secret in them masked and any attempt to close the block from inside
  neutralised. A repository is assumed hostile: it may contain text written to
  manipulate whatever reads it.
- **The scanner's verdicts are authoritative.** The assistant may group, sort
  and explain findings. It may not reclassify, downgrade or suppress one, and
  `unverified` means *no liveness check ran* — never that a credential is
  inactive or a file is clean. A scan that stopped early says so and is never a
  clean result.
- **The server reads only the directories it was launched with.** Allowed roots
  come from the command line that started it (the working directory by
  default), and nothing on the protocol can change them. A `path` argument
  outside them is refused, and the MCP roots capability — which VS Code and
  Visual Studio use to advertise workspace folders — is deliberately not
  honoured: a `roots/list_changed` that widened what the server may read would
  let the client move its own boundary. Such notifications are ignored and
  logged. To scan another directory, restart the server pointing at it:
  `npx -y --package=secretloop secretloop-mcp /path/to/repo`.
- **Every invocation is logged to stderr** — tool name, arguments and result
  counts, never a value — the same accounting the extension writes to
  **View > Output > SecretLoop**.

### Verifying a credential is live (`secretloop_verify`)

The fifth tool is the only one that sends anything anywhere. It answers "does
this credential still work?" the only way that question can be answered — by
presenting it to its provider — so it is **opt-in, one-time, and approved by a
human in a terminal**, never by the assistant and never by a tool argument.

It takes two calls with a person in between:

1. The assistant calls `secretloop_verify`. Nothing is transmitted. It returns
   `CONSENT_REQUIRED` and writes a request to `~/.secretloop/pending/`.
2. **You** run `secretloop approve <fingerprint>` in your own terminal. It shows
   the provider, the file and line, the masked value, and states plainly that
   the credential will leave the machine and that an MCP client asked for it.
   You answer `y` or `N`. It refuses to run without an interactive terminal, so
   it cannot be piped, scripted, or driven by an agent.
3. The assistant calls `secretloop_verify` again, and the check runs.

Approval is bound to **one** credential value, in one file, for one provider,
for one use, and expires after five minutes. It commits to a SHA-256 of the
exact bytes you were shown — so if the repository changes the value after you
approve, nothing is sent and the result is `UNKNOWN`. Denial, expiry, a changed
file, a retargeted symlink and a replay are all `UNKNOWN`; none of them is ever
`DEAD`, because only a provider can say that.

Responses disclose transmission explicitly:
`"network": { "externalTransmission": true, "destination": "GitHub" }`.

**The trust boundary is your OS user account.** The consent files hold hashes,
never credentials, and are created mode `0600` — but any process running as you
can read and write them. This protects you from a hostile repository and from an
over-eager or compromised agent. It does not protect you from malware already
running under your own account, and nothing on this machine could.

As with the other tools, your client's approval dialog governs whether the
assistant may *call* `secretloop_verify` — that is your client's control, and it
is not SecretLoop's consent mechanism. Permitting the call only lets the
assistant ask; the terminal prompt is what authorizes the transmission.

Your client's own approval prompt — Copilot's **Allow** in Visual Studio 2022,
**Confirm** in Visual Studio 2026, the equivalent in VS Code, Cursor and Claude
— governs whether the agent may *call* these tools at all; it is your client's
control, not SecretLoop's consent mechanism, and whatever you permit there, no
tool here writes anything, contacts a provider, or returns an unredacted
credential.

An assistant composes its own reply, and no server can bind what it says. The
tool responses carry the counts and the scan's scope so a claim can be checked
against them, and `secretloop scan` on the command line remains the record.

## Controlling false positives

False-positive fatigue is what gets scanners muted, so suppression is
first-class rather than an afterthought:

- `secretloop:allow` on the finding's line or the line above it. `gitleaks:allow`
  is honored too, so a repo already annotated for gitleaks needs no
  re-annotation — gitleaks shipped and has a large installed base, which is
  exactly the migration path worth carrying.
- `.secretloop.json` — `excludePaths`, `excludeRules`, `allowValues`,
  `entropyPassEnabled`. A documented template ships in the repository as
  `.secretloop.example.json`.
  Your excludes are *added to* the built-in list (node_modules, lockfiles,
  minified bundles), never replace it.
- **Baseline** — `--write-baseline` records existing findings so a repo with a
  backlog can adopt scanning today and still fail on anything new. Fingerprints
  are keyed on (path, rule, value), not line number, so reformatting doesn't
  resurrect an accepted finding.
- Built-in structural filters drop the classic noise sources before they ever
  reach you: git SHAs, SHA-256 digests, lockfile integrity hashes, UUIDs, data
  URIs, file paths, and version strings.

### Why are the fake keys in my test fixtures flagged?

Because a scanner cannot tell that they are fake. A credential-shaped string in
a fixture file and a credential-shaped string in production code are the same
bytes; the only thing separating them is intent, which is not in the file.

The entropy pass already stands down there — a generic high-entropy string in a
test, fixture or example path is not reported unless you pass
`--include-fixtures`. What still fires everywhere is a **named provider rule**,
and that is deliberate. A real token committed to a test file is a real leaked
token: it works, it is public, and the attacker reading your repository does not
care which directory it sits in. Fixture directories are one of the most common
places a real key gets pasted "just to check something" — and the fakes around
it are exactly what makes it invisible to a human reviewer.

The other half of the argument is what tolerance costs. A scanner that stays
quiet about credential-shaped values in test paths teaches you that its warnings
are optional, and a tool you have learned to scroll past protects nothing on the
day it is right.

So there is no flag that suppresses named-rule findings in fixtures, and that
absence is a decision rather than a gap. What there is instead is per-finding
suppression you can review:

- `secretloop:allow` on the finding's line or the line above it — the finding is
  annotated where it lives, so the next reader sees the judgement and can
  disagree with it. `secretloop-ignore` and `gitleaks:allow` are accepted too.
- `--write-baseline` — accept everything present today and fail only on what is
  new, which is the right move for a repository adopting scanning with a
  backlog.
- `.secretloop.json` — `allowValues` for a specific published sample,
  `excludeRules` to turn a rule off entirely, `excludePaths` for a directory.

The best fix, where you can take it, is to make the fake obviously fake:
generate fixture credentials at runtime instead of writing a literal. This
repository does that for its own test corpus, which is why scanning itself
reports nothing from it.

## Commands

All of these are in the Command Palette under **SecretLoop**:

| Command | What it does |
|---|---|
| `SecretLoop: Scan Entire Workspace` | Scans every file git would track |
| `SecretLoop: Scan Staged Files` | Checks what you are about to commit |
| `SecretLoop: Scan Git History for Secrets` | Walks all commits for credentials already pushed |
| `SecretLoop: Accept Current Findings as Baseline` | Writes `.secretloop-baseline.json` so only new findings fail |
| `SecretLoop: Install Pre-commit Hook` | Wires `secretloop staged` into `.git/hooks/pre-commit` |
| `SecretLoop: Uninstall Pre-commit Hook` | Removes it again, restoring any hook it displaced |
| `SecretLoop: Set AWS Admin Credentials for Rotation` | Stores them in the OS keychain, never in a settings file |
| `SecretLoop: Clear Stored AWS Admin Credentials` | Removes them from the keychain |
| `SecretLoop: Reset Prompt Preferences` | Undoes a "Never" answer to the verification offer |

## Remediation

- **One-click redact**: replaces the secret with a placeholder. Copying it out
  first is a separate quick-fix, *Copy to clipboard, then redact*, offered
  second and named for its risk — anything running on the machine can read the
  clipboard, and it syncs across devices.
- **One-click extract-to-.env**: moves the secret into a `.env` file, replaces
  the code with a language-aware reference (`process.env.X`, `os.environ["X"]`,
  `os.Getenv("X")`, etc.), and adds `.env` to `.gitignore` if missing.
- **Staged-file warnings** escalate only for a confirmed-live secret; anything
  else is one warning counting what the checks established — live, needing a
  look, unverified, dead — so commit-time friction is proportional to actual
  risk.

### What this deliberately does not do

No org-wide governance dashboard, policy engine, or SIEM integration — that is
GitGuardian's home turf, where breadth and enterprise trust already win. This is
scoped to the loop one developer or one small team actually runs: editor,
commit, CI.

## Project layout

```
secretloop/
├── package.json               # extension manifest + CLI bin, commands, settings
├── .secretloop.example.json # documented config template
├── .github/workflows/ci.yml   # tests + self-scan (the tool scans its own repo)
├── src/
│   ├── extension.ts     # activation, diagnostics, code actions, commands
│   ├── scanner.ts       # rule + entropy detection, confidence tiers, suppression
│   ├── rules.ts         # 100+ provider rules with keyword prescreen + allowlists
│   ├── entropy.ts       # Shannon entropy pass with structural FP filtering
│   ├── config.ts        # .secretloop.json, glob matching, fingerprints, baseline
│   ├── history.ts       # git history scanning (git log -p parser)
│   ├── walk.ts          # file enumeration honoring .gitignore via git ls-files
│   ├── report.ts        # text / JSON / SARIF output
│   ├── verify.ts        # live verification calls for 15 providers
│   ├── rotate.ts        # self-revoke or dashboard-deeplink rotation per provider
│   ├── remediate.ts     # redact / extract-to-.env logic
│   ├── hooks.ts         # install/uninstall the git pre-commit hook
│   └── cli.ts           # standalone binary: scan / staged / history
└── tests/
    ├── fixtures.ts      # synthetic credential corpus, seeded — no real secrets
    ├── rules.test.ts    # every rule vs its own sample + a false-positive corpus
    ├── scanner.test.ts  # tiers, line numbers, fingerprints, suppression
    ├── config.test.ts   # glob matching, exclude merging, fingerprint stability
    ├── history.test.ts  # git patch parsing against fixture diffs
    ├── report.test.ts   # redaction, ordering, SARIF validity
    └── verify.test.ts   # provider response parsing against mocked fetch
```

## Pre-commit hook

Run **SecretLoop: Install Pre-commit Hook** from the command palette to have
staged files scanned automatically before every commit. The hook runs
`secretloop staged` — format + entropy detection, no network calls, so a
commit is never blocked on a provider being reachable. Add `--verify` to the
hook yourself if you want liveness checks at commit time and can accept the
latency.

If a pre-commit hook already exists, SecretLoop chains to it rather than
replacing it: yours moves to `.git/secretloop/pre-commit.foreign` and runs
first, and only if it passes are staged files scanned. Uninstalling restores it.
Running it as its own process is what makes this safe — `set -e`, `exit 0` and
`exec` stay scoped to your hook instead of skipping the scan, and a
`#!/usr/bin/env python3` hook keeps running as Python.

Bypass for a single commit with `git commit --no-verify`. Remove the hook
with **SecretLoop: Uninstall Pre-commit Hook**.

## Running the tests

```bash
npm install && npm test
```

Seventeen test files, no network and no real credentials:

- **`rules.test.ts`** — the suite that matters most. Every shipped rule must
  match its own fixture (a rule that never fires is worse than no rule, because
  it creates false confidence), must not fire on a corpus of real-world
  lookalikes (git SHAs, lockfile hashes, UUIDs, `process.env` references, AWS's
  documentation key), and must not exhibit catastrophic backtracking.
- **`scanner.test.ts`** — confidence tiers, line numbers, fingerprint stability,
  offset correctness, inline suppression (`secretloop:allow` and `gitleaks:allow`),
  duplicate merging, and config-driven exclusion.
- **`config.test.ts`** — glob semantics (`*` must not cross `/`), exclude-path
  merging, fingerprint normalisation, and loading `.secretloop.json`.
- **`history.test.ts`** — patch parsing against fixture diffs: hunk line
  numbers, multi-line PEM assembly, deduplication across commits, and *not*
  reporting removed lines.
- **`report.test.ts`** — redaction (no raw secret in any output format), SARIF
  2.1.0 validity, verified-live findings sorting first, and a regression test
  pinning the versioned `secretloopFingerprint/v2` key.
- **`verify.test.ts`** — provider response parsing against mocked `fetch`,
  including the safety-critical case: a network failure returns *unknown*, never
  *not a secret*, so a flaky connection can't downgrade a live credential.

AWS verification isn't covered by unit tests since it requires
`@aws-sdk/client-sts` and a signed request; it's exercised manually.

## Running it locally

```bash
npm install
npm run compile
```

Then press `F5` in VS Code to launch an Extension Development Host with
SecretLoop active. Open any file containing a fake API key to see it flagged;
hover for the quick-fix lightbulb to redact or extract it.

## Settings

| Setting | Default | Description |
|---|---|---|
| `secretloop.entropyThreshold` | `4.3` | Shannon entropy cutoff for flagging generic strings |
| `secretloop.autoScanOnSave` | `true` | Re-scan on file save |
| `secretloop.blockCommitOnSecret` | `true` | Warn if staged files contain secrets |
| `secretloop.envFilePath` | `.env` | Where extracted secrets are written |
| `secretloop.excludePaths` | `[]` | Extra globs never scanned (added to built-in excludes) |
| `secretloop.entropyPassEnabled` | `true` | Report generic high-entropy strings with no known format |
| `secretloop.enableLiveVerification` | `false` | Make read-only calls to providers to confirm a credential is active. SecretLoop offers to turn this on the first time it finds a credential it could check |

## Security notes

- Verification calls send the detected credential value to the provider's own
  API (e.g. `api.github.com`, `slack.com`) to check validity — that's the only
  way to confirm liveness. No detected value is ever sent anywhere else. This is
  **off by default**; SecretLoop asks before making its first such call, naming
  the provider, and takes "Never" as permanent. Set
  `secretloop.enableLiveVerification` to `true` to skip the prompt, or leave it
  `false` to keep SecretLoop entirely offline.
- Verification results are cached in memory for five minutes, keyed by a SHA-256
  hash of the credential rather than the value itself, so re-scanning a file as
  you type does not re-send the secret. Every call is abandoned after five
  seconds; a timed-out check counts as unknown, never as "not a secret".
- The AWS admin credentials used for rotation are stored in your **OS keychain**
  via VS Code's SecretStorage — never in a settings file. Set them with
  **SecretLoop: Set AWS Admin Credentials for Rotation** from the Command
  Palette, and remove them with **SecretLoop: Clear Stored AWS Admin
  Credentials**. Scope that IAM identity to `iam:UpdateAccessKey` only — nothing
  broader.

  These used to be settings. If you ever put an admin key in `settings.json`,
  **treat it as exposed and rotate it**: SecretLoop migrates the value into the
  keychain and clears the setting on first launch, but that only removes today's
  copy. It does nothing about Settings Sync history, a committed
  `.vscode/settings.json`, or a dotfiles repository.

  > **Confirmed against a running extension host.** That migration reads the old
  > values through `getConfiguration().inspect()` after their manifest entries
  > were removed, and a value planted under `secretloop.awsAdminAccessKeyId` was
  > read and migrated, with a registered key probed alongside as a control.
  > Reading a key whose manifest entry is gone works.
  >
  > SecretLoop still records, in **View > Output > SecretLoop**, whether every
  > key it inspected was actually readable — so "no AWS admin credential in
  > settings" always states the basis for that claim, and a future change that
  > breaks readability surfaces as a named failure rather than a clean-looking
  > result from a check that could not look.

## Extending detection rules

Add an entry to `src/rules.ts`:

```ts
{
  id: "acme-api-key",
  description: "Acme API Key",
  regex: /\bacme_[A-Za-z0-9]{32}\b/g,
  fullMatch: true,          // false = the secret is capture group 1
  keywords: ["acme_"],      // literal prescreen; the regex is skipped without it
  entropy: 3.5,             // optional minimum entropy for the captured value
  allowlist: [/^acme_test_/], // rule-scoped false positives
  severity: "critical",
}
```

Then add a sample to `positiveSamples` in `tests/fixtures.ts` — `rules.test.ts`
fails if any rule lacks one. The `regex` must carry the `g` flag; a test enforces
that, since a non-global regex would loop forever in the scanner.

## Roadmap

Shipped since the first scaffold: git history scanning, SARIF/JSON output,
baselines, `.secretloop.json` config, inline suppression, the standalone CLI,
and the pre-commit hook installer.

The full plan lives in [`docs/ROADMAP.md`](docs/ROADMAP.md). The short version:

- **Detector parity is not the goal.** 100+ rules against gitleaks' ~160 and
  TruffleHog's 800+, and closing that gap is explicitly out of scope — nobody
  switches scanners for parity. Coverage gets added where a real user hits a
  real gap, not to move a number.
- **What is the goal** is the loop the name refers to: a finding that knows
  whether it is live, and carries its own remediation.
- **Next** is putting it in developers' hands and learning what actually hurts
  after a credential leaks — before building more of it.

Contributions that add a rule you personally needed are welcome. See
[Extending detection rules](#extending-detection-rules) above; a rule needs a
positive fixture, a negative one, and an entry in the corpus test.


---

SecretLoop — **From leaked to fixed.**
A GPY Analytics product.
