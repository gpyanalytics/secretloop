# MCP demo GIFs — source-verified facts

Every product string rendered by `render.py` and `render_chat.py` is copied from
this repository's source and cited below to `file:line`, at
`2cd94c3111ae14346d731fc5146c135e2101f3b0`. The renderers execute nothing: they
draw pictures.

The demo credential is **synthetic**. Its complete value does not appear in any
renderer, in this document, or in any generated artifact — only the masked form
`redactValue()` produces.

## 1. Detection

| fact | value | citation |
|---|---|---|
| rule id | `github-token` | `src/rules.ts:381` |
| description | GitHub Personal Access Token | `src/rules.ts:382` |
| regex | `/\bghp_[A-Za-z0-9]{36}\b/g` | `src/rules.ts:383` |
| severity | `critical` | `src/rules.ts:387` |
| token total length | 40 (`ghp_` + 36) | derived from the regex |

## 2. Transmission

| fact | value | citation |
|---|---|---|
| `TRANSMITTING_RULE_IDS` | `VERIFIABLE_RULE_IDS` minus `isAmbiguousIssuer` | `src/verify.ts:152-154` |
| `github-token` has a verifier | yes | `src/verify.ts:119` |
| `github-token` ambiguous? | no (absent from `AMBIGUOUS_ISSUERS`) | `src/verify.ts:109-111` |
| **`github-token` ∈ TRANSMITTING_RULE_IDS** | **yes** | derived from the two rows above |
| `stripe-secret-key` has a verifier | yes | `src/verify.ts:125` |
| **`stripe-secret-key` ∉ TRANSMITTING_RULE_IDS** | **yes — it is ambiguous** | `src/verify.ts:110` |
| Stripe exclusion reason (source comment) | "no published sub-marker separates the formats, and a wrong guess sends the key anyway" | `src/verify.ts:106-107` |
| provider display name | `GitHub` | `src/verify.ts:162` |

## 3. Redaction

`redactValue`, `src/scanner.ts:760-765`. For length ≥ 16:

    value.slice(0,4) + "*".repeat(min(len-8, 20)) + value.slice(-4)

| fact | value |
|---|---|
| synthetic token length | 40 |
| masked visible form | `ghp_********************Q7r8` |
| masked length | 28 (4 + 20 stars + 4) |

Derived from the synthetic fixture that previously lived in `render_chat.py`
before that fixture was deleted. The complete value is not recorded anywhere.

## 4. Fingerprint

| fact | value | citation |
|---|---|---|
| digest | SHA-256 hex, truncated to the first 16 chars | `src/config.ts:312-313` |
| shape | `normalizePath(path):ruleId:digest(value)` | `src/config.ts:322` |
| derived digest | `620e24b631970fdc` | local SHA-256 over the synthetic fixture |
| full fingerprint | `src/config/deploy.env:github-token:620e24b631970fdc` | |

Derivation was local hashing only: no network, no SecretLoop runtime, no
keychain, no provider call.

**The previous renderer's digest was fabricated.** `render_chat.py` hard-coded
`7e0b21e789c1a4d3`, which is not the digest of its own fixture. The true value
is `620e24b631970fdc`.

## 5. Pre-consent MCP payload

`src/mcp-core.ts:1360-1375`. Fields, exactly:

    tool: "secretloop_verify"
    state: "CONSENT_REQUIRED"
    provider
    fingerprint
    instruction   <- CONSENT_INSTRUCTION(fingerprint), src/mcp-core.ts:1180-1181
    network: null
    note          <- src/mcp-core.ts:1369-1372
    authority     <- AUTHORITY, src/mcp-core.ts:315-318

Instruction text: ``Run `secretloop approve <fingerprint>` in your terminal to
authorize this one verification.``

Note text: "Nothing has been transmitted. Verification sends this credential to
GitHub, so it requires a human to approve it in a terminal on this machine. An
assistant cannot grant this, and no tool argument can."

`CONSENT_REQUIRED` is the literal MCP payload state and is rendered as such. It
is not replaced with human-report wording. `network: null` is the source's own
no-transmission signal; no "bytes transmitted" line exists in the product.

## 6. Replay / UNKNOWN payload

`unknown()`, `src/mcp-core.ts:1184-1202`; replay call site `src/mcp-core.ts:1268`.

    tool: "secretloop_verify"
    state: "UNKNOWN"
    reason: "consent already used"
    network: null
    note: "UNKNOWN means no verdict was reached. It does not mean the credential
           is inactive, and no credential was transmitted."
    authority
    fingerprint   <- passed in `extra` at :1268

## 7. LIVE payload

`src/mcp-core.ts:1291-1306`: `state` is `LIVE` when `finding.verifyStatus ===
"live"`, and on a real transmission `network` is
`{ externalTransmission: true, destination: <provider> }` — **not** `null`.

Test backing: `tests/verify.test.ts:48-57`, "GitHub: 200 response marks token
verified with scopes", drives `verifyFinding` with `mockFetch({status: 200})`
and asserts `result.status === "live"`. `verifyGitHubToken` calls
`https://api.github.com/user` (`src/verify.ts:372-377`) — never exercised here.

No real request is made by the demo. Every LIVE frame carries the visible label
**`demo — simulated provider response; no request was made`**.

## 8. Approval CLI

`runApprove`, `src/cli.ts:967-1091`.

| fact | citation |
|---|---|
| TTY required | `src/cli.ts:982-988` |
| non-interactive refusal | `src/cli.ts:984-985` |
| approval block (provider / location / value) | `src/cli.ts:1061-1070` |
| y/N question | `src/cli.ts:1076` |
| success message | `src/cli.ts:1086-1089` |
| denial message | `src/cli.ts:1081` |
| TTL | `APPROVAL_TTL_MS = 5 * 60_000`, `src/consent.ts:40` |

Exact refusal: "secretloop: approve needs an interactive terminal. It authorizes
sending a credential to a third party, so it cannot be piped, scripted, or run
by an agent."

Exact approval block:

    SecretLoop is asking permission to verify a credential.

      provider:  GitHub
      location:  src/config/deploy.env:7
      value:     ghp_********************Q7r8

      The credential will LEAVE THIS MACHINE and be sent to GitHub.
      This was requested by an MCP client, not by you typing a command.
      Approval is for this one check and expires in 5 minutes.

    Send this credential to GitHub? [y/N]

Exact success: "Approved for one verification, valid 5 minutes. Nothing has been
sent yet — the client's next secretloop_verify call performs the check."

## 9. Commitment

| fact | value | citation |
|---|---|---|
| commitment computed internally | **YES** — `createHash("sha256").update(finding.value,"utf8").digest("hex")` | `src/cli.ts:1058` |
| commitment displayed by `approve` | **NO** — the `io.out` block prints provider, location and masked value only | `src/cli.ts:1061-1070` |

No GIF displays a commitment hash, a truncated commitment, or a "hash of the
token" annotation.

## 10. Remediation and rotation

**Correction to the task brief.** The brief stated the rotation URL map has no
GitHub entry. It does: `src/rotate.ts:136-141` maps `github-token` and
`github-fine-grained-pat` to `https://github.com/settings/tokens`, with the
message "GitHub doesn't offer self-service token revocation via API. Opened the
tokens page — revoke it there, then re-scan."

What makes rotation wrong for *this* demo is the surface, not its absence:
`rotateFinding` takes a `vscode.SecretStorage` and is imported only by
`src/extension.ts:20`. It is a **VS Code extension command**, reachable from
neither the CLI nor MCP, which are the only surfaces these GIFs show.

Remediation shown: redact in place (`src/remediate.ts:63`) and extract to `.env`
(`src/remediate.ts:107`). No GIF offers rotation, a rotation link, or one-click
rotation.

## 11. MCP tool boundary

Registered MCP tools, `src/mcp.ts:142, 166, 198, 231, 259`:
`secretloop_scan`, `secretloop_list_findings`, `secretloop_get_finding`,
`secretloop_verify`, `secretloop_history_scan`.

`grep -rn "secretloop_approve" src/` returns nothing — **approve is a CLI
command, not an MCP tool**. The stronger source-authored sentence ("An assistant
cannot grant this, and no tool argument can") is rendered only where the product
says it: inside the MCP payload `note`.

## 12. String corrections (old -> new)

Never reproduces the complete synthetic credential.

| # | renderer | old | new | citation | reason |
|---|---|---|---|---|---|
| 1 | render.py | `stripe-live-key` scenario throughout | `github-token` scenario | `src/rules.ts:381` | the demo rule must be in the transmitting set; Stripe is not (`src/verify.ts:110`) |
| 2 | render.py | `value: sk_live_51H…****…q9Zt` | `value: ghp_********************Q7r8` | `src/scanner.ts:764` | old mask was invented; new one is what `redactValue` produces |
| 3 | render.py | `config/deploy.env:stripe-live-key:7e0b21e789c1` | `src/config/deploy.env:github-token:620e24b631970fdc` | `src/config.ts:312,322` | 12-hex digest is not a shape the product emits; digest is 16 hex |
| 4 | render_chat.py | `FP=...:7e0b21e789c1a4d3` | `...:620e24b631970fdc` | local SHA-256 | the old digest was fabricated, not the digest of its own fixture |
| 5 | both | `bytes transmitted: 0` | `network: null` | `src/mcp-core.ts:1368` | no such field exists in the product |
| 6 | render.py | `expires in 10 min` | `expires in 5 minutes` / `valid 5 minutes` | `src/consent.ts:40`, `src/cli.ts:1069,1087` | TTL is 5 minutes |
| 7 | render.py | `Commitment: sha256:3b1f…e8c2` | removed | `src/cli.ts:1061-1070` | `approve` never displays the commitment |
| 8 | render_chat.py | `commitment: sha256:3b1f9a2e…` + "a hash of the token" | removed | `src/cli.ts:1061-1070` | same |
| 9 | render.py | `the key still works → rotate it now` | removed | `src/extension.ts:20`, `src/rotate.ts:127` | rotation is a VS Code command, absent from the CLI/MCP surfaces shown |
| 10 | render_chat.py | `unknown: "consent already used"` | `state: "UNKNOWN"` / `reason: "consent already used"` / `network: null` | `src/mcp-core.ts:1190-1197, 1268` | the old form is not product output |
| 11 | render.py | replay rendered as `CONSENT_REQUIRED` | replay rendered as structured `UNKNOWN` | `src/mcp-core.ts:1268` | a consumed record returns UNKNOWN, not the consent gate |
| 12 | render.py | `pending record written: ~/.secretloop/pending/9f3a…` | removed | `src/mcp-core.ts:1360-1375` | not a field of the MCP payload |
| 13 | render.py | `Send this credential to api.stripe.com to check liveness? [y/N]` | `Send this credential to GitHub? [y/N]` | `src/cli.ts:1076` | the prompt names the provider, not a hostname |
| 14 | render.py | `[x] approve needs an interactive terminal. / It cannot be piped, scripted, or run by an agent.` | exact three-line refusal | `src/cli.ts:984-985` | paraphrase replaced with source text |
| 15 | render.py | output to `/home/claude/gif/secretloop-mcp-consent.gif` | `docs/demos/secretloop-mcp-terminal.gif` | — | output must live in the repo |
| 16 | render_chat.py | output to `/home/claude/gif3/secretloop-mcp-<v>.gif` | `docs/demos/secretloop-mcp-<v>.gif` | — | same |
| 17 | render_chat.py | `KEY="ghp_"+"<synthetic credential redacted>"` | constant deleted; only `MASK` remains | `src/scanner.ts:764` | no complete PAT-shaped value may persist |
| 18 | render_chat.py | "The value arrives masked — SecretLoop redacts it before the tool result exists." | "SecretLoop returned the finding masked — the tool result carries the redacted value, not the credential." | `src/scanner.ts:760` | mechanism wording; avoids an unproven "never sees" claim |
| 19 | render_chat.py | `state: "LIVE"` with no simulation label | adds `demo — simulated provider response; no request was made` | `tests/verify.test.ts:48` | LIVE is test-backed, not a real GitHub check |
| 20 | render_chat.py | `state: "LIVE"` with no network field | `network: { externalTransmission: true, destination: "GitHub" }` | `src/mcp-core.ts:1301-1302` | on a real verify the field is populated, not null |
| 21 | both | `/usr/share/fonts/truetype/dejavu/...` hard-coded | font candidate list (DejaVu, then macOS Menlo/Helvetica) | — | the hard-coded Linux paths do not exist on this machine |
| 22 | render_chat.py | `→` in tool lines | `->` | — | the arrow rendered as a missing-glyph box |

## 13. Packaging

`docs/demos` is excluded from both distributions; see the report accompanying
this pass. Publishing these images to a README or the Marketplace later requires
stable public HTTPS asset URLs.
