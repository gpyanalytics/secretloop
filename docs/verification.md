# Verification

Verification asks a provider whether a detected credential still works. It is
the one thing SecretLoop does that sends a credential to a third party, so it is
off everywhere by default and has a separate control on each surface. Applies to
**published 0.5.0**.

## Three surfaces, three switches

| surface | switch | default |
|---|---|---|
| CLI | `--verify` | off |
| VS Code | `secretloop.enableLiveVerification` | `false`; the extension offers to enable it the first time it finds a checkable credential |
| MCP | `secretloop approve <fingerprint>` in a terminal, per credential | nothing is ever sent without it |

If your policy is that no credential leaves the machine: do not pass `--verify`,
pin the editor setting off, and either do not connect the MCP server or never
approve a request.

## Which rules can transmit

18 rules have a verifier, covering 15 providers: GitHub (four token formats),
GitLab, Slack, Stripe, Google, AWS, OpenAI, Anthropic, Hugging Face, npm,
DigitalOcean, SendGrid, Discord, Notion and Cloudflare. A credential matched by
any other rule is never transmitted, whatever the flag says.

One of the 18 never transmits either: `sk_live_`/`sk_test_` keys are issued by
Stripe, Clerk and WorkOS, nothing in the value says which, and a wrong guess
would hand a live credential to an unrelated company. That rule reports
`unknown` with the reason `ambiguous-issuer`. **17 rules can put a credential on
the wire.**

Every verifier makes the cheapest read-only call that proves the credential
works — an identity or scope endpoint — never a call that changes state. AWS
verification needs the paired secret key in the same file; without it the
outcome is `missing-pair`.

## The liveness tri-state

| status | meaning |
|---|---|
| `live` | the provider confirmed the credential works |
| `dead` | the provider says it no longer works |
| `unknown` | the check reached no verdict, and the reason is recorded |

`unknown` is never collapsed into `dead`. A 403 can mean revoked or
live-but-scoped, and calling it revoked produces exactly the sentence someone
reads when deciding not to rotate a live key. Unverified never means safe.

Reasons an outcome is `unknown`:

| reason | what happened | what to do |
|---|---|---|
| `network` | the provider was never reached, or the 5-second timeout fired | fix egress and re-run |
| `provider-refused` | a 403: a live-but-scoped credential and a revoked one are indistinguishable | inspect it in the provider console |
| `provider-unavailable` | a 429 or 5xx | retry later; says nothing about the credential |
| `missing-pair` | the check needs a second credential that is not nearby | AWS: the secret key must sit in the same file |
| `no-verifier` | no rule-level check exists at all | judge it on format |
| `ambiguous-issuer` | the format is shared by several providers | confirm it in the issuing provider's dashboard |
| `unsupported-transform` | the finding came from decoding an encoded span; the encoded text is not the credential and the decoded form is never kept | judge it on format |
| `unsupported-container` | the finding is inside an archive member, which no surface can re-read to confirm what would be sent | judge it on format |

## What is never transmitted

- Values matched by rules without a verifier, and the ambiguous Stripe format.
- Findings inside archive members and findings recovered by decoding.
  On every surface the refusal happens before dispatch, and the outbound record
  never counts them. Over MCP the refusal also happens before a consent record
  is written, so a human is never asked to approve a send that cannot happen.
- Cache hits: outcomes are cached in memory for five minutes, keyed by a
  SHA-256 of the value, and joining an in-flight request is not a second send.

The CLI, the extension's Output channel and the MCP audit log all record what
actually left the machine — the count and the providers — not what was
attempted, so the record cannot overstate.

## The consent gate

Over MCP an assistant cannot grant verification. The first `secretloop_verify`
call transmits nothing and returns `CONSENT_REQUIRED`; the check runs only after
a person runs `secretloop approve <fingerprint>` in a terminal, which refuses to
run without one. Approval is opt-in, one-time, bound to a SHA-256 of the exact
value shown, and expires after five minutes. The full flow, and why every
non-verdict outcome is `UNKNOWN` rather than `DEAD`, is on the
[MCP page](mcp.md#the-consent-gate).

## Rotation is separate

Verification never rotates anything. Rotation is a VS Code quick-fix on a
confirmed-live or provider-refused finding: Slack tokens can be revoked through
Slack's API; GitHub, Stripe and Google open the provider console; AWS opens the
IAM console or, with stored admin credentials, deactivates the leaked key. There
is no automated key-minting rotation and none is planned; see the
[roadmap](project/roadmap.md#permanently-out-of-scope).
