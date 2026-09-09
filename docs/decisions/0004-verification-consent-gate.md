# 0004 — An MCP verification needs a human approval in a terminal, bound to one value

**Status:** shipped in 0.2.0; the archive-member and encoded-finding refusals
and the two disclosure fixes are `main`, unreleased (PRs #43, #44, #49).
**Surface:** MCP.

## Decision

`secretloop_verify` is the only MCP tool that can transmit a credential. It takes
two calls with a person in between. The first writes a pending consent record —
a SHA-256 commitment to the credential's current bytes, its file, provider and
workspace — and returns `CONSENT_REQUIRED` with nothing sent. A human runs
`secretloop approve <fingerprint>` in an interactive terminal; the record is
approved with the current value's hash and a five-minute expiry. The second call
re-reads the file from disk, re-scans it, checks containment, compares the
commitment, claims the record atomically by rename, and only then dispatches.
Every non-verdict outcome is `UNKNOWN`, never `DEAD`.

Authorization never travels over the protocol: no tool argument, no claim that
the user approved, and no MCP roots notification can grant or widen anything.
Allowed directories are fixed at launch.

## Why

An MCP client is not a person, and a repository can be hostile. The one action
that sends a credential to a third party therefore needs a decision made
somewhere the client cannot reach, tied to exactly the bytes the person saw, and
usable once.

## Invariants, and how each is held

| invariant | mechanism |
|---|---|
| consent gate | record on disk, flipped to approved only by the terminal command |
| commitment integrity | SHA-256 of the value; mismatch deletes the record and returns `UNKNOWN` |
| consume before transmit | atomic rename before the network; a replay loses the race |
| TOCTOU | re-read, re-scan, containment re-checked at the second call |
| workspace boundary | launch-time roots; realpath containment at enumeration and read |
| untrusted content | context and error fragments quoted in a wrapper the repository cannot close |
| no leak | projected findings are masked and offset-free; the approve prompt strips terminal control sequences |
| protocol purity | stdout is JSON-RPC only; the audit log is stderr |
| git argument smuggling | revision ranges validated against an allowlist before spawn |

## On `main`

- Findings inside archive members and findings recovered by decoding are
  refused before provider lookup, before disk re-resolution and before any
  consent record is written; nothing is transmitted and no approval is requested
  (decisions 0002 and 0003).
- The pre-release security review found two low-severity disclosure issues in
  this layer and PR #49 fixed both: the member refusal now quotes the container
  and member through the established untrusted-data wrapper, and
  `secretloop_get_finding` gives a member finding the accurate reason for its
  missing context instead of the ordinary-file symlink explanation. Quoting makes
  untrusted text representable; it does not guarantee what a model does with it.

## Evidence

Consent and MCP test suites (record permissions, replay, expiry, changed value,
retargeted symlink, redaction, wrapper breakout); the pre-release security
review record (SHA-256 `7d090ba9…a122`) and its resolution addendum; the
security policy in [SECURITY.md](../../SECURITY.md).
