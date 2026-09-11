# MCP server

SecretLoop ships an MCP server, `secretloop-mcp`, so an AI assistant you already
use can run the scanner and reason about the results. **There is no AI inside
SecretLoop**: no model, no API key, no LLM dependency. The assistant does the
explaining; the deterministic scanner does the finding, and only the scanner
decides what a finding is.

Applies to **published 0.5.1**. Client configurations are in
[Integrations](integrations.md#mcp-clients).

## Starting it

```
npx -y --package=secretloop secretloop-mcp [allowed-directory ...]
```

`--package=secretloop` is required: `secretloop-mcp` is a command inside the
`secretloop` package, not a package of its own. The server speaks MCP over
stdio; stdout is the protocol and every diagnostic goes to stderr. Each
invocation is logged there with its arguments and result counts, never a value.

## The five tools

| tool | what it does |
|---|---|
| `secretloop_scan` | Scans the working tree of `path`. Optional `include` globs narrow it, on top of the project's own exclusions. Read-only. |
| `secretloop_list_findings` | Filters the last scan's findings by severity, rule id or liveness. Always reports the unfiltered total beside the filtered count. Refuses, rather than returning an empty list, when no scan has run. |
| `secretloop_get_finding` | One finding by fingerprint: rule metadata, location, and the surrounding source lines inside an untrusted-content block with every secret masked. |
| `secretloop_history_scan` | Scans git history, bounded to 500 commits or 45 seconds by default (caps 5,000 and 120 seconds), returning at most 500 findings and saying when it stopped early. |
| `secretloop_verify` | Asks a provider whether one *supported* credential is still live — only after a human approves it in a terminal. |

The first four never write, rotate, change configuration or contact anyone.
`secretloop_verify` is the only tool that can send anything, and only after the
consent gate below is satisfied.

The `secretloop_scan` description the server embeds names no rule count (the
0.4.0 server said "103 provider rules", which was stale when it shipped). It
describes the scanner as named
credential-format rules with a keyword prescreen plus a generic high-entropy
tier that runs only when the project's `.secretloop.json` enables it — the tool
has no input of its own for the tier. The current count is in
[coverage](coverage.md).

## What crosses the boundary, and what does not

- **Values are redacted, always.** Every value is masked the way the CLI masks
  it — the format prefix and the last four characters — and there is no flag,
  argument or tool that unredacts, including in `secretloop_get_finding`'s
  context. Projected findings carry no text offsets.
- **Repository content comes back as data, not instructions.** Source lines are
  returned inside an `<untrusted-repository-content>` block, line-prefixed,
  with every known secret masked, and any attempt to close the block from
  inside neutralised. Error messages quote caller-supplied and repository-chosen
  fragments — paths, fingerprints, revision ranges — inside the same wrapper.
- **The scanner's verdicts are authoritative.** Every payload says so. The
  assistant may group, sort and explain findings; it may not reclassify or
  suppress one, and `unverified` means *no liveness check ran*, never clean. A
  scan that stopped early says so and is never a clean result.
- **The server reads only the directories it was launched with.** Allowed
  roots come from the command line (the working directory by default) and
  nothing on the protocol can widen them. A `path` outside them is refused, and
  the MCP roots capability that editors use to advertise workspace folders is
  deliberately not honoured: such notifications are ignored and logged. Files
  whose real location is outside the allowed roots — a committed symlink — are
  dropped and counted, at enumeration and again at every read.
- **A revision range is validated before git is spawned**: only the characters
  a rev-range is made of, never a leading `-`, so no git option can be smuggled
  through `revRange`.

## Archive members and encoded findings

On `main` the scanner opens archives one layer deep and decodes base64, hex and
percent-encoded spans once. Over MCP those findings behave as follows:

- A member finding's `file` is the display path `container!/member`. Its
  fingerprint carries the container and member as structural material, so a
  real file whose name happens to look like a member path never shares an
  identity with it.
- **`secretloop_verify` refuses an archive-member finding before any provider
  lookup, before the finding is re-read from disk, and before any consent
  record is written.** Nothing is transmitted and no approval is requested. The
  refusal names the container and the member, and both are quoted through the
  same untrusted-data wrapper every other error uses, so a member name written
  to look like instructions or like the wrapper's closing tag is represented as
  data. Quoting makes untrusted text representable; it does not guarantee what a
  model does with it.
- **`secretloop_verify` likewise refuses a finding recovered by decoding an
  encoded span**: the encoded text is not the credential and the decoded form
  is never kept, so there is nothing that could honestly be sent.
- **`secretloop_get_finding` returns `context: null` for a member finding**,
  with the reason that the finding is inside an archive member, which has no
  re-readable file and is never reopened for context. Ordinary files keep their
  behaviour exactly: wrapped context, or the symlink-or-replaced reason when a
  real file no longer resolves inside the workspace.
- `secretloop_get_finding` reports whether the rule has a verifier and whether
  it is a generic (shape) rule.

These behaviours were confirmed in the pre-release security review and its two
fixes, merged as [PR #49](https://github.com/gpyanalytics/secretloop/pull/49).
See [Verification](verification.md#what-is-never-transmitted).

## The consent gate

`secretloop_verify` takes two calls with a person in between:

1. The assistant calls `secretloop_verify`. Nothing is transmitted. It returns
   `CONSENT_REQUIRED` with `network: null` and writes a pending record under
   `~/.secretloop/pending/` holding a SHA-256 of the credential, never the value.
2. **You** run `secretloop approve <fingerprint>` in your own terminal. It
   shows the provider, the file and line, the masked value, and says plainly
   that the credential will leave the machine and that an MCP client asked for
   it. Terminal control sequences in a path or value are stripped before display
   so a repository cannot repaint the prompt. It refuses to run without an
   interactive terminal.
3. The assistant calls `secretloop_verify` again and the check runs.

Approval is bound to one credential value, in one file, for one provider, for
one use, and expires after five minutes. The second call re-reads the file,
re-scans it, and compares the current value's hash with the approved
commitment; if anything differs, nothing is sent and the result is `UNKNOWN`.
The record is claimed atomically before the network is touched, so a replay
loses the race rather than sending twice. Denial, expiry, a changed file, a
retargeted symlink and a replay are all `UNKNOWN`, never `DEAD`. Responses
disclose transmission explicitly:
`"network": { "externalTransmission": true, "destination": "GitHub" }`.

**The trust boundary is your OS user account.** The consent files are created
mode `0600` and hold hashes, but any process running as you can read and write
them. This protects against a hostile repository and an over-eager or compromised
agent, not against malware already running under your account.

Your client's own approval dialog governs whether the assistant may *call*
these tools at all. That is your client's control, not SecretLoop's consent
mechanism: permitting the call only lets the assistant ask.

## Limitations

- Verified in a VS Code and GitHub Copilot agent-mode session during
  development; other clients are documented from their own documentation, not
  individually validated. The rendering of the wrapped refusal text by a live
  client was not exercised for the `main` changes.
- An assistant composes its own reply, and no server can bind what it says. The
  tool responses carry counts and scope so a claim can be checked, and
  `secretloop scan` on the command line remains the record.
