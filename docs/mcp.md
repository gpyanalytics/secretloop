# MCP server

SecretLoop ships an MCP server, `secretloop-mcp`, so an AI assistant you already
use can run the scanner and reason about the results. **There is no AI inside
SecretLoop**: no model, no API key, no LLM dependency. The assistant does the
explaining; the deterministic scanner does the finding, and only the scanner
decides what a finding is.

Applies to **published 0.5.1**, except for two disclosures marked below —
`secretloop_list_findings` returning the scan's `scope`, and
`secretloop_history_scan` reporting inline-suppression counts. Both are **merged
on `main` and prepared as 0.6.0, not published**: an installed 0.5.1 does neither.
Client configurations are in [Integrations](integrations.md#mcp-clients).

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
| `secretloop_list_findings` | Filters the last scan's findings by severity, rule id or liveness. Always reports the unfiltered total beside the filtered count, and — **new in 0.6.0, not published** — the `scope` of the scan those findings came from. Refuses, rather than returning an empty list, when no scan has run. |
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
- **Listed findings say what was inspected to produce them.** **New in 0.6.0 —
  merged, not published; an installed 0.5.1 returns no `scope` here.**
  `secretloop_list_findings` returns the `scope` of the scan behind its rows —
  the same object `secretloop_scan` returned, carried through the session cache
  rather than recomputed. Before this it returned no `scope` at all: a client
  got rows with no account of their origin.

  **What it establishes:** which working-tree scan of which root produced these
  findings, and what that scan inspected — `filesScanned`, `outsideExcluded`,
  `apiDocumentsScoped`, any `archives` accounting, and the scope sentence.

  **What it does not establish:** freshness. `source: "session-cache"` and
  `scannedAt` already say these findings describe an *earlier* observation, and
  `scope` makes no claim that a scan just ran. It is also **not** the report
  comparator's `scopeDigest`: nothing is hashed, nothing identifies a selection
  for comparison, and no eligibility decision reads it.

  **Filters do not move it.** A filter narrows which rows come back, not what
  was looked at; `matched`, `totalInScan` and `filteredOut` are what describe
  the narrowing. `scope` is unchanged by filtering, so provenance survives it.

  **Response-level, not per-finding, and deliberately.** The session cache has
  exactly one writer — `secretloop_scan` — which stores the scope in the same
  object literal as the findings, so an entry always describes exactly one
  working-tree scan of one root. A per-row field would repeat that on every row
  and could drift from it, so none was added. Provenance is therefore never
  unknown here; it cannot be, because no other operation can write the cache.

  **History never mixes in.** `secretloop_history_scan` keeps its own scope in
  its own response and writes nothing to the session cache, so a history scan
  can neither restamp nor contribute to what `list_findings` returns.

  **No prior scan is not an empty result.** `list_findings` still refuses when
  no scan has run for the root, and that refusal is unchanged. A completed scan
  that found nothing answers normally, with its scope, saying what it inspected
  while finding nothing — which is a different statement.

- **A history scan discloses what it suppressed, as a count.** **New in 0.6.0 —
  merged, not published; an installed 0.5.1 discloses neither count here.** The
  scope sentence `secretloop_history_scan` returns now carries the
  inline-suppression counts the CLI's has always carried — *N finding(s)
  suppressed by inline directives, M with a recorded reason* — so a scan that
  dropped findings to a `secretloop:allow` no longer reads like one that had
  nothing to drop. It is
  **aggregate only**: no reason text, no suppressed value, no fingerprint, no
  path, no source line, and no suppressed finding as a result row. Nothing new
  is hashed and no suppression identity is created.
  The reason clause appears only when a reason was actually recorded. It is
  absent both when a scan recorded none and when the producer could not
  establish the count at all — the sentence cannot distinguish those two, and
  the CLI's sentence never could either; the CLI's JSON report is where the
  difference is visible, as an omitted field rather than a zero.
  A scan that stopped early keeps its existing partial sentence, which makes no
  coverage claim at all: counts describe only what was inspected, and
  incompleteness stays disclosed through `complete` and `stopReason`.
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
