# MCP server

SecretLoop ships an MCP server, `secretloop-mcp`, so an AI assistant you already
use can run the scanner and reason about the results. **There is no AI inside
SecretLoop**: no model, no API key, no LLM dependency. The assistant does the
explaining; the deterministic scanner does the finding, and only the scanner
decides what a finding is.

Applies to **published 0.6.0**. Two disclosures are new in 0.6.0 and absent from
0.5.1: `secretloop_list_findings` returning the scan's `scope`, and
`secretloop_history_scan` reporting inline-suppression counts.
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
| `secretloop_list_findings` | Filters the last scan's findings by severity, rule id or liveness. Always reports the unfiltered total beside the filtered count, and — **new in 0.6.0** — the `scope` of the scan those findings came from. Refuses, rather than returning an empty list, when no scan has run. |
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
- **Listed findings say what was inspected to produce them.** **New in 0.6.0**;
  0.5.1 returns no `scope` here.
  `secretloop_list_findings` returns the `scope` of the scan behind its rows —
  the same object `secretloop_scan` returned, carried through the session cache
  rather than recomputed. Before this it returned no `scope` at all: a client
  got rows with no account of their origin.

  **What it establishes:** which working-tree scan of which root produced these
  findings, and what that scan inspected — `filesScanned`, `outsideExcluded`,
  `apiDocumentsScoped`, any `archives` accounting, the scope sentence and
  (**Unreleased**) `openedFileChecks`, the per-descriptor accounting of the
  readers' identity and kernel-path checks — counts only, no path — described
  in [coverage](coverage.md#opened-file-checks). The scope statement ends with
  the same accounting as its last clause.

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

- **A history scan discloses what it suppressed, as a count.** **New in 0.6.0**;
  0.5.1 discloses neither count here. The
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

**The store is checked before it is trusted** (**Unreleased**). On macOS and
Linux every consent operation — reading a record at either call, listing for
`secretloop approve`, approving, claiming and deleting — first requires
`~/.secretloop` and `~/.secretloop/pending` to be real directories (not
symbolic links) owned by your account with mode `0700`. A directory you own
that is too open is set to `0700` and re-checked; one owned by another account
is never changed and is refused; a link is never followed. When the check
fails, `secretloop_verify` answers with an error in fixed words (no path,
record, hash or OS message) and transmits nothing, and `secretloop approve`
refuses with the same words and approves nothing. The check covers the store's two directories by mode bits and ownership, **and
the whole path above them**. Every directory from `~/.secretloop` up to the
filesystem root must be a real directory, owned by you or by root, and not
writable by anyone else; on macOS it must also carry no extended access-control
entry. The walk does not stop at a mount boundary. It does not close a window
against a process already running as you, and a directory re-permissioned after
it was inspected is not seen.

**Setups this refuses that used to work.** A group-writable home directory, even
if the group contains only you — there is no portable way to ask who else
belongs to a group, so every group-write bit counts as a grant. A home under a
directory owned by another ordinary account. A world-writable directory anywhere
on the path, unless it is also sticky and owned by you or root, which is why
`/tmp` still works. A path more than 64 directories deep.

If SecretLoop refuses for this reason, look at the path yourself with `ls -ld`
starting at your home directory and find the one directory that is too open. Fix
that directory; ask an administrator if it is not yours. **Do not** make a whole
tree private, and do not remove access-control entries wholesale to clear the
message — you would be changing far more than the thing at fault.

**What it costs.** Each directory on the path is inspected on every consent
operation, and nothing is cached: a remembered "safe" answer would keep asserting
something about a directory that may since have changed. On Linux that is a
`lstat` per directory and is not measurable. On macOS each directory also costs
one `/bin/ls`, so the cost scales with how deep your home is: a typical
`/Users/you/.secretloop` inspects **4 directories**, and a consent operation
measured at **60 ms** with 16 directories and about **170 ms** with 40 on an
arm64 laptop. The work is bounded twice, by a cap on directories walked and a cap
on inspections per operation.

On **Linux** the mode is enough on its own to exclude a named-user or
named-group ACL entry, because the ACL mask and the mode's group bits move
together — measured as a second account on ext-family and overlay filesystems
with POSIX draft ACLs, and not claimed for NFSv4 ACLs, network mounts or
filesystems that were not measured.

On **macOS** the mode says nothing about extended entries, so SecretLoop
inspects the store, `pending` and each record with the built-in `/bin/ls` and
**refuses any object carrying an extended access-control entry**, including one
inherited from a parent directory. The check runs before anything is written, so
a store created under a parent with inheritance entries is refused while it is
still empty rather than after a record has been put in it.

This is a support restriction, not a judgement that your ACL is unsafe.
SecretLoop does not evaluate entries, so it also refuses ones that grant nobody
anything:

- a `deny`-only entry;
- an entry naming only your own account;
- an `only_inherit` entry, which never applies to the object it sits on;
- entries added by backup software, or by an employer's device management, or
  inherited from a home directory your organisation configured.

If your store is refused for this reason, inspect it yourself with
`ls -lde ~/.secretloop`. SecretLoop will not strip entries for you, and you
should not remove them to make the message go away: if you did not configure
them, move the store aside instead and let SecretLoop create a fresh one, then
ask the client to request the verification again. If `/bin/ls` cannot be run, or
its answer does not fully validate, SecretLoop refuses rather than assuming
there is no entry. A filesystem that cannot report access-control lists at all
has not been tested. Each record is checked as well: it is opened once, without following a
link at its own name and without waiting on a pipe, and must be a regular file
you own with no group or other permission bits and a plausible size, decided
before any of it is read. A record that fails is refused, not repaired, and the
refusal is reported rather than being turned into "no pending request". A
missing `pending` directory under an
existing, private `.secretloop` is not an error; it is recreated on the next
request. If you meet the refusal on a
store you did not create, move it aside rather than deleting or loosening it,
and ask the client to request the verification again. **Windows:** the check is a
different one, because mode bits are not meaningful there. SecretLoop reads the
owner and the access list of `.secretloop`, of `pending` and of each record it
is about to use, and requires every entry to allow only your account, SYSTEM or
Administrators, the owner to be one of those three, and your account to hold
full access; a reparse point at any of them is refused and never followed. Each
record is checked on its own, because a record another account planted and a
protected parent later caught looks private while its owner stays that account.
Every folder from the drive root down to the store's parent is checked too, and
the store is refused if any account outside a small platform set can delete,
rename or re-permission one of them. A new store is created private and a failed
creation withdraws only what it made; an existing store is refused rather than
repaired. The built-in `powershell.exe` and `icacls.exe` are used for this; if
either cannot be run, or a store sits on a network or UNC path, the request is
refused rather than assumed safe. Applying an access list does not revoke a
handle another process already holds, and for a store that already existed these
checks describe the present only, not its history.

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
