# Troubleshooting

The messages SecretLoop prints when it refuses, cannot look, or gates a build,
and what each one means. Applies to **published 0.6.0**. The separated skip
clauses marked below are new in 0.6.0.

## Exit codes

| code | meaning |
|---|---|
| `0` | Nothing met the `--fail-on` gate. Not proof of a clean repository: read the scope sentence. |
| `1` | The gate fired. stderr names the count that met the threshold, the threshold, and the report path if `-o` was given. |
| `2` | A real failure: unreadable configuration, an unknown flag or mode, `--fail-on verified` without `--verify`, a `staged` run outside a git repository, an unsupported Node version. |

## Messages

**`SecretLoop requires Node >=18.0.0 (you are running …).`** — printed before
anything else loads, exit 2. Upgrade Node; the liveness checks use the runtime's
built-in `fetch`.

**`nothing was scanned, so this is not a clean result`** — the staged set was
empty, or every enumerated file was skipped. Exit 0, but the sentence is there so
a scan that looked at nothing is not read as a pass.

**`git could not list staged files: …`** — a `staged` run could not read the
index (not a repository, or the index is locked). Exit 2 rather than a
clean-looking empty scan, so a pre-commit hook fails closed.

**`--fail-on verified could not vouch for N credential(s)`** — verification ran
but reached no verdict for some findings. The lines under it say why: fix egress
for `could not reach the provider`; inspect directly for `the provider refused
the check`; retry later for rate limits. `--fail-on high` gates on format alone
if that is what you want.

**`--fail-on verified requires --verify`** — the gate depends on a verification
pass having run. Exit 2.

**`--fail-on <x> is not a known mode`** — use one of `any`, `verified`,
`critical`, `high`, `never`. Exit 2.

**`allowValues entry "…" is not a valid regular expression`** — fix the pattern in
`.secretloop.json`. The message quotes the pattern, which is one reason to keep
whole credentials out of `allowValues`.

**`Could not parse .secretloop-baseline.json: …`** — the baseline file is
corrupt. It is named so you know which file to fix.

**`N file(s) not scanned — larger than maxFileSizeBytes`** — raise
`maxFileSizeBytes` in `.secretloop.json` if those files matter.

**`N file(s) not scanned — binary`** — **new in 0.6.0; 0.5.1 and earlier print
`binary or unreadable` instead and count it against completeness.** A NUL byte in
the first 8,000 bytes:
input a text scanner is not meant to read. An intentional exclusion, so it is
disclosed but does **not** make the report incomplete. PKCS#12 keystores are
still detected structurally, and archives are still opened — neither is counted
here.

The test is a probe, not a proof, and it does **not** mean the file is free of
secrets — only that nothing looked. **UTF-16 and UTF-32 text lands here**, since
those encodings pad ASCII with NUL; so does any text with an embedded NUL. Such
a file is still read in full — the test runs on bytes already in memory — but
none of its content is *scanned*, before or after the NUL. One stray NUL near
the top of a large source file therefore costs you the whole file. A binary file
whose first 8,000 bytes carry no NUL is *not* caught and is scanned as text. If you keep credentials in a
UTF-16 file, convert it to UTF-8 to bring it into scope.

**`N file(s) not scanned — could not be read`** — **new in 0.6.0; see above.**
The scan meant to read these and could not: a permission or I/O
failure, or a binary format it supports but
could not conclusively inspect. Unlike a binary skip, this **does** make the
report incomplete, because "we could not look" is never evidence that nothing
was there.

**`N path(s) not scanned — not a regular file`** — a directory, fifo, socket or
device turned up where a file was expected.

**`N file(s) not scanned — gone before they could be read`** — the path was
enumerated and had disappeared by the time the read reached it.

**`N recognized archive container(s) not opened`** — a file with archive
magic that the parser declined (corrupt, or ZIP64). It was scanned as raw text
instead; the structured `summary.archives` object says why.

**`N archive(s) not fully enumerated`** — a container walk stopped at the
10,000-entry cap, the decompression budget, a truncation or a bad header. The
remainder was not looked at; for a ZIP the count of uninspected entries is
known, for a tar it is not.

**`The finding no longer resolves in this workspace; re-run secretloop_scan`**
(MCP) — the file changed, moved, or points outside the allowed roots since the
scan.

**`… is outside the directories this server was started with`** (MCP) — the
server reads only the roots it was launched with. Restart it pointing at the
directory: `npx -y --package=secretloop secretloop-mcp /path/to/repo`.

**`No scan has been run … call secretloop_scan first`** (MCP) — a listing or
detail request with no scan in this session is refused rather than answered
with an empty list.

**`CONSENT_REQUIRED`** (MCP) — not an error: verification needs a person to run
`secretloop approve <fingerprint>` in a terminal. See
[Verification](verification.md#the-consent-gate).

**`secretloop approve` refuses to run** — it needs an interactive terminal; it
cannot be piped, scripted or driven by an agent. Ctrl-D is a no.

## Findings you did not expect

**Fake keys in test fixtures are reported.** By design: a named rule cannot tell
a fake from a real one, and fixture directories are where real keys get pasted.
Use an inline directive, a baseline, or `allowValues`, or generate fixtures at
runtime. See [Configuration](configuration.md#why-fake-keys-in-test-fixtures-are-still-reported).

**Too much noise after `--include-entropy`.** That is the tier's measured
character: 279 of 299 false positives on the frozen benchmark. Leave it off,
try `--key-context`, or scope it with `.secretloop.json`. See
[Benchmarks](benchmarks.md).

**I want to see what the entropy tier finds in my fixtures.** There is one
documented command for that, with what it does and does not establish:
[Inspecting fixtures and test data](cli.md#inspecting-fixtures-and-test-data).

**A finding disappeared after upgrading.** Compare the scope sentence. Since
0.4.0 the entropy tier is off by default; `--include-entropy` reproduces the
previous output byte for byte. On `main`, a value inside an OpenAPI document is
no longer reported by the entropy tier unless `--include-api-document-entropy`
is passed.

**A finding changed rule or fingerprint after upgrading to 0.5.0.** The one intended case: with
`--include-entropy --include-fixtures`, a 32-byte base64 key that
`encryption-key-assignment` now claims reports under that rule instead of
`generic-high-entropy`, so its fingerprint changes and a baseline entry for the
old identity stops matching. Re-accept it.

**The pre-commit hook broke my existing hook.** It should not: an existing hook
is moved to `.git/secretloop/pre-commit.foreign` and run first as its own
process. **Uninstall Pre-commit Hook** restores it.

**`npx -y secretloop-mcp` fails.** The command is inside the `secretloop`
package: use `npx -y --package=secretloop secretloop-mcp`.

## Reporting a problem

Bugs and questions: the repository's issue tracker. Vulnerabilities: the
private channel in [SECURITY.md](../SECURITY.md), never a public issue.
