# Changelog

## Unreleased

**Not in any published package.** Published 0.5.0 behaves as described under
that heading below.

### Verification diagnostics

- **A GitHub 403 that carries rate-limit evidence is no longer read as a refusal.**
  GitHub documents that both a primary and a secondary rate limit can arrive as a
  `403`, distinguished by `x-ratelimit-remaining: 0` or a `retry-after` header. Every
  `403` was mapped to `provider-refused`, whose remedy tells the reader to go and
  inspect the credential — the opposite of what a rate-limited check needs. Those two
  responses now map to `provider-unavailable` and name the header that says when to
  retry. A `403` carrying neither keeps `provider-refused` and its wording unchanged.
  The evidence is read in the GitHub verifier rather than in the shared status mapper,
  so Stripe, Google, Cloudflare and every caller of the shared bearer-token helper are
  untouched.
- **Slack's documented policy refusals are no longer reported as transient.**
  `access_denied`, `accesslimited`, `ekm_access_denied` and `enterprise_is_restricted`
  are described in Slack's own error table as policy or administrative restrictions.
  All four were mapped to `provider-unavailable`, telling the reader to retry later —
  advice that can never succeed against a policy. They now map to `provider-refused`.
  The five errors that mean a token is finished still read `dead`, unchanged, and every
  other error, including one this build has never seen, stays `provider-unavailable`.
- **A Slack rate-limit response is no longer reported as a network failure.** Slack
  documents `429` with `Retry-After` and no JSON payload. The verifier parsed the body
  before looking at the status, so that response threw, and the throw was reported as
  `network`: "failed before reaching the provider", about a provider that had answered.
  The status is now read first and the body is never touched for a `429`. A response
  that arrives and cannot be parsed is `provider-unavailable`; `network` is reserved
  for a request that never arrived.
- No credential's liveness verdict changed. `live` and `dead` are pinned by a separate
  test, no request count changed, and no retry, delay or additional request was added.

### VS Code

- **The workspace-scan summary discloses suppressed findings.** The CLI scope
  sentence and the MCP `scope` object both report findings dropped by an inline
  `secretloop:allow` or `gitleaks:allow` directive, and generic-tier findings
  suppressed in test and fixture paths. The editor summary reported neither,
  although the per-file counters were already carried through the shared
  workspace scan, so a scan that silently dropped findings read exactly like one
  with nothing to drop. **Scan Entire Workspace** now totals both counters and
  passes them to the same formatter the CLI uses, so the clauses, their wording
  and their order are identical across the three surfaces, and a zero count
  still prints nothing. No finding, fingerprint or suppression decision changed.
- **`secretloop.excludePaths` is now read.** The setting has been declared in
  the extension manifest since it was added, and nothing consumed it: a user
  could add a glob in editor settings, get no error, and watch the files be
  scanned anyway. The editor's configuration builder now resolves it through
  VS Code and concatenates it onto the exclusions already in force, so a scan
  skips the built-in defaults, plus `excludePaths` from `.secretloop.json`,
  plus the editor setting. The merge is additive: an editor setting can exclude
  more than the project file does, never less, and an empty setting changes
  nothing. Non-string entries are ignored rather than passed to the glob
  compiler. All three editor scan paths — the workspace command, the staged
  scan and the on-save document scan — pick it up, because the read happens in
  the shared builder rather than at each call site. Baseline generation
  deliberately does not consult it: a baseline is a shared project artifact and
  must not depend on one contributor's editor settings. The setting is declared
  without a configuration scope, so VS Code resolves one value per window;
  per-folder overrides in a multi-root workspace are still not supported.
  Detection, fingerprints, verification, archive handling, the CLI and the MCP
  server are unchanged.

### History scanning

- **Cancelling a history scan now stops the parsing too.** Aborting already
  killed the `git log` process and resolved with the partial result, but
  whatever git had written before dying was still parsed, so progress kept being
  reported for a scan the caller had stopped — up to the entire history when git
  finished before the consumer read it. The stdout handler now ignores chunks
  delivered after the abort and stops at the line the abort fired on, discarding
  the partial trailing line. Findings parsed before the abort are still returned,
  the process is still terminated, the promise still resolves rather than
  rejecting, and an uncancelled scan is unchanged. This also removes the timing
  dependence from the one test that had flaked in CI: it can now assert the
  exact commit count instead of "fewer than the whole history".

## 0.5.0 — 2026-09-09

Published to npm, Open VSX and the VS Code Marketplace on 2026-09-09 from
commit `fd6637d7`, tagged `v0.5.0`. Nine merged pull requests: #43, #44, #45,
#47, #48, #49, #50, #51, #52.

**Upgrade note.** A default scan now reads inside archives and decodes encoded
spans, so a repository whose only exposed credential sat in a `.zip` or behind
base64 can move from exit 0 to exit 1 with no configuration change. If you run
the generic entropy tier, findings inside OpenAPI, Swagger and AsyncAPI
documents are no longer reported unless you pass
`--include-api-document-entropy`. One fixture-path line changes fingerprint for
users running `--include-entropy --include-fixtures`, because the new
`encryption-key-assignment` rule now claims a value the entropy tier used to
report; re-accept that one finding into your baseline. No rule id, threshold,
severity or output format was removed or renamed.

### Detection scope

- **Encoded credentials.** Standard base64, hexadecimal and URL percent-encoded
  runs are decoded exactly once and the named rules run over the decoded text.
  A run of at most 4,096 characters decoding to 12–4,096 bytes of strict UTF-8
  without NUL qualifies; decoded output is never re-decoded and the entropy
  tier does not run over it. The finding reports the encoded span, folds the
  transform into its fingerprint, and is never transmitted: verification
  returns unknown with reason `unsupported-transform` on every surface, and
  the MCP consent flow writes no record for it. (PR #43)
- **Archives.** ZIP, tar, gzip and gzip-wrapped tar files are opened in memory,
  one layer deep, and each member is scanned as a file at
  `container!/member`. Nothing is extracted; nested archives stay opaque.
  Limits are fixed: 10,000 entries per container, member names up to 1,024
  characters, members over `maxFileSizeBytes` refused before decompression,
  total output at most 100 times the outer file. Encrypted, ZIP64, unsupported
  compression, traversal, absolute, duplicate, symlink, hard-link and device
  entries are refused and counted. Member findings are never transmitted
  (reason `unsupported-container`). (PR #44)
- **API description documents.** With the entropy tier enabled, a `.json`,
  `.yaml` or `.yml` text recognised as an OpenAPI, Swagger or AsyncAPI document
  is scanned by every named rule but not by the entropy heuristic, and the scan
  reports how many documents that affected. `--include-api-document-entropy`
  and `includeApiDocumentEntropy` restore the previous behaviour with identical
  fingerprints. History scans and `mask` are unchanged. (PR #45)
- **Archive coverage disclosure.** The scope sentence, JSON `summary.archives`,
  SARIF invocation properties, MCP `scope.archives` and the VS Code summary
  now count containers opened, members scanned, members refused by reason,
  members excluded by configuration, metadata entries skipped, containers not
  fully enumerated (with the number of declared entries not inspected where
  known) and recognised containers that would not open — separately from file
  counts. A recognised container that will not open takes the ordinary text
  path and is not double-counted as a binary skip. Findings, fingerprints and
  exit codes are unchanged. (PR #47)

### MCP

- The `secretloop_verify` refusal for an archive-member finding quotes the
  container path and member name through the same untrusted-data wrapper as
  every other repository-authored fragment; control characters become spaces
  and long fragments are truncated with a note. The refusal still happens
  before provider lookup, consent minting and any transmission.
  `secretloop_get_finding` now gives an archive-member finding the accurate
  reason for its missing context instead of the ordinary-file symlink
  explanation. Ordinary files behave exactly as before. (PR #49)
- The `secretloop_scan` tool description no longer states a rule count. It said
  "103 provider rules" from the server's first release in 0.1.7, when the rule
  set already numbered 109. It now describes the scanner as
  named credential-format rules with a keyword prescreen plus a generic
  high-entropy tier that runs only when the project's `.secretloop.json`
  enables it. Descriptive metadata only: no schema, scanning, consent,
  verification or network behaviour changed.

### Documentation

- The documentation is consolidated: one page per topic under `docs/`, a hub at
  `docs/README.md`, planning pages under `docs/project/`, decision records
  under `docs/decisions/`, and the benchmark records under `docs/benchmarks/`.
  The old paths (`RESULTS.md`, `docs/ROADMAP.md`, `docs/BACKLOG.md`,
  `docs/MARKET.md`, `docs/BENCHMARK.md`, `docs/PRIMER.md`) remain as pointers
  because the published 0.4.0 README links to some of them. `SECURITY.md`
  names the current published version and the archive and decoding handling.
  `CONTRIBUTING.md` is new and excluded from the VSIX. `RELEASING.md` §6 points
  its rule-count check at the moved pages; no gate changed.

### Rules

One new rule — 109 rules to 110. No existing rule ID, threshold, fingerprint
or output format changed.

- **`encryption-key-assignment`** — a quoted 32-byte symmetric key in
  canonical base64 (exactly 43 symbols and one `=`) assigned to an identifier
  ending in `aes…key` (optionally `aes128`/`aes192`/`aes256`, `cbc`/`gcm`),
  `secretbox…key` or `encryption…key`; high, format-match, no verifier. It
  takes `generic-api-key-assignment`'s separator and quote grammar whole, adds
  the same 3.5-bit entropy floor (base64 of thirty-two zero bytes is
  forty-three `A` and a pad, which the repeated-character placeholder rule
  cannot see past the pad), and is a named rule: it reports in test and
  fixture paths at default settings, where the one validated benchmark site it
  recovers lives. Provider-neutral by design — the identifiers name the same
  material in Rails, libsodium, Terraform and Helm. With the entropy pass on,
  a value this rule claims is no longer offered to the entropy tier, so the
  same line stops being counted as a suppressed generic finding in a fixture
  path, and with `--include-fixtures` it reports under this rule's identity
  rather than `generic-high-entropy` (a new fingerprint for that one line).
  Outside the rule on purpose: bare (unquoted) values, the Kubernetes
  `EncryptionConfiguration` `secret:` field, hex keys, 16- and 24-byte keys,
  the URL-safe alphabet and Go raw strings.

### Dependencies

- Development-only lockfile refresh, resolving three advisories in release
  tooling: **js-yaml 4.3.1 → 4.3.2** (GHSA-2883-xcg3-v3hh / CVE-2026-84375,
  high, reached through `@vscode/vsce`'s secretlint integration) and
  **qs 6.15.3 → 6.16.0** (GHSA-4mjr-xmp4-gh2g / CVE-2026-82417 and
  GHSA-x5fp-wj9c-mxmx / CVE-2026-82562, moderate). Both are in-range updates
  of transitive development dependencies; `package.json` declares no runtime
  dependency and none was added, and all three shipped bundles are byte-
  identical across the change. (PR #52)

## 0.4.0 — 2026-09-08

**Generic high-entropy scanning is now opt-in.** `entropyPassEnabled` defaults
to `false`, so a default scan reports named-format rules and file-level PKCS#12
detection only.

This **intentionally reduces default recall**. The entropy pass is the tier that
catches credentials with no recognisable shape, and turning it off by default
means a scan that says nothing has looked at less than it used to.

The evidence is uneven and worth stating precisely. The N9 study in
`bench/N9-ALPHA-FRAC.md` observed both true and false generic-entropy findings,
but did not compare those true positives against rule-only detection, so the
incremental recall uniquely contributed by the entropy pass was not measured.
What is measured is the cost: in that same N9 six-repository study the tier
produced 279 of the 307 false positives. A default is being set on the measured
half of that trade, and the unmeasured half is the reason the tier ships intact
rather than removed.

Restore it with `"entropyPassEnabled": true` in `.secretloop.json`, or per run
with `secretloop scan --include-entropy` (also `staged` and `history`). In VS
Code, explicit project configuration wins over the editor setting. On the CLI,
`--include-entropy` wins over project configuration.

The VS Code `secretloop.entropyPassEnabled` setting is now honored. It was
declared in `package.json` but never read, so changing it previously had no
effect on scanning — anyone who set it to `false` was already getting the
entropy pass regardless. It is now a real opt-in, and its default is `false` to
match.

**Measured on the frozen six-repository benchmark** at
`fd013706d31a3b21a9c80d8a991ea14ff54b66e7`, using the same protocol, the same
frozen labels and the same 145-site validated universe as the 0.3.0 release
benchmark:

- default: **167 TP / 20 FP / 0 unknown**, 89.3% precision,
  SITE_FILE 137/145 = 94.5%
- entropy-enabled (`--include-entropy`): **181 TP / 299 FP / 0 unknown**,
  37.7% precision, SITE_FILE 142/145 = 97.9%

The default removes 293 findings: **279 false positives and 14 validated true
positives**, costing 5 additional validated sites. The 14 are all
`generic-high-entropy` in Kubernetes AES encryption-config test data — base64
key material matching no provider format, so no named rule reaches it. This
change is **not recall-neutral**, and the higher precision figure does not stand
on its own.

`--include-entropy` reproduced the prior frozen reports **byte-for-byte**: all
six report JSON files are identical hash-for-hash to the authoritative 0.3.0
artifacts, so the previous behaviour is available exactly, not approximately.
Nothing else moved — all 293 removals are from that one tier, with zero
non-generic removals, zero additions, zero changes to surviving findings, and
all 8 PKCS#12 true positives retained. Evidence — benchmark-workspace freeze
record: `entropy-default-freeze-fd01370.md`.

`secretloop mask` is unchanged: it reports named rules only unless you pass
`--entropy`.

## 0.3.0 — 2026-09-08

Two rule defects, both found by the six-repository precision benchmark
(`bench/precision/`) and both fixed at the mechanism rather than by
allowlisting the values that exposed them. No version bump; no change to any
other rule, to the entropy pass, or to the recorded benchmark results.

- **`onepassword-service-account` reported ordinary identifiers.** The rule was
  `ops_` in front of `[A-Za-z0-9+/=_-]{40,}`. Every character of the prefix is
  in the variable class and the class admits `_`, so the pattern described one
  unbroken run of snake_case: any forty-character lowercase identifier starting
  with `ops_` matched it. The benchmark caught it reporting a test-fixture
  directory name at severity critical, from a manifest containing no credential
  at all. The rule now declares the existing `postPrefixEntropy` floor at
  **3.75 bits** — the highest 0.25-step floor that lost nothing across
  10,000,000 uniform draws at the rule's own 40-character minimum over its own
  67-symbol class, where the least random draw carried 3.9776 bits.

- **`http-basic-auth-url` reported documentation examples.** URLs on RFC 2606's
  reserved `example.com`, `example.net` and `example.org` cannot resolve to
  anyone's host, so a credential embedded in one has no account behind it. The
  captured passwords in these findings were ordinary lowercase strings that
  clear the rule's entropy gate and are not documentation words, so no filter
  over the captured value could distinguish them — only the authority could.
  New `matchAllowlist` on `SecretRule` tests patterns against the whole match
  instead of the capture, and this rule declares one entry for those three
  domains and their subdomains. The `.test`, `.example`, `.invalid` and
  `.localhost` TLDs RFC 2606 also reserves are deliberately excluded: no
  benchmark false positive used one, and adding them would widen what the
  scanner hides with nothing measured to show it is safe. `db-connection-string`
  has the same URL shape, produced no such false positive, and is unchanged.

Across the six pinned repositories this removes 7 false positives (axios 4,
deno 3) and adds none, with no surviving finding's fingerprint changed. One
`http-basic-auth-url` false positive in `requests` is knowingly left in place:
its host is registrable, so the mechanism above cannot reach it, and its actual
cause is a different one — an f-string placeholder captured as a password —
which is not addressed here.

A third fix, in the scanner rather than in any rule, closing the one false
positive the two above knowingly left standing.

- **Bare `{IDENT}` placeholders are no longer reported as URL credentials.**
  `isPlaceholder` already rejected the shell and template forms, `${NAME}` and
  `$NAME`, through its `EXPANSION` guard. Python f-strings, `str.format`
  templates and most CI substitution syntaxes name a value with braces and no
  leading sigil, so that guard — which keys on `$` — never saw them, and a
  template naming a password was captured as the password. This was the single
  `http-basic-auth-url` false positive left in `requests` by the example-domain
  fix above, and it is a different mechanism: a gap in the scanner's shared
  placeholder guard, not in any rule. No rule pattern changed.

  The new check is anchored at both ends and requires the body to be an
  identifier, so it matches only a value that is *entirely* a template.
  `{key}abc123` is a password containing punctuation and still reports; so do
  `{key-value}`, `{}` and `{1abc}`, whose braces wrap something no program
  could name. Its cost is stated rather than hidden: a genuine credential that
  is both brace-wrapped and identifier-shaped would be suppressed. Nothing in
  the corpus looked like that.

  Because `isPlaceholder` runs for every rule before any allowlist, the change
  reaches the four rules whose captures admit braces —
  `generic-api-key-assignment`, `db-connection-string`, `http-basic-auth-url`
  and `snowflake-credentials`. Every other rule's capture is a positive
  character class with no brace in it, and the entropy tier cannot produce this
  shape at all: both of its candidate patterns are `[A-Za-z0-9+/=_.-]`.
  Measured across the six pinned repositories, the change removes exactly one
  finding and adds none.

A file-level detector for PKCS#12 keystores, the first detector that is not a
regex rule. No version bump.

- **New `pkcs12-private-key` detector.** A `.pfx`/`.p12` container is DER, and
  DER is NUL-dense, so it is dropped by the binary check before `scanText` ever
  runs — no `SecretRule` could see one at any severity. This is therefore a
  file-level detector beside the walker's read rather than a rule, and
  **`rules.ts` stays at 109**. Verifier counts are unchanged at 18 rules across
  15 providers, 17 of which can transmit.

- **Content-driven and extension-independent.** Detection is a structural
  ASN.1 walk, never a byte search for key OIDs: a container renamed `.bin`, or
  with no extension at all, still reports, and a key OID sitting inside a
  certificate payload does not. Qualifying evidence is a DIRECT plaintext
  `keyBag` or `pkcs8ShroudedKeyBag` decoded at the structural `SafeBag.bagId`
  position, reached through a supported outer `pkcs7-data` `authSafe`.

- **One finding per qualifying container.** Multiplicity is 1. That is a
  finding-unit decision, not an inability to count: direct plaintext key bags
  are perfectly countable, and SecretLoop deliberately reports the container.

- **A bag-neutral descriptor.** The finding value is the synthesized,
  non-secret sentence `PKCS#12 keystore, <n> bytes, private-key material
  present`. It never claims the key is shrouded, because either bag type can
  qualify. No DER, key bytes, or container digest reaches any output surface.

- **Non-dereferencing candidate scope.** The detector reads candidate bytes
  only when `lstat` says the directory entry is itself a regular file, so a
  symlink alias never yields a second finding for the same container. The
  existing text scanner's symlink behaviour is unchanged.

Three classes of key material are deliberately NOT detected. In each case the
detector does not look, which is not the same as the location being empty — no
claim is made about what is there, or about how common these shapes are:

1. material reachable only through an accepted opaque inner `encryptedData` or
   `envelopedData` sibling, which is never decrypted;
2. material reachable only through a nested `safeContentsBag`, which is
   recognised but never traversed;
3. material reachable only through an outer `pkcs7-signedData` `authSafe`,
   whose payload is not parsed and whose signature is not verified.

- **`secretloop --version`.** Prints the package version and exits 0 without
  scanning. The value is read from `package.json` at run time rather than kept
  as a constant in `src/`, so it follows the release version and cannot drift
  from it. `--version` only: no `-V` alias, and `secretloop version` remains an
  unknown command.

- **Public evidence and docs.** `RESULTS.md` is new: the measured six-repository
  benchmark, its methodology, and its limitations, kept separate from the older
  `docs/BENCHMARK.md` study, which measured something else and is unchanged. The
  README's comparison tables now cite current official vendor documentation for
  every competitor claim and carry no measurement for tools that were not
  benchmarked. `RELEASING.md` gains a rule requiring every strong public verb to
  map to an implementation or test at the strength claimed.

## 0.2.1 — 2026-09-05

Documentation accuracy only — no code, detection, or behaviour change from
0.2.0. The scanner, the rules and the MCP layer are byte-identical: `git diff
v0.2.0..v0.2.1 -- src/` is empty.

- `SECURITY.md` now names all three credential-egress surfaces: the `--verify`
  flag on the command line, the `secretloop.enableLiveVerification` setting in
  the editor, and the `secretloop approve` consent gate for the
  `secretloop_verify` tool an MCP client can call. It previously named two and
  told a reader that closing one was half the job, which left the surface an AI
  agent can reach unmentioned.
- Corrected counts across the docs: **109 rules**, and three numbers that had
  been used interchangeably — **18 rules have verifiers**, covering **15
  providers**, **17** of which can transmit.
- `--key-context` and the previously undocumented configuration keys are
  documented, and the install example names the current version.

## 0.2.0 — 2026-09-04

A local MCP server, so an AI coding agent can drive the scanner without the
scanner becoming an AI product. Detection is unchanged from 0.1.7 and stays
deterministic: the same bytes always produce the same findings, and nothing in
this release asks a model what a secret is.

SecretLoop sits **beside** the scanner you already run, not in place of it. If
gitleaks or TruffleHog gates your CI, keep them there. What is new here is a
controlled interface for the agent that reads your code — one that discloses
what it did not look at, and that cannot send a credential anywhere without a
human saying so in a terminal.

### The MCP server, and its five tools

`secretloop-mcp` speaks MCP over stdio and exposes exactly five tools:

| Tool | What it does |
|---|---|
| `secretloop_scan` | Scans the working tree. Optional globs narrow it. |
| `secretloop_list_findings` | Filters the last scan by severity, rule or liveness. |
| `secretloop_get_finding` | One finding in full, with masked source context. |
| `secretloop_history_scan` | Scans git history, bounded by commit and time limits. |
| `secretloop_verify` | Asks whether one credential is still live — see below. |

Add it to Claude Desktop, Claude Code or Cursor with
`npx -y --package=secretloop secretloop-mcp`; the README has the exact config.

Four of the five are read-only: no writes, no rotation, no config or baseline
changes. Every value is masked the way the CLI masks it, and no tool argument
unredacts. Repository text comes back inside an `<untrusted-repository-content>`
block with any attempt to close that block from inside neutralised — a
repository is assumed hostile, because a file can be written to manipulate
whatever reads it. Server roots come from the command line only; a client
cannot widen them, and paths that resolve outside them are refused before any
filesystem access.

### Verification requires a human, in a terminal

`secretloop_verify` is the one thing that can send a credential off the machine,
and an assistant cannot authorise it. The first call transmits **nothing**: it
returns `CONSENT_REQUIRED` and writes a pending record committing to a hash of
the value, never the value. A human then runs `secretloop approve <fingerprint>`
in a terminal, sees the provider, the location and the masked value, and answers
the prompt. Only then does a second call reach the provider.

The approval is bound to what was on disk when the human looked. If the file
changed, was deleted, was replaced by a symlink pointing out of the workspace,
or if the record is expired, reused or forged, the answer is `UNKNOWN` and the
provider receives nothing. A repository that asks to be verified — in a file, a
filename or a commit message — gets `CONSENT_REQUIRED` and nothing else.

### A scan says what it did not read

The MCP scope statement now discloses skipped files exactly as the CLI does,
word for word: files excluded as generated, findings suppressed by inline
directives, files whose symlinks resolve outside the scan root, generic findings
suppressed in fixture paths, files larger than `maxFileSizeBytes`, and files
skipped as binary or unreadable.

Two of those clauses were previously missing from the MCP surface, so a scan of
a tree whose credentials all sat in oversized or binary files reported the same
sentence as a scan with nothing to hide. Both surfaces now derive the counts
from one classification rather than counting separately, and a test pins the MCP
sentence against the CLI's on a tree carrying both kinds of skip.

### Unchanged

No rule, threshold, severity, fingerprint or output format changed. Scanning the
same tree with 0.2.0 and 0.1.7 produces byte-identical findings.

## 0.1.7

Republish. The 0.1.6 VS Code Marketplace package accidentally bundled dev
dependencies (built from a working tree instead of a clean checkout),
producing an oversized VSIX. No code, rule, or behaviour change from 0.1.6;
the npm package and Open VSX were unaffected. This release ships the
correctly packaged extension.

## 0.1.6

### Fixed — a shared credential format is no longer sent to one of the providers sharing it

`sk_live_`/`sk_test_` is issued by Stripe, Clerk and WorkOS alike. 0.1.5 said so
in this file and in the rule's own description, and then verified every match
against Stripe's API anyway — so scanning a codebase that uses Clerk or WorkOS
and passing `--verify` sent a live secret key to a company that had not issued
it. Verification's one promise is that a credential reaches its own issuer and
nobody else, and for two of the three providers sharing this format it was not
kept.

Such a credential is now **not sent anywhere**. The finding still reports —
same rule, same severity, same fingerprint, and this repository's self-scan is
byte-identical — but its liveness reads *unknown*, with a reason that says the
format has more than one issuer and that checking it would have meant handing it
to the wrong one. The refusal happens before any verifier runs, so no request is
built at all.

The cost is stated rather than argued away: a genuine Stripe key is now
unverified too. No published marker separates the three formats, and guessing
which issuer a key belongs to sends it either way — so the check is declined
rather than gambled. Verification is opt-in and occasional; a disclosure is
permanent.

The record of what left the machine is corrected to match. It fired before the
check ran, so a refusal would have been logged as a send — and that record's
only value is that it cannot overstate what was transmitted.

A guard now walks every rule that has a verifier and asserts its credential can
reach no host but its own provider's. It fails on the previous behaviour, which
is how this defect would have been caught.

### Documentation

- `SECURITY.md` now states what the tool does with your code and your
  credentials: scanning is local and dependency-free, the two features that can
  reach the network are named with the control each one answers to, and the
  editor's `enableLiveVerification` setting is called out because refusing
  `--verify` alone does not cover it.
- Rule counts in `README.md` no longer name an exact figure that goes stale on
  the next rule, and the verifier figures are corrected: fifteen providers
  rather than eighteen, and seventeen rules that can transmit rather than
  eighteen.
- A new README entry answers why credential-shaped values in test fixtures are
  reported, what already stands down there, and which suppressions exist.

## 0.1.5

### Precision — an opt-in key-context gate on the entropy tier

`--key-context`, and `keyContextRequired` in config, report a **quoted**
generic high-entropy string only when the identifier it is assigned to carries
a secret-like word: `key`, `token`, `secret`, `pass`, `password`, `auth`,
`cred`, `bearer`, `private`, `session`, `cookie`, `signature`, `signing`,
`salt` and the obvious spellings around them. Nothing else changes — no rule ID,
no threshold, no severity, no output format, and no fingerprint.

**It ships off, and the default is a measurement result rather than caution.**
The number that would justify turning it on for everyone is the fraction of
*true positives* it suppresses, and that number cannot be measured with
available data. Estimating it requires knowing the identifiers real secrets are
stored under; the two real-world proxies bracket it from opposite sides by
selection bias. Identifiers taken from a keyword-anchored detector's own hits
match the word list **100.00%** of the time — that detector only fires on such
names, so the population is selected to match. Identifiers taken from every
high-entropy string in real packages match **10.54%**, because that population
is overwhelmingly hashes and resource IDs rather than credentials. Any
threshold placed between 0% and 89% suppression is chosen, not measured. So the
noise reduction is published as a figure, the gate is opt-in, and the trade is
left to whoever knows how their own repository names things. A false negative
in a secret scanner is the expensive direction, and a default-on gate would buy
a measured drop in noise with an unmeasured number of silent misses.

**Measured noise reduction**, over 123,940 files of fourteen published SDKs and
frameworks at pinned commits, holding 20,396 candidates: **14.36% suppressed**
(2,928). That aggregate is concentrated — one generated-client monorepo carries
80.10% of the candidates and suppresses 1.02% of them — so the figure without it
is reported beside it: **68.06%** (2,762 of 4,058). Neither number is the true
one; together they bound how much the answer depends on which repositories are
in the corpus. Per-repository rates run from 0.00% to 90.46%, which is the
result restated: this gate's value depends on naming conventions, which is
exactly why it is a choice.

Of the candidates, 91.58% are quoted literals but only 15.72% have a resolvable
identifier at all. The remaining 75.86% — array elements, bare JSON values,
anything with no assignment in front of it — fall through untouched, and 8.42%
are unquoted and never gated.

**The identifier never comes from inside the candidate.** The search region
ends before the opening quote and never crosses a newline, so no part of a
value is ever evidence about itself. This is the fixed constraint the design is
built around rather than an implementation detail: the previous attempt derived
the identifier from the candidate, and since a Firebase Cloud Messaging
registration token reads `AAAA<id>:APA91b<rest>`, the bare-assignment pattern
split it at the token's own colon and gated a real credential on half of
itself. Resolution returns nothing on anything unclear, and nothing means fall
through — the gate only ever suppresses when it has a confident,
outside-the-span identifier.

Matching is whole-word after a camel, snake, kebab and digit split, never
substring: `author` is not `auth`, `keyboard` is not `key`, `bypass` is not
`pass`, `design` is not `sign`. `api`, `hash` and `sign` are excluded outright —
too common in identifiers holding nothing, and `api` alone would open the gate
for most of a client library.

Quoted literals only. Bare assignments, `.env`-style lines and values inside
larger tokens are never gated, and bare-assignment support is out of scope.
The flag reaches this gate and nothing else: the ordered-run and path-shape
vetoes, the post-prefix entropy floors and every provider rule are unaffected
by it in both positions.

`bench/keyed-corpus.ts` reproduces the measurement and imports its predicates
from the shipped source, so the numbers cannot drift from what runs.
`bench/keyed-repos.txt` records every repository and the full commit it was
read at.

### Rules

Six new provider rules — 103 rules to 109. No existing rule ID changed, no
existing threshold changed, and no output format changed. Every format below was
verified against the provider's own documentation before its pattern was
written, and each minimum length is a conservative floor rather than a
documented value, because none of these providers publishes one.

- **`openrouter-api-key`** — `sk-or-`, critical. Ships without a post-prefix
  entropy floor, and that is measured rather than overlooked: the variable
  portion is hexadecimal, so at the rule's minimum length a 3.75 floor rejects
  85.0968% of legitimate keys, 3.00 rejects 0.0111%, and only 2.50 reaches zero
  — where it excludes nothing the length requirement does not already exclude.
- **`vercel-access-token`** — `vcp_` `vci_` `vca_` `vcr_` `vck_`, high, floor 3.00.
- **`supabase-secret-key`** — `sb_secret_`, critical, floor 2.75. Publishable
  keys are documented as safe to expose in source and are never reported.
- **`neon-api-key`** — `napi_`, critical, floor 3.50. The class excludes `_`, so
  Node-API symbols such as `napi_create_string_utf8` stop at their first
  underscore and cannot reach the minimum.
- **`tailscale-api-key`** — `tskey-api-`, `tskey-client-`, `tskey-scim-`,
  `tskey-webhook-`, critical, floor 2.75.
- **`tailscale-auth-key`** — `tskey-auth-`, critical, floor 2.75. Kept separate
  from the API rule because a pre-authentication key provisions a device onto
  the tailnet rather than administering it, and the two are revoked in different
  places.

Each floor is the highest value that lost nothing across 10,000,000 uniform
draws at that rule's own minimum length.

### Fixed — OpenRouter keys were reported as OpenAI keys

`openai-api-key` matches `sk-` followed by a character class that contains
everything an OpenRouter key puts after `sk-`, so every `sk-or-…` key was
reported under the wrong provider. That is worse than a generic finding: the
provider selects the verifier, names the consent prompt and picks the rotation
link, so the finding sent you to the wrong console. Fixed the way the same
overlap was already fixed for Anthropic — an allowlist entry on the broader
rule, `/^sk-or-/` beside `/^sk-ant-/`. OpenAI's own key shapes are unaffected.

**Re-baseline after upgrading.** A fingerprint is `path:rule-id:digest`, so a
`sk-or-…` finding already accepted into a baseline under `openai-api-key` no
longer matches under `openrouter-api-key`: the digest is unchanged, the rule ID
is not, and the finding returns as new.

### Changed — a format three providers share is named as such

`stripe-secret-key` now reads *"Stripe / Clerk / WorkOS secret key (format
shared by all three)"*. All three issue secret keys as `sk_live_`/`sk_test_`,
and no pattern separates them, so none is attempted — but a finding that said
"Stripe" and meant Clerk sent someone to rotate a key in a dashboard that does
not hold it.

## 0.1.4

### Precision

Two vetoes on `generic-high-entropy` and a clearer exit message. The vetoes come
from the first external run of this tool on a real frontend monorepo, which
returned two findings and no true positives. Both were from this one tier and
both are now fixtures.

No rule ID changed, no entropy threshold changed, no severity or confidence
changed, and no output format changed. Across this repository, 15 entropy-tier
findings disappear, **no named-rule finding disappears**, and every surviving
finding keeps its fingerprint byte for byte.

**Ordered character runs are no longer read as randomness.** Shannon entropy
counts how often each character occurs and never looks at what follows what, so
a printed alphabet is the highest-scoring string there is — every character
exactly once. The reported false positive was an email-validation character
class at entropy 6.02, higher than any credential scores. A candidate is now
rejected on either of two order statistics: a monotonic run of six or more
consecutive character codes, or 40% of adjacent pairs one code apart. Two
conditions because neither sees the other's shape, and the pair fraction sits
high because small alphabets produce sequential pairs by chance far more often
than base64 does.

Measured before enabling, against the same 140,000-sample realistic-token corpus
0.1.3 used for the post-prefix floor, at one recorded seed: **0 rejected by run
length, 0 by pair fraction — 0.0000% loss.** Bare 32- and 64-character hex was
added to that corpus because 0.1.3's carried none and a 16-symbol alphabet is
where sequential pairs arise by chance: 0 of 20,000 at 64 characters and 1 of
20,000 at 32, and that one could not have been a candidate anyway — lowercase
hex is two character classes, so it faces the higher bar, and 16 symbols cannot
exceed 4.0 bits.

The cost is stated rather than argued away: a credential that genuinely contains
a printed run of six or more consecutive characters is no longer reported by
this tier. A keyword-anchored credential is unaffected, because
`generic-api-key-assignment` does not consult it.

**Slash-separated CamelCase paths are no longer read as credentials.** The other
reported false positive was a Storybook component title at entropy 4.39. Paths
like that are how a whole ecosystem names things — stories, routes, i18n keys,
GraphQL operations — and each segment being a word is what makes the string
score like a token while carrying no randomness. A candidate is vetoed only when
all three hold: two or more separators, every segment letters with **no digits**,
and at least one segment carrying a lowercase-to-uppercase transition.

The letters-only condition is the safety margin. Identifier paths rarely have
mid-segment digits and random tokens almost always do, so it is what keeps this
away from a base64 payload and from a 40-character AWS secret key with no
`AWS_SECRET_ACCESS_KEY` anchor — which has no named rule and depends on this
tier entirely. Measured against the same corpus: **5,202 of 140,000 samples
carry two or more slashes (3.7157%), and 0 of them satisfy all three —
0.0000% loss.** The first number matters as much as the second: it says the
veto is exercised rather than vacuously safe.

Both vetoes are evaluated inside the entropy tier alone. Named provider rules
are unconditional and do not consult either.

`bench/entropy-vetoes.ts` regenerates that corpus and imports both predicates
from the shipped source, so the numbers above cannot drift from what runs.

### Changed — the exit-code message says how many, and against what

`exit 1: findings at or above the fail-on threshold (this is the CI gate, not an
error)` told a reader the gate had fired and nothing else. It is now:

```
secretloop: exit 1 — 3 finding(s) at or above --fail-on high (CI gate).
  Report written to results.sarif. Use --fail-on never for a report-only run.
```

The count is what **met the threshold**, not what was found: a scan with forty
mediums and one critical says one under `--fail-on critical`. The second line
appears only when `-o` was given. Exit-code semantics, finding contents and
every other line of output are unchanged, and the message stays on stderr — a
piped report is byte-identical. The README gains an exit-codes section with a
`--fail-on never` report-only example.

## 0.1.3

Two false-positive fixes. Both come from a twenty-repository survey run against
0.1.2 **after** it shipped — a different and much broader exercise than the two
SDK checkouts 0.1.2 was tuned against, and no part of it changed 0.1.2.

No rule ID changed and no existing threshold changed. No output format changed.
Findings that survive these fixes keep their fingerprints: across this
repository and the source files below, 283 findings are present before and
after with byte-identical fingerprints, and nothing new appeared.

### Fixed — fixed-prefix rules matched low-diversity runs

A rule that matches a fixed literal prefix followed by a character class has a
problem when every character of that prefix also belongs to the class: the
pattern then describes one unbroken run of one alphabet, and any long enough run
of that alphabet satisfies it.

`twitter-bearer-token` is the extreme case — twenty-one `A` characters in front
of `[A-Za-z0-9%]{50,}`. In one public repository it produced **7,129 findings at
`high` severity from five files** of assembly padding and committed test data.
The existing repeated-character guard did not catch them: it requires the value
to be a single character repeated, and padding with two stray bytes in it is
not. A `high` severity rule firing seven thousand times on padding is the
fastest way to teach someone to ignore alerts.

**The variable portion after the prefix must now clear an entropy floor.** One
mechanism, applied to the eight rules that share the defect, rather than eight
separate exceptions — `atlassian-api-token`, `facebook-access-token`,
`github-fine-grained-pat`, `intercom-token`, `jfrog-token`, `pypi-token`,
`square-access-token` (one of its two branches) and `twitter-bearer-token`. Of
103 rules, 55 are fixed-prefix and 28 carry the precondition; the floor is
enabled only where the variable run is long enough for a threshold to be shown
safe. It fails open: a rule that declares nothing is untouched, and a prefix
that stops matching leaves the finding reported rather than dropped.

The threshold is measured, not chosen. Two populations, both on the portion
after the prefix:

| population | Shannon entropy |
|---|---|
| the false positives above, re-scanned from the source files | 0.040 – 3.337 bits |
| 100,000,000 uniformly random tokens at the tightest enabled configuration | **4.1649 bits minimum** |

The floor sits at 3.75 — the midpoint, 0.413 bits above the worst false positive
and 0.415 below the least random of a hundred million legitimate tokens.

Distinct-character count was measured and **rejected** as the discriminator: the
least diverse of those tokens carried 21 distinct characters and the worst false
positive carried 29, so the two populations overlap on diversity and separate
only on entropy.

Measured on a 200,000-sample synthetic corpus (deterministic, one recorded
seed), with every value drawn from the character class the rule's own pattern
declares:

- **legitimate-token loss: 0 of 140,000 — 0.0000%.** Per rule, at both the
  documented token length and the shortest length the pattern accepts.
- every false-positive-shaped sample the scanner reported before the change is
  rejected after it, across all eight rules
- no finding was added anywhere
- on the five source files: **7,129 findings before, 0 after**

Known boundary, stated rather than hidden: a variable run drawn from a
16-symbol alphabet at 50–60 characters straddles the floor. None of these eight
providers issues tokens of that shape, which is why the rules that do — such as
`sentry-auth-token`, whose run is declared over 65 symbols but issued as hex —
are deliberately not on the list.

### Fewer findings — `go.work.sum` is excluded, like `go.sum`

`go.sum` has always been excluded. Go workspaces (Go 1.18+) put the same content
in a second filename — module paths, versions and checksums — and that one was
never listed. One public repository produced **44 entropy findings from a single
`go.work.sum`**, every one a module digest. Measured on that file: 44 before, 0
after.

It joins the base exclusion group, beside `go.sum` rather than in the
generated-file group, so the two files answer `--include-generated` the same
way: **neither is restored by it**, which has always been true of `go.sum`. The
alternative would have made the flag scan one and not the other, a difference
nobody could predict from the filenames.

### Measured and not fixed — fixed-prefix matches inside base64 assets

The same survey found `square-access-token` and `facebook-access-token` matching
inside base64 blobs embedded in a vector image and a machine-learning resource
file — five findings — and suggested the entropy floor above would cover them
too. **Measurement rejected that, and they are unchanged.**

Those values carry 4.33 to 4.81 bits over 95 to 119 characters. The least random
of 10,000,000 uniformly random legitimate tokens of the same length carries
4.885. A gap of 0.075 bits sits *inside* the legitimate distribution's own tail,
so no threshold separates the two populations, and one that appeared to would be
fitted to a pair of samples rather than to a property of credentials. A test
asserts these still match, so lowering the threshold to reach them fails loudly
instead of quietly trading real credentials for five findings.

A different mechanism might address them. None is proposed here on this
evidence.

## 0.1.2

One safety fix, one precision pass, and remediation guidance on the surfaces
that had none. No rule IDs, thresholds or fingerprints changed, so existing
baselines keep matching. The only output change is additive: SARIF results gain
a `properties.remediation` field.

### Fixed — fixture-path suppression could hide a real credential

0.1.1 stopped reporting *generic-tier* findings in test, fixture and example
paths. "Generic tier" was `generic-high-entropy` **or** `genericRuleIds`, and
that set's single member is `generic-api-key-assignment` — a `high` severity
`format-match`, and the only rule covering providers with no named format. So
`api_key = "…"` in a test file was hidden at default settings, in the place
credentials most often leak.

It was worse than one hidden rule. Suppression runs inside `scanText`, and
verification runs afterwards over what `scanText` returned, so a
**verified-live** credential in a fixture path had no path by which it could
ever report.

The two policies had been fused only because `generic: true` was introduced for
overlap tiebreaking and then reused for suppression. They are separate now:
suppression covers the entropy pass alone. **Suppress the guess, never the
certainty.**

This surfaces findings that were previously hidden, and on a repository that
keeps credentials in fixtures that is a large number. A large open-source
JavaScript SDK gains 64
working-tree and 84 history `generic-api-key-assignment` findings — 9 and 23
distinct values, mostly one test API key repeated across fixture JSON. They were
always in those files; 0.1.1 was not showing them. That is the fix working, not
a regression. A large open-source Objective-C SDK gains one, because its suite
lives in `Tests/` and
the path match is case-sensitive — see below.

Known and unchanged: the fixture-path match is case-sensitive, so `Tests/` is
not recognised where `tests/` is. Recorded in the code rather than fixed here,
because making it case-insensitive *widens* suppression and this release
narrows it. It is safe to do later precisely because of the split above.

### Fewer findings — the entropy tier skips structured text

Entropy false positives are not random: they are structured text that happens
to score well. Each matcher below is paired with an assertion that real
credentials still report through it.

- **Mangled and plain C/ObjC symbols.** A crash report is a symbol table.
- **Source filenames and `#import` targets** — a closed extension list, so a
  high-entropy value ending `.pem` or `.key` still reports.
- **Absolute paths with doubled slashes or `+` segments** — dyld image paths.
  Not a new filter; the existing one could not match an empty segment or a `+`.
- **Dotted identifier chains** — reverse-DNS bundle ids, build products,
  `process.env.X`, `this.foo.Bar` — **only when every segment is itself
  low-entropy.** A JWT is three dot-separated base64url segments, so the shape
  alone would have skipped 56.96% of them; the segment condition takes that to
  0.0000%.
- **Whole `NAME=value` build settings**, keyed on an `=` that is not base64
  padding.
- **Module specifiers, by syntactic position** — the operand of `from`,
  `require`, `import` or `declare module`. Position rather than shape, because
  a shape-based rule for these costs 1.802% of random keys, and because
  `const token = "ghp_…"` is not an import whatever the value looks like.
- **Xcode `.xcscheme` files join the generated group.** Their noise is
  build-target names, which are bare identifiers and cannot be matched by shape
  safely.

There is deliberately **no bare-identifier matcher**. Every predicate that would
clear the remaining ObjC-constant noise skips 100% of AWS access key ids or
`ghp_` tokens — `AKIAIOSFODNN7EXAMPLE` is SCREAMING_SNAKE_CASE. That noise stays
visible on purpose, and the reasoning sits beside the code.

Measured on both checkouts with `--fail-on never`, split by tier because the two
halves of this release move in opposite directions: the entropy tier is the
precision work, and the format-match column is the safety fix surfacing findings
0.1.1 hid.

| corpus | entropy | format-match | total |
|---|---|---|---|
| JS SDK (tree) | 4 → **0** | 0 → **64** | 4 → 64 |
| JS SDK (history) | 26 → **19** | 2 → **86** | 28 → 105 |
| ObjC SDK (tree) | 132 → **0** | 1 → 1 | 133 → 1 |
| ObjC SDK (history) | 196 → **23** | 3 → **6** | 199 → 29 |

A rising total is the expected result on a repository that keeps credentials in
fixtures. Read the entropy column for the noise reduction and the format-match
column for what was being hidden.

Every specific-rule finding, and the `high` API key in one project's test
fixtures, still reports. Fingerprints are unchanged for all 48
findings present in both the 0.1.1 and 0.1.2 scans.

### Remediation guidance

A finding now says what to do about it. Previously only the editor knew — the
CLI, JSON and SARIF surfaces reported a credential and suggested nothing, which
is the half of "detect, verify, remediate" that CI actually reads.

- **The text report and SARIF carry guidance** on a genuine finding: remove the
  credential from source and load it from an environment variable instead. In
  SARIF it is per result, in `properties.remediation`; rule metadata is
  untouched, so nothing about a rule changes with the files a scan covered.
- **VS Code offers the matching quick-fix** where it applies — *Move to `.env`
  and reference it*, alongside redact and, for a credential that verified live,
  rotate. **The `.env` write happens only when you invoke that quick-fix.**
  Nothing is written automatically, and a scan never writes anything.
- **Fixture findings still report, and carry no relocation advice.** Now that
  format-match findings in test paths are visible, telling someone to move
  `YOUR_BROWSER_API_KEY` out of a fixture and into `.env` would be wrong advice
  — so the finding appears without it, and the editor withholds only that one
  action there. Redact and rotate stay available, because a credential that is
  genuinely live in a test file is the most dangerous thing this tool finds.
- JSON is unchanged.

## 0.1.1

Precision and honesty, plus four narrowly-scoped detection fixes found by
benchmarking against gitleaks and TruffleHog. Every other rule, rule ID and
threshold is unchanged.

### Fewer findings
- **Generated files are skipped by default** — lockfiles (`*.lock`, including
  CocoaPods `Podfile.lock`), Gradle and Maven wrappers, Xcode project files and
  SARIF reports. Scan them anyway with `--include-generated`, which bypasses
  this group only: `node_modules`, `package-lock.json` and minified bundles are
  never scanned, as before. On the benchmark's real-noise corpus this removed
  408 of 855 history findings.
- **URLs and file paths no longer look like secrets.** The entropy pass already
  skipped bare URLs and absolute paths; it now also skips protocol-relative
  URLs (`//cdn.example.com/…`) and relative paths
  (`../node_modules/react-native/…`). A further 148 history findings. Genuine
  high-entropy values are unaffected, including base64 containing slashes.
- **Repeated values are reported once.** One credential copied into forty files
  is one thing to rotate, so the text report groups occurrences of the same
  value into a single entry listing every location. Counts, JSON and SARIF are
  unchanged — one result per occurrence, every fingerprint intact — so existing
  baselines and dashboards are unaffected.

On the real-noise corpus: history 855 → 299 findings (82 grouped entries);
working tree 239 → 150 findings (30 grouped entries).

### Detection

Four fixes, each found by benchmarking against gitleaks 8.30.1 and TruffleHog
3.97.1 on a labelled corpus of 60 planted credentials and 120 decoys. The
benchmark ships as `bench/` — `npm run bench` reproduces every number below.

- **Passwords containing punctuation are now detected.** The generic
  assignment rule's capture class allowed only `A-Za-z0-9_-/+=.`, so
  `password = "p4ss!w@rd#value"` was invisible to the one rule whose keyword
  list names passwords twice. Measured in isolation: 10 of 10 detected when the
  passwords were alphanumeric, 2 of 10 once punctuation was added.
- **`key := "value"` is now detected.** The separator pattern consumed a single
  character, so Go's short variable declaration left the `=` unmatched and the
  rule did not fire — measured at 0 of 10 against 10 of 10 for the `=` form. All
  103 rules were audited rather than the two the benchmark happened to plant;
  22 shared the defect and all 22 are fixed. The entropy pass had been covering
  it, so this only ever affected people who turned the entropy pass off, which
  is what the example config recommends for a noisy codebase.
- **The jwt.io demo token is recognised as a documentation sample.** The token
  every JWT tutorial pastes was reported as a credential. It is matched on its
  payload — the `John Doe` demo claims — so changing the algorithm in the header
  does not defeat it.
- **Hashed bundle filenames no longer look like secrets.** `main.<hash>.chunk.js`
  slipped past the filter written to catch exactly that shape, because the
  filter's stem could not contain a dot.
- **AWS's published documentation secret key is recognised as a sample.** The
  counterpart to `AKIAIOSFODNN7EXAMPLE`, which was already caught by the
  `EXAMPLE` pattern. This one carries no such marker, so it is matched
  literally. It had never been recognised -- the entropy pass's relative-path
  filter was dropping it by accident, because the value contains two slashes and no `+`
  or `=`, and narrowing that filter uncovered it. Both tiers drop it: the
  `aws-secret-key` rule reads the same shared list the entropy pass does, so
  the sample is not merely demoted from one tier to the other.

Measured on the benchmark corpus, working tree, before → after:

| tier | precision | recall |
|---|---|---|
| default (entropy on) | 0.768 → 1.000 | 0.860 → 1.000 |
| named rules only | 0.808 → 1.000 | 0.840 → 1.000 |

Every planted credential is now found, and no decoy is reported.

The same corpus measures the two entropy-pass changes further down this
release. On 185 KLOC of real code with no known secrets, the false-positive
count went 150 → 151 across the four fixes above -- one code expression in a
test fixture, from the widened password class -- and then 151 → 4 (0.022 per
KLOC) once findings in fixture paths were suppressed and the relative-path
filter was narrowed.

Narrowing that filter is what exposed the AWS sample: it had been eating
23.18% of random 40-character base64 keys, real ones included, and the
documentation sample along with them. The replacement predicate eats 0.823%.

The benchmark itself was measuring one of its own artifacts. `_history_plan.json`
— the generator's record of the ten history-only plants, values in plaintext —
was written inside the corpus root, so `git add -A` put it in the object store
before a later `git rm` took it out of the working tree. The history scan found
it there and the scorer counted it as false positives, capping corpus A history
precision at 0.857 by construction. Both scratch files now live beside the
corpus rather than inside it; all four arms measure 1.000 precision and 1.000
recall. Detection did not change — only what the corpus was asking the scanner
to explain.

No rule ID, keyword, entropy threshold or allowlist outside these five changed.

### Honesty about what was and was not looked at
- **Redaction hardened for short secrets.** Masking revealed the first and last
  four characters at every length above eight, which showed eight of a
  nine-character value — the length range where human-chosen passwords live.
  Values of 9–15 characters now show only a two-character prefix and never a
  suffix. Values of 8 or fewer are still fully masked; 16 and above are
  unchanged.
- **Scan scope is now disclosed in JSON and SARIF**, not only in the text
  report. JSON gains `summary.scope`, `summary.scannedCount` and
  `summary.scopeNoun`; SARIF gains a standard `invocations` entry carrying the
  same sentence. CI reads exactly these two formats, so this is where the
  guarantee that "nothing was scanned" never reads as "nothing was found"
  matters most. Existing keys are unchanged; the new ones are additive.
  Note for SARIF consumers: **every SARIF document now carries an `invocations`
  block**, including scans with nothing unusual to disclose. Anything that
  enumerates a run's top-level properties will see one more than before.
- **Inline suppressions are counted and disclosed.** A scan that dropped
  findings to `secretloop:allow` or `gitleaks:allow` now says so:
  `; 3 finding(s) suppressed by inline directives`. The directives themselves
  behave exactly as before in a scan. `secretloop mask` no longer honours them
  at all -- see *A directive cannot silence the scrubber* below.
  **Scoped to the CLI.** The editor's workspace-scan summary carries the
  generated-file and symlink counts but not this one or the fixture-suppression
  count, so a workspace scan in VS Code still under-discloses relative to
  `secretloop scan` on the same repository. Tracked for 0.1.2; the CLI is where
  CI reads, which is why it went first.
- **Staged scans fail loudly when git cannot answer.** `secretloop staged`
  treated a failed `git diff --cached` as an empty index, so a locked index
  during a pre-commit hook exited 0 on a scan that never ran. It now exits 2 and
  says why.

### Masking, and what a scan admits it did not read

Four fixes from an external review of this release. The first three are why
0.1.1 had not been published; the fourth is what let one of them stay invisible.

- **A directive cannot silence the scrubber.** `secretloop mask` and the
  editor's *Mask Secrets in Clipboard* scanned through the same path a repository
  scan uses, so an inline `# gitleaks:allow` beside a credential suppressed the
  match -- and a suppressed match never enters the finding list, so there was
  nothing to redact and nothing to count. The credential went to stdout under a
  summary reading `masked 0 finding(s)`; the editor left it on the clipboard and
  said *no secrets found in the clipboard*. The annotation is there precisely
  because the value beside it is real, which is what makes honouring it in a
  transform the wrong reading: it is a triage decision about a repository, and a
  stream someone piped through a scrubber is not that repository's findings.
  Scanning is unchanged and still honours every directive it always did.

- **A project config cannot disable masking.** Both mask paths built their
  configuration from the repository you happened to be standing in, so a
  `.secretloop.json` carrying `"allowValues": [".*"]` or an `excludeRules` list
  turned `kubectl logs prod | secretloop mask | pbcopy` into a passthrough,
  again reporting zero. Rule selection for masking now comes from the shipped
  defaults and nothing on disk widens it. A malformed config still cannot stop a
  mask, which was the only property the old fallback was defending.

- **A scan says how many files it could not read.** Files skipped for exceeding
  `maxFileSizeBytes`, for looking binary, or for being unreadable at the read
  were dropped without being counted, and the scanned count is the number of
  files that survived -- so a tree of 500 files where 480 sat over the size cap
  reported `Scanned 20 file(s). No secrets found.` Every other skip this scanner
  performs already named itself; this was the last silent one and, on a real
  repository, the largest. Two new clauses, in text, JSON and SARIF alike:
  `; 12 file(s) not scanned — larger than maxFileSizeBytes (raise it in
  .secretloop.json to cover them)` and `; 3 file(s) not scanned — binary or
  unreadable`. Kept apart because only one of them names a fix. A file supplied
  from an unsaved editor buffer is scanned, not counted as a skip.

- **`mask` reports a malformed invocation.** `main()` dispatched the mask
  command before the argument check, and that check is the only reader of what
  the parser collected -- so every parse error was discarded for the one command
  whose failure mode is an unmasked secret. `secretloop mask --entropoy` masked
  with the generic tier off and exited 0. Argument errors are now reported
  before any command runs, and mask exits 2 having written nothing.

### Corrections
- **A non-zero exit says what it means.** `--fail-on` prints to stderr when it
  fails a build: `exit 1: findings at or above the fail-on threshold (this is
  the CI gate, not an error)`. Report output on stdout is byte-identical.
- **A corrupt baseline now names the file** — `Could not parse
  .secretloop-baseline.json: …` instead of a bare parser error.
- **`--verify` and `--write-baseline` together are now refused.** The
  combination sent every detected credential to its provider and then wrote the
  baseline and exited before reporting, so every verdict was discarded. Nothing
  leaked and the outbound record counted each call honestly — it was network
  traffic carrying live credentials in service of nothing. It now exits 2 and
  says to write the baseline first, then verify against it.
- **A revision range can no longer be read by git as an option.** `--rev-range`
  is checked against the characters rev-ranges are made of before it reaches
  `git log`'s arguments, where a value like `--output=<path>` would have made
  git write a file. The CLI's argument parser already refused flag-shaped
  values, so no released version was exploitable through it; the check now sits
  at the point where the argument is used, which covers every caller rather
  than the one that goes through the parser.
- **A credential is verified once even when several checks start at once.** The
  result cache could only help after a result existed, so concurrent checks of
  the same credential each contacted the provider. A second check now waits for
  the first. Counts of what was sent are unchanged in meaning — they have
  always recorded what actually left the machine, and now less does.
- **`.secretloop.example.json` claimed a fallback that never shipped.** It said
  a `.secretguard.json` from before the rebrand would still be read if no
  `.secretloop.json` existed. No release ever did this: `resolveConfigFile`
  has only ever looked for `.secretloop.json`. The comment is corrected, and no
  fallback was added. If you are carrying a `.secretguard.json`, rename it.
