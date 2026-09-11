# Coverage

What a scan reads, what it deliberately does not, and how it says so. Applies to
**published 0.5.0**.

## What is scanned

- **Working tree.** Files enumerated with `git ls-files --cached --others
  --exclude-standard` when git is available, so `.gitignore` is honoured;
  otherwise a directory walk that skips `.git` and `node_modules`. Every path
  is checked to resolve inside the scan root, at enumeration and again at read:
  a committed symlink pointing outside the repository is dropped and counted,
  never followed.
- **Staged changes** (`staged`): the index, through the same guards.
- **Git history** (`history`): one streaming `git log -p` pass over added lines,
  cancellable, bounded by `--max-commits` or `--rev-range`. A secret deleted in
  a later commit is still in the object store.
- **Text only.** A file with a NUL byte in its first 8,000 bytes is binary and
  skipped as unreadable; a file over `maxFileSizeBytes` (1 MB by default) is
  skipped as oversized. Both are counted in the scope sentence.

## Detection tiers

- **Named rules** — 110, each a
  keyword-prescreened pattern for one credential format, with rule-scoped
  allowlists, optional entropy floors, and the shared placeholder and
  documentation-sample filters. A named finding is a **format match** and
  reports everywhere, including test and fixture paths.
- **PKCS#12 keystores** — a file-level, content-driven detector for `.pfx`/`.p12`
  containers holding private-key material, extension-independent, one finding
  per qualifying container with a non-secret descriptor as its value. Not a
  rule, and not counted as one.
- **Generic high-entropy tier** — off by default since 0.4.0. Reports
  random-looking strings that match no format, after structural filters, at
  `entropyThreshold` (4.3; 4.5 for single-charset strings). Held back and
  counted in fixture paths unless `includeFixtures` is set. It cannot report an
  all-hex or all-digit value at any length, because two-charset strings need
  4.5 bits and hex tops out at 4.0; named rules cover the known hex providers.
  To inspect what it finds in fixture paths, see
  [Inspecting fixtures and test data](cli.md#inspecting-fixtures-and-test-data).
- **`encryption-key-assignment`** — a quoted 32-byte symmetric key in
  canonical base64 assigned to an `aes…key`, `secretbox…key` or `encryption…key`
  identifier. High severity, format match, no verifier, entropy floor 3.5.
  Provider-neutral by design. Rule 110.

## Encoded spans

Standard base64, hexadecimal and URL percent-encoded runs in a text are decoded
**once**, strictly, and the named rules run over the decoded text. A run longer
than 4,096 characters, one that decodes to fewer than 12 or more than 4,096
bytes, one that is not valid UTF-8, or one containing NUL is not a candidate.
Decoded output is never decoded again (one layer, structurally), and the decoded
text is never retained: the finding's value is the encoded source span, masked
like any other. Such findings carry a distinct fingerprint, are never
transmitted for verification, and record which transform produced them. The
entropy tier is not run over decoded text.

## Archives

ZIP, tar, gzip and gzip-wrapped tar containers are opened **in memory, one
layer deep**, and each member is scanned exactly as a file of the same bytes
would be: named rules, PKCS#12, inline directives, fixture-path suppression,
encoded decoding and the configured entropy mode all apply through the
member's display path `container!/member`. Nothing is extracted to disk and a
member name is never resolved against any filesystem.

Frozen limits: 10,000 entries per container; member names up to 1,024
characters; a member larger than `maxFileSizeBytes` is refused before any
decompression; total decompressed output is capped at 100 times the outer
file's size. Encrypted entries, ZIP64 containers, unsupported compression
methods, names with `..`, absolute names, drive letters, control characters,
duplicate names, symlinks, hard links and device entries are refused and
counted by reason. An archive inside a member stays opaque. A gzip stream's
FNAME header is never used as a name.

A container that carries archive magic but will not open — corrupt, or ZIP64 —
is disclosed as a *recognized archive container not opened* and then takes the
ordinary text path, so a named-rule value inside it is still reported at the
file path, without archive provenance.

## API description documents

With the entropy tier on, an OpenAPI, Swagger or AsyncAPI document — identified
by a `.json`, `.yaml` or `.yml` extension on its own path plus a top-level
marker — is scanned by every named rule but not by the entropy heuristic, and
the scan counts how many documents that affected. Measured reason: 101 of the
279 entropy false positives in the frozen benchmark were `operationId` and
`description` strings inside OpenAPI documents, and no validated true positive
sat in one. Restore with `--include-api-document-entropy` or
`includeApiDocumentEntropy`. History and `mask` keep the pre-scope behaviour.

## What the scan discloses

A scan must never read like a clean result when it could not look. The scope
sentence and the JSON `summary` carry:

| clause | meaning |
|---|---|
| `N file(s)` | files actually read |
| `N generated file(s) excluded` | skipped by the generated-file group; `--include-generated` reads them |
| `N finding(s) suppressed by inline directives` | spans a directive removed |
| `N file(s) resolved outside the scan root` | symlinks whose target is outside |
| `N generic finding(s) suppressed in test/fixture paths` | entropy-tier findings held back |
| `N API description document(s) scanned without generic entropy` | documents the entropy tier skipped |
| `N file(s) not scanned — larger than maxFileSizeBytes` | oversized files |
| `N file(s) not scanned — binary or unreadable` | binary, unreadable, or a container that also failed the text path |
| `N archive(s) opened — M member(s) scanned` | containers opened, members offered to the scanner |
| `N archive member(s) not scanned` | members refused; reasons in `summary.archives.members.refused` |
| `N archive member(s) excluded by configuration` | members matching `excludePaths` |
| `N archive metadata entry(s) skipped` | tar pax and GNU long-name records, which are not members |
| `N archive(s) not fully enumerated — D declared entry(s) not inspected, U with unknown remainder` | a walk that stopped at a cap, budget, truncation or bad header; ZIP declares its count, tar cannot |
| `N recognized archive container(s) not opened` | containers with archive magic the parser declined |

The structured object behind the archive clauses (`summary.archives` in JSON,
`invocations[0].properties.archives` in SARIF, `scope.archives` over MCP)
carries the same counts with the bounded reason codes. Counts only: no path,
member name or value.

## What is deliberately not scanned

- `node_modules`, `package-lock.json` and minified bundles: never, by any flag.
- The generated-file group (lockfiles, Gradle/Maven wrappers, Xcode project
  files, `*.sarif` reports) unless `--include-generated`.
- `go.sum` and `go.work.sum` (module checksums).
- Archives nested inside archive members; encoded content inside decoded
  content; encrypted archive entries.
- Some PKCS#12 shapes remain opaque by design: outer `signedData`, inner
  `envelopedData`, nested `safeContents`.
- Bare (unquoted) values for `encryption-key-assignment`, including the
  Kubernetes `EncryptionConfiguration` `secret:` field, which the entropy tier
  covers when enabled.

These are scope statements, not statements that those locations are empty.
