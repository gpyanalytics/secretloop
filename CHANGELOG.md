# Changelog

## Unreleased

### Validation

- **The Windows suite now runs natively on ARM64, on a Windows 11 client
  edition.** Three CI jobs on the standard `windows-11-arm` runner: the full
  suite on Node 20 and 22, the two-account consent fixture, and the packaging
  smokes. Measured rather than assumed — Windows 11 Enterprise 10.0.26200,
  `ProductType 1` (workstation, not Server), ARM 64-bit, Node reporting
  `process.arch=arm64` with no emulation indicator — and the job **fails** if
  any of that is untrue, because an emulated x64 result presented as native
  ARM64 evidence would be worse than none. **Node 18 is not in that matrix and
  cannot be**: nodejs.org publishes no `win-arm64` build for any v18 release.
  `engines.node` is unchanged at `">=18.0.0"`; it states the lowest version the
  code supports, not a promise of a binary for every platform and architecture.
  No product behaviour changed.
- **What that does not establish.** One hosted image is not universal client
  support. The ordinary suite jobs run **elevated**, so only the two-account
  jobs are evidence about ordinary-account behaviour, and the existing x64
  two-account results stay x64 results. Local accounts say nothing about domain
  accounts. Non-English hosts, managed or relocated profiles, and non-NTFS
  volumes are still unexercised.

### Consent

- **SecretLoop refuses to trust consent records when the consent directory
  fails its private-store checks (macOS, Linux).** Before every consent
  operation — reading a record at either `secretloop_verify` call, listing
  for `secretloop approve`, approving, claiming, deleting and writing — the
  store's two directories (`~/.secretloop` and its `pending`) must be real
  directories, not symbolic links, owned by your account, with mode `0700`. A
  directory you own that is too open is set to `0700` and re-checked; one
  owned by another account is refused and never changed; a link is refused and
  never followed. On refusal the MCP tool answers an error and `secretloop
  approve` exits 2, both in fixed words that carry no path, record, hash or
  OS message; nothing is transmitted, approved, written or claimed. Before
  this change a failed `chmod` was swallowed and the store was used anyway —
  measured (`consent-file-security-assessment`): in a root-owned
  world-writable store another ordinary user could list record ids, plant
  files beside them and rename records away.
- **What this does not do, stated plainly.** It inspects the store's own two
  directories, not the home directory above them or a component swapped
  between the check and the next operation (a window open to any account that
  can write the home directory — normally only you and root); it does not see
  POSIX ACL entries, so "private" here means mode bits and ownership, not
  every effective grant;
  it changes nothing it does not own and never touches your home directory's
  permissions; and it closes no window against a process already running as
  you, which is the documented trust boundary. First use still creates the
  store. A `.secretloop` that was already private is unaffected.
- Compatibility: an existing store that is already a private directory needs
  nothing. A store that is a link, is owned by another account, or cannot be
  made private is refused with guidance to inspect it and move it aside, not
  to delete it, loosen it, or run anything elevated.
- **The record file itself is now checked on macOS and Linux, not just the directories around
  it.** Until now a consent record was opened by name and read. So a symbolic link at a record
  path was followed to wherever it pointed, a record owned by another account was read, one left
  readable by others was read, and a named pipe at a record path made the reader wait for a writer
  that never came — measured: it never returned and had to be killed. Each of those is now
  refused. The record is opened once, with the final component not followed and without blocking,
  and what it is — a regular file, owned by you, with no group or other permission bits, and no
  larger than any record SecretLoop writes — is decided from that same open file before a byte of
  it is read. An unsafe record is refused, never repaired: its owner and mode are left exactly as
  found. A record that simply is not there is still "no record", and a store whose `pending`
  directory is gone still behaves as it did.
- **And the writer now measures what it is about to write, so it cannot mint a record the reader
  refuses.** "No larger than any record SecretLoop writes" was an assumption about field lengths,
  and it was wrong. Only three fields carry text of any length — the workspace path, the
  repo-relative file and the fingerprint that embeds it — and although the filesystem bounds
  those, JSON escaping is not one byte per byte. A control character costs six, and a POSIX file
  name may hold any byte but "/" and NUL. Measured: those three fields at PATH_MAX serialize to
  12,779 bytes in ASCII and 74,204 in control characters. The writer really did create a
  74,101-byte record that every later read refused, and one such record refused the whole listing
  rather than just itself. `writeRecord` now measures the serialized bytes against the reader's
  own bound and refuses beforehand, so nothing is created; a pending record is held a further 96
  bytes back, because approval adds 88 and a request that can be made must be one that can be
  granted. The refusal says the path is too long and says the store is fine, rather than sending
  you to inspect a healthy store.
- **macOS: an extended access-control list on the store or a record now refuses.** The mode
  check that settles this on Linux settles nothing on macOS. Measured, in both directions: on
  Linux the POSIX ACL mask and the group bits of the mode move together, so `0700` really does
  mean no other account has effective access through a named entry — six different ways of
  writing such an entry were tried on two filesystems and none granted access while the group and
  other bits were zero. macOS ACLs are NFSv4-style and have no mask, and nothing about them
  reaches `st_mode`. Measured with SecretLoop's own writer: under a parent directory carrying
  inheritance entries, it created a store, a pending directory and a record at modes 0700, 0700
  and 0600 — and every one of them carried `everyone inherited allow`, the record granting read
  and write to everyone. Node reported only the modes. On macOS SecretLoop now inspects the store,
  the pending directory and each record with the built-in `/bin/ls`, and refuses any that carries
  an extended entry. **Nothing is repaired**: an entry removed now says nothing about who read the
  store before, cannot establish who owns it, and cannot revoke a descriptor another process
  already holds.
- **The macOS refusal is a support restriction, not a verdict on your ACL.** SecretLoop refuses
  every extended entry because it does not evaluate them, so it also refuses entries that grant
  nobody anything — a `deny`-only entry, an entry naming only you, an inherit-only entry, and
  entries placed by backup software or by an employer's device management. Those stores are
  refused although they may be perfectly private. `docs/mcp.md` lists them and says what to do.
- **The inspection happens before anything is written, not after.** A store created under a parent
  with inheritance entries is checked while it still holds nothing but empty directories, and a
  refusal removes only what that call created. A check that ran after the record was written could
  refuse the record but could not unwrite it.
- **The path above the store is now checked too, on macOS and Linux.** Every earlier check looked
  at the store, its `pending` directory and the records inside; none looked at the directories
  ABOVE them. Measured: an account that can write the store's parent renamed the whole store away
  and created its own in its place. Against that substituted store SecretLoop refused on ownership
  and transmitted nothing, so in the cases measured the effect was denial of service rather than
  disclosure — but on macOS the same position is worse, because an inheritance entry on the
  parent is inherited by a store and a record your own process creates. SecretLoop now requires
  every directory from the store up to the filesystem root to be a real directory owned by you or
  by root and not writable by anyone else, and on macOS to carry no extended entry. The check runs
  before the store is created, not after.
- **Configurations this now refuses, which used to work.** A **group-writable home directory** is
  refused, even when the group contains only you: there is no portable way to ask who else is in a
  group, so every group-write bit is treated as a grant. A home under a directory owned by another
  ordinary account is refused. A world-writable directory on the path is refused unless it also has
  the sticky bit and is owned by you or root — `/tmp` keeps working, a world-writable directory
  without sticky does not. A path whose inspection would exceed 64
  directories is refused rather than walked — 64 INSPECTED directories, which is 64 levels when
  nothing on the path is a symbolic link and about 32 when something is, because both the
  literal and the resolved path are then inspected.
- **Why sticky is allowed at all, and how far it goes.** Measured as a second ordinary account in a
  sticky, root-owned, world-writable directory: deleting and renaming your store are **denied**,
  which is what earns the exception. But **creating a name that does not exist yet is allowed**, so
  your store can be pre-planted before you ever run SecretLoop. What answers that is a different
  check: a pre-planted store belongs to whoever made it, and SecretLoop refuses a store it does not
  own. The residual is a denial of service the path rule does not close, and if the sticky
  directory is owned by the attacker rather than root it gives no protection at all — which is
  why it is accepted only under a trusted owner.
- **One consent request now has one work allowance.** Each individual check was bounded and the
  total was not. Measured on macOS, one `ls` per inspected object: writing a record made 43 calls
  about 10 distinct objects, because the path is re-walked by each stage; approving made 60; and
  listing grew with the number of pending requests with no ceiling at all. A per-process timeout
  does not bound that — 512 of them, each taking its own timeout, is not a bounded request. A
  request now gets at most 512 inspections, 4 MiB of their combined output, 256 entries read from
  `pending`, and 20 seconds overall, with nested work sharing the one allowance. Reading the
  `pending` directory stops at the limit rather than loading it and trimming afterwards, so the
  enumeration really is bounded. On exhaustion SecretLoop refuses: it never returns a shortened
  list as though it were complete, and never approves a record it did not finish checking.
  Nothing is cached to make this fit.
- **The time limit is not a wall-clock guarantee, and is not described as one.** It is checked
  between pieces of work, and a child process is given only the time remaining rather than a fresh
  allowance. A single filesystem call on an unresponsive mount cannot be interrupted from inside
  the process.
- **macOS refuses an ancestor carrying an `allow` access-control entry, including an owner-only
  one.** That is a support restriction, not a finding: refusing it is not evidence that the entry
  grants anyone else access. A `deny`-only entry is not refused merely for existing. The store and
  its records keep the stricter rule of refusing any entry at all.
- **Correction to the inspection limit as previously described.** It counts inspected directories,
  deduplicated across the literal and resolved paths, not levels of nesting; and macOS has a
  second, lower limit of 40 because each directory there costs a subprocess. The two are ordered,
  so on macOS the effective ceiling is 40.
- **What the path check does not establish.** A sequence of inspections at different instants is
  not a snapshot of the filesystem: a directory re-permissioned after it was looked at is not seen,
  the check is not atomic with the store checks that follow it or with any later open, and it
  revokes nothing that another process already has open. It describes the path now, and says
  nothing about who could reach the store in the past.
- **What the macOS check does not establish.** It runs on a path, not on a descriptor: `/bin/ls`
  has no file-descriptor form, so the inspection and the later open are two lookups of the same
  name and the lifecycle is no more atomic than before. If the tool is missing, times out, or
  returns anything that does not fully validate, SecretLoop refuses rather than assuming there is
  no entry. A record whose name could split the tool's output is refused rather than inspected.
  And on a filesystem that cannot report access-control lists at all, "no entries" would mean the
  filesystem declined to answer — that case is **not yet tested**.
- **What the record check does not establish.** Judging and reading through one descriptor is not
  the same as making the lifecycle atomic: a record can still be replaced between one operation
  and the next, and the claim that guards a verification is still the atomic rename, not this
  check. Not following the final component says nothing about the directories above it. And mode
  bits are not a statement about extended access-control lists, which remain unread on both
  platforms. On macOS an extended entry is invisible to them entirely, and whether they say
  anything on Linux — where the group bits correspond to an access-control mask — is a separate
  question still to be measured, not something this change settles either way.
- **Windows now has its own check, and it is not the POSIX one.** Ownership
  and mode fields are meaningless there, so what protects a record is its
  security descriptor. Before every consent operation SecretLoop reads the
  owner and access list of `.secretloop`, of its `pending` directory and of
  **each record it is about to use**, and requires every entry to be an allow
  entry naming only your account, SYSTEM or Administrators, the owner to be
  one of those three, and your account to hold full access through an entry
  that is not inherit-only. A reparse point at any of them is refused and
  never followed. It also walks **every directory from the volume root down to
  the store's parent** and refuses if any account outside a small platform set
  can delete, replace or re-permission one of them — because a private
  `.secretloop` inside a folder someone else can rename can be swapped
  wholesale without its own permissions ever changing.
- **Why records are checked one by one.** A record planted by another account
  and later caught by a protected parent has its *inherited* access list
  rewritten to look private while its owner stays the account that planted it,
  and an owner can re-grant itself. Measured before this was written; a check
  that reads only the access list accepts it. The owner check is what refuses
  it.
- **New stores are created private, and a failed creation leaves nothing.**
  The parent chain is verified *before* anything is created; then the store is
  made, given an owner-only access list, and re-inspected, with `pending`
  inheriting it. If any step fails, only the directories that call created are
  removed, with a non-recursive delete, so nothing pre-existing is touched and
  a directory something else has meanwhile written to is left in place rather
  than emptied. An existing store is verified and refused, never repaired.
- **What this does not do on Windows.** Applying an access list does not
  revoke a handle another process already holds; access is checked when a
  handle is opened. Verifying the parent chain prevents that situation for a
  store SecretLoop creates — the directory is new, under a parent no other
  ordinary account can write — but it revokes nothing, and for a store that
  already existed it cannot. These checks describe the present: they do not
  establish that a store was always private, nor that no handle was opened
  while it was not. Inspection is by path and the work that follows is by
  path, so a replacement in between is not detected; the bounded claim is that
  no *other ordinary account* can perform it. Nothing here defends against an
  administrator, against SYSTEM, against a compromised Windows service, or
  against code already running as you.
- **Windows compatibility.** A store under a default profile is unaffected: a
  stock chain and an inherited-private store both pass. A store under a folder
  that grants other accounts is now refused **and will not be created** — move
  it under your profile, or remove those grants yourself. A store or record
  owned by another account is refused rather than repaired. SecretLoop uses
  the built-in `powershell.exe` and `icacls.exe` from the system directory; if
  either cannot be run, consent is unavailable rather than assumed safe. A
  store on a network or UNC path is refused: these checks have not been
  established for that kind of location. No new dependency is added.

### Containment

- **The scanner now checks the file it actually opened before reading it, and
  says what it checked.** Both readers — the text reader and the binary
  detectors' candidate reader, header probe included — inspect a file, capture
  its device and inode, open it, and then compare the opened descriptor against
  that identity before the first byte is read. On Linux they also read the
  kernel's own record of the opened descriptor's path (`/proc/self/fd`) and
  require it to lie under the scan root by path component. What this buys, in
  plain terms: certain file substitutions between the inspection and the read
  are **detected before anything is read**, an observed violation **refuses
  the file**, and every scan **reports when a check could not run**.
- **What is refused, and how it is reported.** A descriptor whose identity
  differs from the inspected object is refused as **`replaced`** — a new skip
  reason, disclosed as `N file(s) not scanned — replaced between inspection and
  read`, counted as a coverage limitation, and making the report `incomplete`.
  A descriptor whose kernel-recorded path is outside the root is refused with
  the existing **`outside`** reason. A refusal on the binary probe's descriptor
  refuses the whole file; the text reader is not tried again on that name.
  Nothing is read from a refused descriptor. An ordinary per-file refusal never
  stops the scan.
- **New disclosure: `openedFileChecks`.** Every working-tree and staged scan
  now accounts for each descriptor its readers opened for content — three per
  ordinary file, one per reader — and what the two checks did on each:
  `verified`, `refused`, `unavailable`, `failed` or `notReached`, for
  `identity` and for `kernelPath`. It appears as `summary.coverage.openedFileChecks`
  in JSON, in the SARIF invocation properties, in the MCP `scope` object and as
  the **last clause of every scope sentence**, for example
  `; 12 descriptor(s) opened for content: identity 12 verified; kernel path 12 unavailable`.
  The clause is printed on every scan, all-verified included, so a sentence
  without it cannot be mistaken for one where every check ran. A history scan
  never runs these readers and omits the block. `unavailable` is disclosed but
  is **not** a coverage limitation.
- **The guarantee, stated exactly, and its limits.** On Linux with a readable
  `/proc/self/fd`, for every descriptor the block records as `kernelPath:
  verified`: no bytes are read from an object whose kernel-recorded location,
  *at the check that immediately precedes its first read*, lies outside the
  root. Every platform, for every descriptor recorded `identity: verified`: no
  bytes are read from an object other than the one inspected one syscall
  before the open. A descriptor recorded `unavailable` for a check **is read
  without that check**, and the block says so; neither claim extends to it. It does **not** establish containment at the moment of the open,
  throughout the read, or against every filesystem race — measured, not
  supposed: an outside object moved under the root after the open and before
  the check is accepted with its outside-origin bytes read; an inside object
  moved out after the check is still read; the identity check alone cannot see
  a parent replaced between path resolution and the identity capture (on
  darwin and Windows there is no kernel path, so that case is read there and
  the block says `kernel path N unavailable`); and content can change in place.
  Windows and macOS therefore get **risk reduction**, not a Linux-equivalent
  check. **F-1 Concern A remains open.** No native dependency, `openat2`
  binding or broader filesystem policy was added.
- **`schemaVersion` is now `5`.** The refusals above **widen what `incomplete`
  counts**: a version-4 producer read a substituted object and said
  `incomplete: false`; a version-5 producer says `true` for the same event. That
  is the documented bump trigger, so the version moves. Consequences, measured
  with real reports: a published 0.6.0 (schema-4) report is byte-for-byte what
  it was; the comparator in this build refuses a schema-4 report **on either
  side** with `unsupported-schema` (exit 3, no difference computed) — a 4/5
  pair additionally reports `mixed-schema`, and a 4/4 pair is refused too;
  two schema-5 reports of a stable tree compare exactly as before; a file
  refused by the checks still makes its report `incomplete` and the pair
  ineligible. `BINARY_CONTRACT_VERSION` (2) and `SCOPE_CONTRACT_VERSION` (1)
  are unchanged: neither representation moved. The `openedFileChecks` block
  itself is descriptive and lives under `summary.coverage`, never beside the
  identities. On a stable tree, builds from either side produce byte-identical
  findings, fingerprints and every comparison identity except `schemaVersion`;
  the other differences are the new clause and the new block. Reading a scope
  sentence that used to end at a known clause now
  finds the accounting clause after it.

### Coverage

- **The file-size cap now bounds the READ, not an earlier look at the name.**
  `readTextFileResult` and `readBinaryCandidate` inspected a path with `stat` and
  then read it with `readFileSync`, which takes no maximum-bytes option — so the
  cap described the file `stat` happened to see, not the bytes actually read. A
  file that grew between the two calls was read in full at whatever size it had
  reached. Reproduced deterministically: a 64-byte cap, a 10-byte file at
  inspection, **4096 bytes read**.
  Both readers now open the file **once**, inspect that descriptor with `fstat`,
  and read every byte from it with the cap enforced **during** the read. At most
  one bounded chunk is ever read past the limit, which is what lets "exactly the
  limit" and "one byte over" be told apart; the buffer is discarded before
  anything classifies or scans it. The descriptor is closed in a `finally` on
  success, refusal and throw alike.
- **This deliberately changes one behaviour.** A file that grows beyond the
  configured cap between inspection and read is now **refused as `oversized`**
  where it was previously read in full. That is the point of the change. Stable,
  supported inputs are unaffected: on a fixed corpus, builds from either side
  produce byte-identical findings, fingerprints and report metadata.
- **What one descriptor does not buy, stated plainly.** It fixes *which object*
  is read. It does **not** prove that object is inside the scan root: `openSync`
  resolves the name and follows symlinks, so a final-component or
  parent-directory replacement between the containment check and the open is
  still followed. That is **F-1 Concern A, which remains OPEN and is not
  addressed here**. Nor is a descriptor a snapshot — a concurrent writer can
  still change the bytes it yields. The existing `isInsideRoot` check and the
  binary reader's non-dereferencing `lstat` gate are both unchanged.
- **Non-regular inputs are classified before the file is opened.** `openSync` on
  a FIFO with no writer blocks indefinitely, and `readTextFileResult` is reached
  with caller-supplied paths — the staged set — that never went through the walk.
  The type check therefore runs before the open, and is a **type** check only:
  the size guard is the read loop, because using a `stat`'s size to bound a later
  read is the defect this change removes. A regular file swapped for a FIFO
  between that check and the open would still block; that is the same class as
  Concern A and is not addressed here.
- **A `maxFileSizeBytes` that is not a usable number is now refused.**
  Configuration applies no validation to this setting, so a project file saying
  `"maxFileSizeBytes": "abc"` reaches the reader as a string. The previous reader
  ignored such a value and read every file **whole, uncapped**; the file is now
  skipped as `unreadable` instead. Every value that is actually a number behaves
  exactly as before, `Infinity` included — measured across the default, the exact
  size, one under, zero, a negative, and fractional caps.
- This change on its own altered no report or digest contract:
  `BINARY_CONTRACT_VERSION` stays 2, `SCOPE_CONTRACT_VERSION` 1, and it
  introduced no new skip reason — an over-cap file is still `oversized`, still
  counted, and still makes the report incomplete. (`REPORT_SCHEMA_VERSION`
  was still 4 here; the containment entry above moves it to 5 in this same
  release.)
- **A file replaced by a named pipe during scanning no longer causes the
  validated reader path to wait indefinitely for a writer.** Both readers
  classify a path before opening it, so a FIFO that is already there was always
  refused promptly. A regular file replaced by a FIFO *between* that check and
  the open reached a blocking open and the scanner hung until its process was
  killed — measured, not assumed. Every content open in the scanner's readers
  (the text reader, the binary reader's bulk read and its header probe) now
  uses `O_NONBLOCK` where
  the platform defines it, and the opened descriptor is classified with `fstat`
  before any byte is read; a non-file is refused as the existing `not-a-file`
  reason, counted in coverage as before. Regular files, in-root symlinks, the
  byte cap, exact-limit acceptance and overflow refusal are unchanged.
  **Validated on darwin and Linux** (the swap is refused in milliseconds where
  it blocked before). **Windows:** `fs.constants.O_NONBLOCK` is undefined
  there, so the open falls back to a plain read-only open and behaves exactly
  as before; no FIFO can exist on an NTFS path, and no Windows FIFO protection
  is claimed. The comparator's reader of saved report files is a separate
  path over user-supplied inputs and is unchanged. **This does not close F-1
  Concern A:** the open still resolves
  the name and follows symlinks; containment between the check and the open
  remains open and is not changed here.
- **`secretloop compare` no longer waits indefinitely when a report path is a
  named pipe.** The comparator opens each report file and classifies the
  opened descriptor before reading; it has no pre-open check, so the case is
  a path that is already a FIFO when the open runs — measured through the
  built CLI in both argument positions, the command hung until its process was
  killed. The report-file open now uses `O_NONBLOCK` where the platform
  defines it, and the existing "not a regular file" refusal (exit 2, no path
  or content echoed) is reached at once. The report-size cap, the bounded
  single-descriptor read, strict JSON and metadata validation, comparison
  eligibility and exit codes are unchanged. **Validated on darwin and
  Linux.** **Windows:** the constant is undefined there, the open is a plain
  read-only open and behaviour is what it was; no FIFO can exist on an NTFS
  path and no Windows FIFO protection is claimed. Not a general claim about
  non-blocking filesystem operations or denial-of-service immunity.

### Testing

- **The suite and both packaging smokes now run natively on Windows in CI.**
  `test-windows (18)`, `test-windows (20)` and `packaging-windows` run on
  `windows-latest` beside the Linux jobs; they are not required checks and
  take nothing away from the four that are. Until now every Windows statement
  in this repository was an inference from cross-platform Node APIs. Result:
  1,560 passed, 0 failed, 18 skipped per Node major, identical on 18.20.8 and
  20.20.2 — the same 1,578 cases POSIX runs in full. **No product source
  changed** to reach that. Not a claim of Windows support: one hosted
  runner, running elevated, is one measurement.
- **A skipped test is no longer counted as a pass.** `tests/harness.ts` gained
  `skip(reason)`; a platform-gated case prints `skip -` with its reason and a
  separate count in the summary instead of returning early as `ok`. Eighteen
  cases skip on Windows, each stating why — FIFOs, POSIX mode bits, replacing
  a name under an open descriptor (Windows answers `EPERM` at re-creation),
  filenames NTFS refuses, and a `pgrep` count. A file with no skips keeps the
  two-number summary.
- **Four harness faults corrected, found only by running on Windows:** a
  hard-coded `/tmp` in the revRange guard test; `npx` and
  `node_modules/.bin/esbuild` spawned as `.cmd` shims a shell-less spawn
  cannot start; and `smoke-vsix.sh` comparing a CRLF-converted manifest line
  by line, so two identical file lists read as a mismatch. The bundle test now
  uses esbuild's in-process API with the same options.
- **Two cases added that only a Windows run makes decisive:** the walker's
  separator conversion measured into `binaryIdentity` through the real CLI on
  both the git and the fallback enumeration, and the temporary directory
  removed after every reader outcome, which is what a leaked descriptor looks
  like under Windows delete semantics.

## 0.6.0 — 2026-09-15

### What you can do in 0.6.0

SecretLoop 0.6.0 helps you compare scan results, check a redaction and understand
what a scan left out. Detection rules are unchanged.

**Compare a scan before and after your changes.** Save two JSON reports to see
new findings, findings present in both, and findings no longer observed.
SecretLoop explains when the reports cannot be compared instead of presenting
an unreliable difference.

```bash
secretloop scan --format json --output before.json
# Make your changes, then save another scan.
secretloop scan --format json --output after.json
secretloop compare before.json after.json
```

Comparison supports working-tree reports with compatible settings and complete
coverage. Reports with active inline suppression, an applied baseline or a
non-empty allowlist cannot qualify. Staged and history reports are not
supported. **No longer observed does not mean fixed, revoked or safe.**

**Know whether another copy remains after redaction.** In VS Code, the redaction
quick-fixes now check the edited document for the same value. You get a message
saying it is no longer present, a warning with the number of remaining copies,
or a message that the check was unavailable. This checks only the editor
buffer, not other files, saved disk contents, Git history or the provider.
Encoded findings and moving a value to `.env` are not covered by this check.

**Record why a finding was ignored.** Add optional reasons to inline directives,
baseline entries and supported configuration exclusions. You can also limit an
inline directive to a specific rule. Summaries count inline-suppressed findings
with a recorded reason; reason text stays out of reports, logs and MCP responses.

**Understand skipped files and comparison limits.** Scan summaries distinguish
binary skips from read failures. Comparisons account for changes to the set of
binary-excluded paths, so a file becoming unscanned does not silently make its
finding appear gone. Excluded files may still contain secrets.

**Give your AI assistant better scan context.** MCP clients listing cached
findings now receive the scope of the scan that produced them. Completed MCP
history scans also disclose suppression counts. Cached results are not a new
scan, and stopped history scans keep their existing partial-result message.

**Locate matches more precisely in code-scanning reports.** SARIF reports include
column locations where available and the scanner version, helping reviewers
find the matched text.

### Technical details and compatibility

Published to all three channels over about seventeen minutes: npm at 23:31 UTC,
the VS Code Marketplace at 23:44, Open VSX at 23:48. The three timestamps fall on
one UTC date, so the heading carries one date, as every heading here does.

`v0.6.0` tags `96070bf6`, which is the released **source**. The published
artifacts were built earlier, from `5686944`, and were not rebuilt for the tag —
so the tagged tree and the build tree are not the same tree; they differ by
documentation. What makes the tag honest is that every **packaging input** is
byte-identical between them: `package.json`, `package-lock.json`, `.npmignore`,
`.vscodeignore`, `scripts/vsix-manifest.txt`, the bundle source under `src/`, and
the packaged `LICENSE`, `README.md`, `SECURITY.md` and `docs/icon.png`. Nothing
that enters a package changed. This is equivalence of inputs, not a reproducible
build: no rebuild was measured, and `npm pack` and `vsce` embed timestamps.

Additive throughout.

**No rule, threshold, severity or fingerprint changed**, so the same tree reports
the same findings it did under 0.5.1. `REPORT_SCHEMA_VERSION` is 4,
`BINARY_CONTRACT_VERSION` is 2 and `SCOPE_CONTRACT_VERSION` is 1; schemas 1-3 and
binary contract 1 existed only during development and were never published.

### MCP

- **`secretloop_list_findings` now says what was inspected to produce its rows.**
  The scan computed a `scope` and the session cache dropped it, so listing the
  findings afterwards returned them with no account of their origin — the `scope`
  key was **absent**, not null. The cache now stores the scope in the same object
  literal as the findings it describes, and `list_findings` returns it.
- **Additive, and response-level by design.** No existing field changed type or
  meaning and nothing was removed; one key was added to one payload. The cache
  has exactly one writer, so each entry describes exactly one working-tree scan
  of one root — a per-finding provenance field would repeat that on every row and
  could drift from it, so none was added.
- **What it does not claim.** Not freshness: `source` and `scannedAt` already say
  the findings are an earlier observation. Not the comparator's `scopeDigest`:
  nothing is hashed and no eligibility decision reads it. Filters do not move it,
  because a filter narrows returned rows and not what was scanned. A history scan
  writes nothing to the session cache, so it can neither restamp nor contribute
  to what `list_findings` returns, and the refusal when no scan has run is
  unchanged — a completed zero-finding scan still answers with its scope.


- **A history scan over MCP now says what it suppressed.**
  `secretloop_history_scan` asked the scanner for neither the inline-suppression
  count nor the reasoned count, so its scope sentence read exactly like a scan
  with nothing to suppress — the one thing that sentence exists to prevent, and
  a gap that predates the suppression work rather than coming from it. It now
  passes the same accounting the CLI consumes into `describeScope`, producing the
  same sentence for the same selection. **Not by sharing one function:**
  `src/mcp-core.ts` carries its own copy of `describeScope`, deliberately, so the
  MCP bundle does not import a module with a top-level side effect. The two
  implementations are held identical by a parity test in `tests/mcp.test.ts`
  rather than by import — coupling by assertion, which is what makes the
  sentences byte-identical across the bundle boundary.
- **Aggregate only, and unknown is not zero.** Counts and nothing else: no
  reason text, suppressed value, fingerprint, path or source line, no suppressed
  finding as a result row, no new hash and no suppression identity. The reason
  clause is omitted when the producer could not establish the count, exactly as
  it is when the count is a measured zero — the sentence cannot distinguish
  them, and the CLI's JSON report is where that difference shows. A stopped scan
  keeps its existing partial sentence and claims no counts.

### Report comparison

- **`binaryDigest` no longer collapses a literal backslash onto a directory
  separator.** `binaryIdentity` rewrote `\` to `/`, so on POSIX — where a
  backslash is a legal filename character — a real file named `dir\file.png`
  produced the same exclusion identity as the unrelated real path
  `dir/file.png`. Two different exclusion sets read as one. The function now
  takes canonical, repository-relative, `/`-separated paths and **refuses**
  anything ambiguous instead of reinterpreting it; separator conversion for
  Windows producers stays at the enumeration, where the originating semantics
  are known. Non-canonical spellings (`.` and `..` segments, repeated and
  trailing separators) are refused for the same reason. A refusal withholds the
  **entire** digest: the offending path is never dropped so the rest can be
  hashed, and the empty-set digest is never substituted.
- **A literal backslash is a legitimate producer output, not an impossible one.**
  Windows separators are converted at the enumeration
  (`path.relative(...).split(path.sep).join("/")`), so none arrives here as `\`.
  But on POSIX `path.sep` is `/`, so that same conversion correctly leaves a
  backslash that is part of a *name* alone, and the fallback directory walk does
  emit `dir\file.png` for a file called that. The filename is valid; the
  identity representation simply cannot express it, so the digest is withheld.
- **Reachability, stated accurately.** `git ls-files` C-quotes such a name
  whatever `core.quotePath` is set to, so the git-backed enumeration forwards a
  path that does not exist and the containment guard refuses it, already marking
  the report incomplete — **a formatting behaviour of one producer, not a
  containment guarantee.** The **fallback directory walk** has no such behaviour,
  and there two genuinely different trees produced one `binaryDigest` with
  `incomplete: false` on both sides. Demonstrated end to end through the real
  comparator, which admitted the pair and reported no difference.
- **`BINARY_CONTRACT_VERSION` moves 1 → 2.** The representation changed, so
  every `binaryDigest` changes. Without the bump a version-1 report and a
  version-2 report of *different* trees carry the same digest and compare
  silently — measured, not supposed. The cost is deliberate and documented: a
  report written before this change is incomparable with one written after even
  for an unchanged tree, and the comparator says `identity-mismatch
  (binaryDigest)`. `REPORT_SCHEMA_VERSION` stays **4**: `binaryDigest` is still
  required, still `binary:<16 hex>`, and still identifies the binary-excluded
  set — what changed is the representation the digest is computed over, which is
  precisely what the contract version versions.
- **It does not repair reports already written.** Two version-1 reports still
  compare with each other and still carry the collapsed identity. Nothing can
  reach back into a report that was already emitted.

### Remediation

- **A redaction now checks whether the value it removed is still there.** Both
  redaction quick-fixes, and the rotation path that shares them, run one
  automatic check after a successful edit — never a retry, never a second edit.
  Three outcomes: the value occurs nowhere in that editor document, it is still
  there (a warning, with the number of surviving occurrences), or nothing could
  be established.
- **It looks for the exact value, not for a finding.** A `secretloop:allow`, an
  `excludeRules` entry, an `allowValues` pattern or a fixture path makes a
  credential vanish from a scan while it sits in the buffer untouched, so
  absence from a filtered detector run proves nothing. The value the fix already
  held in memory is searched for directly; it is never persisted, logged,
  printed, transmitted or hashed, and no new digest of credential material
  exists. Occurrences are counted non-overlapping.
- **The scope is one editor document and the wording says so.** Nothing is
  saved, disk is not read, and no claim is made about other files, the working
  tree, history, archives or the provider — and never that a credential was
  revoked or rotated. It is an observation of the buffer that was read, not a
  promise that it stays that way, and it claims no causation: another change can
  land between the edit and the read, so the two facts are reported side by side
  and joined by nothing.
- **Unavailable is a first-class outcome**, for a refused or stale edit, an
  unreadable document, no usable value, text containing a NUL byte, and encoded
  findings — whose recorded value is the encoded spelling. A positive
  observation always outranks a coverage doubt; an absence claim never survives
  one.
- `.env` extraction is deliberately not covered by this first slice: it moves
  the value into another file, so it needs its own wording.

### Suppression

- **A suppression can now say why, and none of them has to.**
  `secretloop:allow(rule-id)` scopes a directive to named rules, and
  `secretloop:allow -- reason` records why. Both parts are optional: a bare
  directive suppresses every rule on its line exactly as before, so every
  annotation already written keeps working and no migration exists. Scope
  narrows and never widens, and `gitleaks:allow` takes neither — it is another
  tool's directive, and text after it produces a diagnostic instead.
- **An attempted scope that does not parse is refused whole and suppresses
  nothing**, with a stable diagnostic code on stderr: an empty `allow()`, a
  missing closing bracket, an illegal character, or any rule id this build does
  not ship. A scope is all-or-nothing — `allow(aws-access-key,not-a-rule)`
  suppresses neither — and ids are checked against the rule table and the
  entropy pass rather than a copied list. Only a *genuinely* bare directive,
  with no bracket attached, keeps the legacy suppress-everything behaviour;
  `secretloop:allow (see TICKET-12)` is still prose after a bare directive.
  **Correction to this unreleased candidate**: an earlier draft of this entry
  read an empty or malformed scope as the bare form, so a typo in the new syntax
  silently widened suppression to every rule on the line. It now fails closed.
- **Reasons are sanitised once, at parse time**: capped at 200 characters with a
  diagnostic rather than a rejection, and with control characters and `<`/`>`
  replaced by spaces. That bounds the *format* only — it is not evidence that a
  reason contains no credential, which is why no surface publishes one.
- **The baseline reads `{"fingerprint", "reason"}` beside plain strings**, and
  the project file reads `{"rule", "reason"}` / `{"pattern", "reason"}` in
  `excludeRules` and `excludePaths` — where an object entry previously read as a
  glob, matched nothing and excluded nothing, silently. No file is rewritten and
  no version is bumped: `--write-baseline` still writes strings. A baseline
  entry that cannot be read is skipped and named on stderr rather than failing
  the load, because a baseline that refuses to load un-accepts every finding in
  it at once.
- **Baseline diagnostics name the entry by position and nothing else.** They
  carry a zero-based index and a stable code (`[baseline-entry-malformed]`,
  `[reason-truncated]`), and never the fingerprint, the path inside it, the
  reason or the rejected value. **Correction to this unreleased candidate**: an
  earlier draft prefixed them with the raw fingerprint, which the CLI prints to
  stderr and therefore into CI logs. A baseline or project file that is not
  valid JSON is now reported as such without the parser's own message, which
  quotes the bytes around the error and could echo a reason.
- **Disclosure qualifies the count that was already there** — *N finding(s)
  suppressed by inline directives, M with a recorded reason* — and says nothing
  new when no reason was recorded, byte for byte. The CLI, the MCP scope object
  and the editor summary all print the same sentence, and `reportCoverage` gains
  an additive `inlineSuppressedWithReason` count.
- **History scans count explained suppressions too.** `secretloop history` now
  carries the same accounting the working-tree scan does, through
  `LogPatchParser` and the `onSuppressed` callback, so its scope sentence gains
  the same clause and `reportCoverage` the same count. **Correction to this
  unreleased candidate**: history mode published
  `inlineSuppressedWithReason: 0` while suppressing findings whose directives
  carried reasons — a figure it had never computed. The field is now **absent**
  rather than zero when a producer cannot establish it, the distinction this
  report already draws for `binaryExclusions`; every producer in tree
  establishes it, so reports still carry it. A cancelled history scan reports
  what it read, as its other counts do, and the run is already marked
  incomplete.
- **A refused directive in history is reported too.** The same fixed diagnostics
  the file path prints, deduplicated across the whole parse and capped, on
  stderr. Advisory: they change no exit code, and they quote no line, path,
  reason or rejected text.
- **The reason text is never published** — not in text, JSON or SARIF output,
  not over MCP, and not in a log line. It describes the credential it was
  written beside, and may contain one, so beside a count of what was hidden it
  is a lead on a secret the scan withheld on purpose. An untrusted-content
  wrapper marks provenance; it is not an authorization boundary and does not
  prevent disclosure, so it is not treated as one here. No `suppressionReason`
  field is emitted on any result, and no suppressed finding becomes one. The
  inline reason never leaves the parser: `onSuppressed` receives a count of
  explained suppressions and no text.
- **Recording why changes no identity.** `configDigest` drops `excludeReasons`
  the way it drops `allowValues` content: documenting an exclusion is a comment
  about it, not a change to what was scanned, and two scans of the same
  configuration still compare equal after someone writes down the reason.

### Comparison

- **A shared displayed reference is now explained.** Several *distinct* findings
  can print the same `ruleId` and `digest`, because the digest covers the
  matched value and not the path. They were always counted separately; now the
  output says why they look alike — that more than one distinct finding is shown
  under that reference, that paths are omitted on purpose, and that looking the
  pair up in the original report may return more than one match. JSON gains an
  **additive** `sharedDisplayReferences` array (`ruleId`, `digest`,
  `distinctIdentities`); no existing field changed meaning, nothing new is
  hashed, and no path, fingerprint or positional identifier is published. It is
  kept separate from `ambiguousIdentity`, which is one identity seen several
  times.
- **Invalid findings are collected from both reports instead of only the
  first.** A refusal now lists every invalid finding it can from **both** sides,
  identified by side and array index with a stable reason code and its cause,
  never quoting the rejected value, path, fingerprint or rule id. Each side has
  its own diagnostic budget, so one flooded report cannot hide the other's
  errors; every finding is still inspected, so stated totals are exact, and a
  `diagnostics-truncated` reason says how many were omitted. Whole-comparison
  refusal, the absence of partial differences, exit 3 and the top-level
  `tool`/`comparable`/`reasons` keys are unchanged.

- **`secretloop compare <before.json> <after.json>` compares two saved reports.**
  The comparison metadata has existed since schema 2 so a later tool could decide
  whether two reports may be compared at all; until now nothing enforced those
  rules. This is that enforcement, scoped to **working-tree reports only**.
  - **Working-tree scope is enforced, not inferred.** Each report's
    `scopeDigest` must equal `scopeIdentity({ mode: "worktree" })`, taken from
    the same shared function the producer uses rather than a copied constant —
    so the check tracks `SCOPE_CONTRACT_VERSION` automatically and cannot drift.
    Presence of the nine fields is not sufficient, and neither is the two
    reports agreeing with each other: two history scans over the same commits
    carry equal, well-formed scope digests. A history report therefore cannot be
    made eligible by supplying the one field it lacks, and a staged report given
    a plausible scope identity is refused the same way.
  - **Validating metadata is not authentication.** Reports carry no signature or
    provenance, so every identity checked is a value the producer wrote. Passing
    means the two reports are internally consistent and declare compatible
    scans — never that those scans happened or covered what they claim.
  - **Eligibility is decided first and completely.** All nine schema-4 fields are
    validated with field-specific rules — `root` must match `git:<16 hex>`,
    `scopeDigest` must match `scope:<16 hex>`, and so on — and absent, null,
    wrong-typed, empty and malformed values are each refused. A shared absence
    never qualifies. `incomplete` must be `false` in **both** reports. Schemas 1,
    2 and 3, unknown future versions, and mixed-version pairs are all rejected.
    Tool, repository, configuration, rule-set, suppression, scope and
    binary-exclusion identities must match.
  - **No difference is computed for an ineligible pair**, and the JSON output
    carries no difference keys at all — an empty `new` array beside
    `comparable: false` is exactly what a careless consumer reads as "nothing
    changed".
  - **Exit codes:** `0` compared with nothing new, `1` compared with new
    findings, `2` unusable input, `3` **not comparable**. `3` exists so a refusal
    cannot be mistaken for a clean comparison.
  - **"No longer observed" means absent from the later report** — never fixed,
    removed, rotated or revoked, and it makes no claim about files either scan
    excluded or about renamed findings. The caveat ships in the output.
  - **Duplicate fingerprints are counted, not collapsed.** A fingerprint covers
    (path, rule, value) and not the line, so one credential repeated in a file
    shares one identity. Occurrence-level changes are reported as an explicit
    ambiguity rather than guessed at, and a finding with no usable fingerprint
    refuses the comparison instead of being silently dropped.
  - **Both reports are treated as untrusted.** Size is bounded before reading,
    structure is validated before processing, output fields are built explicitly
    rather than copied from the input, and no `value` or `redactedValue` is ever
    emitted — a field named "redacted" is a claim by the input, not a fact.
    **No report-supplied free text is printed at all.** Results carry only
    `ruleId` (required to be one of the rule ids this build emits — membership,
    derived from `rulesById` plus the entropy and keystore detectors, not merely
    a grammar check), the
    16-hex `digest` tail of the fingerprint, `line` and `severity` (admitted
    only from the scanner's own set). The scanned path and the raw fingerprint
    are **not** shown: a path is arbitrary text, and no format check can
    establish that arbitrary text contains no secret, so the comparator declines
    to print it rather than claim otherwise. `value` and `redactedValue` are
    never emitted, and the report's own `file` and `ruleId` fields are ignored
    in favour of the identity actually matched on. No new secret-derived
    identifier is computed — the digest is a verbatim substring of the
    fingerprint the report already carries. Matching still uses the **full raw
    fingerprint**, never a sanitized one, and an identity that cannot be parsed
    against the full `<path>:<ruleId>:<16 hex>` structure rejects the whole
    comparison instead of being dropped. Validation errors name the field at
    fault and never quote its value. Nothing in a report is fetched or executed.
  - **An unsupported rule id rejects the whole comparison.** The rule segment of
    a fingerprint was previously checked against a grammar only, which accepts
    any lowercase alphanumeric run — so an arbitrary string could pass and be
    printed. Membership in the set this build actually emits is now required,
    the set is derived from the existing authorities rather than copied, and a
    finding naming an unsupported rule refuses the comparison outright with no
    partial results and without echoing the id.
  - **The read is bounded by the descriptor, not the name.** Each report is
    opened once, inspected with `fstat` on the opened object, and read from that
    same descriptor with the cap enforced **during** the read — at most one
    chunk past the limit — and rejected before parsing. The descriptor is closed
    on every path. A file that grows or a path replaced after inspection can no
    longer cause an unbounded read. This is not an immutable or authenticated
    snapshot: another process writing the same file can still change what a
    later run sees.
  - No rescanning, no liveness verification, no provider call, no remediation,
    and no editor or MCP integration.

### Coverage

- **A binary file no longer makes a report incomplete.** The read path
  reported one `unreadable` reason for four unrelated events — a binary file, a
  path that is not a regular file, a read that failed, and a file that vanished
  between enumeration and read — and disclosed all four as "binary or
  unreadable" because it could not tell them apart. `incomplete` is derived from
  that list and comparison requires `incomplete: false` on **both** sides, so a
  single image made every report from a tree permanently ineligible. Scanning
  SecretLoop's own repository skipped 17 files and reported `incomplete: true`.
  Sixteen are images; the seventeenth is `tests/verify-consent.test.ts`, a 47 KB
  TypeScript source carrying exactly one NUL byte at offset 1867 — a separator
  in a test string — whose remaining 96% is not scanned. They are *classified*
  binary, which is not the same as being binary.
  - `SkipReason` now separates `binary`, `not-a-file`, `vanished` and
    `unreadable`. Only `binary` is an intentional exclusion; **every other
    reason still makes the report incomplete**, and `unreadable` remains the
    conservative bucket for anything unexplained.
  - **The binary skip is still disclosed**, as `N file(s) not scanned — binary`.
    What changed is what it means, not whether it is reported. The other reasons
    get their own clauses, each naming what actually happened.
  - **The classifier's boundary is now documented rather than implied.** It
    tests one thing — a NUL byte in the first 8,000 bytes — so UTF-16/UTF-32
    text and any text with an embedded NUL are classified binary, while a binary
    file whose first 8,000 bytes carry no NUL is not. A binary skip therefore
    never establishes that a file is free of secrets, only that nothing looked,
    which is why the disclosure is retained.
  - **A failed inspection of a SUPPORTED binary format stays a limitation.** An
    archive whose parser declined it is still disclosed as a container that was
    not opened, and still counted once rather than twice. A file the PKCS#12
    prefilter admits but that yields no finding keeps the `could not be read`
    reason, because the detector cannot distinguish "well-formed keystore,
    nothing in it" from "declined by the structural walk".
  - The CLI and MCP skip tallies are now exhaustive over the reason type, so a
    future reason cannot silently be absorbed into `unreadable` on one surface
    and something else on the other.
  - **`binaryDigest` identifies WHICH files were excluded as binary**, and is
    the ninth required comparison field. Without it, the exemption above opened
    a hole: a file could cross *into* the binary set between two scans and its
    findings would vanish while every comparison field stayed equal. Measured —
    insert one NUL into a file holding a credential, without touching the
    credential, and the pair stayed eligible while the finding disappeared, so a
    consumer would read a still-present credential as removed. The digest covers
    a canonical, sorted, deduplicated set of repository-relative paths, carried
    with its own contract version; separators are normalized to `/`, a leading
    `./` is stripped, and an absolute path is refused rather than published.
    **No file content, credential or absolute path is hashed.**
    - It is derived from the scan's own exclusion events, never from a second
      walk of the tree that might observe something different.
    - **An empty set is a real identity**, so two scans that excluded nothing
      compare. A producer that cannot observe its own exclusion events omits the
      field instead, which makes the pair ineligible — `history` does exactly
      that, because it reads blobs and emits no file-level exclusion events. A
      stopped scan omits it too, its set being partial.
    - It is **not anonymisation**: repository paths are often predictable, so a
      candidate list can be tested against the digest exactly as against `root`.
  - **`schemaVersion` is now `4`.** `incomplete` counts a strictly narrower set
    of facts than it did under 2, and the boolean still type-checks either way —
    so the version is the only thing preventing a version-2 report and a
    version-3 report from comparing across two different meanings of one field.
    Versions 1, 2 and 3 are unsupported: a consumer implementing this contract
    accepts `4` and rejects everything else. Version 3 is rejected because it
    carries no `binaryDigest`, so nothing establishes which files it declined to
    look at.
  - No detector, finding, fingerprint, consent, suppression identity or provider
    behaviour changed. On a fixed corpus the findings and their fingerprints are
    byte-identical before and after.

### Reports

- **The JSON report carries comparison metadata.** `schemaVersion`,
  `toolVersion`, `root`, `configDigest`, `ruleSetDigest`, `suppressionDigest`
  and `incomplete` at the top level, with descriptive coverage and suppression
  counts under `summary.coverage`. Additive: every pre-existing field keeps its
  name, position and meaning, the findings array is untouched, and SARIF, the
  text report and the baseline format are unchanged. A report produced before
  this existed still parses — it is ineligible for comparison rather than
  assumed to match.
  - **A field that could not be determined is ABSENT, never `null`.** Two
    reports that both said `"root": null` would compare equal on a naive read,
    and a finding that is still present would then be reported as gone.
  - `root` is a digest of the repository's root commit, so it is portable across
    machines and clones and publishes no absolute local path. Absent outside a
    git repository.
  - `allowValues` **content is never hashed** — only its count. A digest over a
    short guessable input is an oracle, not anonymisation.
  - `suppressionDigest` is **withheld entirely** when an allowlist, a baseline or
    an inline directive was in play, because none of those can be identified
    without publishing a new secret-derived hash or treating an equal count as
    equal suppression.
  - **`scopeDigest` identifies which population the scan examined**, so a
    working-tree, staged and history scan of one repository no longer share an
    identity. For history it covers the commits actually read, reported by the
    parser that read them — not the rev-range string, which is the request and
    not the selection. Two disjoint ranges of equal length previously carried
    identical metadata and an identical scope sentence; they no longer do.
    Equivalent selections still compare equal: `HEAD~1..HEAD`, an explicit SHA
    range naming the same commit, and `--max-commits 1` are one selection. Any
    difference in the selected commit set is incomparable in this first version.
  - **A staged report carries no scope identity and is never comparable.** Its
    population is the index: unstaging a byte-identical file makes a finding
    vanish from a staged scan while the secret is still in the working tree, and
    a mode-only identity let that pair read as the finding being gone. Making it
    comparable needs a comparator that labels a staged report as an index
    snapshot, which does not exist.
  - A history scan that stopped early reports **no** selection and marks its
    coverage incomplete, rather than presenting the commits it happened to read
    as the ones it selected.
  - **Development history — superseded before this release shipped.**
    When this entry was written `schemaVersion` was **2** and the contract had
    **eight** required fields. Neither figure describes what 0.6.0 ships. The
    version reached **4** under *Coverage* above, when `binaryDigest` became the
    **ninth** required field; schemas 1, 2 and 3 existed only during development
    and were never published. The steps are kept because they record why each
    bump happened, not because either number is current.
  - The required-field contract is explicit and normative in
    [docs/reports.md](docs/reports.md): **all nine fields**, each with its own
    validity rule, and `incomplete` required to be **`false` in both** reports —
    `true === true` must not permit comparison.
  - `root` is documented as **shared ancestry**, not repository identity and not
    anonymisation: a root commit is public, so the digest is confirmable rather
    than concealing, and a fork shares its upstream's.
  - **Development history — superseded before this release shipped.**
    This entry originally recorded "no comparison command". `secretloop compare`
    is implemented and shipped in 0.6.0, described under *Comparison* above.
    What still holds unchanged: no rename tracking, no "resolved" claim, no new
    detector, and metadata alone does not establish that two scans are
    comparable.

### SARIF

- **`tool.driver.version` is emitted**, so a code-scanning alert can be attributed
  to the SecretLoop version that raised it. The value comes from the CLI's
  existing `packageVersion()` read of `package.json` — the release authority — and
  is passed into the reporter rather than read there, so no second constant exists
  and neither the extension nor the MCP bundle gains a filesystem dependency. A
  caller that supplies no version emits no key: an empty version cannot be told
  from a real one.
- **Results carry `startColumn` and `endColumn`**, with the run declaring
  `columnKind: "utf16CodeUnits"`. GitHub previously annotated the whole line for a
  twenty-character credential. The columns are computed at scan time from the
  offsets the scanner already records — never by searching for the value, which
  the report has redacted by then — and `endColumn` is exclusive, as SARIF
  requires. Columns are **omitted** where they would be wrong: an archive member,
  whose span belongs to the member while the artifact is the container; a span
  crossing a newline, which would need a paired `endLine`; and any finding whose
  line-start offset was unavailable. Line, artifact, logical location,
  fingerprints and invocation properties are unchanged.

## 0.5.1 — 2026-09-11

A maintenance release: four defect fixes, one piece of defensive hardening,
permanent regression tests and three dependency updates. No rule was added,
removed or renamed, the rule count is unchanged at 110, and no detection
threshold, fingerprint, severity or output format changed.

### Consent store

- **`readRecord` now refuses a record whose contents disagree with the filename it
  is stored under**, matching the check `listRecords` already made. The two readers
  of `~/.secretloop/pending/` previously disagreed about what counted as a valid
  record: `listRecords` rejected a planted file, `readRecord` returned it.
  **Defensive hardening, not a fix for a reachable bypass.** `readRecord` has one
  caller, the MCP `verify` tool, which derives the record id from the request and
  independently re-checks the fingerprint, path, expiry, on-disk resolution,
  commitment and provider before anything is transmitted; `record.id` is read by
  nothing. Writing to the consent directory also requires the OS user account,
  which is the documented trust boundary, and anyone with it could write a record
  carrying the correct id. No storage format, commitment check, consent lifecycle,
  consume-before-transmit ordering or public response schema changed.

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

### Dependencies

- **`@types/vscode` 1.134.0 → 1.136.0** (PR #30), **`@aws-sdk/client-sts`
  3.1116.0 → 3.1127.0** (PR #31) and **`@aws-sdk/client-iam` 3.1116.0 →
  3.1127.0** (PR #32). All three are devDependencies; `dependencies` remains
  absent, so an installed package still pulls nothing at runtime.
- **The shipped bundles changed, and a lockfile-only diff was not
  behaviour-free.** The AWS SDK is bundled into `out/cli.js`, `out/mcp.js` and
  `out/extension.js`, so PR #31 carried `@aws-sdk/credential-provider-node`
  3.972.81 → 3.972.82 into all three: a `.catch(() => {})` added to the passive
  credential-refresh chain, plus a version constant.
- **That change is not reachable from either AWS caller.** Both construct their
  client with explicit static credentials, which selects a different provider
  path; measured offline, the default credential-provider chain was constructed
  **zero** times across every exercised path. Verification against STS was
  exercised offline only, against synthetic responses; the IAM rotation path was
  reviewed from source and not exercised at runtime. The SDK's own retry
  behaviour on a throttled response is unchanged by this update.

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
