# 0003 — Archives are opened in memory, one layer deep, under frozen limits

**Status:** shipped in 0.5.0 (2026-09-09) (PR #44). **Surfaces:** every scan surface.

## Decision

ZIP, tar, gzip and gzip-wrapped tar containers are opened in memory and each
member is scanned exactly as a file of the same bytes would be, through the
member's display path `container!/member`. Nothing is extracted to disk; no
member name is resolved against any filesystem; a member that is itself an
archive stays opaque.

Frozen limits, deliberately not configurable: 10,000 entries per container;
member names up to 1,024 characters; a member larger than `maxFileSizeBytes`
refused before any decompression; total decompressed output at most 100 times
the outer file. Refused and counted by reason: encrypted entries, ZIP64,
unsupported compression, names with `..`, absolute names, drive letters,
control characters, duplicate names, symlinks, hard links and device entries. A
gzip stream's FNAME header is never used as a name; the member is named from
the outer path.

## Why

Archives were the largest measured blind spot: the three-tool study found
TruffleHog reading 93 archive-interior rows that SecretLoop skipped. Opening
them one layer deep recovered 53 member findings (52 validated true positives,
1 false positive) in the `deno` npm tarballs alone, including PKCS#12 keystores
inside archives.

## Why these bounds

- **In memory, never on disk.** Extraction is where traversal, symlink and
  permission attacks live. The parser has no filesystem access at all, so a
  hostile member name is a display string and nothing else.
- **Depth one.** Nested archives are the amplification vector. The boundary is
  structural rather than a flag.
- **Budgets.** Per-member size, total ratio and entry count bound both memory
  and CPU; the review measured a 200 MB gzip bomb refused in half a second and a
  ratio bomb stopping at the budget with the remainder disclosed.
- **Verification refuses members.** No surface can re-read a member from disk to
  confirm what would be sent, and the consent flow needs exactly that, so member
  findings report `unsupported-container` and are never transmitted.
- **Identity.** A member's fingerprint carries the container kind, path and
  member name as structural material, so a real file whose name looks like a
  member path never collides with it.

## Documented limits

A ZIP whose comment contains an end-of-central-directory signature can steer
the parser to a different directory than another tool would read; a stopped tar
walk cannot say how much it left behind; look-alike characters in member names
are display-only. The 100× budget lets a small archive expand to a large amount
of scanned text, bounded and measured (about six seconds for 39 MB).

## Evidence

Planted archive corpus 31/31 expected-rule members at exact identity and line,
controls 0/36, out-of-scope 0/40, PKCS#12 members 2/2; six-repository
regression with additive labels for the 53 member findings; pre-release
security review of the parser (fuzzing 2,000 mutated inputs without a throw,
bomb and traversal probes). Records in the benchmark workspace (archive corpus
manifest 92/92, post-implementation 91/91).
