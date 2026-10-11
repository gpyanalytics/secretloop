# 0008 — The security review covers every consent source file

**Status:** adopted 2026-10-12, prospective: first applies to 0.7.3. **Surfaces:** release
process; contributor review.

## Decision

The security-critical surface names `src/consent*.ts` where it named only `src/consent.ts`, in
[RELEASING.md §5](../../RELEASING.md#5-security-review-conditional) and in
[CONTRIBUTING.md](../../CONTRIBUTING.md#changes-to-the-security-critical-surface). The command
that settles whether §5 applies becomes:

```
git diff --name-only <previous-tag>..HEAD -- 'src/mcp*.ts' 'src/consent*.ts' 'src/verify*.ts' 'src/workspace*.ts'
```

Nothing else in §5 changes: the other patterns, the nine invariants the review attacks, the rule
that a large rebase or merge onto the surface counts as touching it, and the exemption for
detection-only changes.

## Why

The consent store's checks grew beyond `src/consent.ts` after the list was written. Four modules
now carry consent-store invariants and matched no pattern:

| file | what it decides |
|---|---|
| `src/consent-acl-win.ts` | whether the store's owner and access lists on Windows can be trusted, including its ancestors |
| `src/consent-acl-macos.ts` | whether macOS extended ACLs grant anyone else access to the store or a record |
| `src/consent-parent-chain.ts` | whether the directories above the store on POSIX could let another account replace it |
| `src/consent-budget.ts` | the aggregate work bound on one consent operation's checks |

A release whose only security-relevant change sat in one of these files would have produced an
empty settling command, and §5 would not have applied. 0.7.2 recorded this gap and included §5 by
owner decision rather than by the rule. The wildcard also covers any consent module added later,
which is intended.

## What this does not change

- **It is not retroactive.** Earlier releases' §5 determinations, the reviewed endpoints listed in
  `docs/development.md`, and the 0.7.2 gap stand as recorded. No past review is reopened, and
  no earlier record is edited.
- **The other release gates are untouched.** D5 (decision 0007 and its amendment of 2026-10-11),
  the rule that a run is never repeated to obtain a green result, the required checks, the CI
  workflows and every other item of RELEASING.md are unchanged.

## What it costs

A release that changes only one of the four modules now needs the adversarial re-review. For
0.7.3 there is no new obligation: no file under `src/` has changed since `v0.7.2`, so the amended
command run against `v0.7.2` is empty, as the old one is.

## Evidence

At `main` `209e5798`, `src/consent*.ts` matches exactly `src/consent.ts` and the four modules
above. Each of the four shipped in 0.7.2. For `v0.7.1..v0.7.2` the old command reports no file
and the amended one reports `src/consent-acl-win.ts`, which is the gap as it occurred. It is
recorded in the private benchmark workspace as `release-0.7.2-scope`.
