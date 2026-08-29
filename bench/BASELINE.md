# Baseline

## Current baseline — generator scratch moved out of the corpus, 29 August 2026

Recorded by running `python3 bench/run.py --corpus-b /path/to/real-noise-repo`
against the build at this commit. Corpus A regenerated from seed 20260829; the
regenerated labels match `bench/labels.json`.

### Corpus A — 50 tree secrets, 120 decoys, 10 history-only

| tier / scan | found | TP | FP decoy | FP other | detected | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| entropy-on tree | 50 | 50 | 0 | 0 | 50/50 | 1.000 | 1.000 | 1.000 |
| entropy-on history | 60 | 60 | 0 | 0 | 60/60 | 1.000 | 1.000 | 1.000 |
| named-only tree | 50 | 50 | 0 | 0 | 50/50 | 1.000 | 1.000 | 1.000 |
| named-only history | 60 | 60 | 0 | 0 | 60/60 | 1.000 | 1.000 | 1.000 |

### Corpus B — the real-noise repository, at its pinned commit

2012 tracked files, 185.4 KLOC, no known secrets — every finding is a false
positive.

| | count |
|---|---|
| tree FPs | 4 (0.022 per KLOC) |
| history FPs | 28 |
| tree by rule | `generic-high-entropy` 4 |

## What moved the history arms to 1.000

`_history_plan.json` — the generator's own record of the ten history-only
plants, with their values in plaintext — was written inside the corpus root.
`gen_history`'s first commit is `git add -A`, so the file entered the object
store before the later `git rm` removed it from the working tree. That left a
clean tree and ten real credentials in git history, which the history scan
found and the scorer counted as false positives because the labels do not list
them.

It was a measurement artifact rather than a scanner defect, and it was capping
history precision by construction: exactly ten findings entropy-on, eight
named-only. Both files now live beside the corpus rather than inside it, where
no git command reaches them, and the deletion commit that existed only to undo
the mistake is gone with it.

| arm | precision before | after |
|---|---|---|
| entropy-on history | 0.857 | **1.000** |
| named-only history | 0.882 | **1.000** |

Recall was 1.000 on both arms before and after — nothing about detection
changed, only what the corpus was asking the scanner to explain. Corpus B is
untouched at 4 tree findings, as expected: it has no generator and no plan file.

## Superseded — corpus repaired 29 August 2026

The table below was current between the corpus repair and the change above.
Its tree rows still hold; its history rows carry the plan-file artifact, and
its corpus B rows predate the fixture-path suppression and the narrowed
relative-path filter, which together took tree false positives from 151 to 4.

| tier / scan | found | TP | FP decoy | FP other | detected | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| entropy-on tree | 50 | 50 | 0 | 0 | 50/50 | 1.000 | 1.000 | 1.000 |
| entropy-on history | 69 | 60 | 0 | 9 | 60/60 | 0.870 | 1.000 | 0.930 |
| named-only tree | 50 | 50 | 0 | 0 | 50/50 | 1.000 | 1.000 | 1.000 |
| named-only history | 68 | 60 | 0 | 8 | 60/60 | 0.882 | 1.000 | 0.938 |

Corpus B at that point: 151 tree FPs (0.815 per KLOC), 300 history FPs,
`generic-high-entropy` 87 and `generic-api-key-assignment` 64.

## What the repair changed, and why the earlier numbers are not comparable

Two corpus defects were fixed together, so numbers recorded before 29 August 2026
are historical and must not be compared cell-by-cell against the table above.

**Secrets no longer sit in fixture paths.** Five planted secrets landed in
`test/` because the directory pool included it. That was harmless while nothing
treated fixture paths specially, and became a contradiction the moment the
product began suppressing generic findings there: a labelled secret in a
suppressed path makes a miss unreadable — scanner failure, or the corpus asking
for something it also asked to be hidden. Secret-bearing files now draw from a
non-fixture pool. Decoys deliberately stay in fixture paths and are labelled
`expected: "suppressed"`, because they are the coverage for that suppression.

**History plants carry credential-shaped variable names.** Every history-only
plant was written as `CREDENTIAL = "..."`, a name no keyword-gated rule can
match. History recall therefore measured the entropy tier and nothing else, and a
named rule scoring zero there said nothing about the rule. Plants now use the
same `KEYNAMES` embeddings the tree uses.

Measured effect of the second repair, same build, same seed:

| tier | history recall before | after |
|---|---|---|
| entropy-on | 0.983 (59/60) | **1.000 (60/60)** |
| named-only | 0.967 (58/60) | **1.000 (60/60)** |

A consequence worth stating: the corpus can no longer see the relative-path
filter defect it originally surfaced. The one plant the entropy tier missed —
a 40-character base64 key with a single `/`, structurally identical to a
two-segment relative path — is now found because a named rule fires on its
keyword. That defect is real and unfixed by this repair; its evidence is the
direct simulation in the Stage C2 work, not this corpus.

## Historical — before the 0.1.1 detection fixes, before the corpus repair

Kept for the record. Corpus A tree 0.768/0.860 entropy-on and 0.808/0.840
named-only; corpus B 150 tree false positives at 0.809 per KLOC, all from
`generic-high-entropy` and `generic-api-key-assignment`, with zero of the 103
named rules firing.
