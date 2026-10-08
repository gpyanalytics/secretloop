# Baseline

## Note on the `entropy-on` arm — 4 October 2026

`bench/run.py` has two corpus A arms, `entropy-on` and `named-only`. Until the
correction recorded here, the `entropy-on` arm did not pass `--include-entropy`;
it simply omitted the project file the `named-only` arm writes. That was a real
distinction while the entropy tier was on by default, so **every table below,
all recorded on 29 August 2026, is a genuine two-arm measurement.** On
8 September 2026 (0.4.0, commit `fd01370`) the tier became opt-in, and from that
day the `entropy-on` arm measured the tier **off**: both arms ran one
configuration (same `configDigest`, `3071344b11905ec5`), and any `entropy-on` row
produced between 8 September and this correction — including the release-validation
benchmark runs of 3 October 2026 — is an entropy-off measurement under an
entropy-on label. The arm now passes `--include-entropy` to both the tree and the
history scan, the `named-only` arm switches the tier off through an explicit
project file, and the run refuses to report if the two arms resolve to the same
configuration identity.

### Corpus A — corrected `entropy-on` measurement, 4 October 2026

Provenance: `bench/run.py` as corrected here, run on the `main` build at
`98847c26fb69e826a491d6e25223d0efae30ddf8` (`out/cli.js` sha256
`229475b76a93149ea9114d3733b3aa6dd7e818e4db11ecd12ac7de77c0b3c94d`, node
v26.8.1, darwin arm64); corpus A regenerated from seed 20260829 with the labels
matching `bench/labels.json`; `entropy-on` = `--include-entropy` on both scans
(`configDigest 7565a70d15c1b1b6`), `named-only` = `{"entropyPassEnabled": false}`
in the corpus root (`configDigest 3071344b11905ec5`).

| tier / scan | found | TP | FP decoy | FP other | detected | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| entropy-on tree | 50 | 50 | 0 | 0 | 50/50 | 1.000 | 1.000 | 1.000 |
| entropy-on history | 60 | 60 | 0 | 0 | 60/60 | 1.000 | 1.000 | 1.000 |
| named-only tree | 50 | 50 | 0 | 0 | 50/50 | 1.000 | 1.000 | 1.000 |
| named-only history | 60 | 60 | 0 | 0 | 60/60 | 1.000 | 1.000 | 1.000 |

The rows equal the entropy-off rows, and that is a property of the corpus, not
proof that the flag did nothing: corpus A's 120 decoys are high-entropy or
credential-shaped by design and the tier reports none of them, so its arms score
the same with the tier on or off. The flag's effect was shown separately, on a
disposable one-commit repository holding two random 48-character tokens (a
quoted assignment value and a bare `name: value`): 0 findings with the tier off,
2 `generic-high-entropy` findings with it on, with the same two fingerprints
from the 0.6.0 build and from this one. Scoring, labels and rules were not
changed to obtain any number above.

**Corpus B is not re-measured here, and its limitation stays open.** The
real-noise repository in the tables below is unnamed and its commit unrecorded,
so its rows cannot be re-run; a corrected `entropy-on` figure for it does not
exist. Naming and pinning a corpus B is still the smallest next step.

## Corpus B, named and pinned — getsentry/sentry-javascript @ fade8e2ddd3dfc2ff18b6e4053a93a94c1c7cbae, 6 October 2026

Measured on the build at `main` `0e2a3749` (SecretLoop 0.7.1 tree compiled with `tsc`; `out/cli.js`
sha256 `abc4cd48aa7f9dfa…`), offline, no `--verify`, with the commands under "Corpus B (named)" in
`bench/COMMANDS.md`. The measurement clone carried the **full history reachable from the pinned
commit: 16,211 commits, 4 root commits, not shallow**. The preserved depth-1 clone of the same commit
(the N8 keyed corpus) was not used for the history arm and was not altered.

This corpus **does not reproduce the historical unnamed corpus B** below: different repository,
different size, different commit. Nothing here is comparable with those rows.

**Findings are untriaged.** The repository is assumed, not audited, to hold no live credential, and
nothing in these counts was labelled by a person. A count below is "findings", not "false
positives", until each one is labelled; no finding was verified against any provider.

| input | value |
|---|---|
| tracked files | **9,976** (`git ls-files -z`, verified). The legacy bench LOC method (`bench/run.py`, which whitespace-splits `git ls-files` output) reported **9,978 tokens** and "4 unreadable": one tracked path contains spaces and split into three tokens, inflating the count by two and producing three of the four "unreadable" entries; the fourth is one tracked entry that is a directory rather than a regular file, which the method cannot open (the scanner reports the same path as "not a regular file"). These are not four genuinely unreadable files. 54 skipped as binary. |
| lines (legacy bench method: newlines in the non-binary tracked files it could open) | **735,547, the legacy measured total.** It omits the path with spaces, so it is below the true count by that file's lines; no corrected total was computed, and the derived 735.5 KLOC is this measured figure, not a complete one. |
| tree scan scope | 9,905 files scanned; 1 generated file excluded by default; 1 file over `maxFileSizeBytes`; 53 binary; 1 not a regular file — the tree report is marked `incomplete` for the two limitations |
| history scan scope | 14,532 non-merge commits (`git log --no-merges`) of the 16,211 reachable; merge commits' own diffs are not scanned by design; 2 generated files excluded; report not marked incomplete |
| `ruleSetDigest` (all arms) | `c6f8fdd1265654d9` |
| `configDigest` entropy-off / entropy-on | `3071344b11905ec5` / `7565a70d15c1b1b6` — distinct, so the two arms are two configurations; the off digest equals that of corpus A's **named-only** arm, whose config file sets `entropyPassEnabled: false` explicitly (the same effective configuration as no config file), and the on digest equals that of corpus A's `entropy-on` arm |
| repository identity (`root`) | `git:2ccf6c6b74bb9a84` in every report |

| arm | findings (untriaged) | by rule |
|---|---|---|
| tree, entropy-off | 15 | generic-api-key-assignment 6, db-connection-string 4, private-key-block 3, http-basic-auth-url 1, jwt 1 |
| tree, entropy-on (`--include-entropy`) | 22 | the 15 above + generic-high-entropy 7 |
| history, entropy-off | 34 | generic-api-key-assignment 15, http-basic-auth-url 7, db-connection-string 6, private-key-block 5, jwt 1 |
| history, entropy-on | 47 | the 34 above + generic-high-entropy 13 |

Per legacy-measured KLOC (735.5; see the line-count row for what it omits), tree arm: 0.020 findings
(entropy-off), 0.030 (entropy-on) — findings per KLOC, not a false-positive rate, for the reason above. Severities, tree: 8 critical, 7 high (+7 medium with
entropy); history: 18 critical, 16 high (+13 medium with entropy). Liveness: every finding `unchecked`.

**Reproducibility:** every arm was run twice from the same clone; the two reports of each arm were
identical in every top-level field, including all findings and all digests. Wall time 5–7 s per tree
scan and 16–22 s per history scan on an Apple-silicon laptop. Raw reports (values masked by the
scanner's default) stay in the benchmark evidence workspace, record `corpus-b-sentry-javascript-2026-10-06`,
and are not committed.

**Limitations:** one person's unlabelled scan on one commit; the scanner's named rules and generic
tier matched 15–47 locations that nobody has classified; the history arm excludes merge commits and
two generated files; the tree arm excludes one oversized and one generated file; none of the counts
says anything about recall, because nothing was planted and nothing is known to be present.

## Current baseline — generator scratch moved out of the corpus, 29 August 2026 (both arms genuine; the tier was on by default then)

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
`generic-high-entropy` and `generic-api-key-assignment`, with zero of the 109
named rules firing.
