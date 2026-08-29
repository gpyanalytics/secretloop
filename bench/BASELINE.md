# Baseline — before the 0.1.1 detection fixes

Recorded by running `python3 bench/run.py --corpus-b <bugsnag-js>` against the
build at commit `7dbac60`, before any rule change. Every number below came from
that run, not from a previous report.

Corpus A regenerated from seed 20260829; the regenerated labels matched
`bench/labels.json`, so this scores the same corpus the fixes will be scored
against.

## Corpus A — 50 tree secrets, 120 decoys, 10 history-only

| tier / scan | found | TP | FP decoy | FP other | detected | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| entropy-on tree | 56 | 43 | 13 | 0 | 43/50 | 0.768 | 0.860 | 0.811 |
| entropy-on history | 73 | 52 | 12 | 9 | 52/60 | 0.712 | 0.867 | 0.782 |
| named-only tree | 52 | 42 | 10 | 0 | 42/50 | 0.808 | 0.840 | 0.824 |
| named-only history | 67 | 50 | 9 | 8 | 50/60 | 0.746 | 0.833 | 0.787 |

Misses by kind — entropy-on tree: `generic-password` (7 of 7).
Misses by kind — named-only tree: `generic-password` (7 of 7), `aws-secret-key` (1 of 6).

## Corpus B — bugsnag-js @ 5da3ae169c9ff716fa70d1388bb8e2157ca46ea6

2012 tracked files, 185.4 KLOC. Every finding is a false positive by definition.

| | count |
|---|---|
| tree FPs | 150 (0.809 per KLOC) |
| history FPs | 299 |
| tree by rule | `generic-high-entropy` 87, `generic-api-key-assignment` 63 |

Zero of the 103 named provider rules fired on this repository. The entire
false-positive surface is the two generic rules.
