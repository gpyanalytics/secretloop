# N9 — identifier/type-name suppression by alphabetic density: STOP

**Result: not shipped.** The frozen candidate `alpha_frac >= 0.83` rejected
**69,721 / 140,000 = 49.80 %** of realistic credentials on the independent
recall corpus. This records what was tested and what it does and does not
establish, in the same spirit as the N8 measurement-impossibility record.

## Origin

The six-repository exploratory benchmark (pinned SHAs, see
`secretloop-benchmark/`) triaged 918 findings by hand. SecretLoop's
`generic-high-entropy` rule produced 279 of its 307 false positives (91 %).
Of those, the largest single class was **111 "long identifier / type name,
not a value"** findings — 85 of them OpenAPI `operationId`s — none of which
match the existing N7a (ordered-run) or N7b (path-shape) vetoes when those
predicates are reconstructed exactly (0 / 279 survivors match either).

The 14 `generic-high-entropy` true positives in that corpus were all
44-character base64 AES fixture keys, taking exactly two `alpha_frac`
values: 0.7955 (×8) and 0.8182 (×6).

## Method

A characterisation-only study, run in this order with each step predeclared
before the next was seen:

1. **Feature extraction** (`characterize_ghe.py`): candidate values recovered
   from the pinned checkout by fingerprint + file + line (the JSON `value`
   field is a non-length-preserving mask), features computed in memory,
   only structural features emitted. Exact N7a/N7b reconstructions included.
2. **Predicate search** (`predicate_search.py`): singles and two-feature
   conjunctions over the 111 identifier FPs vs the 14 TPs; population
   closed at 293 / 279 / 14 / 111 by hard guards; `fixture_like_path`
   excluded from the search; predicates grouped by exact observed hit set.
3. **Freeze**: exactly ONE candidate, `deduped[0]` by a predeclared ranking
   (max identifier-FP suppression → max all-FP → fewest conjuncts → shortest
   → lexical). No second candidate.
4. **Independent gate**: the N1/N7 realistic-token corpus regenerated from
   `bench/entropy-vetoes.ts` (seed 20260831, byte-identical — N7a/N7b again
   0.0000 %), emitting only `bucket / family / length / alpha_count`. The
   frozen predicate applied in Python with the exact semantics that produced
   it: `round(alpha_count / length, 4) >= 0.83`. Gate population = the
   corpus's own REALISTIC set. Non-zero loss = STOP; no retuning.

## Frozen candidate and benchmark evidence

| | value |
|---|---|
| predicate | `round(alpha_count / len, 4) >= 0.83` |
| identifier FPs suppressed | 110 / 111 |
| all generic-high-entropy FPs suppressed | 191 / 279 |
| observed TPs suppressed | 0 / 14 |

The 0 / 14 was an artifact: all 14 TPs are one encoding (base64,
per-character alpha probability 0.800) sitting 0.012 below the threshold.
They span no diversity, so the observed-TP result could not bound recall.

## Gate result (independent corpus, n = 140,000 realistic)

| bucket | n | rejected | loss |
|---|---:|---:|---:|
| realistic-documented | 55,000 | 25,626 | 46.59 % |
| realistic-floor-length | 55,000 | 28,456 | 51.74 % |
| realistic-untouched-branch | 2,000 | 397 | 19.85 % |
| adversarial-low-tail | 28,000 | 15,242 | 54.44 % |
| **REALISTIC total** | **140,000** | **69,721** | **49.80 %** |

| family | n | rejected | loss |
|---|---:|---:|---:|
| twitter-bearer-token | 17,604 | 15,304 | 86.93 % |
| jfrog-token | 18,117 | 11,888 | 65.62 % |
| facebook-access-token | 15,709 | 10,276 | 65.41 % |
| github-fine-grained-pat | 18,072 | 8,562 | 47.38 % |
| pypi-token | 17,476 | 8,273 | 47.34 % |
| square-access-token | 18,346 | 8,153 | 44.44 % |
| intercom-token | 17,413 | 4,754 | 27.30 % |
| square-untouched-branch | 2,000 | 397 | 19.85 % |
| atlassian-api-token | 15,263 | 2,114 | 13.85 % |

The pattern follows the alphabets: base62 families (52 letters / 62
symbols, expected alpha_frac 0.839) sit *above* the threshold on average;
prefixed families are pushed higher still (Twitter's 21 forced `A`s);
Atlassian's four non-letter symbols pull it lowest. Reference: N7a and N7b
on this same corpus, 0 / 140,000.

## What this establishes

- **This candidate is not shippable.** Alphabetic density does not separate
  word-built identifiers from letter-dense token encodings; the axis measures
  both. No threshold resolves it — 0.83 halves recall, and the identifier
  class clusters at 0.86–1.0, so raising the threshold forfeits the coverage
  that motivated the predicate.
- **The identifier class is not an under-triggering of N7.** Exact N7a/N7b
  reconstructions match 0 of 279 surviving findings.
- **Entropy is the wrong axis** for this class (FP 4.50 vs TP 4.90 bits/char,
  wrong direction) — which is why `generic-high-entropy` is the noise source.

## What this does NOT establish

- It does **not** prove that no value-structure predicate can ever separate
  this class. The search spent substantial degrees of freedom (threshold
  sweeps, singles, pairs, hit-set grouping) and found no other candidate worth
  freezing, but that is absence of a found candidate, not proof of
  impossibility.
- The 14 observed TPs are committed fixture material from one repository and
  one encoding; the benchmark corpus is exploratory and Kubernetes-dominated.

## Where the distinguishing information actually is

Not in the string. 85 of the 111 identifier FPs sit in
`api/openapi-spec/`; 70 % of all generic-high-entropy FPs sit in
fixture-like paths. What separates `watchAppsV1NamespacedControllerRevisionList`
from a credential is *where it lives* — an OpenAPI catalogue, a `kind:` field,
a manifest — i.e. context and file format, not value shape. That is the same
territory N8 (key-name context) reached for and parked for unmeasurable
recall. Any future attempt on this class should start from path/format
scope, framed as a disclosure decision, not from another value heuristic.

## Reproduce

```
# features + search (see bench/precision/ for the pinned collection; characterize_ghe.py + predicate_search.py live in the benchmark scratch dir)
python3 characterize_ghe.py --triage triage.csv --results secretloop_benchmarks/results --out ghe_features.csv
python3 predicate_search.py --features ghe_features.csv
# gate: insert bench/n9-emit.ts.snippet before the scoring section of a COPY of
# bench/entropy-vetoes.ts, run it, then judge the emitted features
python3 bench/n9_gate.py n9_gate_features.tsv
```
