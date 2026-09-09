# SecretLoop — benchmark results

Detailed evidence for the numbers quoted in [README.md](../../README.md) and
summarised in [benchmarks](../benchmarks.md). Moved here from the repository
root (`RESULTS.md`) unchanged. This page is
the measurement record, not a summary of it.

Measured at SecretLoop `2cd94c3111ae14346d731fc5146c135e2101f3b0`, the merge that
added file-level PKCS#12 detection.

> **Mode.** Unless explicitly identified in the 0.4.0 default-mode section
> below, the historical SecretLoop numbers on this page were measured with the
> generic high-entropy tier **enabled**. That was the shipped default for those
> measurements. Beginning with 0.4.0, the tier is off by default and enabled
> with `--include-entropy`. The historical rows remain unchanged and exactly
> reproducible — see
> [0.4.0 default mode](#040-default-mode-entropy-tier-off) for the new default
> on the same frozen corpus.

> This is one frozen benchmark on six repositories. It is not a general
> statement about any tool, and it does not measure recall.

## Methodology

Six pinned open-source repositories, scanned as a working tree only — no git
history, no verification, no network — with each tool at its own defaults, and
one human triage policy applied identically to all three.

| Repository | Pinned commit |
| --- | --- |
| `psf/requests` | `dae7ef63b4df6eded86637f251fc4e3a06c3b479` |
| `expressjs/express` | `023767fe9872e029271df1418f73401bff20ff40` |
| `pallets/flask` | `d318b683471101618febed18996405ad26462110` |
| `axios/axios` | `b8d67bbbd6b381e1f4b1887e32686fcc89c5b0a8` |
| `denoland/deno` | `83bb8d5780505d0b4f30c089680ce98b0e7a4770` |
| `kubernetes/kubernetes` | `b2ec8b6fefac451a2dedafc4dd71f2f16c7a6abe` |

Tools: SecretLoop at the SHA above, Gitleaks 8.30.1, TruffleHog 3.97.4.

Findings are compared in a **common scope**: the population is restricted to
what SecretLoop's default scan actually reads, applied tool-neutrally. That
removes archive interiors, paths under SecretLoop's default exclusions such as
`vendor/`, and files over its size limit — 102 rows in total, every one of them
a false positive or an unresolved finding. No true positive was removed by the
restriction.

Verdicts follow one written triage policy fixed before scoring. A committed test
credential is a true positive if it is a real credential shape; a literal
placeholder is a false positive; a private key block is a true positive even as
a fixture; `UNKNOWN` is preserved rather than forced to a verdict.

## Precision, per finding

| Tool | TP / FP / UNKNOWN | Precision |
| --- | --- | --- |
| SecretLoop (entropy enabled) | 181 / 299 / 0 | 37.7% |
| Gitleaks | 181 / 255 / 0 | 41.5% |
| TruffleHog | 158 / 97 / 21 | 57.25–64.86% |

**Why TruffleHog is a range.** 21 of its findings could not be resolved to a
verdict from the evidence available — most report a location where no candidate
can be identified without the raw value, which this study does not retain. The
scorer therefore reports a band: the pessimistic bound counts every unresolved
finding as a false positive (57.25%), the optimistic bound counts every one as a
true positive (64.86%). The midpoint is not a measurement and is not published.

SecretLoop and Gitleaks have no unresolved findings, so their figures are point
estimates.

## Coverage, per secret-bearing file

| Tool | TP-file coverage | TP files missed |
| --- | --- | --- |
| Gitleaks | 100.0% (145/145) | 0 |
| SecretLoop (entropy enabled) | 97.9% (142/145) | 3 |
| TruffleHog | 82.1% (119/145) | 26 |

**This is not exhaustive recall.** The denominator is the union of files in
which *any* of the three tools reported a finding a human then validated as a
true positive — 145 files. Nothing was planted in these repositories, so a
credential that all three tools missed leaves no trace here and is absent from
the denominator entirely.

SecretLoop's three missed files are all in `kubernetes`, all found by Gitleaks'
generic tier, and all committed test fixtures: a kubeadm certificate key, a
kubeadm bootstrap token, and an encryption-config symmetric key.

A per-line comparison shows a larger apparent gap, but most of it is attribution
rather than detection: where a PEM block spans many lines, tools anchor the
finding at different lines of the same block. That difference is not 28 missed
secrets, and is not reported as one.

## What PKCS#12 detection changed

File-level PKCS#12 keystore detection added **8 true positives and 0 false
positives** — eight `.pfx` containers in `denoland/deno` holding a private key,
which no text-based rule could reach because the containers are binary DER.

Precision moved from 173/472 = 36.7% to 181/480 = 37.7%.

## Where SecretLoop's false positives come from

| Rule | FPs |
| --- | --- |
| `generic-high-entropy` | 279 |
| `generic-api-key-assignment` | 17 |
| `db-connection-string` | 2 |
| `private-key-block` | 1 |

`generic-high-entropy` remains the dominant false-positive source. The N9 study
produced no shippable suppression candidate under its frozen methodology; it did
not establish that the class is inherently unfixable. A later study of
format-scoped suppression was rejected on its own evidence and is not planned
work.

Removing every false positive outside `generic-high-entropy` — all 20, perfectly
— would reach 39.4%. Any material improvement has to come from that tier.

## 0.4.0 default mode (entropy tier off)

Measured 2026-09-08 at SecretLoop `fd013706d31a3b21a9c80d8a991ea14ff54b66e7`,
the merge that made the generic high-entropy tier opt-in. Same six pinned
repositories, same protocol, same frozen labels, same 145-site validated
universe. Benchmark-workspace freeze record:
`entropy-default-freeze-fd01370.md`.

| Mode | TP / FP / UNKNOWN | Precision | TP-file coverage |
| --- | --- | --- | --- |
| Entropy enabled (`--include-entropy`) | 181 / 299 / 0 | 37.7% | 97.9% (142/145) |
| **0.4.0 default** | **167 / 20 / 0** | **89.3%** | **94.5% (137/145)** |

**`--include-entropy` reproduces the historical result byte-for-byte.** All six
report JSON files are identical, hash for hash, to the frozen
`2cd94c3` / `d7320cb` reports — not equivalent, the same bytes. Every row
elsewhere on this page therefore remains exactly reproducible on demand.

**The measured cost of the default.** It removes 293 findings from this corpus:
279 false positives **and 14 validated true positives**, in 5 additional
validated sites. Those 14 are all `generic-high-entropy` in Kubernetes AES
encryption-config test data — base64 key material that matches no provider
format, so no named rule reaches it:

| file | lines |
| --- | --- |
| `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation_encryption_test.go` | 61, 89, 95, 108, 114, 129 |
| `.../encryptionconfig/testdata/valid-configs/aes/aes-cbc-multiple-keys.json` | 15, 19 |
| `.../encryptionconfig/testdata/valid-configs/aes/aes-cbc-multiple-keys-reversed.json` | 15, 19 |
| `.../encryptionconfig/testdata/valid-configs/aes/aes-cbc-multiple-providers.json` | 15, 25 |
| `.../encryptionconfig/testdata/valid-configs/aes/aes-cbc-multiple-providers-reversed.json` | 15, 25 |

The three pre-existing SecretLoop misses (`join_test.go`, `staticpods_test.go`,
`transformation_test.go`) are unchanged by this and are not part of the five.
Total missed under the new default: 8 = 3 prior + 5 new.

Nothing else moved. All 293 removals are `generic-high-entropy`; non-generic
removals, additions and surviving-finding changes are all zero, the non-entropy
population is identical across both modes at 187 findings, and all 8 PKCS#12
true positives are retained.

Neither mode is better in general. Higher precision here is bought with lower
coverage on the same population, and the number that would settle the trade —
how much recall the entropy tier uniquely contributes over rule-based
scanning — is still not measured by this study or by N9.

## Scope and limitations

- **Six repositories, one point in time.** One of them dominates the corpus by
  volume, and the language mix is not representative of software generally.
- **Every true positive found here is a committed test fixture.** On a "would a
  user act on this?" reading, all three tools score near zero on this corpus,
  and the precision figures rest on counting fixture credentials as true
  positives.
- **Recall is not measured** and cannot be inferred from this page.
- **GitHub Secret Scanning and GitGuardian were not benchmarked.** No precision
  or coverage figure on this page or in the README is attributed to them.
- **TruffleHog's verdicts** were re-established independently from the pinned
  repository content, without using raw credential material. That is enough to
  compare and to find gaps; it is a single study, not a general result.
- Known detector scope limits: no general archive-member traversal, no general
  recursive base64/hex/URL decoding, and some PKCS#12 shapes remain opaque by
  design — outer `signedData`, inner `envelopedData`, and nested
  `safeContents`. These are scope statements, not statements that those
  locations are empty.

## Evidence artifacts

The measurement artifacts are kept outside this repository, unmodified. The
figures above were re-derived from them rather than copied from an earlier
write-up.

From the merge-SHA re-benchmark:

| Artifact | SHA-256 |
| --- | --- |
| triage, 480 rows | `d79e1e9c0dcdf4a10a416ce05f5f9dbe9ca15c3411e321269e3c70a1191b065b` |
| result record | `5f7919c74d5d6e5db519d25061e82a923af1b87d2562806377c1504cbcf24bc1` |

From the three-tool study:

| Artifact | SHA-256 |
| --- | --- |
| protocol | `62ba93617be60a46516e893bce8e87e007abfc23af6fd494bd130f4e39d8f38d` |
| comparison population | `32b304f1138f9fac9788326e29305f1ec4e4c4194bf115f7002695cbd315539c` |
| TruffleHog clean triage | `f05f5aa94dd1b09c2ba73a607c87f4ad77e9e77a09db0206fecb886ded7bf007` |
| common-scope population | `7da4109a72dc0a3d858fc25b0871680a29b58f42c4e4df2d3947323244dea152` |

An earlier and unrelated study, [the 0.1.2 multi-repository study](0.1.2-multi-repo-study.md), counts
findings across a different repository set at 0.1.2. It does not measure
precision and is not the source of any number on this page.
