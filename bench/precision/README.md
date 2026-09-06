# Six-repository precision baseline

A head-to-head precision measurement against gitleaks on six pinned
open-source repositories, with every finding triaged by hand.

It answers one question: **of what each tool reports on ordinary code, how much
is actually a credential?** It does not measure recall, and cannot — nothing was
planted, so a secret both tools missed leaves no trace here. `bench/BASELINE.md`
measures recall against a labelled corpus; the two are complementary.

## Reproducing it

```bash
bash clone_pinned.sh     # six repos, each at the SHA in pins.txt
bash run_scans.sh        # both tools, same trees -> triage_seed.csv
cp ~/sl-precision/triage_seed.csv ~/sl-precision/triage.csv
#   fill verdict + reason for every row, per TRIAGE.md
python3 compute_precision.py ~/sl-precision/triage.csv
```

Everything lands in `$WORK` (default `~/sl-precision`), outside this repository
and outside every scanned tree, so no scan is ever its own input. The clones are
shallow at a fixed SHA — this is a working-tree measurement, and a full history
of kubernetes and deno costs gigabytes nothing reads.

**Unlike `docs/BENCHMARK.md`, this one is reproducible.** `pins.txt` carries the
commit each repository was measured at, written by the clone script rather than
typed by hand. That file existing is the point: the 20-repository study could
not be reproduced because its clones were deleted and no commit was recorded.

## Method

- SecretLoop v0.2.1, local build at commit `bb60fd8`; gitleaks 8.30.1.
- **Working tree only.** No history scan for either tool.
- **Offline.** No `--verify`, no network egress, no value transmitted anywhere.
- Both tools at default rule sets and default configuration.
- One scope normalisation: `.git/` is excluded from gitleaks by generated
  config, because `gitleaks dir` would otherwise read an object store that
  SecretLoop's working-tree scan never looks at.
- Triage rules were fixed in writing *before* triage started — see `TRIAGE.md`.

### Corpus

| repository | commit |
|---|---|
| psf/requests | `dae7ef63b4df` |
| expressjs/express | `023767fe9872` |
| pallets/flask | `d318b6834711` |
| axios/axios | `b8d67bbbd6b3` |
| denoland/deno | `83bb8d578050` |
| kubernetes/kubernetes | `b2ec8b6fefac` |

Inclusion means a repository was scanned. It does not mean the project uses
SecretLoop, endorses it, or was consulted.

## Result

918 findings, all triaged, no UNKNOWN.

| tool | found | TP | FP | precision |
|---|---|---|---|---|
| gitleaks | 438 | 181 | 257 | **0.413** |
| SecretLoop | 480 | 173 | 307 | **0.360** |

Per repository, precision (findings in brackets):

| repository | gitleaks | SecretLoop |
|---|---|---|
| requests | 1.000 (4) | 0.800 (5) |
| express | — (0) | — (0) |
| flask | 0.000 (6) | 0.000 (6) |
| axios | 1.000 (1) | 0.143 (7) |
| deno | 0.522 (69) | 0.318 (88) |
| kubernetes | 0.391 (358) | 0.374 (374) |

**gitleaks is ahead on this corpus.** 0.413 against 0.360 — close, both poor in
absolute terms, and the gap is one this repository should own rather than
explain away. It comes almost entirely from the generic tiers: 91% of
SecretLoop's false positives are `generic-high-entropy` and 95% of gitleaks'
are `generic-api-key`. The named provider rules on both sides are quiet.

### The number that matters more

**Every true positive in all six repositories is a committed test fixture.**
324 PEM private keys, 27 symmetric keys in encryption-config fixtures, 3 test
tokens. Not one live-shaped credential outside a fixture, from either tool.

Read that way — counting a fixture as noise, which is what a user triaging their
own repository does — **both tools score 0.000**, and the honest summary of this
baseline is that 918 findings produced nothing anyone would act on.

The 0.413 / 0.360 headline depends entirely on the pre-registered rule that a
private key block is a true positive even when it is a fixture. That rule was
written down before triage and is defensible — key material committed to a
public repository is a credential — but it is doing all the work, and a
precision number that turns on one classification call should say so.

### Where the noise comes from

SecretLoop's 307 false positives, by class:

| class | n |
|---|---|
| long identifier or type name | 123 |
| literal placeholder | 32 |
| digest or checksum | 26 |
| path or resource identifier | 22 |
| key identifier, not a credential | 22 |
| documentation example | 21 |
| mime type | 16 |
| generated resource name | 10 |
| everything else | 35 |

The largest class is not credential-shaped at all. `"operationId":
"createAuthorizationV1NamespacedLocalSubjectAccessReview"` is a long camelCase
identifier in an OpenAPI spec; 85 of them come from `api/openapi-spec/v3` alone.
`generic-high-entropy` has no gate that would tell an identifier from a token.

gitleaks' 257 split differently — 163 literal placeholders (`abcdef.0123456789abcdef`,
base64 of `secret is secure`, `dXNlcjpwYXNzd29yZA==`) against 41 identifiers.
It is noisier about hand-written fake credentials; SecretLoop is noisier about
ordinary long strings.

Two specific SecretLoop misfires worth recording:

- `onepassword-service-account` fired once on the filename
  `ops_sanitizer_multiple_timeout_tests_no_trace.out`. A named provider rule
  matching a `.out` filename is a rule defect, not a tuning question.
- `http-basic-auth-url` fired on four translations of the same axios
  documentation paragraph *about* basic auth. One prose sentence, four
  languages, four findings.

### Agreement

| | n |
|---|---|
| both tools, same file and line | 169 |
| gitleaks only | 12 |
| SecretLoop only | 4 |

The tools mostly find the same key material. The precision gap is not about
what they detect — it is about what else they report alongside it.

## What this may not be used to claim

- **Not a recall measurement.** Nothing was planted. A credential both tools
  missed is invisible here, and no statement about detection coverage follows
  from this file.
- **Not "these repositories contain no secrets."** They are treated as
  containing none; that is an assumption, not an audit.
- **Not comparable to `bench/MULTI-CORPUS.md`.** That measures false positives
  per KLOC on a different corpus with a different denominator. Different
  question, different number.
- **Not a general claim about gitleaks.** Six repositories, one of which
  (kubernetes) supplies 80% of the findings, is a narrow corpus. The
  kubernetes-heavy weighting is visible in the per-repository table and should
  stay visible in any summary.
- **Not per-repository attribution of any credential.** No value from any
  finding appears in this document, in `triage.csv`, or in the seed. The seed
  carries a masked value and a scrubbed snippet; the real line stays in the
  pinned checkout.
