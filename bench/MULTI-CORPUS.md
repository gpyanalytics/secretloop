# Multi-corpus false-positive benchmark

A false-positive-rate measurement over fourteen widely-used open-source SDKs and
frameworks. It answers one question and only one: **how much noise does
SecretLoop produce per thousand lines of ordinary code that contains no
secrets?**

Every number here is an aggregate across the whole corpus. No finding count is
attributed to any individual project, and no credential value appears anywhere
in this document. See *What this document may not be used to claim* below --
those rules are part of the method, not a disclaimer bolted onto it.

## Headline

**Benchmarked against 14 popular open-source SDKs (~33.9 M lines of code):
aggregate false-positive rate 0.296 per KLOC.**

With the generic entropy tier turned off -- `entropyPassEnabled: false`, the
named-provider rules alone -- the rate is **0.0039 per KLOC, about one false
positive per 254,000 lines.**

| | |
|---|---|
| Repositories | 14 |
| Files scanned | 148,284 |
| Lines of code (code-only denominator) | 33,854,709 |
| Total findings | 10,029 |
| False positives | 10,025 |
| **Aggregate FP rate** | **0.296 per KLOC** |
| — named-provider rules | 0.0039 per KLOC (133 findings) |
| — generic entropy tier | 0.292 per KLOC (9,892 findings) |

**99% of the noise is the generic entropy tier.** That is the tier
`entropyPassEnabled` exists to switch off, and this is the measurement that
tells you what switching it off costs you in noise and what it saves you in
attention.

## Method

- SecretLoop v0.1.1, **default configuration**, working-tree scan only.
- **Offline.** No `--verify`, no network egress, no credential ever transmitted
  to any provider. Detection is a pure function of the bytes on disk.
- Shallow clones pinned to the commits in *Corpus* below; read-only throughout.
- Reports written outside each scanned tree, so no scan is ever its own input.
- Every value in every report is redacted by SecretLoop's default masking.

### The denominator, stated

"Per KLOC" means nothing unless you say which lines. Two of these repositories
are generated-client monorepos whose `.json` API definitions run to millions of
lines; counting them would inflate the denominator and flatter the result.

- **Code-only (used above): 33,854,709 lines** — source extensions only,
  excluding `.json`, `.md`, `.txt`, `.xml`, `.html`.
- All-text, including those files: 45,754,436 lines, which yields the more
  favourable **0.219 per KLOC**.

The conservative figure is the headline. Both are given so the choice is
visible rather than convenient.

### Ground truth, and its limits

These repositories are treated as containing no live credentials, so every
finding counts against precision. That assumption is the benchmark's main
weakness and it is not free: SecretLoop's own named-rule hits were reviewed by
hand, and 133 of 137 were documentation examples in generated SDK comments,
committed test certificates, `.env.example` files, local-development
`docker-compose` defaults, and in one case a TypeScript type name long enough to
match a secret-shaped pattern.

The remaining four were not false positives and are **not described here**. They
were recorded privately for responsible disclosure to the projects concerned.
This document reports them only as a number, which is the honest way to report
something you have decided not to publish.

**Recall is not measured.** Nothing was planted, so this says how quiet
SecretLoop is, not how much it finds. `bench/BASELINE.md` measures recall
against a labelled corpus; the two are complementary and neither substitutes for
the other.

## Corpus

Listed as a dataset, in the way a paper lists one. Inclusion means a repository
was scanned. It does not mean the project uses SecretLoop, endorses it, or was
consulted.

| repository | commit |
|---|---|
| `aws/aws-sdk-js-v3` | `e53a25aafbdd` |
| `stripe/stripe-node` | `6592470f1c70` |
| `stripe/stripe-js` | `8daa6fad5d31` |
| `googleapis/google-cloud-node` | `c5fea74ac47b` |
| `supabase/supabase-js` | `b3b939a405ae` |
| `langchain-ai/langchainjs` | `ffadf8515774` |
| `openai/openai-node` | `eea2292a4a52` |
| `anthropics/anthropic-sdk-typescript` | `7f3898c525b1` |
| `vercel/ai` | `1c6854096fbe` |
| `facebook/react-native` | `c6b137cac9fe` |
| `expo/expo` | `f1882313ed84` |
| `flutter/flutter` | `634d370c3ab2` |
| `getsentry/sentry-javascript` | `fade8e2ddd3d` |
| `open-telemetry/opentelemetry-js` | `b85eb28343ff` |

## What this document may not be used to claim

These are prohibitions on the marketing use of this data, and they bind whoever
quotes it.

**Allowed**

- "Benchmarked against 14 popular open-source SDKs (~33.9 M LOC): aggregate
  false-positive rate 0.296 per KLOC."
- Listing the repository names and commits above as the corpus, methodology-style.

**Forbidden**

- "Validated by \<company\>", "\<company\> uses SecretLoop", or any wording
  implying a relationship, endorsement, or evaluation by any project listed.
- Any finding count placed next to a single company's or project's name, or any
  framing of these results as a statement about one project's security posture.
  The per-repository counts exist in the raw data and are deliberately **not**
  published here, for exactly this reason.
- Any real credential value, masked or otherwise.
- Any implication that a possible-real finding was published, or any hint as to
  which project it concerned.

A false-positive benchmark measures the scanner. It does not measure the
projects, and it must never be presented as if it did.
