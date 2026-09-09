# Benchmarks

Every number SecretLoop publishes comes from a frozen, reproducible record, and
each record measures one population. This page keeps those populations apart:
mixing a precision figure from one with a coverage figure from another is how a
benchmark starts saying more than it measured.

**Recall is not measured by any study here.** Nothing was planted in the
six-repository corpus, so a credential every tool missed leaves no trace.

## 1. The frozen six-repository comparison (published 0.4.0)

The authoritative record is [six-repository results](benchmarks/six-repository-results.md).
Six pinned open-source repositories (`psf/requests`, `expressjs/express`,
`pallets/flask`, `axios/axios`, `denoland/deno`, `kubernetes/kubernetes`),
working tree only, verification off for every tool, one written triage policy
applied identically to SecretLoop `2cd94c3`, Gitleaks 8.30.1 and TruffleHog
3.97.4, in a common scope restricted to what SecretLoop's default scan reads.

| tool | TP / FP / unknown | precision | TP-file coverage |
|---|---|---|---|
| SecretLoop, entropy tier enabled | 181 / 299 / 0 | 37.7% | 97.9% (142/145) |
| Gitleaks | 181 / 255 / 0 | 41.5% | 100.0% (145/145) |
| TruffleHog | 158 / 97 / 21 | 57.25–64.86% | 82.1% (119/145) |

TruffleHog's precision is a range because 21 findings could not be resolved to
a verdict; the midpoint is not published. **TP-file coverage** is the share of
the 145 files in which any tool reported a human-validated true positive; it is
not recall. Every true positive in this corpus is a committed test fixture.

SecretLoop's column was measured with the generic entropy tier **enabled**, the
default at the time. 279 of its 299 false positives came from that tier; it
also contributed 14 validated true positives across 5 sites.

## 2. The 0.4.0 default (entropy tier off) — same corpus, same labels

Measured at `fd013706`, the merge that made the tier opt-in
(`entropy-default-freeze-fd01370.md` in the benchmark workspace):

| mode | TP / FP / unknown | precision | TP-file coverage |
|---|---|---|---|
| `--include-entropy` | 181 / 299 / 0 | 37.7% | 97.9% (142/145) |
| **0.4.0 default** | **167 / 20 / 0** | **89.3%** | **94.5% (137/145)** |

`--include-entropy` reproduces the historical reports byte for byte. The
default removes 293 findings: 279 false positives **and 14 validated true
positives** in 5 sites, all `generic-high-entropy` on Kubernetes AES
encryption-config test data. Neither mode is better in general; the number that
would settle the trade — the recall the tier uniquely adds over rule-based
scanning — is not measured.

## 3. Changes in 0.5.0 since 0.4.0, same corpus

Each change was measured against the frozen reports with fail-closed comparison
checkers exercised on synthetic mutations before use. Populations are stated
separately: **FULL** counts every finding in the current scan; **HISTORICAL**
counts only identities present in the frozen labels; archive additions and the
one recall addition carry their own additive labels and never rewrite a frozen
one.

| change | default | `--include-entropy` | restore (`--include-api-document-entropy`) |
|---|---|---|---|
| Archive scanning (PR #44): 53 member findings added in `deno` tarballs (52 TP / 1 FP), all other findings identical | +53 | +53 | — |
| API-document entropy scope (PR #45): exactly the 101 predeclared entropy false positives removed, zero added, restore mode byte-identical to the pre-change reports | 0 | −101 FP | 0 |
| Archive coverage disclosure (PR #47): finding objects identical in all 18 repository-mode pairs; only the scope sentence and `summary.archives` changed | 0 | 0 | 0 |
| `encryption-key-assignment` (PR #48): one finding added, the validated `transformation_test.go` site in `kubernetes`; zero removals, zero changed survivors, fifteen non-kubernetes reports byte-identical | +1 TP | +1 TP | +1 TP |

Resulting populations in 0.5.0:

| mode | FULL TP / FP / unknown | HISTORICAL (frozen labels only) | HISTORICAL + additive recall label | TP-file coverage |
|---|---|---|---|---|
| default | 220 / 21 / 0 (241) | 167 / 20 / 0 (187) | 168 / 20 / 0 (188) | 138/145 |
| `--include-entropy` | 234 / 199 / 0 (433) | 181 / 198 / 0 (379) | 182 / 198 / 0 (380) | 143/145 |
| restore | 234 / 300 / 0 (534) | 181 / 299 / 0 (480) | 182 / 299 / 0 (481) | 143/145 |

Two of the three sites the entropy-enabled 0.4.0 scan missed remain missed: a
kubeadm certificate key (candidate parked) and a kubeadm bootstrap token
(candidate rejected on its own evidence). No additional false positive was
measured in any repository. The six repositories were the discovery corpus for
the new rule, so its yield there is in-sample; its independent validation is a
57-case synthetic corpus, which is not evidence of real-world generalization.

## 4. Older studies, kept for the record

- [0.1.2 multi-repository study](benchmarks/0.1.2-multi-repo-study.md) — raw,
  untriaged finding counts across twenty repositories. It measures nothing about
  precision or coverage and is not the source of any number above.
- [`bench/BASELINE.md`](../bench/BASELINE.md) — the seeded corpus A (50 planted
  secrets, 120 decoys, 10 history-only) and corpus B (false positives per KLOC
  on real code). Recall on planted shapes, not breadth.
- [`bench/MULTI-CORPUS.md`](../bench/MULTI-CORPUS.md) — false-positive rate per
  KLOC over fourteen SDKs at v0.1.1: 0.296 per KLOC overall, 0.0039 with the
  entropy tier off.
- [`bench/N9-ALPHA-FRAC.md`](../bench/N9-ALPHA-FRAC.md) — an entropy-suppression
  candidate rejected because it discarded 49.8% of realistic credentials.
- [`bench/precision/`](../bench/precision/README.md) — how the six-repository
  measurement is reproduced: pinned SHAs, scan scripts, the triage policy.

## 5. Capability comparison, from vendor documentation

Not measured — these rows are read from each tool's own current documentation,
and only the three-tool table in §1 was benchmarked. The root README links here
rather than repeating them.

| capability | Gitleaks | TruffleHog | GitHub | GitGuardian | SecretLoop |
|---|---|---|---|---|---|
| Runs without a hosted account | ✅ | ✅ | ❌ | ❌ | ✅ |
| Working-tree, pre-commit and full-history scan | ✅ | ✅ | hosted | hosted | ✅ |
| Validity check against the provider | ❌ | ✅ | ✅ | ✅ | ✅, consent-gated |
| SARIF output | ✅ | ✅ | — | — | ✅ |
| Baseline for existing findings | ✅ | not documented | — | — | ✅ |
| Fix applied in the editor | ❌ | ❌ | ❌ | ❌ | ✅ |
| MCP server for AI agents | ❌ | ❌ | ✅ | ✅ | ✅ |

| claim source | accessed |
|---|---|
| [Gitleaks README](https://github.com/gitleaks/gitleaks) — `git`/`dir`/`stdin` modes, pre-commit hook, `--baseline-path`, json/csv/junit/sarif reports | 2026-09-08 |
| [TruffleHog README](https://github.com/trufflesecurity/trufflehog) — programmatic verification against the API (`--no-verification` disables), git and filesystem sources, pre-commit hook, `--sarif` | 2026-09-08 |
| [GitHub — About secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning) — hosted, scans full history, validity checks contact the issuing service | 2026-09-08 |
| [GitHub — About push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection) — blocks pushes containing supported secrets | 2026-09-08 |
| [GitGuardian — Validity checks](https://docs.gitguardian.com/secrets-detection/customize-detection/validity-checks) — non-intrusive API calls; valid / invalid / failed to check / cannot check / unknown | 2026-09-08 |
| [GitGuardian — MCP server](https://docs.gitguardian.com/ggmcp-docs/overview) and [VS Code extension](https://docs.gitguardian.com/ggshield-docs/integrations/ide-integrations/vscode) | 2026-09-08 |

## Limitations

Six repositories, one point in time, one dominating by volume; every true
positive a committed fixture; recall unmeasured; GitHub Secret Scanning and
GitGuardian not benchmarked and no figure attributed to them. Detection is
offline in every study: no credential was ever verified against a provider.
