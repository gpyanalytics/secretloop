# SecretLoop 0.1.2 — Public Multi-Repo Benchmark

**Status: working document. UNCOMMITTED. Not part of the 0.1.2 release.**

Measured 30–31 August 2026 against SecretLoop 0.1.2 at commit `16f02d8`.
Everything here is input to a possible 0.1.3. **Nothing in this study changed
0.1.2**, and nothing in it should.

---

## Methodology

### Repositories and languages

Twenty public repositories, nine language groups. All twenty were attempted and
all twenty were measured. No repository was substituted.

| language | repositories |
|---|---|
| Python | `django/django`, `pallets/flask`, `psf/requests` |
| Go | `kubernetes/kubernetes`, `hashicorp/terraform`, `gin-gonic/gin` |
| Rust | `rust-lang/cargo`, `tokio-rs/tokio` |
| Java | `spring-projects/spring-boot`, `elastic/elasticsearch` |
| JS/TS | `facebook/react`, `nestjs/nest`, `expressjs/express` |
| Ruby | `rails/rails` |
| C/C++ | `curl/curl`, `redis/redis` |
| PHP | `laravel/laravel` |
| C# | `dotnet/runtime` |
| Mixed / config-heavy | `ansible/ansible`, `docker/compose` |

Repositories were scanned smallest-first so results banked before the giants.

### Tool versions and exact commands

| tool | version | tree / filesystem | history / git |
|---|---|---|---|
| SecretLoop | 0.1.2 (`16f02d8`, local build) | `secretloop scan --path . --format json --fail-on never` | `secretloop history --path . --format json --fail-on never` |
| gitleaks | 8.30.1 | `gitleaks dir . --report-format json --report-path <outside-repo>` | `gitleaks git . --report-format json --report-path <outside-repo>` |
| TruffleHog | 3.97.1 | `trufflehog filesystem . --no-verification --json` | `trufflehog git file://. --no-verification --json` |

Environment: macOS (darwin 25.6.0), Node 24.19.0, git 2.50.1.

### Verification disabled

**No credential verification was run by any tool, against any repository.**
SecretLoop was never given `--verify`. TruffleHog ran `--no-verification` in
both modes. gitleaks ran in its default non-verifying mode. No network request
was made against any discovered value by any tool at any point.

### Tree vs history methodology

Tree scans read the checked-out working tree at the default branch. History
scans walk commit history. The two are reported separately throughout and are
never summed into a single headline number, because a value present in both is
counted by both.

Counts are **raw finding counts** — not deduplicated by value, not triaged. One
credential repeated across forty files counts forty times in every tool.

**Report files were always written outside the repository being scanned.** This
is not incidental. A first attempt wrote one tool's JSON report into the working
tree, and SecretLoop then reported "credentials" inside another scanner's output
— the same "a scan output should never be a scan input" failure the 0.1.1
changelog records. Every number below was produced with reports written
elsewhere.

### Bounded and skipped history methodology

Three repositories exceeded 1 GB: `kubernetes/kubernetes`, `dotnet/runtime`,
`elastic/elasticsearch`. Rather than skip their history, each tool's **actual
installed `--help` output was inspected** for a supported bounded-history
option. All three have one:

| tool | bounded-history flag (verified in `--help`) | used |
|---|---|---|
| SecretLoop | `--max-commits <n>` | `--max-commits 1000` |
| gitleaks | `--log-opts string` (git log options) | `--log-opts "-n 1000"` |
| TruffleHog | `--max-depth=MAX-DEPTH` | `--max-depth=1000` |

Those three repositories were re-cloned at `--depth 1000` and scanned with the
bound above. **Their history rows are labelled "bounded — last 1000 commits"
and must never be read as full history.** Their tree scans are complete and
unbounded.

One caveat on comparability: each tool interprets its own bound. gitleaks
`-n 1000` bounds the `git log` walk, TruffleHog `--max-depth` bounds commit
depth, and SecretLoop `--max-commits` bounds the commits it enumerates. The
three bounded sets are close but not guaranteed identical, so bounded rows are
best compared within a tool rather than across tools.

**No history measurement was skipped, and no bounded scan is reported as full.**

### Safety rules observed

- No third-party repository was modified, committed to, branched, pushed, or
  authenticated against. Every clone was read, scanned, then deleted.
- No credential verification, decoding, or testing of any discovered value.
- **No raw credential value appears in this document.** SecretLoop scans ran
  *without* `--no-redact`, so the JSON reports themselves hold only masked
  values (first and last four characters).

### Limitations

- **No ground-truth corpus exists for these repositories.** See *Honest
  Summary*.
- Three history results are bounded, not full.
- Counts are raw, undeduplicated and untriaged.
- **Structural classification is coarse by design**, because values were kept
  masked. Families identified from a masked prefix plus a path and extension are
  inferences, not certainties; anything needing the full value is left
  unclassified rather than guessed.
- Single run, single machine, single point in time. No repeated runs, no
  variance measurement. Default branches move.
- All three tools ran with default configuration. Each ships different defaults
  about what is worth reporting.
- One harness fault required re-cloning and re-measuring `ansible` and `django`
  for gitleaks and TruffleHog; those numbers come from a second clone the same
  day.
- `nestjs/nest` TruffleHog git (1,766) was not investigated.

---

## Results

`SL` = SecretLoop, `GL` = gitleaks, `TH` = TruffleHog. TH "tree" is its
`filesystem` mode. Bounded rows are labelled explicitly.

| repo | language | SL tree | SL history | GL tree | GL history | TH tree | TH history | history status |
|---|---|---|---|---|---|---|---|---|
| pallets/flask | Python | 6 | 3 | 6 | 12 | 0 | 0 | full |
| psf/requests | Python | 6 | 13 | 4 | 13 | 34 | 53 | full |
| gin-gonic/gin | Go | 3 | 5 | 4 | 6 | 1 | 3 | full |
| tokio-rs/tokio | Rust | 0 | 9 | 0 | 0 | 0 | 0 | full |
| expressjs/express | JS/TS | 0 | 1 | 0 | 0 | 0 | 1 | full |
| nestjs/nest | JS/TS | 2 | 2 | 20 | 20 | 3 | 1766 | full |
| curl/curl | C | 27 | 130 | 9 | 57 | 54 | 198 | full |
| redis/redis | C | 8 | 13 | 0 | 0 | 0 | 0 | full |
| laravel/laravel | PHP | 0 | 10 | 0 | 1 | 0 | 0 | full |
| docker/compose | Go (config-heavy) | 4 | 20 | 7 | 18 | 2 | 10 | full |
| rust-lang/cargo | Rust | 11 | 51 | 1 | 36 | 0 | 15 | full |
| django/django | Python | 21 | 125 | 8 | 25 | 21 | 80 | full |
| rails/rails | Ruby | 59 | 299 | 27 | 120 | 10 | 69 | full |
| hashicorp/terraform | Go | 158 | 612 | 93 | 292 | 11 | 177 | full |
| ansible/ansible | Python (config-heavy) | 53 | 505 | 5 | 526 | 23 | 213 | full |
| facebook/react | JS/TS | 39 | 16273 | 4 | 205 | 5 | 74 | full |
| spring-projects/spring-boot | Java | 324 | 699 | 201 | 239 | 220 | 533 | full |
| elastic/elasticsearch | Java | 1209 | 108 | 476 | 0 | 321 | 0 | **bounded — last 1000 commits** |
| dotnet/runtime | C# | 8095 | 2937 | 274 | 274 | 180 | 146 | **bounded — last 1000 commits** |
| kubernetes/kubernetes | Go | 446 | 77 | 358 | 4 | 155 | 0 | **bounded — last 1000 commits** |

**Coverage:** 20 attempted · 20 completed · 0 partial · 0 skipped · 3 with
bounded history.

---

## SecretLoop Rule / Tier Breakdown

Across all repositories and both modes (full-history rows plus bounded rows):

| count | rule | tier |
|---|---|---|
| 20,019 | `generic-high-entropy` | entropy |
| 7,138 | `twitter-bearer-token` | format-match |
| 1,042 | `private-key-block` | format-match |
| 770 | `generic-api-key-assignment` | format-match |
| 90 | `db-connection-string` | format-match |
| 89 | `bcrypt-hash` | format-match |
| 65 | `http-basic-auth-url` | format-match |
| 6 | `aws-access-key` | format-match |
| 5 | `square-access-token` | format-match |
| 5 | `jwt` | format-match |

### Entropy vs format-match behaviour

Both tiers are dominated by a small number of repositories, and a combined
total is close to meaningless without saying so.

**Entropy tier.** `facebook/react` alone supplies 16,307 of the entropy
findings — 81% of the tier — and 89% of those come from one artifact family
(*Committed browser-profile data*, below). Excluding react, the entropy tier
produced roughly 3,700 findings across 19 repositories, a median of about 39
each. Four repositories produced zero entropy findings in tree mode
(`tokio`, `express`, `laravel`, `flask`); all four are small, modern, and carry
little vendored or generated content.

**Format-match tier.** `dotnet/runtime` supplies 7,250 of them, and 7,129 of
those are a single misfiring rule. Excluding that rule, the format-match tier
produced roughly 2,100 findings across 20 repositories.

**Neither number is a quality signal.** Entropy-tier volume tracks how much
generated, vendored and fixture content a repository carries. A *format-match*
spike is the more interesting signal: as `dotnet/runtime` shows, it is more
likely to indicate a rule defect than a cluster of credentials.

---

## False-Positive Families

Classified from paths, extensions and masked prefixes only. Where the evidence
does not support calling something a false positive, it is called *likely noise*
or *requires triage* instead.

### Previously known families (addressed in 0.1.1 / 0.1.2)

These were the targets of the 0.1.2 entropy work, measured then against
JS/ObjC corpora: mangled C++ symbols, leading-underscore C/ObjC symbols, source
filenames and `#import` targets, absolute paths with doubled slashes or `+`
segments, dotted identifier chains, `NAME=value` build settings, Xcode scheme
target names, and (from 0.1.1) URLs, relative paths, lockfiles and generated
Xcode files.

**Finding: they did not reappear at scale.** Across nine languages that were not
part of the corpus 0.1.2 was tuned against, the residual entropy noise
attributable to these shapes is small — roughly 175 findings classified as
source-code string literals, 53 in config/lockfile syntax, 47 in documentation.
This is the study's main positive result for 0.1.2.

### NEW families found by this study

#### N1 — `twitter-bearer-token` matches homogeneous character runs

**Language:** C# · **Tier:** format-match · **Count:** 7,129 tree + 2,051
bounded history, from **five files** · **Classification: false positive
(confident).**

**Structural description.** The rule requires a fixed twenty-one-character `A`
prefix followed by fifty or more characters drawn from a class that *includes
`A` itself*. Any run of 71 or more `A` characters therefore matches. Every
masked value in this family is the same length, indicating one uniform shape.

**Paths:** `src/tests/Loader/classloader/v1/M10/Acceptance/Case1.cool` (and
`Case2`–`Case4`), `src/libraries/System.Reflection.MetadataLoadContext/tests/src/TestUtils/TestData.cs`.
`.cool` is IL-assembly loader test input containing long padding runs.

**Could a real credential share this shape?** A genuine bearer token has varied
base64 after the fixed prefix. A homogeneous run of one character is not a
token.

**0.1.3 candidate: yes — highest priority.** A `severity: high` named rule
firing 9,180 times on padding data is the loudest possible way to train users to
ignore alerts.

#### N2 — Hash-manifest JSON in committed browser-profile data

**Language:** JS/TS (artifact, not language-specific) · **Tier:** entropy ·
**Count:** 14,443 of react's 16,273 history findings (89%) · **Classification:
likely noise — but see caveat.**

**Structural description.** Chrome extension integrity manifests
(`computed_hashes.json`, `verified_contents.json`) are arrays of block digests —
definitionally hashes. All 14,443 sit under `temp/chrome/…` and `tmp/chrome/…`,
a browser profile directory committed to react's history at some point and
later removed. 7,426 distinct masked values. A further ~1,000 come from
`Local State`, the profile's config file.

**Could a real credential share this shape?** A browser profile is precisely
where live credentials live, so this family must **not** be suppressed by path
or by shape. The tractable observation is narrower: these are findings in a
directory that no longer exists in the working tree.

**0.1.3 candidate: presentation only.** Grouping history findings by the path
prefix that produced them would turn 14,443 findings into one reviewable
cluster without weakening detection. Explicitly *not* a suppression rule.

#### N3 — `go.work.sum` is not excluded, though `go.sum` is

**Language:** Go · **Tier:** entropy · **Count:** 44 in `kubernetes` ·
**Classification: false positive (confident).**

**Structural description.** `baseExcludePaths` contains `**/go.sum` but not
`**/go.work.sum`. Go workspaces (Go 1.18+) use the second filename for exactly
the same content — module checksums, which are hashes by definition. All 44
findings are `generic-high-entropy` in a single file, `go.work.sum`.

**Could a real credential share this shape?** No. The file format holds only
module paths, versions and digests.

**0.1.3 candidate: yes — smallest possible fix**, and the same class of
already-accepted decision as `go.sum` itself.

#### N4 — Fixed-prefix provider rules matching embedded base64 payloads

**Languages:** Ruby, Java · **Tier:** format-match · **Count:** 5 ·
**Classification: false positive (confident).**

Three `square-access-token` findings in
`guides/assets/images/association_basics/has_many_through.svg`, and two
`facebook-access-token` findings in
`x-pack/plugin/ml/src/main/resources/…/spm_precompiled_normalizer.txt`.

**Structural description — corrected after re-measurement.** An earlier draft of
this section described these as SVG `d=` path data and a SentencePiece tokenizer
table. Both descriptions were wrong. In each file the matched span sits inside an
**embedded base64 payload**: the bytes immediately preceding every match are
base64 alphabet characters including `/` and `+`, which is exactly why the rules'
leading `\b` fires in the middle of a blob rather than at a token boundary. The
matched values are dense, high-entropy base64 — not sparse structured text.

**Measured.** Post-prefix Shannon entropy is **4.810** over 95 characters for the
`square-access-token` pair, and **4.33** (the lower of the two) for the
`facebook-access-token` pair over 107 and 119 characters.

**Could a real credential share this shape?** Yes, and that is the finding. Those
entropies fall *inside* the range legitimate provider tokens of the same length
occupy, so an entropy or charset-diversity floor cannot separate the two
populations. A threshold placed low enough to reject these values sits inside the
legitimate distribution's own tail, where it would eventually cost real
credentials.

**0.1.3 candidate: no — not by an entropy floor.** This family does **not** share
a fix with N1, and the earlier claim that it did was not supported by
measurement. N1's false positives are low-diversity runs and separate cleanly on
entropy; these do not separate on entropy at all. Any fix here needs a different
mechanism and its own collateral study.

#### N5 — PEM private keys in test fixtures and module documentation

**Languages:** Java, Go, Python · **Tier:** format-match · **Count:** 1,042
`private-key-block`, the second-largest family · **Classification: requires
triage — NOT called a false positive.**

Two sub-families. In `elasticsearch` (304), `spring-boot` (162) and
`kubernetes` (125) these are genuine PEM blocks in `.key` and `.pem` test
certificate fixtures. In `ansible` they are overwhelmingly *module
documentation* — `lib/ansible/modules/cloud/google/gcp_compute_ssl_certificate.py`
and siblings, whose docstrings embed example certificates.

**Could a real credential share this shape?** It *is* the shape, by definition.
These are real private keys that happen to be published deliberately.

**0.1.3 candidate: weak.** No shape-based suppression is safe here. The
`ansible` docstring case might be worth measuring, and "no safe fix exists" is
an acceptable answer.

#### N6 — Generated build and IDE metadata

**Languages:** Java, C# · **Tier:** entropy · **Count:** ~570 combined ·
**Classification: likely noise.**

`.factorypath` (233, Eclipse-generated annotation-processor classpath),
`Strings.resx` (339, .NET resource XML), and generated OpenAPI specs in
`kubernetes` (`api/openapi-spec/v3`, 85). All are machine-written files of a
kind the generated-file exclusion group already covers in spirit but not by
name.

**0.1.3 candidate: moderate.** Worth measuring against the existing
`generatedExcludePaths` policy rather than adding names ad hoc.

### Summary of 0.1.3 tuning candidates

| priority | candidate | evidence |
|---|---|---|
| 1 | Entropy/charset floor on fixed-prefix rules (fixes N1 only — see N4) | 9,180 of the 9,185 findings; one rule defect, narrow fix |
| 2 | Add `**/go.work.sum` to the exclude list (N3) | 44 findings, same class as an existing entry |
| 3 | History-scan clustering by path prefix (N2) | 14,443 findings from one deleted directory |
| 4 | Review `generatedExcludePaths` against N6 shapes | ~570 findings |
| 5 | Measure the `ansible` documentation case (N5) before designing | 1,042 findings, may have no safe fix |

**Explicitly not candidates:** suppressing PEM blocks by shape, or suppressing
browser-profile entropy by path. Both are exactly where real credentials live.

**None of these were implemented. 0.1.2 is unchanged.**

---

## Possible Real Findings

A path-and-rule heuristic flagged 273 named-rule findings outside obvious
fixture paths. Triage **without reading any value** accounts for almost all as
documentation, test certificates, or the families above.

Four findings were flagged for responsible-disclosure handling. Their
repository names, paths, and detector identities are intentionally omitted
from this document. They were not investigated, decoded, verified, or read,
and are excluded from all benchmark counts and conclusions.

---

## Honest Summary

> **Finding counts across these repositories do not constitute precision,
> recall, F1 or accuracy measurements, because there is no independently
> labeled ground-truth set.**

SecretLoop 0.1.2 was **validated against 20 major public repositories across 9
language groups, with the observed false-positive profile and tuning candidates
documented above.**

### What this study demonstrates

1. **The families 0.1.2 targeted did not reappear at scale** across nine
   languages that were not part of the corpus it was tuned against. That is the
   main positive result.
2. **SecretLoop 0.1.2 has one clear rule defect.** `twitter-bearer-token`
   matches any sufficiently long run of `A` characters, producing 9,180 findings
   from five files in one repository. This is the study's most actionable output.
3. **Five further structural families** were newly identified, with concrete and
   narrow tuning directions.
4. **Repository history, not language, is the strongest predictor of volume.**
   `react` and `express` are the same language and differ by four orders of
   magnitude.

### What this study does NOT demonstrate

- It does not measure precision, recall, accuracy or coverage for any tool.
- It does not establish that any tool is better, more precise, or more accurate
  than any other. **No leaderboard is offered and none should be inferred.**
- Fewer findings is not evidence of higher precision, and more findings is not
  evidence of better coverage. Without ground truth, a difference in count is a
  difference in *profile*.

### On the comparison tools

The gitleaks and TruffleHog figures in this document were **measured by us on
these repositories, with the command modes listed in Methodology, using default
configuration and with verification disabled.** They are not official vendor
benchmarks, not tuned configurations, and not claims about those tools'
capabilities in general.

The three tools do not measure the same thing. SecretLoop runs an entropy tier
the other two do not; TruffleHog is detector-oriented and has no equivalent
generic tier; gitleaks sits between them.

### On SecretLoop's generic tier

Stated plainly: **SecretLoop's generic tier is noisier than the comparison tools
on several repositories in this study** — `react` history, `dotnet/runtime`
tree, and `terraform` history most visibly. Some of that is the entropy tier
doing what a heuristic backstop does; some of it, specifically N1 and N3, is
correctable and belongs in 0.1.3.

**This benchmark intentionally does not exercise SecretLoop's verification and
liveness model**, which is a separate capability and the one the product is
actually built around. Running it against third-party repositories would have
meant authenticating with other people's credentials, which the safety rules of
this study forbid absolutely. Nothing here should be read as evidence about that
capability in either direction.
