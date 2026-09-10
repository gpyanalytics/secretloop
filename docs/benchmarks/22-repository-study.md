# The twenty-two-repository study

> **Status: measurement complete, documentation for review.** This study measures an
> **unreleased build**, not published 0.5.0. See [benchmarks](../benchmarks.md) for how the
> populations on this page relate to the other studies — and why no number here may be
> combined with one from those.

Measured **10 September 2026**; all sixty-six scans ran between 09:06 and 09:27 UTC.

**What this study is.** A precision-and-composition measurement of one scanner build across
twenty-two pinned public repositories, in three detector modes, with every finding adjudicated
either as a full census or as a predeclared random sample.

**What it is not.** It is not a release measurement, not a comparison with any other tool, not
a recall measurement, and not evidence that the detector improved. Each of those is stated
again, with its reason, in [§9](#9-what-this-study-does-not-establish).

---

## 1. Scanner source

| | |
|---|---|
| source commit | `49987de6bb71bc83aeb50f010bedb0745b89249e` (`origin/main` at the time) |
| source tree | `f60c025e5d8d30ba6c8f3ee37e3289543efaf027` |
| scanner artefact | `out/cli.js`, 530 505 bytes, SHA256 `c19356291bd8a11be50de686e15c3d40e16909dbfb25640dac2f018433abbf7a` |
| `package.json` version | `0.5.0` |
| published `v0.5.0` tag | peels to commit `fd6637d77b4561ea0b2298358cac1def55e2b6cc` |

### This is not published 0.5.0

The source is **eight commits ahead** of the `v0.5.0` tag and carries unreleased changes — the
VS Code exclusion and suppression-disclosure work, the history cancellation fix, and the GitHub
and Slack verification diagnostics. `package.json` reads `0.5.0` only because no version bump
had happened. **No figure on this page describes a released build**, and none should be quoted
as a 0.5.0 result.

The runner hashed `out/cli.js` before every repository scan and aborted on any change, so all
sixty-six runs are known to have used the one artefact above.

## 2. The panel

Twenty-two public repositories, each at a fixed commit.

| repository | role | pinned commit | commit date | licence |
|---|---|---|---|---|
| `axios/axios` | frozen six | `b8d67bbbd6b381e1f4b1887e32686fcc89c5b0a8` | frozen pin | MIT |
| `denoland/deno` | frozen six | `83bb8d5780505d0b4f30c089680ce98b0e7a4770` | frozen pin | MIT |
| `expressjs/express` | frozen six | `023767fe9872e029271df1418f73401bff20ff40` | frozen pin | MIT |
| `kubernetes/kubernetes` | frozen six | `b2ec8b6fefac451a2dedafc4dd71f2f16c7a6abe` | frozen pin | Apache-2.0 |
| `pallets/flask` | frozen six | `d318b683471101618febed18996405ad26462110` | frozen pin | BSD-3-Clause |
| `psf/requests` | frozen six | `dae7ef63b4df6eded86637f251fc4e3a06c3b479` | frozen pin | Apache-2.0 |
| `ansible/ansible` | addition | `e9e67d2b820aca37fcc47b06b7416105376ef9d8` | 2026-09-09 | GPL-3.0 |
| `curl/curl` | addition | `110936726e518ff843e0a2063db8143be07dd286` | 2026-09-10 | not asserted |
| `django/django` | addition | `2b30f6255b5ef84afbd827993643d52ef2c0963a` | 2026-09-08 | BSD-3-Clause |
| `docker/compose` | addition | `4f8ad689b9f0899f41eeff94e4c84e609e6fb726` | 2026-09-10 | Apache-2.0 |
| `dotnet/runtime` | addition | `c307f70df227cc74d6c1dd50b663893431e74a6a` | 2026-09-10 | MIT |
| `elastic/elasticsearch` | addition | `9a20abddf36226d980bcee80413c8db7c9cadb3f` | 2026-09-10 | not asserted |
| `gin-gonic/gin` | addition | `dcaa4296d111981ffb31ac3eba90bb63e1eb5ab9` | 2026-08-15 | MIT |
| `hashicorp/terraform` | addition | `eb887449b9d4cf5bc36ad1f4453cd3b766acd429` | 2026-09-09 | not asserted |
| `laravel/laravel` | addition | `aa0cf127fc365a56ee016867144ddffabc2290ae` | 2026-08-25 | not asserted |
| `nestjs/nest` | addition | `39fbddae51281ca56bf2fed9123d98e61509066c` | 2026-08-31 | MIT |
| `rails/rails` | addition | `52fa23ce8e1d39ff281bf300867e9ba7c7d66111` | 2026-09-09 | MIT |
| `react/react` | addition | `a58f939795502a579c02d584600df5369d864c3b` | 2026-09-09 | MIT |
| `redis/redis` | addition | `21ce96878529bf8b31298ec417407c578c1e6278` | 2026-09-09 | not asserted |
| `rust-lang/cargo` | addition | `e7506208ff1b7f01062e410c419f95628dfdb31b` | 2026-09-08 | Apache-2.0 |
| `spring-projects/spring-boot` | addition | `59379ae449f15a6d17a333f5505941f4165ab3b2` | 2026-09-09 | Apache-2.0 |
| `tokio-rs/tokio` | addition | `022c004b4a7c42c0c534e9737e9c66ff916517b1` | 2026-09-09 | MIT |

`facebook/react` now redirects to `react/react`. The canonical name is recorded; the repository
was not swapped for a different project.

### The panel is mixed-date, and previously exposed

**Mixed-date by construction.** The frozen six keep their existing early-September pins so they
stay comparable with their own history; the sixteen additions were pinned at their
default-branch tips on 10 September 2026, before any scan and without consulting scanner output.
A cross-repository comparison therefore compares different dates.

**None of the twenty-two is fresh holdout.** All were previously exposed: the twenty from the
0.1.2 study, the six from the frozen benchmark, and `rails/rails` additionally from a
generic-assignment evaluation. Nothing here may be described as held out.

**No commit-for-commit comparison with the 0.1.2 study is possible.** That study's
per-repository commit SHAs were never recorded and are unrecoverable. The pins above are new
pins resolved for this study and carry no claim to reproduce the earlier measurement. The
"last 1,000 commits" bound noted in that study applied to a history scan and does not carry
over, because this study runs none.

## 3. Scope, modes and commands

**Scope: repository-root working tree only. No git history scan. No live credential
verification** — `--verify` was never passed, and no network request was made against any
discovered value.

```
default          node <cli> scan --path . --format json --fail-on never
include-entropy  node <cli> scan --path . --format json --fail-on never --include-entropy
restore          node <cli> scan --path . --format json --fail-on never --include-entropy --include-api-document-entropy
```

`--fail-on never` stops a finding from halting the runner and changes no detection.
`--no-redact` was never passed, so no raw value reached any report. `--include-fixtures`,
`--include-generated` and `--key-context` were not passed: these three modes are exactly those
the frozen six were measured under.

No repository carried a `.secretloop.json` at its pin, re-checked from the actual checkout at
measurement time, so the effective configuration was the shipped default and identical across
all twenty-two. No exclusion was overridden, and standard traversal and resource limits applied
unmodified.

### Traversal limits — what was never read

The runner did **not** execute any repository's code, install its dependencies, initialise
submodules, or fetch LFS payloads. Clones were made without submodule recursion and with LFS
smudging disabled. Consequently:

- a **submodule** appears as an empty directory and its contents are never scanned;
- an **LFS-tracked file** is present only as a pointer stub, so a credential inside an LFS
  payload is invisible to this study;
- **vendored dependencies** a project does not commit are absent.

Each of these narrows coverage. **None of them is a clean result**, and none is evidence that a
repository contains nothing further.

### Sixty-six scans and sixty-six repeats

22 repositories × 3 modes = **66 measured runs**, and **66 further runs as determinism
repeats** — 132 scan executions in total. The 66 repeats are *not* additional measurements and
contribute to no count on this page; each exists only to be compared against its own run.

**All 66 runs succeeded**; none timed out, and none was excluded. A failed or timed-out scan
would have been recorded as a failure and excluded from every denominator, never counted as
zero findings. Each run was validated on exit code, captured `stderr`, and JSON that parses and
carries `tool`, `summary` and `findings`; each checkout was confirmed clean and at its pin
immediately beforehand; the 30-minute per-run timeout was never reached.

**Every repeat matched its run** on the finding multiset and the summary.

### The frozen-six retention gate

The six repositories carried into this panel had to reproduce their existing populations
exactly, checked on five-field finding identities and site-identity sets rather than on counts.
Three levels of equality were kept apart, and all passed:

| mode | complete finding-object equality | summary metadata | literal report-byte equality | population TP/FP/UNKNOWN/total |
|---|---|---|---|---|
| `default` | 6/6 identical | no differences | 6/6 identical | 220 / 21 / 0 / 241 |
| `include-entropy` | 6/6 identical | no differences | 6/6 identical | 234 / 199 / 0 / 433 |
| `restore` | 6/6 identical | no differences | 6/6 identical | 234 / 300 / 0 / 534 |

Site coverage also reproduced: 138/145, 143/145 and 143/145. **That 145-file denominator is the
frozen six's own positive-site universe.** It is not extended to the additions and is not
borrowed by any other view on this page.

## 4. The four population views

The views **overlap and can never be summed across each other.**

| view | membership | repositories |
|---|---|---:|
| **A — the frozen six** | `axios`, `deno`, `express`, `kubernetes`, `flask`, `requests` | 6 |
| **B — the sixteen additions** | the twenty-two minus the frozen six | 16 |
| **C — the original twenty** | the twenty-two minus `axios/axios` and `denoland/deno` | 20 |
| **D — the combined twenty-two** | A ∪ B | 22 |

A and C share four repositories (`express`, `kubernetes`, `flask`, `requests`); C and D overlap
by twenty. Membership is taken by repository identity, never by subtracting one percentage from
another. Adding a row from one view to a row from another double-counts the overlap.

## 5. Adjudication: census versus sample

**`default` was adjudicated as a full census** — every finding, in every view. The entropy modes
are a **census for the frozen six** (reused by identity, not re-adjudicated) and a
**600-unit random sample for the sixteen additions**.

| mode | frame (the sixteen) | kind | N | n |
|---|---|---|---:|---:|
| `default` | 1080 | census | 1080 | 1080 |
| `include-entropy` | 2887 | sample | 2887 | 600 |
| `restore` | 2887 | sample | 2887 | 600 |

The sampling unit is one finding **object**, so copied occurrences and duplicate identities keep
their multiplicity and nothing is collapsed. The frame was hashed before the draw; selection is
simple random **without replacement**; the inclusion probability is `600/2887 = 0.2078282…`,
equal for every unit, so both samples are self-weighting and carry no design weight. The
estimator denominator is the 600 drawn units.

**1754 keys required a label** — the `default` census plus the units actually drawn in the two
sampled modes. All 1754 carry one. **1133 units sit in the entropy frames undrawn and are
deliberately left unlabelled rather than imputed**; a unit that is counted but not drawn is
reported as such and never given a verdict. Twelve successor corrections were applied as a
layer on top of the base labels, each changing a label that exists, with the base files
unchanged underneath.

### Label criteria, predeclared

- **TP** — the value is secret-bearing by **semantics**: how it is consumed. **Current liveness
  is not the criterion and was never checked.** A committed test credential is a TP.
- **FP** — the value demonstrably serves a non-secret role. A test or example *path* does not by
  itself make a finding an FP.
- **UNKNOWN** — an explicit adjudication recorded with its reason, not a gap. An unfamiliar
  finding is never defaulted to FP.

Two qualifications were declared before the labels they governed: public availability alone does
not make a value non-secret, and code *consuming* a value does not alone make it a TP —
consumption shows the slot, not the secret.

## 6. Results — `default`, a census in every view

Every total below is an exact count. **The only uncertainty is the unresolved-label band.**

| view | TP | FP | UNKNOWN | findings | identification |
|---|---:|---:|---:|---:|---|
| A — frozen six | 220 | 21 | 0 | 241 | 91.2863% (a point; no UNKNOWN) |
| B — sixteen additions | 620 | 388 | 72 | 1080 | **57.4074% – 64.0741%** |
| C — original twenty | 751 | 403 | 72 | 1226 | **61.2561% – 67.1289%** |
| **D — combined twenty-two** | **840** | **409** | **72** | **1321** | **63.5882% – 69.0386%** |

**These bounds are not confidence intervals.** They are the arithmetic consequence of the
UNKNOWN labels: the lower endpoint counts every UNKNOWN against the scanner, the upper endpoint
counts every one for it. Nothing was sampled in this mode, so there is no sampling error to add
— for a census the unresolved-label band is the *whole* of the uncertainty.

Both components of views C and D are censuses, so their totals are exact:
220 + 620 = 840 TP over 241 + 1080 = 1321 findings.

### Where the findings sit

Two repositories dominate: `elastic/elasticsearch` contributes 640 of the 1080 default findings
on the sixteen and `spring-projects/spring-boot` 214. **A pooled figure across this panel is
largely a statement about those two.** Per-repository identification in the census ranges from
100.0% (`hashicorp/terraform`, 14 findings) to 0.0% (`curl/curl`, 2 findings).

## 7. Results — `include-entropy` and `restore`

Reported as **two components that are never merged into one exact number**, because one is a
census and the other an estimate.

**Census part — the frozen six, exact:**

| mode | TP | FP | UNKNOWN | findings | identification |
|---|---:|---:|---:|---:|---|
| `include-entropy` | 234 | 199 | 0 | 433 | 54.0416% (exact) |
| `restore` | 234 | 300 | 0 | 534 | 43.8202% (exact) |

**Sampled part — the sixteen additions, n = 600 of N = 2887:**

| mode | adjudicated sample | unresolved-label bound on the sample | estimated population TP | estimated FP | estimated UNKNOWN |
|---|---|---|---|---|---|
| `include-entropy` | 140 TP / 443 FP / 17 UNKNOWN | 23.3333% – 26.1667% | 673.6 `[591.6, 765.4]` | 2131.6 `[2036.9, 2217.5]` | 81.8 `[55.3, 125.6]` |
| `restore` | 130 TP / 457 FP / 13 UNKNOWN | 21.6667% – 23.8333% | 625.5 `[546.0, 715.4]` | 2198.9 `[2106.6, 2281.7]` | 62.6 `[40.2, 102.5]` |

**Combined views — exact detections, estimated true positives:**

| mode | view | detections (exact) | estimated TP | point bound on each endpoint | conservative overall interval |
|---|---|---:|---|---|---|
| `include-entropy` | C | 3171 | 818.6 `[736.6, 910.4]` | 25.8163% – 28.3958% | `[22.8843%, 31.8307%]` |
| `include-entropy` | **D** | **3320** | **907.6 `[825.6, 999.4]`** | **27.3384% – 29.8022%** | **`[24.5380%, 33.0829%]`** |
| `restore` | C | 3272 | 770.5 `[691.0, 860.4]` | 23.5488% – 25.4605% | `[20.7973%, 28.7111%]` |
| `restore` | **D** | **3421** | **859.5 `[780.0, 949.4]`** | **25.1247% – 26.9532%** | **`[22.4930%, 30.0621%]`** |

The detection counts are exact. **The TP figures are estimates, not counts**, and are not
integers because they are frame-scaled sample counts.

### The two entropy modes see an identical population on the sixteen

Checked as **complete finding objects compared as a multiset, per repository** — not by equal
totals:

| group | `include-entropy` | `restore` | object-multiset equality |
|---|---:|---:|---|
| the sixteen additions | 2887 | 2887 | **identical, all 16 repositories** |
| the frozen six (control) | 433 | 534 | **differs** — `kubernetes` +101 |

Summary metadata is identical for all sixteen and the reports are byte-identical, 16 of 16. The
control group shows the check *can* report a difference when one exists. On this panel,
**`--include-api-document-entropy` adds nothing to the sixteen additions.**

The two samples were nevertheless drawn independently from that identical population — the mode
name is appended to the seed string — so they select different subsets and produce different
estimates of the same quantity. **That difference is sampling variation, not a detector-mode
effect**: on this panel there is no mode effect available to observe. Neither sample is pooled
with, averaged against, or selected over the other.

## 8. Statistical limitations

**The intervals are approximate, and their coverage is nominal.**

> **"Coverage" means two unrelated things on this page.** *Interval coverage* is the probability
> that an interval contains the true value — a statistical property of the method, discussed in
> this section. *Site coverage* (138/145, 143/145) is the share of a file universe in which a
> true positive was found — a property of the scan, discussed in [§3](#the-frozen-six-retention-gate)
> and [§9](#9-what-this-study-does-not-establish). Neither is evidence about the other, and
> neither is recall.

- The method is **Wilson at 95% with a finite population correction `sqrt((N-n)/(N-1))` applied
  to the standard error**, predeclared before the draw.
- **Wilson is approximate.** It inverts a normal approximation to the score statistic, and its
  coverage oscillates with `n` and `p`. Attaching a finite population correction is a standard
  practical adaptation, **not a derivation**: the combination carries no exact finite-population
  coverage guarantee. **Nothing on this page may be called exact except the census counts and
  detection totals.** An exact hypergeometric interval exists for this design; it was not
  predeclared and was not substituted.
- **Two endpoints are not one interval.** Each bound carries its own nominal 95% statement. Two
  such statements do not jointly cover at 95%: under independence the joint level would be about
  90.3%, and these two come from the same sample and are strongly positively dependent, so the
  true joint level lies between roughly **90% and 95%** and is not determined by the data.
  **Nominal simultaneous coverage is not claimed.** Only the conservative overall interval —
  each endpoint at 97.5%, Bonferroni over the two statements — has an argued floor of *at least*
  95%, and it is conservative by construction.
- **A recorded implementation deviation is disclosed rather than hidden.** The recorded
  intervals applied the finite population correction to the whole Wilson radicand instead of to
  the standard error. The corrected form is **wider**, by about 0.007 percentage points here,
  and is the one published — because it is what was predeclared, not because of its width.
- **Sparse strata carry no percentages.** A sampled stratum with fewer than 30 drawn units is
  reported as a count with precision declared unavailable. In `include-entropy`, 6 of 10
  repository strata and 7 of 10 rule strata are sparse; 4 repositories and 5 rules appear in the
  frame with **no unit drawn** — their detection counts are exact and their precision is **N/A,
  never 0%**. Two repositories (`tokio-rs/tokio`, `laravel/laravel`) produced no findings at all
  in the entropy modes. Census strata are exact at any size.
- **The estimand is this frame.** The sampled figures describe the finding population of the
  sixteen additions at their pinned commits under this build — not the detector in general, not
  open-source code, and not any wider population.

### Unresolved labels are a separate uncertainty

| | what it is | where it applies |
|---|---|---|
| **identification bound** | caused by UNKNOWN labels; lower counts every UNKNOWN against the scanner, upper counts every one for it | every view; for a census it is the entire uncertainty |
| **sampling interval** | an interval around **each endpoint separately** | sampled modes only |
| **overall interval** | both endpoints at 97.5%, so the pair holds at *at least* 95% | only where coverage is argued |

An unresolved-label bound and a sampling interval are different quantities and are never
combined into a single number.

### The unresolved labels themselves

Counts must be read with their population attached:

| where | UNKNOWN | out of |
|---|---:|---|
| `default` census, the sixteen (view B) | **72** | 1080 adjudicated — a census |
| `include-entropy` **sample** | **17** | 600 drawn of 2887 |
| `restore` **sample** | **13** | 600 drawn of 2887 |
| frozen six, all three modes | **0** | reused by identity |

The **102** total is therefore the count across the adjudicated set — one census plus two
600-unit samples — and is **not** a count over the full finding population of the panel.

Those 72 are described below along two **different** dimensions. They are not two versions of
one count, and the two tables do not add together.

**By the rule that reported them:**

| rule | UNKNOWN |
|---|---:|
| `bcrypt-hash` | 59 |
| `generic-api-key-assignment` | 13 |
| **total** | **72** |

**By the role each recorded adjudication gives the value:**

| recorded role | UNKNOWN |
|---|---:|
| a committed password hash or authentication verifier | 71 |
| a documentation-site search key whose privilege level the repository does not establish | 1 |
| **total** | **72** |

The 71 are the 59 `bcrypt-hash` findings together with 12 of the 13 generic-assignment findings
— eleven recorded as password hashes used as authentication verifiers, and one as a SHA-512
crypt hash set as a test account's password. The single remaining unit is unresolved for an
unrelated reason: whether that key is search-only or privileged cannot be established from the
repository, and no verification is performed.

So **71 of the 72** turn on one unanswered policy question: **does this benchmark treat a
committed password hash — bcrypt, SHA-512 crypt, Argon2 — as credential material, or as a
derived digest?** A stored verifier is a digest by construction, which the frozen contract calls
FP; it is also the thing that grants access, which the contract calls TP. The contract has no
precedent for it.

All 72 units together are the **entire width** of the view-B band — exactly 6.6667 percentage
points, and 5.4504 points in view D; the password-hash question accounts for 71 of them.
Resolving that question in either direction would collapse the band toward a point. **It is
deliberately not resolved by assumption here**, and no label was forced to narrow an interval.

## 9. What this study does not establish

**No recall, for the sixteen or for the twenty-two.** No independently established positive-site
inventory exists for the additions, so no denominator exists — and triaging a scanner's own
findings cannot create one. The 145-site coverage figures belong to the frozen six's universe
alone and are **not** borrowed by view B, C or D.

**No detector improvement.** Only one build was ever run. There is no before/after, no second
version, and no repeated measurement on a fixed population. **Every difference between views on
this page is a difference of population, not of detector.** A higher score on additional
repositories is not evidence that the detector improved.

**No comparison with, or ranking against, any other tool.** No competitor was executed on this
panel; it was out of scope for this phase. A comparison would require separately pinned tools,
equivalent scope and explicitly stated verification modes. Nothing here supports a claim of
superiority over any other scanner. The three-tool table in [benchmarks §1](../benchmarks.md)
is a different corpus, a different build and a different triage policy, and no figure may move
between the two.

**The 57% entropy-enabled target is not met, and the default result does not meet it.** That
target is defined on **the frozen six at `--include-entropy`**, where precision is
`234/433 = 54.04%`; reaching 57% would mean removing 23 of 199 false positives, at least 2 of
them from the generic-entropy tier. This study leaves that population unchanged, so the target
**remains unmet**. The 63.5882% – 69.0386% figure is a **different mode** (entropy off) on a
**different population** (twenty-two repositories, dominated by the sixteen additions). Turning
entropy off does not satisfy an entropy-enabled target — it removes the tier the target is
about. The two numbers are not interchangeable.

**No credential was verified.** TP means secret-bearing on the evidence in the repository, not
that anything currently authenticates.

## 10. What the results do show

**Entropy widens the net far more than it finds.** On the sixteen additions, enabling the
entropy tier takes detections from 1080 to 2887 — a **2.67×** increase in volume — while
identification falls from 57.4074% – 64.0741% to 23.3333% – 26.1667%. This is an
**operating-point choice**, not a quality difference: the same detector, a wider net, and far
more to read per credential found.

**False positives are concentrated, not diffuse.** In the `default` census one rule,
`generic-api-key-assignment`, carries **78.6%** of every observed false positive, and the top
two carry **85.6%**. In both entropy modes `generic-high-entropy` alone carries about **five in
six**. Named provider rules contribute **3.1%** of default false positives. The generic rules
are simultaneously the largest false-positive source and the lowest-identification rules —
1.9% – 5.9% for generic assignment in the census, 1.6% – 2.6% for generic entropy in the
samples.

**Rule-based detection carries the result.** In the default census `private-key-block` accounts
for 574 of the 1080 findings at 95.6% identification, and `pkcs12-private-key` for 57 at 100%.

## 11. Reproducibility

**What an independent reader can reproduce.** Everything up to and including the detection
counts. The scanner source commit, the build command (`npm run bundle`), the artefact hash, the
twenty-two pins and the three exact command lines are all published above; the repositories are
public and the pins are immutable. Re-running the three commands at those pins with a build
matching `c1935629…` should reproduce the finding objects and the per-mode totals — 1080, 2887
and 2887 on the sixteen; 241, 433 and 534 on the frozen six.

**What an independent reader cannot reproduce.** Every TP / FP / UNKNOWN label, and therefore
every identification figure on this page. The adjudication was performed against internal
evidence records that are **not published**: label files, per-unit evidence, branch audits, the
sampling frames and draws, and the statistical analysis scripts. **They are not available in
this repository and no path to them is offered here.** A reader who disagrees with a verdict
cannot check it against the record, and that limitation is not repaired by anything on this
page.

**Single adjudicator.** One reader assigned the labels, with an evidence sentence for each and
no second opinion. **No inter-rater agreement figure exists and none can be computed after the
fact.** The widest single judgement in the study — one structural criterion deciding 453 of 674
generic-entropy units — is recorded in the internal audits so that a reviewer with access can
disagree with it; the procedure does not prove itself correct.

**No raw values are published.** No credential value, no value-derived digest and no raw finding
dump appears on this page or in this repository as a result of this study.

## 12. Limitations, collected

1. **Not published 0.5.0** — an unreleased build, eight commits ahead of the tag.
2. **Working tree only** — no history scan, no live verification.
3. **Traversal limits** — no submodules, no LFS payloads, no installed dependencies, no code
   executed; coverage is narrowed and no repository is shown to be clean.
4. **Mixed-date panel, no fresh holdout**, and no commit-for-commit comparison with the 0.1.2
   study, whose pins are unrecoverable.
5. **Two repositories dominate the sixteen**; pooled figures largely describe them.
6. **Unresolved-label bounds are not confidence intervals** and are reported separately from
   sampling intervals throughout.
7. **Statistical interval coverage is approximate and nominal** — not to be confused with scan
   or site coverage; simultaneous coverage is not claimed; only the conservative interval has an
   argued floor.
8. **Sparse strata carry counts, not percentages**; a stratum with no unit drawn has precision
   N/A, never 0%.
9. **71 of the 72 default-census UNKNOWN turn on one unanswered policy question** — whether a
   committed password hash is credential material or a derived digest. All 72 together are worth
   6.6667 points of the view-B band and 5.4504 of view D; the question is carried as a bound, not
   forced to a label.
10. **No recall, no competitor comparison, no detector-improvement claim.**
11. **Labels are not independently reproducible** — single adjudicator, unpublished evidence.
