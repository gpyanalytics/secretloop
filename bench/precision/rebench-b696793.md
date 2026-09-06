# Re-benchmark of the bare-{IDENT} placeholder fix — SecretLoop, six pinned repositories

Measurement only. No repository file was edited; nothing was committed.

Upgrades PR #27's `473 -> 472` from a pre-commit working-tree scan to a result
measured at the merged SHA.

## 1. Executable under test

| | |
|---|---|
| SecretLoop HEAD | `b69679383f600826d3db643c3d15fd773da297ba` (branch `main`, merge of PR #27) |
| working tree | clean (`git status --porcelain=v1` empty) |
| build | `npm run bundle` (esbuild, from this checkout) |
| executable | `/Users/mac/Documents/GPY/secretloop/out/cli.js` |
| invoked as | `node "$PWD/out/cli.js"` — never a bare `secretloop` |
| sha256 | `3fbbc26a6ee2372d70451b4a874ebfe0b69db7cada8e4f6fd50ac47a0c6312e9` |

That sha256 is identical to the build measured in the pre-commit worktree, so
the merge commit produced the same executable bytes as the branch it merged.

## 2. Byte identity of the six pinned checkouts

Root: `secretloop-benchmark/secretloop_benchmarks/`

Three checks each. The third matters because SecretLoop scans the working tree
rather than the object store, so an ignored or untracked artifact would enter
the scan unnoticed. Nothing was cleaned.

| repository | HEAD == `bench/precision/pins.txt` | `status --porcelain=v1 -uall` | `clean -ndx` |
|---|---|---|---|
| `psf__requests` | MATCH `dae7ef63b4df…` | empty | no files |
| `expressjs__express` | MATCH `023767fe9872…` | empty | no files |
| `pallets__flask` | MATCH `d318b6834711…` | empty | no files |
| `axios__axios` | MATCH `b8d67bbbd6b3…` | empty | no files |
| `denoland__deno` | MATCH `83bb8d578050…` | empty | no files |
| `kubernetes__kubernetes` | MATCH `b2ec8b6fefac…` | empty | no files |

Byte-identity gate: **PASS**.

## 3. Scan command and scope

Reproduces the invocation in `run_scans.sh` and the scope recorded in
`results/benchmark-meta.txt` (`scope=working-tree-only; verification=off`,
`configuration=default-as-run`), substituting only the executable:

```
( cd "$repo" && node /Users/mac/Documents/GPY/secretloop/out/cli.js \
    scan --format json --fail-on never ) > "$OUT/<repo>.secretloop.json"
```

All six exited 0 with empty stderr. Outputs written to this directory; no prior
rebench directory and no frozen `results/` baseline was overwritten.

## 4. Per-repository counts

Authoritative "before" = the six measured SecretLoop JSON reports in
`rebench-9c47525/` (the 473-finding measured state). Not the markdown note,
not the 480-row `triage.csv`.

| repository | before | after | delta |
|---|---|---|---|
| axios | 3 | 3 | 0 |
| deno | 85 | 85 | 0 |
| express | 0 | 0 | 0 |
| flask | 6 | 6 | 0 |
| kubernetes | 374 | 374 | 0 |
| requests | 5 | 4 | −1 |
| **total** | **473** | **472** | **−1** |

Every per-repository count matches the frozen expectation.

## 5. Delta as identities

Compared first as a multiset on `(repo, file, line, rule_id, fingerprint)`,
then survivors by location `(repo, file, line, rule_id)`, so a surviving
finding whose fingerprint moved would surface as a change rather than be
disguised as one removal plus one addition.

**Removed — 1, exactly the predeclared identity:**

| repository | rule | location |
|---|---|---|
| requests | `http-basic-auth-url` | `tests/test_utils.py:452` |

- **Added: 0**
- **Surviving fingerprint changes: 0**
- All 472 surviving rows are identical on all five identity fields.

## 6. Precision at the merged state

The gate in section 5 passed, so the frozen triage rows were filtered to the
472 measured survivors with **verdicts carried forward unchanged** — no
re-triage, no row edited; the one removed row carried verdict `FP`. Verdict
integrity was asserted programmatically. The filtered input is
`triage.surviving-472.csv` in this directory; it was not written into the
repository. Scored with the committed `bench/precision/compute_precision.py`.

```

472 findings across 5 repositories with findings, working tree only, verification off

## Precision by tool

tool          found    TP    FP   UNK  precision    pess.     opt.
secretloop      472   173   299     0      0.367    0.367    0.367

## Precision by repository

repo                            secretloop
                 found  TP  FP UNK    prec
axios                3   1   2   0   0.333
deno                85  28  57   0   0.329
flask                6   0   6   0   0.000
kubernetes         374 140 234   0   0.374
requests             4   4   0   0   1.000

## False positives by rule

secretloop -- 299 FP across 4 rule(s)
      279  generic-high-entropy  (93%)
       17  generic-api-key-assignment  (6%)
        2  db-connection-string  (1%)
        1  private-key-block  (0%)

## False positives by reason

secretloop
      123  long identifier or type name
       27  literal placeholder
       26  digest or checksum
       22  path or resource identifier
       22  key identifier, not a credential
       19  documentation example
       16  mime type
       10  generated resource name
        8  command-line flag string
        8  detached signature, not a credential
        8  test name / xml fixture text
        4  encoded data, not a credential
        3  version string
        2  public key material
        1  pem marker string, no key material


## Precision, discounting test fixtures

tool            TP    FP  precision
secretloop       0   472      0.000

    173 of the true positives are committed test fixtures -- key
    material and tokens that are real credentials by shape but guard
    nothing. Treating them as noise is the harsher reading, and the
    one that matches what a user triaging their own repository does.
```

**Directly measured at this SHA: 473 -> 472; removed = 1, added = 0,
surviving fingerprint changes = 0.**

**Carried forward from the frozen triage rather than re-measured: 173 TP /
299 FP / 0 UNKNOWN = 36.7% (173/472).** No row was re-triaged; the verdicts
are the ones recorded in `triage.csv`, filtered to the measured survivors.

Matches the accounted figure. UNKNOWN is zero, so the point estimate carries no
bound spread. The preceding measured state was 173/473 = 0.366; the removed row
was a false positive, so the numerator is unchanged and the movement is entirely
denominator.

Two secondary effects worth recording. `http-basic-auth-url` has disappeared
from the false-positive-by-rule breakdown entirely — it contributed one FP at
the previous state and none now. And `requests` reaches 4 findings, 4 true
positives, precision 1.000: it is the only repository with nonzero findings
whose measured SecretLoop findings are all true positives.

## 7. Byte-level corroboration

Report JSON compared sha256-wise in both directions.

Against `rebench-9c47525/` (the before-state, a different build):

| repository | result |
|---|---|
| `psf__requests` | differs — 1 finding removed |
| `expressjs__express`, `pallets__flask`, `axios__axios`, `denoland__deno`, `kubernetes__kubernetes` | byte-identical |

Five of six reproduce bit-for-bit, and the only one that differs is the single
repository the fix was expected to touch.

Against `rebench-worktree-f7bfd58/` (the pre-commit measurement of the same
change): **all six byte-identical.** Merging changed nothing, which is what
makes this note an upgrade of PR #27's number rather than a new result.

## 8. Statement of attribution

Measured on identical pinned bytes at
b69679383f600826d3db643c3d15fd773da297ba; attributed to PR #27. Exploratory
six-repository corpus; all observed TPs are committed fixtures; not a general
precision claim.

## 9. Provenance / post-copy edits

This note and its companion scorer output were produced outside the
repository, reviewed there, and copied in. The copies were verified
byte-for-byte against these SHA-256 digests before any edit below:

| file in this directory | source file | SHA-256 of the source |
|---|---|---|
| `rebench-b696793.md` | `rebench-b696793.md` | `01be93b74dcdf1489cdce313833174f96f92ec94a9ba45a0893df94f543d2fc7` |
| `rebench-b696793-scorer.txt` | `rebench-b696793-scorer.txt` | `a7e2b825308d22712ff79c98c73fff62d79cda7dc4521160d5a9b27832bffc83` |

`rebench-b696793-scorer.txt` was not edited at all and still carries the
digest above. Two edits were made to this note after copying, both recorded
verbatim.

**Edit 1 — section 6, separating what was measured from what was carried
forward.** The original labelled the verdict carry-forward as "Measured",
which conflated a detector delta this run actually observed with a precision
figure inherited from an earlier human triage.

Before:

> \*\*Measured: 173 TP / 299 FP / 0 UNKNOWN = 0.367 (173/472).\*\*

After:

> \*\*Directly measured at this SHA: 473 -> 472; removed = 1, added = 0,
> surviving fingerprint changes = 0.\*\*
>
> \*\*Carried forward from the frozen triage rather than re-measured: 173 TP /
> 299 FP / 0 UNKNOWN = 36.7% (173/472).\*\* No row was re-triaged; the verdicts
> are the ones recorded in `triage.csv`, filtered to the measured survivors.

**Edit 2 — section 6, narrowing an overreaching claim about `requests`.** The
original asserted an absence of false positives in that repository; what was
measured is only that the findings SecretLoop reported there are all true
positives, which says nothing about false positives it did not report.

Before:

> positives, precision 1.000: it is the only repository in the corpus with no
> false positive left.

After:

> positives, precision 1.000: it is the only repository with nonzero findings
> whose measured SecretLoop findings are all true positives.

No other content was changed. The six report JSONs, the 472-row scorer input
and the `.err` files stay in the source directory and are deliberately not
committed: they are regenerable from the pinned checkouts by the command in
section 3, and the report JSONs carry masked finding values.
