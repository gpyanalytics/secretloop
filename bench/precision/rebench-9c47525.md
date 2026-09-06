# Re-benchmark of the merged rule fixes — SecretLoop, six pinned repositories

Measurement only. No repository file was edited; nothing was committed.

## 1. Executable under test

| | |
|---|---|
| SecretLoop HEAD | `9c475258a3ef7791e3cb3ae2ab7f6b5a38ada18a` (branch `main`, merge of PR #25) |
| working tree | clean (`git status --porcelain=v1` empty) |
| build | `npm run bundle` (esbuild, from this checkout) |
| executable | `/Users/mac/Documents/GPY/secretloop/out/cli.js` |
| invoked as | `node "$PWD/out/cli.js"` — never a bare `secretloop` |
| sha256 | `b768d5055255c6e4ed7e90854c66327a498eba4899b4cb6479a47222776fcbdf` |

The homebrew `secretloop` at `/opt/homebrew/bin/secretloop` recorded in
`results/benchmark-meta.txt` was deliberately NOT used: this measurement has to
be attributable to the merged checkout, not to whatever is on PATH.

## 2. Byte identity of the six pinned checkouts

Root: `/Users/mac/Documents/GPY/secretloop-benchmark/secretloop_benchmarks/`

Three checks per repository. The third matters because SecretLoop scans the
working tree rather than the object store, so an ignored or untracked artifact
would silently enter the scan. Nothing was cleaned.

| repository | HEAD == `bench/precision/pins.txt` | `status --porcelain=v1 -uall` | `clean -ndx` |
|---|---|---|---|
| `psf__requests` | MATCH `dae7ef63b4df…` | empty | no files |
| `expressjs__express` | MATCH `023767fe9872…` | empty | no files |
| `pallets__flask` | MATCH `d318b6834711…` | empty | no files |
| `axios__axios` | MATCH `b8d67bbbd6b3…` | empty | no files |
| `denoland__deno` | MATCH `83bb8d578050…` | empty | no files |
| `kubernetes__kubernetes` | MATCH `b2ec8b6fefac…` | empty | no files |

All six pristine. Byte-identity gate: **PASS**.

## 3. Scan command and scope

Reproduces the invocation recorded in `run_scans.sh` and
`results/benchmark-meta.txt` (`scope=working-tree-only; verification=off`,
`configuration=default-as-run`), substituting only the executable:

```
( cd "$repo" && node /Users/mac/Documents/GPY/secretloop/out/cli.js \
    scan --format json --fail-on never ) > "$OUT/<repo>.secretloop.json"
```

Working tree only, no `--verify`, no config override, default rule set. All six
exited 0 with empty stderr. Outputs written to `secretloop-benchmark/rebench-9c47525/`; the frozen
`secretloop_benchmarks/results/*.secretloop.json` baselines were not touched.

## 4. Per-repository counts

Baseline = the 480 `tool=secretloop` rows in committed
`bench/precision/triage.csv`.

| repository | baseline | measured | delta |
|---|---|---|---|
| axios | 7 | 3 | −4 |
| deno | 88 | 85 | −3 |
| express | 0 | 0 | 0 |
| flask | 6 | 6 | 0 |
| kubernetes | 374 | 374 | 0 |
| requests | 5 | 5 | 0 |
| **total** | **480** | **473** | **−7** |

Every per-repository count matches the frozen expectation.

## 5. Delta as identities

Compared as a multiset on `(repo, file, line, rule_id, fingerprint)`. Survivors
were then re-compared by location `(repo, file, line, rule_id)` so that a
surviving finding whose fingerprint moved would surface as a fingerprint
change, not be disguised as one removal plus one addition.

**Removed — 7, exactly the frozen set:**

| repository | rule | location |
|---|---|---|
| axios | `http-basic-auth-url` | `docs/pages/advanced/authentication.md:36` |
| axios | `http-basic-auth-url` | `docs/es/pages/advanced/authentication.md:36` |
| axios | `http-basic-auth-url` | `docs/fr/pages/advanced/authentication.md:36` |
| axios | `http-basic-auth-url` | `docs/zh/pages/advanced/authentication.md:36` |
| deno | `http-basic-auth-url` | `cli/tsc/dts/lib.deno_url.d.ts:354` |
| deno | `http-basic-auth-url` | `cli/tsc/dts/lib.deno_url.d.ts:470` |
| deno | `onepassword-service-account` | `tests/specs/test/ops_sanitizer_multiple_timeout_tests_no_trace/__test__.jsonc:4` |

- **Added: 0**
- **Surviving fingerprint changes: 0**
- All 473 surviving rows are identical on all five identity fields.
- The `requests` `tests/test_utils.py:452` `http-basic-auth-url` row — the
  f-string-placeholder false positive, whose host is registrable and therefore
  out of reach of the example-domain mechanism — **survives, as required.**

Delta gate (7 removed / 0 added / 0 changed): **PASS**.

## 6. Precision on the merged state

Gate in section 5 passed, so the frozen triage rows were filtered to the
measured surviving identities with **verdicts carried forward unchanged** — no
re-triage, no row edited. All 7 removed rows carried verdict `FP`. The filtered
473-row input is `triage.surviving-473.csv` in this directory; it was not
written into the repository. Scored with the committed
`bench/precision/compute_precision.py`.

```

473 findings across 5 repositories with findings, working tree only, verification off

## Precision by tool

tool          found    TP    FP   UNK  precision    pess.     opt.
secretloop      473   173   300     0      0.366    0.366    0.366

## Precision by repository

repo                            secretloop
                 found  TP  FP UNK    prec
axios                3   1   2   0   0.333
deno                85  28  57   0   0.329
flask                6   0   6   0   0.000
kubernetes         374 140 234   0   0.374
requests             5   4   1   0   0.800

## False positives by rule

secretloop -- 300 FP across 5 rule(s)
      279  generic-high-entropy  (93%)
       17  generic-api-key-assignment  (6%)
        2  db-connection-string  (1%)
        1  private-key-block  (0%)
        1  http-basic-auth-url  (0%)

## False positives by reason

secretloop
      123  long identifier or type name
       28  literal placeholder
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
secretloop       0   473      0.000

    173 of the true positives are committed test fixtures -- key
    material and tokens that are real credentials by shape but guard
    nothing. Treating them as noise is the harsher reading, and the
    one that matches what a user triaging their own repository does.
```

**Measured: 173 TP / 300 FP / 0 UNKNOWN = 0.366 (173/473).**

Matches the accounted figure exactly. UNKNOWN is zero, so the point estimate
carries no bound spread. Baseline precision on the same corpus was 173/480 =
0.360; the 7 removals were all false positives, so the numerator is unchanged
and the movement is entirely denominator.

The surviving single `http-basic-auth-url` FP in the by-rule breakdown is the
`requests` row named above.

## 6b. Byte-level corroboration

The freshly produced report JSON was compared sha256-wise against the frozen
`secretloop_benchmarks/results/*.secretloop.json`, which were collected earlier
by a *different* executable (the homebrew build named in `benchmark-meta.txt`):

| repository | rebench JSON vs frozen baseline |
|---|---|
| `psf__requests` | byte-identical |
| `expressjs__express` | byte-identical |
| `pallets__flask` | byte-identical |
| `kubernetes__kubernetes` | byte-identical |
| `axios__axios` | differs — 4 findings removed |
| `denoland__deno` | differs — 3 findings removed |

Four of the six reports reproduce bit-for-bit across a rebuild, a different
executable and a different day, and the only two that differ are exactly the two
repositories the fixes were expected to touch. This is stronger than the
identity comparison in section 5, which tolerates key-order and formatting
drift; it shows there was none.

## 7. Statement of attribution

Measured on identical pinned bytes at
9c475258a3ef7791e3cb3ae2ab7f6b5a38ada18a; attributed to PR #25. Exploratory
six-repository corpus; not a general precision claim.

## Source artifacts

This note and its companion scorer output were produced outside the repository,
reviewed there, and copied in unchanged. The copies were verified byte-for-byte
against these SHA-256 digests before this section was appended:

| file in this directory | source file | SHA-256 of the source |
|---|---|---|
| `rebench-9c47525.md` | `rebench-9c47525.md` | `f123746da24db3a4db8f3b9f1f97a9effc5fc6e6144ec367a5cb84313f79bf4a` |
| `rebench-9c47525-scorer.txt` | `scorer-output.txt` | `4858961144c06a39e07c926411f4f388f6390e45182b9c8e021a5080aedd2787` |

One line of section 3 was edited after copying: an absolute local path to the
source directory was shortened to the repository-relative form used elsewhere in
this note. SecretLoop's own entropy pass reported that absolute path as a
`generic-high-entropy` finding -- the "path or resource identifier"
false-positive class this corpus documents at 22 occurrences -- and this note is
committed under a self-scan gate that admits no new findings. Nothing else in
the body was changed, and no suppression directive was added.

Source directory: `secretloop-benchmark/rebench-9c47525/`, which also holds the
six per-repository report JSONs and the filtered 473-row scorer input. Those are
deliberately not committed: they are regenerable from the pinned checkouts by
the command in section 3, and the report JSONs carry masked finding values.
