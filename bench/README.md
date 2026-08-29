# bench/ — the detection benchmark

`npm run bench` regenerates a labelled corpus from a fixed seed, runs the local
build against it, and prints precision, recall and F1 for both detection tiers
on the working tree and on git history.

```bash
npm run bundle && npm run bench                      # corpus A only
python3 bench/run.py --corpus-b /path/to/bugsnag-js  # + the real-noise corpus
```

Corpus A is **generated, not committed**. A checked-in tree of credential-shaped
files is a liability in a public repository; a seeded generator plus a pinned
`labels.json` proves the same thing. Every run regenerates the corpus and
compares the resulting labels against `labels.json`, so a change to the
generator fails loudly instead of quietly rescoring against a corpus nobody
looked at.

Corpus B is a real repository with no known secrets, so every finding is a false
positive. It stays a manual step because it needs an external checkout pinned to
a specific commit.

## What it measures

- **Corpus A**: 190 files across 12 languages, 50 planted secrets in the tree,
  10 more that exist only in git history, and 120 decoys — SHA digests, UUIDs, a
  JWT of public claims, URLs, lockfile integrity strings, hashed asset names,
  base64 images, and published documentation samples.
- **Corpus B**: false-positive rate per KLOC on 185 KLOC of real code.
- Scoring is **exact line match**. Recall is counted over labels, precision over
  findings.

## What it cannot measure

Carried over from the benchmark report that produced it, because a benchmark
whose limits are not written down gets quoted as if it had none.

1. **It does not measure detector breadth.** Eight secret kinds are planted.
   SecretLoop ships 103 rules; this exercises a handful of them.
2. **The alphabets are the generator's choice, and they matter.** Passwords drawn
   from an alphanumeric alphabet scored 10/10; the same generator with `!@#$%`
   added scored 2/10. Recall here is a property of the corpus as much as of the
   scanner.
3. **Corpus B containing no real secrets is an assumption**, not an audited fact.
   A genuine credential in there would mean one tool's FP count is overstated.
4. **Corpus A's decoy density is roughly 16x natural**, so its false-positive
   rate is not a real-world rate. Corpus B's is the meaningful one.
5. **Precision is undefined on corpus B** — there are no true positives, so only
   the FP rate is meaningful there.
6. **Labelling a JWT a decoy is a judgment call.** A JWT is a bearer credential;
   scoring it as a secret instead moves precision materially.

## Why exact line matching

The corpus places decoys on lines adjacent to secrets — 21 of 50 secret labels
have a decoy neighbour. A +/-1 tolerance window therefore credits findings that
landed on a decoy as true positives: measured at +3 spurious true positives for
SecretLoop and +7 for gitleaks on the first run of this benchmark. Every tool
compared reports exact lines for these formats, so the window bought nothing.

## Holdout: does this generalise beyond the corpus the fixes were written against?

`python3 bench/run.py --seed <n>` regenerates the corpus with a different seed
and skips the labels.json pin. A holdout at seed 20260930, run against the build
after the four 0.1.1 detection fixes:

| tier | tree P/R | history P/R |
|---|---|---|
| entropy-on | 1.000 / 1.000 | 0.879 / 0.967 |
| named-only | 1.000 / 1.000 | 0.891 / 0.950 |

Identical tree scores to the committed corpus. **This is a weaker result than it
looks.** A different seed draws different values from the *same generator*: the
same eight secret kinds, the same twelve host languages, the same embeddings,
the same decoy classes. It shows the fixes are not overfitted to particular
strings; it does not show they generalise to credential shapes or file layouts
the generator cannot produce.

**This is a regression suite, not a benchmark of the product.** It answers "did
this change break or fix what it claimed" against a corpus we wrote. It does not
answer "how good is SecretLoop", and a 1.000 here is a statement about the
corpus as much as about the scanner.

## What the corpus does to the tools it compares

Two measured cases where the corpus, not the scanner, decides the score:

- **PEM plants favour marker matching.** The generator writes
  `-----BEGIN RSA PRIVATE KEY-----` around random base64. SecretLoop and
  gitleaks match the marker and report it; TruffleHog does not, scoring 0 of 7.
  That is not results filtering -- its PrivateKey detector is active and fired 15
  times on corpus B. Checked directly: given a real `openssl genrsa` key
  TruffleHog reports it, and given the synthetic block it does not. It requires
  something that parses as a key. On this axis the corpus rewards the looser
  behaviour, and TruffleHog's is arguably the more correct one.
- **History plants use one variable name.** Every history-only plant is written
  as `CREDENTIAL = "..."`, so keyword-gated rules cannot fire on any of them
  regardless of kind. History recall therefore under-measures named rules across
  the board; only the entropy tier is really being tested there.

## Comparing against other scanners

`COMMANDS.md` records the exact gitleaks and TruffleHog invocations used, with
pinned versions and the file-set exclusions needed to make the comparison fair —
`trufflehog filesystem` walks `node_modules` and `.git/objects`, which the other
scanners exclude, and without `-x th-exclude.txt` its counts are not comparable.
