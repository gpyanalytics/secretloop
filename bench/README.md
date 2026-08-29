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

## Comparing against other scanners

`COMMANDS.md` records the exact gitleaks and TruffleHog invocations used, with
pinned versions and the file-set exclusions needed to make the comparison fair —
`trufflehog filesystem` walks `node_modules` and `.git/objects`, which the other
scanners exclude, and without `-x th-exclude.txt` its counts are not comparable.
