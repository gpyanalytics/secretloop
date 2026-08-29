# Exact commands (all offline; no verification mode for any tool)

## Versions
secretloop  local build, repo commit 30c3e42ad5f16f8c68ac2ddffeb92ef3b44c854f (branch release-0.1.1, v0.1.1)
gitleaks    8.30.1
trufflehog  3.97.1

## Corpus A (seeded)  — ~/sl-benchmark/corpusA
python3 gen_corpus.py  ~/sl-benchmark/corpusA      # 190 files, 50 tree secrets, 120 decoys
python3 gen_history.py ~/sl-benchmark/corpusA      # +10 history-only secrets, 13 commits

node out/cli.js scan    --path $A --format json -o A.secretloop.tree.json
node out/cli.js history --path $A --format json -o A.secretloop.hist.json
# named-rule-only tier: {"entropyPassEnabled": false} written to $A/.secretloop.json, then removed
node out/cli.js scan    --path $A --format json -o A.secretloop.named.tree.json
node out/cli.js history --path $A --format json -o A.secretloop.named.hist.json

gitleaks dir $A --report-format json --report-path A.gitleaks.tree.json --no-banner --exit-code 0
gitleaks git $A --report-format json --report-path A.gitleaks.hist.json --no-banner --exit-code 0

trufflehog filesystem $A --json --no-verification --no-update -x th-exclude.txt > A.trufflehog.tree.jsonl
trufflehog git file://$A --json --no-verification --no-update > A.trufflehog.hist.jsonl

## Corpus B (real noise) — /Users/mac/Documents/Bugsnag/bugsnag-js @ 5da3ae169c9ff716fa70d1388bb8e2157ca46ea6
node out/cli.js scan    --path $BJ --format json -o B.secretloop.tree.json
node out/cli.js history --path $BJ --format json -o B.secretloop.hist.json
gitleaks dir $BJ --report-format json --report-path B.gitleaks.tree.json --no-banner --exit-code 0
gitleaks git $BJ --report-format json --report-path B.gitleaks.hist.json --no-banner --exit-code 0
trufflehog filesystem $BJ --json --no-verification --no-update -x th-exclude.txt > B.trufflehog.tree.nonm.jsonl
trufflehog git file://$BJ --json --no-verification --no-update > B.trufflehog.hist.jsonl

th-exclude.txt:
  node_modules
  \.git/

## Scoring
python3 score_final.py     # exact line match; +/-1 reported as sensitivity only
