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

## Corpus B (historical, unnamed) — /path/to/real-noise-repo, at its pinned commit
# $BJ is that checkout. The repository is not named here and its path is not a
# real one: corpus B is any large real-world JS repository with no known
# secrets, and the numbers below describe the class, not that one project.
node out/cli.js scan    --path $BJ --format json -o B.secretloop.tree.json
node out/cli.js history --path $BJ --format json -o B.secretloop.hist.json
gitleaks dir $BJ --report-format json --report-path B.gitleaks.tree.json --no-banner --exit-code 0
gitleaks git $BJ --report-format json --report-path B.gitleaks.hist.json --no-banner --exit-code 0
trufflehog filesystem $BJ --json --no-verification --no-update -x th-exclude.txt > B.trufflehog.tree.nonm.jsonl
trufflehog git file://$BJ --json --no-verification --no-update > B.trufflehog.hist.jsonl

th-exclude.txt:
  node_modules
  \.git/

## Corpus B (named, from 6 October 2026) — getsentry/sentry-javascript @ fade8e2ddd3dfc2ff18b6e4053a93a94c1c7cbae
# $B is a measurement clone with the FULL history reachable from the pinned
# commit. Fetching the commit by SHA gives the same tree as the shallow clone
# recorded in keyed-repos.txt but, unlike it, a history arm that covers every
# reachable commit (16,211 at this pin, 4 root commits). Record the clone's
# depth with every history figure; a shallow clone gives a bounded one.
git init $B && git -C $B remote add origin https://github.com/getsentry/sentry-javascript.git
git -C $B fetch origin fade8e2ddd3dfc2ff18b6e4053a93a94c1c7cbae
git -C $B checkout --detach FETCH_HEAD
git -C $B rev-list --count HEAD        # 16211 ; and [ ! -f $B/.git/shallow ]
# Do not install the corpus's dependencies: node_modules is not part of the
# tree scanned, and installing changes what is on disk under $B.
node out/cli.js scan    --path $B --format json -o B2.secretloop.tree.off.json
node out/cli.js scan    --path $B --format json -o B2.secretloop.tree.on.json  --include-entropy
node out/cli.js history --path $B --format json -o B2.secretloop.hist.off.json
node out/cli.js history --path $B --format json -o B2.secretloop.hist.on.json  --include-entropy
# --include-entropy is folded into the configuration before the digest is
# computed, so the two arms carry distinct `comparison.configDigest` values;
# a run whose two arms share a digest measured one arm twice.
# Findings on this corpus are UNTRIAGED unless individually labelled: the
# repository is assumed, not audited, to hold no live credential.

## Scoring
python3 score_final.py     # exact line match; +/-1 reported as sensitivity only
