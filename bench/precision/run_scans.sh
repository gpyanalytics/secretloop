#!/usr/bin/env bash
# Run SecretLoop and gitleaks over the same pinned working trees, then emit one
# row per finding for triage.
#
#   bash run_scans.sh
#   WORK=/tmp/p bash run_scans.sh
#
# Scope, stated once because "same scope" is the whole point of the comparison:
#   * Working tree only. No history scan for either tool.
#   * The same checkout, at the same pinned commit, for both tools.
#   * No verification, no network egress: SecretLoop without --verify, gitleaks
#     has no verification mode. Detection is a pure function of bytes on disk.
#   * Both tools at their default rule sets and default configuration.
#   * .git/ is excluded from gitleaks via a generated config, because
#     `gitleaks dir` would otherwise read the object store that SecretLoop's
#     working-tree scan never looks at. That is a scope difference, not a
#     detection difference, and it is the one thing normalised here.
#
# NOT normalised, and reported as a caveat rather than papered over: the two
# tools disagree about which files in that tree are worth reading. SecretLoop
# skips generated files (lockfiles, minified bundles, wrappers) by default;
# gitleaks reads them. Both are defaults, and defaults are what users get.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="${WORK:-$HOME/sl-precision}"
REPOS="$WORK/repos"
OUT="$WORK/reports"
CLI="$ROOT/out/cli.js"

[ -f "$CLI" ] || { echo "!!! $CLI missing -- run 'npm run bundle' first" >&2; exit 1; }
[ -d "$REPOS" ] || { echo "!!! $REPOS missing -- run clone_pinned.sh first" >&2; exit 1; }

mkdir -p "$OUT"

# Reports are written OUTSIDE every scanned tree, so no scan is ever its own
# input. $OUT is a sibling of $REPOS, never a child.

GLCONF="$WORK/gitleaks-scope.toml"
cat > "$GLCONF" <<'TOML'
# Default gitleaks rules, plus one scope normalisation: skip the git object
# store, which the SecretLoop working-tree scan does not read.
[extend]
useDefault = true

[allowlist]
description = "scope: working tree only"
paths = ['''(^|/)\.git/''']
TOML

SLVER="$(python3 -c 'import json;print(json.load(open("'"$ROOT"'/package.json"))["version"])')"
echo "secretloop  v$SLVER  local build, commit $(git -C "$ROOT" rev-parse --short HEAD)"
echo "gitleaks    $(gitleaks version)"
echo

while read -r name url commit; do
  case "$name" in ''|\#*) continue ;; esac
  [ "$commit" = "HEAD" ] && { echo "!!! $name unpinned -- run clone_pinned.sh" >&2; exit 1; }

  d="$REPOS/$name"
  [ -d "$d" ] || { echo "!!! $d missing -- run clone_pinned.sh" >&2; exit 1; }

  have="$(git -C "$d" rev-parse HEAD)"
  [ "$have" = "$commit" ] || { echo "!!! $name at $have, pinned $commit" >&2; exit 1; }

  echo "==> $name @ ${commit:0:12}"

  node "$CLI" scan --path "$d" --format json -o "$OUT/$name.secretloop.json" \
    --fail-on never >/dev/null

  gitleaks dir "$d" \
    --config "$GLCONF" \
    --report-format json --report-path "$OUT/$name.gitleaks.json" \
    --no-banner --exit-code 0 --redact >/dev/null 2>&1

  sl=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["findings"]))' "$OUT/$name.secretloop.json")
  gl=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(len(d) if d else 0)' "$OUT/$name.gitleaks.json")
  echo "    secretloop $sl   gitleaks $gl"
done < "$HERE/pins.txt"

echo
echo "==> building triage seed"

WORK="$WORK" OUT="$OUT" REPOS="$REPOS" PINS="$HERE/pins.txt" python3 - <<'PY'
import csv, json, os, re

work, out, repos, pins = (os.environ[k] for k in ("WORK", "OUT", "REPOS", "PINS"))

# Any run of 16+ credential-alphabet characters is replaced by first4****last4
# before a snippet is written anywhere. The triager reads the real line in the
# pinned checkout; nothing that leaves this script carries a whole value.
TOKEN = re.compile(r'[A-Za-z0-9+/=_\-]{16,}')

def scrub(s):
    def f(m):
        t = m.group(0)
        return t[:4] + '*' * max(4, len(t) - 8) + t[-4:]
    return TOKEN.sub(f, s)

def snippet(repo_dir, rel, line):
    p = os.path.join(repo_dir, rel)
    try:
        with open(p, 'r', encoding='utf-8', errors='replace') as fh:
            for i, text in enumerate(fh, 1):
                if i == line:
                    return scrub(text.strip())[:160]
    except OSError:
        pass
    return ''

rows = []
with open(pins) as fh:
    for raw in fh:
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        name, url, commit = raw.split()
        d = os.path.join(repos, name)

        with open(os.path.join(out, f'{name}.secretloop.json')) as f:
            for x in json.load(f)['findings']:
                rows.append(dict(
                    repo=name, commit=commit[:12], tool='secretloop',
                    rule_id=x['ruleId'], severity=x.get('severity', ''),
                    file=x['file'], line=x['line'],
                    masked_value=x.get('value', ''),
                    snippet=snippet(d, x['file'], x['line']),
                    fingerprint=x.get('fingerprint', ''),
                    verdict='', reason=''))

        with open(os.path.join(out, f'{name}.gitleaks.json')) as f:
            for x in (json.load(f) or []):
                rel = os.path.relpath(x['File'], d)
                rows.append(dict(
                    repo=name, commit=commit[:12], tool='gitleaks',
                    rule_id=x['RuleID'], severity='',
                    file=rel, line=x['StartLine'],
                    masked_value='REDACTED',
                    snippet=snippet(d, rel, x['StartLine']),
                    fingerprint=f"{rel}:{x['RuleID']}:{x['StartLine']}",
                    verdict='', reason=''))

rows.sort(key=lambda r: (r['repo'], r['tool'], r['file'], r['line'], r['rule_id']))

cols = ['repo', 'commit', 'tool', 'rule_id', 'severity', 'file', 'line',
        'masked_value', 'snippet', 'fingerprint', 'verdict', 'reason']
dest = os.path.join(work, 'triage_seed.csv')
with open(dest, 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)

print(f'    {len(rows)} finding(s) -> {dest}')
for tool in ('secretloop', 'gitleaks'):
    n = sum(1 for r in rows if r['tool'] == tool)
    print(f'    {tool:11s} {n}')
PY

echo
echo "Next: cp $WORK/triage_seed.csv $WORK/triage.csv"
echo "      fill verdict (TP|FP|UNKNOWN) and reason for every row"
echo "      python3 $HERE/compute_precision.py $WORK/triage.csv"
