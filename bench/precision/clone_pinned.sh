#!/usr/bin/env bash
# Clone the six precision-baseline repositories, each pinned to one commit.
#
# Shallow (--depth 1) at a specific SHA: the baseline is a working-tree
# measurement, so no history is needed, and a full clone of kubernetes/deno
# costs gigabytes for bytes nothing reads.
#
#   bash clone_pinned.sh            # clone into $WORK (default ~/sl-precision)
#   WORK=/tmp/p bash clone_pinned.sh
#
# Re-running is safe: a repository already checked out at its pinned SHA is
# left alone. Delete $WORK/repos to force a re-clone.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${WORK:-$HOME/sl-precision}"
PINS="$HERE/pins.txt"
REPOS="$WORK/repos"

mkdir -p "$REPOS"

resolved=0

while read -r name url commit; do
  case "$name" in ''|\#*) continue ;; esac

  dest="$REPOS/$name"

  if [ "$commit" = "HEAD" ]; then
    echo "==> $name: resolving default-branch HEAD"
    commit="$(git ls-remote "$url" HEAD | cut -f1)"
    if [ -z "$commit" ]; then
      echo "!!! $name: could not resolve HEAD at $url" >&2
      exit 1
    fi
    # Rewrite the pin in place so the next run reproduces this one.
    tmp="$(mktemp)"
    awk -v n="$name" -v c="$commit" \
      '$1==n && $3=="HEAD" { printf "%-13s %-48s %s\n", $1, $2, c; next } { print }' \
      "$PINS" > "$tmp"
    mv "$tmp" "$PINS"
    resolved=$((resolved + 1))
    echo "    pinned $name -> $commit"
  fi

  if [ -d "$dest/.git" ]; then
    have="$(git -C "$dest" rev-parse HEAD 2>/dev/null || echo none)"
    if [ "$have" = "$commit" ]; then
      echo "==> $name: already at $commit, skipping"
      continue
    fi
    echo "==> $name: at $have, wanted $commit -- re-cloning"
    rm -rf "$dest"
  fi

  echo "==> $name: fetching $commit from $url"
  mkdir -p "$dest"
  git -C "$dest" init -q
  git -C "$dest" remote add origin "$url"
  git -C "$dest" fetch -q --depth 1 origin "$commit"
  git -C "$dest" checkout -q FETCH_HEAD
  echo "    $name: $(git -C "$dest" rev-parse --short HEAD) checked out"
done < "$PINS"

echo
echo "Clones under $REPOS"
du -sh "$REPOS"/* 2>/dev/null || true
if [ "$resolved" -gt 0 ]; then
  echo
  echo "$resolved pin(s) newly resolved and written to $PINS -- commit that file."
fi
