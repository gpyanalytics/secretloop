#!/usr/bin/env bash
#
# Packs the npm tarball, extracts it somewhere with no node_modules and no
# source tree, and runs the CLI the way a user gets it.
#
# This exists because `npm pack --dry-run` verifies the file *list* and the
# damage lands in file *content*. The tarball ships exactly one executable file,
# out/cli.js, and whether that file works depends on which build wrote it last:
# `npm run bundle` produces a self-contained bundle, while `npm run compile`
# (tsc) produces a module that requires ./scanner, ./report and friends — none
# of which the .npmignore allowlist ships. Both produce the same 4-file,
# ~510 kB tarball. Only running it tells the two apart.
#
# Extraction happens outside the repository on purpose: run from within it and
# node resolves the missing modules from the real source tree, and a broken
# tarball passes.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "smoke: packing"
tarball="$(cd "$work" && npm pack "$repo" --silent)"

echo "smoke: extracting $tarball"
tar -xzf "$work/$tarball" -C "$work"

cli="$work/package/out/cli.js"
if [ ! -f "$cli" ]; then
  echo "smoke: FAIL — the tarball does not contain out/cli.js" >&2
  exit 1
fi

# The manifest must not send anyone to a file the tarball omits.
#
# `main` is not free to change: vsce and the VS Code extension host both read it
# to find out/extension.js, which is deliberately excluded from the npm side
# (620 kB of editor bundle a CLI user downloads and never loads). Node's
# `exports` field fully replaces `main` for consumers, so the rule enforced here
# is the real one: main may name a file the tarball lacks ONLY while `exports`
# shadows it. A consumer then gets "No exports main defined", which is true —
# this package is a CLI and has no importable entry — instead of a stack trace
# about a phantom path.
echo "smoke: checking the manifest sends nobody to a missing file"
node -e '
  const fs = require("fs"), path = require("path");
  const dir = process.argv[1];
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const targets = Object.entries(pkg.bin ?? {}).map(([k, v]) => ["bin." + k, v]);

  const exp = pkg.exports;
  if (exp === undefined) {
    targets.push(["main", pkg.main]);
  } else if (typeof exp === "string") {
    targets.push(["exports", exp]);
  } else if (exp["."] !== undefined) {
    targets.push(["exports[.]", typeof exp["."] === "string" ? exp["."] : null]);
  }
  // else: exports exists and defines no ".", so main is unreachable by design.

  const missing = targets
    .filter(([, v]) => v)
    .filter(([, v]) => !fs.existsSync(path.join(dir, v)))
    .map(([field, v]) => field + " -> " + v);

  if (missing.length) {
    console.error("smoke: FAIL - manifest points at files not in the tarball: " + missing.join(", "));
    process.exit(1);
  }
' "$work/package"

echo "smoke: running node package/out/cli.js --help"
cd "$work"
output="$(node package/out/cli.js --help)"

case "$output" in
  *"secretloop <command> [options]"*) ;;
  *) echo "smoke: FAIL — --help did not print usage. Got:" >&2; echo "$output" >&2; exit 1 ;;
esac

# --help exercises argument parsing and nothing else. A scan touches the rule
# table, the walker and the reporter, which is where a partial bundle breaks.
echo "smoke: running a real scan in an empty directory"
mkdir -p "$work/empty-scan"
node package/out/cli.js scan --path "$work/empty-scan" >/dev/null

echo "smoke: ok — $tarball runs standalone"
