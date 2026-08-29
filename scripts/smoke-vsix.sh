#!/usr/bin/env bash
#
# Packs the VSIX, unzips it somewhere outside the repository, and checks the
# archive rather than the intent.
#
# The npm side has scripts/smoke-tarball.sh for the same reason: `vsce ls`
# verifies the file *list*, and the damage lands in file *content* and in what
# the manifest points at. Three failures this catches, all of which vsce itself
# reports as a clean package:
#
#   - An icon named by package.json but excluded by .vscodeignore. vsce lists no
#     icon, raises no warning, and ships a manifest naming a file the archive
#     does not contain: a broken image on the Marketplace listing.
#   - out/extension.js written by `npm run compile` (tsc) rather than
#     `npm run bundle` (esbuild). The tsc output requires ./scanner, ./report
#     and friends; whether those are in the archive depends on what was built
#     last. `npm run clean` in vscode:prepublish is what makes this
#     deterministic, and this asserts it worked.
#   - out/cli.js missing. hooks.ts copies it out of the installed extension to
#     install the pre-commit hook, so an extension without it installs a hook
#     that cannot run.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "smoke: packaging"
(cd "$repo" && npx vsce package --out "$work/probe.vsix" >/dev/null)

echo "smoke: extracting"
unzip -q "$work/probe.vsix" -d "$work/x"
ext="$work/x/extension"

fail() { echo "smoke: FAIL — $1" >&2; exit 1; }

[ -f "$ext/package.json" ] || fail "no extension/package.json in the archive"

echo "smoke: checking the manifest against the archive's own contents"
node -e '
  const fs = require("fs"), path = require("path");
  const dir = process.argv[1];
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const problems = [];

  if (pkg.publisher !== "gpyanalytics") problems.push("publisher is " + pkg.publisher);
  if (!pkg.version) problems.push("no version");

  // An icon the manifest names must be IN here, not merely in the repository.
  if (pkg.icon && !fs.existsSync(path.join(dir, pkg.icon))) {
    problems.push("icon -> " + pkg.icon + " is not in the archive");
  }
  // main is how the extension host finds the entry point.
  if (!pkg.main) problems.push("no main");
  else if (!fs.existsSync(path.join(dir, pkg.main.replace(/^\.\//, "")))) {
    problems.push("main -> " + pkg.main + " is not in the archive");
  }
  if (problems.length) {
    console.error("smoke: FAIL - " + problems.join("; "));
    process.exit(1);
  }
' "$ext"

echo "smoke: checking out/extension.js is the esbuild bundle, not tsc output"
node -e '
  const fs = require("fs");
  const s = fs.readFileSync(process.argv[1], "utf8");
  // The bundle inlines every local module, so it has no relative requires left.
  // A tsc build of extension.ts still requires ./scanner, ./config and friends.
  const relative = [...new Set([...s.matchAll(/require\("(\.[^"]+)"\)/g)].map(m => m[1]))];
  if (relative.length) {
    console.error("smoke: FAIL - out/extension.js still requires " + relative.join(", ") +
                  " - this is tsc output, not the bundle");
    process.exit(1);
  }
' "$ext/out/extension.js"

# hooks.ts copies this out of the installed extension directory.
[ -f "$ext/out/cli.js" ] || fail "out/cli.js missing — the pre-commit hook installer needs it"

echo "smoke: running the archived CLI copy"
output="$(node "$ext/out/cli.js" --help)"
case "$output" in
  *"secretloop <command> [options]"*) ;;
  *) fail "the archived out/cli.js did not print usage" ;;
esac

echo "smoke: checking the archive against scripts/vsix-manifest.txt, exactly"
# An exact list, not a list of things to ignore. The previous version excluded
# known-good paths and passed anything it had not thought of, which is the same
# denylist failure .vscodeignore itself has already shipped twice. A committed
# manifest fails on a stray AND on a disappearance, and changing what ships now
# requires editing a file that says what ships.
actual="$(cd "$work/x" && find extension -type f | sort)"
expected="$(sort "$repo/scripts/vsix-manifest.txt")"
if [ "$actual" != "$expected" ]; then
  echo "smoke: FAIL — VSIX contents do not match scripts/vsix-manifest.txt" >&2
  diff <(echo "$expected") <(echo "$actual") | sed 's/^/  /' >&2
  echo "  (< expected, > actual. Update the manifest only when the change is intended.)" >&2
  exit 1
fi

echo "smoke: ok — VSIX contents, manifest targets and the bundle all check out"
