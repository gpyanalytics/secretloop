#!/usr/bin/env node
/**
 * Refuses to run the suite against a build older than the source.
 *
 * Five test files spawn `out/cli.js` as a child process, so the suite is
 * partly a test of the built artifact rather than of src/. When the two
 * disagree the failure is unreadable: switching branches without rebuilding
 * produced "secretloop: unknown command approve" from a test whose subject was
 * the approval prompt, which reads as a broken feature rather than a stale file.
 *
 * This is the fourth time this class of mistake has cost real debugging here.
 * bench/run.py already guards its own measurement the same way, after a rules
 * change was measured against a bundle that predated it and read as "the fix
 * did nothing". A guard per consumer is how that keeps happening; this one
 * covers every test at once.
 *
 * mtimes, not hashes and not git: the question is "was this built after the
 * source was last touched", which is what mtime answers directly. Reading git
 * would make a dirty working tree — the normal state while developing — either
 * a false alarm or a blind spot, and hashing would need a manifest to compare
 * against, which is one more thing to keep fresh.
 *
 * A tie passes. Editing a file in the same second a build finished is not
 * evidence of staleness, and a guard that cries wolf gets removed rather than
 * fixed.
 *
 * Usage: check-build-fresh.js [srcDir] [outDir]
 * The arguments exist so the guard can be tested against fixtures instead of
 * against the repository's own out/, which the suite is meanwhile running from.
 */
const { readdirSync, statSync, existsSync } = require("fs");
const path = require("path");

const REPO = path.join(__dirname, "..");
const srcDir = process.argv[2] ? path.resolve(process.argv[2]) : path.join(REPO, "src");
const outDir = process.argv[3] ? path.resolve(process.argv[3]) : path.join(REPO, "out");

/** Every file under `dir` with one of `exts`, recursively. */
function filesUnder(dir, exts) {
  const found = [];
  const walk = (d) => {
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (exts.some((e) => entry.name.endsWith(e))) found.push(full);
    }
  };
  walk(dir);
  return found;
}

function extreme(files, pick) {
  let best = null;
  for (const file of files) {
    const mtimeMs = statSync(file).mtimeMs;
    if (best === null || pick(mtimeMs, best.mtimeMs)) best = { file, mtimeMs };
  }
  return best;
}

function fail(lines) {
  process.stderr.write(`${lines.join("\n")}\n`);
  process.exit(1);
}

const sources = filesUnder(srcDir, [".ts"]);
if (sources.length === 0) {
  // Nothing to be stale against. Not this guard's business to complain.
  process.exit(0);
}

/**
 * The artifacts THIS branch builds, read out of the bundle script's entry
 * points rather than by listing out/*.js.
 *
 * out/ accumulates files across branches: release-0.1.1 builds cli and
 * extension, mcp-layer also builds mcp, and switching from the second to the
 * first leaves an out/mcp.js that nothing on this branch will ever refresh.
 * The first version of this guard listed the directory and refused to run over
 * exactly that stray — a true statement about a file, and a false alarm about
 * the build, which is how a guard earns its removal instead of its keep.
 *
 * Reading the entry points means each branch checks what it actually produces,
 * with no list to maintain here.
 */
function expectedArtifacts() {
  let bundle = "";
  try {
    bundle = require(path.join(REPO, "package.json")).scripts?.bundle ?? "";
  } catch {
    /* fall through to the directory listing below */
  }
  const entries = [...bundle.matchAll(/src\/([A-Za-z0-9_.-]+)\.ts/g)].map((m) => m[1]);
  if (entries.length > 0) return entries.map((name) => path.join(outDir, `${name}.js`));
  return existsSync(outDir) ? filesUnder(outDir, [".js"]) : [];
}

const expected = expectedArtifacts();
const missing = expected.filter((f) => !existsSync(f));
if (expected.length === 0 || missing.length > 0) {
  fail([
    `out/ has no build for ${missing.map((f) => path.basename(f)).join(", ") || "this branch"} —`,
    `the suite spawns out/cli.js as a child process.`,
    ``,
    `Run \`npm run compile\` first.`,
  ]);
}
const built = expected;

const newestSource = extreme(sources, (a, b) => a > b);
const oldestBuilt = extreme(built, (a, b) => a < b);

if (oldestBuilt.mtimeMs < newestSource.mtimeMs) {
  // Relative when it reads better, absolute when it does not: a path that
  // climbs out of the repository with a row of "../" is harder to read than the
  // absolute one it was derived from.
  const rel = (f) => {
    const r = path.relative(REPO, f);
    return r.startsWith("..") ? f : r;
  };
  fail([
    `out/ is stale relative to src/ — run \`npm run compile\`.`,
    ``,
    `  ${rel(oldestBuilt.file)} was built before ${rel(newestSource.file)} was last changed.`,
    ``,
    `Five test files spawn out/cli.js, so running now would test the old build`,
    `and report the difference as a broken feature.`,
  ]);
}
